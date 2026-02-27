use alloc::boxed::Box;
use alloc::vec::Vec;
use arch_hal::cpu::clean_dcache_range;
use arch_hal::cpu::invalidate_dcache_range;
use core::hint::spin_loop;
use core::mem::size_of;
use core::ops::ControlFlow;
use dtb::DtbParser;
use dtb::WalkError;
use io_api::ethernet::EthernetFrameIo;
use io_api::ethernet::MacAddr;
use mutex::SpinLock;
use typestate::Le;
use typestate::ReadPure;
use typestate::Readable;
use virtio::VirtIoCore;
use virtio::VirtIoDevice;
use virtio::VirtioErr;
use virtio::VirtioFeatures;
use virtio::device_type::VirtIoDeviceTypes;
use virtio::mmio::VirtIoMmio;
use virtio::queue::VirtqDesc;
use virtio::queue::VirtqDescFlags;

const RX_QUEUE_IDX: u16 = 0;
const TX_QUEUE_IDX: u16 = 1;
const MAX_FRAME_LEN: usize = 2048;
const RX_SLOT_CAP: usize = 64;
const VIRTIO_NET_F_MAC: VirtioFeatures = VirtioFeatures(1 << 5);

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<VirtioNetHdr>() == 10);

const VIRTIO_NET_HDR_LEN: usize = size_of::<VirtioNetHdr>();
const RX_BUFFER_LEN: usize = VIRTIO_NET_HDR_LEN + MAX_FRAME_LEN;
const TX_BUFFER_LEN: usize = VIRTIO_NET_HDR_LEN + MAX_FRAME_LEN;

#[repr(C)]
struct VirtioNetConfig {
    mac: [ReadPure<u8>; 6],
    status: ReadPure<Le<u16>>,
}

struct VirtIoNetAdapter;

impl VirtIoDevice for VirtIoNetAdapter {
    fn driver_features(
        &self,
        select: u32,
        _device_feature: VirtioFeatures,
    ) -> Result<VirtioFeatures, VirtioErr> {
        if select == 0 {
            Ok(VIRTIO_NET_F_MAC)
        } else {
            Ok(VirtioFeatures(0))
        }
    }

    fn num_of_queue(&self) -> Result<u32, VirtioErr> {
        Ok(2)
    }
}

struct RxSlot {
    desc_idx: u16,
    desc_ptr: *mut VirtqDesc,
    buf: Box<[u8; RX_BUFFER_LEN]>,
}

struct TxState {
    buf: Box<[u8; TX_BUFFER_LEN]>,
}

impl TxState {
    fn new() -> Self {
        Self {
            buf: Box::new([0; TX_BUFFER_LEN]),
        }
    }
}

pub struct VirtioNet {
    core: VirtIoCore<VirtIoMmio>,
    rx_slots: Vec<RxSlot>,
    tx: SpinLock<TxState>,
    mac: MacAddr,
}

impl VirtioNet {
    fn new(mmio_base: usize) -> Result<Self, VirtioErr> {
        let mut core = VirtIoCore::new_mmio(mmio_base)?;
        if core.get_device() != VirtIoDeviceTypes::NetworkDevice {
            return Err(VirtioErr::Invalid);
        }
        let adapter = VirtIoNetAdapter;
        core.init(&adapter)?;
        let mac = read_mac_from_config(&core);
        let mut this = Self {
            core,
            rx_slots: Vec::new(),
            tx: SpinLock::new(TxState::new()),
            mac,
        };
        this.init_rx_queue()?;
        Ok(this)
    }

    fn init_rx_queue(&mut self) -> Result<(), VirtioErr> {
        let desc_size = size_of::<VirtqDesc>();
        for _ in 0..RX_SLOT_CAP {
            let (desc_idx, desc) = match self.core.allocate_descriptor(RX_QUEUE_IDX) {
                Ok(v) => v,
                Err(VirtioErr::OutOfAvailableDesc) => break,
                Err(err) => return Err(err),
            };
            let mut rx_buf = Box::new([0; RX_BUFFER_LEN]);
            desc.addr = Le::new(rx_buf.as_mut_ptr() as u64);
            desc.len = Le::new(RX_BUFFER_LEN as u32);
            desc.flags = Le::new(VirtqDescFlags::VIRTQ_DESC_F_WRITE);
            desc.next = Le::new(0);

            clean_dcache_range(desc as *const _ as *const u8, desc_size);
            clean_dcache_range(rx_buf.as_ptr(), RX_BUFFER_LEN);
            if let Err(err) = self.core.set_and_notify(RX_QUEUE_IDX, desc_idx) {
                let _ = self.core.dequeue_used(RX_QUEUE_IDX, desc_idx);
                return Err(err);
            }

            self.rx_slots.push(RxSlot {
                desc_idx,
                desc_ptr: desc as *mut VirtqDesc,
                buf: rx_buf,
            });
        }
        Ok(())
    }

    fn repost_rx_slot(&mut self, slot_idx: usize) -> bool {
        let desc_size = size_of::<VirtqDesc>();
        let slot = &mut self.rx_slots[slot_idx];
        // SAFETY: `desc_ptr` points to a descriptor allocated from this queue and retained
        // for this slot's lifetime; access is serialized through `&mut self` so no aliasing
        // mutable references exist when updating descriptor fields.
        let desc = unsafe { &mut *slot.desc_ptr };
        desc.addr = Le::new(slot.buf.as_mut_ptr() as u64);
        desc.len = Le::new(slot.buf.len() as u32);
        desc.flags = Le::new(VirtqDescFlags::VIRTQ_DESC_F_WRITE);
        desc.next = Le::new(0);
        clean_dcache_range(slot.desc_ptr as *const u8, desc_size);
        clean_dcache_range(slot.buf.as_ptr(), slot.buf.len());
        self.core
            .set_and_notify(RX_QUEUE_IDX, slot.desc_idx)
            .is_ok()
    }
}

impl EthernetFrameIo for VirtioNet {
    fn max_frame_len(&self) -> usize {
        MAX_FRAME_LEN
    }

    fn mac_addr(&self) -> MacAddr {
        self.mac
    }

    fn try_recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
        let (desc_idx, used_len_raw) = self.core.pop_used(RX_QUEUE_IDX).ok().flatten()?;
        let slot_idx = self
            .rx_slots
            .iter()
            .position(|slot| slot.desc_idx == desc_idx)?;
        let slot = &mut self.rx_slots[slot_idx];
        let used_len = usize::min(used_len_raw as usize, slot.buf.len());
        invalidate_dcache_range(slot.buf.as_ptr(), used_len);
        if used_len < VIRTIO_NET_HDR_LEN {
            let _ = self.repost_rx_slot(slot_idx);
            return None;
        }

        let payload = &slot.buf[VIRTIO_NET_HDR_LEN..used_len];
        let copy_len = usize::min(payload.len(), buf.len());
        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
        if !self.repost_rx_slot(slot_idx) {
            return None;
        }
        Some(copy_len)
    }

    fn try_send_frame(&mut self, frame: &[u8]) -> bool {
        if frame.len() > MAX_FRAME_LEN {
            return false;
        }
        let mut tx = self.tx.lock();
        tx.buf[..VIRTIO_NET_HDR_LEN].fill(0);
        let total_len = VIRTIO_NET_HDR_LEN + frame.len();
        tx.buf[VIRTIO_NET_HDR_LEN..total_len].copy_from_slice(frame);
        clean_dcache_range(tx.buf.as_ptr(), total_len);

        let (desc_idx, desc) = match self.core.allocate_descriptor(TX_QUEUE_IDX) {
            Ok(v) => v,
            Err(_) => return false,
        };
        desc.addr = Le::new(tx.buf.as_ptr() as u64);
        desc.len = Le::new(total_len as u32);
        desc.flags =
            Le::new(VirtqDescFlags::VIRTQ_DESC_F_NEXT & VirtqDescFlags::VIRTQ_DESC_F_WRITE);
        desc.next = Le::new(0);
        clean_dcache_range(desc as *const _ as *const u8, size_of::<VirtqDesc>());
        if self.core.set_and_notify(TX_QUEUE_IDX, desc_idx).is_err() {
            let _ = self.core.dequeue_used(TX_QUEUE_IDX, desc_idx);
            return false;
        }

        loop {
            match self.core.pop_used(TX_QUEUE_IDX) {
                Ok(Some((used_idx, _))) => {
                    let _ = self.core.dequeue_used(TX_QUEUE_IDX, used_idx);
                    if used_idx == desc_idx {
                        return true;
                    }
                }
                Ok(None) => spin_loop(),
                Err(_) => {
                    let _ = self.core.dequeue_used(TX_QUEUE_IDX, desc_idx);
                    return false;
                }
            }
        }
    }
}

fn read_mac_from_config(core: &VirtIoCore<VirtIoMmio>) -> MacAddr {
    // SAFETY: `get_configuration_addr()` is provided by the validated virtio-mmio transport;
    // the returned MMIO config region remains mapped and stable for the program lifetime.
    let cfg = unsafe { &*(core.get_configuration_addr() as *const VirtioNetConfig) };
    MacAddr([
        cfg.mac[0].read(),
        cfg.mac[1].read(),
        cfg.mac[2].read(),
        cfg.mac[3].read(),
        cfg.mac[4].read(),
        cfg.mac[5].read(),
    ])
}

pub fn init_from_dtb(dtb: &DtbParser) -> &'static mut VirtioNet {
    let mut mmio_base: Option<usize> = None;
    let result = dtb.find_nodes_by_compatible_view("virtio,mmio", &mut |view,
                                                                        _name|
     -> Result<
        ControlFlow<()>,
        WalkError<()>,
    > {
        let mut regs = view.reg_iter().map_err(WalkError::Dtb)?;
        let Some(entry) = regs.next() else {
            return Ok(ControlFlow::Continue(()));
        };
        let (base, _size) = entry.map_err(WalkError::Dtb)?;
        let core = match VirtIoCore::new_mmio(base) {
            Ok(core) => core,
            Err(_) => return Ok(ControlFlow::Continue(())),
        };
        if core.get_device() == VirtIoDeviceTypes::NetworkDevice {
            mmio_base = Some(base);
            return Ok(ControlFlow::Break(()));
        }
        Ok(ControlFlow::Continue(()))
    });
    match result {
        Ok(ControlFlow::Break(())) | Ok(ControlFlow::Continue(())) => {}
        Err(WalkError::Dtb(err)) => panic!("virtio_net: dtb walk failed: {}", err),
        Err(WalkError::User(())) => panic!("virtio_net: unexpected dtb walker user error"),
    }

    let mmio_base = mmio_base.unwrap_or_else(|| panic!("virtio_net: no virtio-net mmio node"));
    let driver = VirtioNet::new(mmio_base).unwrap_or_else(|err| {
        panic!(
            "virtio_net: failed to initialize device at 0x{:X}: {:?}",
            mmio_base, err
        )
    });
    Box::leak(Box::new(driver))
}
