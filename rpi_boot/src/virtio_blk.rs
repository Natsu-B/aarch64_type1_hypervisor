use block_device_api::BlockDevice;
use block_device_api::IoError;
use block_device_api::virtio_blk_mmio::FeaturePolicy;
use block_device_api::virtio_blk_mmio::MmioAccessError;
use block_device_api::virtio_blk_mmio::QueueParseError;
use block_device_api::virtio_blk_mmio::SECTOR_SIZE;
use block_device_api::virtio_blk_mmio::VIRTIO_BLK_S_IOERR;
use block_device_api::virtio_blk_mmio::VIRTIO_BLK_S_OK;
use block_device_api::virtio_blk_mmio::VIRTIO_BLK_S_UNSUPP;
use block_device_api::virtio_blk_mmio::VIRTIO_BLK_T_FLUSH;
use block_device_api::virtio_blk_mmio::VIRTIO_BLK_T_IN;
use block_device_api::virtio_blk_mmio::VIRTIO_BLK_T_OUT;
use block_device_api::virtio_blk_mmio::VIRTIO_INT_USED_RING;
use block_device_api::virtio_blk_mmio::VIRTIO_MMIO_DEVICE_ID_BLOCK;
use block_device_api::virtio_blk_mmio::VIRTIO_MMIO_MAGIC_VALUE;
use block_device_api::virtio_blk_mmio::VIRTIO_MMIO_VENDOR_ID;
use block_device_api::virtio_blk_mmio::VIRTIO_MMIO_VERSION_MODERN;
use block_device_api::virtio_blk_mmio::VIRTIO_STATUS_DRIVER_OK;
use block_device_api::virtio_blk_mmio::VIRTIO_STATUS_FEATURES_OK;
use block_device_api::virtio_blk_mmio::VIRTQ_DESC_F_NEXT;
use block_device_api::virtio_blk_mmio::VIRTQ_DESC_F_WRITE;
use block_device_api::virtio_blk_mmio::VirtioBlkConfig;
use block_device_api::virtio_blk_mmio::VirtioBlkReq;
use block_device_api::virtio_blk_mmio::VirtioBlkReqLayout;
use block_device_api::virtio_blk_mmio::VirtqDesc;
use block_device_api::virtio_blk_mmio::ack_interrupt_bits;
use block_device_api::virtio_blk_mmio::avail_ring_entry_addr;
use block_device_api::virtio_blk_mmio::calc_ring_index;
use block_device_api::virtio_blk_mmio::device_features;
use block_device_api::virtio_blk_mmio::merge_driver_features;
use block_device_api::virtio_blk_mmio::parse_req_layout;
use block_device_api::virtio_blk_mmio::select_feature_bits;
use block_device_api::virtio_blk_mmio::used_update;
use block_device_api::virtio_blk_mmio::validate_negotiated_features;
use block_device_api::virtio_blk_mmio::validate_queue_size;
use core::mem::MaybeUninit;
use core::mem::size_of;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use core::sync::atomic::Ordering;
use mutex::SpinLock;

use crate::vgic;

pub(crate) const VIRTIO_BLK_MMIO_BASE: usize = 0x10_7c10_0000;
pub(crate) const VIRTIO_BLK_MMIO_SIZE: usize = 0x1000;
pub(crate) const VIRTIO_BLK_IRQ: u32 = 275;

const REG_MAGIC_VALUE: usize = 0x000;
const REG_VERSION: usize = 0x004;
const REG_DEVICE_ID: usize = 0x008;
const REG_VENDOR_ID: usize = 0x00c;
const REG_DEVICE_FEATURES: usize = 0x010;
const REG_DEVICE_FEATURES_SEL: usize = 0x014;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_QUEUE_SEL: usize = 0x030;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
const REG_QUEUE_READY: usize = 0x044;
const REG_QUEUE_NOTIFY: usize = 0x050;
const REG_INTERRUPT_STATUS: usize = 0x060;
const REG_INTERRUPT_ACK: usize = 0x064;
const REG_STATUS: usize = 0x070;
const REG_QUEUE_DESC_LOW: usize = 0x080;
const REG_QUEUE_DESC_HIGH: usize = 0x084;
const REG_QUEUE_DRIVER_LOW: usize = 0x090;
const REG_QUEUE_DRIVER_HIGH: usize = 0x094;
const REG_QUEUE_DEVICE_LOW: usize = 0x0a0;
const REG_QUEUE_DEVICE_HIGH: usize = 0x0a4;
const REG_CONFIG_GENERATION: usize = 0x0fc;
const REG_CONFIG_SPACE: usize = 0x100;

const QUEUE_MAX: u16 = 256;
const ERR_UNINITIALIZED: &str = "virtio-blk: uninitialized";

static VIRTIO_BLK: SpinLock<Option<VirtioBlkDevice>> = SpinLock::new(None);

pub(crate) struct VirtioBlkBackend {
    dev: &'static dyn BlockDevice,
    capacity_sectors: u64,
    read_only: bool,
}

impl VirtioBlkBackend {
    fn new(dev: &'static dyn BlockDevice) -> Result<Self, &'static str> {
        if dev.block_size() != SECTOR_SIZE {
            return Err("virtio-blk: backend block size must be 512 bytes");
        }
        let read_only = dev
            .is_read_only()
            .map_err(|_| "virtio-blk: failed to query read-only state")?;
        Ok(Self {
            dev,
            capacity_sectors: dev.num_blocks(),
            read_only,
        })
    }

    pub(crate) fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), IoError> {
        self.validate_range(lba, dst.len())?;
        // SAFETY: `MaybeUninit<u8>` has identical layout to `u8`.
        let dst_uninit = unsafe {
            core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut MaybeUninit<u8>, dst.len())
        };
        self.dev.read_at(lba, dst_uninit)
    }

    pub(crate) fn write_sectors(&self, lba: u64, src: &[u8]) -> Result<(), IoError> {
        self.validate_range(lba, src.len())?;
        if self.read_only {
            return Err(IoError::ReadOnly);
        }
        self.dev.write_at(lba, src)
    }

    pub(crate) fn flush(&self) -> Result<(), IoError> {
        self.dev.flush()
    }

    pub(crate) fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn validate_range(&self, lba: u64, bytes: usize) -> Result<(), IoError> {
        if bytes % SECTOR_SIZE != 0 {
            return Err(IoError::Align);
        }
        let sectors = (bytes / SECTOR_SIZE) as u64;
        if lba
            .checked_add(sectors)
            .filter(|end| *end <= self.capacity_sectors)
            .is_none()
        {
            return Err(IoError::OutOfRange);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct QueueState {
    size: u16,
    ready: bool,
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    last_avail_idx: u16,
    used_idx: u16,
}

impl QueueState {
    const fn new() -> Self {
        Self {
            size: 0,
            ready: false,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            last_avail_idx: 0,
            used_idx: 0,
        }
    }

    fn reset_runtime(&mut self) {
        self.ready = false;
        self.last_avail_idx = 0;
        self.used_idx = 0;
    }

    fn reset_all(&mut self) {
        self.size = 0;
        self.desc_addr = 0;
        self.avail_addr = 0;
        self.used_addr = 0;
        self.reset_runtime();
    }
}

struct VirtioBlkDevice {
    backend: VirtioBlkBackend,
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    queue: QueueState,
    interrupt_status: u32,
    config_generation: u32,
}

impl VirtioBlkDevice {
    fn new(backend: VirtioBlkBackend) -> Self {
        Self {
            backend,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            queue: QueueState::new(),
            interrupt_status: 0,
            config_generation: 0,
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = 0;
        self.queue_sel = 0;
        self.queue.reset_all();
        self.interrupt_status = 0;
    }

    fn mmio_read(&mut self, offset: usize, size: u8) -> Result<u64, &'static str> {
        if offset < REG_CONFIG_SPACE {
            validate_register_access(offset, size)?;
        } else {
            validate_config_access(offset, size)?;
        }

        let value = match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC_VALUE as u64,
            REG_VERSION => VIRTIO_MMIO_VERSION_MODERN as u64,
            REG_DEVICE_ID => VIRTIO_MMIO_DEVICE_ID_BLOCK as u64,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR_ID as u64,
            REG_DEVICE_FEATURES => {
                let policy = FeaturePolicy {
                    allow_read_only: self.backend.read_only,
                };
                select_feature_bits(device_features(policy), self.device_features_sel) as u64
            }
            REG_DEVICE_FEATURES_SEL => self.device_features_sel as u64,
            REG_DRIVER_FEATURES => {
                select_feature_bits(self.driver_features, self.driver_features_sel) as u64
            }
            REG_DRIVER_FEATURES_SEL => self.driver_features_sel as u64,
            REG_QUEUE_SEL => self.queue_sel as u64,
            REG_QUEUE_NUM_MAX => {
                if self.queue_sel == 0 {
                    QUEUE_MAX as u64
                } else {
                    0
                }
            }
            REG_QUEUE_NUM => {
                if self.queue_sel == 0 {
                    self.queue.size as u64
                } else {
                    0
                }
            }
            REG_QUEUE_READY => {
                if self.queue_sel == 0 && self.queue.ready {
                    1
                } else {
                    0
                }
            }
            REG_INTERRUPT_STATUS => self.interrupt_status as u64,
            REG_STATUS => self.status as u64,
            REG_QUEUE_DESC_LOW => {
                if self.queue_sel == 0 {
                    self.queue.desc_addr as u32 as u64
                } else {
                    0
                }
            }
            REG_QUEUE_DESC_HIGH => {
                if self.queue_sel == 0 {
                    (self.queue.desc_addr >> 32) as u32 as u64
                } else {
                    0
                }
            }
            REG_QUEUE_DRIVER_LOW => {
                if self.queue_sel == 0 {
                    self.queue.avail_addr as u32 as u64
                } else {
                    0
                }
            }
            REG_QUEUE_DRIVER_HIGH => {
                if self.queue_sel == 0 {
                    (self.queue.avail_addr >> 32) as u32 as u64
                } else {
                    0
                }
            }
            REG_QUEUE_DEVICE_LOW => {
                if self.queue_sel == 0 {
                    self.queue.used_addr as u32 as u64
                } else {
                    0
                }
            }
            REG_QUEUE_DEVICE_HIGH => {
                if self.queue_sel == 0 {
                    (self.queue.used_addr >> 32) as u32 as u64
                } else {
                    0
                }
            }
            REG_CONFIG_GENERATION => self.config_generation as u64,
            _ if offset >= REG_CONFIG_SPACE => self.read_config(offset, size)?,
            _ => 0,
        };
        Ok(value)
    }

    fn mmio_write(&mut self, offset: usize, size: u8, value: u64) -> Result<(), &'static str> {
        if offset < REG_CONFIG_SPACE {
            validate_register_access(offset, size)?;
        } else {
            validate_config_access(offset, size)?;
            return Err("virtio-blk: config is read-only");
        }
        let value = u32::try_from(value).map_err(|_| "virtio-blk: write value overflow")?;

        match offset {
            REG_DEVICE_FEATURES_SEL => self.device_features_sel = value,
            REG_DRIVER_FEATURES => {
                self.driver_features =
                    merge_driver_features(self.driver_features, self.driver_features_sel, value)
                        .map_err(map_mmio_access_error)?;
            }
            REG_DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            REG_QUEUE_SEL => self.queue_sel = value,
            REG_QUEUE_NUM => {
                if self.queue_sel != 0 {
                    return Err("virtio-blk: only queue 0 is supported");
                }
                let queue_size =
                    u16::try_from(value).map_err(|_| "virtio-blk: invalid queue size")?;
                validate_queue_size(queue_size, QUEUE_MAX).map_err(map_queue_parse_error)?;
                self.queue.size = queue_size;
            }
            REG_QUEUE_READY => self.set_queue_ready(value)?,
            REG_QUEUE_NOTIFY => self.process_queue_notify(value)?,
            REG_INTERRUPT_ACK => {
                self.interrupt_status = ack_interrupt_bits(self.interrupt_status, value);
            }
            REG_STATUS => self.write_status(value)?,
            REG_QUEUE_DESC_LOW => {
                if self.queue_sel == 0 {
                    self.queue.desc_addr = (self.queue.desc_addr & !0xffff_ffffu64) | value as u64;
                }
            }
            REG_QUEUE_DESC_HIGH => {
                if self.queue_sel == 0 {
                    self.queue.desc_addr =
                        (self.queue.desc_addr & 0xffff_ffffu64) | ((value as u64) << 32);
                }
            }
            REG_QUEUE_DRIVER_LOW => {
                if self.queue_sel == 0 {
                    self.queue.avail_addr =
                        (self.queue.avail_addr & !0xffff_ffffu64) | value as u64;
                }
            }
            REG_QUEUE_DRIVER_HIGH => {
                if self.queue_sel == 0 {
                    self.queue.avail_addr =
                        (self.queue.avail_addr & 0xffff_ffffu64) | ((value as u64) << 32);
                }
            }
            REG_QUEUE_DEVICE_LOW => {
                if self.queue_sel == 0 {
                    self.queue.used_addr = (self.queue.used_addr & !0xffff_ffffu64) | value as u64;
                }
            }
            REG_QUEUE_DEVICE_HIGH => {
                if self.queue_sel == 0 {
                    self.queue.used_addr =
                        (self.queue.used_addr & 0xffff_ffffu64) | ((value as u64) << 32);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn read_config(&self, offset: usize, size: u8) -> Result<u64, &'static str> {
        let cfg_offset = offset
            .checked_sub(REG_CONFIG_SPACE)
            .ok_or("virtio-blk: config offset underflow")?;
        let mut bytes = [0u8; size_of::<VirtioBlkConfig>()];
        bytes[..8].copy_from_slice(&self.backend.capacity_sectors().to_le_bytes());

        let mut value = 0u64;
        for idx in 0..size as usize {
            value |= (bytes[cfg_offset + idx] as u64) << (idx * 8);
        }
        Ok(value)
    }

    fn write_status(&mut self, value: u32) -> Result<(), &'static str> {
        if value == 0 {
            self.reset();
            return Ok(());
        }
        self.status = value;
        if (self.status & VIRTIO_STATUS_FEATURES_OK) != 0 {
            let policy = FeaturePolicy {
                allow_read_only: self.backend.read_only,
            };
            let device = device_features(policy);
            if validate_negotiated_features(device, self.driver_features).is_err() {
                self.status &= !VIRTIO_STATUS_FEATURES_OK;
            }
        }
        Ok(())
    }

    fn set_queue_ready(&mut self, value: u32) -> Result<(), &'static str> {
        if self.queue_sel != 0 {
            return Err("virtio-blk: only queue 0 is supported");
        }
        match value {
            0 => {
                self.queue.reset_runtime();
                Ok(())
            }
            1 => {
                validate_queue_size(self.queue.size, QUEUE_MAX).map_err(map_queue_parse_error)?;
                if self.queue.desc_addr == 0
                    || self.queue.avail_addr == 0
                    || self.queue.used_addr == 0
                {
                    return Err("virtio-blk: queue address is not configured");
                }
                self.queue.ready = true;
                self.queue.last_avail_idx = read_guest_u16(self.queue.avail_addr + 2)?;
                self.queue.used_idx = read_guest_u16(self.queue.used_addr + 2)?;
                Ok(())
            }
            _ => Err("virtio-blk: queue_ready accepts only 0 or 1"),
        }
    }

    fn process_queue_notify(&mut self, queue_index: u32) -> Result<(), &'static str> {
        if queue_index != 0 {
            return Err("virtio-blk: only queue 0 notify is supported");
        }
        if !self.queue.ready {
            return Err("virtio-blk: queue is not ready");
        }
        if (self.status & VIRTIO_STATUS_DRIVER_OK) == 0 {
            return Err("virtio-blk: driver is not ready");
        }

        let avail_idx = read_guest_u16(self.queue.avail_addr + 2)?;
        let pending = avail_idx.wrapping_sub(self.queue.last_avail_idx);
        if pending == 0 {
            return Ok(());
        }
        if pending as u32 > self.queue.size as u32 {
            return Err("virtio-blk: avail ring overrun");
        }

        for _ in 0..pending {
            let ring_index = calc_ring_index(self.queue.last_avail_idx, self.queue.size)
                .map_err(map_queue_parse_error)?;
            let ring_addr = avail_ring_entry_addr(self.queue.avail_addr, ring_index);
            let head = read_guest_u16(ring_addr)?;
            let outcome = self.process_one_request(head)?;

            if let Some(status_addr) = outcome.status_addr {
                write_guest_u8(status_addr, outcome.status)?;
            }
            let update = used_update(
                self.queue.used_addr,
                self.queue.size,
                self.queue.used_idx,
                head,
                outcome.used_len,
            )
            .map_err(map_queue_parse_error)?;
            write_guest_u32(update.used_elem_addr, update.id)?;
            write_guest_u32(
                update
                    .used_elem_addr
                    .checked_add(4)
                    .ok_or("virtio-blk: used elem overflow")?,
                update.len,
            )?;
            write_guest_u16(update.used_idx_addr, update.new_used_idx)?;
            self.queue.used_idx = update.new_used_idx;
            self.queue.last_avail_idx = self.queue.last_avail_idx.wrapping_add(1);
        }

        core::sync::atomic::fence(Ordering::Release);
        self.interrupt_status |= VIRTIO_INT_USED_RING;
        self.signal_used_interrupt()
    }

    fn process_one_request(&self, head: u16) -> Result<RequestOutcome, &'static str> {
        let status_addr_hint = self.find_status_addr_best_effort(head)?;

        let mut desc_reader =
            |idx: u16| read_descriptor(self.queue.desc_addr, self.queue.size, idx).ok();
        let mut req_reader = |addr: u64| read_req_header(addr).ok();
        let parsed = parse_req_layout(self.queue.size, head, &mut desc_reader, &mut req_reader);
        let layout = match parsed {
            Ok(layout) => layout,
            Err(err) => {
                return Ok(RequestOutcome {
                    status: parse_error_status(err),
                    status_addr: status_addr_hint,
                    used_len: 0,
                });
            }
        };
        Ok(self.execute_request(&layout))
    }

    fn execute_request(&self, layout: &VirtioBlkReqLayout) -> RequestOutcome {
        match layout.req_type {
            VIRTIO_BLK_T_IN => {
                let io_res = with_guest_mut_bytes(layout.data_addr, layout.data_len, |dst| {
                    self.backend.read_sectors(layout.sector, dst)
                });
                map_io_to_outcome(layout, io_res, layout.data_len)
            }
            VIRTIO_BLK_T_OUT => {
                let io_res = with_guest_bytes(layout.data_addr, layout.data_len, |src| {
                    self.backend.write_sectors(layout.sector, src)
                });
                map_io_to_outcome(layout, io_res, layout.data_len)
            }
            VIRTIO_BLK_T_FLUSH => {
                let io_res = self.backend.flush();
                map_io_to_outcome(layout, io_res, 0)
            }
            _ => RequestOutcome {
                status: VIRTIO_BLK_S_UNSUPP,
                status_addr: Some(layout.status_addr),
                used_len: 0,
            },
        }
    }

    fn find_status_addr_best_effort(&self, head: u16) -> Result<Option<u64>, &'static str> {
        if head >= self.queue.size {
            return Ok(None);
        }
        let first = read_descriptor(self.queue.desc_addr, self.queue.size, head)?;
        if (first.flags & VIRTQ_DESC_F_NEXT) == 0 {
            return Ok(None);
        }
        let second = read_descriptor(self.queue.desc_addr, self.queue.size, first.next)?;
        if (second.flags & VIRTQ_DESC_F_NEXT) == 0 {
            if (second.flags & VIRTQ_DESC_F_WRITE) != 0 && second.len == 1 {
                return Ok(Some(second.addr));
            }
            return Ok(None);
        }
        let third = read_descriptor(self.queue.desc_addr, self.queue.size, second.next)?;
        if (third.flags & VIRTQ_DESC_F_WRITE) != 0 && third.len == 1 {
            Ok(Some(third.addr))
        } else {
            Ok(None)
        }
    }

    fn signal_used_interrupt(&self) -> Result<(), &'static str> {
        vgic::inject_virtual_spi(VIRTIO_BLK_IRQ, true)
            .map_err(|_| "virtio-blk: IRQ injection failed")
    }
}

struct RequestOutcome {
    status: u8,
    status_addr: Option<u64>,
    used_len: u32,
}

fn map_io_to_outcome(
    layout: &VirtioBlkReqLayout,
    io: Result<(), IoError>,
    success_len: u32,
) -> RequestOutcome {
    match io {
        Ok(()) => RequestOutcome {
            status: VIRTIO_BLK_S_OK,
            status_addr: Some(layout.status_addr),
            used_len: success_len,
        },
        Err(IoError::Unsupported) => RequestOutcome {
            status: VIRTIO_BLK_S_UNSUPP,
            status_addr: Some(layout.status_addr),
            used_len: 0,
        },
        Err(_) => RequestOutcome {
            status: VIRTIO_BLK_S_IOERR,
            status_addr: Some(layout.status_addr),
            used_len: 0,
        },
    }
}

fn parse_error_status(err: QueueParseError) -> u8 {
    match err {
        QueueParseError::InvalidRequestType => VIRTIO_BLK_S_UNSUPP,
        _ => VIRTIO_BLK_S_IOERR,
    }
}

fn validate_register_access(offset: usize, size: u8) -> Result<(), &'static str> {
    if size != 4 {
        return Err("virtio-blk: only 32-bit register access is supported");
    }
    if (offset & 0x3) != 0 {
        return Err("virtio-blk: register access must be 32-bit aligned");
    }
    Ok(())
}

fn validate_config_access(offset: usize, size: u8) -> Result<(), &'static str> {
    if !matches!(size, 1 | 2 | 4) {
        return Err("virtio-blk: config access size must be 8/16/32-bit");
    }
    let cfg_offset = offset
        .checked_sub(REG_CONFIG_SPACE)
        .ok_or("virtio-blk: config offset underflow")?;
    let end = cfg_offset
        .checked_add(size as usize)
        .ok_or("virtio-blk: config access overflow")?;
    if end > size_of::<VirtioBlkConfig>() {
        return Err("virtio-blk: config access out of range");
    }
    Ok(())
}

fn map_mmio_access_error(err: MmioAccessError) -> &'static str {
    match err {
        MmioAccessError::InvalidSize => "virtio-blk: invalid MMIO access size",
        MmioAccessError::InvalidOffset => "virtio-blk: invalid MMIO register offset",
        MmioAccessError::InvalidValue => "virtio-blk: invalid MMIO register value",
        MmioAccessError::QueueNotReady => "virtio-blk: queue is not ready",
    }
}

fn map_queue_parse_error(err: QueueParseError) -> &'static str {
    match err {
        QueueParseError::InvalidQueueSize => "virtio-blk: invalid queue size",
        QueueParseError::InvalidChain => "virtio-blk: invalid descriptor chain",
        QueueParseError::DescriptorLoop => "virtio-blk: descriptor loop detected",
        QueueParseError::IndirectUnsupported => "virtio-blk: indirect descriptors are unsupported",
        QueueParseError::OutOfRange => "virtio-blk: descriptor index out of range",
        QueueParseError::MissingStatus => "virtio-blk: status descriptor is missing",
        QueueParseError::InvalidRequestType => "virtio-blk: unsupported request type",
        QueueParseError::InvalidLayout => "virtio-blk: invalid request layout",
        QueueParseError::Align => "virtio-blk: request buffer alignment error",
    }
}

fn with_guest_mut_bytes(
    addr: u64,
    len: u32,
    f: impl FnOnce(&mut [u8]) -> Result<(), IoError>,
) -> Result<(), IoError> {
    let len = usize::try_from(len).map_err(|_| IoError::InvalidParam)?;
    // SAFETY: The guest provides IPA==PA buffers for virtqueue payloads. EL2 only creates
    // temporary byte slices to pass into backend I/O and never keeps references beyond this call.
    let buf = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) };
    f(buf)
}

fn with_guest_bytes(
    addr: u64,
    len: u32,
    f: impl FnOnce(&[u8]) -> Result<(), IoError>,
) -> Result<(), IoError> {
    let len = usize::try_from(len).map_err(|_| IoError::InvalidParam)?;
    // SAFETY: The guest provides IPA==PA buffers for virtqueue payloads. EL2 only creates
    // temporary byte slices to pass into backend I/O and never keeps references beyond this call.
    let buf = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
    f(buf)
}

fn read_guest_bytes(addr: u64, out: &mut [u8]) -> Result<(), &'static str> {
    for (idx, byte) in out.iter_mut().enumerate() {
        let byte_addr = addr
            .checked_add(idx as u64)
            .ok_or("virtio-blk: guest address overflow")?;
        // SAFETY: EL2 intentionally performs volatile byte reads from guest-provided IPA==PA
        // buffers while emulating virtqueue metadata.
        *byte = unsafe { read_volatile(byte_addr as *const u8) };
    }
    Ok(())
}

fn write_guest_bytes(addr: u64, value: &[u8]) -> Result<(), &'static str> {
    for (idx, byte) in value.iter().enumerate() {
        let byte_addr = addr
            .checked_add(idx as u64)
            .ok_or("virtio-blk: guest address overflow")?;
        // SAFETY: EL2 intentionally performs volatile byte writes to guest-provided IPA==PA
        // buffers while emulating virtqueue used ring and request status.
        unsafe { write_volatile(byte_addr as *mut u8, *byte) };
    }
    Ok(())
}

fn read_guest_u16(addr: u64) -> Result<u16, &'static str> {
    let mut bytes = [0u8; 2];
    read_guest_bytes(addr, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn write_guest_u16(addr: u64, value: u16) -> Result<(), &'static str> {
    write_guest_bytes(addr, &value.to_le_bytes())
}

fn write_guest_u32(addr: u64, value: u32) -> Result<(), &'static str> {
    write_guest_bytes(addr, &value.to_le_bytes())
}

fn write_guest_u8(addr: u64, value: u8) -> Result<(), &'static str> {
    write_guest_bytes(addr, &[value])
}

fn read_descriptor(desc_addr: u64, queue_size: u16, idx: u16) -> Result<VirtqDesc, &'static str> {
    if idx >= queue_size {
        return Err("virtio-blk: descriptor index out of range");
    }
    let offset = (idx as u64)
        .checked_mul(size_of::<VirtqDesc>() as u64)
        .ok_or("virtio-blk: descriptor offset overflow")?;
    let addr = desc_addr
        .checked_add(offset)
        .ok_or("virtio-blk: descriptor address overflow")?;
    let mut bytes = [0u8; size_of::<VirtqDesc>()];
    read_guest_bytes(addr, &mut bytes)?;
    Ok(VirtqDesc {
        addr: u64::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| "virtio-blk: invalid descriptor address bytes")?,
        ),
        len: u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| "virtio-blk: invalid descriptor length bytes")?,
        ),
        flags: u16::from_le_bytes(
            bytes[12..14]
                .try_into()
                .map_err(|_| "virtio-blk: invalid descriptor flags bytes")?,
        ),
        next: u16::from_le_bytes(
            bytes[14..16]
                .try_into()
                .map_err(|_| "virtio-blk: invalid descriptor next bytes")?,
        ),
    })
}

fn read_req_header(addr: u64) -> Result<VirtioBlkReq, &'static str> {
    let mut bytes = [0u8; size_of::<VirtioBlkReq>()];
    read_guest_bytes(addr, &mut bytes)?;
    Ok(VirtioBlkReq {
        req_type: u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| "virtio-blk: invalid request type bytes")?,
        ),
        reserved: u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| "virtio-blk: invalid request reserved bytes")?,
        ),
        sector: u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| "virtio-blk: invalid request sector bytes")?,
        ),
    })
}

pub(crate) fn is_uninitialized_error(err: &'static str) -> bool {
    err == ERR_UNINITIALIZED
}

pub(crate) fn is_initialized() -> bool {
    VIRTIO_BLK.lock().is_some()
}

pub(crate) fn init_with_backend(dev: &'static dyn BlockDevice) -> Result<(), &'static str> {
    let backend = VirtioBlkBackend::new(dev)?;
    let mut guard = VIRTIO_BLK.lock();
    if guard.is_some() {
        return Err("virtio-blk: backend is already initialized");
    }
    *guard = Some(VirtioBlkDevice::new(backend));
    Ok(())
}

pub(crate) fn handles_mmio(addr: usize) -> bool {
    let Some(end) = VIRTIO_BLK_MMIO_BASE.checked_add(VIRTIO_BLK_MMIO_SIZE) else {
        return false;
    };
    (VIRTIO_BLK_MMIO_BASE..end).contains(&addr)
}

pub(crate) fn handle_mmio_read(addr: usize, size: u8) -> Result<u64, &'static str> {
    if !handles_mmio(addr) {
        return Err("virtio-blk: MMIO read address is outside the virtio-blk window");
    }
    let mut guard = VIRTIO_BLK.lock();
    let device = guard.as_mut().ok_or(ERR_UNINITIALIZED)?;
    let offset = addr
        .checked_sub(VIRTIO_BLK_MMIO_BASE)
        .ok_or("virtio-blk: MMIO read offset underflow")?;
    device.mmio_read(offset, size)
}

pub(crate) fn handle_mmio_write(addr: usize, size: u8, value: u64) -> Result<(), &'static str> {
    if !handles_mmio(addr) {
        return Err("virtio-blk: MMIO write address is outside the virtio-blk window");
    }
    let mut guard = VIRTIO_BLK.lock();
    let device = guard.as_mut().ok_or(ERR_UNINITIALIZED)?;
    let offset = addr
        .checked_sub(VIRTIO_BLK_MMIO_BASE)
        .ok_or("virtio-blk: MMIO write offset underflow")?;
    device.mmio_write(offset, size, value)
}
