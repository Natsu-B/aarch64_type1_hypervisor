use block_device_api::BlockDevice;
use block_device_api::IoError;
use block_device_api::virtio_blk_mmio::VirtioBlkMmioDevice;
use block_device_api::virtio_blk_mmio::VirtioBlkMmioError;
use block_device_api::virtio_blk_mmio::VirtioBlkMmioGuestMemory;
use block_device_api::virtio_blk_mmio::VirtioBlkMmioInterrupt;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use mutex::SpinLock;

use crate::vgic;

pub(crate) const VIRTIO_BLK_MMIO_BASE: usize = 0x10_7c10_0000;
pub(crate) const VIRTIO_BLK_MMIO_SIZE: usize = 0x1000;
pub(crate) const VIRTIO_BLK_IRQ_INTID: u32 = 275;

const ERR_UNINITIALIZED: &str = "virtio-blk: uninitialized";

type RpiVirtioBlkDevice =
    VirtioBlkMmioDevice<'static, dyn BlockDevice, GuestMemoryIdentity, VgicInterruptSink>;

static VIRTIO_BLK: SpinLock<Option<RpiVirtioBlkDevice>> = SpinLock::new(None);

struct GuestMemoryIdentity;
struct VgicInterruptSink;

fn checked_guest_base(addr: u64, len: usize) -> Result<usize, VirtioBlkMmioError> {
    let base = usize::try_from(addr)
        .map_err(|_| VirtioBlkMmioError::GuestMemory("virtio-blk: guest address overflow"))?;
    base.checked_add(len)
        .ok_or(VirtioBlkMmioError::GuestMemory(
            "virtio-blk: guest address overflow",
        ))?;
    Ok(base)
}

impl VirtioBlkMmioGuestMemory for GuestMemoryIdentity {
    fn read(&self, addr: u64, out: &mut [u8]) -> Result<(), VirtioBlkMmioError> {
        let base = checked_guest_base(addr, out.len())?;
        for (idx, byte) in out.iter_mut().enumerate() {
            // SAFETY: EL2 intentionally performs volatile byte reads from guest-provided IPA==PA
            // buffers after checked address arithmetic while emulating virtqueue metadata.
            *byte = unsafe { read_volatile((base + idx) as *const u8) };
        }
        Ok(())
    }

    fn write(&self, addr: u64, value: &[u8]) -> Result<(), VirtioBlkMmioError> {
        let base = checked_guest_base(addr, value.len())?;
        for (idx, byte) in value.iter().enumerate() {
            // SAFETY: EL2 intentionally performs volatile byte writes to guest-provided IPA==PA
            // buffers after checked address arithmetic while emulating used-ring and status updates.
            unsafe { write_volatile((base + idx) as *mut u8, *byte) };
        }
        Ok(())
    }

    fn with_read_buffer<F>(&self, addr: u64, len: usize, f: F) -> Result<(), VirtioBlkMmioError>
    where
        F: FnOnce(&[u8]) -> Result<(), IoError>,
    {
        let base = checked_guest_base(addr, len)?;
        // SAFETY: The guest payload buffer lies in the identity-mapped IPA==PA space, the range
        // was overflow-checked above, and the immutable borrow lives only for this synchronous call.
        let buf = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
        f(buf).map_err(VirtioBlkMmioError::Backend)
    }

    fn with_write_buffer<F>(&self, addr: u64, len: usize, f: F) -> Result<(), VirtioBlkMmioError>
    where
        F: FnOnce(&mut [u8]) -> Result<(), IoError>,
    {
        let base = checked_guest_base(addr, len)?;
        // SAFETY: The guest payload buffer lies in the identity-mapped IPA==PA space, the range
        // was overflow-checked above, and the mutable borrow lives only for this synchronous call.
        let buf = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
        f(buf).map_err(VirtioBlkMmioError::Backend)
    }
}

impl VirtioBlkMmioInterrupt for VgicInterruptSink {
    fn set_irq_level(&self, asserted: bool) -> Result<(), VirtioBlkMmioError> {
        vgic::inject_virtual_spi(VIRTIO_BLK_IRQ_INTID, asserted)
            .map_err(|_| VirtioBlkMmioError::Interrupt("virtio-blk: IRQ injection failed"))
    }
}

pub(crate) fn init_with_backend(dev: &'static dyn BlockDevice) -> Result<(), &'static str> {
    let device = VirtioBlkMmioDevice::new(dev, GuestMemoryIdentity, VgicInterruptSink)
        .map_err(map_mmio_error)?;
    let mut guard = VIRTIO_BLK.lock();
    if guard.is_some() {
        return Err("virtio-blk: backend is already initialized");
    }
    *guard = Some(device);
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
    device.mmio_read(offset, size).map_err(map_mmio_error)
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
    device
        .mmio_write(offset, size, value)
        .map_err(map_mmio_error)
}

fn map_mmio_error(err: VirtioBlkMmioError) -> &'static str {
    err.as_str()
}
