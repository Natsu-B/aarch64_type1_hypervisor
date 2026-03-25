#![allow(clippy::identity_op)]

#[cfg(test)]
extern crate std;

use crate::BlockDevice;
use crate::IoError;
use core::mem::MaybeUninit;
use core::mem::size_of;

pub const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
pub const VIRTIO_MMIO_VERSION_MODERN: u32 = 2;
pub const VIRTIO_MMIO_DEVICE_ID_BLOCK: u32 = 2;
pub const VIRTIO_MMIO_VENDOR_ID: u32 = 0x554d_4551; // "QEMU" conventional value

pub const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1 << 0;
pub const VIRTIO_STATUS_DRIVER: u32 = 1 << 1;
pub const VIRTIO_STATUS_DRIVER_OK: u32 = 1 << 2;
pub const VIRTIO_STATUS_FEATURES_OK: u32 = 1 << 3;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u32 = 1 << 6;
pub const VIRTIO_STATUS_FAILED: u32 = 1 << 7;

pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;
pub const VIRTIO_BLK_F_RO: u64 = 1u64 << 5;

pub const VIRTIO_INT_USED_RING: u32 = 1 << 0;

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const SECTOR_SIZE: usize = 512;
pub const SECTOR_SIZE_U64: u64 = 512;

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

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtioBlkReq {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtioBlkConfig {
    pub capacity: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

const _: () = assert!(size_of::<VirtioBlkReq>() == 16);
const _: () = assert!(size_of::<VirtqDesc>() == 16);
const _: () = assert!(size_of::<VirtqUsedElem>() == 8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioAccessError {
    InvalidSize,
    InvalidOffset,
    InvalidValue,
    QueueNotReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueParseError {
    InvalidQueueSize,
    InvalidChain,
    DescriptorLoop,
    IndirectUnsupported,
    OutOfRange,
    MissingStatus,
    InvalidRequestType,
    InvalidLayout,
    Align,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioBlkReqLayout {
    pub header_addr: u64,
    pub data_addr: u64,
    pub data_len: u32,
    pub status_addr: u64,
    pub req_type: u32,
    pub sector: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsedRingUpdate {
    pub used_elem_addr: u64,
    pub used_idx_addr: u64,
    pub ring_index: u16,
    pub new_used_idx: u16,
    pub id: u32,
    pub len: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct FeaturePolicy {
    pub allow_read_only: bool,
}

pub const fn device_features(policy: FeaturePolicy) -> u64 {
    let mut features = VIRTIO_F_VERSION_1;
    if policy.allow_read_only {
        features |= VIRTIO_BLK_F_RO;
    }
    features
}

pub fn select_feature_bits(features: u64, sel: u32) -> u32 {
    match sel {
        0 => features as u32,
        1 => (features >> 32) as u32,
        _ => 0,
    }
}

pub fn merge_driver_features(old: u64, sel: u32, value: u32) -> Result<u64, MmioAccessError> {
    match sel {
        0 => Ok((old & !0xffff_ffffu64) | value as u64),
        1 => Ok((old & 0xffff_ffffu64) | ((value as u64) << 32)),
        _ => Err(MmioAccessError::InvalidValue),
    }
}

pub fn validate_negotiated_features(device: u64, driver: u64) -> Result<(), MmioAccessError> {
    if (driver & !device) != 0 {
        return Err(MmioAccessError::InvalidValue);
    }
    if (driver & VIRTIO_F_VERSION_1) == 0 {
        return Err(MmioAccessError::InvalidValue);
    }
    Ok(())
}

pub fn ack_interrupt_bits(old: u32, ack: u32) -> u32 {
    old & !ack
}

pub fn validate_queue_size(size: u16, queue_max: u16) -> Result<(), QueueParseError> {
    if size == 0 || size > queue_max {
        return Err(QueueParseError::InvalidQueueSize);
    }
    if !size.is_power_of_two() {
        return Err(QueueParseError::InvalidQueueSize);
    }
    Ok(())
}

pub fn desc_table_len_bytes(queue_size: u16) -> u64 {
    queue_size as u64 * size_of::<VirtqDesc>() as u64
}

pub fn avail_ring_len_bytes(queue_size: u16) -> u64 {
    (size_of::<VirtqAvail>() + queue_size as usize * size_of::<u16>()) as u64
}

pub fn used_ring_len_bytes(queue_size: u16) -> u64 {
    (size_of::<VirtqUsed>() + queue_size as usize * size_of::<VirtqUsedElem>()) as u64
}

pub fn avail_ring_entry_addr(avail_addr: u64, ring_index: u16) -> u64 {
    avail_addr + size_of::<VirtqAvail>() as u64 + ring_index as u64 * size_of::<u16>() as u64
}

pub fn used_ring_entry_addr(used_addr: u64, ring_index: u16) -> u64 {
    used_addr
        + size_of::<VirtqUsed>() as u64
        + ring_index as u64 * size_of::<VirtqUsedElem>() as u64
}

pub fn used_ring_idx_addr(used_addr: u64) -> u64 {
    used_addr + 2
}

pub fn next_avail_to_process(last_avail_idx: u16, avail_idx: u16) -> Result<u16, QueueParseError> {
    let delta = avail_idx.wrapping_sub(last_avail_idx);
    if delta == 0 {
        return Err(QueueParseError::OutOfRange);
    }
    Ok(last_avail_idx)
}

pub fn calc_ring_index(idx: u16, queue_size: u16) -> Result<u16, QueueParseError> {
    validate_queue_size(queue_size, queue_size)?;
    Ok(idx & (queue_size - 1))
}

pub fn check_aligned_sector_buffer(len: u32) -> Result<(), QueueParseError> {
    if len == 0 {
        return Ok(());
    }
    if (len as usize) % SECTOR_SIZE != 0 {
        return Err(QueueParseError::Align);
    }
    Ok(())
}

pub fn classify_io_status(io_unsupported: bool, ok: bool) -> u8 {
    if ok {
        VIRTIO_BLK_S_OK
    } else if io_unsupported {
        VIRTIO_BLK_S_UNSUPP
    } else {
        VIRTIO_BLK_S_IOERR
    }
}

pub fn used_update(
    used_addr: u64,
    queue_size: u16,
    used_idx_before: u16,
    head_id: u16,
    used_len: u32,
) -> Result<UsedRingUpdate, QueueParseError> {
    validate_queue_size(queue_size, queue_size)?;
    let ring_index = used_idx_before & (queue_size - 1);
    Ok(UsedRingUpdate {
        used_elem_addr: used_ring_entry_addr(used_addr, ring_index),
        used_idx_addr: used_ring_idx_addr(used_addr),
        ring_index,
        new_used_idx: used_idx_before.wrapping_add(1),
        id: head_id as u32,
        len: used_len,
    })
}

pub fn parse_req_layout(
    queue_size: u16,
    head: u16,
    desc_at: &mut dyn FnMut(u16) -> Option<VirtqDesc>,
    read_req_header: &mut dyn FnMut(u64) -> Option<VirtioBlkReq>,
) -> Result<VirtioBlkReqLayout, QueueParseError> {
    validate_queue_size(queue_size, queue_size)?;
    if head >= queue_size {
        return Err(QueueParseError::OutOfRange);
    }

    let mut visited = 0u16;
    let mut cur = head;
    let mut chain: [VirtqDesc; 3] = [VirtqDesc::default(); 3];
    let mut chain_len = 0usize;

    loop {
        if visited >= queue_size {
            return Err(QueueParseError::DescriptorLoop);
        }
        visited = visited.wrapping_add(1);

        let desc = desc_at(cur).ok_or(QueueParseError::OutOfRange)?;
        if (desc.flags & VIRTQ_DESC_F_INDIRECT) != 0 {
            return Err(QueueParseError::IndirectUnsupported);
        }
        if chain_len >= chain.len() {
            return Err(QueueParseError::InvalidChain);
        }
        chain[chain_len] = desc;
        chain_len += 1;

        if (desc.flags & VIRTQ_DESC_F_NEXT) == 0 {
            break;
        }
        cur = desc.next;
        if cur >= queue_size {
            return Err(QueueParseError::OutOfRange);
        }
    }

    if chain_len < 2 || chain_len > 3 {
        return Err(QueueParseError::InvalidLayout);
    }

    let header = chain[0];
    if (header.flags & VIRTQ_DESC_F_WRITE) != 0 {
        return Err(QueueParseError::InvalidLayout);
    }
    if header.len < size_of::<VirtioBlkReq>() as u32 {
        return Err(QueueParseError::InvalidLayout);
    }
    let req = read_req_header(header.addr).ok_or(QueueParseError::InvalidLayout)?;
    let req_type = req.req_type;
    if req_type != VIRTIO_BLK_T_IN && req_type != VIRTIO_BLK_T_OUT && req_type != VIRTIO_BLK_T_FLUSH
    {
        return Err(QueueParseError::InvalidRequestType);
    }

    if chain_len == 2 {
        if req_type != VIRTIO_BLK_T_FLUSH {
            return Err(QueueParseError::InvalidLayout);
        }
        let status = chain[1];
        if (status.flags & VIRTQ_DESC_F_WRITE) == 0 || status.len != 1 {
            return Err(QueueParseError::MissingStatus);
        }
        return Ok(VirtioBlkReqLayout {
            header_addr: header.addr,
            data_addr: 0,
            data_len: 0,
            status_addr: status.addr,
            req_type,
            sector: req.sector,
        });
    }

    let data = chain[1];
    let status = chain[2];
    if (status.flags & VIRTQ_DESC_F_WRITE) == 0 || status.len != 1 {
        return Err(QueueParseError::MissingStatus);
    }
    match req_type {
        VIRTIO_BLK_T_IN => {
            if (data.flags & VIRTQ_DESC_F_WRITE) == 0 {
                return Err(QueueParseError::InvalidLayout);
            }
            check_aligned_sector_buffer(data.len)?;
        }
        VIRTIO_BLK_T_OUT => {
            if (data.flags & VIRTQ_DESC_F_WRITE) != 0 {
                return Err(QueueParseError::InvalidLayout);
            }
            check_aligned_sector_buffer(data.len)?;
        }
        VIRTIO_BLK_T_FLUSH => return Err(QueueParseError::InvalidLayout),
        _ => return Err(QueueParseError::InvalidRequestType),
    }

    Ok(VirtioBlkReqLayout {
        header_addr: header.addr,
        data_addr: data.addr,
        data_len: data.len,
        status_addr: status.addr,
        req_type,
        sector: req.sector,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioBlkMmioError {
    Access(MmioAccessError),
    Queue(QueueParseError),
    Backend(IoError),
    GuestMemory(&'static str),
    Interrupt(&'static str),
    InvalidState(&'static str),
}

impl VirtioBlkMmioError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Access(MmioAccessError::InvalidSize) => "virtio-blk: invalid MMIO access size",
            Self::Access(MmioAccessError::InvalidOffset) => {
                "virtio-blk: invalid MMIO register offset"
            }
            Self::Access(MmioAccessError::InvalidValue) => {
                "virtio-blk: invalid MMIO register value"
            }
            Self::Access(MmioAccessError::QueueNotReady) => "virtio-blk: queue is not ready",
            Self::Queue(QueueParseError::InvalidQueueSize) => "virtio-blk: invalid queue size",
            Self::Queue(QueueParseError::InvalidChain) => "virtio-blk: invalid descriptor chain",
            Self::Queue(QueueParseError::DescriptorLoop) => "virtio-blk: descriptor loop detected",
            Self::Queue(QueueParseError::IndirectUnsupported) => {
                "virtio-blk: indirect descriptors are unsupported"
            }
            Self::Queue(QueueParseError::OutOfRange) => "virtio-blk: descriptor index out of range",
            Self::Queue(QueueParseError::MissingStatus) => {
                "virtio-blk: status descriptor is missing"
            }
            Self::Queue(QueueParseError::InvalidRequestType) => {
                "virtio-blk: unsupported request type"
            }
            Self::Queue(QueueParseError::InvalidLayout) => "virtio-blk: invalid request layout",
            Self::Queue(QueueParseError::Align) => "virtio-blk: request buffer alignment error",
            Self::Backend(IoError::InvalidParam) => {
                "virtio-blk: backend rejected request parameters"
            }
            Self::Backend(IoError::OutOfRange) => "virtio-blk: backend request out of range",
            Self::Backend(IoError::Align) => "virtio-blk: backend alignment error",
            Self::Backend(IoError::Busy) => "virtio-blk: backend busy",
            Self::Backend(IoError::Timeout) => "virtio-blk: backend timeout",
            Self::Backend(IoError::Device) => "virtio-blk: backend device error",
            Self::Backend(IoError::ReadOnly) => "virtio-blk: backend is read-only",
            Self::Backend(IoError::Unsupported) => "virtio-blk: backend operation unsupported",
            Self::Backend(IoError::NoMemory) => "virtio-blk: backend out of memory",
            Self::Backend(IoError::Io) => "virtio-blk: backend I/O error",
            Self::Backend(IoError::Protocol) => "virtio-blk: backend protocol error",
            Self::Backend(IoError::NotReady) => "virtio-blk: backend is not ready",
            Self::Backend(IoError::Corrupted) => "virtio-blk: backend state is corrupted",
            Self::GuestMemory(msg) | Self::Interrupt(msg) | Self::InvalidState(msg) => msg,
        }
    }
}

impl From<MmioAccessError> for VirtioBlkMmioError {
    fn from(value: MmioAccessError) -> Self {
        Self::Access(value)
    }
}

impl From<QueueParseError> for VirtioBlkMmioError {
    fn from(value: QueueParseError) -> Self {
        Self::Queue(value)
    }
}

impl From<IoError> for VirtioBlkMmioError {
    fn from(value: IoError) -> Self {
        Self::Backend(value)
    }
}

pub trait VirtioBlkMmioGuestMemory {
    fn read(&self, addr: u64, out: &mut [u8]) -> Result<(), VirtioBlkMmioError>;

    fn write(&self, addr: u64, value: &[u8]) -> Result<(), VirtioBlkMmioError>;

    fn with_read_buffer<F>(&self, addr: u64, len: usize, f: F) -> Result<(), VirtioBlkMmioError>
    where
        F: FnOnce(&[u8]) -> Result<(), IoError>;

    fn with_write_buffer<F>(&self, addr: u64, len: usize, f: F) -> Result<(), VirtioBlkMmioError>
    where
        F: FnOnce(&mut [u8]) -> Result<(), IoError>;
}

pub trait VirtioBlkMmioInterrupt {
    fn set_irq_level(&self, asserted: bool) -> Result<(), VirtioBlkMmioError>;
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

struct VirtioBlkBackend<'a, B: BlockDevice + ?Sized> {
    dev: &'a B,
    capacity_sectors: u64,
    read_only: bool,
}

impl<'a, B> VirtioBlkBackend<'a, B>
where
    B: BlockDevice + ?Sized,
{
    fn new(dev: &'a B) -> Result<Self, VirtioBlkMmioError> {
        if dev.block_size() != SECTOR_SIZE {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: backend block size must be 512 bytes",
            ));
        }
        let read_only = dev.is_read_only()?;
        Ok(Self {
            dev,
            capacity_sectors: dev.num_blocks(),
            read_only,
        })
    }

    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), VirtioBlkMmioError> {
        self.validate_range(lba, dst.len())?;
        // SAFETY: `MaybeUninit<u8>` has the same layout as `u8`, and the backend contract
        // guarantees that successful reads initialize the full destination buffer.
        let dst_uninit = unsafe {
            core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut MaybeUninit<u8>, dst.len())
        };
        self.dev.read_at(lba, dst_uninit).map_err(Into::into)
    }

    fn write_sectors(&self, lba: u64, src: &[u8]) -> Result<(), VirtioBlkMmioError> {
        self.validate_range(lba, src.len())?;
        if self.read_only {
            return Err(VirtioBlkMmioError::Backend(IoError::ReadOnly));
        }
        self.dev.write_at(lba, src).map_err(Into::into)
    }

    fn flush(&self) -> Result<(), VirtioBlkMmioError> {
        self.dev.flush().map_err(Into::into)
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn validate_range(&self, lba: u64, bytes: usize) -> Result<(), VirtioBlkMmioError> {
        if bytes % SECTOR_SIZE != 0 {
            return Err(VirtioBlkMmioError::Backend(IoError::Align));
        }
        let sectors = (bytes / SECTOR_SIZE) as u64;
        if lba
            .checked_add(sectors)
            .filter(|end| *end <= self.capacity_sectors)
            .is_none()
        {
            return Err(VirtioBlkMmioError::Backend(IoError::OutOfRange));
        }
        Ok(())
    }
}

pub struct VirtioBlkMmioDevice<'a, B, M, I>
where
    B: BlockDevice + ?Sized,
    M: VirtioBlkMmioGuestMemory,
    I: VirtioBlkMmioInterrupt,
{
    backend: VirtioBlkBackend<'a, B>,
    memory: M,
    interrupt: I,
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    queue: QueueState,
    interrupt_status: u32,
    config_generation: u32,
}

impl<'a, B, M, I> VirtioBlkMmioDevice<'a, B, M, I>
where
    B: BlockDevice + ?Sized,
    M: VirtioBlkMmioGuestMemory,
    I: VirtioBlkMmioInterrupt,
{
    pub fn new(backend: &'a B, memory: M, interrupt: I) -> Result<Self, VirtioBlkMmioError> {
        Ok(Self {
            backend: VirtioBlkBackend::new(backend)?,
            memory,
            interrupt,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            queue: QueueState::new(),
            interrupt_status: 0,
            config_generation: 0,
        })
    }

    pub fn mmio_read(&mut self, offset: usize, size: u8) -> Result<u64, VirtioBlkMmioError> {
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

    pub fn mmio_write(
        &mut self,
        offset: usize,
        size: u8,
        value: u64,
    ) -> Result<(), VirtioBlkMmioError> {
        if offset < REG_CONFIG_SPACE {
            validate_register_access(offset, size)?;
        } else {
            validate_config_access(offset, size)?;
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: config is read-only",
            ));
        }
        let value = u32::try_from(value).map_err(|_| MmioAccessError::InvalidValue)?;

        match offset {
            REG_DEVICE_FEATURES_SEL => self.device_features_sel = value,
            REG_DRIVER_FEATURES => {
                self.driver_features =
                    merge_driver_features(self.driver_features, self.driver_features_sel, value)?;
            }
            REG_DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            REG_QUEUE_SEL => self.queue_sel = value,
            REG_QUEUE_NUM => {
                if self.queue_sel != 0 {
                    return Err(VirtioBlkMmioError::InvalidState(
                        "virtio-blk: only queue 0 is supported",
                    ));
                }
                let queue_size = u16::try_from(value).map_err(|_| MmioAccessError::InvalidValue)?;
                validate_queue_size(queue_size, QUEUE_MAX)?;
                self.queue.size = queue_size;
            }
            REG_QUEUE_READY => self.set_queue_ready(value)?,
            REG_QUEUE_NOTIFY => self.process_queue_notify(value)?,
            REG_INTERRUPT_ACK => self.ack_interrupt(value)?,
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

    fn read_config(&self, offset: usize, size: u8) -> Result<u64, VirtioBlkMmioError> {
        let cfg_offset =
            offset
                .checked_sub(REG_CONFIG_SPACE)
                .ok_or(VirtioBlkMmioError::InvalidState(
                    "virtio-blk: config offset underflow",
                ))?;
        let mut bytes = [0u8; size_of::<VirtioBlkConfig>()];
        bytes[..8].copy_from_slice(&self.backend.capacity_sectors().to_le_bytes());

        let mut value = 0u64;
        for idx in 0..size as usize {
            value |= (bytes[cfg_offset + idx] as u64) << (idx * 8);
        }
        Ok(value)
    }

    fn write_status(&mut self, value: u32) -> Result<(), VirtioBlkMmioError> {
        if value == 0 {
            self.reset()?;
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

    fn reset(&mut self) -> Result<(), VirtioBlkMmioError> {
        self.status = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = 0;
        self.queue_sel = 0;
        self.queue.reset_all();
        self.set_interrupt_status(0)
    }

    fn set_queue_ready(&mut self, value: u32) -> Result<(), VirtioBlkMmioError> {
        if self.queue_sel != 0 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: only queue 0 is supported",
            ));
        }
        match value {
            0 => {
                self.queue.reset_runtime();
                Ok(())
            }
            1 => {
                validate_queue_size(self.queue.size, QUEUE_MAX)?;
                if self.queue.desc_addr == 0
                    || self.queue.avail_addr == 0
                    || self.queue.used_addr == 0
                {
                    return Err(VirtioBlkMmioError::InvalidState(
                        "virtio-blk: queue address is not configured",
                    ));
                }
                self.validate_queue_alignment()?;
                self.queue.ready = true;
                self.queue.last_avail_idx = self.read_guest_u16(self.queue.avail_addr + 2)?;
                self.queue.used_idx = self.read_guest_u16(self.queue.used_addr + 2)?;
                Ok(())
            }
            _ => Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: queue_ready accepts only 0 or 1",
            )),
        }
    }

    fn validate_queue_alignment(&self) -> Result<(), VirtioBlkMmioError> {
        if (self.queue.desc_addr & 0xf) != 0 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: descriptor table is not 16-byte aligned",
            ));
        }
        if (self.queue.avail_addr & 0x1) != 0 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: avail ring is not 2-byte aligned",
            ));
        }
        if (self.queue.used_addr & 0x3) != 0 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: used ring is not 4-byte aligned",
            ));
        }
        Ok(())
    }

    fn ack_interrupt(&mut self, ack: u32) -> Result<(), VirtioBlkMmioError> {
        let status = ack_interrupt_bits(self.interrupt_status, ack);
        self.set_interrupt_status(status)
    }

    fn set_interrupt_status(&mut self, status: u32) -> Result<(), VirtioBlkMmioError> {
        let had_interrupt = self.interrupt_status != 0;
        let has_interrupt = status != 0;
        self.interrupt_status = status;
        if had_interrupt == has_interrupt {
            return Ok(());
        }
        self.interrupt.set_irq_level(has_interrupt)
    }

    fn process_queue_notify(&mut self, queue_index: u32) -> Result<(), VirtioBlkMmioError> {
        if queue_index != 0 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: only queue 0 notify is supported",
            ));
        }
        if !self.queue.ready {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: queue is not ready",
            ));
        }
        if (self.status & VIRTIO_STATUS_DRIVER_OK) == 0 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: driver is not ready",
            ));
        }

        let avail_idx = self.read_guest_u16(self.queue.avail_addr + 2)?;
        let pending = avail_idx.wrapping_sub(self.queue.last_avail_idx);
        if pending == 0 {
            return Ok(());
        }
        if pending as u32 > self.queue.size as u32 {
            return Err(VirtioBlkMmioError::InvalidState(
                "virtio-blk: avail ring overrun",
            ));
        }

        for _ in 0..pending {
            let ring_index = calc_ring_index(self.queue.last_avail_idx, self.queue.size)?;
            let ring_addr = avail_ring_entry_addr(self.queue.avail_addr, ring_index);
            let head = self.read_guest_u16(ring_addr)?;
            let outcome = self.process_one_request(head);

            if let Some(status_addr) = outcome.status_addr {
                self.write_guest_u8(status_addr, outcome.status)?;
            }
            let update = used_update(
                self.queue.used_addr,
                self.queue.size,
                self.queue.used_idx,
                head,
                outcome.used_len,
            )?;
            self.write_guest_u32(update.used_elem_addr, update.id)?;
            self.write_guest_u32(
                update
                    .used_elem_addr
                    .checked_add(4)
                    .ok_or(VirtioBlkMmioError::InvalidState(
                        "virtio-blk: used elem overflow",
                    ))?,
                update.len,
            )?;
            self.write_guest_u16(update.used_idx_addr, update.new_used_idx)?;
            self.queue.used_idx = update.new_used_idx;
            self.queue.last_avail_idx = self.queue.last_avail_idx.wrapping_add(1);
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.set_interrupt_status(self.interrupt_status | VIRTIO_INT_USED_RING)
    }

    fn process_one_request(&self, head: u16) -> RequestOutcome {
        let status_addr_hint = self.find_status_addr_best_effort(head);
        let mut desc_reader = |idx: u16| self.read_descriptor(idx).ok();
        let mut req_reader = |addr: u64| self.read_req_header(addr).ok();
        let parsed = parse_req_layout(self.queue.size, head, &mut desc_reader, &mut req_reader);
        let layout = match parsed {
            Ok(layout) => layout,
            Err(err) => {
                return RequestOutcome {
                    status: parse_error_status(err),
                    status_addr: status_addr_hint,
                    used_len: 0,
                };
            }
        };
        self.execute_request(&layout)
    }

    fn execute_request(&self, layout: &VirtioBlkReqLayout) -> RequestOutcome {
        match layout.req_type {
            VIRTIO_BLK_T_IN => {
                let io_res = self
                    .memory
                    .with_write_buffer(layout.data_addr, layout.data_len as usize, |dst| {
                        self.backend
                            .read_sectors(layout.sector, dst)
                            .map_err(|err| match err {
                                VirtioBlkMmioError::Backend(io) => io,
                                _ => IoError::Io,
                            })
                    })
                    .map_err(normalize_buffer_io_error);
                map_io_to_outcome(layout, io_res, layout.data_len)
            }
            VIRTIO_BLK_T_OUT => {
                let io_res = self
                    .memory
                    .with_read_buffer(layout.data_addr, layout.data_len as usize, |src| {
                        self.backend
                            .write_sectors(layout.sector, src)
                            .map_err(|err| match err {
                                VirtioBlkMmioError::Backend(io) => io,
                                _ => IoError::Io,
                            })
                    })
                    .map_err(normalize_buffer_io_error);
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

    fn find_status_addr_best_effort(&self, head: u16) -> Option<u64> {
        if head >= self.queue.size {
            return None;
        }
        let first = self.read_descriptor(head).ok()?;
        if (first.flags & VIRTQ_DESC_F_NEXT) == 0 {
            return None;
        }
        let second = self.read_descriptor(first.next).ok()?;
        if (second.flags & VIRTQ_DESC_F_NEXT) == 0 {
            if (second.flags & VIRTQ_DESC_F_WRITE) != 0 && second.len == 1 {
                return Some(second.addr);
            }
            return None;
        }
        let third = self.read_descriptor(second.next).ok()?;
        if (third.flags & VIRTQ_DESC_F_WRITE) != 0 && third.len == 1 {
            Some(third.addr)
        } else {
            None
        }
    }

    fn read_guest_u16(&self, addr: u64) -> Result<u16, VirtioBlkMmioError> {
        let mut bytes = [0u8; 2];
        self.memory.read(addr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn write_guest_u16(&self, addr: u64, value: u16) -> Result<(), VirtioBlkMmioError> {
        self.memory.write(addr, &value.to_le_bytes())
    }

    fn write_guest_u32(&self, addr: u64, value: u32) -> Result<(), VirtioBlkMmioError> {
        self.memory.write(addr, &value.to_le_bytes())
    }

    fn write_guest_u8(&self, addr: u64, value: u8) -> Result<(), VirtioBlkMmioError> {
        self.memory.write(addr, &[value])
    }

    fn read_descriptor(&self, idx: u16) -> Result<VirtqDesc, VirtioBlkMmioError> {
        if idx >= self.queue.size {
            return Err(VirtioBlkMmioError::Queue(QueueParseError::OutOfRange));
        }
        let offset = (idx as u64)
            .checked_mul(size_of::<VirtqDesc>() as u64)
            .ok_or(VirtioBlkMmioError::GuestMemory(
                "virtio-blk: descriptor offset overflow",
            ))?;
        let addr =
            self.queue
                .desc_addr
                .checked_add(offset)
                .ok_or(VirtioBlkMmioError::GuestMemory(
                    "virtio-blk: descriptor address overflow",
                ))?;
        let mut bytes = [0u8; size_of::<VirtqDesc>()];
        self.memory.read(addr, &mut bytes)?;
        Ok(VirtqDesc {
            addr: u64::from_le_bytes(bytes[0..8].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid descriptor address bytes")
            })?),
            len: u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid descriptor length bytes")
            })?),
            flags: u16::from_le_bytes(bytes[12..14].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid descriptor flags bytes")
            })?),
            next: u16::from_le_bytes(bytes[14..16].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid descriptor next bytes")
            })?),
        })
    }

    fn read_req_header(&self, addr: u64) -> Result<VirtioBlkReq, VirtioBlkMmioError> {
        let mut bytes = [0u8; size_of::<VirtioBlkReq>()];
        self.memory.read(addr, &mut bytes)?;
        Ok(VirtioBlkReq {
            req_type: u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid request type bytes")
            })?),
            reserved: u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid request reserved bytes")
            })?),
            sector: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk: invalid request sector bytes")
            })?),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestOutcome {
    status: u8,
    status_addr: Option<u64>,
    used_len: u32,
}

fn normalize_buffer_io_error(err: VirtioBlkMmioError) -> VirtioBlkMmioError {
    match err {
        VirtioBlkMmioError::Backend(io) => VirtioBlkMmioError::Backend(io),
        other => other,
    }
}

fn map_io_to_outcome(
    layout: &VirtioBlkReqLayout,
    io_result: Result<(), VirtioBlkMmioError>,
    used_len: u32,
) -> RequestOutcome {
    match io_result {
        Ok(()) => RequestOutcome {
            status: VIRTIO_BLK_S_OK,
            status_addr: Some(layout.status_addr),
            used_len,
        },
        Err(VirtioBlkMmioError::Backend(IoError::Unsupported)) => RequestOutcome {
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

fn validate_register_access(offset: usize, size: u8) -> Result<(), VirtioBlkMmioError> {
    if size != 4 {
        return Err(VirtioBlkMmioError::Access(MmioAccessError::InvalidSize));
    }
    if (offset & 0x3) != 0 {
        return Err(VirtioBlkMmioError::Access(MmioAccessError::InvalidOffset));
    }
    Ok(())
}

fn validate_config_access(offset: usize, size: u8) -> Result<(), VirtioBlkMmioError> {
    if !matches!(size, 1 | 2 | 4) {
        return Err(VirtioBlkMmioError::Access(MmioAccessError::InvalidSize));
    }
    let cfg_offset =
        offset
            .checked_sub(REG_CONFIG_SPACE)
            .ok_or(VirtioBlkMmioError::InvalidState(
                "virtio-blk: config offset underflow",
            ))?;
    let cfg_end = cfg_offset
        .checked_add(size as usize)
        .ok_or(VirtioBlkMmioError::InvalidState(
            "virtio-blk: config access overflow",
        ))?;
    if cfg_end > size_of::<VirtioBlkConfig>() {
        return Err(VirtioBlkMmioError::Access(MmioAccessError::InvalidOffset));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    fn make_req(req_type: u32, sector: u64) -> VirtioBlkReq {
        VirtioBlkReq {
            req_type,
            reserved: 0,
            sector,
        }
    }

    fn desc(addr: u64, len: u32, flags: u16, next: u16) -> VirtqDesc {
        VirtqDesc {
            addr,
            len,
            flags,
            next,
        }
    }

    #[test]
    fn features_require_version_1() {
        let device = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO;
        let driver_ok = VIRTIO_F_VERSION_1;
        let driver_bad = 0;
        assert!(validate_negotiated_features(device, driver_ok).is_ok());
        assert_eq!(
            validate_negotiated_features(device, driver_bad),
            Err(MmioAccessError::InvalidValue)
        );
    }

    #[test]
    fn merge_driver_features_keeps_64bit_state() {
        let v0 = merge_driver_features(0, 0, 0x1122_3344).unwrap();
        let v1 = merge_driver_features(v0, 1, 0x5566_7788).unwrap();
        assert_eq!(v1, 0x5566_7788_1122_3344u64);
    }

    #[test]
    fn queue_size_must_be_pow2() {
        assert!(validate_queue_size(8, 256).is_ok());
        assert_eq!(
            validate_queue_size(7, 256),
            Err(QueueParseError::InvalidQueueSize)
        );
    }

    #[test]
    fn parse_three_desc_read_request() {
        let req = make_req(VIRTIO_BLK_T_IN, 32);
        let table = [
            desc(
                0x1000,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
            desc(0x2000, 1024, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2),
            desc(0x3000, 1, VIRTQ_DESC_F_WRITE, 0),
        ];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        let parsed = parse_req_layout(8, 0, &mut get_desc, &mut read_req).unwrap();
        assert_eq!(parsed.req_type, VIRTIO_BLK_T_IN);
        assert_eq!(parsed.data_addr, 0x2000);
        assert_eq!(parsed.status_addr, 0x3000);
    }

    #[test]
    fn parse_flush_two_desc_request() {
        let req = make_req(VIRTIO_BLK_T_FLUSH, 0);
        let table = [
            desc(
                0x1000,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
            desc(0x3000, 1, VIRTQ_DESC_F_WRITE, 0),
        ];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        let parsed = parse_req_layout(8, 0, &mut get_desc, &mut read_req).unwrap();
        assert_eq!(parsed.req_type, VIRTIO_BLK_T_FLUSH);
        assert_eq!(parsed.data_len, 0);
    }

    #[test]
    fn reject_indirect_descriptor() {
        let req = make_req(VIRTIO_BLK_T_IN, 1);
        let table = [desc(
            0x1000,
            size_of::<VirtioBlkReq>() as u32,
            VIRTQ_DESC_F_INDIRECT,
            0,
        )];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        assert_eq!(
            parse_req_layout(1, 0, &mut get_desc, &mut read_req),
            Err(QueueParseError::IndirectUnsupported)
        );
    }

    #[test]
    fn reject_misaligned_data_length() {
        let req = make_req(VIRTIO_BLK_T_OUT, 2);
        let table = [
            desc(
                0x1000,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
            desc(0x2000, 513, VIRTQ_DESC_F_NEXT, 2),
            desc(0x3000, 1, VIRTQ_DESC_F_WRITE, 0),
        ];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        assert_eq!(
            parse_req_layout(8, 0, &mut get_desc, &mut read_req),
            Err(QueueParseError::Align)
        );
    }

    #[test]
    fn reject_descriptor_loop() {
        let req = make_req(VIRTIO_BLK_T_IN, 1);
        let table = [desc(
            0x1000,
            size_of::<VirtioBlkReq>() as u32,
            VIRTQ_DESC_F_NEXT,
            0,
        )];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        assert_eq!(
            parse_req_layout(1, 0, &mut get_desc, &mut read_req),
            Err(QueueParseError::DescriptorLoop)
        );
    }

    #[test]
    fn reject_status_not_writable() {
        let req = make_req(VIRTIO_BLK_T_IN, 2);
        let table = [
            desc(
                0x1000,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
            desc(0x2000, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2),
            desc(0x3000, 1, 0, 0),
        ];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        assert_eq!(
            parse_req_layout(8, 0, &mut get_desc, &mut read_req),
            Err(QueueParseError::MissingStatus)
        );
    }

    #[test]
    fn reject_non_flush_two_desc_chain() {
        let req = make_req(VIRTIO_BLK_T_OUT, 0);
        let table = [
            desc(
                0x1000,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
            desc(0x3000, 1, VIRTQ_DESC_F_WRITE, 0),
        ];
        let mut read_req = |addr: u64| (addr == 0x1000).then_some(req);
        let mut get_desc = |idx: u16| table.get(idx as usize).copied();
        assert_eq!(
            parse_req_layout(8, 0, &mut get_desc, &mut read_req),
            Err(QueueParseError::InvalidLayout)
        );
    }

    #[test]
    fn used_ring_update_wraps_index() {
        let update = used_update(0x5000, 8, 0xffff, 3, 4096).unwrap();
        assert_eq!(update.ring_index, 7);
        assert_eq!(update.new_used_idx, 0);
        assert_eq!(update.id, 3);
    }

    #[test]
    fn interrupt_ack_clears_only_requested_bits() {
        let old = VIRTIO_INT_USED_RING | (1 << 7);
        let new = ack_interrupt_bits(old, VIRTIO_INT_USED_RING);
        assert_eq!(new, 1 << 7);
    }

    struct FakeBlockDevice {
        storage: Mutex<Vec<u8>>,
        read_only: bool,
    }

    impl FakeBlockDevice {
        fn new(storage: Vec<u8>, read_only: bool) -> Self {
            assert_eq!(storage.len() % SECTOR_SIZE, 0);
            Self {
                storage: Mutex::new(storage),
                read_only,
            }
        }
    }

    impl BlockDevice for FakeBlockDevice {
        fn init(&mut self) -> Result<(), IoError> {
            Ok(())
        }

        fn block_size(&self) -> usize {
            SECTOR_SIZE
        }

        fn num_blocks(&self) -> u64 {
            (self.storage.lock().unwrap().len() / SECTOR_SIZE) as u64
        }

        fn read_at(&self, lba: u64, buf: &mut [MaybeUninit<u8>]) -> Result<(), IoError> {
            if (buf.len() % SECTOR_SIZE) != 0 {
                return Err(IoError::Align);
            }
            let start = (lba as usize)
                .checked_mul(SECTOR_SIZE)
                .ok_or(IoError::OutOfRange)?;
            let end = start.checked_add(buf.len()).ok_or(IoError::OutOfRange)?;
            let storage = self.storage.lock().unwrap();
            let src = storage.get(start..end).ok_or(IoError::OutOfRange)?;
            for (dst, byte) in buf.iter_mut().zip(src.iter().copied()) {
                dst.write(byte);
            }
            Ok(())
        }

        fn write_at(&self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
            if self.read_only {
                return Err(IoError::ReadOnly);
            }
            if (buf.len() % SECTOR_SIZE) != 0 {
                return Err(IoError::Align);
            }
            let start = (lba as usize)
                .checked_mul(SECTOR_SIZE)
                .ok_or(IoError::OutOfRange)?;
            let end = start.checked_add(buf.len()).ok_or(IoError::OutOfRange)?;
            let mut storage = self.storage.lock().unwrap();
            let dst = storage.get_mut(start..end).ok_or(IoError::OutOfRange)?;
            dst.copy_from_slice(buf);
            Ok(())
        }

        fn flush(&self) -> Result<(), IoError> {
            Ok(())
        }

        fn max_io_bytes(&self) -> Result<Option<usize>, IoError> {
            Ok(None)
        }

        fn is_read_only(&self) -> Result<bool, IoError> {
            Ok(self.read_only)
        }

        fn uninstall(&self) {}
    }

    struct FakeGuestMemory {
        bytes: Mutex<Vec<u8>>,
    }

    impl FakeGuestMemory {
        fn new(size: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0; size]),
            }
        }

        fn range(addr: u64, len: usize) -> Result<(usize, usize), VirtioBlkMmioError> {
            let start = usize::try_from(addr).map_err(|_| {
                VirtioBlkMmioError::GuestMemory("virtio-blk test: guest address overflow")
            })?;
            let end = start
                .checked_add(len)
                .ok_or(VirtioBlkMmioError::GuestMemory(
                    "virtio-blk test: guest address overflow",
                ))?;
            Ok((start, end))
        }

        fn write_bytes(&self, addr: u64, value: &[u8]) {
            let (start, end) = Self::range(addr, value.len()).unwrap();
            let mut bytes = self.bytes.lock().unwrap();
            bytes[start..end].copy_from_slice(value);
        }

        fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
            let (start, end) = Self::range(addr, len).unwrap();
            self.bytes.lock().unwrap()[start..end].to_vec()
        }

        fn write_u16(&self, addr: u64, value: u16) {
            self.write_bytes(addr, &value.to_le_bytes());
        }

        fn write_u32(&self, addr: u64, value: u32) {
            self.write_bytes(addr, &value.to_le_bytes());
        }

        fn write_u64(&self, addr: u64, value: u64) {
            self.write_bytes(addr, &value.to_le_bytes());
        }

        fn write_u8(&self, addr: u64, value: u8) {
            self.write_bytes(addr, &[value]);
        }

        fn write_req(&self, addr: u64, req: VirtioBlkReq) {
            self.write_u32(addr, req.req_type);
            self.write_u32(addr + 4, req.reserved);
            self.write_u64(addr + 8, req.sector);
        }

        fn write_desc(&self, table_addr: u64, idx: u16, desc: VirtqDesc) {
            let addr = table_addr + idx as u64 * size_of::<VirtqDesc>() as u64;
            self.write_u64(addr, desc.addr);
            self.write_u32(addr + 8, desc.len);
            self.write_u16(addr + 12, desc.flags);
            self.write_u16(addr + 14, desc.next);
        }

        fn read_u16(&self, addr: u64) -> u16 {
            u16::from_le_bytes(self.read_bytes(addr, 2).try_into().unwrap())
        }

        fn read_u32(&self, addr: u64) -> u32 {
            u32::from_le_bytes(self.read_bytes(addr, 4).try_into().unwrap())
        }

        fn read_u8(&self, addr: u64) -> u8 {
            self.read_bytes(addr, 1)[0]
        }
    }

    impl VirtioBlkMmioGuestMemory for &FakeGuestMemory {
        fn read(&self, addr: u64, out: &mut [u8]) -> Result<(), VirtioBlkMmioError> {
            let (start, end) = FakeGuestMemory::range(addr, out.len())?;
            let bytes = self.bytes.lock().unwrap();
            out.copy_from_slice(
                bytes
                    .get(start..end)
                    .ok_or(VirtioBlkMmioError::GuestMemory(
                        "virtio-blk test: guest memory read out of range",
                    ))?,
            );
            Ok(())
        }

        fn write(&self, addr: u64, value: &[u8]) -> Result<(), VirtioBlkMmioError> {
            let (start, end) = FakeGuestMemory::range(addr, value.len())?;
            let mut bytes = self.bytes.lock().unwrap();
            bytes
                .get_mut(start..end)
                .ok_or(VirtioBlkMmioError::GuestMemory(
                    "virtio-blk test: guest memory write out of range",
                ))?
                .copy_from_slice(value);
            Ok(())
        }

        fn with_read_buffer<F>(&self, addr: u64, len: usize, f: F) -> Result<(), VirtioBlkMmioError>
        where
            F: FnOnce(&[u8]) -> Result<(), IoError>,
        {
            let (start, end) = FakeGuestMemory::range(addr, len)?;
            let bytes = self.bytes.lock().unwrap();
            let slice = bytes
                .get(start..end)
                .ok_or(VirtioBlkMmioError::GuestMemory(
                    "virtio-blk test: guest memory read buffer out of range",
                ))?;
            f(slice).map_err(VirtioBlkMmioError::Backend)
        }

        fn with_write_buffer<F>(
            &self,
            addr: u64,
            len: usize,
            f: F,
        ) -> Result<(), VirtioBlkMmioError>
        where
            F: FnOnce(&mut [u8]) -> Result<(), IoError>,
        {
            let (start, end) = FakeGuestMemory::range(addr, len)?;
            let mut bytes = self.bytes.lock().unwrap();
            let slice = bytes
                .get_mut(start..end)
                .ok_or(VirtioBlkMmioError::GuestMemory(
                    "virtio-blk test: guest memory write buffer out of range",
                ))?;
            f(slice).map_err(VirtioBlkMmioError::Backend)
        }
    }

    #[derive(Default)]
    struct FakeInterrupt {
        levels: Mutex<Vec<bool>>,
    }

    impl FakeInterrupt {
        fn levels(&self) -> Vec<bool> {
            self.levels.lock().unwrap().clone()
        }
    }

    impl VirtioBlkMmioInterrupt for &FakeInterrupt {
        fn set_irq_level(&self, asserted: bool) -> Result<(), VirtioBlkMmioError> {
            self.levels.lock().unwrap().push(asserted);
            Ok(())
        }
    }

    const DESC_ADDR: u64 = 0x1000;
    const AVAIL_ADDR: u64 = 0x2000;
    const USED_ADDR: u64 = 0x3000;
    const REQ_ADDR: u64 = 0x4000;
    const DATA_ADDR: u64 = 0x5000;
    const STATUS_ADDR: u64 = 0x6000;

    fn make_device<'a>(
        backend: &'a FakeBlockDevice,
        memory: &'a FakeGuestMemory,
        irq: &'a FakeInterrupt,
    ) -> VirtioBlkMmioDevice<'a, FakeBlockDevice, &'a FakeGuestMemory, &'a FakeInterrupt> {
        VirtioBlkMmioDevice::new(backend, memory, irq).unwrap()
    }

    fn enable_driver<B, M, I>(device: &mut VirtioBlkMmioDevice<'_, B, M, I>)
    where
        B: BlockDevice + ?Sized,
        M: VirtioBlkMmioGuestMemory,
        I: VirtioBlkMmioInterrupt,
    {
        device.mmio_write(REG_DRIVER_FEATURES_SEL, 4, 1).unwrap();
        device.mmio_write(REG_DRIVER_FEATURES, 4, 1).unwrap();
        device
            .mmio_write(
                REG_STATUS,
                4,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u64,
            )
            .unwrap();
    }

    fn configure_ready_queue<B, M, I>(
        device: &mut VirtioBlkMmioDevice<'_, B, M, I>,
        memory: &FakeGuestMemory,
        queue_size: u16,
    ) where
        B: BlockDevice + ?Sized,
        M: VirtioBlkMmioGuestMemory,
        I: VirtioBlkMmioInterrupt,
    {
        memory.write_u16(AVAIL_ADDR + 2, 0);
        memory.write_u16(USED_ADDR + 2, 0);
        device.mmio_write(REG_QUEUE_SEL, 4, 0).unwrap();
        device
            .mmio_write(REG_QUEUE_NUM, 4, queue_size as u64)
            .unwrap();
        device.mmio_write(REG_QUEUE_DESC_LOW, 4, DESC_ADDR).unwrap();
        device.mmio_write(REG_QUEUE_DESC_HIGH, 4, 0).unwrap();
        device
            .mmio_write(REG_QUEUE_DRIVER_LOW, 4, AVAIL_ADDR)
            .unwrap();
        device.mmio_write(REG_QUEUE_DRIVER_HIGH, 4, 0).unwrap();
        device
            .mmio_write(REG_QUEUE_DEVICE_LOW, 4, USED_ADDR)
            .unwrap();
        device.mmio_write(REG_QUEUE_DEVICE_HIGH, 4, 0).unwrap();
        device.mmio_write(REG_QUEUE_READY, 4, 1).unwrap();
    }

    #[test]
    fn mmio_registers_expose_modern_block_device() {
        let backend = FakeBlockDevice::new(vec![0u8; SECTOR_SIZE * 3], false);
        let memory = FakeGuestMemory::new(0x8000);
        let irq = FakeInterrupt::default();
        let mut device = make_device(&backend, &memory, &irq);

        assert_eq!(
            device.mmio_read(REG_MAGIC_VALUE, 4).unwrap(),
            VIRTIO_MMIO_MAGIC_VALUE as u64
        );
        assert_eq!(
            device.mmio_read(REG_VERSION, 4).unwrap(),
            VIRTIO_MMIO_VERSION_MODERN as u64
        );
        assert_eq!(
            device.mmio_read(REG_DEVICE_ID, 4).unwrap(),
            VIRTIO_MMIO_DEVICE_ID_BLOCK as u64
        );
        assert_eq!(
            device.mmio_read(REG_VENDOR_ID, 4).unwrap(),
            VIRTIO_MMIO_VENDOR_ID as u64
        );
        assert_eq!(
            device.mmio_read(REG_QUEUE_NUM_MAX, 4).unwrap(),
            QUEUE_MAX as u64
        );
        assert_eq!(device.mmio_read(REG_CONFIG_SPACE, 4).unwrap(), 3);
        assert_eq!(device.mmio_read(REG_CONFIG_SPACE + 4, 4).unwrap(), 0);
        assert_eq!(
            device.mmio_read(REG_MAGIC_VALUE, 1),
            Err(VirtioBlkMmioError::Access(MmioAccessError::InvalidSize))
        );
    }

    #[test]
    fn queue_setup_transitions_to_ready() {
        let backend = FakeBlockDevice::new(vec![0u8; SECTOR_SIZE * 2], false);
        let memory = FakeGuestMemory::new(0x8000);
        let irq = FakeInterrupt::default();
        let mut device = make_device(&backend, &memory, &irq);

        configure_ready_queue(&mut device, &memory, 8);

        assert_eq!(device.mmio_read(REG_QUEUE_NUM, 4).unwrap(), 8);
        assert_eq!(device.mmio_read(REG_QUEUE_READY, 4).unwrap(), 1);
    }

    #[test]
    fn valid_read_request_updates_used_ring_and_irq_ack_deasserts() {
        let mut storage = vec![0u8; SECTOR_SIZE * 3];
        for (idx, byte) in storage[SECTOR_SIZE..SECTOR_SIZE * 2].iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(3).wrapping_add(1);
        }
        let backend = FakeBlockDevice::new(storage.clone(), false);
        let memory = FakeGuestMemory::new(0x8000);
        let irq = FakeInterrupt::default();
        let mut device = make_device(&backend, &memory, &irq);

        configure_ready_queue(&mut device, &memory, 8);
        enable_driver(&mut device);

        memory.write_desc(
            DESC_ADDR,
            0,
            desc(
                REQ_ADDR,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
        );
        memory.write_desc(
            DESC_ADDR,
            1,
            desc(
                DATA_ADDR,
                SECTOR_SIZE as u32,
                VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
                2,
            ),
        );
        memory.write_desc(DESC_ADDR, 2, desc(STATUS_ADDR, 1, VIRTQ_DESC_F_WRITE, 0));
        memory.write_req(REQ_ADDR, make_req(VIRTIO_BLK_T_IN, 1));
        memory.write_u16(AVAIL_ADDR + 2, 1);
        memory.write_u16(AVAIL_ADDR + 4, 0);
        memory.write_u8(STATUS_ADDR, 0xff);

        device.mmio_write(REG_QUEUE_NOTIFY, 4, 0).unwrap();

        assert_eq!(
            memory.read_bytes(DATA_ADDR, SECTOR_SIZE),
            storage[SECTOR_SIZE..SECTOR_SIZE * 2].to_vec()
        );
        assert_eq!(memory.read_u8(STATUS_ADDR), VIRTIO_BLK_S_OK);
        assert_eq!(memory.read_u16(USED_ADDR + 2), 1);
        assert_eq!(memory.read_u32(USED_ADDR + 4), 0);
        assert_eq!(memory.read_u32(USED_ADDR + 8), SECTOR_SIZE as u32);
        assert_eq!(
            device.mmio_read(REG_INTERRUPT_STATUS, 4).unwrap(),
            VIRTIO_INT_USED_RING as u64
        );
        assert_eq!(irq.levels(), vec![true]);

        device
            .mmio_write(REG_INTERRUPT_ACK, 4, VIRTIO_INT_USED_RING as u64)
            .unwrap();

        assert_eq!(device.mmio_read(REG_INTERRUPT_STATUS, 4).unwrap(), 0);
        assert_eq!(irq.levels(), vec![true, false]);
    }

    #[test]
    fn malformed_descriptor_chain_completes_with_ioerr_status() {
        let backend = FakeBlockDevice::new(vec![0u8; SECTOR_SIZE * 2], false);
        let memory = FakeGuestMemory::new(0x8000);
        let irq = FakeInterrupt::default();
        let mut device = make_device(&backend, &memory, &irq);

        configure_ready_queue(&mut device, &memory, 8);
        enable_driver(&mut device);

        memory.write_desc(
            DESC_ADDR,
            0,
            desc(
                REQ_ADDR,
                size_of::<VirtioBlkReq>() as u32,
                VIRTQ_DESC_F_NEXT,
                1,
            ),
        );
        memory.write_desc(
            DESC_ADDR,
            1,
            desc(
                DATA_ADDR,
                SECTOR_SIZE as u32,
                VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
                2,
            ),
        );
        memory.write_desc(DESC_ADDR, 2, desc(STATUS_ADDR, 1, VIRTQ_DESC_F_WRITE, 0));
        memory.write_req(REQ_ADDR, make_req(VIRTIO_BLK_T_OUT, 0));
        memory.write_u16(AVAIL_ADDR + 2, 1);
        memory.write_u16(AVAIL_ADDR + 4, 0);
        memory.write_u8(STATUS_ADDR, 0xff);

        device.mmio_write(REG_QUEUE_NOTIFY, 4, 0).unwrap();

        assert_eq!(memory.read_u8(STATUS_ADDR), VIRTIO_BLK_S_IOERR);
        assert_eq!(memory.read_u16(USED_ADDR + 2), 1);
        assert_eq!(memory.read_u32(USED_ADDR + 4), 0);
        assert_eq!(memory.read_u32(USED_ADDR + 8), 0);
        assert_eq!(irq.levels(), vec![true]);
    }
}
