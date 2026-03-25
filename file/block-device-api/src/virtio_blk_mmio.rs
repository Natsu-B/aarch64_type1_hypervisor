#![allow(clippy::identity_op)]

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
