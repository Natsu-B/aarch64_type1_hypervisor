/// An MMIO region describing a device register frame.
///
/// `base` is the physical or already-mapped virtual base address used for volatile access.
/// `size` is the byte size of the region.
///
/// Implementations typically require:
/// - `base` aligned to the frame granule (commonly 4KiB),
/// - a mapping with device memory attributes,
/// - a region size matching the register block layout used by the backend.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub base: usize,
    pub size: usize,
}

/// Reads `size` bytes from `addr` with a single volatile access and zero-extends the result.
///
/// Only the natural MMIO access widths (1, 2, 4, and 8 bytes) are supported; any other
/// `size` returns `None` without touching memory.
///
/// # Safety
///
/// `addr` must be valid for a volatile read of `size` bytes and aligned to `size`.
#[inline]
pub unsafe fn read_volatile_sized(addr: usize, size: u8) -> Option<u64> {
    // SAFETY: The caller guarantees `addr` is valid and aligned for a `size`-byte read.
    unsafe {
        Some(match size {
            1 => u64::from(core::ptr::read_volatile(addr as *const u8)),
            2 => u64::from(core::ptr::read_volatile(addr as *const u16)),
            4 => u64::from(core::ptr::read_volatile(addr as *const u32)),
            8 => core::ptr::read_volatile(addr as *const u64),
            _ => return None,
        })
    }
}

/// Writes the low `size` bytes of `value` to `addr` with a single volatile access.
///
/// Only the natural MMIO access widths (1, 2, 4, and 8 bytes) are supported; any other
/// `size` returns `None` without touching memory.
///
/// # Safety
///
/// `addr` must be valid for a volatile write of `size` bytes and aligned to `size`.
#[inline]
pub unsafe fn write_volatile_sized(addr: usize, size: u8, value: u64) -> Option<()> {
    // SAFETY: The caller guarantees `addr` is valid and aligned for a `size`-byte write.
    unsafe {
        match size {
            1 => core::ptr::write_volatile(addr as *mut u8, value as u8),
            2 => core::ptr::write_volatile(addr as *mut u16, value as u16),
            4 => core::ptr::write_volatile(addr as *mut u32, value as u32),
            8 => core::ptr::write_volatile(addr as *mut u64, value),
            _ => return None,
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::read_volatile_sized;
    use super::write_volatile_sized;

    #[test]
    fn sized_access_round_trips_each_width() {
        let mut word = 0u64;
        let addr = &raw mut word as usize;
        for size in [1u8, 2, 4, 8] {
            // SAFETY: `addr` points to a live, 8-byte aligned local.
            unsafe { write_volatile_sized(addr, 8, 0) }.unwrap();
            // SAFETY: `addr` points to a live, 8-byte aligned local.
            unsafe { write_volatile_sized(addr, size, u64::MAX) }.unwrap();
            let expected = if size == 8 {
                u64::MAX
            } else {
                (1u64 << (u32::from(size) * 8)) - 1
            };
            // SAFETY: `addr` points to a live, 8-byte aligned local.
            assert_eq!(unsafe { read_volatile_sized(addr, size) }, Some(expected));
        }
    }

    #[test]
    fn sized_access_rejects_unsupported_widths() {
        let mut word = 0x1122_3344_5566_7788u64;
        let addr = &raw mut word as usize;
        // SAFETY: Unsupported sizes return before touching memory.
        assert_eq!(unsafe { read_volatile_sized(addr, 3) }, None);
        // SAFETY: Unsupported sizes return before touching memory.
        assert_eq!(unsafe { write_volatile_sized(addr, 16, 0) }, None);
        assert_eq!(word, 0x1122_3344_5566_7788);
    }
}
