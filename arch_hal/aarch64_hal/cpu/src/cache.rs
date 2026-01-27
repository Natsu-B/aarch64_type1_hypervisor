use core::arch::asm;

#[inline(always)]
fn align_range(ptr: *const u8, len: usize) -> (usize, usize, usize) {
    let line = super::dcache_line_size();
    let addr = ptr as usize;
    let start = addr & !(line - 1);
    let end = addr.saturating_add(len).saturating_add(line - 1) & !(line - 1);
    (start, end, line)
}

/// Clean data cache lines covering the range `[ptr, ptr + len)` to the Point of Coherency.
///
/// The virtual address range must be valid for cache maintenance by VA in the current address
/// space. Intended for DMA-coherent ring or descriptor memory shared with devices.
#[inline]
pub fn clean_dcache_range(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let (mut cur, end, line) = align_range(ptr, len);
    unsafe {
        while cur < end {
            asm!("dc cvac, {addr}", addr = in(reg) cur);
            cur += line;
        }
        asm!("dsb sy");
    }
}

/// Invalidate data cache lines covering the range `[ptr, ptr + len)` from the Point of Coherency.
///
/// The virtual address range must be valid for cache maintenance by VA in the current address
/// space. Intended for DMA-coherent ring or descriptor memory shared with devices.
#[inline]
pub fn invalidate_dcache_range(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let (mut cur, end, line) = align_range(ptr, len);
    unsafe {
        while cur < end {
            asm!("dc ivac, {addr}", addr = in(reg) cur);
            cur += line;
        }
        asm!("dsb sy");
    }
}

/// Clean and invalidate data cache lines covering the range `[ptr, ptr + len)` at the Point of
/// Coherency.
///
/// The virtual address range must be valid for cache maintenance by VA in the current address
/// space. Intended for DMA-coherent ring or descriptor memory shared with devices.
#[inline]
pub fn clean_invalidate_dcache_range(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let (mut cur, end, line) = align_range(ptr, len);
    unsafe {
        while cur < end {
            asm!("dc civac, {addr}", addr = in(reg) cur);
            cur += line;
        }
        asm!("dsb sy");
    }
}

/// Invalidate instruction cache lines covering the range `[ptr, ptr + len)` to the Point of
/// Unification.
///
/// The virtual address range must be valid for cache maintenance by VA in the current address
/// space. Intended for freshly-written code or patched instructions.
#[inline]
pub fn invalidate_icache_range(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let line = super::icache_line_size();
    let addr = ptr as usize;
    let start = addr & !(line - 1);
    let end = addr.saturating_add(len).saturating_add(line - 1) & !(line - 1);

    // SAFETY: `ic ivau` requires the VA range to be mapped in the current address space.
    unsafe {
        let mut cur = start;
        while cur < end {
            asm!("ic ivau, {addr}", addr = in(reg) cur);
            cur += line;
        }
        asm!("dsb ish");
        asm!("isb");
    }
}
