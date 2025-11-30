use arch_hal::paging::PagingErr;
use arch_hal::paging::Stage2Paging;
use core::cmp::min;
use core::ptr;
use mutex::SpinLock;

const PAGE_SIZE: usize = 0x1000;
const BRK_INSN: u32 = 0xD420_0000; // BRK #0
const MAX_SW_BREAKPOINTS: usize = 64;

#[derive(Clone, Copy)]
struct BreakpointEntry {
    addr: u64,
    original_insn: u32,
    used: bool,
}

impl BreakpointEntry {
    const fn empty() -> Self {
        Self {
            addr: 0,
            original_insn: 0,
            used: false,
        }
    }
}

static BREAKPOINTS: SpinLock<[BreakpointEntry; MAX_SW_BREAKPOINTS]> =
    SpinLock::new([BreakpointEntry::empty(); MAX_SW_BREAKPOINTS]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointError {
    Unaligned,
    TableFull,
    NotFound,
    Stage2(PagingErr),
}

impl From<PagingErr> for BreakpointError {
    fn from(value: PagingErr) -> Self {
        Self::Stage2(value)
    }
}

/// Copy guest memory from an IPA range into `dst`.
///
/// # Pre-conditions
/// - Stage-2 translation must already be initialized and enabled.
/// - The resulting physical address must be directly accessible from EL2 (the current boot flow
///   installs an identity mapping for RAM).
pub fn copy_from_guest_ipa(ipa: u64, dst: &mut [u8]) -> Result<(), PagingErr> {
    if ipa > usize::MAX as u64 {
        return Err(PagingErr::Corrupted);
    }
    let base = ipa as usize;
    let mut copied = 0;
    while copied < dst.len() {
        let cur_ipa = base.checked_add(copied).ok_or(PagingErr::Corrupted)?;
        let pa = Stage2Paging::ipa_to_pa(cur_ipa)?;
        let page_offset = cur_ipa & (PAGE_SIZE - 1);
        let page_remain = PAGE_SIZE - page_offset;
        let chunk = min(page_remain, dst.len() - copied);

        // SAFETY: `chunk` is bounded by the remaining slice length and page size, and Stage-2
        // guarantees the physical address resolves to accessible memory in the current design.
        unsafe {
            ptr::copy_nonoverlapping(pa as *const u8, dst.as_mut_ptr().add(copied), chunk);
        }

        copied += chunk;
    }
    Ok(())
}

/// Copy data from `src` into guest memory at the provided IPA.
///
/// # Pre-conditions
/// - Stage-2 translation must already be initialized and enabled.
/// - The resulting physical address must be directly accessible from EL2 (identity mapping).
pub fn copy_to_guest_ipa(ipa: u64, src: &[u8]) -> Result<(), PagingErr> {
    if ipa > usize::MAX as u64 {
        return Err(PagingErr::Corrupted);
    }
    let base = ipa as usize;
    let mut copied = 0;
    while copied < src.len() {
        let cur_ipa = base.checked_add(copied).ok_or(PagingErr::Corrupted)?;
        let pa = Stage2Paging::ipa_to_pa(cur_ipa)?;
        let page_offset = cur_ipa & (PAGE_SIZE - 1);
        let page_remain = PAGE_SIZE - page_offset;
        let chunk = min(page_remain, src.len() - copied);

        // SAFETY: `chunk` is bounded by the remaining slice length and page size, and Stage-2
        // guarantees the physical address resolves to accessible memory in the current design.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr().add(copied), pa as *mut u8, chunk);
        }

        copied += chunk;
    }
    Ok(())
}

/// Convenience wrapper matching the gdb `Target` trait shape for memory reads.
pub fn read_memory(addr: u64, dst: &mut [u8]) -> Result<(), PagingErr> {
    copy_from_guest_ipa(addr, dst)
}

/// Convenience wrapper matching the gdb `Target` trait shape for memory writes.
pub fn write_memory(addr: u64, src: &[u8]) -> Result<(), PagingErr> {
    copy_to_guest_ipa(addr, src)
}

/// Insert a software breakpoint by patching the guest instruction with `BRK #0`.
///
/// The IPA must be 4-byte aligned (AArch64 fixed-length instructions). The helper tracks a fixed
/// number of breakpoints and preserves the original instruction so it can be restored later.
pub fn insert_sw_breakpoint(ipa: u64) -> Result<(), BreakpointError> {
    if (ipa & 0b11) != 0 {
        return Err(BreakpointError::Unaligned);
    }

    let mut original = [0u8; 4];
    copy_from_guest_ipa(ipa, &mut original)?;
    let original_insn = u32::from_le_bytes(original);

    copy_to_guest_ipa(ipa, &BRK_INSN.to_le_bytes())?;

    let mut breakpoints = BREAKPOINTS.lock();
    if let Some(entry) = breakpoints.iter_mut().find(|bp| bp.used && bp.addr == ipa) {
        entry.original_insn = original_insn;
        return Ok(());
    }
    if let Some(entry) = breakpoints.iter_mut().find(|bp| !bp.used) {
        *entry = BreakpointEntry {
            addr: ipa,
            original_insn,
            used: true,
        };
        return Ok(());
    }

    Err(BreakpointError::TableFull)
}

/// Remove a software breakpoint and restore the original instruction.
pub fn remove_sw_breakpoint(ipa: u64) -> Result<(), BreakpointError> {
    if (ipa & 0b11) != 0 {
        return Err(BreakpointError::Unaligned);
    }

    let mut breakpoints = BREAKPOINTS.lock();
    if let Some(entry) = breakpoints.iter_mut().find(|bp| bp.used && bp.addr == ipa) {
        let original = entry.original_insn.to_le_bytes();
        copy_to_guest_ipa(ipa, &original)?;
        entry.used = false;
        return Ok(());
    }

    Err(BreakpointError::NotFound)
}
