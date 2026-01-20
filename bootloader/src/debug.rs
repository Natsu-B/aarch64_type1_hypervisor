use crate::gdb_uart;
use crate::gdb_uart::GdbUartStream;
use arch_hal::aarch64_gdb;
use arch_hal::aarch64_gdb::Aarch64GdbStub;
use arch_hal::aarch64_gdb::DebugEntryCause;
use arch_hal::aarch64_gdb::MemoryAccess;
use arch_hal::cpu;
use arch_hal::exceptions::registers::ExceptionClass;
use arch_hal::paging::PagingErr;
use arch_hal::paging::Stage2Paging;
use arch_hal::timer;
use core::cell::SyncUnsafeCell;
use core::cmp::min;
use core::mem::MaybeUninit;
use core::ptr;

const PAGE_SIZE: usize = 0x1000;
const MAX_GDB_PKT: usize = 1024;
const ATTACH_DEADLINE_MS: u64 = 20;

struct DebugActiveGuard;

impl DebugActiveGuard {
    fn new() -> Self {
        gdb_uart::set_debug_active(true);
        Self
    }
}

impl Drop for DebugActiveGuard {
    fn drop(&mut self) {
        gdb_uart::set_debug_active(false);
    }
}

struct Stage2Memory;

impl MemoryAccess for Stage2Memory {
    type Error = PagingErr;

    fn read(&mut self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        copy_from_guest_ipa(addr, dst)
    }

    fn write(&mut self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        copy_to_guest_ipa(addr, src)
    }
}

static GDB_STUB: SyncUnsafeCell<
    MaybeUninit<Aarch64GdbStub<GdbUartStream, Stage2Memory, MAX_GDB_PKT>>,
> = SyncUnsafeCell::new(MaybeUninit::uninit());

pub(crate) fn init_gdb_stub() {
    // SAFETY: called once during early boot, before debug exceptions are enabled.
    unsafe {
        let stub = &mut *GDB_STUB.get();
        stub.write(Aarch64GdbStub::new(GdbUartStream, Stage2Memory));
        aarch64_gdb::register_debug_stub(stub.assume_init_mut());
    }
}

pub(crate) fn handle_debug_exception(regs: &mut cpu::Registers, ec: ExceptionClass) {
    aarch64_gdb::debug_exception_entry(regs, ec);
}

pub(crate) fn enter_debug_from_irq(regs: &mut cpu::Registers, reason: u8) {
    if gdb_uart::is_debug_active() {
        return;
    }

    let cause = match reason {
        1 => DebugEntryCause::AttachDollar,
        2 => DebugEntryCause::CtrlC,
        _ => return,
    };

    let _debug_active = DebugActiveGuard::new();
    let saved_daif = cpu::read_daif();
    cpu::enable_irq();

    let now = timer::read_counter();
    let freq = timer::read_counter_frequency();
    let ticks = (u128::from(freq) * u128::from(ATTACH_DEADLINE_MS)) / 1000;
    let deadline = now.saturating_add(ticks as u64);

    let prefetch = gdb_uart::prefetch_first_rsp_frame(deadline);
    if prefetch != gdb_uart::PrefetchResult::Success {
        cpu::irq_restore(saved_daif);
        return;
    }

    aarch64_gdb::debug_entry(regs, cause);
    cpu::irq_restore(saved_daif);
}

fn copy_from_guest_ipa(ipa: u64, dst: &mut [u8]) -> Result<(), PagingErr> {
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

        // SAFETY: `chunk` is bounded by the slice and page size, and Stage-2 guarantees access.
        unsafe {
            ptr::copy_nonoverlapping(pa as *const u8, dst.as_mut_ptr().add(copied), chunk);
        }

        copied += chunk;
    }
    Ok(())
}

fn copy_to_guest_ipa(ipa: u64, src: &[u8]) -> Result<(), PagingErr> {
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

        // SAFETY: `chunk` is bounded by the slice and page size, and Stage-2 guarantees access.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr().add(copied), pa as *mut u8, chunk);
        }

        copied += chunk;
    }
    Ok(())
}
