use crate::gdb_uart;
use crate::monitor;
use arch_hal::aarch64_gdb;
use arch_hal::aarch64_gdb::Aarch64GdbStub;
use arch_hal::aarch64_gdb::DebugEntryCause;
use arch_hal::aarch64_gdb::DebugIo;
use arch_hal::aarch64_gdb::MemoryAccess;
use arch_hal::aarch64_gdb::WatchpointKind;
use arch_hal::cpu;
use arch_hal::exceptions::registers::ExceptionClass;
use arch_hal::paging::PagingErr;
use arch_hal::paging::Stage2Paging;
use arch_hal::timer;
use core::cell::SyncUnsafeCell;
use core::cmp::min;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::Ordering;
use mutex::pod::RawAtomicPod;

const PAGE_SIZE: usize = 0x1000;
const MAX_GDB_PKT: usize = 8192;
const MAX_GDB_TX_CAP: usize = 16384;
const ATTACH_DEADLINE_MS: u64 = 5000;
const PREFETCH_IDLE_TIMEOUT_MS: u64 = 2000;
// Set to 0 to disable the post-attach idle timeout.
const IDLE_TIMEOUT_MS: u64 = 60000;

struct DebugActiveGuard {
    prev: bool,
}

impl DebugActiveGuard {
    fn new() -> Self {
        let prev = gdb_uart::is_debug_active();
        gdb_uart::set_debug_active(true);
        Self { prev }
    }
}

impl Drop for DebugActiveGuard {
    fn drop(&mut self) {
        gdb_uart::set_debug_active(self.prev);
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

type GdbStub = Aarch64GdbStub<Stage2Memory, MAX_GDB_PKT, MAX_GDB_TX_CAP>;

static GDB_STUB: SyncUnsafeCell<MaybeUninit<GdbStub>> = SyncUnsafeCell::new(MaybeUninit::uninit());
static GUEST_IPA_BASE: RawAtomicPod<u64> = RawAtomicPod::new_raw(0);
static GUEST_IPA_SIZE: RawAtomicPod<u64> = RawAtomicPod::new_raw(0);
static MEMORY_MAP_BUF: SyncUnsafeCell<[u8; 1024]> = SyncUnsafeCell::new([0; 1024]);

pub fn set_guest_ipa_window(ipa_base: u64, ipa_size: u64) {
    GUEST_IPA_BASE.store(ipa_base, Ordering::Release);
    GUEST_IPA_SIZE.store(ipa_size, Ordering::Release);
}

pub fn set_memory_map(
    guest_ram_base: u64,
    guest_ram_size: u64,
    rom_ranges: &[(u64, u64)],
    io_ranges: &[(u64, u64)],
) {
    if guest_ram_size == 0 {
        set_stub_memory_map(None);
        return;
    }

    let buf = unsafe { &mut *MEMORY_MAP_BUF.get() };
    let mut idx = 0usize;
    let mut ok = append_bytes(buf, &mut idx, b"<memory-map>\n");
    for &(start, len) in rom_ranges {
        if len == 0 {
            continue;
        }
        ok &= append_memory_entry(buf, &mut idx, b"rom", start, len);
    }
    for &(start, len) in io_ranges {
        if len == 0 {
            continue;
        }
        ok &= append_memory_entry(buf, &mut idx, b"io", start, len);
    }
    ok &= append_memory_entry(buf, &mut idx, b"ram", guest_ram_base, guest_ram_size);
    ok &= append_bytes(buf, &mut idx, b"</memory-map>\n");

    if ok {
        set_stub_memory_map(Some(&buf[..idx]));
    } else {
        set_stub_memory_map(None);
    }
}

pub(crate) fn init_gdb_stub() {
    // SAFETY: called once during early boot, before debug exceptions are enabled.
    unsafe {
        let stub = &mut *GDB_STUB.get();
        aarch64_gdb::register_debug_io(DebugIo {
            try_read: gdb_uart::try_read_byte,
            try_write: gdb_uart::try_write_byte,
            flush: gdb_uart::flush,
        });
        // Avoid constructing large fixed-size buffers on the stack.
        GdbStub::init_in_place(stub, Stage2Memory);
        let stub = stub.assume_init_mut();
        stub.set_monitor_handler(Some(monitor::bootloader_monitor_handler));
        aarch64_gdb::register_debug_stub(stub);
    }
}

pub(crate) fn handle_debug_exception(regs: &mut cpu::Registers, ec: ExceptionClass) {
    if crate::vbar_watch::handle_debug_exception(regs, ec) {
        return;
    }
    // Nested exceptions during vbar_watch stepping return false to force a GDB stop.
    // Ensure the debug loop can make forward progress even if IRQ delivery is masked
    // on exception entry (polling path via gdb_uart + RX interrupt suppression).
    gdb_uart::set_debug_session_active(true);
    monitor::enable_memfault_trap_if_off();

    let _debug_active = DebugActiveGuard::new();
    let _stop_loop = gdb_uart::begin_stop_loop();
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
    let _stop_loop = gdb_uart::begin_stop_loop();

    let el2_timer = timer::El2PhysicalTimer::new();
    let (attach_deadline, prefetch_idle_ticks) = attach_deadlines(&el2_timer);
    // Reserved for post-attach idle timeout wiring in the debug loop.
    let _post_attach_idle_timeout_ms = IDLE_TIMEOUT_MS;

    let prefetch = gdb_uart::prefetch_first_rsp_frame(attach_deadline, prefetch_idle_ticks);
    if prefetch != gdb_uart::PrefetchResult::Success {
        cpu::irq_restore(saved_daif);
        return;
    }

    gdb_uart::set_debug_session_active(true);
    monitor::enable_memfault_trap_if_off();

    aarch64_gdb::debug_entry(regs, cause);
    cpu::irq_restore(saved_daif);
}

pub(crate) fn enter_debug_from_memfault(
    regs: &mut cpu::Registers,
    kind: WatchpointKind,
    addr: u64,
) -> bool {
    if gdb_uart::is_debug_active() {
        return false;
    }

    // Hold debug-active + stop-loop for the whole debug entry to guarantee polling works
    // even when guest IRQs are masked.
    let _debug_guard = DebugActiveGuard::new();
    let saved_daif = cpu::read_daif();
    let _stop_guard = gdb_uart::begin_stop_loop();
    gdb_uart::poll_rx();

    if !gdb_uart::is_debug_session_active() {
        let attach_reason = gdb_uart::take_attach_reason();
        if attach_reason == 0 {
            cpu::irq_restore(saved_daif);
            return false;
        }
        let attach_deadline_ticks = timer::El2PhysicalTimer::new()
            .now()
            .saturating_add(625_000_000);
        let idle_timeout_ticks = 3_750_000_000;
        let prefetch =
            gdb_uart::prefetch_first_rsp_frame(attach_deadline_ticks, idle_timeout_ticks);
        if prefetch != gdb_uart::PrefetchResult::Success {
            cpu::irq_restore(saved_daif);
            return false;
        }
        gdb_uart::set_debug_session_active(true);

        // IMPORTANT:
        // - The first RSP frame (e.g. qSupported) may already be buffered by prefetch.
        // - Do NOT send an unsolicited stop-reply (T05watch...) before replying to that request.
        // - Report the memfault stop reason via `?` using server last_stop.
        let cause = match attach_reason {
            2 => aarch64_gdb::DebugEntryCause::CtrlCWithWatchpoint { kind, addr },
            _ => aarch64_gdb::DebugEntryCause::AttachDollarWithWatchpoint { kind, addr },
        };
        aarch64_gdb::debug_entry(regs, cause);
        cpu::irq_restore(saved_daif);
        return true;
    }

    // Session already active: send a normal asynchronous watchpoint stop-reply.
    aarch64_gdb::debug_watchpoint_entry(regs, kind, addr);
    cpu::irq_restore(saved_daif);
    true
}

fn guest_ipa_contains(ipa: u64, len: usize) -> bool {
    let base = GUEST_IPA_BASE.load(Ordering::Acquire);
    let size = GUEST_IPA_SIZE.load(Ordering::Acquire);
    if size == 0 {
        return false;
    }
    let len = match u64::try_from(len) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let end = match ipa.checked_add(len) {
        Some(value) => value,
        None => return false,
    };
    let limit = match base.checked_add(size) {
        Some(value) => value,
        None => return false,
    };
    ipa >= base && end <= limit
}

fn set_stub_memory_map(data: Option<&'static [u8]>) {
    // SAFETY: called during early boot before concurrent debug entry.
    unsafe {
        let stub = &mut *GDB_STUB.get();
        let stub = stub.assume_init_mut();
        stub.set_memory_map(data);
    }
}

fn append_bytes(buf: &mut [u8], idx: &mut usize, bytes: &[u8]) -> bool {
    if buf.len().saturating_sub(*idx) < bytes.len() {
        return false;
    }
    let end = *idx + bytes.len();
    buf[*idx..end].copy_from_slice(bytes);
    *idx = end;
    true
}

fn attach_deadlines(el2_timer: &timer::El2PhysicalTimer) -> (u64, u64) {
    let now = el2_timer.now();
    let freq = el2_timer.counter_frequency_hz().get();
    let attach_ticks = (u128::from(freq) * u128::from(ATTACH_DEADLINE_MS)) / 1000;
    let attach_deadline = now.saturating_add(attach_ticks as u64);
    let prefetch_idle_ticks = if PREFETCH_IDLE_TIMEOUT_MS == 0 {
        0
    } else {
        let ticks = (u128::from(freq) * u128::from(PREFETCH_IDLE_TIMEOUT_MS)) / 1000;
        ticks.min(u128::from(u64::MAX)) as u64
    };
    (attach_deadline, prefetch_idle_ticks)
}

fn append_memory_entry(buf: &mut [u8], idx: &mut usize, kind: &[u8], start: u64, len: u64) -> bool {
    let mut ok = append_bytes(buf, idx, b"<memory type=\"");
    ok &= append_bytes(buf, idx, kind);
    ok &= append_bytes(buf, idx, b"\" start=\"0x");
    ok &= append_hex_u64(buf, idx, start);
    ok &= append_bytes(buf, idx, b"\" length=\"0x");
    ok &= append_hex_u64(buf, idx, len);
    ok &= append_bytes(buf, idx, b"\"/>\n");
    ok
}

fn append_hex_u64(buf: &mut [u8], idx: &mut usize, val: u64) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    let mut value = val;

    if value == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while value != 0 {
            tmp[len] = HEX[(value & 0xf) as usize];
            len += 1;
            value >>= 4;
        }
    }

    if buf.len().saturating_sub(*idx) < len {
        return false;
    }
    for i in 0..len {
        buf[*idx + i] = tmp[len - 1 - i];
    }
    *idx += len;
    true
}

fn copy_from_guest_ipa(ipa: u64, dst: &mut [u8]) -> Result<(), PagingErr> {
    if !guest_ipa_contains(ipa, dst.len()) {
        return Err(PagingErr::Stage2Fault);
    }
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
    if !guest_ipa_contains(ipa, src.len()) {
        return Err(PagingErr::Stage2Fault);
    }
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
