use crate::gdb_session;
use crate::gdb_session::ATTACH_REASON;
use crate::gdb_session::DEBUG_SESSION_ACTIVE;
use crate::gdb_session::GdbTransport;
use crate::gdb_session::PrefetchBuf;
pub use crate::gdb_session::PrefetchResult;
use crate::gdb_session::RxRing;
pub use crate::gdb_session::is_debug_active;
pub use crate::gdb_session::is_debug_session_active;
pub use crate::gdb_session::is_debug_session_initialized;
pub use crate::gdb_session::peek_attach_reason;
pub use crate::gdb_session::set_debug_active;
pub use crate::gdb_session::set_debug_session_active;
pub use crate::gdb_session::set_debug_session_initialized;
pub use crate::gdb_session::take_attach_reason;
use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::timer;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;
use mutex::pod::RawAtomicPod;

const RX_RING_SIZE: usize = 4096;
const FLUSH_LIMIT: usize = RX_RING_SIZE;

static STOP_LOOP_ACTIVE: RawAtomicPod<bool> = unsafe { RawAtomicPod::new_raw_unchecked(false) };

struct GdbUartState<const N: usize> {
    rx: RxRing<N>,
    prefetch: PrefetchBuf,
}

// SAFETY: `GDB_UART_READY` publishes initialization completion with Release ordering.
static GDB_UART_READY: RawAtomicPod<bool> = unsafe { RawAtomicPod::new_raw_unchecked(false) };
// SAFETY: mutated only with interrupts disabled (IRQ-save lock).
static GDB_UART_STATE: RawSpinLockIrqSave<MaybeUninit<GdbUartState<RX_RING_SIZE>>> =
    RawSpinLockIrqSave::new(MaybeUninit::uninit());

/// Initializes the UDP-backed GDB UART state.
///
/// This keeps the same call signature as the PL011 backend; arguments are ignored.
pub fn init(_base: usize, _clock_hz: u64, _baud: u32) {
    // Fast-path: already initialized.
    if GDB_UART_READY.load(Ordering::Acquire) {
        return;
    }
    let mut guard = GDB_UART_STATE.lock_irqsave();
    if GDB_UART_READY.load(Ordering::Acquire) {
        return;
    }
    (*guard).write(GdbUartState {
        rx: RxRing::new(),
        prefetch: PrefetchBuf::new(),
    });
    GDB_UART_READY.store(true, Ordering::Release);
}

/// Guard that keeps stop-loop state active until drop.
pub struct StopLoopGuard {
    restore: bool,
    pause_start_ticks: u64,
}

/// Begins a debug stop-loop section for attach/prefetch logic.
pub fn begin_stop_loop() -> StopLoopGuard {
    // Enforce nesting avoidance with one CAS RMW so only one core can mark stop-loop active.
    // RawAtomicPod becomes truly atomic only after `mutex::enable_raw_atomics()` during
    // single-core bring-up; SMP correctness requires that sequencing before secondaries start.
    if STOP_LOOP_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return StopLoopGuard {
            restore: false,
            pause_start_ticks: 0,
        };
    }
    let pause_start_ticks = timer::El2PhysicalTimer::new().now();

    if !GDB_UART_READY.load(Ordering::Acquire) {
        return StopLoopGuard {
            restore: true,
            pause_start_ticks,
        };
    }
    let mut guard = GDB_UART_STATE.lock_irqsave();
    // SAFETY: READY is published after full initialization with Release ordering.
    let state = unsafe { (*guard).assume_init_mut() };
    state.prefetch.clear();
    StopLoopGuard {
        restore: true,
        pause_start_ticks,
    }
}

impl Drop for StopLoopGuard {
    fn drop(&mut self) {
        if !self.restore {
            return;
        }
        let el2_timer = timer::El2PhysicalTimer::new();
        let now = el2_timer.now();
        let delta = now.wrapping_sub(self.pause_start_ticks);
        let old = el2_timer.lower_el_virtual_offset();
        // Compensate CNTVOFF_EL2 by the stop-loop duration so guest CNTVCT does not advance.
        let new = old.wrapping_add(delta);
        el2_timer.set_lower_el_virtual_offset(new);
        if GDB_UART_READY.load(Ordering::Acquire) {
            let mut guard = GDB_UART_STATE.lock_irqsave();
            // SAFETY: READY is published after full initialization with Release ordering.
            let state = unsafe { (*guard).assume_init_mut() };
            state.rx.clear();
            state.prefetch.clear();
        }
        STOP_LOOP_ACTIVE.store(false, Ordering::Release);
    }
}

/// Handles backend IRQ work.
///
/// For UDP transport this is equivalent to polling RX.
pub fn handle_irq() {
    poll_rx();
}

/// Polls UDP RX and drains bytes into the internal ring buffer.
pub fn poll_rx() {
    if !GDB_UART_READY.load(Ordering::Acquire) {
        return;
    }
    let mut guard = GDB_UART_STATE.lock_irqsave();
    // SAFETY: READY is published after full initialization with Release ordering.
    let state = unsafe { (*guard).assume_init_mut() };
    crate::net::udp_uart::poll(
        |byte| {
            let _ = state.rx.push_drop_oldest(byte);
            record_attach_byte(byte);
        },
        |_byte| {},
    );
}

fn record_attach_byte(byte: u8) {
    // Breakpoint: attach byte detection (should be inactive after session init).
    if !DEBUG_SESSION_ACTIVE.load(Ordering::Acquire) {
        let reason = ATTACH_REASON.load(Ordering::Acquire);
        if byte == 0x03 {
            // Release publishes the attach request after RX buffering.
            if reason != 2 {
                ATTACH_REASON.store(2, Ordering::Release);
            }
        } else if byte == b'$' && reason == 0 {
            // Release publishes the attach request after RX buffering.
            ATTACH_REASON.store(1, Ordering::Release);
        }
    }
}

/// Prefetches the first incoming RSP frame for attach handling.
///
/// See [`gdb_session::prefetch_first_rsp_frame`] for the timeout semantics.
pub fn prefetch_first_rsp_frame(
    attach_deadline_ticks: u64,
    idle_timeout_ticks: u64,
) -> PrefetchResult {
    gdb_session::prefetch_first_rsp_frame::<Transport>(attach_deadline_ticks, idle_timeout_ticks)
}

/// UDP hooks for the shared attach prefetch logic.
struct Transport;

impl GdbTransport for Transport {
    fn with_prefetch<R>(f: impl FnOnce(&mut PrefetchBuf) -> R) -> Option<R> {
        if !GDB_UART_READY.load(Ordering::Acquire) {
            return None;
        }
        let mut guard = GDB_UART_STATE.lock_irqsave();
        // SAFETY: READY is published after full initialization with Release ordering.
        let state = unsafe { (*guard).assume_init_mut() };
        Some(f(&mut state.prefetch))
    }

    fn try_read_byte() -> Option<u8> {
        self::try_read_byte()
    }

    fn try_write_byte(byte: u8) -> bool {
        self::try_write_byte(byte)
    }

    fn flush_rx_input() {
        self::flush_rx_input();
    }
}

fn flush_rx_input() {
    if !GDB_UART_READY.load(Ordering::Acquire) {
        return;
    }
    let mut guard = GDB_UART_STATE.lock_irqsave();
    // SAFETY: READY is published after full initialization with Release ordering.
    let state = unsafe { (*guard).assume_init_mut() };
    for _ in 0..FLUSH_LIMIT {
        if state.rx.pop().is_none() {
            break;
        }
    }
}

/// Tries to read one byte from prefetched/ring data.
pub fn try_read_byte() -> Option<u8> {
    if !GDB_UART_READY.load(Ordering::Acquire) {
        return None;
    }
    {
        let mut guard = GDB_UART_STATE.lock_irqsave();
        // SAFETY: READY is published after full initialization with Release ordering.
        let state = unsafe { (*guard).assume_init_mut() };

        if let Some(byte) = state.prefetch.pop() {
            return Some(byte);
        }
        if let Some(byte) = state.rx.pop() {
            return Some(byte);
        }
    }

    // Poll backend directly when the debug loop is active or in a stop-loop section.
    if STOP_LOOP_ACTIVE.load(Ordering::Acquire) || is_debug_active() {
        poll_rx();
        let mut guard = GDB_UART_STATE.lock_irqsave();
        // SAFETY: READY is published after full initialization with Release ordering.
        let state = unsafe { (*guard).assume_init_mut() };
        return state.rx.pop();
    }
    None
}

/// Tries to write one byte over UDP-backed GDB transport.
pub fn try_write_byte(byte: u8) -> bool {
    if !GDB_UART_READY.load(Ordering::Acquire) {
        return false;
    }
    crate::net::udp_uart::gdb_try_write_byte(byte)
}

/// Flushes pending GDB transport bytes.
pub fn flush() {
    if !GDB_UART_READY.load(Ordering::Acquire) {
        return;
    }
    crate::net::udp_uart::gdb_flush();
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::gdb_session::DEBUG_ACTIVE;
    use crate::gdb_session::DEBUG_SESSION_INITIALIZED;
    use core::sync::atomic::Ordering;

    fn reset_attach_state() {
        DEBUG_ACTIVE.store(false, Ordering::Release);
        DEBUG_SESSION_ACTIVE.store(false, Ordering::Release);
        DEBUG_SESSION_INITIALIZED.store(false, Ordering::Release);
        ATTACH_REASON.store(0, Ordering::Release);
    }

    #[test_case]
    fn attach_reason_sets_with_debug_active_and_session_inactive() {
        reset_attach_state();
        set_debug_active(true);
        set_debug_session_active(false);
        record_attach_byte(b'$');
        assert_eq!(ATTACH_REASON.load(Ordering::Acquire), 1);
        reset_attach_state();
    }

    #[test_case]
    fn attach_reason_ignored_when_session_active() {
        reset_attach_state();
        set_debug_session_active(true);
        record_attach_byte(b'$');
        assert_eq!(ATTACH_REASON.load(Ordering::Acquire), 0);
        reset_attach_state();
    }
}
