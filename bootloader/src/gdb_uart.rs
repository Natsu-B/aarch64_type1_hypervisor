use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::pl011::FifoLevel;
use arch_hal::pl011::Pl011Uart;
use arch_hal::timer;
use core::hint::spin_loop;
use core::sync::atomic::Ordering;
use gdb_remote::RspFrameAssembler;
use gdb_remote::RspFrameEvent;
use mutex::pod::RawAtomicPod;

const RX_RING_SIZE: usize = 1024;
const PREFETCH_CAP: usize = RX_RING_SIZE + 4;
const NAK_ATTEMPTS: usize = 32;
const FLUSH_LIMIT: usize = RX_RING_SIZE;

// Publish debug entry state without relying on higher-level locking.
static DEBUG_ACTIVE: RawAtomicPod<bool> = RawAtomicPod::new_raw(false);
static ATTACH_REASON: RawAtomicPod<u8> = RawAtomicPod::new_raw(0);

struct RxRing<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
}

impl<const N: usize> RxRing<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            tail: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn push_drop_newest(&mut self, byte: u8) -> bool {
        let next = (self.head + 1) % N;
        if next == self.tail {
            // Drop newest when full to keep the oldest buffered data.
            return false;
        }
        self.buf[self.head] = byte;
        self.head = next;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.buf[self.tail];
        self.tail = (self.tail + 1) % N;
        Some(byte)
    }
}

struct GdbUartState<const N: usize> {
    uart: Pl011Uart,
    rx: RxRing<N>,
    prefetch_buf: [u8; PREFETCH_CAP],
    prefetch_len: usize,
    prefetch_pos: usize,
}

static GDB_UART_STATE: RawSpinLockIrqSave<Option<GdbUartState<RX_RING_SIZE>>> =
    RawSpinLockIrqSave::new(None);

pub fn init(base: usize, clock_hz: u64, baud: u32) {
    let mut uart = Pl011Uart::new(base, clock_hz);
    uart.init(baud);
    uart.enable_rx_interrupts(FifoLevel::OneQuarter, true);
    let state = GdbUartState {
        uart,
        rx: RxRing::new(),
        prefetch_buf: [0; PREFETCH_CAP],
        prefetch_len: 0,
        prefetch_pos: 0,
    };
    let mut guard = GDB_UART_STATE.lock_irqsave();
    *guard = Some(state);
}

pub fn handle_irq() {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return;
    };
    state.uart.handle_rx_irq(&mut |byte| {
        let _ = state.rx.push_drop_newest(byte);
        if !DEBUG_ACTIVE.load(Ordering::Acquire) {
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
    });
}

pub fn is_debug_active() -> bool {
    // Acquire pairs with Release stores so debug entry sees any buffered bytes.
    DEBUG_ACTIVE.load(Ordering::Acquire)
}

pub fn set_debug_active(active: bool) {
    // Release publishes debug-active transitions to IRQ readers.
    DEBUG_ACTIVE.store(active, Ordering::Release);
}

pub fn take_attach_reason() -> u8 {
    // AcqRel ensures we observe any IRQ-side buffering before consuming the reason.
    ATTACH_REASON.swap(0, Ordering::AcqRel)
}

pub fn clear_prefetch() {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return;
    };
    state.prefetch_len = 0;
    state.prefetch_pos = 0;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefetchResult {
    Success,
    Timeout,
    Overflow,
    Unavailable,
}

pub fn prefetch_first_rsp_frame(deadline_ticks: u64) -> PrefetchResult {
    clear_prefetch();
    {
        let guard = GDB_UART_STATE.lock_irqsave();
        if guard.is_none() {
            return PrefetchResult::Unavailable;
        }
    }

    let mut assembler = RspFrameAssembler::new();
    let mut buf = [0u8; PREFETCH_CAP];
    let mut len = 0usize;

    loop {
        if timer::read_counter() >= deadline_ticks {
            return fail_prefetch(PrefetchResult::Timeout);
        }

        let Some(byte) = pop_rx_once() else {
            spin_loop();
            continue;
        };

        let event = assembler.push(byte);
        match event {
            RspFrameEvent::Ignore => {}
            RspFrameEvent::Resync => {
                len = 0;
                if !push_prefetch_byte(&mut buf, &mut len, byte) {
                    return fail_prefetch(PrefetchResult::Overflow);
                }
            }
            RspFrameEvent::NeedMore => {
                if !push_prefetch_byte(&mut buf, &mut len, byte) {
                    return fail_prefetch(PrefetchResult::Overflow);
                }
            }
            RspFrameEvent::CtrlC => {
                if !push_prefetch_byte(&mut buf, &mut len, byte) {
                    return fail_prefetch(PrefetchResult::Overflow);
                }
                if !store_prefetch(&buf[..len]) {
                    return PrefetchResult::Unavailable;
                }
                return PrefetchResult::Success;
            }
            RspFrameEvent::FrameComplete => {
                if !push_prefetch_byte(&mut buf, &mut len, byte) {
                    return fail_prefetch(PrefetchResult::Overflow);
                }
                if !store_prefetch(&buf[..len]) {
                    return PrefetchResult::Unavailable;
                }
                return PrefetchResult::Success;
            }
        }
    }
}

fn push_prefetch_byte(buf: &mut [u8], len: &mut usize, byte: u8) -> bool {
    if *len >= buf.len() {
        return false;
    }
    buf[*len] = byte;
    *len += 1;
    true
}

fn store_prefetch(buf: &[u8]) -> bool {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    if buf.len() > state.prefetch_buf.len() {
        return false;
    }
    state.prefetch_buf[..buf.len()].copy_from_slice(buf);
    state.prefetch_len = buf.len();
    state.prefetch_pos = 0;
    true
}

fn fail_prefetch(result: PrefetchResult) -> PrefetchResult {
    if matches!(result, PrefetchResult::Timeout | PrefetchResult::Overflow) {
        try_send_nak();
        flush_rx_ring();
        clear_prefetch();
    }
    result
}

fn try_send_nak() {
    for _ in 0..NAK_ATTEMPTS {
        if try_write_byte(b'-') {
            break;
        }
    }
}

fn flush_rx_ring() {
    for _ in 0..FLUSH_LIMIT {
        if pop_rx_once().is_none() {
            break;
        }
    }
}

fn pop_rx_once() -> Option<u8> {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    guard.as_mut()?.rx.pop()
}

fn pop_prefetch_or_rx() -> Option<u8> {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return None;
    };
    if state.prefetch_pos < state.prefetch_len {
        let byte = state.prefetch_buf[state.prefetch_pos];
        state.prefetch_pos += 1;
        if state.prefetch_pos >= state.prefetch_len {
            state.prefetch_pos = 0;
            state.prefetch_len = 0;
        }
        return Some(byte);
    }
    state.rx.pop()
}

pub fn try_read_byte() -> Option<u8> {
    pop_prefetch_or_rx()
}

pub fn try_write_byte(byte: u8) -> bool {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.uart.try_write_byte(byte)
}

pub fn flush() {}
