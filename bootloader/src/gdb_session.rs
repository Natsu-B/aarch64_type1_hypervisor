//! GDB debug-session state shared by the PL011 and UDP GDB transports.
//!
//! Exactly one transport module is compiled in as `gdb_uart` (selected by the `rpi4_net` /
//! `virtio_net` features). Both expose the same session-flag API, so the flags, their
//! accessors, the RX ring buffer, and the first-frame prefetch logic live here and are
//! re-exported by the active transport.

use arch_hal::timer;
use core::hint::spin_loop;
use core::sync::atomic::Ordering;
use gdb_remote::RspFrameAssembler;
use gdb_remote::RspFrameEvent;
use mutex::pod::RawAtomicPod;

/// Capacity of the attach prefetch buffer: one maximum-size RSP packet plus framing.
const PREFETCH_CAP: usize = 1024 + 4;
/// How many times a failed prefetch retries sending the `-` NAK before giving up.
const NAK_ATTEMPTS: usize = 32;

// Publish debug entry state without relying on higher-level locking.
pub(crate) static DEBUG_ACTIVE: RawAtomicPod<bool> =
    unsafe { RawAtomicPod::new_raw_unchecked(false) };
// Set once a GDB session handshake has completed and we should emit async stop replies.
pub(crate) static DEBUG_SESSION_ACTIVE: RawAtomicPod<bool> =
    unsafe { RawAtomicPod::new_raw_unchecked(false) };
// Tracks whether we've completed an initial RSP handshake at least once.
pub(crate) static DEBUG_SESSION_INITIALIZED: RawAtomicPod<bool> =
    unsafe { RawAtomicPod::new_raw_unchecked(false) };
// Why the debugger should attach: 0 = none, 1 = RSP frame start, 2 = Ctrl-C interrupt.
pub(crate) static ATTACH_REASON: RawAtomicPod<u8> = unsafe { RawAtomicPod::new_raw_unchecked(0) };

/// Fixed-size RX byte ring that drops the oldest byte when full.
pub(crate) struct RxRing<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
}

impl<const N: usize> RxRing<N> {
    // The PL011 transport zero-initialises its state in place, so only the UDP transport
    // constructs the ring with `new`.
    #[cfg_attr(
        not(any(feature = "rpi4_net", feature = "virtio_net")),
        allow(dead_code)
    )]
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            tail: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub(crate) fn push_drop_oldest(&mut self, byte: u8) -> bool {
        let next = (self.head + 1) % N;
        if next == self.tail {
            // Drop oldest to preserve the newest bytes for resync/attach.
            self.tail = (self.tail + 1) % N;
        }
        self.buf[self.head] = byte;
        self.head = next;
        true
    }

    pub(crate) fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.buf[self.tail];
        self.tail = (self.tail + 1) % N;
        Some(byte)
    }

    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}

/// Returns whether the debugger is currently active.
pub fn is_debug_active() -> bool {
    // Acquire pairs with Release stores so debug entry sees any buffered bytes.
    DEBUG_ACTIVE.load(Ordering::Acquire)
}

/// Updates debug-active state.
pub fn set_debug_active(active: bool) {
    // Release publishes debug-active transitions to IRQ readers.
    DEBUG_ACTIVE.store(active, Ordering::Release);
}

/// Returns whether the GDB session handshake has completed.
pub fn is_debug_session_active() -> bool {
    DEBUG_SESSION_ACTIVE.load(Ordering::Acquire)
}

/// Updates GDB session-active state.
pub fn set_debug_session_active(active: bool) {
    DEBUG_SESSION_ACTIVE.store(active, Ordering::Release);
}

/// Returns whether the first session initialization has happened.
pub fn is_debug_session_initialized() -> bool {
    DEBUG_SESSION_INITIALIZED.load(Ordering::Acquire)
}

/// Updates one-time session-initialized state.
pub fn set_debug_session_initialized(active: bool) {
    DEBUG_SESSION_INITIALIZED.store(active, Ordering::Release);
}

/// Consumes and returns the current attach reason.
pub fn take_attach_reason() -> u8 {
    // AcqRel ensures we observe any IRQ-side buffering before consuming the reason.
    ATTACH_REASON.swap(0, Ordering::AcqRel)
}

/// Reads attach reason without consuming it.
pub fn peek_attach_reason() -> u8 {
    ATTACH_REASON.load(Ordering::Acquire)
}

/// First RSP frame captured during attach, replayed to the GDB stub before live RX bytes.
pub(crate) struct PrefetchBuf {
    buf: [u8; PREFETCH_CAP],
    len: usize,
    pos: usize,
}

impl PrefetchBuf {
    // The PL011 transport zero-initialises its state in place, so only the UDP transport
    // constructs the buffer with `new`.
    #[cfg_attr(
        not(any(feature = "rpi4_net", feature = "virtio_net")),
        allow(dead_code)
    )]
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; PREFETCH_CAP],
            len: 0,
            pos: 0,
        }
    }

    /// Clears any buffered prefetch bytes.
    pub(crate) fn clear(&mut self) {
        self.len = 0;
        self.pos = 0;
    }

    /// Stores `byte` at `index` of the frame being collected; fails once the buffer is full.
    fn write_at(&mut self, index: usize, byte: u8) -> bool {
        let Some(slot) = self.buf.get_mut(index) else {
            return false;
        };
        *slot = byte;
        true
    }

    /// Publishes the first `len` collected bytes so [`Self::pop`] replays them.
    fn publish(&mut self, len: usize) -> bool {
        if len > self.buf.len() {
            return false;
        }
        self.len = len;
        self.pos = 0;
        true
    }

    /// Returns the next prefetched byte, rewinding the buffer once it is drained.
    pub(crate) fn pop(&mut self) -> Option<u8> {
        if self.pos >= self.len {
            return None;
        }
        let byte = self.buf[self.pos];
        self.pos += 1;
        if self.pos >= self.len {
            self.clear();
        }
        Some(byte)
    }
}

/// Result of first-frame prefetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefetchResult {
    Success,
    Timeout,
    Overflow,
    Unavailable,
}

/// Byte-level hooks a GDB transport provides to the shared attach prefetch logic.
pub(crate) trait GdbTransport {
    /// Runs `f` on the transport's prefetch buffer, or returns `None` before initialization.
    fn with_prefetch<R>(f: impl FnOnce(&mut PrefetchBuf) -> R) -> Option<R>;

    /// Reads one byte from prefetched, buffered, or (while stopped) live input.
    fn try_read_byte() -> Option<u8>;

    /// Writes one byte to the debugger, returning `false` if the transport is busy.
    fn try_write_byte(byte: u8) -> bool;

    /// Discards buffered RX input after a failed prefetch.
    fn flush_rx_input();
}

/// Prefetches the first incoming RSP frame for attach handling.
///
/// Waits for the first byte within `attach_deadline_ticks`, then extends the timeout
/// by `idle_timeout_ticks` on every subsequent byte to avoid tearing down slow-but-active
/// transfers.
pub(crate) fn prefetch_first_rsp_frame<T: GdbTransport>(
    attach_deadline_ticks: u64,
    idle_timeout_ticks: u64,
) -> PrefetchResult {
    if T::with_prefetch(PrefetchBuf::clear).is_none() {
        return PrefetchResult::Unavailable;
    }

    let mut assembler = RspFrameAssembler::new();
    let mut len = 0usize;

    let el2_timer = timer::El2PhysicalTimer::new();
    let mut attached = false;
    let mut deadline_ticks = attach_deadline_ticks;

    loop {
        let now = el2_timer.now();
        if !attached {
            if now >= deadline_ticks {
                return fail_prefetch::<T>(PrefetchResult::Timeout);
            }
        } else if idle_timeout_ticks != 0 && now >= deadline_ticks {
            return fail_prefetch::<T>(PrefetchResult::Timeout);
        }

        let Some(byte) = T::try_read_byte() else {
            spin_loop();
            continue;
        };

        let event = assembler.push(byte);
        match event {
            RspFrameEvent::Ignore => continue,
            // A new `$` restarts frame collection from this byte.
            RspFrameEvent::Resync => len = 0,
            RspFrameEvent::NeedMore | RspFrameEvent::CtrlC | RspFrameEvent::FrameComplete => {}
        }
        attached = true;
        if idle_timeout_ticks != 0 {
            deadline_ticks = el2_timer.now().saturating_add(idle_timeout_ticks);
        }

        if !push_prefetch_byte::<T>(&mut len, byte) {
            return fail_prefetch::<T>(PrefetchResult::Overflow);
        }
        if matches!(event, RspFrameEvent::CtrlC | RspFrameEvent::FrameComplete) {
            if T::with_prefetch(|prefetch| prefetch.publish(len)) != Some(true) {
                return PrefetchResult::Unavailable;
            }
            return PrefetchResult::Success;
        }
    }
}

fn push_prefetch_byte<T: GdbTransport>(len: &mut usize, byte: u8) -> bool {
    if T::with_prefetch(|prefetch| prefetch.write_at(*len, byte)) != Some(true) {
        return false;
    }
    *len += 1;
    true
}

fn fail_prefetch<T: GdbTransport>(result: PrefetchResult) -> PrefetchResult {
    if matches!(result, PrefetchResult::Timeout | PrefetchResult::Overflow) {
        try_send_nak::<T>();
        T::flush_rx_input();
        let _ = T::with_prefetch(PrefetchBuf::clear);
    }
    result
}

fn try_send_nak<T: GdbTransport>() {
    for _ in 0..NAK_ATTEMPTS {
        if T::try_write_byte(b'-') {
            break;
        }
    }
}
