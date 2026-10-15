//! GDB debug-session state shared by the PL011 and UDP GDB transports.
//!
//! Exactly one transport module is compiled in as `gdb_uart` (selected by the `rpi4_net` /
//! `virtio_net` features). Both expose the same session-flag API, so the flags, their
//! accessors, and the RX ring buffer live here and are re-exported by the active transport.

use core::sync::atomic::Ordering;
use mutex::pod::RawAtomicPod;

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
