#![no_std]

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::convert::Infallible;
use core::hint::spin_loop;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// Errors that can occur while using a byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError<E> {
    /// Underlying transport-level error.
    Transport(E),
    /// Stream has been closed and no more data can be read or written.
    Closed,
}

/// Non-blocking, IRQ-friendly byte-oriented stream abstraction.
pub trait ByteStream {
    /// Error type returned by stream operations.
    type Error;

    /// Attempt to read a single byte from the stream.
    ///
    /// Returns `Ok(Some(byte))` when a byte is available, or `Ok(None)` if the
    /// operation would block.
    fn try_read(&self) -> Result<Option<u8>, Self::Error>;

    /// Attempt to write a single byte to the stream.
    ///
    /// Returns `Ok(true)` when the byte is accepted/enqueued, or `Ok(false)` if
    /// the operation would block.
    fn try_write(&self, byte: u8) -> Result<bool, Self::Error>;

    /// Kick transmit progress or update hardware state.
    ///
    /// Must be non-blocking.
    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Blocking helpers for `ByteStream`.
///
/// These helpers spin until progress is possible and are **not IRQ-safe**.
pub trait ByteStreamBlockingExt: ByteStream {
    /// Read a single byte, spinning until one is available.
    ///
    /// Not IRQ-safe; do not call from interrupt context.
    fn read_blocking(&self) -> Result<u8, Self::Error> {
        loop {
            match self.try_read()? {
                Some(b) => return Ok(b),
                None => spin_loop(),
            }
        }
    }

    /// Write a single byte, spinning until it is accepted.
    ///
    /// Not IRQ-safe; do not call from interrupt context.
    fn write_blocking(&self, byte: u8) -> Result<(), Self::Error> {
        loop {
            match self.try_write(byte)? {
                true => return Ok(()),
                false => spin_loop(),
            }
        }
    }

    /// Write an entire buffer, spinning until all bytes are accepted.
    ///
    /// Not IRQ-safe; do not call from interrupt context.
    fn write_all_blocking(&self, buf: &[u8]) -> Result<(), Self::Error> {
        for &b in buf {
            self.write_blocking(b)?;
        }
        self.flush()
    }
}

impl<T: ByteStream + ?Sized> ByteStreamBlockingExt for T {}

struct SpscRingBuffer<const N: usize> {
    buf: UnsafeCell<[u8; N]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl<const N: usize> SpscRingBuffer<N> {
    const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0u8; N]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, byte: u8) -> bool {
        if N == 0 {
            return false;
        }
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = if tail + 1 == N { 0 } else { tail + 1 };
        if next_tail == head {
            return false;
        }
        // SAFETY: Single-producer writes to the slot indexed by `tail`, and the
        // consumer only reads slots after observing the published tail. The
        // buffer is accessed through `UnsafeCell` to avoid creating aliased
        // mutable references.
        unsafe {
            (*self.buf.get())[tail] = byte;
        }
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<u8> {
        if N == 0 {
            return None;
        }
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        // SAFETY: Single-consumer reads the slot indexed by `head` after
        // loading `tail` with Acquire, which pairs with the producer's Release
        // store that published the data. No mutable references are created.
        let byte = unsafe { (*self.buf.get())[head] };
        let next_head = if head + 1 == N { 0 } else { head + 1 };
        self.head.store(next_head, Ordering::Release);
        Some(byte)
    }
}

// SAFETY: The API enforces single-producer/single-consumer usage. The producer
// and consumer only coordinate via atomics with Acquire/Release ordering, and
// all interior mutation uses `UnsafeCell` without creating aliasing `&mut`.
unsafe impl<const N: usize> Sync for SpscRingBuffer<N> {}

/// IRQ-friendly byte stream backed by single-producer/single-consumer rings.
///
/// RX ring: `rx_push_irq` is the sole producer and `try_read` is the sole consumer.
/// TX ring: `try_write` is the sole producer and `tx_pop_irq` is the sole consumer.
/// Each ring leaves one slot empty to distinguish full from empty (capacity `N - 1`).
pub struct IrqBufferedStream<const RX: usize, const TX: usize> {
    rx: SpscRingBuffer<RX>,
    tx: SpscRingBuffer<TX>,
    rx_closed: AtomicBool,
    tx_closed: AtomicBool,
}

impl<const RX: usize, const TX: usize> IrqBufferedStream<RX, TX> {
    pub const fn new() -> Self {
        Self {
            rx: SpscRingBuffer::new(),
            tx: SpscRingBuffer::new(),
            rx_closed: AtomicBool::new(false),
            tx_closed: AtomicBool::new(false),
        }
    }

    /// Push a received byte from IRQ context. Returns `false` if RX is full or closed.
    pub fn rx_push_irq(&self, b: u8) -> bool {
        if self.rx_closed.load(Ordering::Acquire) {
            return false;
        }
        self.rx.push(b)
    }

    /// Pop a byte for TX from IRQ context.
    pub fn tx_pop_irq(&self) -> Option<u8> {
        self.tx.pop()
    }

    /// Mark the RX side as closed; no further data will arrive.
    pub fn close_rx(&self) {
        self.rx_closed.store(true, Ordering::Release);
    }

    /// Mark the TX side as closed; no further writes are accepted.
    pub fn close_tx(&self) {
        self.tx_closed.store(true, Ordering::Release);
    }
}

impl<const RX: usize, const TX: usize> Default for IrqBufferedStream<RX, TX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RX: usize, const TX: usize> ByteStream for IrqBufferedStream<RX, TX> {
    type Error = StreamError<Infallible>;

    fn try_read(&self) -> Result<Option<u8>, Self::Error> {
        if let Some(b) = self.rx.pop() {
            return Ok(Some(b));
        }
        if self.rx_closed.load(Ordering::Acquire) {
            return Err(StreamError::Closed);
        }
        Ok(None)
    }

    fn try_write(&self, byte: u8) -> Result<bool, Self::Error> {
        if self.tx_closed.load(Ordering::Acquire) {
            return Err(StreamError::Closed);
        }
        Ok(self.tx.push(byte))
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use std::cell::RefCell;
    use std::vec::Vec;

    struct StubStream {
        read_calls: Cell<usize>,
        read_ready_after: usize,
        read_value: u8,
        write_block_until: Cell<usize>,
        writes: RefCell<Vec<u8>>,
        flush_calls: Cell<usize>,
    }

    impl StubStream {
        fn new(read_ready_after: usize, read_value: u8, write_block_until: usize) -> Self {
            Self {
                read_calls: Cell::new(0),
                read_ready_after,
                read_value,
                write_block_until: Cell::new(write_block_until),
                writes: RefCell::new(Vec::new()),
                flush_calls: Cell::new(0),
            }
        }
    }

    impl ByteStream for StubStream {
        type Error = ();

        fn try_read(&self) -> Result<Option<u8>, Self::Error> {
            let calls = self.read_calls.get();
            self.read_calls.set(calls + 1);
            if calls < self.read_ready_after {
                Ok(None)
            } else {
                Ok(Some(self.read_value))
            }
        }

        fn try_write(&self, byte: u8) -> Result<bool, Self::Error> {
            let remaining = self.write_block_until.get();
            if remaining > 0 {
                self.write_block_until.set(remaining - 1);
                return Ok(false);
            }
            self.writes.borrow_mut().push(byte);
            Ok(true)
        }

        fn flush(&self) -> Result<(), Self::Error> {
            let calls = self.flush_calls.get();
            self.flush_calls.set(calls + 1);
            Ok(())
        }
    }

    #[test]
    fn irq_buffered_stream_rx_roundtrip() {
        let stream: IrqBufferedStream<4, 4> = IrqBufferedStream::new();
        assert!(stream.rx_push_irq(0x11));
        assert!(stream.rx_push_irq(0x22));
        assert!(stream.rx_push_irq(0x33));
        assert!(!stream.rx_push_irq(0x44));

        assert_eq!(stream.try_read().unwrap(), Some(0x11));
        assert_eq!(stream.try_read().unwrap(), Some(0x22));
        assert_eq!(stream.try_read().unwrap(), Some(0x33));
        assert_eq!(stream.try_read().unwrap(), None);

        stream.close_rx();
        assert_eq!(stream.try_read(), Err(StreamError::Closed));
        assert!(!stream.rx_push_irq(0x55));
    }

    #[test]
    fn irq_buffered_stream_tx_roundtrip() {
        let stream: IrqBufferedStream<4, 4> = IrqBufferedStream::new();
        assert_eq!(stream.try_write(0x10).unwrap(), true);
        assert_eq!(stream.try_write(0x20).unwrap(), true);
        assert_eq!(stream.try_write(0x30).unwrap(), true);
        assert_eq!(stream.try_write(0x40).unwrap(), false);

        assert_eq!(stream.tx_pop_irq(), Some(0x10));
        assert_eq!(stream.tx_pop_irq(), Some(0x20));
        assert_eq!(stream.tx_pop_irq(), Some(0x30));
        assert_eq!(stream.tx_pop_irq(), None);

        stream.close_tx();
        assert_eq!(stream.try_write(0x50), Err(StreamError::Closed));
    }

    #[test]
    fn blocking_ext_helpers() {
        let stream = StubStream::new(3, 0x5a, 2);
        let byte = stream.read_blocking().unwrap();
        assert_eq!(byte, 0x5a);
        assert!(stream.read_calls.get() >= 4);

        stream.write_blocking(0xaa).unwrap();
        stream.write_all_blocking(&[0x01, 0x02]).unwrap();

        let writes = stream.writes.borrow();
        assert_eq!(&*writes, &[0xaa, 0x01, 0x02]);
        assert_eq!(stream.flush_calls.get(), 1);
    }
}
