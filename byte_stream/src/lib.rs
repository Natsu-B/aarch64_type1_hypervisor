#![no_std]

/// Errors that can occur while using a byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError<E> {
    /// Underlying transport-level error.
    Transport(E),
    /// Stream has been closed and no more data can be read.
    Closed,
}

/// Blocking byte-oriented stream abstraction.
pub trait ByteStream {
    /// Error type returned by stream operations.
    type Error;

    /// Read a single byte from the stream, blocking until available.
    fn read(&mut self) -> Result<u8, Self::Error>;

    /// Write a single byte to the stream.
    fn write(&mut self, byte: u8) -> Result<(), Self::Error>;

    /// Flush any buffered data. Default is a no-op.
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Write an entire buffer to the stream.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        for &b in buf {
            self.write(b)?;
        }
        self.flush()
    }
}
