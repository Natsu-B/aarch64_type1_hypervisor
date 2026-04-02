//! Generic byte stream traits for async I/O.

use core::task::Context;
use core::task::Poll;

/// Async byte stream interface.
pub trait PollByteStream {
    /// Error type for I/O operations.
    type Error;

    /// Polls for available data to read.
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>>;

    /// Polls for write readiness and writes data.
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Self::Error>>;

    /// Polls for flush completion.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
}
