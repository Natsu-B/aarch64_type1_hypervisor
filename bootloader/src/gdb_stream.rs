use crate::gdb_uart;
use core::convert::Infallible;
use core::task::Context;
use core::task::Poll;
use io_api::stream::PollByteStream;

pub struct BootGdbUartStream;

impl BootGdbUartStream {
    pub const fn new() -> Self {
        Self
    }
}

impl PollByteStream for BootGdbUartStream {
    type Error = Infallible;

    fn poll_read(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut read = 0usize;
        while read < buf.len() {
            let Some(byte) = gdb_uart::try_read_byte() else {
                break;
            };
            buf[read] = byte;
            read += 1;
        }

        if read == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(read))
        }
    }

    fn poll_write(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut written = 0usize;
        while written < buf.len() {
            if !gdb_uart::try_write_byte(buf[written]) {
                break;
            }
            written += 1;
        }

        if written == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(written))
        }
    }

    fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        gdb_uart::flush();
        Poll::Ready(Ok(()))
    }
}
