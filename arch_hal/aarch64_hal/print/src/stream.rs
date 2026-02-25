use crate::pl011::Pl011Uart;
use core::convert::Infallible;
use core::task::Context;
use core::task::Poll;
use io_api::stream::PollByteStream;

pub struct Pl011Stream<'a> {
    uart: &'a Pl011Uart,
}

impl<'a> Pl011Stream<'a> {
    pub const fn new(uart: &'a Pl011Uart) -> Self {
        Self { uart }
    }
}

impl PollByteStream for Pl011Stream<'_> {
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
            let Some(byte) = self.uart.try_read_byte() else {
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
            if !self.uart.try_write_byte(buf[written]) {
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
        self.uart.flush();
        Poll::Ready(Ok(()))
    }
}
