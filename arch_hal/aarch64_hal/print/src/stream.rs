use byte_stream::ByteStream;
use core::convert::Infallible;

use crate::pl011::Pl011Uart;

/// Non-blocking byte-stream adapter over a PL011 UART.
pub struct Pl011Stream<'a> {
    uart: &'a Pl011Uart,
}

impl<'a> Pl011Stream<'a> {
    pub fn new(uart: &'a Pl011Uart) -> Self {
        Self { uart }
    }
}

impl<'a> ByteStream for Pl011Stream<'a> {
    type Error = Infallible;

    fn try_read(&self) -> Result<Option<u8>, Self::Error> {
        Ok(self.uart.try_read_byte())
    }

    fn try_write(&self, byte: u8) -> Result<bool, Self::Error> {
        Ok(self.uart.try_write_byte(byte))
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
