use byte_stream::ByteStream;
use core::convert::Infallible;

use crate::pl011::Pl011Uart;

/// Blocking byte-stream adapter over a PL011 UART.
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

    fn read(&mut self) -> Result<u8, Self::Error> {
        Ok(self.uart.read_char())
    }

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.uart.write_byte(byte);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
