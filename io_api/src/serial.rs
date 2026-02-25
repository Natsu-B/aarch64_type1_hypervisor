pub trait SerialByteIo {
    type Error;

    fn try_read_byte(&self) -> Option<u8>;

    fn try_write_byte(&self, byte: u8) -> bool;

    fn flush(&self) -> Result<(), Self::Error>;
}

pub trait SerialRxIrq {
    fn handle_rx_irq(&self, on_byte: &mut dyn FnMut(u8));
}

pub trait SerialIrqCtrl {
    fn set_rx_irq_enabled(&self, enabled: bool);

    fn set_tx_irq_enabled(&self, enabled: bool);
}
