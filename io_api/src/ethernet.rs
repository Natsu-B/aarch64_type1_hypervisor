#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MacAddr(pub [u8; 6]);

pub trait EthernetFrameIo {
    /// Returns the maximum frame size supported by this backend.
    fn max_frame_len(&self) -> usize;

    /// Returns the local MAC address for this interface.
    fn mac_addr(&self) -> MacAddr;

    /// Attempts to receive one frame into `buf`.
    ///
    /// Returns the received frame length on success.
    fn try_recv_frame(&mut self, buf: &mut [u8]) -> Option<usize>;

    /// Attempts to transmit one complete frame.
    fn try_send_frame(&mut self, frame: &[u8]) -> bool;

    /// Optional IRQ hook for backends that require interrupt-side servicing.
    fn on_irq(&mut self) {}
}
