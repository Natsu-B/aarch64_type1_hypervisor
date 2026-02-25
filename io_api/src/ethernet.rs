#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MacAddr(pub [u8; 6]);

pub trait EthernetFrameIo {
    const MAX_FRAME: usize;

    fn try_recv_frame(&mut self, buf: &mut [u8]) -> Option<usize>;

    fn try_send_frame(&mut self, frame: &[u8]) -> bool;

    fn on_irq(&mut self);
}
