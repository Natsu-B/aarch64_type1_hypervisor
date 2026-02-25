use dtb::DtbParser;
use io_api::ethernet::EthernetFrameIo;

/// Initializes and returns the board Ethernet frame I/O backend from DTB data.
///
/// This is currently a placeholder until the RPi4 NIC driver is wired.
pub fn init_ethernet_from_dtb(_dtb: &DtbParser) -> &'static mut dyn EthernetFrameIo {
    unimplemented!("rpi4_net enabled but NIC driver not wired yet")
}
