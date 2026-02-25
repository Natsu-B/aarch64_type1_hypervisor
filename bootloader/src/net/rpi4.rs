use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
use dtb::DtbParser;
use io_api::ethernet::EthernetFrameIo;

/// Initializes and returns the board Ethernet frame I/O backend from DTB data.
///
/// This is used by UDP UART networking setup in `bootloader/src/main.rs` when
/// `feature = \"rpi4_net\"` is enabled. Boot-time failure is treated as fatal.
pub fn init_ethernet_from_dtb(dtb: &DtbParser) -> &'static mut dyn EthernetFrameIo {
    match Bcm2711GenetV5::init_from_dtb(dtb) {
        Ok(driver) => driver as &'static mut dyn EthernetFrameIo,
        Err(err) => panic!("rpi4_net: failed to init BCM2711 GENETv5: {:?}", err),
    }
}
