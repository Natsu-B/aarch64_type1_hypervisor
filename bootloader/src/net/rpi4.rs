use arch_hal::debug_uart;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
use core::fmt;
use core::time::Duration;
use dtb::DtbParser;

fn debug_uart_log(args: fmt::Arguments<'_>) {
    debug_uart::write_fmt_truncated::<224>(args);
}

/// Initializes BCM2711 GENETv5 from DTB data with an optional PHY link wait limit.
///
/// This is used by UDP UART networking setup in `bootloader/src/main.rs` when
/// `feature = \"rpi4_net\"` is enabled.
///
/// - `link_wait = Some(d)`: fail with `PhyTimeout` after approximately `d`.
/// - `link_wait = None`: wait indefinitely for PHY link bring-up.
///
/// # Panics
///
/// Panics if the driver cannot be initialized, including when the PHY link wait times out.
pub fn init_genet_from_dtb_with_link_wait(
    dtb: &DtbParser,
    link_wait: Option<Duration>,
) -> &'static mut Bcm2711GenetV5 {
    match link_wait {
        Some(timeout) => debug_uart_log(format_args!(
            "rpi4_net: ethernet init start (phy_link_wait={}ms)\n",
            timeout.as_millis()
        )),
        None => debug_uart_log(format_args!(
            "rpi4_net: ethernet init start (phy_link_wait=forever)\n"
        )),
    }

    match Bcm2711GenetV5::init_from_dtb(dtb, link_wait) {
        Ok(driver) => {
            debug_uart_log(format_args!("rpi4_net: ethernet ready\n"));
            driver
        }
        Err(err) => panic!("rpi4_net: failed to init BCM2711 GENETv5: {:?}", err),
    }
}
