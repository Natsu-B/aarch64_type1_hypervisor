use arch_hal::debug_uart;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
use core::fmt;
use core::fmt::Write as _;
use core::time::Duration;
use dtb::DtbParser;
use io_api::ethernet::EthernetFrameIo;

struct BootLogBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> BootLogBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.buf[..self.len]).ok()
    }
}

impl<const N: usize> fmt::Write for BootLogBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let avail = self.buf.len().saturating_sub(self.len);
        if avail == 0 {
            return Ok(());
        }
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(avail);
        self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

fn debug_uart_log(args: fmt::Arguments<'_>) {
    let mut line = BootLogBuf::<224>::new();
    let _ = line.write_fmt(args);
    if let Some(s) = line.as_str() {
        debug_uart::write(s);
    }
}

/// Initializes and returns the board Ethernet frame I/O backend from DTB data.
///
/// This is used by UDP UART networking setup in `bootloader/src/main.rs` when
/// `feature = \"rpi4_net\"` is enabled.
///
/// This default entry point waits indefinitely for PHY link bring-up.
/// Use [`init_genet_from_dtb_with_link_wait`] for bounded waits.
pub fn init_genet_from_dtb(dtb: &DtbParser) -> &'static mut Bcm2711GenetV5 {
    init_genet_from_dtb_with_link_wait(dtb, None)
}

/// Initializes BCM2711 GENETv5 with an optional PHY link wait limit.
///
/// - `link_wait = Some(d)`: fail with `PhyTimeout` after approximately `d`.
/// - `link_wait = None`: wait indefinitely for PHY link bring-up.
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

pub fn init_ethernet_from_dtb(dtb: &DtbParser) -> &'static mut dyn EthernetFrameIo {
    init_genet_from_dtb(dtb) as &'static mut dyn EthernetFrameIo
}
