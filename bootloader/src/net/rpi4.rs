use arch_hal::debug_uart;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetError;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
use arch_hal::timer::SystemTimer;
use core::fmt;
use core::fmt::Write as _;
use core::time::Duration;
use dtb::DtbParser;
use io_api::ethernet::EthernetFrameIo;

const PHY_TIMEOUT_RETRY_BACKOFF_MS: u64 = 200;

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
/// `feature = \"rpi4_net\"` is enabled. PHY link timeouts are retried; other
/// boot-time initialization errors remain fatal.
pub fn init_ethernet_from_dtb(dtb: &DtbParser) -> &'static mut dyn EthernetFrameIo {
    let mut retry_timer = SystemTimer::new();
    retry_timer.init();
    let mut attempt = 1u32;
    debug_uart_log(format_args!(
        "rpi4_net: ethernet init start (retrying on PHY timeout)\n"
    ));

    loop {
        match Bcm2711GenetV5::init_from_dtb(dtb) {
            Ok(driver) => {
                debug_uart_log(format_args!(
                    "rpi4_net: ethernet ready after attempt={}\n",
                    attempt
                ));
                return driver as &'static mut dyn EthernetFrameIo;
            }
            Err(Bcm2711GenetError::PhyTimeout) => {
                debug_uart_log(format_args!(
                    "rpi4_net: ethernet init: PHY link timeout (5s), attempt={}, retrying in {}ms\n",
                    attempt, PHY_TIMEOUT_RETRY_BACKOFF_MS
                ));
                retry_timer.wait(Duration::from_millis(PHY_TIMEOUT_RETRY_BACKOFF_MS));
                attempt = attempt.wrapping_add(1);
            }
            Err(err) => panic!("rpi4_net: failed to init BCM2711 GENETv5: {:?}", err),
        }
    }
}
