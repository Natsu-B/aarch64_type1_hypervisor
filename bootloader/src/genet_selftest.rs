use arch_hal::debug_uart;
use arch_hal::println;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
#[cfg(not(any(feature = "rpi4_net", feature = "virtio_net")))]
use dtb::DtbParser;

/// Initializes GENET in PHY-less local loopback mode and runs the loopback selftest.
#[cfg(not(any(feature = "rpi4_net", feature = "virtio_net")))]
pub fn run_from_dtb(dtb: &DtbParser) {
    debug_uart::write("[selftest] bcm2711-genet: init local loopback mode (skip PHY)\n");
    let driver = match Bcm2711GenetV5::init_from_dtb_loopback_no_phy(dtb) {
        Ok(driver) => driver,
        Err(err) => {
            println!("[selftest] bcm2711-genet: init failed: {:?}", err);
            panic!(
                "bcm2711-genet local-loopback selftest init failed: {:?}",
                err
            );
        }
    };

    match driver.local_loopback_selftest() {
        Ok(()) => {
            debug_uart::write("[selftest] bcm2711-genet: PASS\n");
        }
        Err(err) => {
            println!("[selftest] bcm2711-genet: FAIL: {:?}", err);
            panic!("bcm2711-genet local-loopback selftest failed: {:?}", err);
        }
    }
}

/// Runs the loopback selftest on the already-initialized GENET used for networking.
#[cfg(feature = "rpi4_net")]
pub fn run_with_driver(driver: &mut Bcm2711GenetV5) {
    debug_uart::write("[selftest] bcm2711-genet: run local loopback on active GENET\n");
    match driver.local_loopback_selftest_live() {
        Ok(()) => {
            debug_uart::write("[selftest] bcm2711-genet: PASS\n");
        }
        Err(err) => {
            println!("[selftest] bcm2711-genet: FAIL: {:?}", err);
            panic!("bcm2711-genet local-loopback selftest failed: {:?}", err);
        }
    }
}
