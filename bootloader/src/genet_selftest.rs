use arch_hal::debug_uart;
use arch_hal::println;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
use dtb::DtbParser;

pub fn run(dtb: &DtbParser) {
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
