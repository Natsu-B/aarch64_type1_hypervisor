use core::ops::ControlFlow;

use dtb::DtbNodeView;
use dtb::DtbParser;
use dtb::WalkError;
use dtb::WalkResult;
use print::println;

use crate::bcm2712::brcmstb::BrcmStb;
use crate::bcm2712::brcmstb::OutBoundData;
use crate::bcm2712::brcmstb::PcieStatus;
use crate::bcm2712::mip::Bcm2712MIP;
use typestate::Readable;

pub mod brcmstb;
pub mod mip;

pub struct Rp1Config {
    pub peripheral_bar_addr: OutBoundData,
    pub shared_sram_bar_addr: OutBoundData,
}

pub fn init_rp1(dtb: &DtbParser) -> Result<Rp1Config, Bcm2712Error> {
    println!("init rp1...");
    // currently we assumes that the rp1 is already initialized by the firmware
    // by config.txt pciex4_reset = 0
    let result =
        dtb.find_nodes_by_compatible_view("brcm,bcm2712-pcie", &mut |view, _name| search_rp1(view));
    match result {
        Ok(ControlFlow::Break(config)) => Ok(config),
        Ok(ControlFlow::Continue(())) => Err(Bcm2712Error::DtbDeviceNotFound),
        Err(WalkError::Dtb(err)) => Err(Bcm2712Error::DtbParseError(err)),
        Err(WalkError::User(err)) => Err(err),
    }
}

pub enum Bcm2712Error {
    DtbParseError(&'static str),
    DtbDeviceNotFound,
    PcieIsNotInitialized,
    UnexpectedDevice(&'static str),
    InvalidWindow,
}

fn search_rp1(view: &DtbNodeView) -> WalkResult<Rp1Config, Bcm2712Error> {
    let mut has_rp1 = false;
    view.for_each_child_view(&mut |child| {
        if child.name() == "rp1" {
            has_rp1 = true;
            let pcie_reg = view
                .reg_iter()
                .map_err(WalkError::Dtb)?
                .next()
                .ok_or(Bcm2712Error::DtbDeviceNotFound)?
                .map_err(WalkError::Dtb)?;
            println!(
                "PCIE: base_addr=0x{:x}, size=0x{:x}",
                pcie_reg.0, pcie_reg.1
            );

            let brcm_stb = BrcmStb::new(pcie_reg.0);

            // check msi-parent are mip
            let mip = view
                .msi_parent()
                .map_err(WalkError::Dtb)?
                .ok_or(Bcm2712Error::DtbDeviceNotFound)?;
            let mip_name = mip.name();
            if mip
                .compatible_contains("brcm,bcm2712-mip")
                .map_err(Bcm2712Error::DtbParseError)?
            {
                return Err(Bcm2712Error::UnexpectedDevice(mip_name).into());
            }

            // check the pcie are initialized
            if !link_up(brcm_stb) {
                return Err(Bcm2712Error::PcieIsNotInitialized.into());
            }

            // check bar address
            let bar1 = brcm_stb
                .read_outbound_window(1)?
                .ok_or(Bcm2712Error::PcieIsNotInitialized)?;
            println!(
                "PCIE: pheripheral BAR address: pcie_base: 0x{:x} cpu_base: 0x{:x} size: 0x{:x}",
                bar1.pcie_base, bar1.cpu_base, bar1.size
            );
            let bar2 = brcm_stb
                .read_outbound_window(2)?
                .ok_or(Bcm2712Error::PcieIsNotInitialized)?;
            println!(
                "PCIE: shared SRAM BAR address: pcie_base: 0x{:x} cpu_base: 0x{:x} size: 0x{:x}",
                bar2.pcie_base, bar2.cpu_base, bar2.size
            );

            init_rp1_interrupt(brcm_stb, &mip)?;

            Ok(ControlFlow::Break(Rp1Config {
                peripheral_bar_addr: bar1,
                shared_sram_bar_addr: bar2,
            }))
        } else {
            Ok(ControlFlow::Continue(()))
        }
    })
}

fn link_up(brcm_stb: &BrcmStb) -> bool {
    let status = brcm_stb.pcie_status.read();
    status.get(PcieStatus::phy_linkup) != 0 && status.get(PcieStatus::dl_active) != 0
}

fn init_rp1_interrupt(brcm_stb: &BrcmStb, mip: &DtbNodeView) -> Result<(), Bcm2712Error> {
    // mip settings
    let mip_addr = mip
        .reg_iter()
        .map_err(Bcm2712Error::DtbParseError)?
        .next()
        .ok_or(Bcm2712Error::DtbDeviceNotFound)?
        .map_err(Bcm2712Error::DtbParseError)?;
    let mip = Bcm2712MIP::new(mip_addr.0);
    mip.init();

    // check inbound settings
    let found = (1..=10)
        .try_fold(
            ControlFlow::Continue(()),
            |_, i| -> Result<ControlFlow<(), ()>, Bcm2712Error> {
                if let Some(inbound) = brcm_stb.read_inbound_window(i)? {
                    println!(
                        "PCIE: inbound window {}: pcie_base: 0x{:x} cpu_base: 0x{:x} size: 0x{:x}",
                        i, inbound.pcie_base, inbound.cpu_base, inbound.size
                    );

                    // TODO read from DTB
                    let ok = inbound.pcie_base == 0xff_ffff_f000
                        && inbound.cpu_base == 0x10_0013_0000
                        && inbound.size == 0x1000;

                    if ok {
                        return Ok(ControlFlow::Break(()));
                    }
                }
                Ok(ControlFlow::Continue(()))
            },
        )?
        .is_break();

    if !found {
        return Err(Bcm2712Error::PcieIsNotInitialized);
    }

    // set RP1 interrupt
    // TODO

    Ok(())
}
