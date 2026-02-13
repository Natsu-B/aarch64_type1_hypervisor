use core::ops::ControlFlow;
use core::ptr::slice_from_raw_parts;

use crate::bcm2712::brcmstb::BrcmStb;
use crate::bcm2712::brcmstb::PcieStatus;
use dtb::DtbNodeView;
use dtb::DtbParser;
use dtb::WalkError;
use dtb::WalkResult;
use mutex::RawSpinLock;
use pci::PciBhlc;
use pci::PciHeaderKind;
use pci::PciId;
use pci::msix::PciMsiXTable;
use print::println;
use typestate::Readable;

pub mod brcmstb;
pub mod mip;
pub mod rp1_interrupt;

pub(crate) struct MsiXTablePtr {
    base: *const PciMsiXTable,
    len: usize,
}

unsafe impl Send for MsiXTablePtr {}

pub(crate) static MsiXTable: RawSpinLock<Option<MsiXTablePtr>> = RawSpinLock::new(None);

pub(crate) fn get_msi_x_table(table: &MsiXTablePtr) -> &'static [PciMsiXTable] {
    // SAFETY: `MsiXTablePtr` is created from a valid, MMIO-mapped MSI-X table during RP1 init
    // and remains valid for the lifetime of the system; `len` is the table entry count.
    unsafe { &*slice_from_raw_parts(table.base, table.len) }
}

pub struct Rp1Config {
    pub peripheral_addr: Option<(u64, u64)>,
    pub shared_sram_addr: Option<(u64, u64)>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bcm2712Error {
    DtbParseError(&'static str),
    DtbDeviceNotFound,
    PcieIsNotInitialized,
    UnexpectedDevice(&'static str),
    InvalidWindow,
    InvalidPciHeaderType,
    InvalidSettings,
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

            let result = view.with_msi_parent_view(&mut |mip, mip_name| {
                if !mip
                    .compatible_contains("brcm,bcm2712-mip")
                    .map_err(WalkError::Dtb)?
                {
                    return Err(Bcm2712Error::UnexpectedDevice(mip_name).into());
                }

                let mip_reg = mip
                    .reg_iter()
                    .map_err(WalkError::Dtb)?
                    .next()
                    .ok_or(Bcm2712Error::DtbDeviceNotFound)?
                    .map_err(WalkError::Dtb)?;
                println!("PCIE: MIP addr: 0x{:x}, size: 0x{:x}", mip_reg.0, mip_reg.1);

                // check the pcie are initialized?
                if !link_up(brcm_stb) {
                    return Err(Bcm2712Error::PcieIsNotInitialized.into());
                }

                // check bar address
                let config = brcm_stb.set_config_window()?;
                println!(
                    "PCIE: RP1 Vender ID: 0x{:x}",
                    config.id.read().get(PciId::vendor_id)
                );
                println!(
                    "PCIE: RP1 Device ID: 0x{:x}",
                    config.id.read().get(PciId::device_id)
                );
                if config
                    .bhlc
                    .read()
                    .get_enum(PciBhlc::header_kind)
                    .is_none_or(|t: PciHeaderKind| t != PciHeaderKind::Standard)
                {
                    return Err(Bcm2712Error::InvalidPciHeaderType.into());
                }

                let msi_x = unsafe { brcm_stb.get_msi_x_capability() }?;
                let msi_x_bar = unsafe {
                    brcm_stb.msi_x_table_bar_addr(msi_x)?
                } as u64;
                let bar1 = unsafe { brcm_stb.read_bar_address(1) }? as u64;
                let bar2 = unsafe { brcm_stb.read_bar_address(2) }? as u64;
                println!("PCIE: RP1 Pheripheral BAR addr: 0x{:x}", bar1);
                println!("PCIE: RP1 Shared SRAM BAR addr: 0x{:x}", bar2);

                let mut msi_x_table_addr = None;
                let mut peripheral_addr = None;
                let mut  shared_sram_addr = None;

                // check outbound windows
                for i in 0..=4 {
                   if let Ok(Some(bar)) = brcm_stb
                        .read_outbound_window(i){
                    println!(
                        "PCIE: outbound window {}: pcie_base: 0x{:x} cpu_base: 0x{:x} size: 0x{:x}",
                        i, bar.pcie_base, bar.cpu_base, bar.size
                    );
                    if (bar.pcie_base..(bar.pcie_base + bar.size)).contains(&msi_x_bar) {
                        msi_x_table_addr = Some(msi_x_bar - bar.pcie_base + bar.cpu_base)
                    ;}
                    if (bar.pcie_base..(bar.pcie_base + bar.size)).contains(&bar1) {
                        peripheral_addr = Some((bar1 - bar.pcie_base + bar.cpu_base, 0x40_0000));
                    }
                    if (bar.pcie_base..(bar.pcie_base + bar.size)).contains(&bar2) {
                        shared_sram_addr = Some((bar2 - bar.pcie_base + bar.cpu_base, 0x1_0000));
                    }
                }
                }
                let Some(msi_x_table_addr) = msi_x_table_addr else {
                    println!("PCIE: msi x window are not set");
                    return Err(Bcm2712Error::InvalidWindow.into());
                };
                let mut table = MsiXTable.lock();
                *table = Some(unsafe { brcm_stb.init_rp1_msi_x_settings(msi_x, msi_x_table_addr, 0xff_ffff_f000) }?);

                rp1_interrupt::init_rp1_interrupt(brcm_stb, mip_reg.0 as u64)?;

                Ok(ControlFlow::Break(Rp1Config {
                    peripheral_addr,
                    shared_sram_addr,
                }))
            });

            match result {
                Ok(ControlFlow::Break(config)) => Ok(ControlFlow::Break(config)),
                Ok(ControlFlow::Continue(())) => Err(Bcm2712Error::DtbDeviceNotFound.into()),
                Err(err) => Err(err),
            }
        } else {
            Ok(ControlFlow::Continue(()))
        }
    })
}

fn link_up(brcm_stb: &BrcmStb) -> bool {
    let status = brcm_stb.pcie_status.read();
    status.get(PcieStatus::phy_linkup) != 0 && status.get(PcieStatus::dl_active) != 0
}
