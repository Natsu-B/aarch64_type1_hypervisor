use pci::msix::PciMsiXTableVectorControl;
use print::println;

use crate::bcm2712::Bcm2712Error;
use crate::bcm2712::MsiXTable;
use crate::bcm2712::brcmstb::BrcmStb;
use crate::bcm2712::brcmstb::InBoundData;
use crate::bcm2712::get_msi_x_table;
use crate::bcm2712::mip::Bcm2712MIP;
use typestate::Writable;

// TODO read dtb
const MIP_SPI_OFFSET: u32 = 128;

pub(crate) fn init_rp1_interrupt(brcm_stb: &BrcmStb, mip_base: u64) -> Result<(), Bcm2712Error> {
    // mip settings
    println!("PCIE: MIP address: 0x{:x}", mip_base);
    let mip = Bcm2712MIP::new(mip_base);
    mip.init();

    // check inbound settings
    let mut found = false;
    let mut pcie = [false; 10];
    for i in 1..=10 {
        println!("PCIE: Checking inbound window {}", i);
        if let Some(inbound) = brcm_stb.read_inbound_window(i)? {
            println!(
                "PCIE: inbound window {}: pcie_base: 0x{:x} cpu_base: 0x{:x} size: 0x{:x}",
                i, inbound.pcie_base, inbound.cpu_base, inbound.size
            );
            pcie[i as usize - 1] = true;
            if inbound.pcie_base <= 0xff_ffff_f000 {
                let offset = 0xff_ffff_f000u64 - inbound.pcie_base;
                if offset + 0x1000 <= inbound.size
                    && inbound.cpu_base.checked_add(offset) == Some(mip_base)
                {
                    found = true;
                }
            }
        }
    }

    // check msi inbound window
    if !found {
        println!("PCIE: setting rp1 interrupt inbound window");
        let Some(x) = (1..=10usize).filter(|x| !pcie[*x - 1]).next() else {
            println!("PCIE: Inbound window are full");
            return Err(Bcm2712Error::InvalidWindow);
        };
        println!("PCIE: Setting Inbound Window {}...", x);
        let inbound_window = InBoundData {
            pcie_base: 0xff_ffff_f000,
            cpu_base: mip_base,
            size: 0x1000,
        };
        brcm_stb.set_inbound_window(x as u8, inbound_window)?;
        cpu::dsb_sy();
    }

    Ok(())
}

pub fn enable_interrupt(spi: u32) -> Result<(), Bcm2712Error> {
    toggle_interrupt(spi, true)
}

pub fn disable_interrupt(spi: u32) -> Result<(), Bcm2712Error> {
    toggle_interrupt(spi, false)
}

fn toggle_interrupt(spi: u32, enable: bool) -> Result<(), Bcm2712Error> {
    let Some(offset) = spi
        .checked_sub(MIP_SPI_OFFSET)
        .and_then(|v| v.checked_sub(32))
    else {
        return Err(Bcm2712Error::InvalidSettings);
    };
    let msi_x_table = MsiXTable.lock();
    let Some(msi_x_table) = msi_x_table.as_ref() else {
        return Err(Bcm2712Error::PcieIsNotInitialized);
    };
    // SAFETY: `get_msi_x_table` returns a valid MMIO slice covering all MSI-X vectors.
    let tables = get_msi_x_table(msi_x_table);
    let entry = tables.get(offset as usize).ok_or(Bcm2712Error::InvalidSettings)?;
    entry.vector_control.write(if enable {
        PciMsiXTableVectorControl::new().set(PciMsiXTableVectorControl::mask, 0)
    } else {
        PciMsiXTableVectorControl::new().set(PciMsiXTableVectorControl::mask, 1)
    });
    Ok(())
}
