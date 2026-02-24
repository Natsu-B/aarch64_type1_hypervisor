use core::ops::ControlFlow;

use arch_hal::println;
use dtb::DtbNodeView;
use dtb::WalkError;
use dtb::WalkResult;

pub fn init_pcie_with_node(view: &DtbNodeView) -> WalkResult<(), ()> {
    let mut has_rp1 = false;
    let _ = view.for_each_child_view(&mut |child| {
        if child.name() == "rp1" {
            has_rp1 = true;
            return Ok(ControlFlow::Break(()));
        }
        Ok(ControlFlow::Continue(()))
    })?;
    if !has_rp1 {
        return Ok(ControlFlow::Continue(()));
    }

    let mut pcie_reg = None;
    let mut iter = view.reg_iter().map_err(WalkError::Dtb)?;
    while let Some(entry) = iter.next() {
        pcie_reg = Some(entry.map_err(WalkError::Dtb)?);
        break;
    }
    let pcie_reg = pcie_reg.ok_or(WalkError::Dtb("pcie: missing reg"))?;
    println!(
        "PCIE: base_addr=0x{:x}, size=0x{:x}",
        pcie_reg.0, pcie_reg.1
    );

    // check mis-parent are mip
    // TODO

    // link up
    println!("PCIE: is_link_up? :{}", link_up(pcie_reg.0));

    Ok(ControlFlow::Break(()))
}

fn link_up(addr: usize) -> bool {
    const PCIE_MISC_PCIE_STATUS: usize = 0x4068;
    const STATUS_DL_ACTIVE: u32 = 0x20;
    const STATUS_PHYLINKUP: u32 = 0x10;

    let status = unsafe { core::ptr::read_volatile((addr + PCIE_MISC_PCIE_STATUS) as *const u32) };
    (status & (STATUS_DL_ACTIVE | STATUS_PHYLINKUP)) == (STATUS_DL_ACTIVE | STATUS_PHYLINKUP)
}
