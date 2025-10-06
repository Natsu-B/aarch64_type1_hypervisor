#![no_std]

use core::arch::asm;

pub fn get_current_el() -> u64 {
    let current_el: u64;
    unsafe { asm!("mrs {}, currentel", out(reg) current_el) };
    current_el >> 2
}

pub fn setup_hypervisor_registers() {
    const HCR_EL2_RW: u64 = 1 << 31;
    const HCR_EL2_API: u64 = 1 << 41;
    let hcr_el2 = HCR_EL2_RW | HCR_EL2_API;
    unsafe { asm!("msr hcr_el2, {}", in(reg) hcr_el2) };
}

pub fn get_id_aa64mmfr0_el1() -> u64 {
    let id: u64;
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) id) };
    id
}

pub fn set_vtcr_el2(vtcr_el2: u64) {
    unsafe { asm!("msr vtcr_el2, {}", in(reg)vtcr_el2) };
}

pub fn set_vttbr_el2(vttbr_el2: u64) {
    unsafe { asm!("msr vttbr_el2, {}", in(reg) vttbr_el2) };
}
