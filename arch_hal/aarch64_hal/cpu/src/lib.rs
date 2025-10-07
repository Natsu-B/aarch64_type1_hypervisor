#![no_std]

use core::arch::asm;

use crate::registers::ID_AA64MMFR0_EL1;
use crate::registers::PARange;
pub mod registers;

fn dcache_line_size() -> usize {
    let ctr_el0: u64;
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr_el0) };
    let dminline = ((ctr_el0 >> 16) & 0xf) as usize;
    4usize << dminline
}

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

pub fn set_hcr_el2(hcr: u64) {
    unsafe { asm!("msr hcr_el2, {}", in(reg) hcr) };
}



pub fn clean_dcache_poc(addr: usize, size: usize) {
    if size == 0 {
        return;
    }
    let line_size = dcache_line_size();
    let start = addr & !(line_size - 1);
    let end = addr.saturating_add(size).saturating_add(line_size - 1) & !(line_size - 1);
    let mut current = start;
    unsafe {
        while current < end {
            asm!("dc cvac, {}", in(reg) current);
            current += line_size;
        }
        asm!("dsb ish");
    }
}

pub fn dsb_ish() {
    unsafe { asm!("dsb ish") };
}

pub fn isb() {
    unsafe { asm!("isb") };
}

pub fn flush_tlb_el2_el1() {
    unsafe {
        asm!(
            "
            dsb ishst
            tlbi vmalls12e1is
            dsb ish
            isb"
        )
    };
}

pub fn get_parange() -> Option<PARange> {
    let id = ID_AA64MMFR0_EL1::from_bits(get_id_aa64mmfr0_el1());
    id.get_enum(ID_AA64MMFR0_EL1::parange)
}
