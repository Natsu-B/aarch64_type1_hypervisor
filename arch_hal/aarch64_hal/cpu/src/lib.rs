#![no_std]

use core::arch::asm;

use crate::registers::ID_AA64MMFR0_EL1;
use crate::registers::MPIDR_EL1;
use crate::registers::PARange;
pub mod registers;

/// Core affinity encoded as MPIDR style fields (Aff3:Aff2:Aff1:Aff0).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CoreAffinity {
    pub aff0: u8,
    pub aff1: u8,
    pub aff2: u8,
    pub aff3: u8,
}

impl CoreAffinity {
    pub const fn new(aff0: u8, aff1: u8, aff2: u8, aff3: u8) -> Self {
        Self {
            aff0,
            aff1,
            aff2,
            aff3,
        }
    }

    pub const fn to_bits(&self) -> u64 {
        self.aff0 as u64
            | (self.aff1 as u64) << 8
            | (self.aff2 as u64) << 16
            | (self.aff3 as u64) << 32
    }
}

#[repr(C)]
pub struct Registers {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub x31: u64,
}

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

pub fn get_id_aa64mmfr0_el1() -> u64 {
    let id: u64;
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) id) };
    id
}

pub fn get_esr_el2() -> u64 {
    let esr_el2: u64;
    unsafe { asm!("mrs {}, esr_el2", out(reg) esr_el2) };
    esr_el2
}

pub fn get_far_el2() -> u64 {
    let far_el2: u64;
    unsafe { asm!("mrs {}, far_el2", out(reg) far_el2) };
    far_el2
}

pub fn get_hpfar_el2() -> u64 {
    let hpfar_el2: u64;
    unsafe { asm!("mrs {}, hpfar_el2", out(reg) hpfar_el2) };
    hpfar_el2
}

pub fn get_elr_el2() -> u64 {
    let elr_el2: u64;
    unsafe { asm!("mrs {}, elr_el2", out(reg) elr_el2) };
    elr_el2
}

pub fn get_mpidr_el1() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, mpidr_el1", val = out(reg) val) };
    val
}

pub fn get_hcr_el2() -> u64 {
    let hcr_el2: u64;
    unsafe { asm!("mrs {}, hcr_el2", out(reg) hcr_el2) };
    hcr_el2
}

pub fn get_mair_el2() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, mair_el2", val = out(reg) val) };
    val
}

pub fn get_tcr_el2() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, tcr_el2", val = out(reg) val) };
    val
}

pub fn get_ttbr0_el2() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, ttbr0_el2", val = out(reg) val) };
    val
}

pub fn get_sctlr_el2() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, sctlr_el2", val = out(reg) val) };
    val
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

pub fn set_vbar_el1(vbar: u64) {
    unsafe { asm!("msr vbar_el1, {}", in(reg) vbar) };
}

pub fn set_vbar_el2(vbar: u64) {
    unsafe { asm!("msr vbar_el2, {}", in(reg) vbar) };
}

pub fn set_elr_el2(elr_el2: u64) {
    unsafe { asm!("msr elr_el2, {}", in(reg) elr_el2) };
}

pub fn set_sctlr_el2(sctlr_el2: u64) {
    unsafe { asm!("msr sctlr_el2, {}", in(reg) sctlr_el2) };
}

pub fn set_ttbr0_el2(ttbr0_el2: u64) {
    unsafe { asm!("msr ttbr0_el2, {}", in(reg) ttbr0_el2) };
}

pub fn set_mair_el2(mair_el2: u64) {
    unsafe { asm!("msr mair_el2, {}", in(reg) mair_el2) };
}

pub fn set_tcr_el2(tcr_el2: u64) {
    unsafe { asm!("msr tcr_el2, {}", in(reg) tcr_el2) };
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

pub fn dsb_sy() {
    unsafe { asm!("dsb sy") };
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

pub fn invalidate_icache_all() {
    unsafe {
        core::arch::asm!(
            "ic iallu",
            "dsb sy",
            "isb",
            options(nostack, preserves_flags),
        );
    }
}

pub fn get_parange() -> Option<PARange> {
    let id = ID_AA64MMFR0_EL1::from_bits(get_id_aa64mmfr0_el1());
    id.get_enum(ID_AA64MMFR0_EL1::parange)
}

/// Return a CPU-specific ID composed from MPIDR_EL1.AFF{0..3}.
/// The returned ID layout is compatible with the PSCI CPU_ON `target_cpu` argument.
pub fn get_current_core_id() -> CoreAffinity {
    let mpidr_el1 = MPIDR_EL1::from_bits(get_mpidr_el1());
    let aff0 = 0;
    let aff1 = mpidr_el1.get(MPIDR_EL1::aff1);
    let aff2 = mpidr_el1.get(MPIDR_EL1::aff2);
    let aff3 = mpidr_el1.get(MPIDR_EL1::aff3);

    CoreAffinity::new(aff0, aff1 as u8, aff2 as u8, aff3 as u8)
}

pub fn va_to_ipa_el2(va: u64) -> Option<u64> {
    let par_after: u64;

    unsafe {
        core::arch::asm!(
            "mrs {tmp}, par_el1",
            "at S1E1R, {va}",
            "isb",
            "mrs {par_after}, par_el1",
            "msr par_el1, {tmp}",
            tmp        = lateout(reg) _,
            par_after  = out(reg) par_after,
            va         = in(reg) va,
            options(nostack)
        );
    }

    if (par_after & 1) != 0 {
        return None;
    }

    let ipa = par_after & 0x0000_FFFF_FFFF_F000;
    Some(ipa | (va & 0xFFF))
}
