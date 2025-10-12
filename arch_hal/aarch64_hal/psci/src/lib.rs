#![no_std]
use core::arch::asm;

use cpu::Registers;
use cpu::get_elr_el2;
use cpu::set_elr_el2;
use print::println;

#[repr(u64)]
enum PsciVal {
    CpuOnSmc32 = 0x8400_0003,
    CpuOnSmc64 = 0xC400_0003,
}

pub fn handle_secure_monitor_call(regs: &mut Registers) {
    match regs.x0 {
        x if x == PsciVal::CpuOnSmc64 as u64 => {
            println!("hypervisor: prevent cpu on");
            regs.x0 = -3i64 as u64; // return DENIED
        }
        _ => {
            secure_monitor_call(regs);
        }
    }
    // advance elr_el2
    set_elr_el2(get_elr_el2() + 4);
}

pub fn secure_monitor_call(regs: &mut Registers) {
    unsafe {
        asm!(
            "smc #0",
            inout("x0")  regs.x0,
            inout("x1")  regs.x1,
            inout("x2")  regs.x2,
            inout("x3")  regs.x3,
            inout("x4")  regs.x4,
            inout("x5")  regs.x5,
            inout("x6")  regs.x6,
            inout("x7")  regs.x7,
            inout("x8")  regs.x8,
            inout("x9")  regs.x9,
            inout("x10") regs.x10,
            inout("x11") regs.x11,
            inout("x12") regs.x12,
            inout("x13") regs.x13,
            inout("x14") regs.x14,
            inout("x15") regs.x15,
            inout("x16") regs.x16,
            inout("x17") regs.x17,
            clobber_abi("C")
        );
    }
}
