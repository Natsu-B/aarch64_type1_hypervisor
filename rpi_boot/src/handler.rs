use arch_hal::cpu;
use arch_hal::cpu::Registers;
use arch_hal::exceptions;
use arch_hal::println;
use arch_hal::psci::PsciFunctionId;
use arch_hal::psci::PsciReturnCode;
use arch_hal::psci::default_psci_handler;
use arch_hal::psci::{self};
use core::arch::asm;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use exceptions::registers::InstructionRegisterSize;
use exceptions::registers::SyndromeAccessSize;
use exceptions::registers::WriteNotRead;

use crate::PL011_UART_ADDR;
use crate::multicore::ap_on;

pub(crate) fn setup_handler() {
    exceptions::synchronous_handler::set_data_abort_handler(data_abort_handler);

    // deny guest PSCI CPU_ON.
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc64, ap_on);
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc32, ap_on);
    psci::set_psci_handler(PsciFunctionId::CpuSuspendSmc32, deny_handler);
    psci::set_psci_handler(PsciFunctionId::CpuSuspendSmc64, deny_handler);
    psci::set_psci_handler(PsciFunctionId::CpuDefaultSuspendSmc32, deny_handler);
    psci::set_psci_handler(PsciFunctionId::CpuDefaultSuspendSmc64, deny_handler);

    psci::set_unknown_psci_handler(unknown_psci_handler);
}

fn data_abort_handler(
    register: &mut u64,
    address: u64,
    reg_size: InstructionRegisterSize,
    access_width: SyndromeAccessSize,
    write_access: WriteNotRead,
) {
    unsafe {
        match write_access {
            WriteNotRead::ReadingMemoryAbort => {
                let v = match access_width {
                    SyndromeAccessSize::Byte => read_volatile(address as *const u8) as u64,
                    SyndromeAccessSize::HalfWord => read_volatile(address as *const u16) as u64,
                    SyndromeAccessSize::Word => read_volatile(address as *const u32) as u64,
                    SyndromeAccessSize::DoubleWord => read_volatile(address as *const u64),
                };

                *register = match reg_size {
                    InstructionRegisterSize::Instruction32bit => v & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => v,
                };
            }

            WriteNotRead::WritingMemoryAbort => {
                let reg_val = match reg_size {
                    InstructionRegisterSize::Instruction32bit => *register & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => *register,
                };
                let uart = PL011_UART_ADDR;
                if (uart..uart + 0x1000).contains(&(address as usize)) {
                    if uart == address as usize && reg_val == b'\n' as u64 {
                        println!("\nhypervisor: alive");
                    }
                } else {
                    println!(
                        "data abort trapped: addr: {:X}, access_width: {:?}, write?: {}, data: {}",
                        address,
                        access_width,
                        write_access == WriteNotRead::WritingMemoryAbort,
                        *register
                    );
                };
                match access_width {
                    SyndromeAccessSize::Byte => {
                        write_volatile(address as *mut u8, reg_val as u8);
                    }
                    SyndromeAccessSize::HalfWord => {
                        write_volatile(address as *mut u16, reg_val as u16);
                    }
                    SyndromeAccessSize::Word => {
                        write_volatile(address as *mut u32, reg_val as u32);
                    }
                    SyndromeAccessSize::DoubleWord => {
                        write_volatile(address as *mut u64, reg_val as u64);
                    }
                }
            }
        }
    }
    // advance elr_el2
    cpu::set_elr_el2(cpu::get_elr_el2() + 4);
}

fn deny_handler(regs: &mut cpu::Registers) {
    regs.x0 = PsciReturnCode::Denied.to_x0();
}

fn unknown_psci_handler(fid_raw: u32, regs: &mut cpu::Registers) {
    println!("unknown psci call fid=0x{:08X}", fid_raw);
    println!(
        "x0={:#018x} x1={:#018x} x2={:#018x} x3={:#018x}",
        regs.x0, regs.x1, regs.x2, regs.x3
    );
    println!(
        "x4={:#018x} x5={:#018x} x6={:#018x} x7={:#018x}",
        regs.x4, regs.x5, regs.x6, regs.x7
    );
    println!(
        "x8={:#018x} x9={:#018x} x10={:#018x} x11={:#018x}",
        regs.x8, regs.x9, regs.x10, regs.x11
    );
    println!(
        "x12={:#018x} x13={:#018x} x14={:#018x} x15={:#018x}",
        regs.x12, regs.x13, regs.x14, regs.x15
    );
    println!(
        "x16={:#018x} x17={:#018x} x18={:#018x} x19={:#018x}",
        regs.x16, regs.x17, regs.x18, regs.x19
    );
    println!(
        "x20={:#018x} x21={:#018x} x22={:#018x} x23={:#018x}",
        regs.x20, regs.x21, regs.x22, regs.x23
    );
    println!(
        "x24={:#018x} x25={:#018x} x26={:#018x} x27={:#018x}",
        regs.x24, regs.x25, regs.x26, regs.x27
    );
    println!(
        "x28={:#018x} x29={:#018x} x30={:#018x} x31={:#018x}",
        regs.x28, regs.x29, regs.x30, regs.x31
    );
    default_psci_handler(regs);
}
