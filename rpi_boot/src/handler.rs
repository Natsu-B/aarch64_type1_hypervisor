use crate::UART_ADDR;
use arch_hal::cpu;
use arch_hal::exceptions;
use arch_hal::println;
use core::arch::asm;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use exceptions::registers::InstructionRegisterSize;
use exceptions::registers::SyndromeAccessSize;
use exceptions::registers::WriteNotRead;

pub(crate) fn setup_handler() {
    exceptions::synchronous_handler::set_data_abort_handler(data_abort_handler);
}

fn data_abort_handler(
    register: &mut u64,
    address: u64,
    reg_size: InstructionRegisterSize,
    access_width: SyndromeAccessSize,
    write_access: WriteNotRead,
) {
    println!(
        "data abort trapped: addr: {:X}, access_width: {:?}, write?: {}, data: {}",
        address,
        access_width,
        write_access == WriteNotRead::WritingMemoryAbort,
        *register
    );
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
