use arch_hal::cpu;
use arch_hal::exceptions;
use arch_hal::exceptions::emulation::EmulationOutcome;
use arch_hal::exceptions::emulation::MmioDecoded;
use arch_hal::exceptions::emulation::{self};
use arch_hal::exceptions::memory_hook::AccessClass;
use arch_hal::exceptions::memory_hook::MmioError;
use arch_hal::exceptions::memory_hook::MmioHandler;
use arch_hal::exceptions::memory_hook::SplitPolicy;
use arch_hal::gic::GicCpuInterface;
use arch_hal::gic::PIntId;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2AccessSize;
use arch_hal::println;
use arch_hal::psci::PsciFunctionId;
use arch_hal::psci::PsciReturnCode;
use arch_hal::psci::default_psci_handler;
use arch_hal::psci::{self};
use core::ffi::c_void;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use exceptions::registers::ESR_EL2;
use exceptions::registers::InstructionRegisterSize;
use exceptions::registers::SyndromeAccessSize;
use exceptions::registers::WriteNotRead;
use exceptions::synchronous_handler::DataAbortHandlerEntry;
use exceptions::synchronous_handler::DataAbortInfo;

use crate::GICV2_DRIVER;
use crate::PL011_UART_ADDR;
use crate::multicore::ap_on;
use crate::vgic;

pub(crate) fn setup_handler() {
    exceptions::synchronous_handler::set_data_abort_handler(DATA_ABORT_HANDLER);
    exceptions::irq_handler::set_irq_handler(irq_handler);

    // intercept guest PSCI CPU_ON for hypervisor-controlled AP bring-up.
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc64, ap_on);
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc32, ap_on);
    psci::set_psci_handler(PsciFunctionId::CpuSuspendSmc32, deny_handler);
    psci::set_psci_handler(PsciFunctionId::CpuSuspendSmc64, deny_handler);
    psci::set_psci_handler(PsciFunctionId::CpuDefaultSuspendSmc32, deny_handler);
    psci::set_psci_handler(PsciFunctionId::CpuDefaultSuspendSmc64, deny_handler);

    psci::set_unknown_psci_handler(unknown_psci_handler);
}

pub(crate) fn gic() -> Option<&'static Gicv2> {
    // SAFETY: GICV2_DRIVER is initialized once during boot and then treated as read-only.
    unsafe { &*GICV2_DRIVER.get() }.as_ref()
}

fn passthrough_read(_ctx: *const (), ipa: u64, size: u8) -> Result<u64, MmioError> {
    unsafe {
        Ok(match size {
            1 => read_volatile(ipa as *const u8) as u64,
            2 => read_volatile(ipa as *const u16) as u64,
            4 => read_volatile(ipa as *const u32) as u64,
            8 => read_volatile(ipa as *const u64),
            _ => return Err(MmioError::Unhandled),
        })
    }
}

fn passthrough_write(_ctx: *const (), ipa: u64, size: u8, value: u64) -> Result<(), MmioError> {
    unsafe {
        match size {
            1 => write_volatile(ipa as *mut u8, value as u8),
            2 => write_volatile(ipa as *mut u16, value as u16),
            4 => write_volatile(ipa as *mut u32, value as u32),
            8 => write_volatile(ipa as *mut u64, value as u64),
            _ => return Err(MmioError::Unhandled),
        }
    }
    Ok(())
}

fn passthrough_probe(_ctx: *const (), _ipa: u64, size: u8, _is_write: bool) -> bool {
    matches!(size, 1 | 2 | 4 | 8) && !vgic::handles_gicd(_ipa as usize)
}

fn data_abort_handler(
    _ctx: *mut c_void,
    regs: &mut cpu::Registers,
    info: &DataAbortInfo,
    decoded: Option<&MmioDecoded>,
) {
    if let Some(plan) = decoded {
        if handle_gicd_decoded(plan, regs) {
            return;
        }
        log_uart_write(plan, regs);
        match emulation::execute_mmio(regs, info, &PASSTHROUGH_MMIO, plan) {
            EmulationOutcome::Handled => return,
            EmulationOutcome::NotHandled => {
                panic!("decoded MMIO request was not handled: {:?}", plan)
            }
        }
    }

    let Some(address) = info.fault_ipa else {
        panic!(
            "data abort without IPA (FnV={}, FAR_EL2={:#X})",
            info.esr_el2.get(ESR_EL2::fnv),
            info.far_el2
        );
    };

    let Some(access) = info.access else {
        panic!(
            "data abort at IPA 0x{:X} without access info (ISV decode failed)",
            address
        );
    };

    let Some(register) = info.register_mut(regs) else {
        panic!(
            "data abort at IPA 0x{:X} with invalid register {}",
            address, access.reg_num
        );
    };

    let reg_size: InstructionRegisterSize = access.reg_size;
    let access_width: SyndromeAccessSize = access.access_width;
    let write_access: WriteNotRead = access.write_access;
    let access_bytes = match access_width {
        SyndromeAccessSize::Byte => 1,
        SyndromeAccessSize::HalfWord => 2,
        SyndromeAccessSize::Word => 4,
        SyndromeAccessSize::DoubleWord => 8,
    };

    if vgic::handles_gicd(address as usize) {
        let Some(gic_access) = gic_access_size_from_bytes(access_bytes) else {
            panic!("gicd: unsupported access size {}", access_bytes);
        };
        match write_access {
            WriteNotRead::ReadingMemoryAbort => {
                let value =
                    vgic::handle_gicd_read(address as usize, gic_access).expect("gicd read failed");
                *register = match reg_size {
                    InstructionRegisterSize::Instruction32bit => value as u64 & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => value as u64,
                };
            }
            WriteNotRead::WritingMemoryAbort => {
                let reg_val = match reg_size {
                    InstructionRegisterSize::Instruction32bit => *register & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => *register,
                };
                vgic::handle_gicd_write(address as usize, gic_access, reg_val as u32)
                    .expect("gicd write failed");
            }
        }
        cpu::set_elr_el2(cpu::get_elr_el2() + 4);
        return;
    }

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
                let uart = PL011_UART_ADDR.0;
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

fn handle_gicd_decoded(plan: &MmioDecoded, regs: &mut cpu::Registers) -> bool {
    match plan {
        MmioDecoded::Single {
            desc, ipa, split, ..
        } => {
            if !vgic::handles_gicd(*ipa as usize) {
                return false;
            }
            if split.is_some() {
                panic!("gicd: split access not supported");
            }
            let Some(access) = gic_access_size_from_bytes(desc.size) else {
                panic!("gicd: unsupported access size {}", desc.size);
            };
            if desc.is_store {
                let reg_val = store_value(desc, regs);
                vgic::handle_gicd_write(*ipa as usize, access, reg_val as u32)
                    .expect("gicd write failed");
            } else {
                let value =
                    vgic::handle_gicd_read(*ipa as usize, access).expect("gicd read failed");
                let Some(register) = regs.gpr_mut(desc.rt) else {
                    panic!("gicd: invalid register {}", desc.rt);
                };
                *register = match desc.rt_size {
                    InstructionRegisterSize::Instruction32bit => value as u64 & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => value as u64,
                };
            }
            cpu::set_elr_el2(cpu::get_elr_el2() + 4);
            true
        }
        MmioDecoded::Pair { ipa0, ipa1, .. } => {
            if vgic::handles_gicd(*ipa0 as usize) || vgic::handles_gicd(*ipa1 as usize) {
                panic!("gicd: pair access not supported");
            }
            false
        }
        MmioDecoded::Prefetch { .. } => false,
    }
}

fn gic_access_size_from_bytes(access_bytes: u8) -> Option<Gicv2AccessSize> {
    match access_bytes {
        1 => Some(Gicv2AccessSize::U8),
        4 => Some(Gicv2AccessSize::U32),
        _ => None,
    }
}

fn irq_handler(_regs: &mut cpu::Registers) {
    let Some(gicv2) = gic() else {
        return;
    };
    let Ok(Some(irq)) = gicv2.acknowledge() else {
        return;
    };
    if Some(irq.intid) == vgic::maintenance_intid() {
        vgic::handle_maintenance_irq().unwrap();
    } else {
        vgic::on_physical_irq(PIntId(irq.intid), true).unwrap();
    }
    gicv2.end_of_interrupt(irq).unwrap();
    gicv2.deactivate(irq).unwrap();
}

static PASSTHROUGH_MMIO: MmioHandler = MmioHandler {
    ctx: core::ptr::null(),
    read: passthrough_read,
    write: passthrough_write,
    probe: Some(passthrough_probe),
    read_pair: None,
    write_pair: None,
    access_class: AccessClass::DeviceMmio,
    split_policy: SplitPolicy::Never,
};

static DATA_ABORT_HANDLER: DataAbortHandlerEntry = DataAbortHandlerEntry {
    ctx: core::ptr::null_mut(),
    handler: data_abort_handler,
};

fn log_uart_write(plan: &MmioDecoded, regs: &cpu::Registers) {
    let (ipa, desc) = match plan {
        MmioDecoded::Single {
            desc,
            ipa,
            split: _,
            ..
        } if desc.is_store => (*ipa as usize, desc),
        _ => return,
    };
    let uart = PL011_UART_ADDR.0;
    if !(uart..uart + 0x1000).contains(&ipa) {
        return;
    }
    let value = store_value(desc, regs);
    if ipa == uart && value == b'\n' as u64 {
        println!("\nhypervisor: alive");
    }
}

fn store_value(desc: &emulation::SingleDesc, regs: &cpu::Registers) -> u64 {
    let regs_view = regs.gprs();
    let raw = if desc.rt == 31 {
        0
    } else {
        regs_view[desc.rt as usize]
    };
    match desc.size {
        1 => raw & 0xff,
        2 => raw & 0xffff,
        4 => raw & 0xffff_ffff,
        _ => raw,
    }
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
