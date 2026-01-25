use crate::GUEST_UART;
use crate::debug;
use crate::gdb_uart;
use crate::guest_mmio_allowlist_contains_range;
use crate::vgic;
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
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2AccessSize;
use arch_hal::println;
use arch_hal::psci;
use arch_hal::psci::PsciFunctionId;
use arch_hal::psci::PsciReturnCode;
use core::cell::SyncUnsafeCell;
use core::ffi::c_void;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use exceptions::registers::ESR_EL2;
use exceptions::registers::InstructionRegisterSize;
use exceptions::registers::SyndromeAccessSize;
use exceptions::registers::WriteNotRead;
use exceptions::synchronous_handler::DataAbortHandlerEntry;
use exceptions::synchronous_handler::DataAbortInfo;

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

static GICV2: SyncUnsafeCell<Option<Gicv2>> = SyncUnsafeCell::new(None);
static GDB_UART_INTID: SyncUnsafeCell<Option<u32>> = SyncUnsafeCell::new(None);
static UNMAPPED_ABORT_COUNT: SyncUnsafeCell<u32> = SyncUnsafeCell::new(0);

const UNMAPPED_ABORT_LOG_LIMIT: u32 = 16;

pub(crate) fn setup_handler() {
    exceptions::synchronous_handler::set_data_abort_handler(DATA_ABORT_HANDLER);
    exceptions::synchronous_handler::set_debug_handler(debug::handle_debug_exception);
    exceptions::irq_handler::set_irq_handler(irq_handler);

    // deny guest PSCI CPU_ON.
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc64, deny_cpu_on_handler);
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc32, deny_cpu_on_handler);
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
    matches!(size, 1 | 2 | 4 | 8)
}

pub(crate) fn register_gic(gic: Gicv2, gdb_uart_intid: Option<u32>) {
    // SAFETY: single initialization during early boot before IRQs are enabled.
    unsafe {
        *GICV2.get() = Some(gic);
        *GDB_UART_INTID.get() = gdb_uart_intid;
    }
}

pub(crate) fn gic() -> Option<&'static Gicv2> {
    // SAFETY: GIC is initialized once and then read-only.
    unsafe { &*GICV2.get() }.as_ref()
}

fn access_width_bytes(access_width: SyndromeAccessSize) -> usize {
    match access_width {
        SyndromeAccessSize::Byte => 1,
        SyndromeAccessSize::HalfWord => 2,
        SyndromeAccessSize::Word => 4,
        SyndromeAccessSize::DoubleWord => 8,
    }
}

fn should_log_unmapped_abort() -> bool {
    // SAFETY: data abort handler is synchronous and non-preemptible for this counter.
    unsafe {
        let counter = &mut *UNMAPPED_ABORT_COUNT.get();
        let next = counter.saturating_add(1);
        *counter = next;
        next <= UNMAPPED_ABORT_LOG_LIMIT || next.is_power_of_two()
    }
}

fn data_abort_handler(
    _ctx: *mut c_void,
    regs: &mut cpu::Registers,
    info: &DataAbortInfo,
    decoded: Option<&MmioDecoded>,
) {
    if let Some(plan) = decoded {
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

    let addr = address as usize;
    let access_bytes = access_width_bytes(access_width);
    let reg_bits = match reg_size {
        InstructionRegisterSize::Instruction32bit => 32,
        InstructionRegisterSize::Instruction64bit => 64,
    };
    let esr = cpu::get_esr_el2();
    let elr = cpu::get_elr_el2();

    if vgic::handles_gicd(addr) {
        match write_access {
            WriteNotRead::ReadingMemoryAbort => {
                if let Some(access) = gic_access_size(access_width) {
                    if let Ok(value) = vgic::handle_gicd_read(addr, access) {
                        *register = match reg_size {
                            InstructionRegisterSize::Instruction32bit => {
                                value as u64 & (u32::MAX as u64)
                            }
                            InstructionRegisterSize::Instruction64bit => value as u64,
                        };
                    }
                }
            }
            WriteNotRead::WritingMemoryAbort => {
                let reg_val = match reg_size {
                    InstructionRegisterSize::Instruction32bit => *register & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => *register,
                };
                if let Some(access) = gic_access_size(access_width) {
                    let _ = vgic::handle_gicd_write(addr, access, reg_val as u32);
                }
            }
        }
        cpu::set_elr_el2(elr + 4);
        return;
    }

    let allowlisted = guest_mmio_allowlist_contains_range(addr, access_bytes);
    let log_now = should_log_unmapped_abort();
    if allowlisted {
        if log_now {
            println!(
                "warning: unexpected abort on allowlisted MMIO {} addr=0x{:X} size={} reg={} esr=0x{:X} elr=0x{:X}",
                if matches!(write_access, WriteNotRead::WritingMemoryAbort) {
                    "write"
                } else {
                    "read"
                },
                addr,
                access_bytes,
                reg_bits,
                esr,
                elr
            );
        }
        match write_access {
            WriteNotRead::ReadingMemoryAbort => {
                // SAFETY: address is within a DTB-derived allowlisted MMIO range.
                let v = unsafe {
                    match access_width {
                        SyndromeAccessSize::Byte => read_volatile(address as *const u8) as u64,
                        SyndromeAccessSize::HalfWord => read_volatile(address as *const u16) as u64,
                        SyndromeAccessSize::Word => read_volatile(address as *const u32) as u64,
                        SyndromeAccessSize::DoubleWord => read_volatile(address as *const u64),
                    }
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
                // SAFETY: address is within a DTB-derived allowlisted MMIO range.
                unsafe {
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
                // SAFETY: guest UART is initialized before guests can generate aborts.
                let guest_uart_base = unsafe { (*GUEST_UART.get()).map(|u| u.base) };
                if guest_uart_base.is_some_and(|base| base == addr) && reg_val == b'\n' as u64 {
                    println!("\nhypervisor: alive");
                }
            }
        }
        cpu::set_elr_el2(elr + 4);
        return;
    }

    if log_now {
        println!(
            "warning: unmapped access {} addr=0x{:X} size={} reg={} esr=0x{:X} elr=0x{:X}",
            if matches!(write_access, WriteNotRead::WritingMemoryAbort) {
                "write"
            } else {
                "read"
            },
            addr,
            access_bytes,
            reg_bits,
            esr,
            elr
        );
    }
    if matches!(write_access, WriteNotRead::ReadingMemoryAbort) {
        *register = 0;
    }
    cpu::set_elr_el2(elr + 4);
}

fn gic_access_size(access_width: SyndromeAccessSize) -> Option<Gicv2AccessSize> {
    match access_width {
        SyndromeAccessSize::Byte => Some(Gicv2AccessSize::U8),
        SyndromeAccessSize::Word => Some(Gicv2AccessSize::U32),
        _ => None,
    }
}

fn irq_handler(regs: &mut cpu::Registers) {
    // SAFETY: IRQ handler runs after GIC is initialized.
    // println!("irq_handler called");
    let Some(gic) = (unsafe { &*GICV2.get() }) else {
        return;
    };
    let Ok(Some(ack)) = gic.acknowledge() else {
        return;
    };
    // println!("irq_handler ack intid: {}", ack.intid);
    // SAFETY: GDB UART INTID is written once during boot and then read-only.
    let gdb_intid = unsafe { *GDB_UART_INTID.get() };
    if gdb_uart::is_debug_active() {
        if Some(ack.intid) == gdb_intid {
            gdb_uart::handle_irq();
        }
        gic.end_of_interrupt(ack).unwrap();
        return;
    }

    if Some(ack.intid) == gdb_intid {
        gdb_uart::handle_irq();
    } else if Some(ack.intid) == vgic::maintenance_intid() {
        vgic::handle_maintenance_irq().unwrap();
    } else {
        vgic::on_physical_irq(ack.intid).unwrap();
    }
    gic.end_of_interrupt(ack).unwrap();

    let reason = gdb_uart::take_attach_reason();
    if reason != 0 {
        debug::enter_debug_from_irq(regs, reason);
    }
}

fn deny_cpu_on_handler(regs: &mut cpu::Registers) {
    regs.x0 = PsciReturnCode::Denied.to_x0();
}
