use crate::GDB_UART;
use crate::GUEST_UART;
use crate::debug;
use crate::gdb_uart;
use crate::vgic;
use arch_hal::cpu;
use arch_hal::exceptions;
use arch_hal::gic::GicCpuInterface;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2AccessSize;
use arch_hal::println;
use arch_hal::psci;
use arch_hal::psci::PsciFunctionId;
use arch_hal::psci::PsciReturnCode;
use core::cell::SyncUnsafeCell;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use exceptions::registers::InstructionRegisterSize;
use exceptions::registers::SyndromeAccessSize;
use exceptions::registers::WriteNotRead;

static GICV2: SyncUnsafeCell<Option<Gicv2>> = SyncUnsafeCell::new(None);
static GDB_UART_INTID: SyncUnsafeCell<Option<u32>> = SyncUnsafeCell::new(None);

pub(crate) fn setup_handler() {
    exceptions::synchronous_handler::set_data_abort_handler(data_abort_handler);
    exceptions::synchronous_handler::set_debug_handler(debug::handle_debug_exception);
    exceptions::irq_handler::set_irq_handler(irq_handler);

    // deny guest PSCI CPU_ON.
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc64, deny_cpu_on_handler);
    psci::set_psci_handler(PsciFunctionId::CpuOnSmc32, deny_cpu_on_handler);
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

fn data_abort_handler(
    register: &mut u64,
    address: u64,
    reg_size: InstructionRegisterSize,
    access_width: SyndromeAccessSize,
    write_access: WriteNotRead,
) {
    // SAFETY: Data abort emulation touches MMIO addresses explicitly filtered below.
    unsafe {
        let guest_uart = (*GUEST_UART.get()).map(|u| (u.base, u.size));
        let gdb_uart = (*GDB_UART.get()).map(|u| (u.base, u.size));
        let addr = address as usize;

        match write_access {
            WriteNotRead::ReadingMemoryAbort => {
                if vgic::handles_gicd(addr) {
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
                    cpu::set_elr_el2(cpu::get_elr_el2() + 4);
                    return;
                }
                if gdb_uart.is_some_and(|(base, size)| (base..base + size).contains(&addr)) {
                    *register = 0;
                } else {
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
            }

            WriteNotRead::WritingMemoryAbort => {
                let reg_val = match reg_size {
                    InstructionRegisterSize::Instruction32bit => *register & (u32::MAX as u64),
                    InstructionRegisterSize::Instruction64bit => *register,
                };

                if vgic::handles_gicd(addr) {
                    if let Some(access) = gic_access_size(access_width) {
                        let _ = vgic::handle_gicd_write(addr, access, reg_val as u32);
                    }
                    cpu::set_elr_el2(cpu::get_elr_el2() + 4);
                    return;
                }
                if gdb_uart.is_some_and(|(base, size)| (base..base + size).contains(&addr)) {
                    // Ignore guest writes to the GDB UART to keep it hypervisor-only.
                } else if guest_uart.is_some_and(|(base, size)| (base..base + size).contains(&addr))
                {
                    if guest_uart.is_some_and(|(base, _)| base == addr) && reg_val == b'\n' as u64 {
                        println!("\nhypervisor: alive");
                    }
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
                } else {
                    panic!("invalid abort addr: 0x{:X}", address);
                };
            }
        }
    }
    // advance elr_el2
    cpu::set_elr_el2(cpu::get_elr_el2() + 4);
}

fn gic_access_size(access_width: SyndromeAccessSize) -> Option<Gicv2AccessSize> {
    match access_width {
        SyndromeAccessSize::Byte => Some(Gicv2AccessSize::U8),
        SyndromeAccessSize::Word => Some(Gicv2AccessSize::U32),
        _ => None,
    }
}

fn irq_handler() {
    // SAFETY: IRQ handler runs after GIC is initialized.
    println!("irq_handler called");
    let Some(gic) = (unsafe { &*GICV2.get() }) else {
        return;
    };
    let Ok(Some(ack)) = gic.acknowledge() else {
        return;
    };
    // SAFETY: GDB UART INTID is written once during boot and then read-only.
    let gdb_intid = unsafe { *GDB_UART_INTID.get() };
    if Some(ack.intid) == gdb_intid {
        gdb_uart::handle_irq();
    } else if Some(ack.intid) == vgic::maintenance_intid() {
        vgic::handle_maintenance_irq().unwrap();
    } else {
        vgic::on_physical_irq(ack.intid).unwrap();
    }
    gic.end_of_interrupt(ack).unwrap();
}

fn deny_cpu_on_handler(regs: &mut cpu::Registers) {
    regs.x0 = PsciReturnCode::Denied.to_x0();
}
