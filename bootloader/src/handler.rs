use crate::GUEST_UART;
use crate::debug;
use crate::gdb_uart;
use crate::guest_mmio_allowlist_contains_range;
use crate::irq_monitor;
use crate::monitor;
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
use arch_hal::timer;
use core::cell::SyncUnsafeCell;
use core::ffi::c_void;
use core::ptr::read_volatile;
use core::ptr::write_volatile;
use exceptions::registers::ESR_EL2;
use exceptions::registers::InstructionRegisterSize;
use exceptions::registers::SyndromeAccessSize;
use exceptions::registers::TI;
use exceptions::registers::WriteNotRead;
use exceptions::synchronous_handler::DataAbortHandlerEntry;
use exceptions::synchronous_handler::DataAbortInfo;
use exceptions::synchronous_handler::InstructionAbortInfo;
use exceptions::synchronous_handler::TrappedWfInfo;
use gdb_remote::WatchpointKind;

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
static MEMFAULT_TRAP_SKIP_LOG: SyncUnsafeCell<MemfaultTrapSkipLog> =
    SyncUnsafeCell::new(MemfaultTrapSkipLog::new());

const UNMAPPED_ABORT_LOG_LIMIT: u32 = 16;
const MEMFAULT_TRAP_SKIP_LOG_WINDOW_MS: u64 = 500;

struct MemfaultTrapSkipLog {
    last_addr: u64,
    last_ticks: u64,
    valid: bool,
}

impl MemfaultTrapSkipLog {
    const fn new() -> Self {
        Self {
            last_addr: 0,
            last_ticks: 0,
            valid: false,
        }
    }
}

pub(crate) fn setup_handler() {
    exceptions::synchronous_handler::set_data_abort_handler(DATA_ABORT_HANDLER);
    exceptions::synchronous_handler::set_debug_handler(debug::handle_debug_exception);
    exceptions::synchronous_handler::set_sysreg_trap_handler(
        crate::vbar_watch::sysreg_trap_handler,
    );
    exceptions::synchronous_handler::set_instruction_abort_handler(instruction_abort_handler);
    exceptions::synchronous_handler::set_trapped_wf_handler(trapped_wf_handler);
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

fn should_log_memfault_trap_skip(addr: u64) -> bool {
    let now = timer::read_counter();
    let freq = timer::read_counter_frequency();
    if freq == 0 {
        return true;
    }
    let window_ticks = (u128::from(freq) * u128::from(MEMFAULT_TRAP_SKIP_LOG_WINDOW_MS)) / 1000;
    let window_ticks = window_ticks.min(u128::from(u64::MAX)) as u64;

    // SAFETY: data abort handler is synchronous and non-preemptible for this state.
    unsafe {
        let state = &mut *MEMFAULT_TRAP_SKIP_LOG.get();
        if !state.valid {
            state.valid = true;
            state.last_addr = addr;
            state.last_ticks = now;
            return true;
        }
        let same_addr = state.last_addr == addr;
        let within_window = window_ticks != 0 && now.wrapping_sub(state.last_ticks) < window_ticks;
        if same_addr && within_window {
            return false;
        }
        state.last_addr = addr;
        state.last_ticks = now;
        true
    }
}

fn decoded_mmio_is_allowlisted(decoded: &MmioDecoded) -> bool {
    fn split_allowlisted(split: &emulation::SplitPlan) -> bool {
        for segment in split.segments() {
            if !guest_mmio_allowlist_contains_range(segment.ipa as usize, segment.size as usize) {
                return false;
            }
        }
        true
    }

    fn range_allowlisted(ipa: u64, size: u8, split: &Option<emulation::SplitPlan>) -> bool {
        if let Some(plan) = split {
            split_allowlisted(plan)
        } else {
            guest_mmio_allowlist_contains_range(ipa as usize, size as usize)
        }
    }

    match decoded {
        MmioDecoded::Single {
            desc, ipa, split, ..
        } => range_allowlisted(*ipa, desc.size, split),
        MmioDecoded::Pair {
            desc,
            ipa0,
            ipa1,
            split0,
            split1,
            ..
        } => {
            range_allowlisted(*ipa0, desc.size, split0)
                && range_allowlisted(*ipa1, desc.size, split1)
        }
        MmioDecoded::Prefetch { .. } => true,
    }
}

fn data_abort_handler(
    _ctx: *mut c_void,
    regs: &mut cpu::Registers,
    info: &DataAbortInfo,
    decoded: Option<&MmioDecoded>,
) {
    if let Some(plan) = decoded {
        if decoded_mmio_is_allowlisted(plan) {
            match emulation::execute_mmio(regs, info, &PASSTHROUGH_MMIO, plan) {
                EmulationOutcome::Handled => return,
                EmulationOutcome::NotHandled => {
                    panic!("decoded MMIO request was not handled: {:?}", plan)
                }
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

    let reg_size: InstructionRegisterSize = access.reg_size;
    let access_width: SyndromeAccessSize = access.access_width;
    let write_access: WriteNotRead = access.write_access;
    let reg_num = access.reg_num;

    let addr_u64 = address;
    let addr = address as usize;
    let access_bytes = access_width_bytes(access_width);
    let reg_bits = match reg_size {
        InstructionRegisterSize::Instruction32bit => 32,
        InstructionRegisterSize::Instruction64bit => 64,
    };
    let esr = cpu::get_esr_el2();
    let elr = cpu::get_elr_el2();

    if crate::vbar_watch::is_vbar_page(address & !0xfff) {
        let Some(register) = info.register_mut(regs) else {
            panic!(
                "data abort at IPA 0x{:X} with invalid register {}",
                address, reg_num
            );
        };
        match write_access {
            WriteNotRead::ReadingMemoryAbort => {
                let v = crate::vbar_watch::read_vbar_value(address, access_bytes)
                    .expect("vbar read emulation failed");
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
                crate::vbar_watch::write_vbar_value(address, access_bytes, reg_val)
                    .expect("vbar write emulation failed");
            }
        }
        cpu::set_elr_el2(elr + 4);
        return;
    }

    if vgic::handles_gicd(addr) {
        let Some(register) = info.register_mut(regs) else {
            panic!(
                "data abort at IPA 0x{:X} with invalid register {}",
                address, reg_num
            );
        };
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
        let Some(register) = info.register_mut(regs) else {
            panic!(
                "data abort at IPA 0x{:X} with invalid register {}",
                address, reg_num
            );
        };
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

    let memfault_info = monitor::MemfaultInfo {
        addr: addr_u64,
        pc: elr,
        access: if matches!(write_access, WriteNotRead::WritingMemoryAbort) {
            monitor::MemfaultAccess::Write
        } else {
            monitor::MemfaultAccess::Read
        },
        size: access_bytes as u8,
        esr,
        far: info.far_el2,
    };
    let in_debug = gdb_uart::is_debug_active();
    let session_active = gdb_uart::is_debug_session_active();
    let trap_ok = !in_debug && session_active;
    let decision = monitor::record_memfault(memfault_info);
    // AArch64 instructions are 4 bytes; `size` is the access width, not instruction length.
    let next_elr = elr.wrapping_add(4);
    let mut did_trap = false;
    if decision.should_trap && !in_debug {
        let kind = match write_access {
            WriteNotRead::WritingMemoryAbort => WatchpointKind::Write,
            WriteNotRead::ReadingMemoryAbort => WatchpointKind::Read,
        };
        if matches!(write_access, WriteNotRead::ReadingMemoryAbort) {
            let Some(register) = info.register_mut(regs) else {
                panic!(
                    "data abort at IPA 0x{:X} with invalid register {}",
                    address, reg_num
                );
            };
            *register = 0;
        }
        cpu::set_elr_el2(next_elr);
        did_trap = debug::enter_debug_from_memfault(regs, kind, addr_u64);
        if !did_trap && !trap_ok && should_log_memfault_trap_skip(addr_u64) {
            println!(
                "warning: memfault trap requested but no active debugger session; autoskipping addr=0x{:X} size={} reg={} esr=0x{:X} elr=0x{:X}",
                addr, access_bytes, reg_bits, esr, elr
            );
        }
    }

    if !decision.should_trap && !in_debug {
        gdb_uart::handle_irq();
        debug::enter_debug_from_irq(regs, gdb_uart::take_attach_reason());
    }

    if log_now && decision.should_log && !did_trap {
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
    if !did_trap {
        if matches!(write_access, WriteNotRead::ReadingMemoryAbort) {
            let Some(register) = info.register_mut(regs) else {
                panic!(
                    "data abort at IPA 0x{:X} with invalid register {}",
                    address, reg_num
                );
            };
            *register = 0;
        }
        cpu::set_elr_el2(next_elr);
    }
}

fn instruction_abort_handler(regs: &mut cpu::Registers, info: &InstructionAbortInfo) {
    let elr = info.elr_el2;
    let far = info.far_el2;
    let ipa_or_far = info.fault_ipa.unwrap_or(far);
    let ifsc = info.ifsc;
    println!(
        "guest instruction abort: ifsc={:?} elr=0x{:X} far=0x{:X} ipa_hint={:?} esr=0x{:X}",
        ifsc,
        elr,
        far,
        info.fault_ipa,
        info.esr_el2.bits()
    );

    let memfault_info = monitor::MemfaultInfo {
        addr: ipa_or_far,
        pc: elr,
        access: monitor::MemfaultAccess::Read,
        size: 4,
        esr: info.esr_el2.bits(),
        far,
    };

    let in_debug = gdb_uart::is_debug_active();
    let decision = monitor::record_memfault(memfault_info);
    if decision.should_trap && !in_debug {
        if debug::enter_debug_from_memfault(regs, WatchpointKind::Access, ipa_or_far) {
            return;
        }
    }

    loop {
        // SAFETY: halting the core until an interrupt is safe since nothing else should be running.
        unsafe { core::arch::asm!("wfi") };
    }
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
    if ack.intid == timer::SBSA_EL2_PHYSICAL_TIMER_INTID {
        irq_monitor::handle_physical_timer_irq();
        gic.end_of_interrupt(ack).unwrap();
        return;
    }
    // SAFETY: GDB UART INTID is written once during boot and then read-only.
    let gdb_intid = unsafe { *GDB_UART_INTID.get() };
    let maintenance_intid = vgic::maintenance_intid();
    let count_for_storm = Some(ack.intid) != gdb_intid && Some(ack.intid) != maintenance_intid;
    irq_monitor::record_ack(ack.intid, count_for_storm);
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

fn trapped_wf_handler(regs: &mut cpu::Registers, info: &TrappedWfInfo) {
    gdb_uart::poll_rx();
    let reason = gdb_uart::take_attach_reason();
    if reason != 0 {
        debug::enter_debug_from_irq(regs, reason);
    }

    cpu::set_elr_el2(cpu::get_elr_el2().wrapping_add(4));

    match info.ti {
        TI::WFE | TI::WFET => {
            // SAFETY: WFE is used to emulate a trapped guest wait after releasing locks.
            unsafe { core::arch::asm!("wfe", options(nomem, nostack, preserves_flags)) };
        }
        TI::WFI | TI::WFIT => {
            // SAFETY: WFI is used to emulate a trapped guest wait after releasing locks.
            unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
        }
    }
}

fn deny_cpu_on_handler(regs: &mut cpu::Registers) {
    regs.x0 = PsciReturnCode::Denied.to_x0();
}
