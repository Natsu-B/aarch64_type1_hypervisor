use crate::GLOBAL_ALLOCATOR;
use crate::SPSR_EL2_M_EL1H;
use alloc::vec;
use alloc::vec::Vec;
use arch_hal::cpu;
use arch_hal::cpu::CoreAffinity;
use arch_hal::debug_uart;
use arch_hal::println;
use arch_hal::psci::secure_monitor_call;
use core::arch::asm;
use core::arch::naked_asm;
use core::cell::OnceCell;
use core::mem::size_of;
use core::ops::ControlFlow;
use mutex::SpinLock;

static AP_STACK_SIZE: usize = 0x1000;

static STACK_MEM_FOR_EACH_CPU: SpinLock<OnceCell<Vec<(CoreAffinity, usize)>>> =
    SpinLock::new(OnceCell::new());

#[repr(C, align(16))]
pub struct HypervisorRegisters {
    vtcr_el2: u64,
    vttbr_el2: u64,
    hcr_el2: u64,
    vbar_el2: u64,
    sctlr_el2: u64,
    tcr_el2: u64,
    ttbr0_el2: u64,
    mair_el2: u64,
    cnthctl_el2: u64,
    cntvoff_el2: u64,
    cptr_el2: u64,
    mdcr_el2: u64,
    el1_entry_point: u64,
    el1_context_id: u64,
}

pub fn setup_multicore(stack: usize) {
    GLOBAL_ALLOCATOR.enable_atomic();
    debug_uart::enable_atomic();
    let cpu_id = cpu::get_current_core_id();
    let stack_list = STACK_MEM_FOR_EACH_CPU.lock();
    stack_list.set(vec![(cpu_id, stack)]).unwrap();
}

// psci application processor on handler
pub fn ap_on(regs: &mut cpu::Registers) {
    println!("application processor on");
    let cpu_id = CoreAffinity::from_bits(regs.x1);
    let mut stack_list = STACK_MEM_FOR_EACH_CPU.lock();
    let stack_list = stack_list.get_mut().unwrap();
    let already_allocated_cpu_stack =
        stack_list.iter().try_for_each(|(cpu_id_list, stack_addr)| {
            if *cpu_id_list == cpu_id {
                ControlFlow::Break(stack_addr)
            } else {
                ControlFlow::Continue(())
            }
        });

    let stack_addr = match already_allocated_cpu_stack {
        ControlFlow::Break(x) => *x,
        ControlFlow::Continue(()) => {
            let stack_addr = GLOBAL_ALLOCATOR
                .allocate_with_size_and_align(AP_STACK_SIZE, AP_STACK_SIZE)
                .expect("out of memory")
                + AP_STACK_SIZE;
            stack_list.push((cpu_id, stack_addr));
            stack_addr
        }
    };

    let register_context = unsafe {
        &mut *((stack_addr - size_of::<HypervisorRegisters>()) as *mut HypervisorRegisters)
    };
    register_context.vtcr_el2 = cpu::get_vtcr_el2();
    register_context.vttbr_el2 = cpu::get_vttbr_el2();
    register_context.hcr_el2 = cpu::get_hcr_el2();
    register_context.vbar_el2 = cpu::get_vbar_el2();
    register_context.sctlr_el2 = cpu::get_sctlr_el2();
    register_context.tcr_el2 = cpu::get_tcr_el2();
    register_context.ttbr0_el2 = cpu::get_ttbr0_el2();
    register_context.mair_el2 = cpu::get_mair_el2();
    register_context.cnthctl_el2 = cpu::get_cnthctl_el2();
    register_context.cntvoff_el2 = cpu::get_cntvoff_el2();
    register_context.cptr_el2 = cpu::get_cptr_el2();
    register_context.mdcr_el2 = cpu::get_mdcr_el2();

    register_context.el1_entry_point = regs.x2;
    register_context.el1_context_id = regs.x3;
    cpu::clean_data_cache_all();
    cpu::invalidate_icache_all();
    cpu::clean_dcache_poc(
        register_context as *const _ as usize,
        size_of::<HypervisorRegisters>(),
    );
    cpu::isb();
    cpu::dsb_ish();

    let cpu_boot_address = ap_start as u64;

    // Safety: require ipa == pa
    regs.x2 = cpu_boot_address;
    regs.x3 = register_context as *const _ as u64;
    secure_monitor_call(regs);
}

#[unsafe(naked)]
extern "C" fn ap_start() {
    naked_asm!("
    mov sp, x0
    b {AP_MAIN}
    ",
    AP_MAIN = sym ap_main)
}

extern "C" fn ap_main(register_context: *const HypervisorRegisters) -> ! {
    let register_context = unsafe { &*register_context };
    // Stage-2 translation tables
    cpu::set_vtcr_el2(register_context.vtcr_el2);
    cpu::set_vttbr_el2(register_context.vttbr_el2);

    // Stage-1 translation tables & attributes
    cpu::set_mair_el2(register_context.mair_el2);
    cpu::set_ttbr0_el2(register_context.ttbr0_el2);
    cpu::set_tcr_el2(register_context.tcr_el2);

    // Timer / debug / trap configuration
    cpu::set_cnthctl_el2(register_context.cnthctl_el2);
    cpu::set_cntvoff_el2(register_context.cntvoff_el2);
    cpu::set_cptr_el2(register_context.cptr_el2);
    cpu::set_mdcr_el2(register_context.mdcr_el2);

    // Exception vectors
    cpu::set_vbar_el2(register_context.vbar_el2);

    // Barriers before turning on MMU / stage-2
    cpu::isb();
    cpu::flush_tlb_el2_el1();
    cpu::flush_tlb_el2();
    cpu::invalidate_icache_all();

    // Enable MMU & stage-2
    cpu::set_sctlr_el2(register_context.sctlr_el2);
    cpu::set_hcr_el2(register_context.hcr_el2);

    cpu::isb();

    println!("ap_main setup DONE!!!");

    unsafe {
        asm!(
            "
            mrs x0, midr_el1
            msr vpidr_el2, x0

            mrs x1, mpidr_el1
            msr vmpidr_el2, x1

            mov x0, {entry_point}
            msr elr_el2, x0
            msr spsr_el2, {spsr_el2}
            mov x0, {context_id}
            isb
            eret
            ",
            entry_point = in(reg) register_context.el1_entry_point,
            spsr_el2 = in(reg) SPSR_EL2_M_EL1H,
            context_id = in(reg) register_context.el1_context_id,
            options(noreturn),
        )
    }
}
