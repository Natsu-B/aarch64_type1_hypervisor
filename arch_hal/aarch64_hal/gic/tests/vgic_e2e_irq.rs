#![cfg_attr(target_arch = "aarch64", no_std)]
#![cfg_attr(target_arch = "aarch64", no_main)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use core::arch::asm;
use core::arch::naked_asm;
use core::ptr;

#[path = "vgic_e2e_common.rs"]
mod common;
#[path = "vgic_e2e_guest_vectors.rs"]
mod guest_vectors;

unsafe extern "C" {
    static __stack_top: u8;
}

static mut GUEST_SHARED_PTR: *mut common::Shared = ptr::null_mut();

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn _start() -> ! {
    naked_asm!("ldr x0, =__stack_top", "mov sp, x0", "bl rust_entry", "b .");
}

#[unsafe(no_mangle)]
extern "C" fn rust_entry() -> ! {
    // SAFETY: clears the test image .bss before any static state is used.
    unsafe {
        common::clear_bss();
    }
    common::run_el2("vgic_e2e_irq", guest_entry_irq)
}

extern "C" fn guest_entry_irq(shared: *mut common::Shared) -> ! {
    // SAFETY: one-time pointer publication for IRQ trampoline on this single guest vCPU.
    unsafe {
        *ptr::addr_of_mut!(GUEST_SHARED_PTR) = shared;
    }

    let vbar = guest_vectors::guest_el1_vectors_addr();
    cpu::set_vbar_el1(vbar);
    cpu::isb();

    let gic = common::GuestGic::default_layout();
    common::guest_init_virtual_interfaces(&gic);

    // SAFETY: IRQ unmask is required for real EL1 IRQ-delivery validation.
    unsafe {
        asm!("msr daifclr, #0b0010", options(nostack, preserves_flags));
    }

    common::guest_set_group1_intid(&gic, common::SGI_ID);
    common::guest_enable_intid(&gic, common::SGI_ID);
    common::guest_send_sgi_self(&gic, common::SGI_ID);
    common::guest_wait_for_irq_count(
        shared,
        common::IDX_SGI,
        1,
        common::IRQ_WAIT_ITERS,
        common::FAIL_IRQ_SGI_WAIT_TIMEOUT,
    );
    common::guest_send_sgi_self(&gic, common::SGI_ID);
    common::guest_wait_for_irq_count(
        shared,
        common::IDX_SGI,
        2,
        common::IRQ_WAIT_ITERS,
        common::FAIL_IRQ_SGI_SECOND_WAIT_TIMEOUT,
    );

    common::guest_set_group1_intid(&gic, common::TIMER_TEST_PPI_INTID);
    common::guest_enable_intid(&gic, common::TIMER_TEST_PPI_INTID);
    common::guest_set_pending_intid(&gic, common::TIMER_TEST_PPI_INTID);
    common::guest_wait_for_irq_count(
        shared,
        common::IDX_PPI,
        1,
        common::IRQ_WAIT_ITERS,
        common::FAIL_IRQ_PPI_WAIT_TIMEOUT,
    );

    common::guest_set_group1_intid(&gic, common::UART_SPI_INTID);
    common::guest_configure_spi(&gic, common::UART_SPI_INTID, 0x80, 0x01);
    common::guest_clear_pending_intid(&gic, common::UART_SPI_INTID);
    common::guest_uart_enable_tx_irq();
    common::guest_wait_for_irq_count(
        shared,
        common::IDX_UART,
        1,
        common::IRQ_WAIT_ITERS,
        common::FAIL_IRQ_UART_WAIT_TIMEOUT,
    );

    common::guest_uart_disable_tx_irq();
    common::guest_finish(shared)
}

#[unsafe(no_mangle)]
extern "C" fn guest_irq_handler_trampoline() {
    // SAFETY: pointer is written before IRQ unmask and then read atomically in the IRQ path.
    let shared = unsafe { ptr::read_volatile(ptr::addr_of!(GUEST_SHARED_PTR)) };
    if shared.is_null() {
        return;
    }

    let gic = common::GuestGic::default_layout();
    let iar_raw = common::guest_ack_virtual_irq(&gic);
    let intid = common::guest_acked_intid(iar_raw);

    if intid == common::SPURIOUS_INTID || intid == common::ALT_SPURIOUS_INTID {
        return;
    }

    common::shared_set_last_intid(shared, intid);
    common::shared_set_last_iar_raw(shared, iar_raw);

    match intid {
        id if id == common::SGI_ID => {
            common::shared_increment_irq_seen(shared, common::IDX_SGI);
        }
        id if id == common::TIMER_TEST_PPI_INTID => {
            common::shared_increment_irq_seen(shared, common::IDX_PPI);
        }
        id if id == common::UART_SPI_INTID => {
            common::shared_increment_irq_seen(shared, common::IDX_UART);
            common::guest_uart_disable_tx_irq();
        }
        other => {
            common::shared_set_unexpected_intid(shared, other);
            common::shared_set_fail_if_unset(shared, common::FAIL_IRQ_UNEXPECTED_INTID);
        }
    }

    common::guest_eoi_virtual_irq(&gic, iar_raw);
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    common::panic_exit("vgic_e2e_irq", info)
}
