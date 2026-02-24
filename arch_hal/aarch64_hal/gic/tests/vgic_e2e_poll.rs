#![cfg_attr(target_arch = "aarch64", no_std)]
#![cfg_attr(target_arch = "aarch64", no_main)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use core::arch::asm;
use core::arch::naked_asm;

#[path = "vgic_e2e_common.rs"]
mod common;

unsafe extern "C" {
    static __stack_top: u8;
}

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
    common::run_el2("vgic_e2e_poll", guest_entry_poll)
}

extern "C" fn guest_entry_poll(shared: *mut common::Shared) -> ! {
    // SAFETY: poll test intentionally keeps IRQ masked while reading virtual IAR directly.
    unsafe {
        asm!("msr daifset, #0b0010", options(nostack, preserves_flags));
    }

    let gic = common::GuestGic::default_layout();
    common::guest_init_virtual_interfaces(&gic);

    common::guest_enable_intid(&gic, common::SGI_ID);
    common::guest_send_sgi_self(&gic, common::SGI_ID);
    let sgi_raw = common::guest_poll_for_intid(
        shared,
        &gic,
        common::SGI_ID,
        common::POLL_TIMEOUT_ITERS,
        common::FAIL_POLL_SGI_TIMEOUT,
        common::FAIL_POLL_SGI_UNEXPECTED,
    );
    common::shared_increment_poll_seen(shared, common::IDX_SGI);
    common::guest_eoi_virtual_irq(&gic, sgi_raw);
    common::guest_assert_not_redelivered(
        shared,
        &gic,
        common::SGI_ID,
        common::DUPLICATE_CHECK_ITERS,
        common::FAIL_POLL_SGI_DUPLICATE,
    );

    common::guest_enable_intid(&gic, common::TIMER_TEST_PPI_INTID);
    common::guest_set_pending_intid(&gic, common::TIMER_TEST_PPI_INTID);
    let ppi_raw = common::guest_poll_for_intid(
        shared,
        &gic,
        common::TIMER_TEST_PPI_INTID,
        common::POLL_TIMEOUT_ITERS,
        common::FAIL_POLL_PPI_TIMEOUT,
        common::FAIL_POLL_PPI_UNEXPECTED,
    );
    common::shared_increment_poll_seen(shared, common::IDX_PPI);
    common::guest_eoi_virtual_irq(&gic, ppi_raw);
    common::guest_clear_pending_intid(&gic, common::TIMER_TEST_PPI_INTID);
    common::guest_assert_not_redelivered(
        shared,
        &gic,
        common::TIMER_TEST_PPI_INTID,
        common::DUPLICATE_CHECK_ITERS,
        common::FAIL_POLL_PPI_DUPLICATE,
    );

    common::guest_configure_spi(&gic, common::UART_SPI_INTID, 0x80, 0x01);
    common::guest_clear_pending_intid(&gic, common::UART_SPI_INTID);
    common::guest_uart_enable_tx_irq();
    let uart_raw = common::guest_poll_for_intid(
        shared,
        &gic,
        common::UART_SPI_INTID,
        common::POLL_TIMEOUT_ITERS,
        common::FAIL_POLL_UART_TIMEOUT,
        common::FAIL_POLL_UART_UNEXPECTED,
    );
    common::shared_increment_poll_seen(shared, common::IDX_UART);
    common::guest_eoi_virtual_irq(&gic, uart_raw);
    common::guest_uart_disable_tx_irq();
    common::guest_assert_not_redelivered(
        shared,
        &gic,
        common::UART_SPI_INTID,
        common::DUPLICATE_CHECK_ITERS,
        common::FAIL_POLL_UART_DUPLICATE,
    );
    common::guest_finish(shared)
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    common::panic_exit("vgic_e2e_poll", info)
}
