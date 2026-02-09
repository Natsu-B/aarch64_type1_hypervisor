#![no_std]
#![feature(naked_functions_rustic_abi)]
#![feature(sync_unsafe_cell)]
#![cfg_attr(all(test, target_arch = "aarch64"), feature(custom_test_frameworks))]
#![cfg_attr(
    all(test, target_arch = "aarch64"),
    test_runner(aarch64_unit_test::test_runner)
)]
#![cfg_attr(
    all(test, target_arch = "aarch64"),
    reexport_test_harness_main = "test_main"
)]
#![cfg_attr(all(test, target_arch = "aarch64"), no_main)]

#[cfg(all(test, not(target_arch = "aarch64")))]
extern crate std;

mod common_handler;
mod el1;
pub mod emulation;
pub mod irq_handler;
pub mod memory_hook;
pub mod registers;
pub mod synchronous_handler;

use crate::common_handler::common_handler;
use crate::irq_handler::irq_handler;
use crate::registers::VBAR_EL1;
use crate::registers::VBAR_EL2;
use crate::synchronous_handler::synchronous_handler;
use core::arch::global_asm;
use core::arch::naked_asm;
use cpu::set_vbar_el1;
use cpu::set_vbar_el2;

pub use memory_hook::AccessClass;
pub use memory_hook::MmioError;
pub use memory_hook::MmioHandler;
pub use memory_hook::SplitPolicy;
global_asm!(
r#"
    .macro SAVE_CALL_RESTORE
    sub sp,   sp, #(8 * 32)
    stp x30, xzr, [sp, #( 15 * 16)]
    stp x28, x29, [sp, #( 14 * 16)]
    stp x26, x27, [sp, #( 13 * 16)]
    stp x24, x25, [sp, #( 12 * 16)]
    stp x22, x23, [sp, #( 11 * 16)]
    stp x20, x21, [sp, #( 10 * 16)]
    stp x18, x19, [sp, #(  9 * 16)]
    stp x16, x17, [sp, #(  8 * 16)]
    stp x14, x15, [sp, #(  7 * 16)]
    stp x12, x13, [sp, #(  6 * 16)]
    stp x10, x11, [sp, #(  5 * 16)]
    stp  x8,  x9, [sp, #(  4 * 16)]
    stp  x6,  x7, [sp, #(  3 * 16)]
    stp  x4,  x5, [sp, #(  2 * 16)]
    stp  x2,  x3, [sp, #(  1 * 16)]
    stp  x0,  x1, [sp, #(  0 * 16)]
    mov  x0, sp
    .endm

    .macro CALL_COMMON_HANDLER name_label
    adrp x1, \name_label
    add  x1, x1, :lo12:\name_label
    b    {common_handler}
    .endm

.section .text
.balign 0x800
// .size   exception_table, 0x800
.global exception_table
exception_table:

.balign 0x080
synchronous_current_el_stack_pointer_0:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_sync_current_0

.balign 0x080
irq_current_el_stack_pointer_0:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_irq_current_0

.balign 0x080
fiq_current_el_stack_pointer_0:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_fiq_current_0

.balign 0x080
s_error_current_el_stack_pointer_0:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_error_current_0

.balign 0x080
synchronous_current_el_stack_pointer_x:
    b el2_sync_current_x_handler

.balign 0x080
irq_current_el_stack_pointer_x:
    SAVE_CALL_RESTORE
    adr x30, {exit_exception}
    b   {irq_handler}

.balign 0x080
fiq_current_el_stack_pointer_x:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_fiq_current_x

.balign 0x080
s_error_current_el_stack_pointer_x:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_error_current_x

.balign 0x080
synchronous_lower_el_aarch64:
    SAVE_CALL_RESTORE
    adr x30, {exit_exception}
    b   {synchronous_handler}

.balign 0x080
irq_lower_el_aarch64:
    SAVE_CALL_RESTORE
    adr x30, {exit_exception}
    b   {irq_handler}

.balign 0x080
fiq_lower_el_aarch64:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_fiq_lower_aarch64

.balign 0x080
s_error_lower_el_aarch64:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_s_error_lower_aarch64

.balign 0x080
synchronous_lower_el_aarch32:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_sync_lower_aarch32

.balign 0x080
irq_lower_el_aarch32:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_irq_lower_aarch32

.balign 0x080
fiq_lower_el_aarch32:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_fiq_lower_aarch32

.balign 0x080
s_error_lower_el_aarch32:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_s_error_lower_aarch32

.weak el2_sync_current_x_handler
el2_sync_current_x_handler:
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_sync_current_x


    .section .rodata
    .p2align 0

name_sync_current_0:        .asciz "sync_current_0"
name_irq_current_0:         .asciz "irq_current_0"
name_fiq_current_0:         .asciz "fiq_current_0"
name_error_current_0:       .asciz "s_error_current_0"

name_sync_current_x:        .asciz "sync_current_x"
name_fiq_current_x:         .asciz "fiq_current_x"
name_error_current_x:       .asciz "s_error_current_x"

name_fiq_lower_aarch64:     .asciz "fiq_lower_aarch64"
name_s_error_lower_aarch64: .asciz "s_error_lower_aarch64"

name_sync_lower_aarch32:    .asciz "sync_lower_aarch32"
name_irq_lower_aarch32:     .asciz "irq_lower_aarch32"
name_fiq_lower_aarch32:     .asciz "fiq_lower_aarch32"
name_s_error_lower_aarch32: .asciz "s_error_lower_aarch32"
"#,
common_handler = sym common_handler,
exit_exception = sym exit_exception,
irq_handler = sym irq_handler,
synchronous_handler = sym synchronous_handler,
);

#[unsafe(naked)]
fn exit_exception() {
    naked_asm!(
        r#"
    ldp x30, xzr, [sp, #( 15 * 16)]
    ldp x28, x29, [sp, #( 14 * 16)]
    ldp x26, x27, [sp, #( 13 * 16)]
    ldp x24, x25, [sp, #( 12 * 16)]
    ldp x22, x23, [sp, #( 11 * 16)]
    ldp x20, x21, [sp, #( 10 * 16)]
    ldp x18, x19, [sp, #(  9 * 16)]
    ldp x16, x17, [sp, #(  8 * 16)]
    ldp x14, x15, [sp, #(  7 * 16)]
    ldp x12, x13, [sp, #(  6 * 16)]
    ldp x10, x11, [sp, #(  5 * 16)]
    ldp  x8,  x9, [sp, #(  4 * 16)]
    ldp  x6,  x7, [sp, #(  3 * 16)]
    ldp  x4,  x5, [sp, #(  2 * 16)]
    ldp  x2,  x3, [sp, #(  1 * 16)]
    ldp  x0,  x1, [sp, #(  0 * 16)]
    add  sp,  sp, #(8 * 32)
    eret
        "#
    );
}

pub fn setup_exception() {
    unsafe extern "C" {
        static exception_table: *const u8;
    }
    set_vbar_el2(
        VBAR_EL2::new()
            .set_raw(VBAR_EL2::vba, unsafe { &exception_table } as *const _
                as u64)
            .bits(),
    );
}

pub fn setup_el1_exception() {
    unsafe extern "C" {
        static exception_table_el1: u8;
    }
    set_vbar_el1(
        VBAR_EL1::new()
            .set_raw(VBAR_EL1::vba, unsafe { &exception_table_el1 } as *const _
                as u64)
            .bits(),
    );
}

#[cfg(all(test, target_arch = "aarch64"))]
fn __unit_test_init() {
    aarch64_unit_test::init_default_uart();
    setup_exception();
}

#[cfg(all(test, target_arch = "aarch64"))]
aarch64_unit_test::uboot_unit_test_harness!(__unit_test_init);
