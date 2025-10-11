#![no_std]
#![feature(naked_functions_rustic_abi)]
#![feature(sync_unsafe_cell)]

mod common_handler;
mod irq_handler;
pub mod registers;
pub mod synchronous_handler;

use cpu::set_vbar_el2;

use crate::common_handler::common_handler;
use crate::irq_handler::irq_handler;
use crate::registers::VBAR_EL2;
use crate::synchronous_handler::synchronous_handler;
use core::arch::global_asm;
use core::arch::naked_asm;

#[repr(C)]
pub struct Registers {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub x31: u64,
}

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
    adr  x1, \name_label
    b    {common_handler}
    .endm

.section .text
.balign 0x800
.size   exception_table, 0x800
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
    SAVE_CALL_RESTORE
    CALL_COMMON_HANDLER name_sync_current_x

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
