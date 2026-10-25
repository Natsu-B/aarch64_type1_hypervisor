//! EL1 guest exception vector table shared by the IRQ-driven vGIC end-to-end tests.
//!
//! Every vector except "current EL with SPx, IRQ" parks the vCPU. The IRQ vector saves the
//! caller-saved and callee-saved GPRs, calls the test-provided
//! `extern "C" fn guest_irq_handler_trampoline()`, restores them, and returns with `eret`.

use core::arch::global_asm;
use core::ptr;

unsafe extern "C" {
    static guest_el1_vectors: u8;
}

/// Returns the address of the 0x800-aligned guest vector table, suitable for `VBAR_EL1`.
pub fn guest_el1_vectors_addr() -> u64 {
    // SAFETY: the symbol is emitted by the vector table below and is 0x800 aligned.
    ptr::addr_of!(guest_el1_vectors) as u64
}

global_asm!(
    r#"
    .section .text
    .balign 0x800
    .global guest_el1_vectors
guest_el1_vectors:
    // current EL with SP0
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled

    // current EL with SPx (EL1h)
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_irq_spx
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled

    // lower EL AArch64
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled

    // lower EL AArch32
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled
    .balign 0x80
    b guest_el1_unhandled

guest_el1_irq_spx:
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

    bl guest_irq_handler_trampoline

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

guest_el1_unhandled:
1:
    wfe
    b 1b
"#
);
