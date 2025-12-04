use core::arch::asm;
use core::arch::global_asm;
use core::ffi::CStr;
use print::println;

/// Saved EL1 context produced by the EL1 vector entries in this module.
///
/// The layout must stay in sync with the `SAVE_FRAME_EL1` macro below:
/// - 0..248   : `gpr[0..31]` (x0-x30) in order, 8 bytes each.
/// - 248..256 : `sp` value at exception entry (before the frame allocation).
/// - 256..264 : `elr_el1`.
/// - 264..272 : `spsr_el1`.
/// - 272..280 : `esr_el1`.
/// - 280..288 : `far_el1`.
#[repr(C)]
pub struct El1ExceptionContext {
    pub gpr: [u64; 31],
    pub sp: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
}

#[inline(always)]
fn cstr_safe(ptr: *const u8) -> &'static str {
    if ptr.is_null() {
        return "<null>";
    }
    unsafe {
        match CStr::from_ptr(ptr).to_str() {
            Ok(s) => s,
            Err(_) => "<invalid-utf8>",
        }
    }
}

/// EL1 exception entry point called from the EL1 vector stubs.
///
/// # Safety
/// `ctx` must point to a valid `El1ExceptionContext` frame constructed by the
/// EL1 vector entry code in this module. `name` must be a valid C string
/// describing which vector slot was taken.
#[unsafe(no_mangle)]
pub extern "C" fn el1_exception_rust_entry(ctx: &El1ExceptionContext, name: *const u8) -> ! {
    let handler_name = cstr_safe(name);

    // Mask further interrupts/fiqs while we inspect the fault state.
    unsafe {
        asm!(
            "msr daifset, #0xf",
            options(nomem, nostack, preserves_flags)
        );
    }

    println!("[EL1] exception handler: {}", handler_name);
    println!(" ELR_EL1 : 0x{:016x}", ctx.elr_el1);
    println!(" SPSR_EL1: 0x{:016x}", ctx.spsr_el1);
    println!(" ESR_EL1 : 0x{:016x}", ctx.esr_el1);
    println!(" FAR_EL1 : 0x{:016x}", ctx.far_el1);
    println!(" SP(orig): 0x{:016x}", ctx.sp);

    for (idx, val) in ctx.gpr.iter().enumerate() {
        println!(" x{:02}: 0x{:016x}", idx, val);
    }

    println!("[EL1] halting after exception");
    loop {
        unsafe {
            asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}

global_asm!(
    r#"
    .macro SAVE_FRAME_EL1
        // Allocate space for El1ExceptionContext (288 bytes).
        sub sp, sp, #288

        // Save general-purpose registers x0-x30 into gpr[0..30].
        stp x0,  x1,  [sp, #0]
        stp x2,  x3,  [sp, #16]
        stp x4,  x5,  [sp, #32]
        stp x6,  x7,  [sp, #48]
        stp x8,  x9,  [sp, #64]
        stp x10, x11, [sp, #80]
        stp x12, x13, [sp, #96]
        stp x14, x15, [sp, #112]
        stp x16, x17, [sp, #128]
        stp x18, x19, [sp, #144]
        stp x20, x21, [sp, #160]
        stp x22, x23, [sp, #176]
        stp x24, x25, [sp, #192]
        stp x26, x27, [sp, #208]
        stp x28, x29, [sp, #224]
        str x30,     [sp, #240]

        // Save the original SP value (before frame allocation) at offset 248.
        add x0, sp, #288
        str x0, [sp, #248]

        // Capture ELR_EL1, SPSR_EL1, ESR_EL1, FAR_EL1.
        mrs x0, elr_el1
        str x0, [sp, #256]
        mrs x0, spsr_el1
        str x0, [sp, #264]
        mrs x0, esr_el1
        str x0, [sp, #272]
        mrs x0, far_el1
        str x0, [sp, #280]
    .endm

    .macro EL1_VECTOR_ENTRY vector_label, name_label
        .balign 0x80
\vector_label:
        SAVE_FRAME_EL1
        adrp x1, \name_label
        add  x1, x1, :lo12:\name_label
        mov  x0, sp
        bl   {el1_exception_rust_entry}
1:
        wfe
        b 1b
    .endm

    .section .text.el1_exceptions, "ax"
    // Ensure 2 KiB alignment for VBAR_EL1 requirements.
    .balign 0x800
    .global exception_table_el1
exception_table_el1:

    // VBAR_EL1 + 0x000: Current EL using SP0
    EL1_VECTOR_ENTRY el1_sync_sp0, name_el1_sync_sp0
    EL1_VECTOR_ENTRY el1_irq_sp0, name_el1_irq_sp0
    EL1_VECTOR_ENTRY el1_fiq_sp0, name_el1_fiq_sp0
    EL1_VECTOR_ENTRY el1_serror_sp0, name_el1_serror_sp0

    // VBAR_EL1 + 0x200: Current EL using SPx (EL1h)
    EL1_VECTOR_ENTRY el1_sync_spx, name_el1_sync_spx
    EL1_VECTOR_ENTRY el1_irq_spx, name_el1_irq_spx
    EL1_VECTOR_ENTRY el1_fiq_spx, name_el1_fiq_spx
    EL1_VECTOR_ENTRY el1_serror_spx, name_el1_serror_spx

    // VBAR_EL1 + 0x400: Lower EL using AArch64
    EL1_VECTOR_ENTRY el1_sync_lower_aarch64, name_el1_sync_lower_aarch64
    EL1_VECTOR_ENTRY el1_irq_lower_aarch64, name_el1_irq_lower_aarch64
    EL1_VECTOR_ENTRY el1_fiq_lower_aarch64, name_el1_fiq_lower_aarch64
    EL1_VECTOR_ENTRY el1_serror_lower_aarch64, name_el1_serror_lower_aarch64

    // VBAR_EL1 + 0x600: Lower EL using AArch32
    EL1_VECTOR_ENTRY el1_sync_lower_aarch32, name_el1_sync_lower_aarch32
    EL1_VECTOR_ENTRY el1_irq_lower_aarch32, name_el1_irq_lower_aarch32
    EL1_VECTOR_ENTRY el1_fiq_lower_aarch32, name_el1_fiq_lower_aarch32
    EL1_VECTOR_ENTRY el1_serror_lower_aarch32, name_el1_serror_lower_aarch32

    .section .rodata
    .p2align 0
name_el1_sync_sp0:            .asciz "el1_sync_sp0"
name_el1_irq_sp0:             .asciz "el1_irq_sp0"
name_el1_fiq_sp0:             .asciz "el1_fiq_sp0"
name_el1_serror_sp0:          .asciz "el1_serror_sp0"

name_el1_sync_spx:            .asciz "el1_sync_spx"
name_el1_irq_spx:             .asciz "el1_irq_spx"
name_el1_fiq_spx:             .asciz "el1_fiq_spx"
name_el1_serror_spx:          .asciz "el1_serror_spx"

name_el1_sync_lower_aarch64:  .asciz "el1_sync_lower_aarch64"
name_el1_irq_lower_aarch64:   .asciz "el1_irq_lower_aarch64"
name_el1_fiq_lower_aarch64:   .asciz "el1_fiq_lower_aarch64"
name_el1_serror_lower_aarch64: .asciz "el1_serror_lower_aarch64"

name_el1_sync_lower_aarch32:  .asciz "el1_sync_lower_aarch32"
name_el1_irq_lower_aarch32:   .asciz "el1_irq_lower_aarch32"
name_el1_fiq_lower_aarch32:   .asciz "el1_fiq_lower_aarch32"
name_el1_serror_lower_aarch32: .asciz "el1_serror_lower_aarch32"
"#,
    el1_exception_rust_entry = sym el1_exception_rust_entry,
);
