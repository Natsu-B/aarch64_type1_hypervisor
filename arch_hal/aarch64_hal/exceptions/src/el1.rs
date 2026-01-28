use core::arch::asm;
use core::arch::global_asm;

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

const CSTR_LIMIT: usize = 64;
const UART_DR_OFFSET: usize = 0x00;
const UART_FR_OFFSET: usize = 0x18;
const UART_FR_TXFF: u32 = 1 << 5;

#[macro_export]
macro_rules! print_el1 {
    ($lit:literal) => {{
        $crate::el1::write_el1_literal(concat!($lit, "\0"));
    }};
    ($label:literal, $value:expr) => {{
        $crate::el1::write_el1_label_hex(concat!($label, "\0"), $value as u64);
    }};
}

#[macro_export]
macro_rules! println_el1 {
    ($lit:literal) => {{
        $crate::el1::write_el1_literal(concat!($lit, "\0"));
        $crate::el1::write_el1_crlf();
    }};
    ($label:literal, $value:expr) => {{
        $crate::el1::write_el1_label_hex(concat!($label, "\0"), $value as u64);
    }};
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn read_tpidr_el1() -> u64 {
    let val: u64;
    // SAFETY: Reads TPIDR_EL1 without side effects.
    unsafe { asm!("mrs {val}, tpidr_el1", val = out(reg) val, options(nostack)) };
    val
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn uart_base() -> Option<usize> {
    let base = read_tpidr_el1() as usize;
    if base == 0 { None } else { Some(base) }
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn uart_wait_tx_ready(base: usize) {
    let fr = (base + UART_FR_OFFSET) as *const u32;
    loop {
        // SAFETY: MMIO read of UART FR register; `base` must be valid MMIO.
        let flags = unsafe { core::ptr::read_volatile(fr) };
        if (flags & UART_FR_TXFF) == 0 {
            break;
        }
    }
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn uart_write_byte(base: usize, byte: u8) {
    uart_wait_tx_ready(base);
    let dr = (base + UART_DR_OFFSET) as *mut u32;
    // SAFETY: MMIO write of UART DR register; `base` must be valid MMIO.
    unsafe { core::ptr::write_volatile(dr, byte as u32) };
}

#[unsafe(link_section = ".text.el1_exceptions")]
pub fn write_el1_literal(cstr_with_nul: &str) {
    let Some(base) = uart_base() else {
        return;
    };
    let bytes = cstr_with_nul.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            break;
        }
        uart_write_byte(base, b);
        i += 1;
    }
}

#[unsafe(link_section = ".text.el1_exceptions")]
pub fn write_el1_crlf() {
    let Some(base) = uart_base() else {
        return;
    };
    uart_write_byte(base, b'\r');
    uart_write_byte(base, b'\n');
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn write_el1_str(ptr: *const u8) {
    let Some(base) = uart_base() else {
        return;
    };
    if ptr.is_null() {
        write_el1_literal("<null>\0");
        return;
    }
    let mut i = 0usize;
    while i < CSTR_LIMIT {
        // SAFETY: `ptr` is expected to be a valid C string pointer to vector table rodata.
        let ch = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if ch == 0 {
            break;
        }
        uart_write_byte(base, ch);
        i += 1;
    }
    if i == CSTR_LIMIT {
        write_el1_literal("...\0");
    }
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn write_el1_hex(value: u64) {
    let Some(base) = uart_base() else {
        return;
    };
    let mut shift = 60u32;
    loop {
        let nybble = ((value >> shift) & 0xF) as u8;
        let ch = if nybble < 10 {
            b'0' + nybble
        } else {
            b'a' + (nybble - 10)
        };
        uart_write_byte(base, ch);
        if shift == 0 {
            break;
        }
        shift -= 4;
    }
}

#[unsafe(link_section = ".text.el1_exceptions")]
pub fn write_el1_label_hex(label_cstr: &str, value: u64) {
    write_el1_literal(label_cstr);
    write_el1_literal(": 0x\0");
    write_el1_hex(value);
    write_el1_crlf();
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn dump_register(label: &str, value: u64) {
    write_el1_label_hex(label, value);
}

#[unsafe(link_section = ".text.el1_exceptions")]
fn dump_gprs(ctx: &El1ExceptionContext) {
    for idx in 0..31usize {
        let mut label = [0u8; 5];
        label[0] = b'x';
        label[1] = b'0' + ((idx / 10) as u8);
        label[2] = b'0' + ((idx % 10) as u8);
        label[3] = 0;
        // SAFETY: label contains only ASCII digits and 'x', so it is valid UTF-8.
        let label_str = unsafe { core::str::from_utf8_unchecked(&label[..3]) };
        write_el1_literal(label_str);
        write_el1_literal(": 0x\0");
        write_el1_hex(ctx.gpr[idx]);
        write_el1_crlf();
    }
}

/// EL1 exception entry point called from the EL1 vector stubs.
///
/// # Safety
/// `ctx` must point to a valid `El1ExceptionContext` frame constructed by the
/// EL1 vector entry code in this module. `name` must be a valid C string
/// describing which vector slot was taken.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.el1_exceptions")]
pub extern "C" fn el1_exception_rust_entry(ctx: &El1ExceptionContext, name: *const u8) -> ! {
    // Mask further interrupts/fiqs while we inspect the fault state.
    unsafe {
        asm!(
            "msr daifset, #0xf",
            options(nomem, nostack, preserves_flags)
        );
    }

    write_el1_literal("[EL1] exception handler: \0");
    write_el1_str(name);
    write_el1_crlf();
    dump_register(" ELR_EL1\0", ctx.elr_el1);
    dump_register(" SPSR_EL1\0", ctx.spsr_el1);
    dump_register(" ESR_EL1\0", ctx.esr_el1);
    dump_register(" FAR_EL1\0", ctx.far_el1);
    dump_register(" SP(orig)\0", ctx.sp);
    dump_gprs(ctx);
    write_el1_literal("[EL1] halting after exception\0");
    write_el1_crlf();

    loop {
        // SAFETY: WFI is used to park the core after printing diagnostics.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
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

    .section .rodata.el1_exceptions
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
