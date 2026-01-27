use arch_hal::cpu;
use core::arch::global_asm;
use core::ptr;

const PAGE_SIZE: usize = 0x1000;
const VBAR_ALIGN: usize = 0x800;
const SAFETY_MARGIN: usize = PAGE_SIZE;
const DEMO_MESSAGE: &[u8] = b"[HyprProbe] EL1 demo exception\r\n\0";

unsafe extern "C" {
    static __hyprprobe_el1_demo_blob_start: u8;
    static __hyprprobe_el1_demo_blob_end: u8;
}

global_asm!(
    r#"
    .section .text.hyprprobe_el1_demo, "ax"
    .balign 0x800
    .global __hyprprobe_el1_demo_blob_start
__hyprprobe_el1_demo_blob_start:

    .macro DEMO_VECTOR_ENTRY label
        .balign 0x80
\label:
        b __hyprprobe_el1_demo_common_handler
        .rept 31
            nop
        .endr
    .endm

    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_sync_sp0
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_irq_sp0
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_fiq_sp0
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_serror_sp0

    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_sync_spx
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_irq_spx
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_fiq_spx
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_serror_spx

    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_sync_lower_aarch64
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_irq_lower_aarch64
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_fiq_lower_aarch64
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_serror_lower_aarch64

    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_sync_lower_aarch32
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_irq_lower_aarch32
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_fiq_lower_aarch32
    DEMO_VECTOR_ENTRY hyprprobe_el1_demo_serror_lower_aarch32

    .balign 4
__hyprprobe_el1_demo_common_handler:
    mrs x0, tpidr_el1
    mrs x1, tpidr_el0
    cbz x0, 2f
    cbz x1, 2f
1:
    ldrb w2, [x1], #1
    cbz w2, 2f
3:
    ldr w3, [x0, #0x18]
    tst w3, #0x20
    b.ne 3b
    str w2, [x0]
    b 1b
2:
    wfe
    b 2b

    .global __hyprprobe_el1_demo_blob_end
__hyprprobe_el1_demo_blob_end:
"#
);

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

pub fn install_el1_demo_vectors(
    guest_ipa_base: usize,
    guest_ipa_size: usize,
) -> Result<u64, &'static str> {
    if guest_ipa_size < 2 * PAGE_SIZE + SAFETY_MARGIN {
        return Err("guest window too small for demo vectors");
    }
    let guest_end = guest_ipa_base
        .checked_add(guest_ipa_size)
        .ok_or("guest window end overflow")?;
    let reserved_end = guest_end
        .checked_sub(SAFETY_MARGIN)
        .ok_or("guest window too small for safety margin")?;
    let mut vbar_page = reserved_end
        .checked_sub(2 * PAGE_SIZE)
        .ok_or("guest window too small for demo pages")?;
    vbar_page = align_down(vbar_page, PAGE_SIZE);
    if (vbar_page & (VBAR_ALIGN - 1)) != 0 {
        return Err("demo vbar page misaligned");
    }
    if vbar_page < guest_ipa_base {
        return Err("demo pages below guest window");
    }
    let msg_page = vbar_page
        .checked_add(PAGE_SIZE)
        .ok_or("demo msg page overflow")?;
    let msg_end = msg_page
        .checked_add(PAGE_SIZE)
        .ok_or("demo msg page end overflow")?;
    if msg_end > reserved_end {
        return Err("demo pages exceed guest window");
    }

    let uart_base = crate::guest_uart_base().ok_or("guest uart not initialized")?;

    let (blob_start, blob_end) = unsafe {
        // SAFETY: The demo blob symbols are defined by the global_asm block in this module.
        (
            &__hyprprobe_el1_demo_blob_start as *const u8,
            &__hyprprobe_el1_demo_blob_end as *const u8,
        )
    };
    let blob_len = (blob_end as usize)
        .checked_sub(blob_start as usize)
        .ok_or("demo blob bounds invalid")?;
    if blob_len == 0 {
        return Err("demo blob empty");
    }
    if blob_len > PAGE_SIZE {
        return Err("demo blob larger than page");
    }
    if DEMO_MESSAGE.len() > PAGE_SIZE {
        return Err("demo message larger than page");
    }

    let vbar_ptr = vbar_page as *mut u8;
    let msg_ptr = msg_page as *mut u8;

    unsafe {
        // SAFETY: vbar_ptr is within guest RAM mapped in EL2 stage1, and blob_len <= PAGE_SIZE.
        ptr::copy_nonoverlapping(blob_start, vbar_ptr, blob_len);
        if blob_len < PAGE_SIZE {
            ptr::write_bytes(vbar_ptr.add(blob_len), 0, PAGE_SIZE - blob_len);
        }
    }

    unsafe {
        // SAFETY: msg_ptr is within guest RAM mapped in EL2 stage1, and message fits in one page.
        ptr::copy_nonoverlapping(DEMO_MESSAGE.as_ptr(), msg_ptr, DEMO_MESSAGE.len());
        if DEMO_MESSAGE.len() < PAGE_SIZE {
            ptr::write_bytes(
                msg_ptr.add(DEMO_MESSAGE.len()),
                0,
                PAGE_SIZE - DEMO_MESSAGE.len(),
            );
        }
    }

    // SAFETY: The bootloader does not rely on TPIDR_EL{0,1}; they are reserved for the demo.
    cpu::set_tpidr_el1(uart_base as u64);
    cpu::set_tpidr_el0(msg_page as u64);

    // SAFETY: vbar_ptr points to EL2-mapped normal memory for cache maintenance by VA.
    cpu::cache::clean_dcache_range(vbar_ptr as *const u8, PAGE_SIZE);
    cpu::cache::invalidate_icache_range(vbar_ptr as *const u8, PAGE_SIZE);

    // SAFETY: msg_ptr points to EL2-mapped normal memory for cache maintenance by VA.
    cpu::cache::clean_dcache_range(msg_ptr as *const u8, DEMO_MESSAGE.len());

    Ok(vbar_page as u64)
}
