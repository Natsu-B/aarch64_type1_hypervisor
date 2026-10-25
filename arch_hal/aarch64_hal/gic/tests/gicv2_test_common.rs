//! Bare-metal boot, TLS, and MMIO scaffolding shared by the GICv2 driver tests.
//!
//! Each test includes this file with `#[path]` and provides a crate-root `fn entry() -> !`,
//! which `rust_entry` calls once BSS and TLS are ready.

// Not every test uses every MMIO helper.
#![allow(dead_code)]

use aarch64_test::exit_failure;
use core::arch::naked_asm;
use core::ptr;
use core::ptr::NonNull;
use gic::GicError;
use print::println;

unsafe extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __stack_top: u8;
}

const TLS_BUF_SIZE: usize = 4096;

#[repr(align(64))]
struct TlsBuf([u8; TLS_BUF_SIZE]);

static mut TLS_BUF: TlsBuf = TlsBuf([0; TLS_BUF_SIZE]);

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn _start() -> ! {
    naked_asm!("ldr x0, =__stack_top", "mov sp, x0", "bl rust_entry", "b .",);
}

#[unsafe(no_mangle)]
extern "C" fn rust_entry() -> ! {
    unsafe { clear_bss() };
    let need = tls::template_size();
    if TLS_BUF_SIZE < need {
        println!(
            "tls buffer too small: need {} bytes, have {} bytes",
            need, TLS_BUF_SIZE
        );
        exit_failure();
    }
    // SAFETY: TLS_BUF is a single-core test buffer, 64-byte aligned, and lives
    // for the duration of the test. No other core aliases it.
    let tls_result = unsafe {
        let tls_ptr = core::ptr::addr_of_mut!(TLS_BUF.0).cast::<u8>();
        tls::init_current_cpu(NonNull::new_unchecked(tls_ptr), TLS_BUF_SIZE)
    };
    if let Err(err) = tls_result {
        println!("tls init failed: {:?}", err);
        exit_failure();
    }
    crate::entry()
}

pub fn read_mmio8(base: usize, offset: usize) -> u8 {
    unsafe { ptr::read_volatile((base + offset) as *const u8) }
}

pub fn read_mmio32(base: usize, offset: usize) -> u32 {
    unsafe { ptr::read_volatile((base + offset) as *const u32) }
}

pub fn write_mmio8(base: usize, offset: usize, value: u8) {
    unsafe { ptr::write_volatile((base + offset) as *mut u8, value) }
}

pub fn write_mmio32(base: usize, offset: usize, value: u32) {
    unsafe { ptr::write_volatile((base + offset) as *mut u32, value) }
}

/// Logs a GIC error and returns `label` as the test failure reason.
pub fn map_err(label: &'static str, err: GicError) -> &'static str {
    println!("{}: {:?}", label, err);
    label
}

unsafe fn clear_bss() {
    let (start, end) = unsafe {
        (
            &__bss_start as *const u8 as usize,
            &__bss_end as *const u8 as usize,
        )
    };
    if end > start {
        unsafe {
            ptr::write_bytes(start as *mut u8, 0, end - start);
        }
    }
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info);
    exit_failure();
}
