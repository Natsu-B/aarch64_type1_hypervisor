#![no_std]
#![feature(alloc_error_handler)]

pub mod stack_canary;

use core::alloc::Layout;
use core::panic::PanicInfo;

use aarch64_test::exit_success;

pub const DEFAULT_UART_BASE: usize = 0x0900_0000;
pub const DEFAULT_UART_CLOCK_HZ: u32 = 48_000_000;

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_YELLOW: &str = "\x1b[33m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_RED: &str = "\x1b[31m";

pub fn init_default_uart() {
    print::debug_uart::init(DEFAULT_UART_BASE, DEFAULT_UART_CLOCK_HZ as u64, 115200);
}

/// A test case that can be executed by the custom runner.
pub trait Testable {
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        stack_canary::check_or_abort("before test");
        print::println!(
            "{}test{} {} ...",
            COLOR_YELLOW,
            COLOR_RESET,
            core::any::type_name::<T>()
        );
        self();
        stack_canary::check_or_abort("after test");
        print::println!("{}ok{}", COLOR_GREEN, COLOR_RESET);
    }
}

/// Custom test runner for bare-metal `custom_test_frameworks`.
pub fn test_runner(tests: &[&dyn Testable]) {
    print::println!("{}running{} {} tests", COLOR_CYAN, COLOR_RESET, tests.len());
    for t in tests {
        t.run();
    }
}

/// Shared panic handler for bare-metal unit tests.
pub fn panic_handler(info: &PanicInfo) -> ! {
    print::println!("{}PANIC:{} {}", COLOR_RED, COLOR_RESET, info);
    aarch64_test::exit_failure();
}

#[alloc_error_handler]
fn oom(layout: Layout) -> ! {
    print::println!("[oom] {:?}", layout);
    exit_success();
}

/// Define a U-Boot/QEMU runnable no_std unit-test harness in the test binary.
///
/// Requirements:
/// - The caller crate must enable `custom_test_frameworks` when
///   `all(test, target_arch = "aarch64")`.
/// - Set `test_runner(aarch64_unit_test::test_runner)` and
///   `reexport_test_harness_main = "test_main"`.
/// - The link script must export `__stack_top`, `__bss_start`, `__bss_end`.
#[macro_export]
macro_rules! uboot_unit_test_harness {
    ($init:path) => {
        #[cfg(all(test, target_arch = "aarch64"))]
        core::arch::global_asm!(
            r#"
            .section .text._start, "ax"
            .global _start
            _start:
                ldr x0, =__stack_top
                mov sp, x0
                bl __rust_entry
            1:  b 1b
            "#
        );

        #[cfg(all(test, target_arch = "aarch64"))]
        unsafe extern "C" {
            static __bss_start: u8;
            static __bss_end: u8;
        }

        #[cfg(all(test, target_arch = "aarch64"))]
        #[inline(always)]
        fn __clear_bss() {
            // SAFETY: The linker defines __bss_start..__bss_end as a valid writable range.
            unsafe {
                let start = core::ptr::addr_of!(__bss_start) as usize;
                let end = core::ptr::addr_of!(__bss_end) as usize;
                let len = end.saturating_sub(start);
                core::ptr::write_bytes(start as *mut u8, 0, len);
            }
        }

        #[cfg(all(test, target_arch = "aarch64"))]
        #[unsafe(no_mangle)]
        unsafe extern "C" fn __rust_entry() -> ! {
            __clear_bss();

            // Bring up minimal console; caller can override via `$init`.
            ($init)();

            // Initialize stack canary after UART is ready.
            aarch64_unit_test::stack_canary::init();
            aarch64_unit_test::stack_canary::check_or_abort("after canary init");

            // Run generated test harness.
            test_main();

            aarch64_test::exit_success();
        }

        #[cfg(all(test, target_arch = "aarch64"))]
        #[panic_handler]
        fn __panic(info: &core::panic::PanicInfo) -> ! {
            $crate::panic_handler(info)
        }
    };
}
