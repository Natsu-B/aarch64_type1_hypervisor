#![no_std]
#![no_main]

use arch_hal::debug_uart;
use arch_hal::soc::bcm2711::genet::Bcm2711GenetV5;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::arch::asm;
use core::arch::naked_asm;
use core::panic::PanicInfo;
use core::ptr::null_mut;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use dtb::DtbParser;

const PL011_BASE: usize = 0xFE20_1000;
const UART_CLOCK_HZ: u64 = 48_000_000;
const UART_BAUD: u32 = 115_200;
const DTB_PTR: usize = 0x2000_0000;
const HEAP_SIZE: usize = 1024 * 1024;

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _STACK_TOP: usize;
}

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        let align_mask = layout.align().saturating_sub(1);
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(layout.size()) else {
                return null_mut();
            };
            if next > HEAP_SIZE {
                return null_mut();
            }

            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: `HEAP` is a dedicated static backing store for this allocator.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() };
                    // SAFETY: `aligned` was bounds-checked against `HEAP_SIZE` above.
                    return unsafe { base.add(aligned) };
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    naked_asm!(
        r#"
        msr spsel, #1
        isb
        ldr x9, =_STACK_TOP
        mov sp, x9
    clear_bss:
        ldr x9, =_BSS_START
        ldr x10, =_BSS_END
    clear_bss_loop:
        cmp x9, x10
        beq clear_bss_end
        str xzr, [x9], #8
        b clear_bss_loop
    clear_bss_end:
        bl main
    loop:
        wfe
        b loop
        "#
    )
}

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    debug_uart::init(PL011_BASE, UART_CLOCK_HZ, UART_BAUD);
    debug_uart::write("[selftest] bcm2711-genet: init local loopback mode (skip PHY)\n");

    let dtb = DtbParser::init(DTB_PTR).unwrap();
    let driver = Bcm2711GenetV5::init_from_dtb_loopback_no_phy(&dtb).unwrap();
    driver.local_loopback_selftest().unwrap();

    debug_uart::write("[selftest] bcm2711-genet: PASS\n");
    wait_forever()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    debug_uart::print_force(format_args!("panic: {}\n", info));
    wait_forever()
}

fn wait_forever() -> ! {
    loop {
        // SAFETY: `wfe` is used as a low-power idle wait in this single-core spin loop.
        unsafe {
            asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}
