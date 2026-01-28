#![no_std]
#![no_main]

extern crate alloc;

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use allocator;
use core::arch::asm;
use core::arch::naked_asm;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use cpu::registers::PARange;
use exceptions;
use paging::stage2::Stage2AccessPermission;
use paging::stage2::Stage2PageTypes;
use paging::stage2::Stage2Paging;
use paging::stage2::Stage2PagingSetting;
use print::debug_uart;
use print::println;

const UART_BASE: usize = 0x900_0000;
const UART_CLOCK_HZ: u32 = 48 * 1_000_000;
static HEAP_READY: AtomicBool = AtomicBool::new(false);
const TEST_HEAP_SIZE: usize = 8 * 1024 * 1024;
static mut TEST_HEAP: [u8; TEST_HEAP_SIZE] = [0; TEST_HEAP_SIZE];
static ALLOCATOR: allocator::DefaultAllocator = allocator::DefaultAllocator::new();

unsafe extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __stack_top: u8;
}

fn entry() -> ! {
    debug_uart::init(UART_BASE, UART_CLOCK_HZ as u64, 115200);
    println!("Starting stage2 translation test...");
    match run() {
        Ok(()) => {
            println!("stage2 translation test: PASS");
            exit_success();
        }
        Err(err) => {
            println!("stage2 translation test: FAIL: {}", err);
            exit_failure();
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn _start() -> ! {
    naked_asm!("ldr x0, =__stack_top", "mov sp, x0", "bl rust_entry", "b .",);
}

#[unsafe(no_mangle)]
extern "C" fn rust_entry() -> ! {
    unsafe { clear_bss() };
    exceptions::setup_exception();
    entry()
}

fn run() -> Result<(), &'static str> {
    setup_allocator()?;
    let baseline = Stage2State::snapshot();

    let (settings, ipa_points, expected_pas) = build_stage2_scenario()?;
    Stage2Paging::init_stage2paging(&settings, &ALLOCATOR).map_err(|_| {
        baseline.restore();
        "stage2 init failed"
    })?;
    Stage2Paging::enable_stage2_translation(false);

    for (ipa, expected) in ipa_points.iter().zip(expected_pas.iter()) {
        let translated = match Stage2Paging::ipa_to_pa(*ipa) {
            Ok(pa) => pa,
            Err(_) => {
                baseline.restore();
                return Err("stage2 translation faulted");
            }
        };
        if translated != *expected {
            baseline.restore();
            return Err("stage2 translation mismatch");
        }
    }

    baseline.restore();
    Ok(())
}

fn build_stage2_scenario()
-> Result<([Stage2PagingSetting; 3], [usize; 3], [usize; 3]), &'static str> {
    let limit = parange_limit_bytes().ok_or("unknown parange")?;
    let first_size = 1usize << 30; // 1 GiB block
    let second_size = 2usize << 20; // 2 MiB block
    let third_size = 3 * 0x1000; // 12 KiB page coverage

    let total_ipa = first_size + second_size + third_size;
    if total_ipa > limit {
        return Err("parange too small for stage2 test");
    }

    let first_pa = 0x2000_0000usize;
    let second_pa = 0x4000_0000usize;
    let third_pa = 0x6000_0000usize;
    if (third_pa + third_size) > limit {
        return Err("physical mapping exceeds parange");
    }

    let stage2 = [
        Stage2PagingSetting {
            ipa: 0,
            pa: first_pa,
            size: first_size,
            types: Stage2PageTypes::Normal,
            perm: Stage2AccessPermission::ReadWrite,
        },
        Stage2PagingSetting {
            ipa: first_size,
            pa: second_pa,
            size: second_size,
            types: Stage2PageTypes::Normal,
            perm: Stage2AccessPermission::ReadWrite,
        },
        Stage2PagingSetting {
            ipa: first_size + second_size,
            pa: third_pa,
            size: third_size,
            types: Stage2PageTypes::Normal,
            perm: Stage2AccessPermission::ReadWrite,
        },
    ];

    let ipa_points = [
        0x1234_5000usize,
        first_size + 0x1000,
        first_size + second_size + 0x2000,
    ];
    let expected_pas = [
        first_pa + 0x1234_5000usize,
        second_pa + 0x1000usize,
        third_pa + 0x2000usize,
    ];

    Ok((stage2, ipa_points, expected_pas))
}

fn parange_limit_bytes() -> Option<usize> {
    cpu::get_parange().map(|range| match range {
        PARange::PA32bits4GB => 1usize << 32,
        PARange::PA36bits64GB => 1usize << 36,
        PARange::PA40bits1TB => 1usize << 40,
        PARange::PA42bits4TB => 1usize << 42,
        PARange::PA44bits16TB => 1usize << 44,
        PARange::PA48bits256TB => 1usize << 48,
        PARange::PA52bits4PB => 1usize << 52,
        PARange::PA56bits64PB => 1usize << 56,
    })
}

struct Stage2State {
    vtcr: u64,
    vttbr: u64,
    hcr: u64,
    daif: u64,
}

impl Stage2State {
    fn snapshot() -> Self {
        let vtcr = read_vtcr_el2();
        let vttbr = read_vttbr_el2();
        let hcr = cpu::get_hcr_el2();
        let daif: u64;

        unsafe {
            asm!(
                "mrs {daif}, daif",
                "msr daifset, #0b1111",
                daif = out(reg) daif,
                options(nostack, preserves_flags),
            );
        }

        Self {
            vtcr,
            vttbr,
            hcr,
            daif,
        }
    }

    fn restore(&self) {
        const HCR_VM_BIT: u64 = 1 << 0;
        let mut current_hcr = cpu::get_hcr_el2();
        current_hcr &= !HCR_VM_BIT;
        cpu::set_hcr_el2(current_hcr);
        cpu::set_vtcr_el2(self.vtcr);
        cpu::set_vttbr_el2(self.vttbr);
        cpu::flush_tlb_el2_el1();
        cpu::set_hcr_el2(self.hcr);
        cpu::isb();

        unsafe {
            asm!(
                "msr daif, {daif}",
                daif = in(reg) self.daif,
                options(nostack, preserves_flags),
            );
        }
    }
}

fn read_vtcr_el2() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, vtcr_el2", val = out(reg) val) };
    val
}

fn read_vttbr_el2() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {val}, vttbr_el2", val = out(reg) val) };
    val
}

unsafe fn clear_bss() {
    unsafe {
        let start = &__bss_start as *const u8 as usize;
        let end = &__bss_end as *const u8 as usize;
        if end > start {
            ptr::write_bytes(start as *mut u8, 0, end - start);
        }
    }
}

fn setup_allocator() -> Result<(), &'static str> {
    if HEAP_READY.load(Ordering::SeqCst) {
        return Ok(());
    }
    ALLOCATOR.init();
    let heap_start = ptr::addr_of_mut!(TEST_HEAP) as *mut u8 as usize;
    let heap_size = TEST_HEAP_SIZE;
    ALLOCATOR.add_available_region(heap_start, heap_size)?;
    ALLOCATOR.finalize()?;
    HEAP_READY.store(true, Ordering::SeqCst);
    Ok(())
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info);
    exit_failure()
}
