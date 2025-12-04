#![no_std]
#![no_main]

extern crate alloc;

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use allocator;
use core::arch::asm;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use cpu::registers::PARange;
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

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    debug_uart::init(UART_BASE, UART_CLOCK_HZ);
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

fn run() -> Result<(), &'static str> {
    setup_allocator()?;
    let baseline = Stage2State::snapshot();

    let (settings, ipa_points, expected_pas) = build_stage2_scenario()?;
    Stage2Paging::init_stage2paging(&settings, &ALLOCATOR).map_err(|_| {
        baseline.restore();
        "stage2 init failed"
    })?;
    Stage2Paging::enable_stage2_translation();

    for (ipa, expected) in ipa_points.iter().zip(expected_pas.iter()) {
        let translated = translate_stage2(*ipa)?;
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
        },
        Stage2PagingSetting {
            ipa: first_size,
            pa: second_pa,
            size: second_size,
            types: Stage2PageTypes::Normal,
        },
        Stage2PagingSetting {
            ipa: first_size + second_size,
            pa: third_pa,
            size: third_size,
            types: Stage2PageTypes::Normal,
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

fn translate_stage2(ipa: usize) -> Result<usize, &'static str> {
    let par_after: u64;
    unsafe {
        asm!(
            "mrs {tmp}, par_el1",
            "at S12E1R, {ipa}",
            "isb",
            "mrs {par_after}, par_el1",
            "msr par_el1, {tmp}",
            tmp = lateout(reg) _,
            par_after = out(reg) par_after,
            ipa = in(reg) ipa,
            options(nostack)
        );
    }
    if (par_after & 1) != 0 {
        return Err("stage2 translation faulted");
    }
    let pa = (par_after & 0x0000_FFFF_FFFF_F000) as usize;
    Ok(pa | (ipa & 0xFFF))
}

struct Stage2State {
    vtcr: u64,
    vttbr: u64,
    hcr: u64,
}

impl Stage2State {
    fn snapshot() -> Self {
        Self {
            vtcr: read_vtcr_el2(),
            vttbr: read_vttbr_el2(),
            hcr: cpu::get_hcr_el2(),
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
