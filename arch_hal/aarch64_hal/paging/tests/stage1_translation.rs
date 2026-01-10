#![no_std]
#![no_main]

extern crate alloc;

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use alloc::vec::Vec;
use allocator;
use core::arch::asm;
use core::arch::naked_asm;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use cpu::registers::PARange;
use cpu::*;
use exceptions;
use paging::PagingErr;
use paging::stage1::EL2Stage1PageTypes;
use paging::stage1::EL2Stage1Paging;
use paging::stage1::EL2Stage1PagingSetting;
use print::debug_uart;
use print::println;

const UART_BASE: usize = 0x900_0000;
const UART_CLOCK_HZ: u32 = 48 * 1_000_000;

static mut DUMMY: u64 = 0xDEAD_BEEF_CAFE_BABE;
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
    println!("Starting stage1 translation test...");
    match run() {
        Ok(()) => {
            println!("stage1 translation test: PASS");
            exit_success();
        }
        Err(err) => {
            println!("stage1 translation test: FAIL: {}", err);
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
    unsafe { ptr::write_volatile(UART_BASE as *mut u8, b'!') };
    exceptions::setup_exception();
    entry()
}

fn run() -> Result<(), &'static str> {
    setup_allocator()?;
    let baseline = Stage1State::snapshot();

    match expect_zero_sized_rejected() {
        Ok(()) => baseline.restore(),
        Err(err) => {
            baseline.restore();
            return Err(err);
        }
    }

    let mut buffer = alloc::vec![0xA5u8; 4096];
    let buffer_ptr = buffer.as_mut_ptr() as usize;
    let buffer_end = buffer_ptr + buffer.len();

    let stack_addr = current_sp();
    let text_addr = run as usize;
    let entry_addr = entry as usize;
    let dummy_addr = ptr::addr_of!(DUMMY) as usize;
    let vbar_el2: usize;
    unsafe {
        asm!(
            "mrs {vbar}, vbar_el2",
            vbar = out(reg) vbar_el2,
            options(nostack, preserves_flags),
        );
    }
    let vbar_start = vbar_el2;
    let vbar_end = vbar_start + 0x800 - 1;

    let mut tracked = Vec::new();
    tracked.push(buffer_ptr);
    tracked.push(buffer_end - 1);
    tracked.push(stack_addr);
    tracked.push(text_addr);
    tracked.push(entry_addr);
    tracked.push(dummy_addr);
    tracked.push(vbar_start);
    tracked.push(vbar_end);
    tracked.push(UART_BASE);
    tracked.push(UART_BASE + 0x1000);

    let limit = identity_limit(&tracked)?;
    let paging_config = [EL2Stage1PagingSetting {
        va: 0,
        pa: 0,
        size: limit,
        types: EL2Stage1PageTypes::Normal,
    }];

    EL2Stage1Paging::init_stage1paging(&paging_config).map_err(|_| {
        baseline.restore();
        "stage1 init failed"
    })?;

    for &addr in &tracked {
        let translated = translate_stage1_va(addr)?;
        if translated != addr {
            baseline.restore();
            return Err("identity mapping mismatch");
        }
    }

    // spot-check that data written before enabling translation is still visible
    for value in buffer.iter_mut() {
        *value = value.wrapping_add(1);
    }
    if buffer[0] != 0xA6 {
        baseline.restore();
        return Err("buffer content changed unexpectedly");
    }

    baseline.restore();
    Ok(())
}

fn expect_zero_sized_rejected() -> Result<(), &'static str> {
    let zero = [EL2Stage1PagingSetting {
        va: 0,
        pa: 0,
        size: 0,
        types: EL2Stage1PageTypes::Normal,
    }];
    match EL2Stage1Paging::init_stage1paging(&zero) {
        Err(PagingErr::ZeroSizedPage) => Ok(()),
        Err(err) => {
            println!("unexpected paging error {:?}", err);
            Err("unexpected paging error kind")
        }
        Ok(()) => Err("zero-sized region unexpectedly accepted"),
    }
}

fn identity_limit(addresses: &[usize]) -> Result<usize, &'static str> {
    let max_supported = parange_limit_bytes().ok_or("unknown parange")?;
    let mut max_addr = 0usize;
    for &addr in addresses {
        max_addr = max_addr.max(addr);
    }
    if max_addr == 0 {
        return Err("no addresses tracked");
    }
    let limit = align_up(max_addr + (1 << 21), 1 << 21);
    if limit > max_supported {
        return Err("identity mapping would exceed PARange");
    }
    Ok(limit)
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

fn translate_stage1_va(va: usize) -> Result<usize, &'static str> {
    let par_after: u64;
    unsafe {
        asm!(
            "mrs {tmp}, par_el1",
            "at S1E2R, {va}",
            "isb",
            "mrs {par_after}, par_el1",
            "msr par_el1, {tmp}",
            tmp = lateout(reg) _,
            par_after = out(reg) par_after,
            va = in(reg) va,
            options(nostack)
        );
    }
    if (par_after & 1) != 0 {
        return Err("stage1 translation faulted");
    }
    let pa = (par_after & 0x0000_FFFF_FFFF_F000) as usize;
    Ok(pa | (va & 0xFFF))
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

fn current_sp() -> usize {
    let sp: usize;
    unsafe { asm!("mov {}, sp", out(reg) sp) };
    sp
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

struct Stage1State {
    hcr: u64,
    mair: u64,
    tcr: u64,
    ttbr0: u64,
    sctlr: u64,
    daif: u64,
}

impl Stage1State {
    fn snapshot() -> Self {
        let hcr = cpu::get_hcr_el2();
        let mair = get_mair_el2();
        let tcr = get_tcr_el2();
        let ttbr0 = get_ttbr0_el2();
        let sctlr = get_sctlr_el2();
        let daif: u64;

        unsafe {
            asm!(
                "mrs {daif}, daif",
                // Set D, A, I, F mask bits (mask all exceptions).
                "msr daifset, #0b1111",
                daif = out(reg) daif,
                options(nostack, preserves_flags),
            );
        }

        Self {
            hcr,
            mair,
            tcr,
            ttbr0,
            sctlr,
            daif,
        }
    }

    fn restore(&self) {
        // Restore control registers so the environment goes back to the pre-test state.
        cpu::set_tcr_el2(self.tcr);
        cpu::set_mair_el2(self.mair);
        cpu::set_ttbr0_el2(self.ttbr0);
        cpu::set_hcr_el2(self.hcr);
        cpu::set_sctlr_el2(self.sctlr);
        cpu::flush_tlb_el2_el1();
        cpu::isb();

        // Restore original interrupt mask state.
        unsafe {
            asm!(
                "msr daif, {daif}",
                daif = in(reg) self.daif,
                options(nostack, preserves_flags),
            );
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
