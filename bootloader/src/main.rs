#![no_std]
#![no_main]
#![feature(sync_unsafe_cell)]

extern crate alloc;
mod handler;
mod systimer;
use crate::systimer::SystemTimer;
use alloc::alloc::alloc;
use alloc::boxed::Box;
use arch_hal::cpu;
use arch_hal::debug_uart;
use arch_hal::exceptions;
use arch_hal::paging::Stage2Paging;
use arch_hal::paging::Stage2PagingSetting;
use arch_hal::pl011;
use arch_hal::pl011::Pl011Uart;
use arch_hal::println;
use core::alloc::Layout;
use core::arch::global_asm;
use core::arch::naked_asm;
use core::cell::SyncUnsafeCell;
use core::ffi::CStr;
use core::ffi::c_char;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ops::ControlFlow;
use core::panic::PanicInfo;
use core::ptr;
use core::ptr::slice_from_raw_parts_mut;
use core::slice;
use core::time::Duration;
use core::usize;
use dtb::DtbGenerator;
use dtb::DtbParser;
use file::AlignedSliceBox;
use typestate::Le;

static LINUX: &[u8] = include_bytes!("../../bin/Image");

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _PROGRAM_START: usize;
    static mut _PROGRAM_END: usize;
    static mut _STACK_TOP: usize;
}

static LINUX_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static DTB_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
pub(crate) static UART_ADDR: SyncUnsafeCell<Option<usize>> = SyncUnsafeCell::new(None);
static PL011_UART_ADDR: usize = 0x10_7D00_1000;

#[repr(C)]
struct LinuxHeader {
    code0: u32,
    code1: u32,
    text_offset: Le<u64>,
    image_size: Le<u64>,
    flags: Le<u64>,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: [u8; 4],
    res5: u32,
}

impl LinuxHeader {
    const MAGIC: [u8; 4] = [b'A', b'R', b'M', 0x64];
}

global_asm!(
    r#"
.global _start
.section ".text.boot"

_start:
    ldr x0, =_STACK_TOP
    mov sp, x0
clear_bss:
    ldr x0, =_BSS_START
    ldr x1, =_BSS_END
clear_bss_loop:
    cmp x0, x1
    beq clear_bss_end
    str xzr, [x0], #8
    b clear_bss_loop
clear_bss_end:
    bl main
loop:
    wfe
    b loop
    "#
);

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    let program_start = unsafe { &raw mut _PROGRAM_START } as *const _ as usize;
    let stack_start = unsafe { &raw mut _STACK_TOP } as *const _ as usize;

    println!("setup exception");
    exceptions::setup_exception();
    handler::setup_handler();

    const DTB_PTR: usize = 0x2000_0000;
    let dtb = DtbParser::init(DTB_PTR).unwrap();
    let mut pl011_addr = None;
    let mut pl011_size = None;
    dtb.find_node(None, Some("arm,pl011"), &mut |addr, size| {
        debug_uart::init(addr);
        pl011_addr = Some(addr);
        pl011_size = Some(size);
        ControlFlow::Break(())
    })
    .unwrap();
    println!("debug uart starting...\r\n");
    assert_eq!(cpu::get_current_el(), 2);

    let mut systimer = SystemTimer::new();
    systimer.init();
    println!("setup allocator");
    allocator::init();
    dtb.find_node(Some("memory"), None, &mut |addr, size| {
        allocator::add_available_region(addr, size).unwrap();
        ControlFlow::Continue(())
    })
    .unwrap();
    dtb.find_memory_reservation_block(&mut |addr, size| {
        allocator::add_reserved_region(addr, size).unwrap();
        ControlFlow::Continue(())
    });
    dtb.find_reserved_memory_node(
        &mut |addr, size| {
            allocator::add_reserved_region(addr, size).unwrap();
            ControlFlow::Continue(())
        },
        &mut |size, align, alloc_range| -> Result<ControlFlow<()>, ()> {
            if allocator::allocate_dynamic_reserved_region(size, align, alloc_range)
                .unwrap()
                .is_some()
            {
                Ok(ControlFlow::Continue(()))
            } else {
                Err(())
            }
        },
    )
    .unwrap();
    allocator::add_reserved_region(program_start, stack_start - program_start).unwrap();
    allocator::add_reserved_region(DTB_PTR, dtb.get_size()).unwrap();
    allocator::finalize().unwrap();
    println!("allocator setup success!!!");

    // setup paging
    println!("start paging...");
    let pl011_addr = pl011_addr.unwrap();
    let pl011_size = pl011_size.unwrap();
    println!("pl011 addr: 0x{:X}, size: 0x{:X}", pl011_addr, pl011_size);
    let parange = match cpu::get_parange().unwrap() {
        cpu::registers::PARange::PA32bits4GB => 32,
        cpu::registers::PARange::PA36bits64GB => 36,
        cpu::registers::PARange::PA40bits1TB => 40,
        cpu::registers::PARange::PA42bits4TB => 42,
        cpu::registers::PARange::PA44bits16TB => 44,
        cpu::registers::PARange::PA48bits256TB => 48,
        cpu::registers::PARange::PA52bits4PB => 52,
        cpu::registers::PARange::PA56bits64PB => 56,
    };
    let paging_data: [Stage2PagingSetting; 2] = [
        Stage2PagingSetting {
            ipa: 0x0000,
            pa: 0x0000,
            size: pl011_addr,
        },
        Stage2PagingSetting {
            ipa: pl011_addr + pl011_size,
            pa: pl011_addr + pl011_size,
            size: (1 << parange) - pl011_addr - pl011_size,
        },
    ];
    Stage2Paging::init_stage2paging(&paging_data).unwrap();
    Stage2Paging::enable_stage2_translation();
    println!("paging success!!!");

    println!("get linux header");
    let linux_header = unsafe { &*(LINUX.as_ptr() as *const LinuxHeader) };
    // check
    if linux_header.magic != LinuxHeader::MAGIC {
        panic!("invalid linux header");
    }
    let image_size = linux_header.image_size.read() as usize;
    let text_offset = linux_header.text_offset.read() as usize;
    let linux = AlignedSliceBox::new_uninit_with_align(image_size, 0x2 * 0x1000 * 0x1000).unwrap();
    let mut linux = unsafe { linux.assume_init() };
    unsafe { &mut linux[..LINUX.len()].copy_from_slice(&LINUX) };
    let jump_addr = linux.as_ptr() as usize + text_offset;
    unsafe { *LINUX_ADDR.get() = jump_addr as usize };
    let mut modified: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(dtb.get_size());
    unsafe {
        core::ptr::copy_nonoverlapping(
            DTB_PTR as *const u8,
            modified.as_mut_ptr() as *mut u8,
            dtb.get_size(),
        )
    };
    let modified = unsafe { modified.assume_init() };
    let dtb_modified = DtbParser::init(modified.as_ptr() as usize).unwrap();
    println!("set up linux data");
    // workaround
    let tmp = Box::new(1);
    drop(tmp);
    let mut reserved_memory = allocator::trim_for_boot(0x1000 * 0x1000 * 128).unwrap();
    println!("allocator closed");
    reserved_memory.push((program_start, stack_start));

    let new_dtb = DtbGenerator::new(&dtb_modified);
    let dtb_size = new_dtb.get_required_size(reserved_memory.len());
    let dtb_data = unsafe {
        &mut *slice_from_raw_parts_mut(
            alloc::alloc::alloc(Layout::from_size_align_unchecked(dtb_size.0, dtb_size.1)),
            dtb_size.0,
        )
    };
    new_dtb
        .make_dtb(dtb_data, reserved_memory.as_ref())
        .unwrap();
    unsafe { *DTB_ADDR.get() = dtb_data.as_ptr() as usize };

    println!("jumping linux...\njump addr: 0x{:X}", jump_addr as usize);

    unsafe {
        core::arch::asm!("isb");
        core::arch::asm!("dsb sy");
    }

    let el1_main = el1_main as *const fn() as usize as u64;
    let stack_addr =
        unsafe { alloc::alloc::alloc(Layout::from_size_align_unchecked(0x1000, 0x1000)) } as usize
            + 0x1000;
    println!(
        "el1_main addr: 0x{:X}\nsp_el1 addr: 0x{:X}",
        el1_main, stack_addr
    );
    const SPSR_EL2_M_EL1H: u64 = 0b0101; // EL1 with SP_EL1(EL1h)
    unsafe {
        core::arch::asm!("msr spsr_el2, {}", in(reg)SPSR_EL2_M_EL1H);
        core::arch::asm!("msr elr_el2, {}", in(reg) el1_main);
        core::arch::asm!("msr sp_el1, {}", in(reg) stack_addr);
        core::arch::asm!("msr sctlr_el2, {}", in(reg) 0);
        cpu::isb();
        core::arch::asm!("eret", options(noreturn));
    }
}

extern "C" fn el1_main() {
    let hello = "hello world from el1_main\n";
    for i in hello.as_bytes() {
        unsafe { ptr::write_volatile(PL011_UART_ADDR as *mut u8, *i) };
    }

    // jump linux
    unsafe {
        core::arch::asm!("msr daifset, #0xf", options(nostack, preserves_flags));

        core::mem::transmute::<usize, extern "C" fn(usize, usize, usize, usize)>(
            *LINUX_ADDR.get() as usize
        )(*DTB_ADDR.get(), 0, 0, 0);
    }
}

fn str_to_usize(s: &str) -> Option<usize> {
    let radix;
    let start;
    match s.get(0..2) {
        Some("0x") => {
            radix = 16;
            start = s.get(2..);
        }
        Some("0o") => {
            radix = 8;
            start = s.get(2..);
        }
        Some("0b") => {
            radix = 2;
            start = s.get(2..);
        }
        _ => {
            radix = 10;
            start = Some(s);
        }
    }
    usize::from_str_radix(start?, radix).ok()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut debug_uart = Pl011Uart::new(PL011_UART_ADDR);
    debug_uart.init(4400_0000, 115200);
    debug_uart.write("core 0 panicked!!!\r\n");
    debug_uart.write_fmt(format_args!("PANIC: {}", info));
    loop {}
}
