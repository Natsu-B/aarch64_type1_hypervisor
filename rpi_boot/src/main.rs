#![no_std]
#![no_main]
#![feature(sync_unsafe_cell)]

extern crate alloc;
mod handler;
mod systimer;
use crate::systimer::SystemTimer;
use alloc::alloc::alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use arch_hal::cpu;
use arch_hal::debug_uart;
use arch_hal::exceptions;
use arch_hal::paging::Stage2PageTypes;
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
use core::ptr::write_volatile;
use core::slice;
use core::time::Duration;
use core::usize;
use dtb::DtbGenerator;
use dtb::DtbParser;
use file::AlignedSliceBox;
use typestate::Le;

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _PROGRAM_START: usize;
    static mut _PROGRAM_END: usize;
    static mut _STACK_TOP: usize;
    static mut _LINUX_IMAGE: usize;
}

static LINUX_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static DTB_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static RP1_BASE: usize = 0x1c_0000_0000;
static RP1_GPIO: usize = RP1_BASE + 0xd_0000;
static RP1_PAD: usize = RP1_BASE + 0xf_0000;
static PL011_UART_ADDR: usize = RP1_BASE + 0x3_0000;
// static PL011_UART_ADDR: usize = 0x10_7D00_1000;

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
    let program_start = &raw mut _PROGRAM_START as *const _ as usize;
    let program_end = &raw mut _PROGRAM_END as *const _ as usize;
    let linux_image = &raw mut _LINUX_IMAGE as *const _ as usize;

    debug_uart::init(PL011_UART_ADDR, 48 * 1000 * 1000);
    // debug_uart::init(PL011_UART_ADDR, 44 * 1000 * 1000);
    cpu::isb();
    cpu::dsb_ish();
    debug_uart::write("HelloWorld!!!");
    println!("debug uart starting...\r\n");

    println!("setup exception");
    exceptions::setup_exception();
    handler::setup_handler();

    const DTB_PTR: usize = 0x2000_0000;
    let dtb = DtbParser::init(DTB_PTR).unwrap();
    assert_eq!(cpu::get_current_el(), 2);

    let mut systimer = SystemTimer::new();
    systimer.init();
    println!("setup allocator");
    allocator::init();
    dtb.find_node(Some("memory"), None, &mut |addr, size| {
        println!("available region addr=0x{:X}, size=0x{:X}", addr, size);
        allocator::add_available_region(addr, size).unwrap();
        ControlFlow::Continue(())
    })
    .unwrap();
    dtb.find_memory_reservation_block(&mut |addr, size| {
        println!("reserved (memreserve) addr=0x{:X}, size=0x{:X}", addr, size);
        allocator::add_reserved_region(addr, size).unwrap();
        ControlFlow::Continue(())
    });
    dtb.find_reserved_memory_node(
        &mut |addr, size| {
            println!(
                "reserved (node static) addr=0x{:X}, size=0x{:X}",
                addr, size
            );
            allocator::add_reserved_region(addr, size).unwrap();
            ControlFlow::Continue(())
        },
        &mut |size, align, alloc_range| -> Result<ControlFlow<()>, ()> {
            println!(
                "reserved (node dynamic) size=0x{:X}, align={:?}, range={:?}",
                size, align, alloc_range
            );
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
    println!(
        "reserved program image addr=0x{:X}, size=0x{:X}",
        program_start,
        program_end - program_start
    );
    allocator::add_reserved_region(program_start, program_end - program_start).unwrap();
    println!(
        "reserved dtb addr=0x{:X}, size=0x{:X}",
        DTB_PTR,
        dtb.get_size()
    );
    allocator::add_reserved_region(DTB_PTR, dtb.get_size()).unwrap();
    println!("get linux header");
    let linux_header = unsafe { &*(linux_image as *const LinuxHeader) };
    // check
    if linux_header.magic != LinuxHeader::MAGIC {
        panic!("invalid linux header");
    }
    let image_size = linux_header.image_size.read() as usize;
    let text_offset = linux_header.text_offset.read() as usize;
    let jump_addr = linux_image + text_offset;
    unsafe { *LINUX_ADDR.get() = jump_addr };

    allocator::add_reserved_region(linux_image, image_size).unwrap();
    println!("finalizing allocator...");
    allocator::finalize().unwrap();
    println!("allocator free regions after finalize:");
    allocator::for_each_free_region(|addr, size| {
        println!("  free: addr=0x{:X}, size=0x{:X}", addr, size);
    })
    .unwrap();
    println!("allocator reserved regions after finalize:");
    allocator::for_each_reserved_region(|addr, size| {
        println!("  reserved: addr=0x{:X}, size=0x{:X}", addr, size);
    })
    .unwrap();
    println!("allocator setup success!!!");

    // setup paging
    println!("start paging...");
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
    let ipa_space = 1usize << parange;
    let mut paging_data: Vec<Stage2PagingSetting> = Vec::new();
    dtb.find_node(Some("memory"), None, &mut |addr, size| {
        let memory_last: Option<&Stage2PagingSetting> = paging_data.last();
        let memory_last_addr = if let Some(memory_last) = memory_last {
            memory_last.ipa + memory_last.size
        } else {
            0
        };
        assert!(memory_last_addr <= addr);
        if memory_last_addr < addr {
            paging_data.push(Stage2PagingSetting {
                ipa: memory_last_addr,
                pa: memory_last_addr,
                size: addr - memory_last_addr,
                types: Stage2PageTypes::Device,
            });
        }
        paging_data.push(Stage2PagingSetting {
            ipa: addr,
            pa: addr,
            size,
            types: Stage2PageTypes::Normal,
        });
        ControlFlow::Continue(())
    })
    .unwrap();
    let memory_last = paging_data.last().unwrap();
    let memory_last_addr = memory_last.ipa + memory_last.size;
    paging_data.push(Stage2PagingSetting {
        ipa: memory_last_addr,
        pa: memory_last_addr,
        size: PL011_UART_ADDR - memory_last_addr,
        types: Stage2PageTypes::Device,
    });
    paging_data.push(Stage2PagingSetting {
        ipa: PL011_UART_ADDR + 0x1000,
        pa: PL011_UART_ADDR + 0x1000,
        size: ipa_space - PL011_UART_ADDR - 0x1000,
        types: Stage2PageTypes::Device,
    });
    println!("Stage2Paging: {:#?}", paging_data);
    Stage2Paging::init_stage2paging(&paging_data).unwrap();
    Stage2Paging::enable_stage2_translation();
    println!("paging success!!!");

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

    let mut reserved_memory = allocator::trim_for_boot(0x1000 * 0x1000 * 128).unwrap();
    println!("allocator closed");
    reserved_memory.push((program_start, program_end));

    let new_dtb = DtbGenerator::new(&dtb_modified);
    let dtb_size = new_dtb.get_required_size(reserved_memory.len());
    let dtb_data = unsafe {
        &mut *slice_from_raw_parts_mut(
            alloc::alloc::alloc(Layout::from_size_align_unchecked(dtb_size.0, dtb_size.1)),
            dtb_size.0,
        )
    };
    new_dtb
        .make_dtb(dtb_data, reserved_memory.as_ref(), true)
        .unwrap();
    unsafe { *DTB_ADDR.get() = dtb_data.as_ptr() as usize };

    println!("jumping linux...\njump addr: 0x{:X}", jump_addr as usize);

    // Install an EL1 vector table so that early guest faults are captured.
    exceptions::setup_el1_exception();

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

        core::mem::transmute::<usize, extern "C" fn(usize, usize, usize, usize)>(*LINUX_ADDR.get())(
            *DTB_ADDR.get(),
            0,
            0,
            0,
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut debug_uart = Pl011Uart::new(PL011_UART_ADDR);
    debug_uart.init(4800_0000, 115200);
    debug_uart.write("core 0 panicked!!!\r\n");
    debug_uart.write_fmt(format_args!("PANIC: {}", info));
    loop {}
}
