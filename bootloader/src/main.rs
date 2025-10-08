#![feature(once_cell_get_mut)]
#![no_std]
#![no_main]
#![recursion_limit = "256"]

extern crate alloc;
mod systimer;
use crate::systimer::SystemTimer;
use alloc::alloc::alloc;
use arch_hal::cpu;
use arch_hal::debug_uart;
use arch_hal::pl011;
use arch_hal::pl011::Pl011Uart;
use arch_hal::println;
use core::alloc::Layout;
use core::arch::naked_asm;
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
static DTB: &[u8] = include_bytes!("../../bin/qemu_mod.dtb");

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _PROGRAM_START: usize;
    static mut _PROGRAM_END: usize;
    static mut _STACK_TOP: usize;
}

static PL011_UART_ADDR: usize = 0x900_0000;

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

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    naked_asm!("ldr x9, =_STACK_TOP\n", "mov sp, x9\n", "b main\n",)
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: usize, argv: *const *const u8) -> ! {
    let program_start = unsafe { &raw mut _PROGRAM_START } as *const _ as usize;
    let stack_start = unsafe { &raw mut _STACK_TOP } as *const _ as usize;

    let args = unsafe { slice::from_raw_parts(argv, argc) };
    let dtb_ptr =
        str_to_usize(unsafe { CStr::from_ptr(args[0] as *const c_char).to_str().unwrap() })
            .unwrap();
    let dtb = DtbParser::init(dtb_ptr).unwrap();
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
    allocator::add_reserved_region(dtb_ptr, dtb.get_size()).unwrap();
    allocator::finalize().unwrap();
    println!("allocator setup success!!!");

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
    let modified = DTB;
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
    unsafe {
        core::arch::asm!(
            "mrs x9, HCR_EL2",
            "bic x9, x9, #(1 << 0)",
            "orr x9, x9, #(1 << 31)",
            "msr HCR_EL2, x9",
            "isb",
            options(nostack, preserves_flags)
        );

        core::arch::asm!(
            "tlbi alle2",
            "dsb sy",
            "isb",
            options(nostack, preserves_flags)
        );

        core::arch::asm!(
            "mrs x9, SCTLR_EL2",
            "bic x9, x9, #(1 << 0)",  // M = 0 (MMU off)
            "bic x9, x9, #(1 << 2)",  // C = 0 (D-cache disable)
            "bic x9, x9, #(1 << 12)", // I = 0 (I-cache disable)
            "msr SCTLR_EL2, x9",
            "dsb sy",
            "isb",
            options(nostack, preserves_flags)
        );
    }

    println!("jumping linux...\njump addr: 0x{:X}", jump_addr as usize);

    // jump linux
    unsafe {
        core::arch::asm!("msr daifset, #0xf", options(nostack, preserves_flags));

        core::mem::transmute::<usize, extern "C" fn(usize, usize, usize, usize)>(
            jump_addr as usize,
        )(dtb_data.as_ptr() as usize, 0, 0, 0);
    }
    unreachable!();
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
