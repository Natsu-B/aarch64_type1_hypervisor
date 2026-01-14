#![no_std]
#![no_main]
#![feature(sync_unsafe_cell)]

extern crate alloc;
mod handler;
mod multicore;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use allocator::define_global_allocator;
use arch_hal::cpu;
use arch_hal::debug_uart;
use arch_hal::exceptions;
use arch_hal::gic::GicCpuConfig;
use arch_hal::gic::GicCpuInterface;
use arch_hal::gic::GicDistributor;
use arch_hal::gic::GicPpi;
use arch_hal::gic::MmioRegion;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::paging::EL2Stage1PageTypes;
use arch_hal::paging::EL2Stage1Paging;
use arch_hal::paging::EL2Stage1PagingSetting;
use arch_hal::paging::Stage2PageTypes;
use arch_hal::paging::Stage2Paging;
use arch_hal::paging::Stage2PagingSetting;
use arch_hal::pl011::Pl011Uart;
use arch_hal::println;
use arch_hal::println_force;
use arch_hal::timer::El2PhysicalTimer;
use arch_hal::timer::SystemTimer;
use core::alloc::Layout;
use core::arch::global_asm;
use core::cell::SyncUnsafeCell;
use core::convert::TryInto;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ops::ControlFlow;
use core::panic::PanicInfo;
use core::ptr;
use core::time::Duration;
use core::usize;
use dtb::DeviceTree;
use dtb::DeviceTreeEditExt;
use dtb::DeviceTreeQueryExt;
use dtb::DtbParser;
use dtb::MemReserve;
use dtb::NameRef;
use dtb::NodeEditExt;
use dtb::NodeId;
use dtb::NodeQueryExt;
use dtb::ValueRef;
use typestate::Le;

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _PROGRAM_START: usize;
    static mut _PROGRAM_END: usize;
    static mut _STACK_TOP: usize;
    static mut _LINUX_IMAGE: usize;
}

pub(crate) const SPSR_EL2_M_EL1H: u64 = 0b0101; // EL1 with SP_EL1(EL1h)
static LINUX_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static DTB_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static GICV2_DRIVER: SyncUnsafeCell<Option<Gicv2>> = SyncUnsafeCell::new(None);
static RP1_BASE: usize = 0x1c_0000_0000;
static RP1_GPIO: usize = RP1_BASE + 0xd_0000;
static RP1_PAD: usize = RP1_BASE + 0xf_0000;
// static PL011_UART_ADDR: (usize, u64) = (RP1_BASE + 0x3_0000, 48 * 1000 * 1000);
static PL011_UART_ADDR: (usize, u64) = (0x10_7D00_1000, 44 * 1000 * 1000);

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

define_global_allocator!(GLOBAL_ALLOCATOR, 4096);

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
    let stack_top = &raw mut _STACK_TOP as *const _ as usize;

    debug_uart::init(PL011_UART_ADDR.0, PL011_UART_ADDR.1, 115200);
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
    println!(
        "system counter frequency: {}Hz",
        systimer.counter_frequency_hz()
    );
    println!("setup allocator");
    GLOBAL_ALLOCATOR.init();
    dtb.find_node(Some("memory"), None, &mut |addr, size| {
        println!("available region addr=0x{:X}, size=0x{:X}", addr, size);
        GLOBAL_ALLOCATOR.add_available_region(addr, size).unwrap();
        ControlFlow::Continue(())
    })
    .unwrap();
    dtb.find_memory_reservation_block(&mut |addr, size| {
        println!("reserved (memreserve) addr=0x{:X}, size=0x{:X}", addr, size);
        GLOBAL_ALLOCATOR.add_reserved_region(addr, size).unwrap();
        ControlFlow::Continue(())
    });
    dtb.find_reserved_memory_node(
        &mut |addr, size| {
            println!(
                "reserved (node static) addr=0x{:X}, size=0x{:X}",
                addr, size
            );
            GLOBAL_ALLOCATOR.add_reserved_region(addr, size).unwrap();
            ControlFlow::Continue(())
        },
        &mut |size, align, alloc_range| -> Result<ControlFlow<()>, ()> {
            println!(
                "reserved (node dynamic) size=0x{:X}, align={:?}, range={:?}",
                size, align, alloc_range
            );
            if GLOBAL_ALLOCATOR
                .allocate_dynamic_reserved_region(size, align, alloc_range)
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
    GLOBAL_ALLOCATOR
        .add_reserved_region(program_start, program_end - program_start)
        .unwrap();
    println!(
        "reserved dtb addr=0x{:X}, size=0x{:X}",
        DTB_PTR,
        dtb.get_size()
    );
    GLOBAL_ALLOCATOR
        .add_reserved_region(DTB_PTR, dtb.get_size())
        .unwrap();
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

    GLOBAL_ALLOCATOR
        .add_reserved_region(linux_image, image_size)
        .unwrap();
    println!("finalizing allocator...");
    GLOBAL_ALLOCATOR.finalize().unwrap();
    println!("allocator free regions after finalize:");
    GLOBAL_ALLOCATOR
        .for_each_free_region(|addr, size| {
            println!("  free: addr=0x{:X}, size=0x{:X}", addr, size);
        })
        .unwrap();
    println!("allocator reserved regions after finalize:");
    GLOBAL_ALLOCATOR
        .for_each_reserved_region(|addr, size| {
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
    let mut stage1_paging_data: Vec<EL2Stage1PagingSetting> = Vec::new();
    dtb.find_node(Some("memory"), None, &mut |addr, size| {
        let memory_last = paging_data.last();
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
            stage1_paging_data.push(EL2Stage1PagingSetting {
                va: memory_last_addr,
                pa: memory_last_addr,
                size: addr - memory_last_addr,
                types: EL2Stage1PageTypes::Device,
            });
        }
        paging_data.push(Stage2PagingSetting {
            ipa: addr,
            pa: addr,
            size,
            types: Stage2PageTypes::Normal,
        });
        stage1_paging_data.push(EL2Stage1PagingSetting {
            va: addr,
            pa: addr,
            size,
            types: EL2Stage1PageTypes::Normal,
        });
        ControlFlow::Continue(())
    })
    .unwrap();
    let memory_last = paging_data.last().unwrap();
    let memory_last_addr = memory_last.ipa + memory_last.size;
    paging_data.push(Stage2PagingSetting {
        ipa: memory_last_addr,
        pa: memory_last_addr,
        size: PL011_UART_ADDR.0 - memory_last_addr,
        types: Stage2PageTypes::Device,
    });
    paging_data.push(Stage2PagingSetting {
        ipa: PL011_UART_ADDR.0 + 0x1000,
        pa: PL011_UART_ADDR.0 + 0x1000,
        size: ipa_space - PL011_UART_ADDR.0 - 0x1000,
        types: Stage2PageTypes::Device,
    });
    stage1_paging_data.push(EL2Stage1PagingSetting {
        va: memory_last_addr,
        pa: memory_last_addr,
        size: ipa_space - memory_last_addr,
        types: EL2Stage1PageTypes::Device,
    });
    println!("Stage2Paging: {:#?}", paging_data);
    println!("EL2Stage1Paging: {:#?}", stage1_paging_data);
    Stage2Paging::init_stage2paging(&paging_data, &GLOBAL_ALLOCATOR).unwrap();
    Stage2Paging::enable_stage2_translation(true);
    EL2Stage1Paging::init_stage1paging(&stage1_paging_data).unwrap();
    println!("paging success!!!");

    // setup gicv2
    println!("setup gicv2...");
    let mut gic_distributor = None;
    let mut gic_cpu_interface = None;
    let mut i = 0;
    dtb.find_node(None, Some("arm,gic-400"), &mut |addr, size| {
        match i {
            0 => {
                gic_distributor = Some(MmioRegion { base: addr, size });
            }
            1 => {
                gic_cpu_interface = Some(MmioRegion { base: addr, size });
            }
            _ => {
                println!(
                    "extra gic-400 node found: addr=0x{:X}, size=0x{:X}",
                    addr, size
                );
            }
        }
        i += 1;
        ControlFlow::Continue(())
    })
    .unwrap();
    let gicv2 = Gicv2::new(
        gic_distributor.expect("gic distributor missing"),
        gic_cpu_interface.expect("gic cpu interface missing"),
        None,
        None,
    )
    .unwrap();
    gicv2.init_distributor().unwrap();
    let caps = gicv2.init_cpu_interface().unwrap();
    println!("GICv2 CPU Interface capabilities: {:?}", caps);
    gicv2
        .configure(&GicCpuConfig {
            priority_mask: 0xff,
            enable_group0: false,
            enable_group1: true,
            binary_point: arch_hal::gic::BinaryPoint::Common(caps.binary_points_min),
            eoi_mode: arch_hal::gic::EoiMode::DropOnly,
        })
        .unwrap();

    dtb.find_nodes_by_compatible_view("arm,pl011", &mut |view, string| {
        if view
            .reg_iter()
            .unwrap()
            .any(|info| info.unwrap().0 == PL011_UART_ADDR.0)
        {
            view.for_each_interrupt_specifier(&mut |int| {
                println!("  pl011 interrupt specifier: {:?}", int);
                ControlFlow::Continue(())
            })
            .unwrap();
        }
        ControlFlow::Continue(())
    })
    .unwrap();

    // setup pl011 interrupts
    gicv2
        .configure_spi(
            120 + 32,
            arch_hal::gic::IrqGroup::Group1,
            0x80,
            arch_hal::gic::TriggerMode::Level,
            arch_hal::gic::SpiRoute::Specific(cpu::get_current_core_id()),
            arch_hal::gic::EnableOp::Enable,
        )
        .unwrap();

    // setup timer
    gicv2
        .configure_ppi(
            0xa + 16,
            arch_hal::gic::IrqGroup::Group1,
            0x80,
            arch_hal::gic::TriggerMode::Level,
            arch_hal::gic::EnableOp::Enable,
        )
        .unwrap();

    debug_uart::enable_rx_interrupts(arch_hal::pl011::FifoLevel::OneEighth, true);

    unsafe {
        core::arch::asm!("msr daifclr, #3", options(nostack, preserves_flags)); // enable irq
    }

    unsafe { GICV2_DRIVER.get().replace(Some(gicv2)) };

    let phy = El2PhysicalTimer::new();
    // phy.set_timeout(Duration::from_secs(1));

    loop {
        systimer.wait(Duration::from_secs(1));
        println!("UARTMIS: 0x{:X}", unsafe {
            ptr::read_volatile((PL011_UART_ADDR.0 + 0x40) as *const u32)
        });
        dump_uart_gic(gic_distributor.unwrap().base, PL011_UART_ADDR.0, 0x79 + 32);
        debug_uart::handle_rx_irq_force(|byte| println_force!("force: {}", byte));
        println!("wait for interrupt...");
    }

    multicore::setup_multicore(stack_top);

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

    let mut reserved_memory = GLOBAL_ALLOCATOR
        .trim_for_boot(0x1000 * 0x1000 * 128)
        .unwrap();
    println!("allocator closed");
    let mut allocator_regions = Vec::new();
    GLOBAL_ALLOCATOR
        .for_each_free_region(|addr, size| allocator_regions.push((addr, size)))
        .unwrap();
    reserved_memory.extend_from_slice(&allocator_regions);
    reserved_memory.push((program_start, program_end - program_start));
    reserved_memory.push((DTB_PTR, dtb.get_size()));

    let mut tree = DeviceTree::from_parser(&dtb_modified).unwrap().into_owned();
    let chosen_id = tree.get_or_create_node_by_path("/chosen").unwrap();
    let initrd_range = remove_initrd(&mut tree, chosen_id);
    remove_initrd_memreserve(&mut tree, initrd_range);
    append_reserved_memory(&mut tree, &reserved_memory);
    configure_uart_console(&mut tree, chosen_id, PL011_UART_ADDR.0).unwrap();

    let dtb_box = tree.into_dtb_box().unwrap();
    unsafe { *DTB_ADDR.get() = dtb_box.as_ptr() as usize };
    cpu::clean_dcache_poc(dtb_box.as_ptr() as usize, dtb_box.len());
    core::mem::forget(dtb_box);

    println!("jumping linux...\njump addr: 0x{:X}", jump_addr as usize);

    // Install an EL1 vector table so that early guest faults are captured.
    exceptions::setup_el1_exception();

    cpu::clean_dcache_poc(LINUX_ADDR.get() as usize, size_of::<usize>());
    cpu::clean_dcache_poc(DTB_ADDR.get() as usize, size_of::<usize>());

    cpu::invalidate_icache_all();

    let el1_main = el1_main as *const fn() as usize as u64;
    let stack_addr =
        unsafe { alloc::alloc::alloc(Layout::from_size_align_unchecked(0x1000, 0x1000)) } as usize
            + 0x1000;
    println!(
        "el1_main addr: 0x{:X}\nsp_el1 addr: 0x{:X}",
        el1_main, stack_addr
    );
    unsafe {
        core::arch::asm!("msr spsr_el2, {}", in(reg) SPSR_EL2_M_EL1H);
        core::arch::asm!("msr elr_el2, {}", in(reg) el1_main);
        core::arch::asm!("msr sp_el1, {}", in(reg) stack_addr);
        cpu::isb();
        core::arch::asm!("eret", options(noreturn));
    }
}

#[inline(always)]
unsafe fn mmio_read32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

fn dump_uart_gic(gicd_base: usize, uart_base: usize, intid: u32) {
    let n = (intid / 32) as usize;
    let bit = (intid % 32) as u32;
    let mask = 1u32 << bit;

    unsafe {
        let u_imsc = mmio_read32(uart_base + 0x38);
        let u_ris = mmio_read32(uart_base + 0x3c);
        let u_mis = mmio_read32(uart_base + 0x40);

        let g_isen = mmio_read32(gicd_base + 0x100 + 4 * n);
        let g_ispe = mmio_read32(gicd_base + 0x200 + 4 * n);

        arch_hal::println!(
            "UART: IMSC=0x{:08X} RIS=0x{:08X} MIS=0x{:08X}",
            u_imsc,
            u_ris,
            u_mis
        );
        arch_hal::println!(
            "GICD: ISENABLER{}=0x{:08X} (en={}) ISPENDR{}=0x{:08X} (pend={})",
            n,
            g_isen,
            (g_isen & mask) != 0,
            n,
            g_ispe,
            (g_ispe & mask) != 0
        );
    }
}

extern "C" fn el1_main() {
    let hello = "hello world from el1_main\n";
    for i in hello.as_bytes() {
        unsafe { ptr::write_volatile(PL011_UART_ADDR.0 as *mut u8, *i) };
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

fn be_bytes_to_u64(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u32::from_be_bytes(bytes.try_into().ok()?) as u64),
        8 => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn remove_initrd(tree: &mut DeviceTree<'_>, chosen: NodeId) -> Option<(u64, u64)> {
    let start = tree
        .node(chosen)
        .and_then(|node| node.property("linux,initrd-start"))
        .and_then(|p| be_bytes_to_u64(p.value.as_slice()));
    let end = tree
        .node(chosen)
        .and_then(|node| node.property("linux,initrd-end"))
        .and_then(|p| be_bytes_to_u64(p.value.as_slice()));

    if let Some(node) = tree.node_mut(chosen) {
        node.remove_property("linux,initrd-start");
        node.remove_property("linux,initrd-end");
    }

    if let (Some(start), Some(end)) = (start, end) {
        if end > start {
            return Some((start, end - start));
        }
    }
    None
}

fn remove_initrd_memreserve(tree: &mut DeviceTree<'_>, initrd: Option<(u64, u64)>) {
    if let Some((addr, size)) = initrd {
        tree.mem_reserve
            .retain(|entry| !(entry.address == addr && entry.size == size));
    }
}

fn append_reserved_memory(tree: &mut DeviceTree<'_>, reserved_memory: &[(usize, usize)]) {
    for &(addr, size) in reserved_memory {
        if size == 0 {
            continue;
        }
        let entry = MemReserve {
            address: addr as u64,
            size: size as u64,
        };
        if tree
            .mem_reserve
            .iter()
            .any(|r| r.address == entry.address && r.size == entry.size)
        {
            continue;
        }
        tree.mem_reserve.push(entry);
    }
}

fn configure_uart_console(
    tree: &mut DeviceTree<'_>,
    chosen: NodeId,
    pl011_uart_addr: usize,
) -> Result<(), &'static str> {
    let alias = pick_uart_alias(tree);
    let stdout_value = format!("{alias}:115200\0").into_bytes();
    let node = tree.node_mut(chosen).ok_or("chosen node missing")?;
    node.set_property(
        NameRef::Borrowed("stdout-path"),
        ValueRef::Owned(stdout_value.clone()),
    );
    node.set_property(
        NameRef::Borrowed("linux,stdout-path"),
        ValueRef::Owned(stdout_value),
    );

    update_bootargs(tree, chosen, pl011_uart_addr)
}

fn pick_uart_alias(tree: &DeviceTree<'_>) -> &'static str {
    if let Some(alias_id) = tree.find_node_by_path("/aliases") {
        if let Some(node) = tree.node(alias_id) {
            if node.property("uart0").is_some() {
                return "uart0";
            }
            if node.property("serial0").is_some() {
                return "serial0";
            }
        }
    }
    "uart0"
}

fn update_bootargs(
    tree: &mut DeviceTree<'_>,
    chosen: NodeId,
    pl011_uart_addr: usize,
) -> Result<(), &'static str> {
    let mut args = String::new();

    if let Some(existing) = tree
        .node(chosen)
        .and_then(|node| node.property("bootargs"))
        .map(|p| p.value.as_slice())
    {
        if let Some(raw) = existing.split(|b| *b == 0).next() {
            if let Ok(text) = core::str::from_utf8(raw) {
                for token in text.split_whitespace() {
                    if token.starts_with("console=") || token.starts_with("earlycon=") {
                        continue;
                    }
                    if !args.is_empty() {
                        args.push(' ');
                    }
                    args.push_str(token);
                }
            }
        }
    }

    let earlycon = format!("earlycon=pl011,0x{pl011_uart_addr:x}");
    let console = "console=ttyAMA0,115200";
    for token in [earlycon.as_str(), console] {
        if !args.is_empty() {
            args.push(' ');
        }
        args.push_str(token);
    }

    let mut bytes = args.into_bytes();
    if !bytes.ends_with(&[0]) {
        bytes.push(0);
    }

    tree.node_mut(chosen)
        .ok_or("chosen node missing")?
        .set_property(NameRef::Borrowed("bootargs"), ValueRef::Owned(bytes));
    Ok(())
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut debug_uart = Pl011Uart::new(PL011_UART_ADDR.0, PL011_UART_ADDR.1);
    debug_uart.init(115200);
    debug_uart.write("core 0 panicked!!!\r\n");
    let _ = debug_uart.write_fmt(format_args!("PANIC: {}", info));
    loop {}
}
