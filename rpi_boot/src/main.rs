#![no_std]
#![no_main]
#![feature(generic_const_exprs)]
#![feature(sync_unsafe_cell)]

extern crate alloc;
mod handler;
mod multicore;
mod pcie;
mod vgic;
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
use arch_hal::gic::dt_irq;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::paging::EL2Stage1PageTypes;
use arch_hal::paging::EL2Stage1Paging;
use arch_hal::paging::EL2Stage1PagingSetting;
use arch_hal::paging::Stage2AccessPermission;
use arch_hal::paging::Stage2PageTypes;
use arch_hal::paging::Stage2Paging;
use arch_hal::paging::Stage2PagingSetting;
use arch_hal::pl011::Pl011Uart;
use arch_hal::println;
use arch_hal::soc::bcm2712;
use arch_hal::timer::SystemTimer;
use arch_hal::tls;
use core::alloc::Layout;
use core::arch::global_asm;
use core::cell::SyncUnsafeCell;
use core::convert::TryInto;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ops::ControlFlow;
use core::panic::PanicInfo;
use core::ptr;
use core::ptr::NonNull;
use core::ptr::slice_from_raw_parts_mut;
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
use dtb::WalkError;
use typestate::Le;
use typestate::ReadWrite;

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _PROGRAM_START: usize;
    static mut _PROGRAM_END: usize;
    static mut _STACK_TOP: usize;
    static mut _LINUX_IMAGE: usize;
    static mut __el2_tls_bsp_start: usize;
    static mut __el2_tls_bsp_end: usize;
}

pub(crate) const SPSR_EL2_M_EL1H: u64 = 0b0101; // EL1 with SP_EL1(EL1h)
static LINUX_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static DTB_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
pub(crate) static GICV2_DRIVER: SyncUnsafeCell<Option<Gicv2>> = SyncUnsafeCell::new(None);
pub(crate) const RP1_BASE: usize = 0x1c_0000_0000;
pub(crate) const PL011_UART_ADDR: (usize, u64) = (RP1_BASE + 0x3_0000, 48 * 1000 * 1000);
// static PL011_UART_ADDR: (usize, u64) = (0x10_7D00_1000, 44 * 1000 * 1000);

#[derive(Copy, Clone, Debug)]
struct Gicv2Info {
    dist: MmioRegion,
    cpu: MmioRegion,
    gich: Option<MmioRegion>,
    gicv: Option<MmioRegion>,
    maintenance_intid: Option<u32>,
}

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
    let tls_bsp_start = &raw mut __el2_tls_bsp_start as *const _ as usize;
    let tls_bsp_end = &raw mut __el2_tls_bsp_end as *const _ as usize;

    // setup tls
    unsafe {
        tls::init_current_cpu(
            NonNull::new_unchecked(tls_bsp_start as *mut u8),
            tls_bsp_end - tls_bsp_start,
        )
        .unwrap()
    };

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
    let gic_info = find_gicv2_info(&dtb).unwrap();
    let uart_irq = vgic::UartIrq {
        pintid: 128 + 25 + 32,
        sense: arch_hal::gic::IrqSense::Edge,
    };

    let mut systimer = SystemTimer::new();
    systimer.init();
    println!(
        "system counter frequency: {}Hz",
        systimer.counter_frequency_hz()
    );
    println!("setup allocator");
    GLOBAL_ALLOCATOR.init();
    let result = dtb.find_node(Some("memory"), None, &mut |addr, size| {
        println!("available region addr=0x{:X}, size=0x{:X}", addr, size);
        GLOBAL_ALLOCATOR
            .add_available_region(addr, size)
            .map_err(|_| WalkError::User(()))?;
        Ok(ControlFlow::Continue(()))
    });
    match result {
        Ok(ControlFlow::Continue(())) | Ok(ControlFlow::Break(())) => {}
        Err(WalkError::Dtb(err)) => panic!("{}", err),
        Err(WalkError::User(())) => panic!("find_node: allocator error"),
    }
    dtb.find_memory_reservation_block(&mut |addr, size| {
        println!("reserved (memreserve) addr=0x{:X}, size=0x{:X}", addr, size);
        GLOBAL_ALLOCATOR.add_reserved_region(addr, size).unwrap();
        ControlFlow::Continue(())
    });
    let result = dtb.find_reserved_memory_node(
        &mut |addr, size| {
            println!(
                "reserved (node static) addr=0x{:X}, size=0x{:X}",
                addr, size
            );
            GLOBAL_ALLOCATOR
                .add_reserved_region(addr, size)
                .map_err(|_| WalkError::User(()))?;
            Ok(ControlFlow::Continue(()))
        },
        &mut |size, align, alloc_range| {
            println!(
                "reserved (node dynamic) size=0x{:X}, align={:?}, range={:?}",
                size, align, alloc_range
            );
            let allocated = GLOBAL_ALLOCATOR
                .allocate_dynamic_reserved_region(size, align, alloc_range)
                .map_err(|_| WalkError::User(()))?;
            if allocated.is_some() {
                Ok(ControlFlow::Continue(()))
            } else {
                Err(WalkError::User(()))
            }
        },
    );
    match result {
        Ok(ControlFlow::Break(())) | Ok(ControlFlow::Continue(())) => {}
        Err(WalkError::Dtb(err)) => panic!("{}", err),
        Err(WalkError::User(())) => panic!("reserved-memory: allocator error"),
    }
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
    let result = dtb.find_node(Some("memory"), None, &mut |addr, size| {
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
                perm: Stage2AccessPermission::ReadWrite,
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
            perm: Stage2AccessPermission::ReadWrite,
        });
        stage1_paging_data.push(EL2Stage1PagingSetting {
            va: addr,
            pa: addr,
            size,
            types: EL2Stage1PageTypes::Normal,
        });
        Ok(ControlFlow::Continue(()))
    });
    match result {
        Ok(ControlFlow::Continue(())) | Ok(ControlFlow::Break(())) => {}
        Err(WalkError::Dtb(err)) => panic!("{}", err),
        Err(WalkError::User(())) => panic!("find_node: paging allocator error"),
    }
    let memory_last = paging_data.last().unwrap();
    let memory_last_addr = memory_last.ipa + memory_last.size;
    paging_data.push(Stage2PagingSetting {
        ipa: memory_last_addr,
        pa: memory_last_addr,
        size: PL011_UART_ADDR.0 - memory_last_addr,
        types: Stage2PageTypes::Device,
        perm: Stage2AccessPermission::ReadWrite,
    });
    paging_data.push(Stage2PagingSetting {
        ipa: PL011_UART_ADDR.0 + 0x1000,
        pa: PL011_UART_ADDR.0 + 0x1000,
        size: ipa_space - PL011_UART_ADDR.0 - 0x1000,
        types: Stage2PageTypes::Device,
        perm: Stage2AccessPermission::ReadWrite,
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
    Stage2Paging::enable_stage2_translation(true, false);
    EL2Stage1Paging::init_stage1paging(&stage1_paging_data).unwrap();
    println!("paging success!!!");

    // setup gicv2 (with virtualization)
    println!("setup gicv2...");
    let virt = match (gic_info.gich, gic_info.gicv, gic_info.maintenance_intid) {
        (Some(gich), Some(gicv), Some(maint)) => {
            Some(arch_hal::gic::gicv2::Gicv2VirtualizationRegion {
                gich,
                gicv,
                maintenance_interrupt_id: maint,
            })
        }
        _ => None,
    }
    .expect("gic: missing virtualization region or maintenance interrupt");
    println!("gic v2: {:?}", gic_info);
    let gicv2 = Gicv2::new(gic_info.dist, gic_info.cpu, Some(virt), None).unwrap();
    gicv2.init_distributor().unwrap();
    let caps = gicv2.init_cpu_interface().unwrap();
    println!("GICv2 CPU Interface capabilities: {:?}", caps);
    gicv2
        .configure(&GicCpuConfig {
            priority_mask: 0xff,
            enable_group0: caps.supports_group0,
            enable_group1: true,
            binary_point: arch_hal::gic::BinaryPoint::Common(caps.binary_points_min),
            eoi_mode: arch_hal::gic::EoiMode::DropAndDeactivate,
        })
        .unwrap();

    // setup pl011 interrupts
    gicv2
        .configure_spi(
            uart_irq.pintid,
            arch_hal::gic::IrqGroup::Group1,
            0x80,
            arch_hal::gic::TriggerMode::Edge,
            arch_hal::gic::SpiRoute::Specific(cpu::get_current_core_id()),
            arch_hal::gic::EnableOp::Enable,
        )
        .unwrap();

    println!("setup vgic...");

    vgic::init(&gicv2, &gic_info, Some(uart_irq)).unwrap();

    println!("vgic setup success!!!");

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

    unsafe { GICV2_DRIVER.get().replace(Some(gicv2)) };

    debug_uart::enable_rx_interrupts(arch_hal::pl011::FifoLevel::OneEighth, true);

    println!("gicv2 setup success!!!");

    unsafe {
        core::arch::asm!("msr daifclr, #3", options(nostack, preserves_flags)); // enable irq
    }

    let result = dtb.find_nodes_by_compatible_view("brcm,bcm2712-pcie", &mut |view, _name| {
        pcie::init_pcie_with_node(view)
    });
    match result {
        Ok(ControlFlow::Continue(())) | Ok(ControlFlow::Break(())) => {}
        Err(WalkError::Dtb(err)) => panic!("{}", err),
        Err(WalkError::User(())) => panic!("pcie: unexpected user error"),
    }

    // check rp1
    let rp1 = bcm2712::init_rp1(&dtb).unwrap();
    println!(
        "RP1: Peripheral addr: 0x{:x} SRAM addr: 0x{:x}",
        rp1.peripheral_addr.unwrap().0,
        rp1.shared_sram_addr.unwrap().0
    );

    debug_assert_eq!(rp1.peripheral_addr.unwrap().0, RP1_BASE as u64);

    let io_config = unsafe {
        &*slice_from_raw_parts_mut(
            (rp1.peripheral_addr.unwrap().0 + 0xd_0000) as *mut ReadWrite<u32>,
            56,
        )
    };
    io_config[29].update_bits(0b1111, 0b100);

    let gpio_config = unsafe {
        &*slice_from_raw_parts_mut(
            (rp1.peripheral_addr.unwrap().0 + 0xf_0000 + 0x04) as *mut ReadWrite<u32>,
            28,
        )
    };
    // input enable
    gpio_config[15].set_bits(0b100_1000);

    // setup rp1 uart0 interrupt
    // SAFETY: RP1 peripheral MMIO is mapped; the table is sized for the index used below.
    let pcie_config = unsafe {
        &*slice_from_raw_parts_mut(
            (rp1.peripheral_addr.unwrap().0 + 0x10_8000 + 0x08) as *mut ReadWrite<u32>,
            64,
        )
    };
    pcie_config[25].set_bits(0b1001);

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
    if let Some(gicv) = gic_info.gicv {
        update_gicv2_cpu_interface_reg(&mut tree, gicv).unwrap();
    } else {
        panic!("gic: missing GICV region for DT update");
    }

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

fn find_gicv2_info(dtb: &DtbParser) -> Result<Gicv2Info, &'static str> {
    const COMPATS: [&str; 13] = [
        "arm,arm1176jzf-devchip-gic",
        "arm,arm11mp-gic",
        "arm,cortex-a15-gic",
        "arm,cortex-a7-gic",
        "arm,cortex-a9-gic",
        "arm,eb11mp-gic",
        "arm,gic-400",
        "arm,pl390",
        "arm,tc11mp-gic",
        "brcm,brahma-b15-gic",
        "nvidia,tegra210-agic",
        "qcom,msm-8660-qgic",
        "qcom,msm-qgic2",
    ];
    let mut found: Option<Gicv2Info> = None;
    for compat in COMPATS {
        let result = dtb.find_nodes_by_compatible_view(compat, &mut |view,
                                                                     _name|
         -> Result<
            ControlFlow<()>,
            WalkError<()>,
        > {
            println!("found GICv2 node: {}", compat);
            let mut regs = view.reg_iter().map_err(WalkError::Dtb)?;
            let Some(Ok((dist_base, _dist_size))) = regs.next() else {
                return Ok(ControlFlow::Continue(()));
            };
            let Some(Ok((cpu_base, _cpu_size))) = regs.next() else {
                return Ok(ControlFlow::Continue(()));
            };
            let gich = regs
                .next()
                .and_then(|r| r.ok())
                .map(|(base, _size)| MmioRegion { base, size: 0x1000 });
            let gicv = regs
                .next()
                .and_then(|r| r.ok())
                .map(|(base, _size)| MmioRegion { base, size: 0x2000 });
            let mut maintenance_intid = None;
            let _ = view.for_each_interrupt_specifier(&mut |cells| -> Result<
                ControlFlow<()>,
                WalkError<()>,
            > {
                if maintenance_intid.is_some() {
                    return Ok(ControlFlow::Break(()));
                }
                let decoded = dt_irq::decode_dt_irq(cells)
                    .map_err(|_| WalkError::Dtb("gic: invalid maintenance interrupt"))?;
                maintenance_intid = Some(decoded.intid);
                Ok(ControlFlow::Break(()))
            })?;

            found = Some(Gicv2Info {
                dist: MmioRegion {
                    base: dist_base,
                    size: 0x1000,
                },
                cpu: MmioRegion {
                    base: cpu_base,
                    size: 0x2000,
                },
                gich,
                gicv,
                maintenance_intid,
            });
            Ok(ControlFlow::Break(()))
        });
        match result {
            Ok(ControlFlow::Continue(())) | Ok(ControlFlow::Break(())) => {}
            Err(WalkError::Dtb(err)) => return Err(err),
            Err(WalkError::User(())) => return Err("gic: unexpected user error"),
        }
        if found.is_some() {
            break;
        }
    }
    found.ok_or("gic: missing GICv2 node")
}

fn update_gicv2_cpu_interface_reg(
    tree: &mut DeviceTree<'_>,
    gicv: MmioRegion,
) -> Result<(), &'static str> {
    const COMPATS: [&str; 2] = ["arm,gic-400", "arm,cortex-a15-gic"];
    let mut gic_node = None;
    for id in 0..tree.nodes.len() {
        for compat in COMPATS {
            if node_compatible_contains(tree, id, compat)? {
                gic_node = Some(id);
                break;
            }
        }
        if gic_node.is_some() {
            break;
        }
    }
    let Some(node_id) = gic_node else {
        return Ok(());
    };

    let parent = tree
        .node(node_id)
        .and_then(|n| n.parent)
        .unwrap_or(tree.root);
    let addr_cells = property_u32(tree, parent, "#address-cells")?.unwrap_or(2) as usize;
    let size_cells = property_u32(tree, parent, "#size-cells")?.unwrap_or(1) as usize;
    let stride = (addr_cells + size_cells) * 4;
    let Some(node) = tree.node(node_id) else {
        return Ok(());
    };
    let Some(reg) = node.property("reg") else {
        return Ok(());
    };
    let mut bytes = reg.value.as_slice().to_vec();
    if bytes.len() < stride * 2 {
        return Err("gic: reg property too short");
    }
    let base_off = stride;
    write_be_u32s(&mut bytes, base_off, addr_cells, gicv.base as u64)?;
    write_be_u32s(
        &mut bytes,
        base_off + addr_cells * 4,
        size_cells,
        gicv.size as u64,
    )?;

    if let Some(node) = tree.node_mut(node_id) {
        node.set_property(NameRef::Borrowed("reg"), ValueRef::Owned(bytes));
    }
    Ok(())
}

fn node_compatible_contains(
    tree: &DeviceTree<'_>,
    node_id: usize,
    needle: &str,
) -> Result<bool, &'static str> {
    let Some(node) = tree.node(node_id) else {
        return Ok(false);
    };
    let Some(prop) = node.property("compatible") else {
        return Ok(false);
    };
    let bytes = prop.value.as_slice();
    let mut start = 0usize;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(bytes.len());
        if let Ok(entry) = core::str::from_utf8(&bytes[start..end]) {
            if entry == needle {
                return Ok(true);
            }
        }
        start = end + 1;
    }
    Ok(false)
}

fn property_u32(
    tree: &DeviceTree<'_>,
    node_id: usize,
    key: &str,
) -> Result<Option<u32>, &'static str> {
    let Some(node) = tree.node(node_id) else {
        return Ok(None);
    };
    let Some(prop) = node.property(key) else {
        return Ok(None);
    };
    let bytes = prop.value.as_slice();
    if bytes.len() != 4 {
        return Ok(None);
    }
    Ok(Some(read_be_u32(bytes, 0)?))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("dtb: read_be_u32 overflow")?;
    let slice = bytes.get(offset..end).ok_or("dtb: read_be_u32 oob")?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn write_be_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    let end = offset.checked_add(4).ok_or("dtb: write_be_u32 overflow")?;
    let slice = bytes.get_mut(offset..end).ok_or("dtb: write_be_u32 oob")?;
    slice.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_be_u32s(
    bytes: &mut [u8],
    offset: usize,
    cells: usize,
    value: u64,
) -> Result<(), &'static str> {
    for i in 0..cells {
        let shift = 32 * (cells - 1 - i);
        let cell = ((value >> shift) & 0xffff_ffff) as u32;
        write_be_u32(bytes, offset + i * 4, cell)?;
    }
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
