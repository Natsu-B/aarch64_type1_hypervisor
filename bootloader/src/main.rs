#![feature(once_cell_get_mut)]
#![feature(sync_unsafe_cell)]
#![feature(generic_const_exprs)]
#![no_std]
#![no_main]
#![recursion_limit = "256"]

extern crate alloc;
mod debug;
mod gdb_uart;
mod handler;
mod irq_decode;
mod irq_monitor;
mod monitor;
mod stack_overflow;
mod vbar;
mod vbar_watch;
mod vgic;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use allocator::define_global_allocator;
use arch_hal::cpu;
use arch_hal::debug_uart;
use arch_hal::exceptions;
use arch_hal::gic;
use arch_hal::gic::BinaryPoint;
use arch_hal::gic::EnableOp;
use arch_hal::gic::EoiMode;
use arch_hal::gic::GicCpuConfig;
use arch_hal::gic::GicCpuInterface;
use arch_hal::gic::GicDistributor;
use arch_hal::gic::GicPpi;
use arch_hal::gic::IrqGroup;
use arch_hal::gic::SpiRoute;
use arch_hal::gic::TriggerMode;
use arch_hal::paging::Stage2PageTypes;
use arch_hal::paging::Stage2Paging;
use arch_hal::paging::Stage2PagingSetting;
use arch_hal::paging::stage1::EL2Stage1PageTypes;
use arch_hal::paging::stage1::EL2Stage1Paging;
use arch_hal::paging::stage1::EL2Stage1PagingSetting;
use arch_hal::pl011::Pl011Uart;
use arch_hal::println;
use arch_hal::timer;
use arch_hal::timer::SystemTimer;
use core::alloc::Layout;
use core::arch::naked_asm;
use core::cell::SyncUnsafeCell;
use core::ffi::CStr;
use core::ffi::c_char;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ops::ControlFlow;
use core::panic::PanicInfo;
use core::ptr;
use core::ptr::slice_from_raw_parts;
use core::slice;
use core::usize;
use dtb::DeviceTree;
use dtb::DeviceTreeEditExt;
use dtb::DeviceTreeQueryExt;
use dtb::DtbNodeView;
use dtb::DtbParser;
use dtb::NameRef;
use dtb::NodeEditExt;
use dtb::NodeQueryExt;
use dtb::ValueRef;
use file::AlignedSliceBox;

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _PROGRAM_START: usize;
    static mut _PROGRAM_END: usize;
    static mut _STACK_TOP: usize;
}

pub(crate) const SPSR_EL2_M_EL1H: u64 = 0b0101; // EL1 with SP_EL1(EL1h)
static DTB_ADDR: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
pub(crate) static GUEST_UART: SyncUnsafeCell<Option<UartNode>> = SyncUnsafeCell::new(None);
pub(crate) static GDB_UART: SyncUnsafeCell<Option<UartNode>> = SyncUnsafeCell::new(None);
static DEBUG_UART_ADDR: SyncUnsafeCell<Option<usize>> = SyncUnsafeCell::new(None);

const MAX_MEM_REGIONS: usize = 8;
const PAGE_SIZE: usize = 0x1000;
static MEM_REGION_COUNT: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
static MEM_REGIONS: SyncUnsafeCell<[MemoryRegion; MAX_MEM_REGIONS]> =
    SyncUnsafeCell::new([MemoryRegion { base: 0, size: 0 }; MAX_MEM_REGIONS]);
static GUEST_MMIO_ALLOWLIST: SyncUnsafeCell<Option<Box<[GuestMmioRange]>>> =
    SyncUnsafeCell::new(None);

const PL011_UART_ADDR: usize = 0x900_0000;
const UART_CLOCK_HZ: u64 = 48 * 1_000_000;
const UART_BAUD: u32 = 115_200;
const EL2_TIMER_PPI_PRIORITY: u8 = 0x80; // Priority for the timeout monitor tick.

#[derive(Copy, Clone, Debug)]
pub(crate) struct UartNode {
    base: usize,
    size: usize,
    irq: Option<u32 /* intid */>,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct MemoryRegion {
    base: usize,
    size: usize,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct GuestMmioRange {
    base: usize,
    size: usize,
}

impl GuestMmioRange {
    fn end(&self) -> usize {
        self.base.checked_add(self.size).unwrap_or(usize::MAX)
    }

    fn contains(&self, addr: usize) -> bool {
        addr >= self.base && addr < self.end()
    }
}

#[derive(Copy, Clone, Debug)]
struct Gicv2Info {
    dist: gic::MmioRegion,
    cpu: gic::MmioRegion,
    gich: Option<gic::MmioRegion>,
    gicv: Option<gic::MmioRegion>,
    maintenance_intid: Option<u32>,
}

define_global_allocator!(GLOBAL_ALLOCATOR, 4096);

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    naked_asm!(
        "msr spsel, #1\n",
        "isb\n",
        "ldr x9, =_STACK_TOP\n",
        "mov sp, x9\n",
        "b main\n",
    )
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: usize, argv: *const *const u8) -> ! {
    let program_start = &raw mut _PROGRAM_START as *const _ as usize;
    let stack_start = &raw mut _STACK_TOP as *const _ as usize;

    let args = unsafe { slice::from_raw_parts(argv, argc) };
    let dtb_ptr =
        str_to_usize(unsafe { CStr::from_ptr(args[0] as *const c_char).to_str().unwrap() })
            .unwrap();
    let dtb = DtbParser::init(dtb_ptr).unwrap();
    let mut i = 0;
    dtb.find_nodes_by_compatible_view("arm,pl011", &mut |view, _| {
        match i {
            0 => unsafe {
                let tmp = view.reg_iter().unwrap().next().unwrap().unwrap();
                *GUEST_UART.get() = Some(UartNode {
                    base: tmp.0,
                    size: tmp.1,
                    irq: {
                        let mut tmp = None;
                        view.for_each_interrupt_specifier(&mut |cells| {
                            tmp = Some(
                                irq_decode::dt_irq_to_pintid(cells).expect("uart: bad IRQ spec"),
                            );
                            ControlFlow::Break(())
                        })
                        .unwrap();
                        tmp
                    },
                });
                *DEBUG_UART_ADDR.get() = Some(tmp.0);
            },
            1 => unsafe {
                let tmp = view.reg_iter().unwrap().next().unwrap().unwrap();
                *GDB_UART.get() = Some(UartNode {
                    base: tmp.0,
                    size: tmp.1,
                    irq: {
                        let mut tmp = None;
                        view.for_each_interrupt_specifier(&mut |cells| {
                            tmp = Some(
                                irq_decode::dt_irq_to_pintid(cells).expect("uart: bad IRQ spec"),
                            );
                            ControlFlow::Break(())
                        })
                        .unwrap();
                        tmp
                    },
                });
            },
            _ => return ControlFlow::Break(()),
        }
        i += 1;
        ControlFlow::Continue(())
    })
    .unwrap();
    let guest_uart = unsafe { &*GUEST_UART.get() }.unwrap();
    let gdb_uart = unsafe { &*GDB_UART.get() }.unwrap();
    debug_uart::init(guest_uart.base, UART_CLOCK_HZ, UART_BAUD);
    gdb_uart::init(gdb_uart.base, UART_CLOCK_HZ, UART_BAUD);
    debug::init_gdb_stub();
    println!(
        "debug uart starting (guest console @ 0x{:X})...\r\n",
        guest_uart.base
    );
    let gic_info = find_gicv2_info(&dtb).unwrap();

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
        GLOBAL_ALLOCATOR.add_available_region(addr, size).unwrap();
        record_memory_region(addr, size);
        ControlFlow::Continue(())
    })
    .unwrap();
    dtb.find_memory_reservation_block(&mut |addr, size| {
        GLOBAL_ALLOCATOR.add_reserved_region(addr, size).unwrap();
        ControlFlow::Continue(())
    });
    dtb.find_reserved_memory_node(
        &mut |addr, size| {
            GLOBAL_ALLOCATOR.add_reserved_region(addr, size).unwrap();
            ControlFlow::Continue(())
        },
        &mut |size, align, alloc_range| -> Result<ControlFlow<()>, ()> {
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
    GLOBAL_ALLOCATOR
        .add_reserved_region(program_start, stack_start - program_start)
        .unwrap();
    GLOBAL_ALLOCATOR
        .add_reserved_region(dtb_ptr, dtb.get_size())
        .unwrap();
    GLOBAL_ALLOCATOR.finalize().unwrap();
    println!("allocator setup success!!!");
    record_guest_mmio_allowlist_from_dtb(&dtb, &gdb_uart, &gic_info);
    dump_guest_mmio_allowlist();

    println!("setup EL2 Stage-1 paging with stack guard...");
    let stage1_settings = build_stage1_el2_map();
    EL2Stage1Paging::init_stage1paging(&stage1_settings)
        .expect("EL2 Stage-1 paging initialization failed");
    println!("EL2 Stage-1 paging enabled");

    // SAFETY: emergency stack is initialized after Stage-1 is enabled.
    // The stack is mapped as Normal memory with identity mapping.
    unsafe {
        stack_overflow::init_emergency_stack();
    }
    println!("Emergency stack initialized");

    // setup paging
    println!("start paging...");
    println!(
        "guest uart addr: 0x{:X}, size: 0x{:X}",
        guest_uart.base, guest_uart.size
    );
    println!(
        "gdb uart addr: 0x{:X}, size: 0x{:X}",
        gdb_uart.base, gdb_uart.size
    );
    let (paging_data, guest_window) = build_stage2_guest_map();
    let (guest_ipa_base, guest_ipa_size) = if let Some((ipa_base, ipa_size)) = guest_window {
        debug::set_guest_ipa_window(ipa_base as u64, ipa_size as u64);
        (ipa_base, ipa_size)
    } else {
        debug::set_guest_ipa_window(0, 0);
        (0, 0)
    };
    if guest_ipa_size != 0 {
        let mut rom_ranges = [(0u64, 0u64); 1];
        let mut rom_count = 0usize;
        if let Some(mem_base) = lowest_memory_base() {
            if guest_ipa_base > mem_base {
                rom_ranges[0] = (mem_base as u64, (guest_ipa_base - mem_base) as u64);
                rom_count = 1;
            }
        }

        let mut io_ranges: Vec<(u64, u64)> = Vec::new();
        push_debug_io_range(&mut io_ranges, guest_uart.base, guest_uart.size);
        for range in guest_mmio_allowlist_slice() {
            if range.size == 0 {
                continue;
            }
            push_debug_io_range(&mut io_ranges, range.base, range.size);
        }
        push_debug_io_range(&mut io_ranges, gic_info.dist.base, gic_info.dist.size);
        push_debug_io_range(&mut io_ranges, gic_info.cpu.base, gic_info.cpu.size);
        if let Some(gich) = gic_info.gich {
            push_debug_io_range(&mut io_ranges, gich.base, gich.size);
        }
        if let Some(gicv) = gic_info.gicv {
            push_debug_io_range(&mut io_ranges, gicv.base, gicv.size);
        }

        debug::set_memory_map(
            guest_ipa_base as u64,
            guest_ipa_size as u64,
            &rom_ranges[..rom_count],
            io_ranges.as_slice(),
        );
    } else {
        debug::set_memory_map(0, 0, &[], &[]);
    }
    if paging_data.is_empty() {
        panic!("stage2: no guest RAM to map");
    }
    Stage2Paging::init_stage2paging(&paging_data, &GLOBAL_ALLOCATOR).unwrap();
    Stage2Paging::enable_stage2_translation(true);
    println!("paging success!!!");
    println!("setup exception");
    exceptions::setup_exception();
    handler::setup_handler();
    vbar_watch::init_vbar_watch();
    let (gic, gdb_uart_intid) = init_gicv2_for_gdb(&gic_info, gdb_uart).unwrap();
    gic.configure_ppi(
        timer::SBSA_EL2_PHYSICAL_TIMER_INTID,
        IrqGroup::Group1,
        EL2_TIMER_PPI_PRIORITY,
        TriggerMode::Level,
        EnableOp::Enable,
    )
    .map_err(|_| "gic: configure el2 timer ppi")
    .unwrap();
    irq_monitor::init_physical_timer_poll();
    vgic::init(&gic, &gic_info, guest_uart).unwrap();
    handler::register_gic(gic, Some(gdb_uart_intid));
    {
        let mdcr = cpu::get_mdcr_el2();
        // Trap debug exceptions from lower EL to EL2 (MDCR_EL2.TDE).
        cpu::set_mdcr_el2(mdcr | (1 << 8));
    }
    cpu::enable_irq();
    cpu::enable_debug_exceptions();
    let modified = {
        let mut dtb_bytes = AlignedSliceBox::new_uninit_with_align(dtb.get_size(), 32).unwrap();
        dtb_bytes.copy_from_slice(unsafe {
            &*slice_from_raw_parts(dtb_ptr as *const MaybeUninit<u8>, dtb.get_size())
        });
        unsafe { dtb_bytes.assume_init() }
    };
    let mut dtb_tree = DeviceTree::from_dtb(&modified).unwrap().to_owned();
    apply_guest_dt_edits(
        &mut dtb_tree,
        unsafe { &*GUEST_UART.get() }.unwrap().base,
        &gic_info,
    )
    .unwrap();

    let mut reserved_memory = GLOBAL_ALLOCATOR
        .trim_for_boot(0x1000 * 0x1000 * 128)
        .unwrap();
    println!("allocator closed");
    reserved_memory.push((program_start, stack_start));

    for (addr, size) in &reserved_memory {
        dtb_tree.mem_reserve.push(dtb::MemReserve {
            address: *addr as u64,
            size: *size as u64,
        });
    }
    let dtb_box = dtb_tree.into_dtb_box().unwrap();
    let (dtb_ptr, _dtb_len, _dtb_align) = allocator::AlignedSliceBox::into_raw_parts(dtb_box);
    // SAFETY: the DTB allocation is intentionally leaked so the guest can access it.
    unsafe {
        *DTB_ADDR.get() = dtb_ptr as usize;
    }
    println!("jumping linux...");

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

    // Print HyprProbe ascii art
    println!(
        "\n\n\n\n\n\n\n\n\n _   _                  ____            _          \n| | | |_   _ _ __  _ __|  _ \\ _ __ ___ | |__   ___ \n| |_| | | | | '_ \\| '__| |_) | '__/ _ \\| '_ \\ / _ \\\n|  _  | |_| | |_) | |  |  __/| | | (_) | |_) |  __/\n|_| |_|\\__, | .__/|_|  |_|   |_|  \\___/|_.__/ \\___|\n       |___/|_|        \n\n"
    );

    unsafe {
        core::arch::asm!("msr spsr_el2, {}", in(reg) SPSR_EL2_M_EL1H);
        core::arch::asm!("msr elr_el2, {}", in(reg) el1_main);
        core::arch::asm!("msr sp_el1, {}", in(reg) stack_addr);
        core::arch::asm!("msr sctlr_el2, {0:x}", in(reg) 0);
        cpu::isb();
        core::arch::asm!("eret", options(noreturn));
    }
}

extern "C" fn el1_main() -> ! {
    unsafe {
        core::arch::asm!("mov x1, {}", in(reg) *DTB_ADDR.get());
    }
    loop {
        unsafe { core::arch::asm!("wfi") };
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

fn record_memory_region(base: usize, size: usize) {
    if size == 0 {
        return;
    }
    // SAFETY: early boot records memory regions before secondary cores or interrupts are enabled.
    unsafe {
        let count = &mut *MEM_REGION_COUNT.get();
        if *count >= MAX_MEM_REGIONS {
            return;
        }
        let regions = &mut *MEM_REGIONS.get();
        regions[*count] = MemoryRegion { base, size };
        *count += 1;
    }
}

fn lowest_memory_base() -> Option<usize> {
    let mut min_base: Option<usize> = None;
    // SAFETY: early boot records memory regions before secondary cores or interrupts are enabled.
    unsafe {
        let count = (*MEM_REGION_COUNT.get()).min(MAX_MEM_REGIONS);
        let regions = &*MEM_REGIONS.get();
        for idx in 0..count {
            let region = regions[idx];
            if region.size == 0 {
                continue;
            }
            min_base = Some(match min_base {
                Some(current) => current.min(region.base),
                None => region.base,
            });
        }
    }
    min_base
}

fn guest_mmio_allowlist_slice() -> &'static [GuestMmioRange] {
    // SAFETY: allowlist is populated before the guest is started and then read-only.
    unsafe { (*GUEST_MMIO_ALLOWLIST.get()).as_deref().unwrap_or(&[]) }
}

pub(crate) fn guest_mmio_allowlist_contains(addr: usize) -> bool {
    guest_mmio_allowlist_contains_range(addr, 1)
}

pub(crate) fn guest_mmio_allowlist_contains_range(addr: usize, size: usize) -> bool {
    if size == 0 {
        return false;
    }
    let end = match addr.checked_add(size) {
        Some(end) => end,
        None => return false,
    };
    for range in guest_mmio_allowlist_slice() {
        if range.size == 0 {
            continue;
        }
        if addr >= range.base && end <= range.end() {
            return true;
        }
    }
    false
}

fn normalize_guest_mmio_range(base: usize, size: usize) -> Option<GuestMmioRange> {
    if size == 0 {
        return None;
    }
    let end = base.checked_add(size)?;
    let base_aligned = align_down(base, PAGE_SIZE);
    let end_aligned = align_up(end, PAGE_SIZE);
    if end_aligned <= base_aligned {
        return None;
    }
    Some(GuestMmioRange {
        base: base_aligned,
        size: end_aligned - base_aligned,
    })
}

fn normalize_guest_mmio_allowlist(ranges: &mut Vec<GuestMmioRange>) {
    ranges.retain(|range| range.size != 0);
    ranges.sort_by(|a, b| a.base.cmp(&b.base));

    let mut write = 0usize;
    let total = ranges.len();
    for idx in 0..total {
        let range = ranges[idx];
        if range.size == 0 {
            continue;
        }
        if write == 0 {
            ranges[0] = range;
            write = 1;
            continue;
        }
        let last = &mut ranges[write - 1];
        let last_end = last.end();
        if last_end >= range.base {
            let merged_end = last_end.max(range.end());
            last.size = merged_end.saturating_sub(last.base);
        } else {
            ranges[write] = range;
            write += 1;
        }
    }
    ranges.truncate(write);
}

fn set_guest_mmio_allowlist(ranges: Vec<GuestMmioRange>) {
    // SAFETY: allowlist is populated during single-core boot before interrupts are enabled.
    unsafe {
        let slot = &mut *GUEST_MMIO_ALLOWLIST.get();
        if slot.is_some() {
            println!("warning: guest MMIO allowlist already initialized");
            return;
        }
        *slot = Some(ranges.into_boxed_slice());
    }
}

fn ranges_overlap(a: GuestMmioRange, b: GuestMmioRange) -> bool {
    a.base < b.end() && b.base < a.end()
}

#[derive(Debug)]
struct GuestMmioDenyList {
    gdb_range: Option<GuestMmioRange>,
    deny: Vec<GuestMmioRange>,
}

impl GuestMmioDenyList {
    fn contains_overlap(&self, range: GuestMmioRange) -> bool {
        self.deny
            .iter()
            .copied()
            .any(|deny| ranges_overlap(deny, range))
    }

    fn push_deny(&mut self, base: usize, size: usize) {
        if let Some(range) = normalize_guest_mmio_range(base, size) {
            self.deny.push(range);
        }
    }

    fn finalize(&mut self) {
        normalize_guest_mmio_allowlist(&mut self.deny);
    }
}

#[derive(Default, Debug)]
struct GuestMmioScanStats {
    candidates: usize,
    dropped_reserved: usize,
    dropped_cpu: usize,
    dropped_deny: usize,
    dropped_gdb: usize,
}

fn node_property_eq(node: &DtbNodeView<'_, '_>, key: &str, value: &str) -> bool {
    match node.property_bytes(key) {
        Ok(Some(bytes)) => decode_cstr(bytes).is_some_and(|entry| entry == value),
        _ => false,
    }
}

fn node_is_memory(node: &DtbNodeView<'_, '_>) -> bool {
    if node.name().starts_with("memory") {
        return true;
    }
    node_property_eq(node, "device_type", "memory")
}

fn node_is_disabled(node: &DtbNodeView<'_, '_>) -> bool {
    node_property_eq(node, "status", "disabled")
}

fn node_has_no_map(node: &DtbNodeView<'_, '_>) -> bool {
    matches!(node.property_bytes("no-map"), Ok(Some(_)))
}

fn node_is_cpu(node: &DtbNodeView<'_, '_>) -> bool {
    if node_property_eq(node, "device_type", "cpu") {
        return true;
    }
    node.name().starts_with("cpu@")
}

fn push_guest_mmio_range(
    ranges: &mut Vec<GuestMmioRange>,
    denylist: &GuestMmioDenyList,
    base: usize,
    size: usize,
    stats: &mut GuestMmioScanStats,
) {
    let Some(range) = normalize_guest_mmio_range(base, size) else {
        return;
    };
    if let Some(gdb_range) = denylist.gdb_range {
        if ranges_overlap(range, gdb_range) {
            stats.dropped_gdb += 1;
            return;
        }
    }
    if denylist.contains_overlap(range) {
        stats.dropped_deny += 1;
        return;
    }
    ranges.push(range);
}

fn record_guest_mmio_allowlist_from_dtb(
    dtb: &DtbParser,
    gdb_uart: &UartNode,
    gic_info: &Gicv2Info,
) {
    let mut denylist = GuestMmioDenyList {
        gdb_range: normalize_guest_mmio_range(gdb_uart.base, gdb_uart.size),
        deny: Vec::new(),
    };
    denylist.push_deny(gic_info.dist.base, gic_info.dist.size);
    denylist.push_deny(gic_info.cpu.base, gic_info.cpu.size);
    if let Some(gich) = gic_info.gich {
        denylist.push_deny(gich.base, gich.size);
    }
    // SAFETY: memory regions are recorded during single-core boot before interrupts are enabled.
    unsafe {
        let count = (*MEM_REGION_COUNT.get()).min(MAX_MEM_REGIONS);
        let regions = &*MEM_REGIONS.get();
        for idx in 0..count {
            let region = regions[idx];
            if region.size == 0 {
                continue;
            }
            denylist.push_deny(region.base, region.size);
        }
    }
    let _ = GLOBAL_ALLOCATOR.for_each_reserved_region(|base, size| {
        if size == 0 {
            return;
        }
        denylist.push_deny(base, size);
    });
    denylist.finalize();

    let mut ranges: Vec<GuestMmioRange> = Vec::new();
    let mut stats = GuestMmioScanStats::default();

    fn walk<'dtb, 's>(
        node: DtbNodeView<'dtb, 's>,
        in_reserved: bool,
        in_cpus: bool,
        denylist: &GuestMmioDenyList,
        ranges: &mut Vec<GuestMmioRange>,
        stats: &mut GuestMmioScanStats,
    ) -> Result<ControlFlow<()>, &'static str> {
        let name = node.name();
        let in_reserved = in_reserved || name == "reserved-memory";
        if in_reserved {
            stats.dropped_reserved += 1;
            return Ok(ControlFlow::Continue(()));
        }
        let in_cpus = in_cpus || name == "cpus";
        if in_cpus {
            stats.dropped_cpu += 1;
            return Ok(ControlFlow::Continue(()));
        }
        if node_is_cpu(&node) {
            stats.dropped_cpu += 1;
            return Ok(ControlFlow::Continue(()));
        }

        let skip_collect =
            node_is_memory(&node) || node_is_disabled(&node) || node_has_no_map(&node);
        if !skip_collect {
            if let Ok(mut regs) = node.reg_iter() {
                while let Some(entry) = regs.next() {
                    let (base, size) = match entry {
                        Ok(entry) => entry,
                        Err(_) => break,
                    };
                    if size == 0 {
                        continue;
                    }
                    stats.candidates += 1;
                    push_guest_mmio_range(ranges, denylist, base, size, stats);
                }
            }

            match node.ranges_iter() {
                Ok(Some(mut iter)) => {
                    while let Some(entry) = iter.next() {
                        let entry = match entry {
                            Ok(entry) => entry,
                            Err(_) => break,
                        };
                        if entry.len == 0 {
                            continue;
                        }
                        stats.candidates += 1;
                        push_guest_mmio_range(
                            ranges,
                            denylist,
                            entry.parent_base,
                            entry.len,
                            stats,
                        );
                    }
                }
                Ok(None) | Err(_) => {}
            }
        }

        let mut result: Result<ControlFlow<()>, &'static str> = Ok(ControlFlow::Continue(()));
        let mut should_break = false;
        node.for_each_child_view(&mut |child| match walk(
            child,
            in_reserved,
            in_cpus,
            denylist,
            ranges,
            stats,
        ) {
            Ok(ControlFlow::Continue(())) => ControlFlow::Continue(()),
            Ok(ControlFlow::Break(())) => {
                should_break = true;
                ControlFlow::Break(())
            }
            Err(err) => {
                result = Err(err);
                ControlFlow::Break(())
            }
        })?;
        let _ = result?;
        if should_break {
            return Ok(ControlFlow::Break(()));
        }
        Ok(ControlFlow::Continue(()))
    }

    let result = (|| -> Result<(), &'static str> {
        let root = dtb.root_node_view()?;
        let mut error: Option<&'static str> = None;
        root.for_each_child_view(&mut |child| match walk(
            child,
            false,
            false,
            &denylist,
            &mut ranges,
            &mut stats,
        ) {
            Ok(ControlFlow::Continue(())) => ControlFlow::Continue(()),
            Ok(ControlFlow::Break(())) => ControlFlow::Break(()),
            Err(err) => {
                error = Some(err);
                ControlFlow::Break(())
            }
        })?;
        if let Some(err) = error {
            return Err(err);
        }
        Ok(())
    })();

    if let Err(err) = result {
        println!("warning: guest MMIO allowlist scan failed: {}", err);
    }
    println!(
        "mmio scan: candidates={} dropped reserved-subtree={} dropped cpu-subtree={} dropped deny-overlap={} dropped gdb-overlap={}",
        stats.candidates,
        stats.dropped_reserved,
        stats.dropped_cpu,
        stats.dropped_deny,
        stats.dropped_gdb
    );

    normalize_guest_mmio_allowlist(&mut ranges);
    set_guest_mmio_allowlist(ranges);
}

fn dump_guest_mmio_allowlist() {
    for (idx, range) in guest_mmio_allowlist_slice().iter().enumerate() {
        if range.size == 0 {
            continue;
        }
        println!(
            "guest mmio allowlist[{}]: base=0x{:X} size=0x{:X}",
            idx, range.base, range.size
        );
    }
}

fn push_debug_io_range(io_ranges: &mut Vec<(u64, u64)>, base: usize, size: usize) {
    if size == 0 {
        return;
    }
    let entry = (base as u64, size as u64);
    if io_ranges.iter().any(|&existing| existing == entry) {
        return;
    }
    io_ranges.push(entry);
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
    let mut error = None;
    for compat in COMPATS {
        dtb.find_nodes_by_compatible_view(compat, &mut |view, name| {
            println!("found GICv2 node: {}", compat);
            let mut regs = match view.reg_iter() {
                Ok(it) => it,
                Err(e) => {
                    error = Some(e);
                    return ControlFlow::Break(());
                }
            };
            let Some(Ok((dist_base, _dist_size))) = regs.next() else {
                return ControlFlow::Continue(());
            };
            let Some(Ok((cpu_base, _cpu_size))) = regs.next() else {
                return ControlFlow::Continue(());
            };
            let gich = regs
                .next()
                .and_then(|r| r.ok())
                .map(|(base, _size)| gic::MmioRegion { base, size: 0x1000 });
            let gicv = regs
                .next()
                .and_then(|r| r.ok())
                .map(|(base, _size)| gic::MmioRegion { base, size: 0x2000 });
            let mut maintenance_intid = None;
            if let Err(e) = view.for_each_interrupt_specifier(&mut |cells| {
                if maintenance_intid.is_some() {
                    return ControlFlow::Break(());
                }
                if let Ok(intid) = irq_decode::dt_irq_to_pintid(cells) {
                    maintenance_intid = Some(intid);
                }
                ControlFlow::Break(())
            }) {
                error = Some(e);
                return ControlFlow::Break(());
            }

            found = Some(Gicv2Info {
                dist: gic::MmioRegion {
                    base: dist_base,
                    size: 0x1000,
                },
                cpu: gic::MmioRegion {
                    base: cpu_base,
                    size: 0x2000,
                },
                gich,
                gicv,
                maintenance_intid,
            });
            ControlFlow::Break(())
        })?;
        if found.is_some() {
            break;
        }
    }
    if let Some(err) = error {
        return Err(err);
    }
    found.ok_or("gic: missing GICv2 node")
}

fn init_gicv2_for_gdb(
    info: &Gicv2Info,
    gdb_uart: UartNode,
) -> Result<(gic::gicv2::Gicv2, u32), &'static str> {
    let virt = match (info.gich, info.gicv, info.maintenance_intid) {
        (Some(gich), Some(gicv), Some(maint)) => Some(gic::gicv2::Gicv2VirtualizationRegion {
            gich,
            gicv,
            maintenance_interrupt_id: maint,
        }),
        _ => None,
    };
    println!("gic v2: {:?}", info);
    let gic =
        gic::gicv2::Gicv2::new(info.dist, info.cpu, virt, None).map_err(|_| "gic: init failed")?;
    gic.init_distributor().map_err(|_| "gic: init dist")?;
    let caps = gic.init_cpu_interface().map_err(|_| "gic: init cpu")?;
    let cfg = GicCpuConfig {
        priority_mask: 0xff,
        enable_group0: caps.supports_group0,
        enable_group1: true,
        binary_point: BinaryPoint::Common(caps.binary_points_min),
        eoi_mode: EoiMode::DropAndDeactivate,
    };
    gic.configure(&cfg).map_err(|_| "gic: configure")?;

    let gdb_intid = gdb_uart.irq.ok_or("gic: gdb uart missing IRQ")?;

    gic.configure_spi(
        gdb_intid,
        IrqGroup::Group1,
        0x80,
        TriggerMode::Level,
        SpiRoute::Specific(cpu::get_current_core_id()),
        EnableOp::Enable,
    )
    .map_err(|_| "gic: configure spi")?;

    Ok((gic, gdb_intid))
}

#[derive(Copy, Clone, Debug)]
struct Range {
    start: usize,
    end: usize,
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn align_up(value: usize, align: usize) -> usize {
    value.checked_add(align - 1).unwrap_or(usize::MAX) & !(align - 1)
}

fn sort_stage2_settings(settings: &mut [Stage2PagingSetting], count: usize) {
    for i in 0..count {
        for j in i + 1..count {
            if settings[i].ipa > settings[j].ipa {
                settings.swap(i, j);
            }
        }
    }
}

fn normalize_stage2_settings(settings: &mut [Stage2PagingSetting], count: usize) -> usize {
    let mut write = 0usize;
    for idx in 0..count {
        let cur = settings[idx];
        if cur.size == 0 {
            continue;
        }
        if write == 0 {
            settings[0] = cur;
            write = 1;
            continue;
        }
        let prev = settings[write - 1];
        let prev_end = prev.ipa.saturating_add(prev.size);
        let cur_end = cur.ipa.saturating_add(cur.size);

        if cur.ipa < prev_end {
            if prev.types == cur.types && prev.pa == prev.ipa && cur.pa == cur.ipa {
                let merged_end = prev_end.max(cur_end);
                settings[write - 1].size = merged_end.saturating_sub(prev.ipa);
            } else if cur.types == Stage2PageTypes::Device {
                println!(
                    "warning: stage2 overlap 0x{:X}..0x{:X}, dropping MMIO entry",
                    cur.ipa, cur_end
                );
            } else if prev.types == Stage2PageTypes::Device {
                println!(
                    "warning: stage2 overlap 0x{:X}..0x{:X}, keeping RAM entry",
                    prev.ipa, prev_end
                );
                settings[write - 1] = cur;
            } else {
                println!(
                    "warning: stage2 overlap 0x{:X}..0x{:X}, dropping later entry",
                    cur.ipa, cur_end
                );
            }
            continue;
        }

        if cur.ipa == prev_end
            && prev.types == cur.types
            && prev.pa == prev.ipa
            && cur.pa == cur.ipa
        {
            settings[write - 1].size = cur_end.saturating_sub(prev.ipa);
            continue;
        }

        settings[write] = cur;
        write += 1;
    }
    write
}

fn build_stage1_el2_map() -> Vec<EL2Stage1PagingSetting> {
    unsafe extern "C" {
        static _STACK_BOTTOM: usize;
    }

    let stack_bottom = &raw const _STACK_BOTTOM as usize;
    let guard_page_start = stack_bottom;
    let guard_page_end = stack_bottom + PAGE_SIZE;

    let mut settings = Vec::new();

    // SAFETY: memory regions are recorded during early boot before secondary cores start
    let mem_count = unsafe { *MEM_REGION_COUNT.get() };
    let mem_regions = unsafe { &*MEM_REGIONS.get() };

    for i in 0..mem_count.min(MAX_MEM_REGIONS) {
        let region = mem_regions[i];
        if region.size == 0 {
            continue;
        }

        let start = align_down(region.base, PAGE_SIZE);
        let end = align_up(region.base.saturating_add(region.size), PAGE_SIZE);
        if end <= start {
            continue;
        }

        if guard_page_end <= start || guard_page_start >= end {
            settings.push(EL2Stage1PagingSetting {
                va: start,
                pa: start,
                size: end - start,
                types: EL2Stage1PageTypes::Normal,
            });
        } else {
            if start < guard_page_start {
                settings.push(EL2Stage1PagingSetting {
                    va: start,
                    pa: start,
                    size: guard_page_start - start,
                    types: EL2Stage1PageTypes::Normal,
                });
            }
            if guard_page_end < end {
                settings.push(EL2Stage1PagingSetting {
                    va: guard_page_end,
                    pa: guard_page_end,
                    size: end - guard_page_end,
                    types: EL2Stage1PageTypes::Normal,
                });
            }
        }
    }

    // map other memory regions as mmio
    settings.sort_by(|a, b| a.va.cmp(&b.va));

    if settings[0].va != 0 {
        settings.insert(
            0,
            EL2Stage1PagingSetting {
                va: 0,
                pa: 0,
                size: settings[0].va,
                types: EL2Stage1PageTypes::Device,
            },
        );
    }

    let last = settings.last().unwrap();
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
    settings.push(EL2Stage1PagingSetting {
        va: last.va + last.size,
        pa: last.pa + last.size,
        size: ipa_space - (last.va + last.size),
        types: EL2Stage1PageTypes::Device,
    });

    settings
}

fn build_stage2_guest_map() -> (Vec<Stage2PagingSetting>, Option<(usize, usize)>) {
    const MAX_RESERVED_REGIONS: usize = 32;

    let mut mem_raw = [Range { start: 0, end: 0 }; MAX_MEM_REGIONS];
    let mut mem_count = 0usize;
    // SAFETY: early boot records memory regions before secondary cores or interrupts are enabled.
    unsafe {
        let total = (*MEM_REGION_COUNT.get()).min(MAX_MEM_REGIONS);
        let regions = &*MEM_REGIONS.get();
        for idx in 0..total {
            let region = regions[idx];
            if region.size == 0 {
                continue;
            }
            let start = align_down(region.base, PAGE_SIZE);
            let end = align_up(region.base.saturating_add(region.size), PAGE_SIZE);
            if end <= start {
                continue;
            }
            mem_raw[mem_count] = Range { start, end };
            mem_count += 1;
        }
    }

    for i in 0..mem_count {
        for j in i + 1..mem_count {
            if mem_raw[i].start > mem_raw[j].start {
                mem_raw.swap(i, j);
            }
        }
    }

    let mut mem_ranges = [Range { start: 0, end: 0 }; MAX_MEM_REGIONS];
    let mut mem_ranges_count = 0usize;
    for idx in 0..mem_count {
        let r = mem_raw[idx];
        if mem_ranges_count == 0 {
            mem_ranges[0] = r;
            mem_ranges_count = 1;
            continue;
        }
        let last = &mut mem_ranges[mem_ranges_count - 1];
        if r.start <= last.end {
            last.end = last.end.max(r.end);
        } else {
            mem_ranges[mem_ranges_count] = r;
            mem_ranges_count += 1;
        }
    }

    let mut reserved_raw = [Range { start: 0, end: 0 }; MAX_RESERVED_REGIONS];
    let mut reserved_count = 0usize;
    GLOBAL_ALLOCATOR
        .for_each_reserved_region(|base, size| {
            if size == 0 || reserved_count >= reserved_raw.len() {
                return;
            }
            let start = align_down(base, PAGE_SIZE);
            let end = align_up(base.saturating_add(size), PAGE_SIZE);
            if end <= start {
                return;
            }
            reserved_raw[reserved_count] = Range { start, end };
            reserved_count += 1;
        })
        .unwrap();

    for i in 0..reserved_count {
        for j in i + 1..reserved_count {
            if reserved_raw[i].start > reserved_raw[j].start {
                reserved_raw.swap(i, j);
            }
        }
    }

    let mut reserved = [Range { start: 0, end: 0 }; MAX_RESERVED_REGIONS];
    let mut reserved_merged_count = 0usize;
    for idx in 0..reserved_count {
        let r = reserved_raw[idx];
        if reserved_merged_count == 0 {
            reserved[0] = r;
            reserved_merged_count = 1;
            continue;
        }
        let last = &mut reserved[reserved_merged_count - 1];
        if r.start <= last.end {
            last.end = last.end.max(r.end);
        } else {
            reserved[reserved_merged_count] = r;
            reserved_merged_count += 1;
        }
    }

    let mut best: Option<Range> = None;
    for idx in 0..mem_ranges_count {
        let mem = mem_ranges[idx];
        let mut cursor = mem.start;
        for ridx in 0..reserved_merged_count {
            let r = reserved[ridx];
            if r.end <= cursor {
                continue;
            }
            if r.start >= mem.end {
                break;
            }
            let res_start = r.start.max(mem.start);
            if res_start > cursor {
                let seg = Range {
                    start: cursor,
                    end: res_start.min(mem.end),
                };
                best = match best {
                    Some(current) => {
                        if seg.end - seg.start > current.end - current.start {
                            Some(seg)
                        } else {
                            Some(current)
                        }
                    }
                    None => Some(seg),
                };
            }
            cursor = r.end.max(cursor);
            if cursor >= mem.end {
                break;
            }
        }
        if cursor < mem.end {
            let seg = Range {
                start: cursor,
                end: mem.end,
            };
            best = match best {
                Some(current) => {
                    if seg.end - seg.start > current.end - current.start {
                        Some(seg)
                    } else {
                        Some(current)
                    }
                }
                None => Some(seg),
            };
        }
    }

    let mut settings: Vec<Stage2PagingSetting> = Vec::new();

    if let Some(seg) = best {
        let size = seg.end.saturating_sub(seg.start);
        let guest_window = Range {
            start: seg.start,
            end: seg.start.saturating_add(size),
        };
        let mut warned_overlap = false;
        for range in guest_mmio_allowlist_slice() {
            if range.size == 0 {
                continue;
            }
            if (range.base | range.size) & (PAGE_SIZE - 1) != 0 {
                println!(
                    "warning: stage2 MMIO range unaligned 0x{:X} size 0x{:X}",
                    range.base, range.size
                );
                continue;
            }
            if range.base < guest_window.end && range.end() > guest_window.start {
                if !warned_overlap {
                    println!(
                        "warning: stage2 MMIO overlaps guest RAM, skipping overlapping ranges"
                    );
                    warned_overlap = true;
                }
                continue;
            }
            settings.push(Stage2PagingSetting {
                ipa: range.base,
                pa: range.base,
                size: range.size,
                types: Stage2PageTypes::Device,
            });
        }

        settings.push(Stage2PagingSetting {
            ipa: seg.start,
            pa: seg.start,
            size,
            types: Stage2PageTypes::Normal,
        });

        let mut count = settings.len();
        sort_stage2_settings(settings.as_mut_slice(), count);
        count = normalize_stage2_settings(settings.as_mut_slice(), count);
        settings.truncate(count);

        let mut write = 0usize;
        let total = settings.len();
        for idx in 0..total {
            let setting = settings[idx];
            if (setting.ipa | setting.pa | setting.size) & (PAGE_SIZE - 1) != 0 {
                println!(
                    "warning: stage2 setting unaligned 0x{:X} size 0x{:X}",
                    setting.ipa, setting.size
                );
                continue;
            }
            settings[write] = setting;
            write += 1;
        }
        settings.truncate(write);

        return (settings, Some((seg.start, size)));
    }

    (settings, None)
}

fn apply_guest_uart_dt_edit(
    tree: &mut DeviceTree<'static>,
    guest_uart_base: usize,
) -> Result<(), &'static str> {
    let mut guest_node = None;
    let mut disable_nodes = Vec::new();

    for id in 0..tree.nodes.len() {
        if !node_compatible_contains(tree, id, "arm,pl011")? {
            continue;
        }
        let Some(base) = node_reg_base(tree, id)? else {
            continue;
        };
        if base == guest_uart_base {
            guest_node = Some(id);
        } else {
            disable_nodes.push(id);
        }
    }

    let guest_node = guest_node.ok_or("guest UART node not found in DT")?;
    for id in disable_nodes.iter().copied() {
        if let Some(node) = tree.node_mut(id) {
            node.set_property(
                NameRef::Borrowed("status"),
                ValueRef::Owned(b"disabled\0".to_vec()),
            );
        }
    }

    if let Some(chosen) = tree.find_node_by_path("/chosen") {
        if let Some(path) = node_path(tree, guest_node) {
            let mut value = Vec::with_capacity(path.len() + 1);
            value.extend_from_slice(path.as_bytes());
            value.push(0);
            if let Some(node) = tree.node_mut(chosen) {
                node.set_property(NameRef::Borrowed("stdout-path"), ValueRef::Owned(value));
            }
        }
    }

    if let Some(aliases) = tree.find_node_by_path("/aliases") {
        let mut remove: Vec<String> = Vec::new();
        for id in disable_nodes.iter().copied() {
            if let Some(path) = node_path(tree, id) {
                if let Some(node) = tree.node(aliases) {
                    for prop in &node.properties {
                        if let Some(value) = decode_cstr(prop.value.as_slice()) {
                            if value == path {
                                remove.push(String::from(prop.name.as_str()));
                            }
                        }
                    }
                }
            }
        }
        if let Some(node) = tree.node_mut(aliases) {
            for name in remove {
                node.remove_property(&name);
            }
        }
    }

    Ok(())
}

fn apply_guest_dt_edits(
    tree: &mut DeviceTree<'static>,
    guest_uart_base: usize,
    gic_info: &Gicv2Info,
) -> Result<(), &'static str> {
    apply_guest_bootargs(tree, guest_uart_base)?;
    apply_guest_uart_dt_edit(tree, guest_uart_base)?;
    if let Some(gicv) = gic_info.gicv {
        update_gicv2_cpu_interface_reg(tree, gicv)?;
    }
    Ok(())
}

fn apply_guest_bootargs(
    tree: &mut DeviceTree<'static>,
    guest_uart_base: usize,
) -> Result<(), &'static str> {
    let chosen = tree.get_or_create_node_by_path("/chosen")?;
    let bootargs = alloc::format!(
        "root=/dev/vda2 rw rootwait earlycon=pl011,0x{:08x}",
        guest_uart_base
    );
    let mut value = bootargs.into_bytes();
    value.push(0);
    if let Some(node) = tree.node_mut(chosen) {
        node.set_property(NameRef::Borrowed("bootargs"), ValueRef::Owned(value));
    }
    Ok(())
}

fn update_gicv2_cpu_interface_reg(
    tree: &mut DeviceTree<'static>,
    gicv: gic::MmioRegion,
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
    tree: &DeviceTree<'static>,
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

fn node_reg_base(
    tree: &DeviceTree<'static>,
    node_id: usize,
) -> Result<Option<usize>, &'static str> {
    let Some(node) = tree.node(node_id) else {
        return Ok(None);
    };
    let Some(prop) = node.property("reg") else {
        return Ok(None);
    };
    let parent = node.parent.unwrap_or(tree.root);
    let addr_cells = property_u32(tree, parent, "#address-cells")?.unwrap_or(2);
    let addr_cells = usize::try_from(addr_cells).map_err(|_| "reg: address-cells overflow")?;
    let bytes = prop.value.as_slice();
    if bytes.len() < addr_cells * 4 {
        return Ok(None);
    }
    let mut value: u64 = 0;
    for i in 0..addr_cells {
        let cell = read_be_u32(bytes, i * 4)?;
        value = (value << 32) | cell as u64;
    }
    Ok(Some(value as usize))
}

fn property_u32(
    tree: &DeviceTree<'static>,
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

fn node_path(tree: &DeviceTree<'static>, node_id: usize) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    let mut current = Some(node_id);
    while let Some(id) = current {
        let node = tree.node(id)?;
        let name = node.name.as_str();
        if !name.is_empty() && name != "/" {
            parts.push(name);
        }
        current = node.parent;
    }
    parts.reverse();
    let mut path = String::from("/");
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            path.push('/');
        }
        path.push_str(part);
    }
    Some(path)
}

fn decode_cstr(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // SAFETY: panic path uses a best-effort UART address chosen during early boot.
    let uart_addr = unsafe { *DEBUG_UART_ADDR.get() }.unwrap_or(PL011_UART_ADDR);
    let mut debug_uart = Pl011Uart::new(uart_addr, UART_CLOCK_HZ);
    debug_uart.init(UART_BAUD);
    debug_uart.write("core 0 panicked!!!\r\n");
    let _ = debug_uart.write_fmt(format_args!("PANIC: {}", info));
    loop {}
}
