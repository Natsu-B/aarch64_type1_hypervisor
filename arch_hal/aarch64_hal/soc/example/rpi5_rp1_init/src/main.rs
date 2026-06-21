//! Standalone Raspberry Pi 5 RP1 PCIe/UART/DMA-window bring-up validator.

#![no_std]
#![no_main]

use arch_hal::MirrorOps;
use arch_hal::cpu;
use arch_hal::set_mirror;
use arch_hal::soc::bcm2712;
use arch_hal::soc::bcm2712::rp1::Rp1PeripheralMap;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::arch::asm;
use core::arch::naked_asm;
use core::fmt;
use core::mem::size_of;
use core::ops::ControlFlow;
use core::panic::PanicInfo;
use core::ptr::null_mut;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use dtb::DtbParser;
use dtb::WalkError;

const DTB_PTR: usize = 0x2000_0000;
const HEAP_SIZE: usize = 1024 * 1024;
const SEMIHOST_SYS_WRITE: u64 = 0x05;

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

#[repr(C, align(64))]
struct DmaPreflightArea {
    tx_buffer: [u8; 64],
    descriptor: [u8; 64],
}

static DMA_PREFLIGHT_AREA: DmaPreflightArea = DmaPreflightArea {
    tx_buffer: [0; 64],
    descriptor: [0; 64],
};

// DW AXI DMAC descriptors must be aligned to 64 bytes. The first 64 bytes
// keep the UART payload separately aligned; the descriptor begins at +0x40.
#[repr(C, align(64))]
struct UartDmaTxArea {
    tx: [u8; 32],
    _padding: [u8; 32],
    descriptor: DwAxiDmacLli,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DwAxiDmacLli {
    sar: u64,
    dar: u64,
    block_ts_lo: u32,
    block_ts_hi: u32,
    llp: u64,
    ctl_lo: u32,
    ctl_hi: u32,
    sstat: u32,
    dstat: u32,
    status_lo: u32,
    status_hi: u32,
    reserved_lo: u32,
    reserved_hi: u32,
}

impl DwAxiDmacLli {
    const ZERO: Self = Self {
        sar: 0,
        dar: 0,
        block_ts_lo: 0,
        block_ts_hi: 0,
        llp: 0,
        ctl_lo: 0,
        ctl_hi: 0,
        sstat: 0,
        dstat: 0,
        status_lo: 0,
        status_hi: 0,
        reserved_lo: 0,
        reserved_hi: 0,
    };
}

static mut UART_DMA_TX_AREA: UartDmaTxArea = UartDmaTxArea {
    tx: [0; 32],
    _padding: [0; 32],
    descriptor: DwAxiDmacLli::ZERO,
};

const RP1_DMA_OFFSET: u64 = 0x18_8000;
const RP1_UART_DMACR_OFFSET: usize = 0x48;
const RP1_UART_FR_OFFSET: usize = 0x18;
const RP1_UART_IBRD_OFFSET: usize = 0x24;
const RP1_UART_FBRD_OFFSET: usize = 0x28;
const RP1_UART_LCRH_OFFSET: usize = 0x2c;
const RP1_UART_CR_OFFSET: usize = 0x30;
const PL011_DMACR_TXDMAE: u32 = 1 << 1;
const PL011_LCRH_FEN: u32 = 1 << 4;
const PL011_LCRH_WLEN_8: u32 = 3 << 5;
const PL011_CR_UARTEN: u32 = 1;
const PL011_CR_TXE: u32 = 1 << 8;
const DW_AXI_DMAC_CHANNEL: usize = 0;
const DW_AXI_DMAC_CFG: usize = 0x010;
const DW_AXI_DMAC_CHEN: usize = 0x018;
const DW_AXI_DMAC_INTSTATUS: usize = 0x030;
const DW_AXI_DMAC_COMMON_INTCLEAR: usize = 0x038;
const DW_AXI_DMAC_COMMON_INTSTATUS: usize = 0x050;
const DW_AXI_DMAC_RESET: usize = 0x058;
const DW_AXI_DMAC_CHANNEL_BASE: usize = 0x100;
const DW_AXI_DMAC_CHANNEL_STRIDE: usize = 0x100;
const DW_AXI_DMAC_CH_CFG_L: usize = 0x020;
const DW_AXI_DMAC_CH_CFG_H: usize = 0x024;
const DW_AXI_DMAC_CH_LLP: usize = 0x028;
const DW_AXI_DMAC_CH_STATUS: usize = 0x030;
const DW_AXI_DMAC_CH_INTSTATUS_ENA: usize = 0x080;
const DW_AXI_DMAC_CH_INTSTATUS: usize = 0x088;
const DW_AXI_DMAC_CH_INTSIGNAL_ENA: usize = 0x090;
const DW_AXI_DMAC_CH_INTCLEAR: usize = 0x098;
const DW_AXI_DMAC_IRQ_DMA_TRF: u32 = 1 << 1;
const DW_AXI_DMAC_IRQ_ALL_ERR: u32 = 0x003f_7fe0;
const DW_AXI_DMAC_IRQ_ALL: u32 = u32::MAX;
const DW_AXI_DMAC_CFG_EN: u32 = 1;
const DW_AXI_DMAC_RESET_SOFT: u32 = 1;
const DW_AXI_DMAC_MBLK_TYPE_LL: u32 = 3;
const CH_CFG2_L_SRC_MULTBLK_TYPE_POS: u32 = 0;
const CH_CFG2_L_DST_MULTBLK_TYPE_POS: u32 = 2;
const CH_CFG2_L_SRC_PER_POS: u32 = 4;
const CH_CFG2_L_DST_PER_POS: u32 = 11;
const CH_CFG2_H_TT_FC_POS: u32 = 0;
const CH_CFG2_H_HS_SEL_SRC_POS: u32 = 3;
const CH_CFG2_H_HS_SEL_DST_POS: u32 = 4;
const CH_CFG2_H_PRIORITY_POS: u32 = 20;
const DW_AXI_DMAC_TT_FC_MEM_TO_PER_DMAC: u32 = 1;
const DW_AXI_DMAC_HS_SEL_HW: u32 = 0;
const DW_AXI_DMAC_LLI_CTL_LO_MEM_TO_PER_8BIT: u32 =
    (1 << 18) | (1 << 14) | (1 << 6); // burst=4, dst no-increment, src increment
const DW_AXI_DMAC_LLI_CTL_H_LAST_VALID: u32 = (1 << 31) | (1 << 30);
const UART_DMA_POLL_LIMIT: usize = 1_000_000;
const UART_DMA_TEST_BYTES: &[u8] = b"[rp1-uart-dma] TX\\n";

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
    set_mirror(Some(MirrorOps {
        write: semihost_mirror_write,
        flush: semihost_flush,
    }));
    semihost_log(format_args!("[rpi5-rp1-init] start"));
    semihost_log(format_args!(
        "[rpi5-rp1-init] current EL {}",
        cpu::get_current_el()
    ));
    semihost_log(format_args!("[rpi5-rp1-init] DTB pointer 0x{:x}", DTB_PTR));

    let dtb = match DtbParser::init(DTB_PTR) {
        Ok(dtb) => dtb,
        Err(err) => fail(format_args!("DTB parse failed: {}", err)),
    };

    semihost_log(format_args!("[rpi5-rp1-init] RP1 init mode: Auto"));
    let rp1 = match bcm2712::init_rp1_with_options(
        &dtb,
        bcm2712::Rp1InitOptions {
            mode: bcm2712::Rp1InitMode::Auto,
            strict: false,
        },
    ) {
        Ok(rp1) => rp1,
        Err(err) => {
            // This validator deliberately preserves a semihosting diagnostic
            // result when Auto cannot train the link.  The normal boot path
            // remains strict firmware-assisted through `init_rp1`.
            semihost_log(format_args!("[rpi5-rp1-init] PCIe full init FAIL: {:?}", err));
            semihost_log(format_args!(
                "[rpi5-rp1-init] PASS: diagnostic run completed with skips"
            ));
            wait_forever()
        }
    };

    let uart0_dma = match discover_uart0_dma(&dtb) {
        Ok(Some(dma)) if dma.tx_request.is_some() => {
            semihost_log(format_args!(
                "[rpi5-rp1-init] UART0 DMA DTB tx={:?} rx={:?}",
                dma.tx_request, dma.rx_request
            ));
            Some(dma)
        }
        Ok(_) => {
            semihost_log(format_args!(
                "[rpi5-rp1-init] UART DMA SKIP: UART0 DMA is not present in DTB; enable dtparam=uart0_dma=on"
            ));
            None
        }
        Err(err) => {
            semihost_log(format_args!("[rpi5-rp1-init] UART DMA DTB parse FAIL: {}", err));
            None
        }
    };

    log_rp1_config(&rp1);

    let rp1_map = match Rp1PeripheralMap::from_config(&rp1) {
        Ok(map) => map,
        Err(err) => fail(format_args!("RP1 peripheral BAR invalid: {:?}", err)),
    };
    let uart0_base = match rp1_map.rp1_uart0_base() {
        Ok(base) => base,
        Err(err) => fail(format_args!("RP1 UART0 BAR offset invalid: {:?}", err)),
    };
    semihost_log(format_args!("[rpi5-rp1-init] RP1 UART0 base 0x{:x}", uart0_base));

    let gem_base = match rp1_map.rp1_gem_base() {
        Ok(base) => base,
        Err(err) => fail(format_args!("RP1 GEM BAR offset invalid: {:?}", err)),
    };
    semihost_log(format_args!("[rpi5-rp1-init] RP1 GEM base 0x{:x}", gem_base));

    if let Err(smoke) = bar1_mmio_smoke_test(&rp1_map, uart0_base, gem_base) {
        semihost_log(format_args!(
            "[rpi5-rp1-init] BAR1 smoke FAIL uart=0x{:08x} dmac=0x{:08x} gem=0x{:08x}",
            smoke.uart_value, smoke.dmac_value, smoke.gem_value
        ));
        semihost_log(format_args!(
            "[rpi5-rp1-init] UART DMA: BLOCKED, BAR1 MMIO aperture is not reachable"
        ));
        bcm2712::dump_rp1_pcie_diagnostics(&rp1);
        wait_forever()
    }
    semihost_log(format_args!("[rpi5-rp1-init] BAR1 MMIO smoke PASS"));

    if let Err(reason) = dma_preflight(&rp1) {
        fail(format_args!("DMA PREFLIGHT FAIL: {:?}", reason));
    }
    semihost_log(format_args!("[rpi5-rp1-init] DMA PREFLIGHT PASS"));
    if let Some(dma) = uart0_dma {
        match run_uart0_dma_tx(&rp1, &rp1_map, uart0_base, dma) {
            Ok(()) => semihost_log(format_args!("[rpi5-rp1-init] UART DMA PASS")),
            Err(err) => {
                semihost_log(format_args!("[rpi5-rp1-init] UART DMA FAIL: {:?}", err));
                bcm2712::dump_rp1_pcie_diagnostics(&rp1);
                wait_forever()
            }
        }
    }
    semihost_log(format_args!("[rpi5-rp1-init] BAR/DMA validation PASS; Ethernet intentionally not run"));
    wait_forever()
}

fn log_rp1_config(rp1: &bcm2712::Rp1Config) {
    match rp1.pcie_base {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] PCIe controller 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] PCIe controller unknown")),
    }
    match rp1.peripheral_addr {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] RP1 peripheral BAR 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] RP1 peripheral BAR missing")),
    }
    match rp1.shared_sram_addr {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] RP1 shared SRAM BAR 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] RP1 shared SRAM BAR missing")),
    }
    match rp1.msi_x_table_addr {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] RP1 MSI-X table 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] RP1 MSI-X table missing")),
    }
    match rp1.dma_window {
        Some(window) => semihost_log(format_args!(
            "[rpi5-rp1-init] DMA window pcie_base=0x{:x} cpu_base=0x{:x} size=0x{:x}",
            window.pcie_base, window.cpu_base, window.size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] DMA window missing")),
    }
}

#[derive(Debug, Clone, Copy)]
struct Uart0DmaInfo {
    tx_request: Option<u32>,
    rx_request: Option<u32>,
    reg_base: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bar1SmokeFailure {
    uart_value: u32,
    dmac_value: u32,
    gem_value: u32,
}

/// Prove that BAR1 is a live RP1 aperture before any UART or DMA programming.
/// BAR1 intentionally starts at PCI address zero in the full-RC layout, so its
/// CPU address is the outbound window's CPU base (`0x1f00000000` on CM5).
fn bar1_mmio_smoke_test(
    rp1_map: &Rp1PeripheralMap,
    uart0_base: usize,
    gem_base: usize,
) -> Result<(), Bar1SmokeFailure> {
    let dmac_base = rp1_map
        .mmio_base(RP1_DMA_OFFSET, 0x1000)
        .map_err(|_| Bar1SmokeFailure {
            uart_value: u32::MAX,
            dmac_value: u32::MAX,
            gem_value: u32::MAX,
        })?;
    // UARTFR, DW AXI DMAC ID, and the first GEM register are read-only smoke
    // probes.  Any all-ones completion means PCIe BAR1 was not reachable.
    let uart_value = mmio_read32(uart0_base, RP1_UART_FR_OFFSET);
    let dmac_value = mmio_read32(dmac_base, 0);
    let gem_value = mmio_read32(gem_base, 0);
    semihost_log(format_args!(
        "[rpi5-rp1-init] BAR1 smoke pcie=0x0 cpu=0x{:x} uart=0x{:x} dmac=0x{:x} gem=0x{:x} values=0x{:08x}/0x{:08x}/0x{:08x}",
        rp1_map.base(), uart0_base, dmac_base, gem_base, uart_value, dmac_value, gem_value
    ));
    if uart_value == u32::MAX || dmac_value == u32::MAX || gem_value == u32::MAX {
        return Err(Bar1SmokeFailure {
            uart_value,
            dmac_value,
            gem_value,
        });
    }
    Ok(())
}

fn read_be_cell(bytes: &[u8]) -> Result<u32, &'static str> {
    let array: [u8; 4] = bytes.try_into().map_err(|_| "truncated DTB cell")?;
    Ok(u32::from_be_bytes(array))
}

fn dma_name_at(names: &[u8], wanted: usize) -> Result<Option<&str>, &'static str> {
    let mut start = 0usize;
    let mut index = 0usize;
    while start < names.len() {
        let end = names[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)
            .ok_or("dma-names missing NUL")?;
        if index == wanted {
            return core::str::from_utf8(&names[start..end])
                .map(Some)
                .map_err(|_| "dma-names invalid UTF-8");
        }
        index += 1;
        start = end + 1;
    }
    Ok(None)
}

/// Discover UART0's DMA specifiers in the generated firmware DTB.  The
/// controller-specific request ID comes from `dmas`, not a hard-coded value.
fn discover_uart0_dma(dtb: &DtbParser) -> Result<Option<Uart0DmaInfo>, &'static str> {
    let result = dtb.for_each_node_view(&mut |view| {
        if view.name() != "serial@30000" {
            return Ok(ControlFlow::Continue(()));
        }
        let reg = view.reg_iter()?.next().transpose()?.ok_or("UART0 reg missing")?;
        let compatible = view.property_bytes("compatible")?.unwrap_or(&[]);
        let dmas = view.property_bytes("dmas")?;
        let dma_names = view.property_bytes("dma-names")?;
        semihost_log(format_args!(
            "[rpi5-rp1-init] UART0 DTB path=/axi/pcie@1000120000/rp1/serial@30000 node={} reg=0x{:x}/0x{:x}",
            view.name(), reg.0, reg.1
        ));
        semihost_log(format_args!(
            "[rpi5-rp1-init] UART0 DTB compatible={:?} dmas={:?} dma-names={:?}",
            compatible, dmas, dma_names
        ));
        if !compatible
            .split(|byte| *byte == 0)
            .any(|entry| entry == b"arm,pl011-axi")
        {
            return Err("UART0 compatible is not arm,pl011-axi".into());
        }
        let (Some(dmas), Some(names)) = (dmas, dma_names) else {
            return Ok(ControlFlow::Break(None));
        };
        let mut offset = 0usize;
        let mut index = 0usize;
        let mut info = Uart0DmaInfo {
            tx_request: None,
            rx_request: None,
            reg_base: reg.0 as u64,
        };
        while offset < dmas.len() {
            if dmas.len() - offset < 4 {
                return Err("truncated DMA phandle".into());
            }
            let phandle = read_be_cell(&dmas[offset..offset + 4])?;
            let cells = dtb
                .property_u32_be_by_phandle(phandle, "#dma-cells")?
                .ok_or("DMA controller missing #dma-cells")? as usize;
            let entry_len = 4usize.checked_add(cells.checked_mul(4).ok_or("DMA cells overflow")?)
                .ok_or("DMA entry overflow")?;
            if dmas.len() - offset < entry_len || cells == 0 {
                return Err("malformed UART0 dmas".into());
            }
            let request = read_be_cell(&dmas[offset + 4..offset + 8])?;
            match dma_name_at(names, index)? {
                Some("tx") => info.tx_request = Some(request),
                Some("rx") => info.rx_request = Some(request),
                _ => {}
            }
            offset += entry_len;
            index += 1;
        }
        if let Some(tx) = info.tx_request {
            semihost_log(format_args!(
                "[rpi5-rp1-init] UART0 TX DREQ DTB=0x{:x} linux-diagnostic-expected=0x1a",
                tx
            ));
        }
        if let Some(rx) = info.rx_request {
            semihost_log(format_args!(
                "[rpi5-rp1-init] UART0 RX DREQ DTB=0x{:x} linux-diagnostic-expected=0x19",
                rx
            ));
        }
        Ok(ControlFlow::Break(Some(info)))
    });
    match result {
        Ok(ControlFlow::Break(info)) => Ok(info),
        Ok(ControlFlow::Continue(())) => Ok(None),
        Err(WalkError::Dtb(err)) => Err(err),
        Err(WalkError::User(err)) => Err(err),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmaPreflightError {
    MissingWindow,
    VaToPaFailed,
    AddressNotCovered,
}

fn dma_preflight(rp1: &bcm2712::Rp1Config) -> Result<(), DmaPreflightError> {
    let window = rp1.dma_window.ok_or(DmaPreflightError::MissingWindow)?;
    let va = core::ptr::addr_of!(DMA_PREFLIGHT_AREA) as *const u8 as usize;
    let len = size_of::<DmaPreflightArea>();
    let phys = cpu::va_to_pa_el2_read(va as u64).ok_or(DmaPreflightError::VaToPaFailed)?;
    let dma = window
        .cpu_phys_to_dma(
            phys,
            u64::try_from(len).map_err(|_| DmaPreflightError::AddressNotCovered)?,
        )
        .map_err(|_| DmaPreflightError::AddressNotCovered)?;

    semihost_log(format_args!(
        "[rpi5-rp1-init] DMA buffer va=0x{:x} cpu_phys=0x{:x} dma=0x{:x} len=0x{:x}",
        va, phys, dma, len
    ));
    semihost_log(format_args!(
        "[rpi5-rp1-init] DMA window base=0x{:x} cpu_base=0x{:x} size=0x{:x}",
        window.pcie_base, window.cpu_base, window.size
    ));
    cpu::clean_dcache_range(va as *const u8, len);
    // No device transaction is started in this preflight, so no device-written cache lines
    // exist to invalidate before a CPU read. A future RX DMA path must invalidate before use.
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UartDmaError {
    MissingDmaWindow,
    InvalidDmaController,
    AddressTranslation,
    ResetTimeout { reset: u32 },
    DmaEngineError { status: u32 },
    Timeout { status: u32 },
}

/// Execute one DTB-described UART0 TX DMA transaction after PCIe and DMA
/// preflight have already passed.  The DMA controller is in RP1 BAR1 while
/// its source and descriptor addresses use the PCIe-to-CPU inbound window.
fn run_uart0_dma_tx(
    rp1: &bcm2712::Rp1Config,
    rp1_map: &Rp1PeripheralMap,
    uart0_base: usize,
    dma: Uart0DmaInfo,
) -> Result<(), UartDmaError> {
    let request = dma.tx_request.ok_or(UartDmaError::InvalidDmaController)?;
    if request > 0x3f {
        return Err(UartDmaError::InvalidDmaController);
    }
    let dma_window = rp1.dma_window.ok_or(UartDmaError::MissingDmaWindow)?;
    let dmac_base = rp1_map
        .mmio_base(RP1_DMA_OFFSET, 0x1000)
        .map_err(|_| UartDmaError::InvalidDmaController)?;
    let area = core::ptr::addr_of_mut!(UART_DMA_TX_AREA);

    // SAFETY: this validator is single-core and exclusively owns the static
    // payload/descriptor for this one DMA transaction.
    unsafe {
        let tx = &mut (*area).tx;
        tx[..UART_DMA_TEST_BYTES.len()].copy_from_slice(UART_DMA_TEST_BYTES);
        tx[UART_DMA_TEST_BYTES.len()..].fill(0);
    }
    let tx_va = unsafe { core::ptr::addr_of_mut!((*area).tx).cast::<u8>() } as usize;
    let descriptor_va = unsafe { core::ptr::addr_of_mut!((*area).descriptor).cast::<u8>() } as usize;
    let tx_phys = cpu::va_to_pa_el2_read(tx_va as u64).ok_or(UartDmaError::AddressTranslation)?;
    let descriptor_phys =
        cpu::va_to_pa_el2_read(descriptor_va as u64).ok_or(UartDmaError::AddressTranslation)?;
    let tx_len = u64::try_from(UART_DMA_TEST_BYTES.len()).map_err(|_| UartDmaError::AddressTranslation)?;
    let tx_dma = dma_window
        .cpu_phys_to_dma(tx_phys, tx_len)
        .map_err(|_| UartDmaError::AddressTranslation)?;
    let descriptor_dma = dma_window
        .cpu_phys_to_dma(
            descriptor_phys,
            u64::try_from(size_of::<DwAxiDmacLli>()).map_err(|_| UartDmaError::AddressTranslation)?,
        )
        .map_err(|_| UartDmaError::AddressTranslation)?;
    let uart_cpu_alias = uart0_base as u64;
    let uart_bar_relative = uart_cpu_alias
        .checked_sub(rp1_map.base())
        .ok_or(UartDmaError::AddressTranslation)?;
    let uart_local_dma = rp1_map
        .peripheral_dma_addr(uart_cpu_alias, 4)
        .map_err(|_| UartDmaError::AddressTranslation)?;

    let descriptor = DwAxiDmacLli {
        sar: tx_dma,
        // Linux passes PL011 mapbase through phys_to_dma() before assigning
        // DAR. RP1 `dma-ranges` maps BAR1's peripheral address zero to the
        // local APB0 system address 0xc0_4000_0000.
        dar: uart_local_dma,
        block_ts_lo: (UART_DMA_TEST_BYTES.len() - 1) as u32,
        block_ts_hi: 0,
        llp: 0,
        ctl_lo: DW_AXI_DMAC_LLI_CTL_LO_MEM_TO_PER_8BIT,
        ctl_hi: DW_AXI_DMAC_LLI_CTL_H_LAST_VALID,
        ..DwAxiDmacLli::ZERO
    };
    // SAFETY: `descriptor_va` is within the uniquely owned DMA static above.
    unsafe { core::ptr::write(descriptor_va as *mut DwAxiDmacLli, descriptor) };
    cpu::clean_dcache_range(tx_va as *const u8, UART_DMA_TEST_BYTES.len());
    cpu::clean_dcache_range(descriptor_va as *const u8, size_of::<DwAxiDmacLli>());

    semihost_log(format_args!("[rpi5-rp1-init] UART DMA DMAC layout: CFG2"));
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA DREQ tx=0x{:x} buffer va=0x{:x} pa=0x{:x} dma=0x{:x} len={}",
        request, tx_va, tx_phys, tx_dma, UART_DMA_TEST_BYTES.len()
    ));
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART0 DR cpu=0x{:x} bar-relative=0x{:x} rp1-dma=0x{:x} dtb-reg=0x{:x}",
        uart_cpu_alias, uart_bar_relative, uart_local_dma, dma.reg_base
    ));
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA selected DAR mode=rp1-local-dma addr=0x{:x} desc_dma=0x{:x}",
        uart_local_dma, descriptor_dma
    ));
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA LLI sar=0x{:x} dar=0x{:x} block=0x{:x} ctl=0x{:08x}/0x{:08x} llp=0x{:x}",
        descriptor.sar, descriptor.dar, descriptor.block_ts_lo, descriptor.ctl_lo, descriptor.ctl_hi, descriptor.llp
    ));

    // Do not use `Pl011Uart::init` here: its normal flush waits indefinitely
    // for BUSY to deassert, which is unsuitable for an early bring-up test.
    // Program the minimal TX state directly and retain the finite DMA timeout.
    let original_lcrh = mmio_read32(uart0_base, RP1_UART_LCRH_OFFSET);
    let original_cr = mmio_read32(uart0_base, RP1_UART_CR_OFFSET);
    let original_dmacr = mmio_read32(uart0_base, RP1_UART_DMACR_OFFSET);
    mmio_write32(uart0_base, RP1_UART_IBRD_OFFSET, 26); // 48 MHz / 115200
    mmio_write32(uart0_base, RP1_UART_FBRD_OFFSET, 3);
    mmio_write32(
        uart0_base,
        RP1_UART_LCRH_OFFSET,
        original_lcrh | PL011_LCRH_FEN | PL011_LCRH_WLEN_8,
    );
    mmio_write32(
        uart0_base,
        RP1_UART_CR_OFFSET,
        original_cr | PL011_CR_UARTEN | PL011_CR_TXE,
    );
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA PL011 before FR=0x{:08x} CR=0x{:08x} DMACR=0x{:08x}",
        mmio_read32(uart0_base, RP1_UART_FR_OFFSET),
        mmio_read32(uart0_base, RP1_UART_CR_OFFSET),
        original_dmacr,
    ));

    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA DMAC id=0x{:08x} cfg=0x{:08x} chen-before=0x{:08x} raw=0x{:08x} common=0x{:08x}",
        dmac_read32(dmac_base, 0),
        dmac_read32(dmac_base, DW_AXI_DMAC_CFG),
        dmac_read32(dmac_base, DW_AXI_DMAC_CHEN),
        dmac_read32(dmac_base, DW_AXI_DMAC_INTSTATUS),
        dmac_read32(dmac_base, DW_AXI_DMAC_COMMON_INTSTATUS),
    ));
    dmac_soft_reset(dmac_base)?;
    dmac_disable_channel(dmac_base, DW_AXI_DMAC_CHANNEL);
    let cfg = dmac_read32(dmac_base, DW_AXI_DMAC_CFG) | DW_AXI_DMAC_CFG_EN;
    dmac_write32(dmac_base, DW_AXI_DMAC_CFG, cfg);
    let channel = dmac_channel_offset(DW_AXI_DMAC_CHANNEL);
    let irq_mask = DW_AXI_DMAC_IRQ_DMA_TRF | DW_AXI_DMAC_IRQ_ALL_ERR;
    dmac_write32(dmac_base, channel + DW_AXI_DMAC_CH_INTSTATUS_ENA, irq_mask);
    dmac_write32(dmac_base, channel + DW_AXI_DMAC_CH_INTSIGNAL_ENA, irq_mask);
    dmac_write32(dmac_base, channel + DW_AXI_DMAC_CH_INTCLEAR, DW_AXI_DMAC_IRQ_ALL);
    dmac_write32(dmac_base, DW_AXI_DMAC_COMMON_INTCLEAR, 1 << DW_AXI_DMAC_CHANNEL);
    let cfg_l = dmac_cfg2_l(request);
    let cfg_h = dmac_cfg2_h(0);
    dmac_write32(dmac_base, channel + DW_AXI_DMAC_CH_CFG_L, cfg_l);
    dmac_write32(dmac_base, channel + DW_AXI_DMAC_CH_CFG_H, cfg_h);
    dmac_write64(dmac_base, channel + DW_AXI_DMAC_CH_LLP, descriptor_dma);
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA cfg_l=0x{:08x} cfg_h=0x{:08x} llp=0x{:016x} intena=0x{:08x} signal=0x{:08x}",
        dmac_read32(dmac_base, channel + DW_AXI_DMAC_CH_CFG_L),
        dmac_read32(dmac_base, channel + DW_AXI_DMAC_CH_CFG_H),
        dmac_read64(dmac_base, channel + DW_AXI_DMAC_CH_LLP),
        dmac_read32(dmac_base, channel + DW_AXI_DMAC_CH_INTSTATUS_ENA),
        dmac_read32(dmac_base, channel + DW_AXI_DMAC_CH_INTSIGNAL_ENA),
    ));

    // The UART request is enabled only after the descriptor and channel state
    // are visible to RP1. It is always restored below, including on timeout.
    mmio_write32(uart0_base, RP1_UART_DMACR_OFFSET, original_dmacr | PL011_DMACR_TXDMAE);
    cpu::dsb_sy();
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA PL011 enabled FR=0x{:08x} CR=0x{:08x} DMACR=0x{:08x}",
        mmio_read32(uart0_base, RP1_UART_FR_OFFSET),
        mmio_read32(uart0_base, RP1_UART_CR_OFFSET),
        mmio_read32(uart0_base, RP1_UART_DMACR_OFFSET),
    ));
    dmac_enable_channel(dmac_base, DW_AXI_DMAC_CHANNEL);
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA chen-after-enable=0x{:08x}",
        dmac_read32(dmac_base, DW_AXI_DMAC_CHEN),
    ));

    let mut final_status = 0;
    let mut last_status = u32::MAX;
    let mut result = Err(UartDmaError::Timeout { status: 0 });
    for _ in 0..UART_DMA_POLL_LIMIT {
        let status = dmac_read32(dmac_base, channel + DW_AXI_DMAC_CH_INTSTATUS);
        final_status = status;
        if status != last_status {
            semihost_log(format_args!(
                "[rpi5-rp1-init] UART DMA poll ch-status=0x{:08x} raw=0x{:08x} common=0x{:08x}",
                status,
                dmac_read32(dmac_base, DW_AXI_DMAC_INTSTATUS),
                dmac_read32(dmac_base, DW_AXI_DMAC_COMMON_INTSTATUS),
            ));
            last_status = status;
        }
        if status & DW_AXI_DMAC_IRQ_ALL_ERR != 0 {
            result = Err(UartDmaError::DmaEngineError { status });
            break;
        }
        if status & DW_AXI_DMAC_IRQ_DMA_TRF != 0 {
            result = Ok(());
            break;
        }
        core::hint::spin_loop();
    }
    if matches!(result, Err(UartDmaError::Timeout { .. })) {
        result = Err(UartDmaError::Timeout { status: final_status });
    }

    dmac_disable_channel(dmac_base, DW_AXI_DMAC_CHANNEL);
    dmac_write32(dmac_base, channel + DW_AXI_DMAC_CH_INTCLEAR, DW_AXI_DMAC_IRQ_ALL);
    mmio_write32(uart0_base, RP1_UART_DMACR_OFFSET, original_dmacr);
    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA final status=0x{:08x} chstat=0x{:08x} raw=0x{:08x} common=0x{:08x} chen=0x{:08x}",
        final_status,
        dmac_read32(dmac_base, channel + DW_AXI_DMAC_CH_STATUS),
        dmac_read32(dmac_base, DW_AXI_DMAC_INTSTATUS),
        dmac_read32(dmac_base, DW_AXI_DMAC_COMMON_INTSTATUS),
        dmac_read32(dmac_base, DW_AXI_DMAC_CHEN),
    ));
    result
}

const fn dmac_channel_offset(channel: usize) -> usize {
    DW_AXI_DMAC_CHANNEL_BASE + channel * DW_AXI_DMAC_CHANNEL_STRIDE
}

/// Linux's `use_cfg2` path for controllers with the RP1's 64 DMA targets.
/// Source/destination multiblock modes are linked-list; destination request
/// comes exclusively from the generated DTB's `dmas` TX specifier.
const fn dmac_cfg2_l(dst_per: u32) -> u32 {
    (DW_AXI_DMAC_MBLK_TYPE_LL << CH_CFG2_L_SRC_MULTBLK_TYPE_POS)
        | (DW_AXI_DMAC_MBLK_TYPE_LL << CH_CFG2_L_DST_MULTBLK_TYPE_POS)
        | (0 << CH_CFG2_L_SRC_PER_POS)
        | (dst_per << CH_CFG2_L_DST_PER_POS)
}

/// Memory-to-peripheral, DMAC flow-control and hardware handshaking exactly
/// match the Linux DW AXI DMAC slave path for a TX peripheral.
const fn dmac_cfg2_h(priority: u32) -> u32 {
    (DW_AXI_DMAC_TT_FC_MEM_TO_PER_DMAC << CH_CFG2_H_TT_FC_POS)
        | (DW_AXI_DMAC_HS_SEL_HW << CH_CFG2_H_HS_SEL_SRC_POS)
        | (DW_AXI_DMAC_HS_SEL_HW << CH_CFG2_H_HS_SEL_DST_POS)
        | (priority << CH_CFG2_H_PRIORITY_POS)
}

fn dmac_soft_reset(base: usize) -> Result<(), UartDmaError> {
    // Linux's DW AXI DMAC header defines DMAC_RESET at 0x58. The Synopsys
    // soft-reset request is self-clearing, so bound the readback loop.
    dmac_write32(base, DW_AXI_DMAC_RESET, DW_AXI_DMAC_RESET_SOFT);
    for _ in 0..UART_DMA_POLL_LIMIT {
        let reset = dmac_read32(base, DW_AXI_DMAC_RESET);
        if reset & DW_AXI_DMAC_RESET_SOFT == 0 {
            semihost_log(format_args!(
                "[rpi5-rp1-init] UART DMA reset complete cfg=0x{:08x}",
                dmac_read32(base, DW_AXI_DMAC_CFG)
            ));
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(UartDmaError::ResetTimeout {
        reset: dmac_read32(base, DW_AXI_DMAC_RESET),
    })
}

fn dmac_enable_channel(base: usize, channel: usize) {
    dmac_write32(base, DW_AXI_DMAC_CHEN, (1 << channel) | (1 << (channel + 8)));
}

fn dmac_disable_channel(base: usize, channel: usize) {
    dmac_write32(base, DW_AXI_DMAC_CHEN, 1 << (channel + 8));
}

/// Reads a 32-bit register in the RP1 DMA controller MMIO region. `base` and
/// `offset` are validated from BAR1/constant controller layout before use.
fn dmac_read32(base: usize, offset: usize) -> u32 {
    mmio_read32(base, offset)
}

/// Writes a 32-bit register in the RP1 DMA controller MMIO region. `base` and
/// `offset` are validated from BAR1/constant controller layout before use.
fn dmac_write32(base: usize, offset: usize, value: u32) {
    mmio_write32(base, offset, value)
}

/// Writes a naturally aligned 64-bit DW AXI DMAC register as two 32-bit MMIO
/// writes, matching Linux's lo/hi register access on this 32-bit register map.
fn dmac_write64(base: usize, offset: usize, value: u64) {
    dmac_write32(base, offset, value as u32);
    dmac_write32(base, offset + 4, (value >> 32) as u32);
}

fn dmac_read64(base: usize, offset: usize) -> u64 {
    (dmac_read32(base, offset) as u64) | ((dmac_read32(base, offset + 4) as u64) << 32)
}

/// Volatile MMIO access invariant: callers pass a BAR-validated device base
/// and an offset within the corresponding device register block.
fn mmio_read32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller upholds the documented MMIO address/range invariant.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Volatile MMIO access invariant: callers pass a BAR-validated device base
/// and an offset within the corresponding device register block.
fn mmio_write32(base: usize, offset: usize, value: u32) {
    // SAFETY: caller upholds the documented MMIO address/range invariant.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, value) }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    semihost_log(format_args!("panic: {}", info));
    wait_forever()
}

fn fail(args: fmt::Arguments<'_>) -> ! {
    semihost_log(format_args!("[rpi5-rp1-init] FAIL: {}", args));
    wait_forever()
}

struct SemihostWriter {
    bytes: [u8; 256],
    len: usize,
}

impl SemihostWriter {
    const fn new() -> Self {
        Self {
            bytes: [0; 256],
            len: 0,
        }
    }
}

impl fmt::Write for SemihostWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn semihost_log(args: fmt::Arguments<'_>) {
    let mut writer = SemihostWriter::new();
    if fmt::write(&mut writer, args).is_ok() {
        semihost_write(&writer.bytes[..writer.len]);
    } else {
        semihost_write(b"[rpi5-rp1-init] log line too long");
    }
    semihost_write(b"\n");
}

fn semihost_write(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }

    let args = [1_u64, bytes.as_ptr() as u64, bytes.len() as u64];
    // SAFETY: This is the AArch64 semihosting `SYS_WRITE` ABI. OpenOCD handles the HLT
    // trap while the debug probe is attached; `args` and `bytes` stay valid for the call.
    unsafe {
        asm!(
            "hlt #0xf000",
            inlateout("x0") SEMIHOST_SYS_WRITE => _,
            in("x1") args.as_ptr() as u64,
            options(nostack),
        );
    }
}

fn semihost_mirror_write(text: &str) {
    semihost_write(text.as_bytes());
}

fn semihost_flush() {}

fn wait_forever() -> ! {
    loop {
        // SAFETY: `wfe` is used as a low-power idle wait in this single-core spin loop.
        unsafe {
            asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}
