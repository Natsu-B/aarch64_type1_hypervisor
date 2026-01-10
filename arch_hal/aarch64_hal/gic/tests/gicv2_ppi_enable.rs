#![no_std]
#![no_main]

extern crate alloc;

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use core::arch::asm;
use core::arch::naked_asm;
use core::ptr;
use cpu;
use gic::BinaryPoint;
use gic::EnableOp;
use gic::EoiMode;
use gic::GicCpuConfig;
use gic::GicCpuInterface;
use gic::GicDistributor;
use gic::GicError;
use gic::GicPpi;
use gic::IrqGroup;
use gic::MmioRegion;
use gic::TriggerMode;
use gic::gicv2::GICV2_GICC_FRAME_SIZE;
use gic::gicv2::GICV2_GICD_FRAME_SIZE;
use gic::gicv2::Gicv2;
use print::debug_uart;
use print::println;

const UART_BASE: usize = 0x900_0000;
const UART_CLOCK_HZ: u32 = 48 * 1_000_000;
const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;
const PPI_ID: u32 = 30;

unsafe extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __stack_top: u8;
}

fn entry() -> ! {
    debug_uart::init(UART_BASE, UART_CLOCK_HZ as u64, 115200);

    match run() {
        Ok(()) => {
            println!("gicv2_ppi_enable: PASS");
            exit_success();
        }
        Err(err) => {
            println!("gicv2_ppi_enable: FAIL: {}", err);
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
    entry()
}

fn run() -> Result<(), &'static str> {
    unsafe { asm!("msr daifset, #0b1111",) };

    let gicd_typer = read_mmio32(GICD_BASE, 0x004);
    let security_extension_implemented = ((gicd_typer >> 10) & 0x1) != 0;
    println!(
        "GICD_TYPER=0x{:08x} SecurityExtn={}",
        gicd_typer, security_extension_implemented
    );
    if !security_extension_implemented {
        println!("SecurityExtn=0: logical Group0/Group1 emulation (AckCtl=0, IAR-only)");
    }

    let gic = Gicv2::new(
        MmioRegion {
            base: GICD_BASE,
            size: GICV2_GICD_FRAME_SIZE,
        },
        MmioRegion {
            base: GICC_BASE,
            size: GICV2_GICC_FRAME_SIZE,
        },
        None,
        None,
    )
    .map_err(|err| map_err("gic_new", err))?;

    gic.enable_atomic();
    gic.init_distributor()
        .map_err(|err| map_err("gicd_init", err))?;
    let caps = gic
        .init_cpu_interface()
        .map_err(|err| map_err("gicc_init", err))?;
    if security_extension_implemented {
        if !caps.supports_group1 {
            return Err("group1_not_supported");
        }
    } else if !caps.supports_group0 || !caps.supports_group1 {
        return Err("group_support_mismatch");
    }

    let cpu_cfg = GicCpuConfig {
        priority_mask: 0xff,
        enable_group0: !security_extension_implemented,
        enable_group1: true,
        binary_point: BinaryPoint::Common(1),
        eoi_mode: EoiMode::DropAndDeactivate,
    };
    GicCpuInterface::configure(&gic, &cpu_cfg).map_err(|err| map_err("gicc_configure", err))?;

    run_basic(&gic, security_extension_implemented)?;
    run_error_cases(&gic, security_extension_implemented)?;

    Ok(())
}

fn run_basic(gic: &Gicv2, security_extension_implemented: bool) -> Result<(), &'static str> {
    let bit = 1u32 << PPI_ID;

    // Clear any stale state for the target PPI only.
    write_mmio32(GICD_BASE, 0x180, bit);
    write_mmio32(GICD_BASE, 0x280, bit);
    write_mmio32(GICD_BASE, 0x380, bit);
    cpu::dsb_sy();
    cpu::isb();

    GicPpi::configure_ppi(
        gic,
        PPI_ID,
        IrqGroup::Group1,
        0x80,
        TriggerMode::Edge,
        EnableOp::Enable,
    )
    .map_err(|err| map_err("configure_ppi", err))?;

    let isenabler0 = read_mmio32(GICD_BASE, 0x100);
    if (isenabler0 & bit) == 0 {
        return Err("ppi_not_enabled");
    }

    let priority = read_mmio8(GICD_BASE, 0x400 + PPI_ID as usize);
    if priority != 0x80 {
        return Err("priority_mismatch");
    }

    let icfgr = read_mmio32(GICD_BASE, 0x0c00 + (PPI_ID as usize / 16) * 4);
    let cfg_field = (icfgr >> ((PPI_ID % 16) * 2)) & 0b11;
    if cfg_field != 0b10 {
        return Err("icfgr_mismatch");
    }

    if !security_extension_implemented {
        let logical_group = gic
            .logical_group(PPI_ID)
            .map_err(|err| map_err("logical_group", err))?;
        if logical_group != IrqGroup::Group1 {
            return Err("logical_group_mismatch");
        }
    }

    Ok(())
}

fn run_error_cases(gic: &Gicv2, security_extension_implemented: bool) -> Result<(), &'static str> {
    if !matches!(
        GicPpi::configure_ppi(
            gic,
            0,
            IrqGroup::Group1,
            0x20,
            TriggerMode::Level,
            EnableOp::Disable
        ),
        Err(GicError::UnsupportedIntId)
    ) {
        return Err("sgi_id_not_rejected");
    }

    if !matches!(
        GicPpi::configure_ppi(
            gic,
            33,
            IrqGroup::Group1,
            0x20,
            TriggerMode::Level,
            EnableOp::Disable
        ),
        Err(GicError::UnsupportedIntId)
    ) {
        return Err("spi_id_not_rejected");
    }

    if security_extension_implemented
        && !matches!(
            GicPpi::configure_ppi(
                gic,
                PPI_ID,
                IrqGroup::Group0,
                0x40,
                TriggerMode::Level,
                EnableOp::Disable
            ),
            Err(GicError::UnsupportedFeature)
        )
    {
        return Err("group0_not_blocked");
    }

    Ok(())
}

fn read_mmio8(base: usize, offset: usize) -> u8 {
    unsafe { ptr::read_volatile((base + offset) as *const u8) }
}

fn read_mmio32(base: usize, offset: usize) -> u32 {
    unsafe { ptr::read_volatile((base + offset) as *const u32) }
}

fn write_mmio32(base: usize, offset: usize, value: u32) {
    unsafe { ptr::write_volatile((base + offset) as *mut u32, value) }
}

fn map_err(label: &'static str, err: GicError) -> &'static str {
    println!("{}: {:?}", label, err);
    label
}

unsafe fn clear_bss() {
    let (start, end) = unsafe {
        (
            &__bss_start as *const u8 as usize,
            &__bss_end as *const u8 as usize,
        )
    };
    if end > start {
        unsafe {
            ptr::write_bytes(start as *mut u8, 0, end - start);
        }
    }
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info);
    exit_failure();
}
