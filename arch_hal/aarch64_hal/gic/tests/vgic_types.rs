#![cfg_attr(target_arch = "aarch64", no_std)]
#![cfg_attr(target_arch = "aarch64", no_main)]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use core::arch::naked_asm;
use gic::IrqGroup;
use gic::IrqState;
use gic::VIntId;
use gic::VcpuId;
use gic::VcpuMask;
use gic::VirtualInterrupt;
use print::debug_uart;
use print::println;

const UART_BASE: usize = 0x900_0000;
const UART_CLOCK_HZ: u32 = 48 * 1_000_000;

unsafe extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __stack_top: u8;
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "
        ldr x0, =__stack_top
        mov sp, x0
        bl rust_entry
        "
    );
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rust_entry() -> ! {
    clear_bss();
    debug_uart::init(UART_BASE, UART_CLOCK_HZ as u64, 115200);
    match entry() {
        Ok(()) => {
            println!("vgic_types: PASS");
            exit_success();
        }
        Err(msg) => {
            println!("vgic_types: FAIL {}", msg);
            exit_failure();
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic: {:?}", info);
    exit_failure();
}

fn clear_bss() {
    // SAFETY: linker symbols describe the BSS region.
    unsafe {
        let start = &__bss_start as *const u8 as usize;
        let end = &__bss_end as *const u8 as usize;
        let len = end.saturating_sub(start);
        core::ptr::write_bytes(start as *mut u8, 0, len);
    }
}

fn entry() -> Result<(), &'static str> {
    test_vcpu_mask_basic()?;
    test_virtual_interrupt_helpers()?;
    Ok(())
}

fn test_vcpu_mask_basic() -> Result<(), &'static str> {
    let mut mask: VcpuMask<16> = VcpuMask::EMPTY;
    if !mask.is_empty() {
        return Err("mask not empty initially");
    }
    mask.set(VcpuId(1)).map_err(|_| "set id1 failed")?;
    mask.set(VcpuId(3)).map_err(|_| "set id3 failed")?;
    if !mask.contains(VcpuId(1)) || !mask.contains(VcpuId(3)) {
        return Err("mask contains check failed");
    }
    mask.clear(VcpuId(1)).map_err(|_| "clear id1 failed")?;
    if mask.contains(VcpuId(1)) {
        return Err("clear did not clear");
    }
    let mut iters = [0u16; 4];
    let mut count = 0;
    for v in mask.iter() {
        iters[count] = v.0;
        count += 1;
    }
    if count != 1 || iters[0] != 3 {
        return Err("iter contents unexpected");
    }
    let mut other = VcpuMask::EMPTY;
    other.set(VcpuId(5)).map_err(|_| "set other failed")?;
    mask.union_assign(&other);
    if !mask.contains(VcpuId(5)) {
        return Err("union_assign failed");
    }
    if mask.set(VcpuId(16)).is_ok() {
        return Err("out-of-range set should fail");
    }
    if mask.clear(VcpuId(16)).is_ok() {
        return Err("out-of-range clear should fail");
    }
    Ok(())
}

fn test_virtual_interrupt_helpers() -> Result<(), &'static str> {
    let hw = VirtualInterrupt::Hardware {
        vintid: 50,
        pintid: 75,
        priority: 0x20,
        group: IrqGroup::Group1,
        state: IrqState::Pending,
        source: Some(VcpuId(1)),
    };
    if !hw.is_hw() || hw.pintid() != Some(75) || hw.eoi_maintenance() {
        return Err("hw accessors mismatch");
    }

    let mut sw = VirtualInterrupt::Software {
        vintid: 10,
        eoi_maintenance: true,
        priority: 0x40,
        group: IrqGroup::Group0,
        state: IrqState::Active,
        source: None,
    };
    if sw.is_hw() || sw.pintid().is_some() || !sw.eoi_maintenance() {
        return Err("sw accessors mismatch");
    }
    sw.set_state(IrqState::PendingActive);
    sw.set_eoi_maintenance(false);
    if sw.state() != IrqState::PendingActive || sw.eoi_maintenance() {
        return Err("sw mutation helpers mismatch");
    }

    if sw.vintid() != 10 {
        return Err("sw vintid helper mismatch");
    }
    if hw.vintid() != 50 {
        return Err("hw vintid helper mismatch");
    }
    if hw.source() != Some(VcpuId(1)) {
        return Err("hw source helper mismatch");
    }
    if sw.source().is_some() {
        return Err("sw source helper mismatch");
    }

    let _ = VIntId(sw.vintid());
    Ok(())
}

// Type-check the APR signature change.
fn _sig_check<H: gic::VgicHw>(hw: &H) {
    let _ = hw.read_apr(0);
    let _ = hw.write_apr(0, 0);
}
