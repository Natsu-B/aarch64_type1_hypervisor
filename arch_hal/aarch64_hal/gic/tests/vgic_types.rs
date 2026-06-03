#![cfg_attr(target_arch = "aarch64", no_std)]
#![cfg_attr(target_arch = "aarch64", no_main)]
#![feature(generic_const_exprs)]

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
    test_vcpu_mask_multiword()?;
    test_vcpu_mask_from_bits_large_width()?;
    test_vcpu_mask_width_edges()?;
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

fn test_vcpu_mask_multiword() -> Result<(), &'static str> {
    let mut mask: VcpuMask<130> = VcpuMask::EMPTY;
    if !mask.is_empty() {
        return Err("multiword mask not empty initially");
    }

    mask.set(VcpuId(0)).map_err(|_| "set id0 failed")?;
    mask.set(VcpuId(63)).map_err(|_| "set id63 failed")?;
    mask.set(VcpuId(64)).map_err(|_| "set id64 failed")?;
    mask.set(VcpuId(129)).map_err(|_| "set id129 failed")?;

    if !mask.contains(VcpuId(0))
        || !mask.contains(VcpuId(63))
        || !mask.contains(VcpuId(64))
        || !mask.contains(VcpuId(129))
    {
        return Err("multiword contains check failed");
    }

    mask.clear(VcpuId(63)).map_err(|_| "clear id63 failed")?;
    if mask.contains(VcpuId(63)) {
        return Err("multiword clear did not clear");
    }

    let mut other: VcpuMask<130> = VcpuMask::EMPTY;
    other.set(VcpuId(63)).map_err(|_| "set other id63 failed")?;
    other.set(VcpuId(65)).map_err(|_| "set other id65 failed")?;
    mask.union_assign(&other);

    if !mask.contains(VcpuId(63)) || !mask.contains(VcpuId(65)) {
        return Err("multiword union_assign failed");
    }
    if mask.contains(VcpuId(130)) {
        return Err("multiword contains accepted out-of-range id");
    }
    if mask.set(VcpuId(130)).is_ok() {
        return Err("multiword out-of-range set should fail");
    }
    if mask.clear(VcpuId(130)).is_ok() {
        return Err("multiword out-of-range clear should fail");
    }

    let mut ids = [0u16; 5];
    let mut count = 0;
    for id in mask.iter() {
        if count >= ids.len() {
            return Err("multiword iter produced too many ids");
        }
        ids[count] = id.0;
        count += 1;
    }
    if count != ids.len() || ids != [0, 63, 64, 65, 129] {
        return Err("multiword iter contents unexpected");
    }

    Ok(())
}

fn test_vcpu_mask_from_bits_large_width() -> Result<(), &'static str> {
    let mask: VcpuMask<130> = VcpuMask::from_bits(0b0011_0000_0000_0101);

    if !mask.contains(VcpuId(0))
        || !mask.contains(VcpuId(2))
        || !mask.contains(VcpuId(12))
        || !mask.contains(VcpuId(13))
    {
        return Err("from_bits large-width low bits mismatch");
    }
    if mask.contains(VcpuId(16)) || mask.contains(VcpuId(64)) || mask.contains(VcpuId(129)) {
        return Err("from_bits large-width set bits above low 16");
    }

    let mut ids = [0u16; 4];
    let mut count = 0;
    for id in mask.iter() {
        if count >= ids.len() {
            return Err("from_bits large-width iter produced too many ids");
        }
        ids[count] = id.0;
        count += 1;
    }
    if count != ids.len() || ids != [0, 2, 12, 13] {
        return Err("from_bits large-width iter contents unexpected");
    }

    Ok(())
}

fn test_vcpu_mask_width_edges() -> Result<(), &'static str> {
    let mut zero: VcpuMask<0> = VcpuMask::EMPTY;
    if !zero.is_empty() {
        return Err("zero-width mask not empty initially");
    }
    if zero.contains(VcpuId(0)) {
        return Err("zero-width contains accepted id0");
    }
    if zero.set(VcpuId(0)).is_ok() || zero.clear(VcpuId(0)).is_ok() {
        return Err("zero-width set or clear should fail");
    }
    if VcpuMask::<0>::from_bits(u16::MAX).iter().next().is_some() {
        return Err("zero-width from_bits yielded ids");
    }

    let clipped = VcpuMask::<9>::from_bits(u16::MAX);
    let mut clipped_ids = [0u16; 9];
    let mut clipped_count = 0;
    for id in clipped.iter() {
        if clipped_count >= clipped_ids.len() {
            return Err("clipped iter produced too many ids");
        }
        clipped_ids[clipped_count] = id.0;
        clipped_count += 1;
    }
    if clipped_count != clipped_ids.len() || clipped_ids != [0, 1, 2, 3, 4, 5, 6, 7, 8] {
        return Err("from_bits did not clip to width under 16");
    }

    let raw = VcpuMask::<65>([0, u64::MAX]);
    let mut raw_ids = [0u16; 1];
    let mut raw_count = 0;
    for id in raw.iter() {
        if raw_count >= raw_ids.len() {
            return Err("tail-masked iter produced too many ids");
        }
        raw_ids[raw_count] = id.0;
        raw_count += 1;
    }
    if raw_count != raw_ids.len() || raw_ids != [64] {
        return Err("iter leaked bits from the unused tail");
    }

    let mut normalized: VcpuMask<65> = VcpuMask::EMPTY;
    normalized.union_assign(&raw);
    if normalized != VcpuMask::<65>([0, 1]) {
        return Err("union_assign did not clear unused tail bits");
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
        pintid: None,
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
