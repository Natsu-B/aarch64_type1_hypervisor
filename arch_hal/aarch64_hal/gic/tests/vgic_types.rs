#![cfg_attr(target_arch = "aarch64", no_std)]
#![cfg_attr(target_arch = "aarch64", no_main)]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use core::arch::naked_asm;
use gic::GicError;
use gic::IrqGroup;
use gic::IrqState;
use gic::PIntId;
use gic::PirqNotifications;
use gic::TriggerMode;
use gic::VIntId;
use gic::VcpuId;
use gic::VcpuMask;
use gic::VgicGuestRegs;
use gic::VgicIrqScope;
use gic::VgicPirqModel;
use gic::VgicSgiRegs;
use gic::VgicTargets;
use gic::VgicUpdate;
use gic::VgicVcpuModel;
use gic::VgicVmInfo;
use gic::VgicWork;
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
    test_inject_sgi_and_updates()?;
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

#[derive(Copy, Clone, Default)]
struct DummyVcpu;

impl VgicVcpuModel for DummyVcpu {
    fn set_resident(&self, _core: cpu::CoreAffinity) -> Result<(), GicError> {
        Ok(())
    }

    fn clear_resident(&self, _core: cpu::CoreAffinity) -> Result<(), GicError> {
        Ok(())
    }

    fn refill_lrs<H: gic::VgicHw>(&self, _hw: &H) -> Result<bool, GicError> {
        Ok(false)
    }

    fn handle_maintenance_collect<H: gic::VgicHw>(
        &self,
        _hw: &H,
    ) -> Result<(VgicUpdate, PirqNotifications), GicError> {
        Ok((VgicUpdate::None, PirqNotifications::new()))
    }

    fn switch_out_sync<H: gic::VgicHw>(&self, _hw: &H) -> Result<(), GicError> {
        Ok(())
    }
}

struct DummyModel {
    pending_sources: [[u32; 16]; 4],
    vcpus: [DummyVcpu; 4],
}

impl DummyModel {
    fn new() -> Self {
        Self {
            pending_sources: [[0; 16]; 4],
            vcpus: [DummyVcpu::default(); 4],
        }
    }
}

impl VgicVmInfo for DummyModel {
    type VcpuModel = DummyVcpu;

    fn vcpu_count(&self) -> u16 {
        self.vcpus.len() as u16
    }

    fn vcpu(&self, id: VcpuId) -> Result<&Self::VcpuModel, GicError> {
        self.vcpus.get(id.0 as usize).ok_or(GicError::InvalidVcpuId)
    }
}

impl VgicGuestRegs for DummyModel {
    fn set_dist_enable(
        &mut self,
        _enable_grp0: bool,
        _enable_grp1: bool,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn dist_enable(&self) -> Result<(bool, bool), GicError> {
        Ok((false, false))
    }

    fn set_group(
        &mut self,
        _scope: VgicIrqScope,
        _vintid: VIntId,
        _group: IrqGroup,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_priority(
        &mut self,
        _scope: VgicIrqScope,
        _vintid: VIntId,
        _priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_trigger(
        &mut self,
        _scope: VgicIrqScope,
        _vintid: VIntId,
        _trigger: TriggerMode,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_enable(
        &mut self,
        _scope: VgicIrqScope,
        _vintid: VIntId,
        _enable: bool,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_pending(
        &mut self,
        _scope: VgicIrqScope,
        _vintid: VIntId,
        _pending: bool,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_active(
        &mut self,
        _scope: VgicIrqScope,
        _vintid: VIntId,
        _active: bool,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_group_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_group_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_enable_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_set_enable_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn write_clear_enable_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_pending_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_set_pending_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn write_clear_pending_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_active_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_set_active_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn write_clear_active_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_priority_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_priority_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _value: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_trigger_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_trigger_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _value: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn read_nsacr_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_nsacr_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _value: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_spi_route(
        &mut self,
        _vintid: VIntId,
        _targets: gic::VSpiRouting,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn get_spi_route(&self, _vintid: VIntId) -> Result<gic::VSpiRouting, GicError> {
        Ok(gic::VSpiRouting::Targets(gic::VcpuMask::EMPTY))
    }
}

impl VgicSgiRegs for DummyModel {
    fn read_sgi_pending_sources_word(&self, target: VcpuId, word: u8) -> Result<u32, GicError> {
        if (target.0 as usize) >= self.vcpus.len() || word >= 16 {
            return Err(GicError::InvalidVcpuId);
        }
        Ok(self.pending_sources[target.0 as usize][word as usize])
    }

    fn write_set_sgi_pending_sources_word(
        &mut self,
        target: VcpuId,
        word: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError> {
        if (target.0 as usize) >= self.vcpus.len() || word as usize >= 16 {
            return Err(GicError::InvalidVcpuId);
        }
        let idx = target.0 as usize;
        self.pending_sources[idx][word as usize] |= sources;
        Ok(VgicUpdate::Some {
            targets: VgicTargets::One(target),
            work: VgicWork {
                refill: true,
                kick: true,
            },
        })
    }

    fn write_clear_sgi_pending_sources_word(
        &mut self,
        target: VcpuId,
        word: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError> {
        if (target.0 as usize) >= self.vcpus.len() || word as usize >= 16 {
            return Err(GicError::InvalidVcpuId);
        }
        let idx = target.0 as usize;
        self.pending_sources[idx][word as usize] &= !sources;
        Ok(VgicUpdate::Some {
            targets: VgicTargets::One(target),
            work: VgicWork {
                refill: true,
                kick: true,
            },
        })
    }
}

impl VgicPirqModel for DummyModel {
    fn map_pirq(
        &mut self,
        _pintid: PIntId,
        _target: VcpuId,
        _vintid: VIntId,
        _sense: gic::IrqSense,
        _group: IrqGroup,
        _priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn unmap_pirq(&mut self, _pintid: PIntId) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn on_physical_irq(&mut self, _pintid: PIntId, _level: bool) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }
}

fn test_inject_sgi_and_updates() -> Result<(), &'static str> {
    let mut model = DummyModel::new();
    let mut mask = VcpuMask::EMPTY;
    mask.set(VcpuId(0)).map_err(|_| "set target 0 failed")?;
    mask.set(VcpuId(2)).map_err(|_| "set target 2 failed")?;

    let update =
        VgicSgiRegs::inject_sgi(&mut model, VcpuId(1), mask, 3).map_err(|_| "inject_sgi failed")?;
    match update {
        VgicUpdate::Some { targets, work } => {
            match targets {
                VgicTargets::Mask(masked) => {
                    if !masked.contains(VcpuId(0)) || !masked.contains(VcpuId(2)) {
                        return Err("mask missing targets");
                    }
                }
                _ => return Err("unexpected targets"),
            }
            if !work.refill || !work.kick {
                return Err("work flags incorrect");
            }
        }
        _ => return Err("missing update"),
    }

    let src_bits = (1u32 << 1) << (3 * 8);
    if model.pending_sources[0][0] != src_bits || model.pending_sources[2][0] != src_bits {
        return Err("pending sources not recorded");
    }
    if let Ok(_) = VgicSgiRegs::inject_sgi(&mut model, VcpuId(16), mask, 3) {
        return Err("out-of-range sender accepted");
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
    Ok(())
}

// Type-check the APR signature change.
fn _sig_check<H: gic::VgicHw>(hw: &H) {
    let _ = hw.read_apr(0);
    let _ = hw.write_apr(0, 0);
}
