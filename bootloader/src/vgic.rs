use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::cpu;
use arch_hal::gic;
use arch_hal::gic::GicError;
use arch_hal::gic::IrqGroup;
use arch_hal::gic::IrqSense;
use arch_hal::gic::PIntId;
use arch_hal::gic::VIntId;
use arch_hal::gic::VcpuId;
use arch_hal::gic::VgicHw;
use arch_hal::gic::VgicPirqModel;
use arch_hal::gic::VgicUpdate;
use arch_hal::gic::VgicVcpuModel;
use arch_hal::gic::VgicVmInfo;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2AccessSize;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2DistIdRegs;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2Frontend;
use core::cell::SyncUnsafeCell;

use crate::Gicv2Info;
use crate::UartNode;
use crate::handler;

static VGIC_VM: RawSpinLockIrqSave<Option<gic::vm::GicVmModelForVcpus<1>>> =
    RawSpinLockIrqSave::new(None);
static GICD_RANGE: SyncUnsafeCell<Option<(usize, usize)>> = SyncUnsafeCell::new(None);
static MAINT_INTID: SyncUnsafeCell<Option<u32>> = SyncUnsafeCell::new(None);
static GICD_ID: SyncUnsafeCell<Option<Gicv2DistIdRegs>> = SyncUnsafeCell::new(None);

pub fn init(gic: &Gicv2, info: &Gicv2Info, guest_uart: UartNode) -> Result<(), &'static str> {
    let mut vm = gic
        .create_vm_model::<1>(1)
        .map_err(|_| "vgic: create vm failed")?;

    gic.hw_init().map_err(|_| "vgic: hw init failed")?;
    {
        let vcpu = vm.vcpu(VcpuId(0)).map_err(|_| "vgic: vcpu")?;
        vcpu.set_resident(cpu::get_current_core_id())
            .map_err(|_| "vgic: set resident")?;
    }

    if let Some(pintid) = guest_uart.irq {
        let update = vm
            .map_pirq(
                PIntId(pintid),
                VcpuId(0),
                VIntId(pintid),
                IrqSense::Level,
                IrqGroup::Group1,
                0x80,
            )
            .map_err(|_| "vgic: map pirq")?;
        apply_update(&mut vm, gic, update).map_err(|_| "vgic: update")?;
    }

    let vcpu = vm.vcpu(VcpuId(0)).map_err(|_| "vgic: vcpu")?;
    vcpu.refill_lrs(gic).map_err(|_| "vgic: refill")?;

    // SAFETY: vGIC state is initialized once before guest entry.
    unsafe {
        *GICD_RANGE.get() = Some((info.dist.base, info.dist.size));
        *MAINT_INTID.get() = info.maintenance_intid;
        *GICD_ID.get() = Some(Gicv2DistIdRegs::from_hw_gicd(gic.distributor()));
    }
    let mut guard = VGIC_VM.lock_irqsave();
    *guard = Some(vm);
    Ok(())
}

pub fn maintenance_intid() -> Option<u32> {
    // SAFETY: set during vGIC initialization and then read-only.
    unsafe { *MAINT_INTID.get() }
}

pub fn handles_gicd(addr: usize) -> bool {
    // SAFETY: range set once during init and then treated as read-only.
    let Some((base, size)) = (unsafe { *GICD_RANGE.get() }) else {
        return false;
    };
    (base..base + size).contains(&addr)
}

pub fn handle_gicd_read(addr: usize, access_size: Gicv2AccessSize) -> Result<u32, GicError> {
    // SAFETY: GICD range is initialized once before guest entry.
    let (base, _) = unsafe { (*GICD_RANGE.get()).ok_or(GicError::InvalidAddress)? };
    let offset = addr.saturating_sub(base) as u32;
    let dist_id = unsafe { (*GICD_ID.get()).ok_or(GicError::InvalidState)? };

    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let mut frontend = Gicv2Frontend::new(vm, dist_id);
    frontend.handle_distributor_read(VcpuId(0), offset, access_size)
}

pub fn handle_gicd_write(
    addr: usize,
    access_size: Gicv2AccessSize,
    value: u32,
) -> Result<(), GicError> {
    // SAFETY: GICD range is initialized once before guest entry.
    let (base, _) = unsafe { (*GICD_RANGE.get()).ok_or(GicError::InvalidAddress)? };
    let offset = addr.saturating_sub(base) as u32;
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let dist_id = unsafe { (*GICD_ID.get()).ok_or(GicError::InvalidState)? };

    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let mut frontend = Gicv2Frontend::new(vm, dist_id);
    let update = frontend.handle_distributor_write(VcpuId(0), offset, access_size, value)?;
    apply_update(vm, gic, update)
}

pub fn on_physical_irq(intid: u32) -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let update = vm.on_physical_irq(PIntId(intid), true)?;
    apply_update(vm, gic, update)
}

pub fn handle_maintenance_irq() -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let vcpu = vm.vcpu(VcpuId(0))?;
    let update = vcpu.handle_maintenance(gic, &mut |_pirq| {}, &mut |_pirq| {}, &mut |_pirq| {})?;
    apply_update(vm, gic, update)
}

fn apply_update(
    vm: &mut gic::vm::GicVmModelForVcpus<1>,
    gic: &Gicv2,
    update: VgicUpdate,
) -> Result<(), GicError> {
    if let VgicUpdate::Some { .. } = update {
        let vcpu = vm.vcpu(VcpuId(0))?;
        let _kick = vcpu.refill_lrs(gic)?;
    }
    Ok(())
}
