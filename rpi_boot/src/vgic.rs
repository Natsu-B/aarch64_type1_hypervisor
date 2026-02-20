use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::cpu;
use arch_hal::gic;
use arch_hal::gic::GicError;
use arch_hal::gic::IrqGroup;
use arch_hal::gic::IrqSense;
use arch_hal::gic::PIntId;
use arch_hal::gic::VIntId;
use arch_hal::gic::VcpuId;
use arch_hal::gic::VgicGuestRegs;
use arch_hal::gic::VgicHw;
use arch_hal::gic::VgicIrqScope;
use arch_hal::gic::VgicPirqModel;
use arch_hal::gic::VgicTargets;
use arch_hal::gic::VgicUpdate;
use arch_hal::gic::VgicVcpuModel;
use arch_hal::gic::VgicVmInfo;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2AccessSize;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2DistIdRegs;
use arch_hal::gic::gicv2::vgic_frontend::Gicv2Frontend;
use arch_hal::gic::vm::PirqHooks;
use arch_hal::soc::bcm2712::rp1_interrupt;
use core::cell::SyncUnsafeCell;
use core::ptr;
use core::ptr::slice_from_raw_parts_mut;
use typestate::ReadWrite;

use crate::Gicv2Info;
use crate::RP1_BASE;
use crate::handler;

static VGIC_VM: RawSpinLockIrqSave<Option<gic::vm::GicVmModelForVcpus<4>>> =
    RawSpinLockIrqSave::new(None);
static GICD_RANGE: SyncUnsafeCell<Option<(usize, usize)>> = SyncUnsafeCell::new(None);
static MAINT_INTID: SyncUnsafeCell<Option<u32>> = SyncUnsafeCell::new(None);
static GICD_ID: SyncUnsafeCell<Option<Gicv2DistIdRegs>> = SyncUnsafeCell::new(None);

pub(crate) struct UartIrq {
    pub pintid: u32,
    pub sense: IrqSense,
}

const MIP_SPI_OFFSET: u32 = 128;
const RP1_PCIE_CFG_BASE: usize = RP1_BASE + 0x10_8000 + 0x08;
const RP1_PCIE_CFG_LEN: usize = 64;

fn current_vcpu_id() -> VcpuId {
    VcpuId(0)
}

unsafe fn hook_toggle_rp1_msix(
    _ctx: *mut (),
    pintid: PIntId,
    enable: bool,
) -> Result<(), GicError> {
    // SAFETY: Called by the vGIC with exclusive access to VM state; the RP1 MSI-X table is
    // initialized before guest entry, and this hook performs only non-blocking MMIO updates.
    let res = if enable {
        rp1_interrupt::enable_interrupt(pintid.0)
    } else {
        rp1_interrupt::disable_interrupt(pintid.0)
    };
    res.map_err(|_| GicError::InvalidState)?;
    Ok(())
}

unsafe fn hook_rp1_msix_eoi(_ctx: *mut (), pintid: PIntId) {
    // SAFETY: Called by the vGIC with exclusive access to VM state; this hook performs a
    // bounded MMIO write to acknowledge the MSI-X vector.
    rp1_msix_iack(pintid);
}

fn rp1_msix_iack(pintid: PIntId) {
    let Some(vector) = pintid.0.checked_sub(MIP_SPI_OFFSET + 32) else {
        return;
    };
    let Ok(idx) = usize::try_from(vector) else {
        return;
    };
    if idx >= RP1_PCIE_CFG_LEN {
        return;
    }
    // SAFETY: RP1 PCIe config window is MMIO-mapped at a fixed address; index is bounds-checked.
    let pcie_config = unsafe {
        &*slice_from_raw_parts_mut(RP1_PCIE_CFG_BASE as *mut ReadWrite<u32>, RP1_PCIE_CFG_LEN)
    };
    pcie_config[idx].set_bits(0b0100);
}

pub fn init(gic: &Gicv2, info: &Gicv2Info, uart_irq: Option<UartIrq>) -> Result<(), &'static str> {
    gic.hw_init().map_err(|_| "vgic: hw init failed")?;

    let mut guard = VGIC_VM.lock_irqsave();
    if guard.is_some() {
        return Err("vgic: already initialized");
    }
    *guard = Some(
        gic.create_vm_model::<4>(4)
            .map_err(|_| "vgic: create vm failed")?,
    );
    let vm = guard.as_mut().unwrap();

    {
        let vcpu = vm.vcpu(current_vcpu_id()).map_err(|_| "vgic: vcpu")?;
        vcpu.set_resident(cpu::get_current_core_id())
            .map_err(|_| "vgic: set resident")?;
    }

    if let Some(uart_irq) = uart_irq {
        let update = vm
            .map_pirq(
                PIntId(uart_irq.pintid),
                VcpuId(0),
                VIntId(uart_irq.pintid),
                uart_irq.sense,
                IrqGroup::Group1,
                0x80,
            )
            .map_err(|_| "vgic: map pirq")?;
        apply_update(vm, gic, update).map_err(|_| "vgic: update")?;
        let hooks = PirqHooks {
            ctx: ptr::null_mut(),
            on_enable: Some(hook_toggle_rp1_msix),
            on_route: None,
            on_eoi: Some(hook_rp1_msix_eoi),
            on_deactivate: None,
            on_resample: None,
        };
        vm.set_pirq_hooks(PIntId(uart_irq.pintid), hooks)
            .map_err(|_| "vgic: hooks")?;
    }

    let vcpu = vm.vcpu(current_vcpu_id()).map_err(|_| "vgic: vcpu")?;
    vcpu.refill_lrs(gic).map_err(|_| "vgic: refill")?;

    // SAFETY: vGIC state is initialized once before guest entry.
    unsafe {
        *GICD_RANGE.get() = Some((info.dist.base, info.dist.size));
        *MAINT_INTID.get() = info.maintenance_intid;
        *GICD_ID.get() = Some(Gicv2DistIdRegs::from_hw_gicd(gic.distributor()));
    }
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
    frontend.handle_distributor_read(current_vcpu_id(), offset, access_size)
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
    let update =
        frontend.handle_distributor_write(current_vcpu_id(), offset, access_size, value)?;
    apply_update(vm, gic, update)
}

pub fn on_physical_irq(pintid: PIntId, level: bool) -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let update = vm.on_physical_irq(pintid, level)?;
    apply_update(vm, gic, update)
}

pub fn passthrough_physical_irq(intid: u32, level: bool) -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let vintid = VIntId(intid);
    let scope = if intid < 32 {
        VgicIrqScope::Local(current_vcpu_id())
    } else {
        VgicIrqScope::Global
    };
    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let update = vm.set_pending(scope, vintid, level)?;
    apply_update(vm, gic, update)
}

pub fn handle_maintenance_irq() -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let (update, notifs) = {
        let vcpu = vm.vcpu(current_vcpu_id())?;
        vcpu.handle_maintenance_collect(gic)?
    };
    vm.dispatch_pirq_notifications(&notifs)?;
    apply_update(vm, gic, update)
}

fn apply_update(
    vm: &mut gic::vm::GicVmModelForVcpus<4>,
    gic: &Gicv2,
    update: VgicUpdate,
) -> Result<(), GicError> {
    let VgicUpdate::Some { targets, work } = update else {
        return Ok(());
    };
    if !work.refill {
        return Ok(());
    }
    let vcpu_id = current_vcpu_id();
    if !update_targets_include(targets, vcpu_id) {
        return Ok(());
    }
    let vcpu = vm.vcpu(vcpu_id)?;
    let _kick = vcpu.refill_lrs(gic)?;
    Ok(())
}

fn update_targets_include(targets: VgicTargets, vcpu_id: VcpuId) -> bool {
    match targets {
        VgicTargets::All => true,
        VgicTargets::One(id) => id == vcpu_id,
        VgicTargets::Mask(mask) => mask.contains(vcpu_id),
    }
}
