use arch_hal::cpu;
use arch_hal::gic::GicDistributor;
use arch_hal::gic::GicError;
use arch_hal::gic::IrqGroup;
use arch_hal::gic::IrqSense;
use arch_hal::gic::PIntId;
use arch_hal::gic::VIntId;
use arch_hal::gic::VcpuId;
use arch_hal::gic::VgicHw;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::Gicv2AccessSize;
use arch_hal::gic::gicv2::Gicv2DistIdRegs;
use arch_hal::gic::vm::PirqHookError;
use arch_hal::gic::vm::PirqHookOp;
use arch_hal::gic::vm::manager::VgicDelegate;
use arch_hal::gic::vm::manager::VgicManager;
use core::cell::SyncUnsafeCell;

use crate::Gicv2Info;
use crate::UartNode;
use crate::handler;
use crate::irq_monitor;

struct BootVgicDelegate;

static DELEGATE: BootVgicDelegate = BootVgicDelegate;
static VGIC: VgicManager<1> = VgicManager::new(&DELEGATE, 0);
static GICD_RANGE: SyncUnsafeCell<Option<(usize, usize)>> = SyncUnsafeCell::new(None);
static MAINT_INTID: SyncUnsafeCell<Option<u32>> = SyncUnsafeCell::new(None);
static GICD_ID: SyncUnsafeCell<Option<Gicv2DistIdRegs>> = SyncUnsafeCell::new(None);

impl VgicDelegate for BootVgicDelegate {
    fn distributor(&self) -> Result<&'static dyn GicDistributor, GicError> {
        handler::gic()
            .ok_or(GicError::InvalidState)
            .map(|gic| gic as &'static dyn GicDistributor)
    }

    fn get_resident_affinity(
        &self,
        _vm_id: usize,
        _vcpu_id: u16,
    ) -> Result<Option<cpu::CoreAffinity>, GicError> {
        Ok(Some(cpu::get_current_core_id()))
    }

    fn get_home_affinity(
        &self,
        _vm_id: usize,
        _vcpu_id: u16,
    ) -> Result<cpu::CoreAffinity, GicError> {
        Ok(cpu::get_current_core_id())
    }

    fn get_current_vcpu(&self, _vm_id: usize) -> Result<VcpuId, GicError> {
        Ok(VcpuId(0))
    }

    fn kick_pcpu(&self, _target: cpu::CoreAffinity) -> Result<(), GicError> {
        Ok(())
    }
}

fn boot_pirq_hook(int_id: u32, op: PirqHookOp) -> Result<(), PirqHookError> {
    match op {
        PirqHookOp::Eoi => irq_monitor::record_pirq_eoi(int_id),
        PirqHookOp::Deactivate => irq_monitor::record_pirq_deactivate(int_id),
        PirqHookOp::Enable { .. } | PirqHookOp::Route { .. } | PirqHookOp::Resample => {}
    }
    Ok(())
}

pub(crate) fn init(
    gic: &Gicv2,
    info: &Gicv2Info,
    guest_uart: UartNode,
) -> Result<(), &'static str> {
    gic.hw_init().map_err(|_| "vgic: hw init failed")?;

    // SAFETY: Boot path initializes vGIC once on the BSP before exposing concurrent access.
    // `VGIC` is a static manager, so model storage address remains stable for program lifetime.
    unsafe { VGIC.init_from_gicv2(gic, 1) }.map_err(|_| "vgic: create vm failed")?;

    VGIC.switch_in(gic, VcpuId(0), cpu::get_current_core_id())
        .map_err(|_| "vgic: switch in")?;

    if let Some(pintid) = guest_uart.irq {
        VGIC.map_pirq(
            gic,
            PIntId(pintid),
            VcpuId(0),
            VIntId(pintid),
            IrqSense::Level,
            IrqGroup::Group1,
            0x80,
        )
        .map_err(|_| "vgic: map pirq")?;
    }
    VGIC.set_pirq_hook(Some(boot_pirq_hook))
        .map_err(|_| "vgic: hooks")?;

    // SAFETY: vGIC state is initialized once before guest entry.
    unsafe {
        *GICD_RANGE.get() = Some((info.dist.base, info.dist.size));
        *MAINT_INTID.get() = info.maintenance_intid;
        *GICD_ID.get() = Some(Gicv2DistIdRegs::from_hw_gicd(gic.distributor()));
    }
    Ok(())
}

pub(crate) fn maintenance_intid() -> Option<u32> {
    // SAFETY: set during vGIC initialization and then read-only.
    unsafe { *MAINT_INTID.get() }
}

pub(crate) fn handles_gicd(addr: usize) -> bool {
    // SAFETY: range set once during init and then treated as read-only.
    let Some((base, size)) = (unsafe { *GICD_RANGE.get() }) else {
        return false;
    };
    (base..base + size).contains(&addr)
}

pub(crate) fn handle_gicd_read(addr: usize, access_size: Gicv2AccessSize) -> Result<u32, GicError> {
    // SAFETY: GICD range is initialized once before guest entry.
    let (base, _) = unsafe { (*GICD_RANGE.get()).ok_or(GicError::InvalidAddress)? };
    let offset = addr.saturating_sub(base) as u32;
    let dist_id = unsafe { (*GICD_ID.get()).ok_or(GicError::InvalidState)? };

    VGIC.handle_distributor_read(VcpuId(0), dist_id, offset, access_size)
}

pub(crate) fn handle_gicd_write(
    addr: usize,
    access_size: Gicv2AccessSize,
    value: u32,
) -> Result<(), GicError> {
    // SAFETY: GICD range is initialized once before guest entry.
    let (base, _) = unsafe { (*GICD_RANGE.get()).ok_or(GicError::InvalidAddress)? };
    let offset = addr.saturating_sub(base) as u32;
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let dist_id = unsafe { (*GICD_ID.get()).ok_or(GicError::InvalidState)? };

    VGIC.handle_distributor_write(gic, VcpuId(0), dist_id, offset, access_size, value)
}

pub(crate) fn on_physical_irq(intid: u32) -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let result = VGIC.handle_physical_irq(gic, PIntId(intid), true);
    irq_monitor::record_injected_pirq(intid, result.is_ok());
    result
}

pub(crate) fn handle_maintenance_irq() -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    VGIC.handle_maintenance(gic, VcpuId(0))
}
