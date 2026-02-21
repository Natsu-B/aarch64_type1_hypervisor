use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::cpu;
use arch_hal::gic;
use arch_hal::gic::GicDistributor;
use arch_hal::gic::GicError;
use arch_hal::gic::GicPpi;
use arch_hal::gic::GicSgi;
use arch_hal::gic::IrqGroup;
use arch_hal::gic::IrqSense;
use arch_hal::gic::PIntId;
use arch_hal::gic::SgiTarget;
use arch_hal::gic::SpiRoute;
use arch_hal::gic::VIntId;
use arch_hal::gic::VSpiRouting;
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

static VGIC_VM: RawSpinLockIrqSave<Option<gic::vm::GicVmModelForVcpus<VCPU_COUNT>>> =
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
const VCPU_COUNT: usize = 4;
const DEFAULT_SPI_PRIORITY: u8 = 0x80;
const KICK_SGI_ID: u8 = 15;
const KICK_INTID: u32 = KICK_SGI_ID as u32;

fn enable_guest_ppis(gic: &Gicv2) -> Result<(), GicError> {
    for ppi in 16..32 {
        if matches!(ppi, 25 | 26 | 29) {
            continue;
        }
        gic.set_ppi_enable(ppi, true)?;
    }
    Ok(())
}

fn current_vcpu_id() -> Result<VcpuId, GicError> {
    let core_id = cpu::get_current_core_id();
    let vcpu_id = VcpuId(core_id.aff0 as u16);
    if (vcpu_id.0 as usize) >= VCPU_COUNT {
        return Err(GicError::InvalidVcpuId);
    }
    Ok(vcpu_id)
}

fn vcpu_id_to_affinity(vcpu_id: VcpuId) -> Result<cpu::CoreAffinity, GicError> {
    let aff0 = u8::try_from(vcpu_id.0).map_err(|_| GicError::InvalidVcpuId)?;
    Ok(cpu::CoreAffinity::new(aff0, 0, 0, 0))
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

unsafe fn hook_toggle_passthrough_spi(
    _ctx: *mut (),
    pintid: PIntId,
    enable: bool,
) -> Result<(), GicError> {
    // SAFETY: Called by the vGIC with exclusive access to VM state; uses a global GIC reference
    // to perform bounded, non-blocking MMIO configuration.
    let Some(gic) = handler::gic() else {
        return Err(GicError::InvalidState);
    };
    gic.set_spi_enable(pintid.0, enable)
}

unsafe fn hook_route_passthrough_spi(
    _ctx: *mut (),
    pintid: PIntId,
    route: VSpiRouting,
) -> Result<(), GicError> {
    // SAFETY: Called by the vGIC with exclusive access to VM state; uses a global GIC reference
    // to perform bounded, non-blocking MMIO configuration.
    let Some(gic) = handler::gic() else {
        return Err(GicError::InvalidState);
    };
    let target = match route {
        VSpiRouting::Targets(mask) => {
            let Some(vcpu_id) = mask.iter().next() else {
                return Ok(());
            };
            vcpu_id
        }
        VSpiRouting::Specific(_) | VSpiRouting::AnyParticipating => {
            return Err(GicError::UnsupportedFeature);
        }
    };
    let affinity = vcpu_id_to_affinity(target)?;
    gic.set_spi_route(pintid.0, SpiRoute::Specific(affinity))
}

pub fn init(gic: &Gicv2, info: &Gicv2Info, uart_irq: Option<UartIrq>) -> Result<(), &'static str> {
    gic.hw_init().map_err(|_| "vgic: hw init failed")?;
    enable_guest_ppis(gic).map_err(|_| "vgic: enable guest ppis")?;

    let mut guard = VGIC_VM.lock_irqsave();
    if guard.is_some() {
        return Err("vgic: already initialized");
    }
    *guard = Some(
        gic.create_vm_model::<VCPU_COUNT>(VCPU_COUNT as u8)
            .map_err(|_| "vgic: create vm failed")?,
    );
    let vm = guard.as_mut().unwrap();
    let boot_vcpu_id = current_vcpu_id().map_err(|_| "vgic: invalid vcpu id")?;

    {
        let vcpu = vm.vcpu(boot_vcpu_id).map_err(|_| "vgic: vcpu")?;
        vcpu.set_resident(cpu::get_current_core_id())
            .map_err(|_| "vgic: set resident")?;
    }

    if let Some(uart_irq) = uart_irq {
        let update = vm
            .map_pirq(
                PIntId(uart_irq.pintid),
                boot_vcpu_id,
                VIntId(uart_irq.pintid),
                uart_irq.sense,
                IrqGroup::Group1,
                DEFAULT_SPI_PRIORITY,
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

    let generic_hooks = PirqHooks {
        ctx: ptr::null_mut(),
        on_enable: Some(hook_toggle_passthrough_spi),
        on_route: Some(hook_route_passthrough_spi),
        on_eoi: None,
        on_deactivate: None,
        on_resample: None,
    };
    for intid in 32..1020 {
        if intid >= MIP_SPI_OFFSET + 32 {
            continue;
        }
        let pintid = PIntId(intid);
        let update = match vm.map_pirq(
            pintid,
            boot_vcpu_id,
            VIntId(intid),
            IrqSense::Level,
            IrqGroup::Group1,
            DEFAULT_SPI_PRIORITY,
        ) {
            Ok(update) => update,
            Err(GicError::InvalidState) => continue,
            Err(_) => return Err("vgic: map pirq"),
        };
        apply_update(vm, gic, update).map_err(|_| "vgic: update")?;
        vm.set_pirq_hooks(pintid, generic_hooks)
            .map_err(|_| "vgic: hooks")?;
    }

    let vcpu = vm.vcpu(boot_vcpu_id).map_err(|_| "vgic: vcpu")?;
    vcpu.refill_lrs(gic).map_err(|_| "vgic: refill")?;

    // SAFETY: vGIC state is initialized once before guest entry.
    unsafe {
        *GICD_RANGE.get() = Some((info.dist.base, info.dist.size));
        *MAINT_INTID.get() = info.maintenance_intid;
        *GICD_ID.get() = Some(Gicv2DistIdRegs::from_hw_gicd(gic.distributor()));
    }
    Ok(())
}

pub fn on_cpu_online(gic: &Gicv2) -> Result<(), GicError> {
    enable_guest_ppis(gic)?;

    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let vcpu_id = current_vcpu_id()?;
    let vcpu = vm.vcpu(vcpu_id)?;
    vcpu.set_resident(cpu::get_current_core_id())?;
    let _kick = vcpu.refill_lrs(gic)?;
    Ok(())
}

pub fn maintenance_intid() -> Option<u32> {
    // SAFETY: set during vGIC initialization and then read-only.
    unsafe { *MAINT_INTID.get() }
}

pub fn kick_sgi_intid() -> u32 {
    KICK_INTID
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
    frontend.handle_distributor_read(current_vcpu_id()?, offset, access_size)
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
        frontend.handle_distributor_write(current_vcpu_id()?, offset, access_size, value)?;
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
        VgicIrqScope::Local(current_vcpu_id()?)
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
        let vcpu = vm.vcpu(current_vcpu_id()?)?;
        vcpu.handle_maintenance_collect(gic)?
    };
    vm.dispatch_pirq_notifications(&notifs)?;
    apply_update(vm, gic, update)
}

pub fn handle_kick_sgi() -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let mut guard = VGIC_VM.lock_irqsave();
    let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
    let vcpu = vm.vcpu(current_vcpu_id()?)?;
    let _kick = vcpu.refill_lrs(gic)?;
    Ok(())
}

fn apply_update(
    vm: &mut gic::vm::GicVmModelForVcpus<VCPU_COUNT>,
    gic: &Gicv2,
    update: VgicUpdate,
) -> Result<(), GicError> {
    let VgicUpdate::Some { targets, work } = update else {
        return Ok(());
    };
    if !work.refill {
        return Ok(());
    }
    let current = current_vcpu_id()?;
    let vcpu_count = vm.vcpu_count();
    let handle_target = |target: VcpuId| -> Result<(), GicError> {
        let vcpu = vm.vcpu(target)?;
        let needs_kick = vcpu.refill_lrs(gic)?;
        if target != current && (work.kick || needs_kick) {
            let affinity = vcpu_id_to_affinity(target)?;
            let targets = [affinity];
            gic.send_sgi(KICK_SGI_ID, SgiTarget::Specific(&targets))?;
        }
        Ok(())
    };
    match targets {
        VgicTargets::One(id) => handle_target(id)?,
        VgicTargets::Mask(mask) => {
            for id in mask.iter() {
                handle_target(id)?;
            }
        }
        VgicTargets::All => {
            for id in 0..vcpu_count {
                handle_target(VcpuId(id))?;
            }
        }
    }
    Ok(())
}
