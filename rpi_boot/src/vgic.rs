use arch_hal::cpu;
use arch_hal::gic::GicDistributor;
use arch_hal::gic::GicError;
use arch_hal::gic::GicPpi;
use arch_hal::gic::GicSgi;
use arch_hal::gic::IrqGroup;
use arch_hal::gic::IrqSense;
use arch_hal::gic::PIntId;
use arch_hal::gic::SgiTarget;
use arch_hal::gic::VIntId;
use arch_hal::gic::VcpuId;
use arch_hal::gic::VgicHw;
use arch_hal::gic::gicv2::Gicv2;
use arch_hal::gic::gicv2::Gicv2AccessSize;
use arch_hal::gic::gicv2::Gicv2DistIdRegs;
use arch_hal::gic::vm::PirqHooks;
use arch_hal::gic::vm::manager::VgicDelegate;
use arch_hal::gic::vm::manager::VgicManager;
use arch_hal::soc::bcm2712::rp1_interrupt;
use core::cell::SyncUnsafeCell;
use core::ptr;
use core::ptr::slice_from_raw_parts_mut;
use typestate::ReadWrite;

use crate::Gicv2Info;
use crate::RP1_BASE;
use crate::handler;

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

struct RpiVgicDelegate;

static DELEGATE: RpiVgicDelegate = RpiVgicDelegate;
static VGIC: VgicManager<VCPU_COUNT> = VgicManager::new(&DELEGATE, 0);
static GICD_RANGE: SyncUnsafeCell<Option<(usize, usize)>> = SyncUnsafeCell::new(None);
static MAINT_INTID: SyncUnsafeCell<Option<u32>> = SyncUnsafeCell::new(None);
static GICD_ID: SyncUnsafeCell<Option<Gicv2DistIdRegs>> = SyncUnsafeCell::new(None);

impl VgicDelegate for RpiVgicDelegate {
    fn distributor(&self) -> Result<&'static dyn GicDistributor, GicError> {
        handler::gic()
            .ok_or(GicError::InvalidState)
            .map(|gic| gic as &'static dyn GicDistributor)
    }

    fn get_resident_affinity(
        &self,
        _vm_id: usize,
        vcpu_id: u16,
    ) -> Result<Option<cpu::CoreAffinity>, GicError> {
        Ok(Some(vcpu_id_to_affinity(VcpuId(vcpu_id))?))
    }

    fn get_home_affinity(
        &self,
        _vm_id: usize,
        vcpu_id: u16,
    ) -> Result<cpu::CoreAffinity, GicError> {
        vcpu_id_to_affinity(VcpuId(vcpu_id))
    }

    fn get_current_vcpu(&self, _vm_id: usize) -> Result<VcpuId, GicError> {
        current_vcpu_id()
    }

    fn kick_pcpu(&self, target: cpu::CoreAffinity) -> Result<(), GicError> {
        let gic = handler::gic().ok_or(GicError::InvalidState)?;
        let targets = [target];
        gic.send_sgi(KICK_SGI_ID, SgiTarget::Specific(&targets))
    }
}

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

pub fn init(gic: &Gicv2, info: &Gicv2Info, uart_irq: Option<UartIrq>) -> Result<(), &'static str> {
    gic.hw_init().map_err(|_| "vgic: hw init failed")?;
    enable_guest_ppis(gic).map_err(|_| "vgic: enable guest ppis")?;

    VGIC.init_from_gicv2(gic, VCPU_COUNT as u8)
        .map_err(|_| "vgic: create vm failed")?;

    let boot_vcpu_id = current_vcpu_id().map_err(|_| "vgic: invalid vcpu id")?;
    VGIC.switch_in(gic, boot_vcpu_id, cpu::get_current_core_id())
        .map_err(|_| "vgic: switch in")?;

    if let Some(uart_irq) = uart_irq {
        VGIC.map_pirq(
            gic,
            PIntId(uart_irq.pintid),
            boot_vcpu_id,
            VIntId(uart_irq.pintid),
            uart_irq.sense,
            IrqGroup::Group1,
            DEFAULT_SPI_PRIORITY,
        )
        .map_err(|_| "vgic: map pirq")?;

        let hooks = PirqHooks {
            ctx: ptr::null_mut(),
            on_enable: Some(hook_toggle_rp1_msix),
            on_route: None,
            on_eoi: Some(hook_rp1_msix_eoi),
            on_deactivate: None,
            on_resample: None,
        };
        VGIC.set_pirq_hooks(PIntId(uart_irq.pintid), hooks)
            .map_err(|_| "vgic: hooks")?;
    }

    let generic_hooks = VGIC.passthrough_spi_hooks();
    for intid in 32..1020 {
        if intid >= MIP_SPI_OFFSET + 32 {
            continue;
        }
        let pintid = PIntId(intid);
        match VGIC.map_pirq(
            gic,
            pintid,
            boot_vcpu_id,
            VIntId(intid),
            IrqSense::Level,
            IrqGroup::Group1,
            DEFAULT_SPI_PRIORITY,
        ) {
            Ok(()) => {}
            Err(GicError::InvalidState) => continue,
            Err(_) => return Err("vgic: map pirq"),
        }
        VGIC.set_pirq_hooks(pintid, generic_hooks)
            .map_err(|_| "vgic: hooks")?;
    }

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
    gic.hw_init()?;
    VGIC.switch_in(gic, current_vcpu_id()?, cpu::get_current_core_id())
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

    VGIC.handle_distributor_read(current_vcpu_id()?, dist_id, offset, access_size)
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

    VGIC.handle_distributor_write(gic, current_vcpu_id()?, dist_id, offset, access_size, value)
}

pub fn on_physical_irq(pintid: PIntId, level: bool) -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    VGIC.handle_physical_irq(gic, pintid, level)
}

pub fn passthrough_physical_irq(intid: u32, level: bool) -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    VGIC.inject_physical_irq_as_pending(gic, intid, level)
}

pub fn handle_maintenance_irq() -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    VGIC.handle_maintenance(gic, current_vcpu_id()?)
}

pub fn handle_kick_sgi() -> Result<(), GicError> {
    let gic = handler::gic().ok_or(GicError::InvalidState)?;
    let _kick = VGIC.refill_vcpu(gic, current_vcpu_id()?)?;
    Ok(())
}
