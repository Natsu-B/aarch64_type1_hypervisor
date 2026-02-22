use super::GicVmModelForVcpus;
use super::PirqHooks;
use super::common::LOCAL_INTID_COUNT;
use super::pending_cap_for_vcpus;
use crate::GicDistributor;
use crate::GicError;
use crate::IrqGroup;
use crate::IrqSense;
use crate::PIntId;
use crate::SpiRoute;
use crate::VIntId;
use crate::VSpiRouting;
use crate::VcpuId;
use crate::VgicGuestRegs;
use crate::VgicHw;
use crate::VgicIrqScope;
use crate::VgicPirqModel;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVmInfo;
use crate::gicv2::Gicv2;
use crate::gicv2::vgic_frontend::Gicv2AccessSize;
use crate::gicv2::vgic_frontend::Gicv2DistIdRegs;
use crate::gicv2::vgic_frontend::Gicv2Frontend;
use aarch64_mutex::RawSpinLockIrqSave;
use cpu::CoreAffinity;

/// Platform policy callbacks used by [`VgicManager`].
///
/// All methods must be non-blocking because they can be called while the VM model spinlock is held.
pub trait VgicDelegate: Send + Sync {
    fn distributor(&self) -> Result<&'static dyn GicDistributor, GicError>;
    fn get_resident_affinity(
        &self,
        vm_id: usize,
        vcpu_id: u16,
    ) -> Result<Option<CoreAffinity>, GicError>;
    fn get_home_affinity(&self, vm_id: usize, vcpu_id: u16) -> Result<CoreAffinity, GicError>;
    fn get_current_vcpu(&self, vm_id: usize) -> Result<VcpuId, GicError>;
    fn kick_pcpu(&self, target: CoreAffinity) -> Result<(), GicError>;
}

pub struct VgicManager<const VCPUS: usize>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    delegate: &'static dyn VgicDelegate,
    vm_id: usize,
    model: RawSpinLockIrqSave<Option<GicVmModelForVcpus<VCPUS>>>,
}

impl<const VCPUS: usize> VgicManager<VCPUS>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    pub const fn new(delegate: &'static dyn VgicDelegate, vm_id: usize) -> Self {
        Self {
            delegate,
            vm_id,
            model: RawSpinLockIrqSave::new(None),
        }
    }

    fn init(&self, model: GicVmModelForVcpus<VCPUS>) -> Result<(), GicError> {
        let mut guard = self.model.lock_irqsave();
        if guard.is_some() {
            return Err(GicError::InvalidState);
        }
        *guard = Some(model);
        Ok(())
    }

    pub fn init_from_gicv2(&self, gic: &Gicv2, vcpu_count: u8) -> Result<(), GicError>
    where
        [(); VCPUS - 1]:,
        [(); 16 - VCPUS]:,
    {
        let model = gic.create_vm_model::<VCPUS>(vcpu_count)?;
        self.init(model)
    }

    fn with_model_mut<R>(
        &self,
        f: impl FnOnce(&mut GicVmModelForVcpus<VCPUS>) -> Result<R, GicError>,
    ) -> Result<R, GicError> {
        let mut guard = self.model.lock_irqsave();
        let vm = guard.as_mut().ok_or(GicError::InvalidState)?;
        f(vm)
    }

    pub fn switch_in<H: VgicHw>(
        &self,
        hw: &H,
        vcpu: VcpuId,
        core: CoreAffinity,
    ) -> Result<(), GicError> {
        self.with_model_mut(|vm| {
            let vcpu_model = <GicVmModelForVcpus<VCPUS> as VgicVmInfo>::vcpu(vm, vcpu)?;
            vcpu_model.set_resident(core)?;
            let _kick = vcpu_model.refill_lrs(hw)?;
            Ok(())
        })?;
        hw.set_enabled(true)?;
        Ok(())
    }

    pub fn switch_out_sync<H: VgicHw>(&self, hw: &H, vcpu: VcpuId) -> Result<(), GicError> {
        self.with_model_mut(|vm| {
            let vcpu_model = <GicVmModelForVcpus<VCPUS> as VgicVmInfo>::vcpu(vm, vcpu)?;
            vcpu_model.switch_out_sync(hw)
        })
    }

    pub fn handle_physical_irq<H: VgicHw>(
        &self,
        hw: &H,
        pintid: PIntId,
        level: bool,
    ) -> Result<(), GicError> {
        let update = self.with_model_mut(|vm| vm.on_physical_irq(pintid, level))?;
        self.apply_update(hw, update)
    }

    pub fn inject_ppi<H: VgicHw>(
        &self,
        hw: &H,
        ppi_intid: u32,
        level: bool,
    ) -> Result<(), GicError> {
        let current = self.delegate.get_current_vcpu(self.vm_id)?;
        let update = self.with_model_mut(|vm| {
            vm.set_pending(VgicIrqScope::Local(current), VIntId(ppi_intid), level)
        })?;
        self.apply_update(hw, update)
    }

    pub fn inject_physical_irq_as_pending<H: VgicHw>(
        &self,
        hw: &H,
        intid: u32,
        level: bool,
    ) -> Result<(), GicError> {
        let current = self.delegate.get_current_vcpu(self.vm_id)?;
        let scope = if intid < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(current)
        } else {
            VgicIrqScope::Global
        };
        let update = self.with_model_mut(|vm| vm.set_pending(scope, VIntId(intid), level))?;
        self.apply_update(hw, update)
    }

    pub fn map_pirq<H: VgicHw>(
        &self,
        hw: &H,
        pintid: PIntId,
        target: VcpuId,
        vintid: VIntId,
        sense: IrqSense,
        group: IrqGroup,
        priority: u8,
    ) -> Result<(), GicError> {
        let update =
            self.with_model_mut(|vm| vm.map_pirq(pintid, target, vintid, sense, group, priority))?;
        self.apply_update(hw, update)
    }

    pub fn set_pirq_hooks(&self, pintid: PIntId, hooks: PirqHooks) -> Result<(), GicError> {
        self.with_model_mut(|vm| vm.set_pirq_hooks(pintid, hooks))
    }

    pub fn handle_distributor_read(
        &self,
        vcpu: VcpuId,
        dist_id: Gicv2DistIdRegs,
        offset: u32,
        access_size: Gicv2AccessSize,
    ) -> Result<u32, GicError> {
        self.with_model_mut(|vm| {
            let mut frontend = Gicv2Frontend::new(vm, dist_id);
            frontend.handle_distributor_read(vcpu, offset, access_size)
        })
    }

    pub fn handle_distributor_write<H: VgicHw>(
        &self,
        hw: &H,
        vcpu: VcpuId,
        dist_id: Gicv2DistIdRegs,
        offset: u32,
        access_size: Gicv2AccessSize,
        value: u32,
    ) -> Result<(), GicError> {
        let update = self.with_model_mut(|vm| {
            let mut frontend = Gicv2Frontend::new(vm, dist_id);
            frontend.handle_distributor_write(vcpu, offset, access_size, value)
        })?;
        self.apply_update(hw, update)
    }

    pub fn handle_maintenance<H: VgicHw>(&self, hw: &H, vcpu: VcpuId) -> Result<(), GicError> {
        let update = self.with_model_mut(|vm| {
            let (update, notifs) = {
                let vcpu_model = <GicVmModelForVcpus<VCPUS> as VgicVmInfo>::vcpu(vm, vcpu)?;
                vcpu_model.handle_maintenance_collect(hw)?
            };
            vm.dispatch_pirq_notifications(&notifs)?;
            Ok(update)
        })?;
        self.apply_update(hw, update)
    }

    pub fn refill_vcpu<H: VgicHw>(&self, hw: &H, vcpu: VcpuId) -> Result<bool, GicError> {
        self.with_model_mut(|vm| {
            let vcpu_model = <GicVmModelForVcpus<VCPUS> as VgicVmInfo>::vcpu(vm, vcpu)?;
            vcpu_model.refill_lrs(hw)
        })
    }

    pub(crate) fn apply_update<H: VgicHw>(
        &self,
        hw: &H,
        update: VgicUpdate,
    ) -> Result<(), GicError> {
        let VgicUpdate::Some { targets, work } = update else {
            return Ok(());
        };
        if !work.refill {
            return Ok(());
        }

        let current = self.delegate.get_current_vcpu(self.vm_id)?;
        let mut kick_targets: [Option<CoreAffinity>; VCPUS] = [None; VCPUS];
        let mut kick_count = 0usize;

        self.with_model_mut(|vm| {
            let mut maybe_queue_kick = |target: VcpuId| -> Result<(), GicError> {
                let vcpu = <GicVmModelForVcpus<VCPUS> as VgicVmInfo>::vcpu(vm, target)?;
                let needs_kick = vcpu.refill_lrs(hw)?;
                if target == current || (!work.kick && !needs_kick) {
                    return Ok(());
                }
                let Some(affinity) = self.delegate.get_resident_affinity(self.vm_id, target.0)?
                else {
                    return Ok(());
                };

                if kick_count >= kick_targets.len() {
                    return Err(GicError::OutOfResources);
                }
                if kick_targets[..kick_count]
                    .iter()
                    .any(|existing| *existing == Some(affinity))
                {
                    return Ok(());
                }
                kick_targets[kick_count] = Some(affinity);
                kick_count += 1;
                Ok(())
            };

            match targets {
                VgicTargets::One(id) => maybe_queue_kick(id)?,
                VgicTargets::Mask(mask) => {
                    for id in mask.iter() {
                        maybe_queue_kick(id)?;
                    }
                }
                VgicTargets::All => {
                    for id in 0..vm.vcpu_count() {
                        maybe_queue_kick(VcpuId(id))?;
                    }
                }
            }
            Ok(())
        })?;

        for affinity in kick_targets.into_iter().take(kick_count).flatten() {
            self.delegate.kick_pcpu(affinity)?;
        }
        Ok(())
    }

    pub fn passthrough_spi_hooks(&'static self) -> PirqHooks {
        PirqHooks {
            ctx: self as *const _ as *mut (),
            on_enable: Some(hook_toggle_passthrough_spi::<VCPUS>),
            on_route: Some(hook_route_passthrough_spi::<VCPUS>),
            on_eoi: None,
            on_deactivate: None,
            on_resample: None,
        }
    }
}

unsafe fn manager_from_ctx<const VCPUS: usize>(
    ctx: *mut (),
) -> Result<&'static VgicManager<VCPUS>, GicError>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    if ctx.is_null() {
        return Err(GicError::InvalidState);
    }
    // SAFETY: `ctx` was created by `VgicManager::passthrough_spi_hooks` from a stable `'static`
    // manager reference with the same `VCPUS` parameter.
    Ok(unsafe { &*(ctx as *const VgicManager<VCPUS>) })
}

unsafe fn hook_toggle_passthrough_spi<const VCPUS: usize>(
    ctx: *mut (),
    pintid: PIntId,
    enable: bool,
) -> Result<(), GicError>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    // SAFETY: The callback context is set by `passthrough_spi_hooks` to point to the same static
    // manager instance for this const-generic instantiation.
    let manager = unsafe { manager_from_ctx::<VCPUS>(ctx)? };
    manager
        .delegate
        .distributor()?
        .set_spi_enable(pintid.0, enable)
}

unsafe fn hook_route_passthrough_spi<const VCPUS: usize>(
    ctx: *mut (),
    pintid: PIntId,
    route: VSpiRouting,
) -> Result<(), GicError>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    // SAFETY: The callback context is set by `passthrough_spi_hooks` to point to the same static
    // manager instance for this const-generic instantiation.
    let manager = unsafe { manager_from_ctx::<VCPUS>(ctx)? };
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
    let affinity = manager
        .delegate
        .get_home_affinity(manager.vm_id, target.0)?;
    manager
        .delegate
        .distributor()?
        .set_spi_route(pintid.0, SpiRoute::Specific(affinity))
}
