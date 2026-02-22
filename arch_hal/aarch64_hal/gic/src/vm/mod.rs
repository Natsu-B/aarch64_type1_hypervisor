use self::common::LOCAL_INTID_COUNT;
use self::common::VmCommon;
use self::v2_ext::V2SgiState;
use crate::GicError;
use crate::IrqGroup;
use crate::IrqSense;
use crate::PIntId;
use crate::TriggerMode;
use crate::VIntId;
use crate::VSpiRouting;
use crate::VcpuId;
use crate::VcpuMask;
use crate::VgicGuestRegs;
use crate::VgicIrqScope;
use crate::VgicPirqModel;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::VgicVmInfo;
use crate::VgicWork;
use crate::vm::vcpu::GicVCpuGeneric;
pub use ::common::PirqHookError;
pub use ::common::PirqHookFn;
pub use ::common::PirqHookOp;
use aarch64_mutex::RawSpinLockIrqSave;

pub(crate) mod common;
pub mod manager;
mod v2_ext;
pub(crate) mod vcpu;

pub(crate) use common::SGI_COUNT;

pub const fn pending_cap_for_vcpus(vcpus: usize) -> usize {
    crate::max_intids_for_vcpus(vcpus)
        .saturating_sub(SGI_COUNT)
        .saturating_add(SGI_COUNT.saturating_mul(vcpus))
}

/// Virtual Distributor model: per-vCPU private state for INTIDs 0-31 and shared SPI state for 32+.
pub(crate) struct GicVmModelGeneric<const VCPUS: usize, V: VgicVcpuModel>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
{
    common: VmCommon<VCPUS, V>,
    v2: RawSpinLockIrqSave<V2SgiState<VCPUS>>,
}

pub(crate) type GicVmModelForVcpus<const VCPUS: usize> = GicVmModelGeneric<
    VCPUS,
    GicVCpuGeneric<
        VCPUS,
        { crate::max_intids_for_vcpus(VCPUS) },
        { crate::VgicVmConfig::<VCPUS>::MAX_LRS },
        { pending_cap_for_vcpus(VCPUS) },
    >,
>;

impl<const VCPUS: usize>
    GicVmModelGeneric<
        VCPUS,
        GicVCpuGeneric<
            VCPUS,
            { crate::max_intids_for_vcpus(VCPUS) },
            { crate::VgicVmConfig::<VCPUS>::MAX_LRS },
            { pending_cap_for_vcpus(VCPUS) },
        >,
    >
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
{
    /// Construct a VM with vCPU ids fixed to `VcpuId(0..vcpu_count-1)`; callers must not assume
    /// alternative vCPU id mappings when using this backend.
    pub(crate) fn new(vcpu_count: u16) -> Result<Self, GicError> {
        Self::new_with(vcpu_count, |id| GicVCpuGeneric::with_id(id))
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel> GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
{
    const fn global_intids() -> usize {
        crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT
    }

    /// Construct a VM with vCPU ids fixed to `VcpuId(0..vcpu_count-1)`; custom mappings are not
    /// supported because CPUID fields and banked Distributor state rely on contiguous ids.
    pub(crate) fn new_with(
        vcpu_count: u16,
        make: impl FnMut(VcpuId) -> V,
    ) -> Result<Self, GicError> {
        let vcpu_count_usize = vcpu_count as usize;
        if vcpu_count_usize == 0 {
            return Err(GicError::InvalidVcpuId);
        }
        if vcpu_count_usize > VCPUS {
            return Err(GicError::OutOfResources);
        }

        Ok(Self {
            common: VmCommon::new(vcpu_count_usize, make)?,
            v2: RawSpinLockIrqSave::new(V2SgiState::new()),
        })
    }

    fn update_for_scope(scope: VgicIrqScope, changed: bool) -> VgicUpdate {
        if !changed {
            return VgicUpdate::None;
        }
        let targets = match scope {
            VgicIrqScope::Local(vcpu) => VgicTargets::One(vcpu),
            VgicIrqScope::Global => VgicTargets::All,
        };
        VgicUpdate::Some {
            targets,
            work: VgicWork::REFILL,
        }
    }

    pub(crate) fn set_pirq_manager_ctx(&self, ctx: *mut ()) {
        let mut routing = self.common.routing_lock.lock_irqsave();
        routing.pirq_manager_ctx = ctx;
    }

    pub(crate) fn set_pirq_hook(&self, hook: Option<PirqHookFn>) {
        let mut routing = self.common.routing_lock.lock_irqsave();
        routing.pirq_hook = hook;
    }

    fn pirq_hook_snapshot(&self) -> (*mut (), Option<PirqHookFn>) {
        let routing = self.common.routing_lock.lock_irqsave();
        (routing.pirq_manager_ctx, routing.pirq_hook)
    }

    fn map_pirq_hook_error(err: PirqHookError) -> GicError {
        match err {
            PirqHookError::InvalidState => GicError::InvalidState,
            PirqHookError::Unsupported => GicError::UnsupportedFeature,
            PirqHookError::InvalidInput => GicError::UnsupportedIntId,
        }
    }

    fn route_targets_to_bits(mask: VcpuMask) -> Result<u32, PirqHookError> {
        let mut bits = 0u32;
        for target in mask.iter() {
            if target.0 >= 32 {
                return Err(PirqHookError::Unsupported);
            }
            bits |= 1u32 << target.0;
        }
        Ok(bits)
    }

    pub(crate) fn dispatch_pirq_notifications(
        &self,
        notifs: &crate::PirqNotifications,
    ) -> Result<(), GicError> {
        for pintid in notifs.eoi.iter() {
            self.call_pirq_signal_hook(pintid, PirqHookOp::Eoi)?;
        }
        for pintid in notifs.deactivate.iter() {
            self.call_pirq_signal_hook(pintid, PirqHookOp::Deactivate)?;
        }
        for pintid in notifs.resample.iter() {
            self.call_pirq_signal_hook(pintid, PirqHookOp::Resample)?;
        }
        Ok(())
    }

    fn call_pirq_enable_hook(&self, pintid: PIntId, enable: bool) -> Result<(), GicError>
    where
        [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
        [(); pending_cap_for_vcpus(VCPUS)]:,
    {
        let (ctx, hook) = self.pirq_hook_snapshot();
        if enable {
            if !ctx.is_null() {
                // SAFETY: `ctx` is installed by the manager and points to a stable `VgicManager`
                // for this VM model instance. This call happens after dropping VM locks.
                unsafe {
                    manager::passthrough_spi_enable_from_ctx::<VCPUS>(ctx, pintid, true)?;
                }
            }
            if let Some(hook) = hook {
                hook(pintid.0, PirqHookOp::Enable { enable: true })
                    .map_err(Self::map_pirq_hook_error)?;
            }
        } else {
            if let Some(hook) = hook {
                hook(pintid.0, PirqHookOp::Enable { enable: false })
                    .map_err(Self::map_pirq_hook_error)?;
            }
            if !ctx.is_null() {
                // SAFETY: `ctx` is installed by the manager and points to a stable `VgicManager`
                // for this VM model instance. This call happens after dropping VM locks.
                unsafe {
                    manager::passthrough_spi_enable_from_ctx::<VCPUS>(ctx, pintid, false)?;
                }
            }
        }
        Ok(())
    }

    fn call_pirq_route_hook(&self, pintid: PIntId, route: VSpiRouting) -> Result<(), GicError>
    where
        [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
        [(); pending_cap_for_vcpus(VCPUS)]:,
    {
        let (ctx, hook) = self.pirq_hook_snapshot();
        if !ctx.is_null() {
            // SAFETY: `ctx` is installed by the manager and points to a stable `VgicManager`
            // for this VM model instance. This call happens after dropping VM locks.
            unsafe {
                manager::passthrough_spi_route_from_ctx::<VCPUS>(ctx, pintid, route)?;
            }
        }

        if let Some(hook) = hook {
            let targets = match route {
                VSpiRouting::Targets(mask) => {
                    Self::route_targets_to_bits(mask).map_err(Self::map_pirq_hook_error)?
                }
                VSpiRouting::Specific(_) | VSpiRouting::AnyParticipating => {
                    return Err(GicError::UnsupportedFeature);
                }
            };
            hook(pintid.0, PirqHookOp::Route { targets }).map_err(Self::map_pirq_hook_error)?;
        }
        Ok(())
    }

    fn call_pirq_signal_hook(&self, pintid: PIntId, op: PirqHookOp) -> Result<(), GicError> {
        let (_, hook) = self.pirq_hook_snapshot();
        if let Some(hook) = hook {
            hook(pintid.0, op).map_err(Self::map_pirq_hook_error)?;
        }
        Ok(())
    }

    fn pirq_for_vintid(&self, vintid: VIntId) -> Option<PIntId> {
        let routing = self.common.routing_lock.lock_irqsave();
        routing.pirqs.v2p(vintid)
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel> VgicVmInfo for GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
{
    type VcpuModel = V;

    fn vcpu_count(&self) -> u16 {
        self.common.vcpu_count() as u16
    }

    fn vcpu(&self, id: VcpuId) -> Result<&Self::VcpuModel, GicError> {
        self.common.vcpu(id)
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> VgicGuestRegs
    for GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    fn set_dist_enable(
        &self,
        enable_grp0: bool,
        enable_grp1: bool,
    ) -> Result<VgicUpdate, GicError> {
        let (prev, changed) = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            let prev = regs.dist_enable;
            let next = (enable_grp0, enable_grp1);
            let changed = prev != next;
            regs.dist_enable = next;
            (prev, changed)
        };

        let mut update = VgicUpdate::None;
        if (!prev.0 && enable_grp0) || (!prev.1 && enable_grp1) {
            for vcpu_idx in 0..self.common.vcpu_count() {
                let vcpu = VcpuId(vcpu_idx as u16);
                for intid in 0..LOCAL_INTID_COUNT {
                    if intid < SGI_COUNT {
                        continue;
                    }
                    let vintid = VIntId(intid as u32);
                    let attrs = self.common.irq_attrs(VgicIrqScope::Local(vcpu), vintid)?;
                    let group_enabled = match attrs.group {
                        IrqGroup::Group0 => enable_grp0,
                        IrqGroup::Group1 => enable_grp1,
                    };
                    if attrs.pending && attrs.enable && group_enabled {
                        update.combine(&self.common.maybe_enqueue_irq(
                            VgicIrqScope::Local(vcpu),
                            vintid,
                            None,
                        )?);
                    }
                }
                for sgi in 0..SGI_COUNT {
                    let attrs = self
                        .common
                        .irq_attrs(VgicIrqScope::Local(vcpu), VIntId(sgi as u32))?;
                    let group_enabled = match attrs.group {
                        IrqGroup::Group0 => enable_grp0,
                        IrqGroup::Group1 => enable_grp1,
                    };
                    if attrs.pending && attrs.enable && group_enabled {
                        update.combine(&self.enqueue_sgi_for_target(vcpu, sgi)?);
                    }
                }
            }

            for spi_idx in 0..Self::global_intids() {
                let vintid = VIntId((LOCAL_INTID_COUNT + spi_idx) as u32);
                let attrs = self.common.irq_attrs(VgicIrqScope::Global, vintid)?;
                let group_enabled = match attrs.group {
                    IrqGroup::Group0 => enable_grp0,
                    IrqGroup::Group1 => enable_grp1,
                };
                if attrs.pending && attrs.enable && group_enabled {
                    update.combine(&self.common.maybe_enqueue_irq(
                        VgicIrqScope::Global,
                        vintid,
                        None,
                    )?);
                }
            }
        }

        update.combine(&Self::update_for_scope(VgicIrqScope::Global, changed));
        Ok(update)
    }

    fn dist_enable(&self) -> Result<(bool, bool), GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        Ok(regs.dist_enable)
    }

    fn set_group(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        group: IrqGroup,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.set_group(scope, vintid, group)?
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_priority(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.set_priority(scope, vintid, priority)?
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_trigger(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        trigger: TriggerMode,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.set_trigger(scope, vintid, trigger)?
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_enable(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        enable: bool,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.set_enable(scope, vintid, enable)?
        };
        let mut update = VgicUpdate::None;
        let intid = vintid.0 as usize;

        if enable {
            match scope {
                VgicIrqScope::Local(vcpu) if intid < SGI_COUNT => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, intid)?);
                }
                _ => {
                    let attrs = self.common.irq_attrs(scope, vintid)?;
                    if attrs.pending {
                        update.combine(&self.common.maybe_enqueue_irq(scope, vintid, None)?);
                    }
                }
            }
        } else {
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }

        update.combine(&Self::update_for_scope(scope, changed));
        if changed {
            if let Some(pintid) = self.pirq_for_vintid(vintid) {
                self.call_pirq_enable_hook(pintid, enable)?;
            }
        }
        Ok(update)
    }

    fn set_pending(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        pending: bool,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.set_pending(scope, vintid, pending)?
        };
        let mut update = VgicUpdate::None;
        let intid = vintid.0 as usize;

        if pending {
            match scope {
                VgicIrqScope::Local(vcpu) if intid < SGI_COUNT => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, intid)?);
                }
                _ => update.combine(&self.common.maybe_enqueue_irq(scope, vintid, None)?),
            }
        } else {
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }

        update.combine(&Self::update_for_scope(scope, changed));
        Ok(update)
    }

    fn read_group_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        regs.irq_state.read_group_word(scope, base)
    }

    fn write_group_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.write_group_word(scope, base, value)?
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_enable_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        regs.irq_state.read_enable_word(scope, base)
    }

    fn write_set_enable_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_set_enable_word(scope, base, set_bits)?
        };
        let mut update = VgicUpdate::None;

        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            match scope {
                VgicIrqScope::Local(vcpu) if (base.0 + bit) < SGI_COUNT as u32 => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, (base.0 + bit) as usize)?);
                }
                _ => {
                    let attrs = self.common.irq_attrs(scope, vintid)?;
                    if attrs.pending {
                        update.combine(&self.common.maybe_enqueue_irq(scope, vintid, None)?);
                    }
                }
            }
            if let Some(pintid) = self.pirq_for_vintid(vintid) {
                self.call_pirq_enable_hook(pintid, true)?;
            }
        }

        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn write_clear_enable_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_clear_enable_word(scope, base, clear_bits)?
        };
        let mut update = VgicUpdate::None;

        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
            if let Some(pintid) = self.pirq_for_vintid(vintid) {
                self.call_pirq_enable_hook(pintid, false)?;
            }
        }

        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn read_pending_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        regs.irq_state.read_pending_word(scope, base)
    }

    fn write_set_pending_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_set_pending_word(scope, base, set_bits)?
        };
        let mut update = VgicUpdate::None;

        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            match scope {
                VgicIrqScope::Local(vcpu) if (base.0 + bit) < SGI_COUNT as u32 => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, (base.0 + bit) as usize)?);
                }
                _ => update.combine(&self.common.maybe_enqueue_irq(scope, vintid, None)?),
            }
        }

        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn write_clear_pending_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_clear_pending_word(scope, base, clear_bits)?
        };
        let mut update = VgicUpdate::None;

        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }

        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn read_active_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        regs.irq_state.read_active_word(scope, base)
    }

    fn write_set_active_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_set_active_word(scope, base, set_bits)?
        };
        Ok(Self::update_for_scope(scope, mask != 0))
    }

    fn write_clear_active_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_clear_active_word(scope, base, clear_bits)?
        };
        Ok(Self::update_for_scope(scope, mask != 0))
    }

    fn read_priority_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        regs.irq_state
            .read_priority_word_raw(scope, base.0 as usize)
    }

    fn write_priority_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state
                .write_priority_word_raw(scope, base.0 as usize, value)?
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_trigger_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let regs = self.common.regs_lock.lock_irqsave();
        regs.irq_state.read_trigger_word(scope, base)
    }

    fn write_trigger_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed = {
            let mut regs = self.common.regs_lock.lock_irqsave();
            regs.irq_state.write_trigger_word(scope, base, value)?
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_spi_route(&self, vintid: VIntId, targets: VSpiRouting) -> Result<VgicUpdate, GicError> {
        match targets {
            VSpiRouting::Targets(mask) => {
                let vcpu_count = self.common.vcpu_count();
                for id in mask.iter() {
                    if (id.0 as usize) >= vcpu_count {
                        return Err(GicError::InvalidVcpuId);
                    }
                }

                let (changed, pintid) = {
                    let mut routing = self.common.routing_lock.lock_irqsave();
                    let changed = routing
                        .routing
                        .set_route(vintid, VSpiRouting::Targets(mask))?;
                    let pintid = if changed {
                        routing.pirqs.v2p(vintid)
                    } else {
                        None
                    };
                    (changed, pintid)
                };

                if let Some(pintid) = pintid {
                    self.call_pirq_route_hook(pintid, VSpiRouting::Targets(mask))?;
                }

                Ok(Self::update_for_scope(VgicIrqScope::Global, changed))
            }
            VSpiRouting::Specific(_) | VSpiRouting::AnyParticipating => {
                Err(GicError::UnsupportedFeature)
            }
        }
    }

    fn get_spi_route(&self, vintid: VIntId) -> Result<VSpiRouting, GicError> {
        let routing = self.common.routing_lock.lock_irqsave();
        routing.routing.get_route(vintid)
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> VgicPirqModel
    for GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); pending_cap_for_vcpus(VCPUS)]:,
{
    fn map_pirq(
        &self,
        pintid: PIntId,
        target: VcpuId,
        vintid: VIntId,
        sense: IrqSense,
        group: IrqGroup,
        priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        self.map_pirq_inner(pintid, target, vintid, sense, group, priority)
    }

    #[cfg(test)]
    fn unmap_pirq(&self, pintid: PIntId) -> Result<VgicUpdate, GicError> {
        self.unmap_pirq_inner(pintid)
    }

    fn on_physical_irq(&self, pintid: PIntId, level: bool) -> Result<VgicUpdate, GicError> {
        self.on_physical_irq_inner(pintid, level)
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::IrqState;
    use crate::VcpuMask;
    use crate::VgicSgiRegs;
    use crate::VirtualInterrupt;
    use core::cell::RefCell;
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;

    const TEST_VCPUS: usize = 4;

    struct EnqueueLog {
        count: usize,
        last: Option<VirtualInterrupt>,
    }

    impl EnqueueLog {
        fn new() -> Self {
            Self {
                count: 0,
                last: None,
            }
        }
    }

    struct CancelLog {
        count: usize,
        last: Option<(VIntId, Option<VcpuId>)>,
    }

    impl CancelLog {
        fn new() -> Self {
            Self {
                count: 0,
                last: None,
            }
        }
    }

    struct RecordingVcpu {
        enqueued: RefCell<EnqueueLog>,
        cancelled: RefCell<CancelLog>,
    }

    impl RecordingVcpu {
        fn new(_id: VcpuId) -> Self {
            Self {
                enqueued: RefCell::new(EnqueueLog::new()),
                cancelled: RefCell::new(CancelLog::new()),
            }
        }
    }

    impl VgicVcpuModel for RecordingVcpu {
        fn set_resident(&self, _core: cpu::CoreAffinity) -> Result<(), GicError> {
            Ok(())
        }

        fn refill_lrs<H: crate::VgicHw>(&self, _hw: &H) -> Result<bool, GicError> {
            Ok(false)
        }

        fn handle_maintenance_collect<H: crate::VgicHw>(
            &self,
            _hw: &H,
        ) -> Result<(VgicUpdate, crate::PirqNotifications), GicError> {
            Ok((VgicUpdate::None, crate::PirqNotifications::new()))
        }

        fn switch_out_sync<H: crate::VgicHw>(&self, _hw: &H) -> Result<(), GicError> {
            Ok(())
        }
    }

    impl VgicVcpuQueue for RecordingVcpu {
        fn enqueue_irq(&self, irq: VirtualInterrupt) -> Result<VgicWork, GicError> {
            let mut log = self.enqueued.borrow_mut();
            log.count += 1;
            log.last = Some(irq);
            Ok(VgicWork::REFILL)
        }

        fn cancel_irq(&self, vintid: VIntId, source: Option<VcpuId>) -> Result<(), GicError> {
            let mut log = self.cancelled.borrow_mut();
            log.count += 1;
            log.last = Some((vintid, source));
            Ok(())
        }
    }

    type RecordingVm = GicVmModelGeneric<TEST_VCPUS, RecordingVcpu>;

    fn recording_vm(vcpu_count: u16) -> RecordingVm {
        RecordingVm::new_with(vcpu_count, |id| RecordingVcpu::new(id)).unwrap()
    }

    fn assert_wf<T>() {}

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn gic_vm_model_for_vcpus_instantiates_common_sizes() {
        assert_wf::<GicVmModelForVcpus<1>>();
        assert_wf::<GicVmModelForVcpus<2>>();
        assert_wf::<GicVmModelForVcpus<4>>();
        assert_wf::<GicVmModelForVcpus<8>>();
        assert_wf::<GicVmModelForVcpus<16>>();
        assert_wf::<GicVmModelGeneric<4, RecordingVcpu>>();
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn vm_model_rejects_invalid_vcpu_counts() {
        assert!(matches!(
            RecordingVm::new_with(0, |id| RecordingVcpu::new(id)),
            Err(GicError::InvalidVcpuId)
        ));
        assert!(matches!(
            RecordingVm::new_with((TEST_VCPUS as u16) + 1, |id| RecordingVcpu::new(id)),
            Err(GicError::OutOfResources)
        ));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pending_and_enabled_irq_is_enqueued() {
        let mut vm = recording_vm(1);
        vm.set_dist_enable(true, true).unwrap();
        vm.set_enable(VgicIrqScope::Local(VcpuId(0)), VIntId(5), true)
            .unwrap();
        let update = vm
            .set_pending(VgicIrqScope::Local(VcpuId(0)), VIntId(5), true)
            .unwrap();
        let vcpu = vm.vcpu(VcpuId(0)).unwrap();
        let enqueued = vcpu.enqueued.borrow();
        assert_eq!(enqueued.count, 1);
        match enqueued.last.as_ref().expect("expected virq") {
            VirtualInterrupt::Software { vintid, state, .. } => {
                assert_eq!(*vintid, 5);
                assert_eq!(*state, IrqState::Pending);
            }
            _ => panic!("expected software pending virq"),
        }
        assert!(matches!(
            update,
            VgicUpdate::Some {
                targets: VgicTargets::One(VcpuId(0)),
                work
            } if work.refill
        ));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pending_queued_after_enable() {
        let mut vm = recording_vm(1);
        vm.set_dist_enable(true, true).unwrap();
        vm.set_pending(VgicIrqScope::Local(VcpuId(0)), VIntId(7), true)
            .unwrap();
        {
            let vcpu = vm.vcpu(VcpuId(0)).unwrap();
            assert_eq!(vcpu.enqueued.borrow().count, 0);
        }
        vm.set_enable(VgicIrqScope::Local(VcpuId(0)), VIntId(7), true)
            .unwrap();
        let vcpu = vm.vcpu(VcpuId(0)).unwrap();
        assert_eq!(vcpu.enqueued.borrow().count, 1);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn sgi_sources_enqueue_with_sender() {
        let mut vm = recording_vm(2);
        vm.set_dist_enable(true, true).unwrap();
        vm.set_enable(VgicIrqScope::Local(VcpuId(1)), VIntId(0), true)
            .unwrap();
        vm.write_set_sgi_pending_sources_word(VcpuId(1), 0, 1)
            .unwrap();
        let vcpu = vm.vcpu(VcpuId(1)).unwrap();
        let enqueued = vcpu.enqueued.borrow();
        assert_eq!(enqueued.count, 1);
        match enqueued.last.as_ref().expect("expected SGI") {
            VirtualInterrupt::Software { vintid, source, .. } => {
                assert_eq!(*vintid, 0);
                assert_eq!(*source, Some(VcpuId(0)));
            }
            _ => panic!("expected software SGI"),
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn hardware_irq_enqueues_hw_entry() {
        let mut vm = recording_vm(1);
        vm.set_dist_enable(true, true).unwrap();
        vm.map_pirq(
            PIntId(48),
            VcpuId(0),
            VIntId(40),
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        vm.on_physical_irq(PIntId(48), true).unwrap();
        let vcpu = vm.vcpu(VcpuId(0)).unwrap();
        let enqueued = vcpu.enqueued.borrow();
        assert_eq!(enqueued.count, 1);
        match enqueued.last.as_ref().expect("expected hardware virq") {
            VirtualInterrupt::Hardware { pintid, .. } => {
                assert_eq!(*pintid, 48);
            }
            _ => panic!("expected hardware virq"),
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn map_pirq_does_not_touch_spi_route() {
        let mut vm = recording_vm(2);
        let vintid = VIntId(40);
        vm.set_spi_route(vintid, VSpiRouting::Targets(VcpuMask::from_bits(0b10)))
            .unwrap();
        vm.map_pirq(
            PIntId(48),
            VcpuId(1),
            vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        assert_eq!(
            vm.get_spi_route(vintid).unwrap(),
            VSpiRouting::Targets(VcpuMask::from_bits(0b10))
        );
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn map_pirq_applies_group_and_priority_without_storing() {
        let mut vm = recording_vm(1);
        vm.map_pirq(
            PIntId(50),
            VcpuId(0),
            VIntId(40),
            IrqSense::Level,
            IrqGroup::Group1,
            0x5a,
        )
        .unwrap();

        let group_word = vm
            .read_group_word(VgicIrqScope::Global, VIntId(32))
            .unwrap();
        assert_eq!(group_word & (1u32 << (40 - 32)), 1u32 << (40 - 32));

        let prio_word = vm
            .read_priority_word(VgicIrqScope::Global, VIntId(40))
            .unwrap();
        assert_eq!(prio_word & 0xff, 0x5a);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn map_pirq_rejects_invalid_target_vcpu() {
        let mut vm = recording_vm(1);
        let res = vm.map_pirq(
            PIntId(48),
            VcpuId(2),
            VIntId(40),
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        );
        assert!(matches!(res, Err(GicError::InvalidVcpuId)));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn map_pirq_rejects_invalid_ids() {
        let mut vm = recording_vm(1);
        let max_intids = crate::max_intids_for_vcpus(TEST_VCPUS) as u32;
        let bad_pintid = PIntId(max_intids);
        let res = vm.map_pirq(
            bad_pintid,
            VcpuId(0),
            VIntId(40),
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        );
        assert!(matches!(res, Err(GicError::UnsupportedIntId)));

        let bad_vintid = VIntId(max_intids);
        let res = vm.map_pirq(
            PIntId(48),
            VcpuId(0),
            bad_vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        );
        assert!(matches!(res, Err(GicError::UnsupportedIntId)));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn sgi_sources_isolated() {
        let vm = recording_vm(1);
        let common_size = core::mem::size_of::<VmCommon<TEST_VCPUS, RecordingVcpu>>();
        let v2_size = core::mem::size_of::<V2SgiState<TEST_VCPUS>>();
        let vm_size = core::mem::size_of_val(&vm);
        assert!(vm_size >= common_size + v2_size);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pirq_reverse_lookup_updates_on_map_and_unmap() {
        let mut vm = recording_vm(1);
        let pintid = PIntId(48);
        let vintid = VIntId(40);
        vm.map_pirq(
            pintid,
            VcpuId(0),
            vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        {
            let routing = vm.common.routing_lock.lock_irqsave();
            assert_eq!(
                routing.pirqs.lookup_by_vintid(vintid).unwrap(),
                Some(pintid)
            );
        }
        vm.unmap_pirq(pintid).unwrap();
        {
            let routing = vm.common.routing_lock.lock_irqsave();
            assert_eq!(routing.pirqs.lookup_by_vintid(vintid).unwrap(), None);
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pirq_duplicate_vintid_rejected() {
        let mut vm = recording_vm(1);
        let vintid = VIntId(40);
        vm.map_pirq(
            PIntId(48),
            VcpuId(0),
            vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        let res = vm.map_pirq(
            PIntId(49),
            VcpuId(0),
            vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        );
        assert!(matches!(res, Err(GicError::InvalidState)));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pirq_enable_hook_called_on_change() {
        let mut vm = recording_vm(1);
        let pintid = PIntId(48);
        let vintid = VIntId(40);
        vm.map_pirq(
            pintid,
            VcpuId(0),
            vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        fn enable_hook(int_id: u32, op: PirqHookOp) -> Result<(), PirqHookError> {
            if int_id == 48 && matches!(op, PirqHookOp::Enable { .. }) {
                COUNTER.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
        vm.set_pirq_hook(Some(enable_hook));
        COUNTER.store(0, Ordering::SeqCst);
        let base = VIntId(32);
        let bit = vintid.0 - base.0;
        vm.write_clear_enable_word(VgicIrqScope::Global, base, 1u32 << bit)
            .unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pirq_route_hook_called_on_route_change() {
        let mut vm = recording_vm(2);
        let pintid = PIntId(48);
        let vintid = VIntId(40);
        vm.map_pirq(
            pintid,
            VcpuId(1),
            vintid,
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        static ROUTE_COUNTER: AtomicUsize = AtomicUsize::new(0);
        fn route_hook(int_id: u32, op: PirqHookOp) -> Result<(), PirqHookError> {
            if int_id == 48 && matches!(op, PirqHookOp::Route { .. }) {
                ROUTE_COUNTER.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
        vm.set_pirq_hook(Some(route_hook));
        ROUTE_COUNTER.store(0, Ordering::SeqCst);
        let route = VSpiRouting::Targets(VcpuMask::from_bits(0b10));
        vm.set_spi_route(vintid, route).unwrap();
        assert_eq!(ROUTE_COUNTER.load(Ordering::SeqCst), 1);
    }
}
