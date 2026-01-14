pub(crate) mod irq_state;
pub(crate) mod pirq;
pub(crate) mod routing;
pub(crate) mod vcpu_array;

use crate::GicError;
use crate::IrqGroup;
use crate::IrqState as IrqStateKind;
use crate::PIntId;
use crate::VIntId;
use crate::VcpuId;
use crate::VcpuMask;
use crate::VgicIrqScope;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::VirtualInterrupt;

use irq_state::IrqAttrs;
use irq_state::IrqState as IrqStateTable;
use pirq::PirqTable;
use routing::SpiRouting;
use vcpu_array::VcpuArray;

pub(crate) use irq_state::LOCAL_INTID_COUNT;
pub(crate) use irq_state::SGI_COUNT;

pub(crate) struct VmCommon<const VCPUS: usize, V: VgicVcpuModel>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
{
    pub(crate) dist_enable: (bool, bool),
    pub(crate) vcpus: VcpuArray<VCPUS, V>,
    pub(crate) irq_state: IrqStateTable<VCPUS>,
    pub(crate) routing: SpiRouting<VCPUS>,
    pub(crate) pirqs: PirqTable<VCPUS>,
}

impl<const VCPUS: usize, V: VgicVcpuModel> VmCommon<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
{
    pub(crate) fn new(vcpu_count: usize, make: impl FnMut(VcpuId) -> V) -> Result<Self, GicError> {
        Ok(Self {
            dist_enable: (false, false),
            vcpus: VcpuArray::new_with(vcpu_count, make)?,
            irq_state: IrqStateTable::new(vcpu_count),
            routing: SpiRouting::new(),
            pirqs: PirqTable::new(),
        })
    }

    pub(crate) fn vcpu_count(&self) -> usize {
        self.irq_state.vcpu_count()
    }

    pub(crate) fn vcpu(&self, id: VcpuId) -> Result<&V, GicError> {
        self.vcpus.get(id.0 as usize).ok_or(GicError::InvalidVcpuId)
    }

    pub(crate) fn vcpu_index(&self, id: VcpuId) -> Result<usize, GicError> {
        self.irq_state.vcpu_index(id)
    }

    pub(crate) fn dist_enabled(&self, group: IrqGroup) -> bool {
        match group {
            IrqGroup::Group0 => self.dist_enable.0,
            IrqGroup::Group1 => self.dist_enable.1,
        }
    }

    pub(crate) fn irq_attrs(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
    ) -> Result<IrqAttrs, GicError> {
        self.irq_state.irq_attrs(scope, vintid)
    }

    pub(crate) fn targets_for_global_spi(&self, vintid: VIntId) -> Result<VcpuMask, GicError> {
        self.routing.targets_for_spi(vintid, self.vcpu_count())
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> VmCommon<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
{
    pub(crate) fn build_sw_virq(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        source: Option<VcpuId>,
    ) -> Result<VirtualInterrupt, GicError> {
        let attrs = self.irq_attrs(scope, vintid)?;
        let state = if attrs.pending && attrs.active {
            IrqStateKind::PendingActive
        } else if attrs.pending {
            IrqStateKind::Pending
        } else if attrs.active {
            IrqStateKind::Active
        } else {
            IrqStateKind::Inactive
        };
        Ok(VirtualInterrupt::Software {
            vintid: vintid.0,
            eoi_maintenance: false,
            priority: attrs.priority,
            group: attrs.group,
            state,
            source,
        })
    }

    pub(crate) fn build_hw_virq(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        pintid: PIntId,
    ) -> Result<VirtualInterrupt, GicError> {
        let attrs = self.irq_attrs(scope, vintid)?;
        let state = if attrs.pending && attrs.active {
            IrqStateKind::PendingActive
        } else if attrs.pending {
            IrqStateKind::Pending
        } else if attrs.active {
            IrqStateKind::Active
        } else {
            IrqStateKind::Inactive
        };
        Ok(VirtualInterrupt::Hardware {
            vintid: vintid.0,
            pintid: pintid.0,
            priority: attrs.priority,
            group: attrs.group,
            state,
            source: None,
        })
    }

    pub(crate) fn enqueue_to_target(
        &self,
        target: VcpuId,
        virq: VirtualInterrupt,
    ) -> Result<VgicUpdate, GicError> {
        let work = self.vcpu(target)?.enqueue_irq(virq)?;
        Ok(VgicUpdate::Some {
            targets: VgicTargets::One(target),
            work,
        })
    }

    pub(crate) fn maybe_enqueue_irq(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        source: Option<VcpuId>,
    ) -> Result<VgicUpdate, GicError> {
        let attrs = self.irq_attrs(scope, vintid)?;
        if !attrs.pending || !attrs.enable || !self.dist_enabled(attrs.group) {
            return Ok(VgicUpdate::None);
        }

        match scope {
            VgicIrqScope::Local(vcpu) => {
                let irq = self.build_sw_virq(scope, vintid, source)?;
                self.enqueue_to_target(vcpu, irq)
            }
            VgicIrqScope::Global => {
                let targets = self.targets_for_global_spi(vintid)?;
                if targets.is_empty() {
                    return Ok(VgicUpdate::None);
                }
                let irq = self.build_sw_virq(scope, vintid, source)?;
                let mut update = VgicUpdate::None;
                for target in targets.iter() {
                    update.combine(&self.enqueue_to_target(target, irq)?);
                }
                Ok(update)
            }
        }
    }
}
