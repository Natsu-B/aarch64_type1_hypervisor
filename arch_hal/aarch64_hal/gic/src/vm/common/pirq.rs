use crate::GicError;
use crate::IrqGroup;
use crate::IrqSense;
use crate::PIntId;
use crate::TriggerMode;
use crate::VIntId;
use crate::VcpuId;
use crate::VgicGuestRegs;
use crate::VgicIrqScope;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::vm::GicVmModelGeneric;
use crate::vm::common::LOCAL_INTID_COUNT;

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct PirqEntry {
    pub(crate) target: VcpuId,
    pub(crate) vintid: VIntId,
    pub(crate) sense: IrqSense,
}

pub(crate) struct PirqTable<const VCPUS: usize>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
{
    entries: [Option<PirqEntry>; crate::max_intids_for_vcpus(VCPUS)],
}

impl<const VCPUS: usize> PirqTable<VCPUS>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
{
    pub(crate) fn new() -> Self {
        Self {
            entries: [None; { crate::max_intids_for_vcpus(VCPUS) }],
        }
    }

    fn index(&self, pintid: PIntId) -> Result<usize, GicError> {
        let idx = pintid.0 as usize;
        if idx >= self.entries.len() {
            return Err(GicError::UnsupportedIntId);
        }
        Ok(idx)
    }

    pub(crate) fn get(&self, pintid: PIntId) -> Result<Option<PirqEntry>, GicError> {
        let idx = self.index(pintid)?;
        Ok(self.entries[idx])
    }

    pub(crate) fn take(&mut self, pintid: PIntId) -> Result<Option<PirqEntry>, GicError> {
        let idx = self.index(pintid)?;
        Ok(self.entries[idx].take())
    }

    pub(crate) fn ensure_entry(
        &mut self,
        pintid: PIntId,
        entry: PirqEntry,
    ) -> Result<bool, GicError> {
        let idx = self.index(pintid)?;
        match self.entries[idx] {
            Some(existing) if existing == entry => Ok(false),
            Some(_) => Err(GicError::InvalidState),
            None => {
                self.entries[idx] = Some(entry);
                Ok(true)
            }
        }
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
{
    pub(crate) fn map_pirq_inner(
        &mut self,
        pintid: PIntId,
        target: VcpuId,
        vintid: VIntId,
        sense: IrqSense,
        group: IrqGroup,
        priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        self.common.vcpu_index(target)?; // validate target

        let entry = PirqEntry {
            target,
            vintid,
            sense,
        };
        let existing = self.common.pirqs.get(pintid)?;
        if let Some(prev) = existing {
            if prev != entry {
                return Err(GicError::InvalidState);
            }
        }

        let scope = if vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(target)
        } else {
            VgicIrqScope::Global
        };

        let mut update = VgicUpdate::None;
        update.combine(&self.set_group(scope, vintid, group)?);
        update.combine(&self.set_priority(scope, vintid, priority)?);
        update.combine(&self.set_trigger(
            scope,
            vintid,
            match sense {
                IrqSense::Edge => TriggerMode::Edge,
                IrqSense::Level => TriggerMode::Level,
            },
        )?);
        update.combine(&self.set_enable(scope, vintid, true)?);

        if existing.is_none() {
            let _ = self.common.pirqs.ensure_entry(pintid, entry)?;
        }
        Ok(update)
    }

    pub(crate) fn unmap_pirq_inner(&mut self, pintid: PIntId) -> Result<VgicUpdate, GicError> {
        let entry = match self.common.pirqs.take(pintid) {
            Ok(Some(entry)) => entry,
            Ok(None) => return Ok(VgicUpdate::None),
            Err(GicError::UnsupportedIntId) => return Ok(VgicUpdate::None),
            Err(err) => return Err(err),
        };
        let scope = if entry.vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(entry.target)
        } else {
            VgicIrqScope::Global
        };
        self.set_enable(scope, entry.vintid, false)
    }

    pub(crate) fn on_physical_irq_inner(
        &mut self,
        pintid: PIntId,
        level: bool,
    ) -> Result<VgicUpdate, GicError> {
        let Some(entry) = self.common.pirqs.get(pintid)? else {
            return Err(GicError::UnsupportedIntId);
        };

        let scope = if entry.vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(entry.target)
        } else {
            VgicIrqScope::Global
        };

        let mut update = VgicUpdate::None;

        // NOTE: `level` semantics for pIRQ ingress:
        // - For level-sensitive pIRQs, `level=true` means the line is asserted, `level=false`
        //   means deasserted.
        // - For edge-sensitive pIRQs, callers must pass `level=true` exactly once per detected
        //   edge (pulse). Passing repeated `level=true` while the virtual IRQ is still pending
        //   can inject duplicates; `level=false` is ignored for edge-sensitive pIRQs.
        let set_pending = match entry.sense {
            IrqSense::Edge => level,
            IrqSense::Level => level,
        };

        if set_pending {
            let changed = self
                .common
                .irq_state
                .set_pending(scope, entry.vintid, true)?;
            let attrs = self.common.irq_attrs(scope, entry.vintid)?;
            if attrs.pending && attrs.enable && self.common.dist_enabled(attrs.group) {
                let irq = self.common.build_hw_virq(scope, entry.vintid, pintid)?;
                match scope {
                    VgicIrqScope::Local(target) => {
                        update.combine(&self.common.enqueue_to_target(target, irq)?)
                    }
                    VgicIrqScope::Global => {
                        let targets = self.common.targets_for_global_spi(entry.vintid)?;
                        for target in targets.iter() {
                            update.combine(&self.common.enqueue_to_target(target, irq)?);
                        }
                    }
                }
            }
            update.combine(&GicVmModelGeneric::<VCPUS, V>::update_for_scope(
                scope, changed,
            ));
        } else if matches!(entry.sense, IrqSense::Level) {
            let changed = self
                .common
                .irq_state
                .set_pending(scope, entry.vintid, false)?;
            update.combine(&self.cancel_for_scope(scope, entry.vintid, None)?);
            update.combine(&GicVmModelGeneric::<VCPUS, V>::update_for_scope(
                scope, changed,
            ));
        }

        Ok(update)
    }
}
