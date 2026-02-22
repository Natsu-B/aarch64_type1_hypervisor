use crate::GicError;
use crate::IrqGroup;
use crate::IrqSense;
use crate::IrqState as IrqStateKind;
use crate::PIntId;
use crate::TriggerMode;
use crate::VIntId;
use crate::VcpuId;
use crate::VcpuMask;
use crate::VgicGuestRegs;
use crate::VgicIrqScope;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::VgicWork;
use crate::VirtualInterrupt;
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
    v2p: [Option<PIntId>; crate::max_intids_for_vcpus(VCPUS)],
}

impl<const VCPUS: usize> PirqTable<VCPUS>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
{
    pub(crate) fn new() -> Self {
        Self {
            entries: [None; { crate::max_intids_for_vcpus(VCPUS) }],
            v2p: [None; { crate::max_intids_for_vcpus(VCPUS) }],
        }
    }

    fn index(&self, pintid: PIntId) -> Result<usize, GicError> {
        let idx = pintid.0 as usize;
        if idx >= self.entries.len() {
            return Err(GicError::UnsupportedIntId);
        }
        Ok(idx)
    }

    fn vindex(&self, vintid: VIntId) -> Result<usize, GicError> {
        let idx = vintid.0 as usize;
        if idx >= self.v2p.len() {
            return Err(GicError::UnsupportedIntId);
        }
        Ok(idx)
    }

    pub(crate) fn get(&self, pintid: PIntId) -> Result<Option<PirqEntry>, GicError> {
        let idx = self.index(pintid)?;
        Ok(self.entries[idx])
    }

    #[cfg(test)]
    pub(crate) fn take(&mut self, pintid: PIntId) -> Result<Option<PirqEntry>, GicError> {
        let idx = self.index(pintid)?;
        let entry = self.entries[idx].take();
        if let Some(entry) = entry {
            let v_idx = self.vindex(entry.vintid)?;
            if matches!(self.v2p[v_idx], Some(existing) if existing == pintid) {
                self.v2p[v_idx] = None;
            }
        }
        Ok(entry)
    }

    pub(crate) fn ensure_entry(
        &mut self,
        pintid: PIntId,
        entry: PirqEntry,
    ) -> Result<bool, GicError> {
        let idx = self.index(pintid)?;
        let v_idx = self.vindex(entry.vintid)?;

        if let Some(existing_pintid) = self.v2p[v_idx] {
            if existing_pintid != pintid {
                return Err(GicError::InvalidState);
            }
        }

        match self.entries[idx] {
            Some(existing) if existing == entry => {
                self.v2p[v_idx] = Some(pintid);
                Ok(false)
            }
            Some(_) => Err(GicError::InvalidState),
            None => {
                self.entries[idx] = Some(entry);
                self.v2p[v_idx] = Some(pintid);
                Ok(true)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn lookup_by_vintid(&self, vintid: VIntId) -> Result<Option<PIntId>, GicError> {
        let idx = self.vindex(vintid)?;
        Ok(self.v2p[idx])
    }

    pub(crate) fn v2p(&self, vintid: VIntId) -> Option<PIntId> {
        let idx = vintid.0 as usize;
        self.v2p.get(idx).copied().flatten()
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT + 31) / 32]:,
    [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
    [(); crate::vm::pending_cap_for_vcpus(VCPUS)]:,
{
    pub(crate) fn map_pirq_inner(
        &self,
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
        {
            let routing = self.common.routing_lock.lock_irqsave();
            let existing = routing.pirqs.get(pintid)?;
            if let Some(prev) = existing {
                if prev != entry {
                    return Err(GicError::InvalidState);
                }
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

        let commit_result = {
            let mut routing = self.common.routing_lock.lock_irqsave();
            routing.pirqs.ensure_entry(pintid, entry).map(|_| ())
        };
        if let Err(err) = commit_result {
            // Roll back virtual enable if another mapping raced us after Phase 1 validation.
            update.combine(&self.set_enable(scope, vintid, false)?);
            return Err(err);
        }

        Ok(update)
    }

    #[cfg(test)]
    pub(crate) fn unmap_pirq_inner(&self, pintid: PIntId) -> Result<VgicUpdate, GicError> {
        let entry = {
            let mut routing = self.common.routing_lock.lock_irqsave();
            match routing.pirqs.take(pintid) {
                Ok(Some(entry)) => entry,
                Ok(None) => return Ok(VgicUpdate::None),
                Err(GicError::UnsupportedIntId) => return Ok(VgicUpdate::None),
                Err(err) => return Err(err),
            }
        };
        let scope = if entry.vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(entry.target)
        } else {
            VgicIrqScope::Global
        };
        self.set_enable(scope, entry.vintid, false)
    }

    pub(crate) fn on_physical_irq_inner(
        &self,
        pintid: PIntId,
        level: bool,
    ) -> Result<VgicUpdate, GicError> {
        let (entry, global_targets) = {
            let routing = self.common.routing_lock.lock_irqsave();
            let Some(entry) = routing.pirqs.get(pintid)? else {
                return Err(GicError::UnsupportedIntId);
            };
            let targets = if entry.vintid.0 >= LOCAL_INTID_COUNT as u32 {
                routing
                    .routing
                    .targets_for_spi(entry.vintid, self.common.vcpu_count())?
            } else {
                VcpuMask::EMPTY
            };
            (entry, targets)
        };

        let scope = if entry.vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(entry.target)
        } else {
            VgicIrqScope::Global
        };

        let mut update = VgicUpdate::None;
        let mut changed = false;
        let mut enqueue_irq: Option<VirtualInterrupt> = None;

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

        {
            let mut regs = self.common.regs_lock.lock_irqsave();
            if set_pending {
                changed = regs.irq_state.set_pending(scope, entry.vintid, true)?;
                let attrs = regs.irq_state.irq_attrs(scope, entry.vintid)?;
                let dist_enabled = match attrs.group {
                    IrqGroup::Group0 => regs.dist_enable.0,
                    IrqGroup::Group1 => regs.dist_enable.1,
                };
                if attrs.pending && attrs.enable && dist_enabled {
                    let state = if attrs.pending && attrs.active {
                        IrqStateKind::PendingActive
                    } else if attrs.pending {
                        IrqStateKind::Pending
                    } else if attrs.active {
                        IrqStateKind::Active
                    } else {
                        IrqStateKind::Inactive
                    };
                    enqueue_irq = Some(VirtualInterrupt::Hardware {
                        vintid: entry.vintid.0,
                        pintid: pintid.0,
                        priority: attrs.priority,
                        group: attrs.group,
                        state,
                        source: None,
                    });
                }
            } else if matches!(entry.sense, IrqSense::Level) {
                changed = regs.irq_state.set_pending(scope, entry.vintid, false)?;
            }
        }

        if let Some(irq) = enqueue_irq {
            match scope {
                VgicIrqScope::Local(target) => {
                    update.combine(&self.common.enqueue_to_target(target, irq)?);
                }
                VgicIrqScope::Global => {
                    for target in global_targets.iter() {
                        update.combine(&self.common.enqueue_to_target(target, irq)?);
                    }
                }
            }
        } else if !set_pending && matches!(entry.sense, IrqSense::Level) {
            match scope {
                VgicIrqScope::Local(target) => {
                    self.common.vcpu(target)?.cancel_irq(entry.vintid, None)?;
                    update.combine(&VgicUpdate::Some {
                        targets: VgicTargets::One(target),
                        work: VgicWork::REFILL,
                    });
                }
                VgicIrqScope::Global => {
                    for target in global_targets.iter() {
                        self.common.vcpu(target)?.cancel_irq(entry.vintid, None)?;
                        update.combine(&VgicUpdate::Some {
                            targets: VgicTargets::One(target),
                            work: VgicWork::REFILL,
                        });
                    }
                }
            }
        }

        update.combine(&GicVmModelGeneric::<VCPUS, V>::update_for_scope(
            scope, changed,
        ));
        Ok(update)
    }
}
