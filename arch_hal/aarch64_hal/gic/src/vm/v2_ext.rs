use crate::GicError;
use crate::VIntId;
use crate::VcpuId;
use crate::VgicIrqScope;
use crate::VgicSgiRegs;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::VgicWork;
use crate::vm::GicVmModelGeneric;
use crate::vm::common::SGI_COUNT;

pub(crate) struct V2SgiState<const VCPUS: usize> {
    pub(crate) sgi_sources: [[u32; 4]; VCPUS],
}

impl<const VCPUS: usize> V2SgiState<VCPUS> {
    pub(crate) fn new() -> Self {
        Self {
            sgi_sources: [[0u32; 4]; VCPUS],
        }
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - crate::vm::common::LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - crate::vm::common::LOCAL_INTID_COUNT + 31) / 32]:,
{
    pub(crate) fn enqueue_sgi_for_target(
        &self,
        target: VcpuId,
        sgi: usize,
    ) -> Result<VgicUpdate, GicError> {
        let idx = self.common.vcpu_index(target)?;
        let word = sgi / 4;
        let lane = sgi % 4;
        if word >= 4 || sgi >= SGI_COUNT {
            return Err(GicError::UnsupportedIntId);
        }
        let sources = {
            let v2 = self.v2.lock_irqsave();
            (v2.sgi_sources[idx][word] >> (lane * 8)) & 0xff
        };
        if sources == 0 {
            return self.common.maybe_enqueue_irq(
                VgicIrqScope::Local(target),
                VIntId(sgi as u32),
                None,
            );
        }

        let mut update = VgicUpdate::None;
        let vcpu_count = self.common.vcpu_count();
        for sender in 0..vcpu_count {
            if (sources & (1 << sender)) == 0 {
                continue;
            }
            update.combine(&self.common.maybe_enqueue_irq(
                VgicIrqScope::Local(target),
                VIntId(sgi as u32),
                Some(VcpuId(sender as u16)),
            )?);
        }
        Ok(update)
    }

    pub(crate) fn cancel_for_scope(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        source: Option<VcpuId>,
    ) -> Result<VgicUpdate, GicError> {
        let mut update = VgicUpdate::None;
        match scope {
            VgicIrqScope::Local(vcpu) => {
                if (vintid.0 as usize) < SGI_COUNT && source.is_none() {
                    let idx = self.common.vcpu_index(vcpu)?;
                    let sgi = vintid.0 as usize;
                    let word = sgi / 4;
                    let lane = sgi % 4;
                    let lane_mask = {
                        let v2 = self.v2.lock_irqsave();
                        (v2.sgi_sources[idx][word] >> (lane * 8)) & 0xff
                    };
                    for sender in 0..self.common.vcpu_count() {
                        if (lane_mask & (1 << sender)) == 0 {
                            continue;
                        }
                        self.common
                            .vcpu(vcpu)?
                            .cancel_irq(vintid, Some(VcpuId(sender as u16)))?;
                    }
                }
                self.common.vcpu(vcpu)?.cancel_irq(vintid, source)?;
                update.combine(&VgicUpdate::Some {
                    targets: VgicTargets::One(vcpu),
                    work: VgicWork::REFILL,
                });
            }
            VgicIrqScope::Global => {
                let targets = self.common.targets_for_global_spi(vintid)?;
                for target in targets.iter() {
                    self.common.vcpu(target)?.cancel_irq(vintid, source)?;
                    update.combine(&VgicUpdate::Some {
                        targets: VgicTargets::One(target),
                        work: VgicWork::REFILL,
                    });
                }
            }
        }
        Ok(update)
    }
}

impl<const VCPUS: usize, V: VgicVcpuModel + VgicVcpuQueue> VgicSgiRegs
    for GicVmModelGeneric<VCPUS, V>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - crate::vm::common::LOCAL_INTID_COUNT]:,
    [(); (crate::max_intids_for_vcpus(VCPUS) - crate::vm::common::LOCAL_INTID_COUNT + 31) / 32]:,
{
    fn read_sgi_pending_sources_word(&self, target: VcpuId, sgi: u8) -> Result<u32, GicError> {
        let idx = self.common.vcpu_index(target)?;
        let word = sgi as usize;
        if word >= 4 {
            return Err(GicError::UnsupportedIntId);
        }
        let v2 = self.v2.lock_irqsave();
        Ok(v2.sgi_sources[idx][word])
    }

    fn write_set_sgi_pending_sources_word(
        &self,
        target: VcpuId,
        sgi: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError> {
        let idx = self.common.vcpu_index(target)?;
        let word = sgi as usize;
        if word >= 4 {
            return Err(GicError::UnsupportedIntId);
        }

        let mut update = VgicUpdate::None;
        let mut pending_enqueues: [(u8, VcpuId); 32] = [(0, VcpuId(0)); 32];
        let mut pending_enqueue_count = 0usize;
        let (new_entry, changed) = {
            let mut v2 = self.v2.lock_irqsave();
            let prev = v2.sgi_sources[idx][word];
            let new_bits = sources & !prev;

            for bit in 0..32 {
                if (new_bits & (1u32 << bit)) == 0 {
                    continue;
                }
                let lane = bit / 8;
                let sender = bit % 8;
                if sender as usize >= self.common.vcpu_count() || sender >= 8 {
                    return Err(GicError::InvalidVcpuId);
                }
                if lane >= 4 {
                    return Err(GicError::UnsupportedIntId);
                }
                let sgi_id = word * 4 + lane;
                if sgi_id >= SGI_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                pending_enqueues[pending_enqueue_count] = (sgi_id as u8, VcpuId(sender as u16));
                pending_enqueue_count += 1;
            }
            let new_entry = prev | sources;
            let changed = new_entry != prev;
            v2.sgi_sources[idx][word] = new_entry;
            (new_entry, changed)
        };

        {
            let mut regs = self.common.regs_lock.lock_irqsave();
            for lane in 0..4 {
                let lane_mask = 0xff << (lane * 8);
                let sgi_id = word * 4 + lane;
                if sgi_id < SGI_COUNT {
                    let _ = regs.irq_state.set_pending(
                        VgicIrqScope::Local(target),
                        VIntId(sgi_id as u32),
                        (new_entry & lane_mask) != 0,
                    )?;
                }
            }
        }

        for (sgi_id, sender) in pending_enqueues.into_iter().take(pending_enqueue_count) {
            update.combine(&self.common.maybe_enqueue_irq(
                VgicIrqScope::Local(target),
                VIntId(sgi_id as u32),
                Some(sender),
            )?);
        }

        update.combine(&GicVmModelGeneric::<VCPUS, V>::update_for_scope(
            VgicIrqScope::Local(target),
            changed,
        ));
        Ok(update)
    }

    fn write_clear_sgi_pending_sources_word(
        &self,
        target: VcpuId,
        sgi: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError> {
        let idx = self.common.vcpu_index(target)?;
        let word = sgi as usize;
        if word >= 4 {
            return Err(GicError::UnsupportedIntId);
        }

        let mut update = VgicUpdate::None;
        let mut cancellations: [(u8, VcpuId); 32] = [(0, VcpuId(0)); 32];
        let mut cancellation_count = 0usize;
        let (new_entry, changed) = {
            let mut v2 = self.v2.lock_irqsave();
            let prev = v2.sgi_sources[idx][word];
            let cleared_bits = prev & sources;

            for bit in 0..32 {
                if (cleared_bits & (1u32 << bit)) == 0 {
                    continue;
                }
                let lane = bit / 8;
                let sender = bit % 8;
                if sender as usize >= self.common.vcpu_count() || sender >= 8 {
                    return Err(GicError::InvalidVcpuId);
                }
                if lane >= 4 {
                    return Err(GicError::UnsupportedIntId);
                }
                let sgi_id = word * 4 + lane;
                if sgi_id >= SGI_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }

                cancellations[cancellation_count] = (sgi_id as u8, VcpuId(sender as u16));
                cancellation_count += 1;
            }
            let new_entry = prev & !sources;
            let changed = new_entry != prev;
            v2.sgi_sources[idx][word] = new_entry;
            (new_entry, changed)
        };

        for (sgi_id, sender) in cancellations.into_iter().take(cancellation_count) {
            self.common
                .vcpu(target)?
                .cancel_irq(VIntId(sgi_id as u32), Some(sender))?;
            update.combine(&VgicUpdate::Some {
                targets: VgicTargets::One(target),
                work: VgicWork::REFILL,
            });
        }

        {
            let mut regs = self.common.regs_lock.lock_irqsave();
            for lane in 0..4 {
                let lane_mask = 0xff << (lane * 8);
                let sgi_id = word * 4 + lane;
                if sgi_id < SGI_COUNT {
                    let _ = regs.irq_state.set_pending(
                        VgicIrqScope::Local(target),
                        VIntId(sgi_id as u32),
                        (new_entry & lane_mask) != 0,
                    )?;
                }
            }
        }

        update.combine(&GicVmModelGeneric::<VCPUS, V>::update_for_scope(
            VgicIrqScope::Local(target),
            changed,
        ));
        Ok(update)
    }
}
