// GICv2 virtualization backend: programs GICH list registers and exposes maintenance events.
// Note: GICv2 hardware does not virtualize the Distributor; guest Distributor accesses must be
// trapped/emulated in software, and virtual interrupts are injected through LRs described here.
use crate::EoiMode;
use crate::GicError;
use crate::IrqGroup;
use crate::IrqState;
use crate::VgicHw;
use crate::VirtualInterrupt;
use crate::gicv2::Gicv2;
use crate::gicv2::registers::GICH_APR;
use crate::gicv2::registers::GICH_HCR;
use crate::gicv2::registers::GICH_LR;
use crate::gicv2::registers::GICH_VMCR;
use crate::gicv2::registers::GICH_VTR;
use crate::vm::GicVmModelForVcpus;
use core::array;
use typestate::Readable;
use typestate::Writable;

impl Gicv2 {
    pub fn create_vm_model<const VCPUS: usize>(
        &self,
        vcpu_num: u8,
    ) -> Result<GicVmModelForVcpus<VCPUS>, GicError>
    where
        [(); VCPUS - 1]:,
        [(); 16 - VCPUS]:,
        [(); crate::max_intids_for_vcpus(VCPUS)]:,
        [(); crate::max_intids_for_vcpus(VCPUS) - 32]:,
        [(); crate::VgicVmConfig::<VCPUS>::MAX_LRS]:,
        [(); crate::vm::pending_cap_for_vcpus(VCPUS)]:,
    {
        if self.virtualization_extension.is_none() {
            return Err(GicError::UnsupportedFeature);
        }
        if vcpu_num == 0 {
            return Err(GicError::InvalidVcpuId);
        }
        if (vcpu_num as usize) > VCPUS {
            return Err(GicError::OutOfResources);
        }
        // CPUID field in GICv2 LR format is 3 bits. This backend supports at most 8 vCPUs and
        // requires contiguous guest vCPU ids 0..vcpu_count-1 that match the CPUID field used in LRs
        // and banked ITARGETSR0_7 handling.
        if vcpu_num > 8 {
            return Err(GicError::OutOfResources);
        }
        GicVmModelForVcpus::<VCPUS>::new(vcpu_num as u16)
    }
}

pub struct Gicv2VcpuHwState {
    vmcr: GICH_VMCR,
    apr: GICH_APR,
    lr: [GICH_LR; 64],
}

// LR encode/decode helpers (GICv2).
pub fn encode_lr(irq: VirtualInterrupt) -> Result<GICH_LR, GicError> {
    let vintid = irq.vintid();
    if vintid >= 1020 {
        return Err(GicError::InvalidVgicIrq);
    }
    // EOI maintenance is meaningful only for SW-composed LRs; reject attempts to mix it with HW LRs.
    if irq.is_hw() && irq.eoi_maintenance() {
        return Err(GicError::InvalidVgicIrq);
    }
    let priority = irq.priority();
    let group = irq.group();
    let state = irq.state();
    let prio_field = (priority as u32) >> 3; // LR stores 5 bits; take the top bits.
    let state_bits = match state {
        IrqState::Inactive => 0b00,
        IrqState::Pending => 0b01,
        IrqState::Active => 0b10,
        IrqState::PendingActive => 0b11,
    };

    match irq {
        VirtualInterrupt::Hardware { pintid, .. } => {
            // Hardware backed interrupts must track pending/active in the Distributor.
            if matches!(state, IrqState::PendingActive) {
                return Err(GicError::InvalidVgicIrq);
            }
            // 10-bit physID field only accepts 0-1023 and rejects the architecturally reserved ranges.
            if pintid <= 15 || (1020..=1023).contains(&pintid) || pintid >= 1024 {
                return Err(GicError::InvalidVgicIrq);
            }
            Ok(GICH_LR::new()
                .set(GICH_LR::virtual_id, vintid)
                .set(GICH_LR::physical_id, pintid)
                .set(GICH_LR::priority, prio_field)
                .set(GICH_LR::grp1, (group == IrqGroup::Group1) as u32)
                .set(GICH_LR::state, state_bits)
                .set(GICH_LR::hw, 1))
        }
        VirtualInterrupt::Software {
            eoi_maintenance,
            source,
            ..
        } => {
            if state == IrqState::Inactive && eoi_maintenance {
                return Err(GicError::InvalidVgicIrq);
            }
            if vintid < 16 && state != IrqState::Inactive && source.is_none() {
                return Err(GicError::InvalidVgicIrq);
            }
            if let Some(src) = source {
                if src.0 >= 8 {
                    return Err(GicError::InvalidCpuId);
                }
            }
            // CPUID in the LR must match the guest vCPU id (0..7) as enforced at VM creation time.
            let cpuid = if vintid < 16 {
                source.map(|s| s.0 as u32).unwrap_or(0)
            } else {
                0
            };
            Ok(GICH_LR::new()
                .set(GICH_LR::virtual_id, vintid)
                .set(GICH_LR::cpuid, cpuid)
                // Generate EOI maintenance for SW LRs so we can cleanly track completion.
                .set(GICH_LR::eoi, eoi_maintenance as u32)
                .set(GICH_LR::priority, prio_field)
                .set(GICH_LR::grp1, (group == IrqGroup::Group1) as u32)
                .set(GICH_LR::state, state_bits)
                .set(GICH_LR::hw, 0))
        }
    }
}

pub fn decode_lr(raw: GICH_LR) -> Result<VirtualInterrupt, GicError> {
    let hw = raw.get(GICH_LR::hw) == 1;
    let vintid = raw.get(GICH_LR::virtual_id);
    if vintid >= 1020 {
        return Err(GicError::InvalidVgicIrq);
    }
    let group = if raw.get(GICH_LR::grp1) == 0 {
        IrqGroup::Group0
    } else {
        IrqGroup::Group1
    };
    let priority = (raw.get(GICH_LR::priority) << 3) as u8;
    let state = match raw.get(GICH_LR::state) {
        0b00 => IrqState::Inactive,
        0b01 => IrqState::Pending,
        0b10 => IrqState::Active,
        0b11 => IrqState::PendingActive,
        _ => unreachable!(),
    };

    if hw {
        let pid = raw.get(GICH_LR::physical_id);
        if pid <= 15 || (1020..=1023).contains(&pid) {
            return Err(GicError::InvalidVgicIrq);
        }
        Ok(VirtualInterrupt::Hardware {
            vintid,
            pintid: pid,
            priority,
            group,
            state,
            source: None,
        })
    } else {
        let source = if vintid < 16 && state != IrqState::Inactive {
            let cpuid_raw = raw.get(GICH_LR::cpuid) as u16;
            Some(crate::VcpuId(cpuid_raw))
        } else {
            None
        };
        Ok(VirtualInterrupt::Software {
            vintid,
            eoi_maintenance: raw.get(GICH_LR::eoi) != 0,
            priority,
            group,
            state,
            source,
        })
    }
}

impl VgicHw for Gicv2 {
    type SavedState = Gicv2VcpuHwState;

    fn hw_init(&self) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };

        // SAFETY: GICH is per-CPU, accessed only from EL2 on this PE.
        virt.gich.hcr.write(
            GICH_HCR::new()
                .set(GICH_HCR::en, 0)
                .set(GICH_HCR::uie, 0)
                .set(GICH_HCR::npie, 0)
                .set(GICH_HCR::lrenpie, 0),
        );

        // Clear VMCR/APR/LR region.
        virt.gich.vmcr.write(GICH_VMCR::new());
        virt.gich.apr.write(GICH_APR::new());
        for lr in virt.gich.lr.iter() {
            lr.write(GICH_LR::new());
        }

        cpu::dsb_sy();
        cpu::isb();

        Ok(())
    }

    fn num_lrs(&self) -> Result<usize, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let num = virt.gich.vtr.read().get(GICH_VTR::list_regs) as usize + 1;
        Ok(num.min(64))
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let mut hcr = virt.gich.hcr.read();
        hcr = hcr.set(GICH_HCR::en, enabled as u32);
        virt.gich.hcr.write(hcr);
        cpu::isb();
        Ok(())
    }

    fn set_underflow_irq(&self, enable: bool) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let mut hcr = virt.gich.hcr.read();
        hcr = hcr.set(GICH_HCR::uie, enable as u32);
        virt.gich.hcr.write(hcr);
        cpu::isb();
        Ok(())
    }

    fn current_eoi_mode(&self) -> Result<EoiMode, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let vmcr = virt.gich.vmcr.read();
        Ok(if vmcr.get(GICH_VMCR::eoi_mode) == 0 {
            EoiMode::DropAndDeactivate
        } else {
            EoiMode::DropOnly
        })
    }

    fn empty_lr_bitmap(&self) -> Result<u64, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let num = self.num_lrs()?;
        let mask = if num == 64 {
            u64::MAX
        } else {
            (1u64 << num) - 1
        };
        Ok((virt.gich.elrsr[0].read().bits() as u64
            | (virt.gich.elrsr[1].read().bits() as u64) << 32)
            & mask)
    }

    fn eoi_lr_bitmap(&self) -> Result<u64, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let num = self.num_lrs()?;
        let mask = if num == 64 {
            u64::MAX
        } else {
            (1u64 << num) - 1
        };
        Ok((virt.gich.eisr[0].read().bits() as u64
            | (virt.gich.eisr[1].read().bits() as u64) << 32)
            & mask)
    }

    fn clear_eoi_lr_bitmap(&self, bitmap: u64) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };

        // GICH_EISR{0,1} is read-only. For each LR<n>, the corresponding EISR Status<n> bit is 1
        // when all of the following are true:
        // - LR<n>.State == 0b00 (Inactive)
        // - LR<n>.HW == 0
        // - LR<n>.EOI == 1
        //
        // Therefore, clearing LR<n>.EOI is the most robust way to clear EISR without relying on any
        // implementation-defined writeback behavior.
        let num = self.num_lrs()?.min(64);
        let mask = if num == 64 {
            u64::MAX
        } else {
            (1u64 << num) - 1
        };
        let bitmap = bitmap & mask;

        for idx in 0..num {
            if (bitmap & (1u64 << idx)) == 0 {
                continue;
            }
            let mut lr = virt.gich.lr[idx].read();

            // EISR Status<n> implies HW==0 in the architecture, but we still guard against
            // HW-backed entries here to avoid corrupting the PhysID field overlay.
            if lr.get(GICH_LR::hw) != 0 {
                continue;
            }

            lr = lr.set(GICH_LR::eoi, 0);
            virt.gich.lr[idx].write(lr);
        }
        Ok(())
    }

    fn take_eoi_count(&self) -> Result<u32, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };

        // EOICount drives maintenance interrupts (LRENP). Treat this as a consume-on-read field:
        // read the current value, then clear it so the same condition does not retrigger.
        let mut hcr = virt.gich.hcr.read();
        let count = hcr.get(GICH_HCR::eoicount) as u32;
        if count != 0 {
            hcr = hcr.set(GICH_HCR::eoicount, 0);
            virt.gich.hcr.write(hcr);
            cpu::isb();
        }
        Ok(count)
    }

    fn read_apr(&self, index: usize) -> Result<u32, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        if index != 0 {
            return Err(GicError::IndexOutOfRange);
        }
        Ok(virt.gich.apr.read().bits())
    }

    fn write_apr(&self, index: usize, value: u32) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        if index != 0 {
            return Err(GicError::IndexOutOfRange);
        }
        virt.gich.apr.write(GICH_APR::from_bits(value));
        Ok(())
    }

    fn read_lr(&self, index: usize) -> Result<crate::VirtualInterrupt, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let num = self.num_lrs()?;
        if index >= num {
            return Err(GicError::IndexOutOfRange);
        }
        let lr_raw = virt.gich.lr[index].read();
        decode_lr(lr_raw)
    }

    fn write_lr(&self, index: usize, irq: crate::VirtualInterrupt) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let num = self.num_lrs()?;
        if index >= num {
            return Err(GicError::IndexOutOfRange);
        }
        let lr_raw = encode_lr(irq)?;
        virt.gich.lr[index].write(lr_raw);
        Ok(())
    }

    fn maintenance_reasons(&self) -> Result<crate::MaintenanceReasons, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let misr = virt.gich.misr.read();
        Ok(crate::MaintenanceReasons(misr.bits()))
    }

    fn save_state(&self) -> Result<Self::SavedState, GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        let lr = array::from_fn(|i| virt.gich.lr[i].read());
        Ok(Self::SavedState {
            vmcr: virt.gich.vmcr.read(),
            apr: virt.gich.apr.read(),
            lr,
        })
    }

    fn restore_state(&self, state: &Self::SavedState) -> Result<(), GicError> {
        let Some(virt) = &self.virtualization_extension else {
            return Err(GicError::UnsupportedFeature);
        };
        virt.gich
            .hcr
            .clear_bits(GICH_HCR::new().set(GICH_HCR::en, 1));
        cpu::dsb_sy();
        cpu::isb();

        virt.gich.vmcr.write(state.vmcr);
        virt.gich.apr.write(state.apr);
        for (lr_reg, &val) in virt.gich.lr.iter().zip(state.lr.iter()) {
            lr_reg.write(val);
        }
        Ok(())
    }
}

#[cfg(test)]
mod misr_tests {
    use super::*;
    use crate::IrqGroup;
    use crate::IrqState;
    use crate::MaintenanceReasons;
    use crate::VcpuId;
    use crate::VirtualInterrupt;
    use crate::gicv2::registers::GICH_MISR;
    use crate::gicv2::registers::LrState;

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn misr_mapping_matches_spec() {
        let cases = [
            (
                GICH_MISR::new().set(GICH_MISR::eoi, 1).bits(),
                MaintenanceReasons::EOI,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::u, 1).bits(),
                MaintenanceReasons::UNDERFLOW,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::lrenp, 1).bits(),
                MaintenanceReasons::LR_ENTRY_NOT_PRESENT,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::np, 1).bits(),
                MaintenanceReasons::NO_PENDING,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::vgrp0e, 1).bits(),
                MaintenanceReasons::VGRP0_ENABLED,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::vgrp0d, 1).bits(),
                MaintenanceReasons::VGRP0_DISABLED,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::vgrp1e, 1).bits(),
                MaintenanceReasons::VGRP1_ENABLED,
            ),
            (
                GICH_MISR::new().set(GICH_MISR::vgrp1d, 1).bits(),
                MaintenanceReasons::VGRP1_DISABLED,
            ),
        ];
        for (raw, bit) in cases {
            let reasons = MaintenanceReasons(raw);
            assert_eq!(reasons.bits(), bit);
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn encode_rejects_hw_pending_active() {
        let irq = VirtualInterrupt::Hardware {
            vintid: 45,
            pintid: 200,
            priority: 0x20,
            group: IrqGroup::Group1,
            state: IrqState::PendingActive,
            source: None,
        };
        assert!(matches!(encode_lr(irq), Err(GicError::InvalidVgicIrq)));
    }

    fn roundtrip(irq: VirtualInterrupt) -> VirtualInterrupt {
        let raw = encode_lr(irq).expect("encode_lr must succeed");
        decode_lr(raw).expect("decode_lr must succeed")
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_roundtrip_sw_irq_basic_fields() {
        let irq = VirtualInterrupt::Software {
            vintid: 48,
            eoi_maintenance: false,
            priority: 0x12,
            group: IrqGroup::Group1,
            state: IrqState::Pending,
            source: None,
        };

        let dec = roundtrip(irq);

        assert_eq!(dec.vintid(), irq.vintid());
        assert_eq!(dec.pintid(), None);
        assert_eq!(dec.group(), irq.group());
        assert_eq!(dec.state(), irq.state());
        assert!(!dec.is_hw());

        // GICv2 LR priority stores the top 5 bits (priority >> 3); low 3 bits are lost.
        assert_eq!(dec.priority() & 0xF8, irq.priority() & 0xF8);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_encode_rejects_invalid_vintid() {
        let irq = VirtualInterrupt::Software {
            vintid: 1020,
            eoi_maintenance: false,
            priority: 0,
            group: IrqGroup::Group1,
            state: IrqState::Pending,
            source: None,
        };
        assert!(matches!(encode_lr(irq), Err(GicError::InvalidVgicIrq)));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_encode_hw_requires_valid_pintid() {
        for pintid in [0, 15, 1020, 1023, 2000] {
            let bad = VirtualInterrupt::Hardware {
                vintid: 40,
                pintid,
                priority: 0,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            };
            assert!(matches!(encode_lr(bad), Err(GicError::InvalidVgicIrq)));
        }

        let ok_mid = VirtualInterrupt::Hardware {
            vintid: 40,
            pintid: 40,
            priority: 0,
            group: IrqGroup::Group1,
            state: IrqState::Pending,
            source: None,
        };
        encode_lr(ok_mid).expect("pINTID 40 must be accepted");

        let ok = VirtualInterrupt::Hardware {
            vintid: 40,
            pintid: 89,
            priority: 0xA0,
            group: IrqGroup::Group1,
            state: IrqState::Pending,
            source: None,
        };
        let dec = roundtrip(ok);
        assert_eq!(dec.vintid(), 40);
        assert_eq!(dec.pintid(), Some(89));
        assert!(dec.is_hw());
        assert!(!dec.eoi_maintenance());
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_encode_decode_sgi_source() {
        let irq = VirtualInterrupt::Software {
            vintid: 7,
            eoi_maintenance: false,
            priority: 0x30,
            group: IrqGroup::Group1,
            state: IrqState::Pending,
            source: Some(VcpuId(3)),
        };

        let dec = roundtrip(irq);
        assert_eq!(dec.vintid(), 7);
        assert_eq!(dec.source(), Some(VcpuId(3)));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_encode_sgi_requires_source_when_active() {
        let irq = VirtualInterrupt::Software {
            vintid: 3,
            eoi_maintenance: false,
            priority: 0x10,
            group: IrqGroup::Group1,
            state: IrqState::Pending,
            source: None,
        };

        assert!(matches!(encode_lr(irq), Err(GicError::InvalidVgicIrq)));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_decode_sgi_maps_cpuid_when_active() {
        let raw = GICH_LR::new()
            .set(GICH_LR::virtual_id, 1)
            .set(GICH_LR::cpuid, 7)
            .set_enum(GICH_LR::state, LrState::Pending)
            .set(GICH_LR::hw, 0);
        let irq = decode_lr(raw).expect("must be successed");
        assert!(match irq {
            VirtualInterrupt::Software {
                vintid,
                state,
                source,
                ..
            } => vintid == 1 && state == IrqState::Pending && source == Some(VcpuId(7)),
            _ => false,
        })
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn lr_decode_sgi_sets_source_none_when_inactive() {
        let raw = GICH_LR::new()
            .set(GICH_LR::virtual_id, 2)
            .set_enum(GICH_LR::state, LrState::Invalid)
            .set(GICH_LR::hw, 0);
        let irq = decode_lr(raw).expect("must be successed");
        assert!(match irq {
            VirtualInterrupt::Software { state, source, .. } =>
                state == IrqState::Inactive && source.is_none(),
            _ => false,
        })
    }
}
