use typestate::Readable;
use typestate::Writable;

use crate::EnableOp;
use crate::GicDistributor;
use crate::GicError;
use crate::IrqGroup;
use crate::TriggerMode;
use crate::gicv2::Gicv2;
use crate::gicv2::registers::GICD_CTLR;

impl Gicv2 {
    pub(crate) fn init_banked_sgi_ppi_state(&self) -> Result<(), GicError> {
        // disable PPIs
        const PPI_MASK: u32 = 0xffff_0000;

        self.gicd.icenabler[0].write(PPI_MASK);
        self.gicd.icpendr[0].write(PPI_MASK);
        self.gicd.icactiver[0].write(PPI_MASK);

        for v in self.gicd.ipriorityr.iter().take(8).flatten() {
            v.write(0xff);
        }

        if !self.is_security_extension_implemented() {
            self.gicd.igroupr[0].write(0xffff_ffff);
        }

        cpu::dsb_sy();
        cpu::isb();

        Ok(())
    }
}

impl GicDistributor for Gicv2 {
    fn init(&self) -> Result<(), crate::GicError> {
        // disable distributor
        let mutex = self.mutex.lock();
        if self.is_security_extension_implemented() {
            self.gicd
                .ctlr
                .write(GICD_CTLR::new().set(GICD_CTLR::enable_grp1_non_secure, 0));
        } else {
            self.gicd.ctlr.write(
                GICD_CTLR::new()
                    .set(GICD_CTLR::enable_grp0, 0)
                    .set(GICD_CTLR::enable_grp1, 0),
            );
        }
        drop(mutex);
        cpu::dsb_sy();
        cpu::isb();

        let max_intid = self.max_intid();
        let num_words = ((max_intid as usize) + 31) / 32;

        // Program interrupt groups only when Security Extensions are not implemented.
        // On implementations with Security Extensions (e.g. GIC-400), GICD_IGROUPRn is Secure-only;
        // Non-secure accesses are RAZ/WI. Firmware must configure interrupt groups.
        if !self.is_security_extension_implemented() {
            let words = core::cmp::min(num_words, self.gicd.igroupr.len());
            for n in 0..words {
                let mask = Self::word_mask(max_intid, n);
                if mask == 0 {
                    break;
                }
                self.gicd.igroupr[n].write(mask);
            }
        }

        // disable all interrupts
        let words = core::cmp::min(num_words, self.gicd.icenabler.len());
        for n in 0..words {
            let mask = Self::word_mask(max_intid, n);
            if mask == 0 {
                break;
            }
            self.gicd.icenabler[n].write(mask);
            self.gicd.icpendr[n].write(mask);
            self.gicd.icactiver[n].write(mask);
        }

        let mutex = self.mutex.lock();
        let ipriority_capacity = (self.gicd.ipriorityr.len() * 4) as u32;
        let actual_interrupts = max_intid.min(ipriority_capacity);
        for intid in 0..(actual_interrupts as usize) {
            self.gicd.ipriorityr[intid / 4][intid % 4].write(0xff);
        }
        drop(mutex);

        // enable distributor
        if self.is_security_extension_implemented() {
            self.gicd
                .ctlr
                .write(GICD_CTLR::new().set(GICD_CTLR::enable_grp1_non_secure, 1));
        } else {
            self.gicd.ctlr.write(
                GICD_CTLR::new()
                    .set(GICD_CTLR::enable_grp0, 1)
                    .set(GICD_CTLR::enable_grp1, 1),
            );
        }
        cpu::dsb_sy();
        cpu::isb();

        Ok(())
    }

    fn set_spi_enable(&self, intid: u32, enable: bool) -> Result<(), GicError> {
        if intid < 32 || intid >= self.max_intid() {
            return Err(GicError::UnsupportedIntId);
        }
        if enable {
            self.gicd.isenabler[intid as usize / 32].write(1 << intid as usize % 32);
        } else {
            self.gicd.icenabler[intid as usize / 32].write(1 << intid as usize % 32);
        }

        Ok(())
    }

    fn configure_spi(
        &self,
        intid: u32,
        group: crate::IrqGroup,
        priority: u8,
        trigger: crate::TriggerMode,
        route: crate::SpiRoute,
        enable: EnableOp,
    ) -> Result<(), crate::GicError> {
        if group == IrqGroup::Group0 {
            // this crate does not support secure state
            return Err(GicError::UnsupportedFeature);
        }
        if intid < 32 || intid >= self.max_intid() {
            return Err(GicError::UnsupportedIntId);
        }
        let word = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);
        let enable_after = match enable {
            EnableOp::Keep => {
                (self.gicd.isenabler[word].read() >> (intid as usize % 32)) & 0b1 != 0
            }
            EnableOp::Enable => true,
            EnableOp::Disable => false,
        };

        // disable interrupts for setting
        self.gicd.icenabler[word].write(bit);

        // clear pending/active
        self.gicd.icpendr[word].write(bit);
        self.gicd.icactiver[word].write(bit);

        let mutex = self.mutex.lock();
        // Non-secure Group 1: set IGROUPR bit (RMW; do not overwrite other interrupts' group bits).
        // On implementations with Security Extensions (e.g. GIC-400), GICD_IGROUPRn is Secure-only;
        // Non-secure accesses are RAZ/WI. Firmware must configure interrupt groups.
        if !self.is_security_extension_implemented() {
            let igroupr = self.gicd.igroupr[word].read();
            self.gicd.igroupr[word].write(igroupr | bit);
        }

        self.gicd.ipriorityr[intid as usize / 4][intid as usize % 4]
            .update_bits(0b1111_1111, priority);

        match route {
            crate::SpiRoute::Specific(core_affinity) => {
                let cpu_id = self.cpu_id_from_affinity(core_affinity)?;
                let cpu_targets = Self::cpu_targets_mask_from_cpu_id(cpu_id)?;
                let spi = (intid as usize)
                    .checked_sub(32)
                    .ok_or(GicError::UnsupportedIntId)?;
                let reg = spi / 4;
                let byte = spi % 4;
                self.gicd.itargetsr[reg][byte].write(cpu_targets);
            }
            crate::SpiRoute::AnyParticipating => return Err(GicError::UnsupportedFeature),
        }

        self.gicd.icfgr[intid as usize / 16].clear_bits(0b11 << ((intid as usize % 16) * 2));
        self.gicd.icfgr[intid as usize / 16].set_bits(
            if trigger == TriggerMode::Level {
                0b00
            } else {
                0b10
            } << ((intid as usize % 16) * 2),
        );
        drop(mutex);

        if enable_after {
            self.gicd.isenabler[word].write(bit);
        }

        Ok(())
    }

    fn set_pending(&self, intid: u32, pending: bool) -> Result<(), crate::GicError> {
        if intid < 32 || intid >= self.max_intid() {
            return Err(GicError::UnsupportedIntId);
        }
        let word = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);

        if pending {
            self.gicd.ispendr[word].write(bit);
        } else {
            self.gicd.icpendr[word].write(bit);
        }
        Ok(())
    }
}
