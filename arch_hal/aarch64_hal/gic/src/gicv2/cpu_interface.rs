use typestate::Readable;
use typestate::Writable;

use crate::AckedIrq;
use crate::BinaryPoint;
use crate::EoiMode;
use crate::GicCpuCaps;
use crate::GicCpuInterface;
use crate::GicError;
use crate::gicv2::Gicv2;
use crate::gicv2::registers::GICC_ABPR;
use crate::gicv2::registers::GICC_BPR;
use crate::gicv2::registers::GICC_CTLR;
use crate::gicv2::registers::GICC_DIR;
use crate::gicv2::registers::GICC_EOIR;
use crate::gicv2::registers::GICC_IAR;
use crate::gicv2::registers::GICC_PMR;

impl GicCpuInterface for Gicv2 {
    fn init(&self) -> Result<GicCpuCaps, GicError> {
        // disable cpu interface
        let supports_group0 = if self.is_security_extension_implemented() {
            self.gicc
                .ctlr
                .clear_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp1_non_secure, 1));
            false
        } else {
            self.gicc.ctlr.clear_bits(
                GICC_CTLR::new()
                    .set(GICC_CTLR::enable_grp0, 1)
                    .set(GICC_CTLR::enable_grp1, 1),
            );
            true
        };

        cpu::dsb_sy();
        cpu::isb();

        // initialize banked Distributor state for SGI/PPI targeting
        self.init_banked_sgi_ppi_state()?;

        // set affinity to cpu_id table
        let affinity = cpu::get_current_core_id();
        let mut itargetsr = 0;
        for v in self.gicd.itargetsr0_7.iter().flatten() {
            itargetsr |= v.read();
        }
        let cpu_if = self.cpu_id_from_itargetsr0_7(itargetsr)?;
        let mut table = self.affinity_table.write();
        let slot = &mut table[cpu_if as usize];
        match slot {
            Some(a) if *a != affinity => return Err(GicError::InvalidState),
            None | Some(_) => *slot = Some(affinity),
        }

        // set priority mask(non block)
        self.set_priority_mask(0xff)?;
        // check supported priority bits(RAZ/WI)
        let priority = self.gicc.pmr.read().get(GICC_PMR::priority);

        // set binary point
        self.gicc
            .bpr
            .write(GICC_BPR::new().set(GICC_BPR::binary_point, 0));
        let binary_point = self.gicc.bpr.read().get(GICC_BPR::binary_point);

        // enable cpu interface
        if self.is_security_extension_implemented() {
            self.gicc
                .ctlr
                .set_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp1_non_secure, 1));
        } else {
            self.gicc.ctlr.set_bits(
                GICC_CTLR::new()
                    .set(GICC_CTLR::enable_grp0, 1)
                    .set(GICC_CTLR::enable_grp1, 1),
            );
        }

        // check spilt EOI/deactivate mode support
        let supports_deactivate = if self.is_security_extension_implemented() {
            self.gicc
                .ctlr
                .set_bits(GICC_CTLR::new().set(GICC_CTLR::eoi_mode_ns_non_secure, 1));
            self.gicc.ctlr.read().get(GICC_CTLR::eoi_mode_ns_non_secure) != 0
        } else {
            self.gicc
                .ctlr
                .set_bits(GICC_CTLR::new().set(GICC_CTLR::eoi_mode_ns, 1));
            self.gicc.ctlr.read().get(GICC_CTLR::eoi_mode_ns) != 0
        };

        Ok(GicCpuCaps {
            priority_bits: priority.count_ones() as u8,
            binary_points_min: binary_point as u8,
            supports_group0,
            supports_group1: true,
            supports_separate_binary_points: !self.is_security_extension_implemented(),
            supports_deactivate,
        })
    }

    fn configure(&self, cfg: &crate::GicCpuConfig) -> Result<(), GicError> {
        // disable cpu interface for configuration
        if self.is_security_extension_implemented() {
            self.gicc
                .ctlr
                .clear_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp1_non_secure, 1));
        } else {
            self.gicc.ctlr.clear_bits(
                GICC_CTLR::new()
                    .set(GICC_CTLR::enable_grp0, 1)
                    .set(GICC_CTLR::enable_grp1, 1),
            );
        };
        cpu::dsb_sy();
        cpu::isb();

        // priority mask
        self.set_priority_mask(cfg.priority_mask)?;

        if self.is_security_extension_implemented() {
            // binary point
            match cfg.binary_point {
                BinaryPoint::Common(binary_point) => self
                    .gicc
                    .bpr
                    .write(GICC_BPR::new().set(GICC_BPR::binary_point, binary_point as u32)),
                BinaryPoint::Separate {
                    group0: _,
                    group1: _,
                } => return Err(GicError::UnsupportedFeature),
            }

            match cfg.eoi_mode {
                EoiMode::DropOnly => self
                    .gicc
                    .ctlr
                    .set_bits(GICC_CTLR::new().set(GICC_CTLR::eoi_mode_ns_non_secure, 1)),
                EoiMode::DropAndDeactivate => self
                    .gicc
                    .ctlr
                    .clear_bits(GICC_CTLR::new().set(GICC_CTLR::eoi_mode_ns_non_secure, 1)),
            }

            if cfg.enable_group0 {
                return Err(GicError::UnsupportedFeature);
            }

            self.gicc.ctlr.set_bits(
                GICC_CTLR::new().set(GICC_CTLR::enable_grp1_non_secure, cfg.enable_group1 as u32),
            );
        } else {
            // binary point
            match cfg.binary_point {
                BinaryPoint::Common(binary_point) => {
                    self.gicc
                        .ctlr
                        .set_bits(GICC_CTLR::new().set(GICC_CTLR::cbpr, 1));
                    self.gicc
                        .bpr
                        .write(GICC_BPR::new().set(GICC_BPR::binary_point, binary_point as u32));
                }
                BinaryPoint::Separate { group0, group1 } => {
                    self.gicc
                        .ctlr
                        .clear_bits(GICC_CTLR::new().set(GICC_CTLR::cbpr, 1));
                    self.gicc
                        .bpr
                        .write(GICC_BPR::new().set(GICC_BPR::binary_point, group0 as u32));
                    self.gicc
                        .abpr
                        .write(GICC_ABPR::new().set(GICC_ABPR::binary_point, group1 as u32));
                }
            }

            match cfg.eoi_mode {
                EoiMode::DropOnly => self.gicc.ctlr.set_bits(
                    GICC_CTLR::new()
                        .set(GICC_CTLR::eoi_mode_s, 1)
                        .set(GICC_CTLR::eoi_mode_ns, 1),
                ),
                EoiMode::DropAndDeactivate => self.gicc.ctlr.clear_bits(
                    GICC_CTLR::new()
                        .set(GICC_CTLR::eoi_mode_s, 1)
                        .set(GICC_CTLR::eoi_mode_ns, 1),
                ),
            }

            if cfg.enable_group0 {
                self.gicc
                    .ctlr
                    .set_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp0, 1));
            } else {
                self.gicc
                    .ctlr
                    .clear_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp0, 1));
            }

            if cfg.enable_group1 {
                self.gicc
                    .ctlr
                    .set_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp1, 1));
            } else {
                self.gicc
                    .ctlr
                    .clear_bits(GICC_CTLR::new().set(GICC_CTLR::enable_grp1, 1));
            }
        };

        cpu::dsb_sy();
        cpu::isb();

        Ok(())
    }

    fn set_priority_mask(&self, pmr: u8) -> Result<(), crate::GicError> {
        self.gicc
            .pmr
            .write(GICC_PMR::new().set(GICC_PMR::priority, pmr as u32));
        Ok(())
    }

    fn acknowledge(&self) -> Result<Option<crate::AckedIrq>, crate::GicError> {
        let iar = self.gicc.iar.read();
        let interrupt_id = iar.get(GICC_IAR::interrupt_id);
        let cpu_if = iar.get(GICC_IAR::cpu_id);

        let source = match interrupt_id {
            0..=15 => Some(self.affinity_from_cpu_id(cpu_if as u8)?),
            16..=1019 => None,
            1020..=1023 => return Ok(None), // spurious interrupt
            _ => return Err(GicError::UnsupportedIntId),
        };

        Ok(Some(AckedIrq {
            raw: iar.bits(),
            intid: interrupt_id,
            source,
        }))
    }

    fn end_of_interrupt(&self, ack: crate::AckedIrq) -> Result<(), crate::GicError> {
        self.gicc.eoir.write(GICC_EOIR::from_bits(ack.raw));
        Ok(())
    }

    fn deactivate(&self, ack: crate::AckedIrq) -> Result<(), crate::GicError> {
        self.gicc.dir.write(GICC_DIR::from_bits(ack.raw));
        Ok(())
    }
}
