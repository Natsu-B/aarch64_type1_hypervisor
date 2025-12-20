use core::mem::size_of;

use crate::GicError;
use crate::MmioRegion;
use crate::gicv2::registers::GICD_ICPIDR2;
use crate::gicv2::registers::GICD_TYPER;
use crate::gicv2::registers::GicV2CpuInterface;
use crate::gicv2::registers::GicV2Distributor;
use crate::gicv2::registers::GicV2VirtualCpuInterface;
use crate::gicv2::registers::GicV2VirtualInterfaceControl;
use cpu::CoreAffinity;
use mutex::RawRwLock;
use mutex::RawSpinLock;
use typestate::Readable;

mod cpu_interface;
mod distributor;
mod registers;
mod virtualization;

#[derive(Copy, Clone, Debug)]
pub struct Gicv2mFrameArgs {
    pub reg: MmioRegion,
    /// Optional DT overrides for broken MSI_TYPER values.
    pub msi_base_spi: Option<u32>,
    pub msi_num_spis: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
pub struct Gicv2VirtualizationRegion {
    pub gich: MmioRegion,
    pub gicv: MmioRegion,
    // INT_ID
    pub maintenance_interrupt_id: u32,
}

struct GicV2VirtualizationExtension {
    gich: &'static GicV2VirtualInterfaceControl,
    gicv: &'static GicV2VirtualCpuInterface,
    maintenance_interrupt: u32,
}

pub struct Gicv2 {
    // for gicd specific register protection
    mutex: RawSpinLock<()>,
    security_extension_implemented: bool,
    gicd: &'static GicV2Distributor,
    gicc: &'static GicV2CpuInterface,
    virtualization_extension: Option<GicV2VirtualizationExtension>,
    affinity_table: RawRwLock<[Option<CoreAffinity>; 8]>,
}

impl Gicv2 {
    pub fn new(
        gicd_reg: MmioRegion,
        gicc_reg: MmioRegion,
        virtualization: Option<Gicv2VirtualizationRegion>,
        gicv2m_reg: Option<&[Gicv2mFrameArgs]>,
    ) -> Result<Self, GicError> {
        if !gicd_reg.base.is_multiple_of(0x1000) || gicd_reg.size != size_of::<GicV2Distributor>() {
            return Err(GicError::InvalidSize);
        }
        if !gicc_reg.base.is_multiple_of(0x1000) || gicc_reg.size != size_of::<GicV2CpuInterface>()
        {
            return Err(GicError::InvalidSize);
        }
        if let Some(virtualization) = virtualization {
            let gich = virtualization.gich;
            let gicv = virtualization.gicv;
            let interrupt_id = virtualization.maintenance_interrupt_id;
            if !gich.base.is_multiple_of(0x1000)
                || gich.size != size_of::<GicV2VirtualInterfaceControl>()
            {
                return Err(GicError::InvalidSize);
            }
            if !gicv.base.is_multiple_of(0x1000)
                || gicv.size != size_of::<GicV2VirtualCpuInterface>()
            {
                return Err(GicError::InvalidSize);
            }
            if interrupt_id < 16 || 32 <= interrupt_id {
                return Err(GicError::UnsupportedIntId);
            }
        }
        if let Some(frames) = gicv2m_reg {
            for f in frames {
                if !f.reg.base.is_multiple_of(0x1000) || f.reg.size == 0 {
                    return Err(GicError::InvalidSize);
                }
                match (f.msi_base_spi, f.msi_num_spis) {
                    (None, None) => {}
                    (Some(_), Some(n)) if n != 0 => {}
                    _ => return Err(GicError::InvalidSize),
                }
            }
        }
        let gicd = unsafe { &*(gicd_reg.base as *const GicV2Distributor) };
        let icpidr2 = GICD_ICPIDR2::from_bits(gicd.pidr[6].read());
        if icpidr2.get(GICD_ICPIDR2::arch_rev) != 2 {
            return Err(GicError::UnsupportedRevision);
        }
        Ok(Self {
            mutex: RawSpinLock::new(()),
            security_extension_implemented: gicd.typer.read().get(GICD_TYPER::security_extn) == 1,
            gicd,
            gicc: unsafe { &*(gicc_reg.base as *const GicV2CpuInterface) },
            virtualization_extension: virtualization.map(|v| GicV2VirtualizationExtension {
                gich: unsafe { &*(v.gich.base as *const GicV2VirtualInterfaceControl) },
                gicv: unsafe { &*(v.gicv.base as *const GicV2VirtualCpuInterface) },
                maintenance_interrupt: v.maintenance_interrupt_id,
            }),
            affinity_table: RawRwLock::new([None; 8]),
        })
    }

    pub fn enable_atomic(&self) {
        self.mutex.enable_atomic();
        self.affinity_table.enable_atomic();
    }

    #[inline]
    fn max_intid(&self) -> u32 {
        let typer = self.gicd.typer.read();
        // Maximum interrupts = 32 * (ITLinesNumber + 1), but INTIDs >= 1020 are spurious/reserved.
        (32 * (typer.get(GICD_TYPER::it_lines_number) + 1)).min(1020)
    }

    #[inline]
    fn cpu_id_from_affinity(&self, affinity: CoreAffinity) -> Result<u8, GicError> {
        let table = self.affinity_table.read();
        let cpu_if = table
            .iter()
            .position(|x| x.is_some_and(|a| a == affinity))
            .ok_or(GicError::UnsupportedAffinity)?;
        Ok(cpu_if as u8)
    }

    #[inline]
    fn affinity_from_cpu_id(&self, cpu_if: u8) -> Result<CoreAffinity, GicError> {
        if cpu_if >= 8 {
            return Err(GicError::InvalidCpuId);
        }
        let table = self.affinity_table.read();
        let affinity = table[cpu_if as usize].ok_or(GicError::InvalidCpuId)?;
        Ok(affinity)
    }

    #[inline]
    fn cpu_id_from_itargetsr0_7(&self, value: u8) -> Result<u8, GicError> {
        // read GICD_TYPER to determine number of CPU interfaces
        let ncpu = self.gicd.typer.read().get(GICD_TYPER::cpu_number) as u8 + 1;

        // ITARGETSR0-7 are banked/RO; treat returned value as one-hot mask.
        // On UP systems, these registers can be RAZ/WI and read back as 0.
        if value == 0 {
            if ncpu == 1 {
                return Ok(0);
            }
            return Err(GicError::InvalidCpuId);
        }

        // Require one-hot encoding (a single bit set).
        if (value & (value - 1)) != 0 {
            return Err(GicError::InvalidCpuId);
        }

        let cpu_id = value.trailing_zeros() as u8;
        // Reject out-of-range values and values beyond implemented CPU interfaces.
        if cpu_id >= ncpu {
            return Err(GicError::InvalidCpuId);
        }
        Ok(cpu_id)
    }

    #[inline]
    fn cpu_targets_mask_from_cpu_id(cpu_id: u8) -> Result<u8, GicError> {
        if cpu_id >= 8 {
            return Err(GicError::InvalidCpuId);
        }
        Ok(1u8 << cpu_id)
    }

    #[inline]
    fn is_security_extension_implemented(&self) -> bool {
        self.security_extension_implemented
    }

    #[inline]
    fn word_mask(max_intid: u32, word: usize) -> u32 {
        let start = word * 32;
        let end = core::cmp::min(start + 32, max_intid as usize);
        if end <= start {
            return 0;
        }
        let bits = end - start;
        if bits == 32 {
            0xffff_ffff
        } else {
            (1u32 << bits) - 1
        }
    }
}
