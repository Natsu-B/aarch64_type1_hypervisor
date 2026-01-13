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
pub mod registers;
pub mod vgic_frontend;
pub mod virtualization;

pub const GICV2_GICD_FRAME_SIZE: usize = size_of::<GicV2Distributor>();
pub const GICV2_GICC_FRAME_SIZE: usize = size_of::<GicV2CpuInterface>();

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
}

pub struct Gicv2 {
    // for gicd specific register protection
    mutex: RawSpinLock<()>,
    security_extension_implemented: bool,
    gicd: &'static GicV2Distributor,
    gicc: &'static GicV2CpuInterface,
    virtualization_extension: Option<GicV2VirtualizationExtension>,
    /// Shadow logical group bitmap used when Security Extensions are absent.
    logical_groups: RawRwLock<[u32; 32]>,
    affinity_table: RawRwLock<
        [Option<(
            CoreAffinity,
            bool, /* enable_group0 */
            bool, /* enable_group1 */
        )>; 8],
    >,
}

unsafe impl Sync for Gicv2 {}

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
            }),
            logical_groups: RawRwLock::new([0; 32]),
            affinity_table: RawRwLock::new([None; 8]),
        })
    }

    pub fn enable_atomic(&self) {
        self.mutex.enable_atomic();
        self.logical_groups.enable_atomic();
        self.affinity_table.enable_atomic();
    }

    #[inline]
    fn max_intid(&self) -> u32 {
        let typer = self.gicd.typer.read();
        // Maximum interrupts = 32 * (ITLinesNumber + 1), but INTIDs >= 1020 are spurious/reserved.
        (32 * (typer.get(GICD_TYPER::it_lines_number) + 1)).min(1020)
    }

    #[inline]
    pub(crate) fn cpu_id_from_affinity(&self, affinity: CoreAffinity) -> Result<u8, GicError> {
        let table = self.affinity_table.read();
        let cpu_if = table
            .iter()
            .position(|x| x.is_some_and(|a| a.0 == affinity))
            .ok_or(GicError::UnsupportedAffinity)?;
        Ok(cpu_if as u8)
    }

    #[inline]
    pub(crate) fn affinity_from_cpu_id(&self, cpu_if: u8) -> Result<CoreAffinity, GicError> {
        if cpu_if >= 8 {
            return Err(GicError::InvalidCpuId);
        }
        let table = self.affinity_table.read();
        let affinity = table[cpu_if as usize].ok_or(GicError::InvalidCpuId)?;
        Ok(affinity.0)
    }

    #[inline]
    fn get_enable_group_from_affinity(
        &self,
        affinity: CoreAffinity,
    ) -> Result<(bool, bool), GicError> {
        let table = self.affinity_table.read();
        let cpu_if = table
            .iter()
            .position(|x| x.is_some_and(|a| a.0 == affinity))
            .ok_or(GicError::UnsupportedAffinity)?;
        let entry = table[cpu_if].ok_or(GicError::InvalidCpuId)?;
        Ok((entry.1, entry.2))
    }

    #[inline]
    fn cpu_if_and_targets_mask_from_itargetsr0_7(&self, value: u8) -> Result<u8, GicError> {
        let ncpu = self.gicd.typer.read().get(GICD_TYPER::cpu_number) as u8 + 1;

        // ITARGETSR0-7 are banked/RO; treat returned value as one-hot mask.
        // On UP systems, these registers can be RAZ/WI and read back as 0.
        if ncpu == 1 {
            return Ok(0);
        }

        // Require one-hot encoding (a single bit set).
        if value == 0 || (value & (value - 1)) != 0 {
            return Err(GicError::InvalidCpuId);
        }

        let cpu_if = value.trailing_zeros() as u8;
        if cpu_if >= ncpu {
            return Err(GicError::InvalidCpuId);
        }

        Ok(cpu_if)
    }

    #[inline]
    fn cpu_targets_mask_from_affinity(&self, affinity: CoreAffinity) -> Result<u8, GicError> {
        let cpu_if = self.cpu_id_from_affinity(affinity)?;
        Ok(1 << cpu_if)
    }

    #[inline]
    fn is_security_extension_implemented(&self) -> bool {
        self.security_extension_implemented
    }

    fn set_shadow_group(&self, intid: u32, group: crate::IrqGroup) -> Result<(), GicError> {
        if intid >= self.max_intid() {
            return Err(GicError::UnsupportedIntId);
        }
        let word = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);
        let mut bitmap = self.logical_groups.write();
        match group {
            crate::IrqGroup::Group0 => bitmap[word] &= !bit,
            crate::IrqGroup::Group1 => bitmap[word] |= bit,
        }
        Ok(())
    }

    fn shadow_group(&self, intid: u32) -> Result<crate::IrqGroup, GicError> {
        if intid >= self.max_intid() {
            return Err(GicError::UnsupportedIntId);
        }
        let word = (intid / 32) as usize;
        let bit = 1u32 << (intid % 32);
        let bitmap = self.logical_groups.read();
        let is_group1 = (bitmap[word] & bit) != 0;
        Ok(if is_group1 {
            crate::IrqGroup::Group1
        } else {
            crate::IrqGroup::Group0
        })
    }

    fn reset_shadow_groups(&self) {
        let mut bitmap = self.logical_groups.write();
        for word in bitmap.iter_mut() {
            *word = 0;
        }
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
