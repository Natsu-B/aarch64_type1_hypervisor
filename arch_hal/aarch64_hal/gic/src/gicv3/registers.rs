#![allow(non_camel_case_types)]

use core::mem::size_of;
use typestate::ReadOnly;
use typestate::ReadWrite;
use typestate::WriteOnly;
use typestate::bitregs;

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<GicV3Distributor>() == 0x1_0000);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<GicV3RedistributorCtrl>() == 0x1_0000);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<GicV3RedistributorSgiPpi>() == 0x1_0000);

#[repr(C)]
pub(crate) struct GicV3Distributor {
    // 0x0000 - 0x003C
    pub ctlr: ReadWrite<GICD_CTLR>, // 0x0000
    pub typer: ReadOnly<u32>,       // 0x0004
    pub iidr: ReadOnly<u32>,        // 0x0008
    pub typer2: ReadOnly<u32>,      // 0x000C
    pub statusr: ReadWrite<u32>,    // 0x0010
    // Reserved 0x0014-0x001C (12 bytes)
    _rsvd_0014_001c: [u8; 0x0C],
    _impldef_0020_003c: [u8; 0x20], // 0x0020-0x003C

    // 0x0040 - 0x0058
    pub setspi_nsr: WriteOnly<u32>, // 0x0040
    _rsvd_0044: [u8; 0x04],         // 0x0044
    pub clrspi_nsr: WriteOnly<u32>, // 0x0048
    _rsvd_004c: [u8; 0x04],         // 0x004C
    pub setspi_sr: WriteOnly<u32>,  // 0x0050
    _rsvd_0054: [u8; 0x04],         // 0x0054
    pub clrspi_sr: WriteOnly<u32>,  // 0x0058
    _rsvd_005c_007c: [u8; 0x24],    // 0x005C-0x007F

    // 0x0080 - 0x0FFC
    pub igroupr: [ReadWrite<u32>; 32],   // 0x0080-0x00FC
    pub isenabler: [ReadWrite<u32>; 32], // 0x0100-0x017C
    pub icenabler: [ReadWrite<u32>; 32], // 0x0180-0x01FC
    pub ispendr: [ReadWrite<u32>; 32],   // 0x0200-0x027C
    pub icpendr: [ReadWrite<u32>; 32],   // 0x0280-0x02FC
    pub isactiver: [ReadWrite<u32>; 32], // 0x0300-0x037C
    pub icactiver: [ReadWrite<u32>; 32], // 0x0380-0x03FC
    // Priority window: 0x0400..0x07FF (exactly 0x400 bytes)
    pub ipriorityr: [ReadWrite<u32>; 255],
    _rsvd_07fc_07ff: [u8; 4],

    // 0x0800 - 0x0BFC (RAZ/WI when ARE=1)
    pub itargetsr: [ReadOnly<u32>; 256], // offset 0x0800

    // 0x0C00 - 0x0EFC
    pub icfgr: [ReadWrite<u32>; 64],    // 0x0C00-0x0CFC
    pub igrpmodr: [ReadWrite<u32>; 32], // 0x0D00-0x0D7C
    _rsvd_0d80_0dff: [u8; 0x80],        // 0x0D80-0x0DFF
    pub nsacr: [ReadWrite<u32>; 64],    // 0x0E00-0x0EFC

    // 0x0F00 - 0x0FFC
    pub sgir: WriteOnly<u32>,           // 0x0F00
    _rsvd_0f04_0f0f: [u8; 0x0C],        // 0x0F04-0x0F0F
    pub cpendsgir: [ReadWrite<u32>; 4], // 0x0F10-0x0F1C
    pub spendsgir: [ReadWrite<u32>; 4], // 0x0F20-0x0F2C
    _rsvd_0f30_0f7c: [u8; 0x50],        // 0x0F30-0x0F7F
    pub inmir: [ReadWrite<u32>; 32],    // 0x0F80-0x0FFC

    // ---- Extended SPI (E) range ----
    pub igroupr_e: [ReadWrite<u32>; 32], // 0x1000-0x107C
    _rsvd_1080_11ff: [u8; 0x180],
    pub isenabler_e: [ReadWrite<u32>; 32], // 0x1200-0x127C
    _rsvd_1280_13ff: [u8; 0x180],
    pub icenabler_e: [ReadWrite<u32>; 32], // 0x1400-0x147C
    _rsvd_1480_15ff: [u8; 0x180],
    pub ispendr_e: [ReadWrite<u32>; 32], // 0x1600-0x167C
    _rsvd_1680_17ff: [u8; 0x180],
    pub icpendr_e: [ReadWrite<u32>; 32], // 0x1800-0x187C
    _rsvd_1880_19ff: [u8; 0x180],
    pub isactiver_e: [ReadWrite<u32>; 32], // 0x1A00-0x1A7C
    _rsvd_1a80_1bff: [u8; 0x180],
    pub icactiver_e: [ReadWrite<u32>; 32], // 0x1C00-0x1C7C
    _rsvd_1c80_1fff: [u8; 0x380],
    pub ipriorityr_e: [ReadWrite<u32>; 256], // 0x2000-0x23FC
    _rsvd_2400_2fff: [u8; 0x0C00],
    pub icfgr_e: [ReadWrite<u32>; 64], // 0x3000-0x30FC
    _rsvd_3100_33ff: [u8; 0x0300],
    pub igrpmodr_e: [ReadWrite<u32>; 32], // 0x3400-0x347C
    _rsvd_3480_35ff: [u8; 0x0180],
    pub nsacr_e: [ReadWrite<u32>; 64], // 0x3600-0x36FC
    _rsvd_3700_3afc: [u8; 0x0400],
    pub inmir_e: [ReadWrite<u32>; 32], // 0x3B00-0x3B7C
    _rsvd_3b80_5fff: [u8; 0x2480],     // 0x3B80-0x5FFF

    // IROUTER window: 0x6000..0x7FFF
    pub irouter: [ReadWrite<u64>; 1020], // 0x6000-0x7FDF
    _rsvd_7fe0_7fff: [u8; 0x20],         // 0x7FE0-0x7FFF

    // Extended IROUTER window: 0x8000..0x9FFF
    pub irouter_e: [ReadWrite<u64>; 1024], // 0x8000-0x9FFF

    // 0xA000..0xFFD0
    _rsvd_a000_ffd0: [u8; 0x5FD0],
    // 0xFFD0..0xFFFC
    pub idregs_ro: [ReadOnly<u32>; 12],
}

/// Redistributor control/LPI frame at RD_base (64KB)
#[repr(C)]
pub(crate) struct GicV3RedistributorCtrl {
    /// Redistributor Control Register
    pub ctlr: ReadWrite<u32>, // 0x0000 GICR_CTLR
    /// Redistributor ID Register
    pub iidr: ReadOnly<u32>, // 0x0004 GICR_IIDR
    /// Redistributor Type Register (64-bit)
    pub typer: ReadOnly<u64>, // 0x0008 GICR_TYPER
    _rsvd_0010: [u8; 0x04], // 0x0010
    /// Power Management Control
    pub waker: ReadWrite<u32>, // 0x0014 GICR_WAKER
    _rsvd_0018_006c: [u8; 0x58], // 0x0018-0x006C
    /// LPI Property Table Base (64-bit)
    pub propbaser: ReadWrite<u64>, // 0x0070 GICR_PROPBASER
    /// LPI Pending Table Base (64-bit)
    pub pendbaser: ReadWrite<u64>, // 0x0078 GICR_PENDBASER
    _rsvd_0080_ffcc: [u8; 0xFF50], // 0x0080-0xFFCC
    /// Peripheral/Component ID window (RO)
    pub idregs_ro: [ReadOnly<u32>; 12], // 0xFFD0-0xFFFC
}

/// Redistributor SGI/PPI frame at SGI_base = RD_base + 0x10000 (64KB)
#[repr(C)]
pub(crate) struct GicV3RedistributorSgiPpi {
    _rsvd_0000_007c: [u8; 0x80],  // 0x0000-0x007C
    pub igroupr0: ReadWrite<u32>, // 0x0080
    _rsvd_0084_00fc: [u8; 0x7C],
    pub isenabler0: ReadWrite<u32>, // 0x0100
    _rsvd_0104_017c: [u8; 0x7C],
    pub icenabler0: ReadWrite<u32>, // 0x0180
    _rsvd_0184_01fc: [u8; 0x7C],
    pub ispendr0: ReadWrite<u32>, // 0x0200
    _rsvd_0204_027c: [u8; 0x7C],
    pub icpendr0: ReadWrite<u32>, // 0x0280
    _rsvd_0284_02fc: [u8; 0x7C],
    pub isactiver0: ReadWrite<u32>, // 0x0300
    _rsvd_0304_037c: [u8; 0x7C],
    pub icactiver0: ReadWrite<u32>, // 0x0380
    _rsvd_0384_03fc: [u8; 0x7C],
    pub ipriorityr: [ReadWrite<u32>; 8], // 0x0400-0x041C
    _rsvd_0420_0bfc: [u8; 0x7E0],        // 0x0420-0x0BFC
    pub icfgr0: ReadOnly<u32>,           // 0x0C00
    pub icfgr1: ReadWrite<u32>,          // 0x0C04
    _rsvd_0c08_0cfc: [u8; 0xF8],         // 0x0C08-0x0CFC
    pub igrpmodr0: ReadWrite<u32>,       // 0x0D00
    _rsvd_0d04_0dfc: [u8; 0xFC],
    pub nsacr: ReadWrite<u32>, // 0x0E00
    _rsvd_0e04_0efc: [u8; 0xFC],
    // Pad remainder of 64KB SGI_base frame
    _rsvd_0f00_ffff: [u8; 0xF100], // 0x0F00-0xFFFF
}

bitregs! {
    /// GIC Distributor Control Register bits (ARM IHI 0048B Table 4-1).
    pub(crate) struct GICD_CTLR: u32 {
        // Enable Group0 interrupts
        pub(crate) enable_grp0@[0:0],
        // Enable Group1 interrupts
        pub(crate) enable_grp1@[1:1],
        reserved@[3:2] [res0],
        // Affinity Routing Enable
        pub(crate) are@[4:4],
        reserved@[5:5] [res0],
        // Disable Security
        pub(crate) ds@[6:6],
        // Enable 1 of N Wakeup Functionality
        pub(crate) e1nwf@[7:7],
        reserved@[30:8] [res0],
        // Register Write Pending. Read Only
        pub(crate) rwp@[31:31] as RWP {
            NoRegisterWriteInProgress = 0b0,
            RegisterWriteInProgress = 0b1,
        },
    }
}
