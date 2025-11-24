#![allow(non_camel_case_types)]

use typestate::bitregs;

bitregs! {
    /// VTCR_EL2 Virtualization Translation Control Register
    /// Purpose:
    ///     The control register for stage 2 of the EL1&0 translation regime.
    pub(crate) struct VTCR_EL2: u64 {
        // The size offset of the memory region addressed by VTTBR_EL2.
        // Region size = 2^(64 - T0SZ) bytes.
        // Permissible T0SZ depends on SL0 (and SL2 when DS==1) and the translation granule size (TG0).
        // If inconsistent with SL0/TG0, a stage-2 level-0 Translation fault is generated.
        pub(crate) t0sz@[5:0],

        // Stage-2 initial lookup level selector.
        // Encodings depend on TG0 and, when DS==1, the combination {SL2, SL0}.
        // If inconsistent with T0SZ/TG0, stage-2 Translation fault.
        // currently only not implemented FEAT_TTST is supported
        pub(crate) sl0@[7:6] as SL0 {
            // If VTCR_EL2.TG0 is 0b00 (4KB granule), start at level 2. If VTCR_EL2.TG0 is 0b10 (16KB granule) or 0b01 (64KB granule), start at level 3.
            Level2 = 0b00,
            // If VTCR_EL2.TG0 is 0b00 (4KB granule), start at level 1. If VTCR_EL2.TG0 is 0b10 (16KB granule) or 0b01 (64KB granule), start at level 2.
            Level1 = 0b01,
            // If VTCR_EL2.TG0 is 0b00 (4KB granule), start at level 0. If VTCR_EL2.TG0 is 0b10 (16KB granule) or 0b01 (64KB granule), start at level 1.
            Level0 = 0b10,
        },

        // Inner cacheability for stage-2 table walks:
        //   0b00 = Inner Non-cacheable
        //   0b01 = Inner WB RA WA Cacheable
        //   0b10 = Inner WT RA nWA Cacheable
        //   0b11 = Inner WB RA nWA Cacheable
        // Use orgn0 enum
        pub(crate) irgn0@[9:8] as InnerCache {
            NonCacheable = 0b00,
            WBRAWACacheable = 0b01,
            WTRAnWACacheable = 0b10,
            WBRAnWACacheable = 0b11,
        },

        // Outer cacheability for stage-2 table walks:
        //   0b00 = Outer Non-cacheable
        //   0b01 = Outer WB RA WA Cacheable
        //   0b10 = Outer WT RA nWA Cacheable
        //   0b11 = Outer WB RA nWA Cacheable
        pub(crate) orgn0@[11:10] as OuterCache {
            NonCacheable = 0b00,
            WBRAWACacheable = 0b01,
            WTRAnWACacheable = 0b10,
            WBRAnWACacheable = 0b11,
        },

        // Shareability for stage-2 table walks:
        //   0b00 = Non-shareable
        //   0b10 = Outer Shareable
        //   0b11 = Inner Shareable
        //   0b01 = Reserved
        pub(crate) sh0@[13:12] as Shareability {
            NonShareable = 0b00,
            OuterSharable = 0b10,
            InnerSharable = 0b11,
            Reserved = 0b01,
        },

        // Translation granule for stage 2:
        //   0b00 = 4KB, 0b01 = 64KB, 0b10 = 16KB, 0b11 = Reserved
        pub(crate) tg0@[15:14] as TG0 {
            Granule4KB = 0b00,
            Granule64KB = 0b01,
            Granule16KB = 0b10,
            Reserved = 0b11,
        },

        // Output Physical Address Size of stage-2 translation:
        //   0b000=32b, 0b001=36b, 0b010=40b, 0b011=42b, 0b100=44b, 0b101=48b,
        //   0b110=52b when LPA2 semantics apply (DS==1); otherwise behaves as 48b.
        //   0b111=Reserved (do not program unless documented by the implementation).
        pub(crate) ps@[18:16] as PhysicalAddressSize {
            AddressSize32b = 0b000,
            AddressSize36b = 0b001,
            AddressSize40b = 0b010,
            AddressSize42b = 0b011,
            AddressSize44b = 0b100,
            AddressSize48b = 0b101,
            AddressSize52b = 0b110,
            AddressSize56b = 0b111,
        },

        // VMID size control:
        //   0b0 = 8-bit VMID
        //   0b1 = 16-bit VMID (when FEAT_VMID16 is implemented)
        pub(crate) vs@[19:19],
        reserved@[20:20] [res0],

        // Hardware Access flag update (stage 2), when FEAT_HAFDBS is implemented:
        //   0b0=Disabled, 0b1=Enabled
        pub(crate) ha@[21:21],

        // Hardware Dirty state tracking (stage 2), when FEAT_HAFDBS is implemented:
        //   0b0=Disabled, 0b1=Enabled
        pub(crate) hd@[22:22],
        reserved@[24:23] [res0],

        // Hardware use of descriptor bit[59] for stage-2 Block/Page entries (IMPLEMENTATION DEFINED).
        // If not implemented, behaves as RES0/RAZ-WI per implementation.
        pub(crate) hwu59@[25:25],
        // Hardware use of descriptor bit[60] (IMPLEMENTATION DEFINED).
        pub(crate) hwu60@[26:26],
        // Hardware use of descriptor bit[61] (IMPLEMENTATION DEFINED).
        pub(crate) hwu61@[27:27],
        // Hardware use of descriptor bit[62] (IMPLEMENTATION DEFINED).
        pub(crate) hwu62@[28:28],

        // Address space for stage-2 table walks of Non-secure IPA:
        //   0b0 = Walks use Secure PA space
        //   0b1 = Walks use Non-secure PA space
        pub(crate) nsw@[29:29],

        // Address space for stage-2 output of Non-secure IPA:
        //   0b0 = Output PA is in Secure space
        //   0b1 = Output PA is in Non-secure space
        pub(crate) nsa@[30:30],
        reserved@[31:31] [res1],

        // LPA2 semantics enable for stage 2 (affects minimum T0SZ, descriptor formats, PS==0b110 meaning, and SL2 usage):
        //   0b0 = VMSAv8-64 semantics
        //   0b1 = Enable VMSAv8-64 with LPA2 semantics
        pub(crate) ds@[32:32],

        // Extra starting-level bit used together with SL0 when DS==1 (granule-specific; typically 4KB):
        //   When DS==0: RES0
        pub(crate) sl2@[33:33],

        // When FEAT_THE is implemented (default: unknown value)
        //  AssuredOnly attribute enable for VMSAv8-64. Configures use of bit[58] of the stage 2 translation table
        //  Block or Page descriptor.
        //    - 0b0: Bit[58] of each stage 2 translation Block or Page descriptor does
        //      not indicate AssuredOnly attribute
        //    - 0b1: Bit[58] of each stage 2 translation Block or Page descriptor
        //      indicate AssuredOnly attribute
        // When VTCR_EL2.D128 is set: res0
        // otherwise res0
        pub(crate) assured_only@[34:34],

        // When FEAT_THE is implemented (default: unknown value)
        //  Control bit to check for presence of MMU TopLevel1 permission attribute
        //    - 0b0: This bit does not have any effect on stage 2 translations
        //    - 0b1: Enables MMU TopLevel1 permission attribute check for TTBR0_EL1 and TTBR1_EL1 translations
        // otherwise res0
        pub(crate) tl1@[35:35],

        // When FEAT_THE is implemented (default: unknown value)
        //  Control bit to select the stage-2 permission model
        //    - 0b0: Direct permission model
        //    - 0b1: Indirect permission model
        // When VTCR_EL2.D128 is set: res1
        // otherwise: res0
        pub(crate) s2pie@[36:36],

        // When FEAT_S2POE is implemented (default: unknown value)
        //  Permission Overlay enable (stage 2). Not permitted to be cached in a TLB.
        //    - 0b0: Overlay disabled
        //    - 0b1: Overlay enabled
        // otherwise: res0
        pub(crate) s2poe@[37:37],

        // When FEAT_D128 is implemented (default: unknown value)
        //  Selects VMSAv9-128 translation system for stage 2:
        //    - 0b0: Follow VMSAv8-64 translation process
        //    - 0b1: Follow VMSAv9-128 translation process
        // otherwise: res0
        pub(crate) d128@[38:38],

        reserved@[39:39] [res0],

        // When FEAT_THE & FEAT_GCS are implemented (default: unknown value)
        //  Assured stage-1 translations for Guarded Control Stacks:
        //    - 0b0: AssuredOnly in stage 2 not required for privileged GCS data accesses
        //    - 0b1: AssuredOnly in stage 2 required for privileged GCS data accesses
        // otherwise: res0
        pub(crate) gcsh@[40:40],

        // When FEAT_THE is implemented (default: unknown value)
        //  Check for TopLevel0 permission attribute:
        //    - 0b0: No effect on stage-2 translations
        //    - 0b1: Enable TL0 attribute check for TTBR0_EL1/TTBR1_EL1 translations
        // otherwise: res0
        pub(crate) tl0@[41:41],

        reserved@[43:42] [res0],

        // When FEAT_HAFT is implemented (default: unknown value)
        //  Hardware-managed Access Flag for Table descriptors:
        //    - 0b0: Disabled
        //    - 0b1: Enabled
        // otherwise: res0
        pub(crate) haft@[44:44],

        // When FEAT_HDBSS is implemented (default: unknown value)
        //  Hardware tracking of Dirty state Structure:
        //    - 0b0: Disabled
        //    - 0b1: Enabled
        // otherwise: res0
        pub(crate) hdbss@[45:45],
        reserved@[63:46] [res0],
    }
}

bitregs! {
    /// VTTBR_EL2 — Virtualization Translation Table Base Register
    /// # Safety
    ///     Unsupported when VTTBR_EL2 is 128-bit.
    ///     When FEAT_D128 is implemented and VTCR_EL2.D128 == 1, VTTBR_EL2 becomes 128-bit.
    pub(crate) struct VTTBR_EL2: u64 {
        // CnP — Common not Private:
        //   0b0 = Translation table pointed to by this VTTBR is private to the PE.
        //   0b1 = Translation table entries are common across PEs in the same Inner Shareable domain.
        //         Using different tables with the same VMID while CnP==1 is CONSTRAINED UNPREDICTABLE.
        pub(crate) cnp@[0:0],

        // SKL — Skip Level:
        //   Determines how many levels to skip from the regular start level of the
        //   Non-secure stage-2 translation table walk.
        //     0b00 = Skip 0 level
        //     0b01 = Skip 1 level
        //     0b10 = Skip 2 levels
        //     0b11 = Skip 3 levels
        pub(crate) skl@[2:1] as SkipLevel {
            Skip0Level = 0b00,
            Skip1Level = 0b01,
            Skip2Level = 0b10,
            Skip3Level = 0b11,
        },

        reserved@[4:3] [res0],

        // BADDR — Translation table base address:
        //   Bits A[47:x] of the stage-2 base address are held here.
        //   Bits A[(x-1):0] are zero (alignment to the size of the base table),
        //   where x depends on VTCR_EL2.{TG0,SL0,SL2,DS} and the effective start level.
        //   Note: With larger OA sizes (e.g., 52-bit when permitted), higher address bits
        //   are only accessible when the 128-bit form of VTTBR_EL2 is enabled.
        pub(crate) baddr@[47:5],

        // VMID — Virtual Machine Identifier:
        //   When FEAT_VMID16 is implemented and VTCR_EL2.VS==1: full [63:48] used (16-bit VMID).
        //   Otherwise: upper eight bits [63:56] are RES0, yielding an 8-bit VMID.
        pub(crate) vmid@[63:48]
    }
}
