#![allow(non_camel_case_types)]
use typestate::bitregs;

bitregs! {
    /// ID_AA64MMFR0_EL1 — AArch64 Memory Model Feature Register 0
    /// Purpose:
    ///     Provides information about the implemented memory model and memory management support in AArch64 state
    /// # Safety
    ///     all field is ReadOnly
    pub(crate) struct ID_AA64MMFR0_EL1: u64 {
        // Physical Address range supported (PA size).
        //   0b0000=32b/4GB, 0001=36b/64GB, 0010=40b/1TB, 0011=42b/4TB,
        //   0100=44b/16TB, 0101=48b/256TB, 0110=52b/4PB (when FEAT_LPA),
        //   0111=56b/64PB (when FEAT_D128). Others: reserved.
        pub parange@[3:0] as PARange {
            PA32bits4GB = 0b000,
            PA36bits64GB = 0b001,
            PA40bits1TB = 0b010,
            PA42bits4TB = 0b011,
            PA44bits16TB = 0b100,
            PA48bits256TB = 0b101,
            PA52bits4PB = 0b110,
            PA56bits64PB = 0b111,
        },

        // Number of ASID bits:
        //   0b0000 = 8-bit ASID
        //   0b0010 = 16-bit ASID
        //   others = reserved
        pub(crate) asidbits@[7:4],

        // Mixed-endian support at EL1/EL2/EL3:
        //   0b0000 = No mixed-endian (SCTLR_ELx.EE fixed)
        //   0b0001 = Mixed-endian supported (SCTLR_ELx.EE configurable)
        //   others = reserved
        pub(crate) bigend@[11:8],

        // Distinction between Secure and Non-secure Memory:
        //   0b0000 = Not supported (not permitted if EL3 is implemented)
        //   0b0001 = Supported
        //   others = reserved
        pub(crate) snsmem@[15:12],

        // Mixed-endian support at EL0 only:
        //   0b0000 = No mixed-endian at EL0 (SCTLR_EL1.E0E fixed)
        //   0b0001 = Mixed-endian at EL0 supported (SCTLR_EL1.E0E configurable)
        //   others = reserved
        // Note: If BigEnd != 0b0000, this field is RES0/invalid.
        pub(crate) bigendel0@[19:16],

        // 16KB granule (stage 1) support:
        //   0b0000 = Not supported
        //   0b0001 = Supported
        //   0b0010 = Supported with 52-bit input/output (when FEAT_LPA2)
        //   others = reserved
        pub(crate) tgran16@[23:20],

        // 64KB granule (stage 1) support:
        //   0b0000 = Supported
        //   0b1111 = Not supported
        //   others = reserved
        pub(crate) tgran64@[27:24],

        // 4KB granule (stage 1) support:
        //   0b0000 = Supported
        //   0b0001 = Supported with 52-bit input/output (when FEAT_LPA2)
        //   0b1111 = Not supported
        //   others = reserved
        pub(crate) tgran4@[31:28],

        // 16KB granule at stage 2 (alternative ID scheme):
        //   0b0000 = See TGran16 (stage 1 field)
        //   0b0001 = Not supported at stage 2
        //   0b0010 = Supported at stage 2
        //   0b0011 = Supported with 52-bit input/output (when FEAT_LPA2)
        //   others = reserved
        // If EL2 not implemented: reads 0b0000. 0b0000 is deprecated when EL2 is implemented.
        pub(crate) tgran16_2@[35:32],

        // 64KB granule at stage 2 (alternative ID scheme):
        //   0b0000 = See TGran64 (stage 1 field)
        //   0b0001 = Not supported at stage 2
        //   0b0010 = Supported at stage 2
        //   others = reserved
        // If EL2 not implemented: reads 0b0000. 0b0000 is deprecated when EL2 is implemented.
        pub(crate) tgran64_2@[39:36],

        // Indicates support for 4KiB memory granule size at stage2
        // If EL2 is not implemented: res0
        pub(crate) tgran4_2@[43:40] as TGran4_2 {
            // Support for 4KB granule at stage 2 is identified in the
            // ID_AA64MMFR0_EL1.TGran4 field.
            SeeEL1 = 0b00,
            NotSupported = 0b01,
            Supported = 0b10,
            // 4KB granule at stage 2 supports 52-bit input addresses and can
            // describe 52-bit output addresses.
            // Applies when FEAT_LPA2 is implemented
            Supported52bit = 0b11,
        },

        // ExS — non-context-synchronizing exception entry/exit:
        //   0b0000 = All exception entries/exits are context-synchronizing
        //   0b0001 = Non-context-synchronizing entry/exit supported (FEAT_ExS)
        //   others = reserved
        pub(crate) exs@[47:44],

        reserved@[55:48] [res0],

        // FGT — Fine-Grained Trap controls presence:
        //   0b0000 = Not implemented (not permitted from Armv8.6)
        //   0b0001 = FEAT_FGT (first level of fine-grained traps)
        //   0b0010 = FEAT_FGT2 (extended fine-grained traps)
        //   others = reserved (from Armv8.9, 0b0001 is not permitted)
        pub(crate) fgt@[59:56],

        // ECV — Enhanced Counter Virtualization:
        //   0b00 = Not implemented
        //   0b01 = FEAT_ECV (counter views, EVNTIS, extends PMSCR/TRFCR fields)
        //   0b10 = FEAT_ECV_POFF (adds CNTPOFF_EL2 and control bits)
        pub(crate) ecv@[63:60] as ECV {
            NotImplemented = 0b00,
            // Enhanced Counter Virtualization is implemented. Supports CNTHCTL_EL2.{EL1TVT, EL1TVCT,
            // EL1NVPCT, EL1NVVCT, EVNTIS}, CNTKCTL_EL1.EVNTIS, CNTPCTSS_EL0 counter views,
            // and CNTVCTSS_EL0 counter views. Extends the PMSCR_EL1.PCT, PMSCR_EL2.PCT,
            // TRFCR_EL1.TS, and TRFCR_EL2.TS fields
            Implemented1 = 0b01,
            // As 0b0001, and the CNTPOFF_EL2 register and the CNTHCTL_EL2.ECV and SCR_EL3.ECVEn
            // fields are implemented.
            Implemented2 = 0b10,
        },
    }
}

bitregs! {
    /// ID_AA64PFR0_EL1 — AArch64 Processor Feature Register 0
    /// Purpose:
    ///     Provides information about the implemented Exception levels in AArch64 state.
    /// # Safety
    ///     all field is ReadOnly
    pub(crate) struct ID_AA64PFR0_EL1: u64 {
        pub(crate) el0@[3:0],
        pub(crate) el1@[7:4],
        pub(crate) el2@[11:8],
        pub(crate) el3@[15:12],
        reserved@[63:16] [res0],
    }
}

bitregs! {
    /// ID_AA64DFR0_EL1 — AArch64 Debug Feature Register 0
    /// Purpose:
    ///     Provides information about the implemented debug architecture, including breakpoint count.
    pub(crate) struct ID_AA64DFR0_EL1: u64 {
        reserved@[11:0] [res0],
        // BRPs: number of breakpoint registers minus one.
        pub(crate) brps@[15:12],
        reserved@[19:16] [res1],
        // WRPs: number of watchpoint registers minus one.
        pub(crate) wrps@[23:20],
        reserved@[63:24] [res0],
    }
}

bitregs! {
    pub(crate) struct MPIDR_EL1: u64 {
        pub(crate) aff0@[7:0],
        pub(crate) aff1@[15:8],
        pub(crate) aff2@[23:16],
        pub(crate) mt@[24:24],
        reserved@[29:25] [res0],
        pub(crate) u@[30:30],
        reserved@[31:31] [res1],
        pub(crate) aff3@[39:32],
        reserved@[63:40] [res0],
    }
}
