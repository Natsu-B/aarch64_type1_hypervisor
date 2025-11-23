#![allow(non_camel_case_types)]

use typestate::bitregs;

bitregs! {
    /// TCR_EL2 Translation Control Register (EL2)
    /// Purpose:
    ///     Controls EL2 stage-1 translations (EL2 / EL2&0 translation regime):
    ///     virtual address size, granule, cacheability/shareability, top-byte/tag
    ///     handling, and various EL2-specific extensions (LPA2, MTE, PAuth, etc).
    pub(crate) struct TCR_EL2: u64 {
        // Size offset of the virtual address range translated by TTBR0_EL2.
        // Region size = 2^(64 - T0SZ) bytes.
        // Valid range depends on TG0, the initial lookup level, and DS when LPA2 is enabled.
        // Too small values cause a level-0 translation fault.
        pub(crate) t0sz@[5:0],

        // Reserved, must be programmed as 0.
        reserved@[7:6] [res0],

        // Inner cacheability for EL2 stage-1 table walks using TTBR0_EL2:
        //   0b00 = Inner Non-cacheable
        //   0b01 = Inner WB RA WA Cacheable
        //   0b10 = Inner WT RA nWA Cacheable
        //   0b11 = Inner WB RA nWA Cacheable
        pub(crate) irgn0@[9:8] as InnerCache {
            NonCacheable = 0b00,
            WBRAWACacheable = 0b01,
            WTRAnWACacheable = 0b10,
            WBRAnWACacheable = 0b11,
        },

        // Outer cacheability for EL2 stage-1 table walks using TTBR0_EL2:
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

        // Shareability for EL2 stage-1 table walks using TTBR0_EL2:
        //   0b00 = Non-shareable
        //   0b10 = Outer Shareable
        //   0b11 = Inner Shareable
        //   0b01 = Reserved (CONSTRAINED UNPREDICTABLE if used)
        pub(crate) sh0@[13:12] as Shareability {
            NonShareable = 0b00,
            OuterSharable = 0b10,
            InnerSharable = 0b11,
            Reserved = 0b01,
        },

        // Translation granule for EL2 stage-1 (TTBR0_EL2):
        //   0b00 = 4KB
        //   0b01 = 64KB
        //   0b10 = 16KB
        //   0b11 = Reserved
        pub(crate) tg0@[15:14] as TG0 {
            Granule4KB = 0b00,
            Granule64KB = 0b01,
            Granule16KB = 0b10,
            Reserved = 0b11,
        },

        // Physical Address Size (PA space size) for EL2 stage-1 output:
        //   0b000 = 32 bits (4   GB)
        //   0b001 = 36 bits (64  GB)
        //   0b010 = 40 bits (1   TB)
        //   0b011 = 42 bits (4   TB)
        //   0b100 = 44 bits (16  TB)
        //   0b101 = 48 bits (256 TB)
        //   0b110 = 52 bits (4   PB), if LPA/LPA2 conditions are met; otherwise
        //           treated as 0b101 (48-bit output).
        //   0b111 = Reserved
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

        // Reserved, must be programmed as 0.
        reserved@[19:19] [res0],

        // Top Byte Ignored (TBI) for addresses in the TTBR0_EL2 region:
        //   0b0 = Top byte participates in address match.
        //   0b1 = Top byte is ignored for address translation and can be used
        //         as a tag.
        // Affects EL2 AArch64 addresses translated via TTBR0_EL2 regardless of
        // whether EL2 or EL2&0 translation regime is used.
        // If FEAT_PAuth is implemented and TBID == 1, TBI only applies to Data
        // accesses (Instruction addresses keep their top byte checked).
        pub(crate) tbi@[20:20],

        // Hardware Access flag update for EL2 stage-1 translations (FEAT_HAFDBS):
        //   0b0 = Hardware AF update disabled (software must manage AF).
        //   0b1 = Hardware sets Access flag on first access.
        pub(crate) ha@[21:21],

        // Hardware management of dirty state for EL2 stage-1 translations (FEAT_HAFDBS):
        //   0b0 = Hardware dirty-bit management disabled.
        //   0b1 = Hardware dirty-bit management enabled (e.g. DBM-like tracking).
        // When HA is effectively 0, HD behaves as 0 for all purposes except direct reads.
        pub(crate) hd@[22:22],

        // Reserved, must be programmed as 1 (RES1).
        reserved@[23:23] [res1],

        // Hierarchical Permission Disable for EL2 stage-1 (FEAT_HPDS):
        //   0b0 = Hierarchical permissions enabled. APTable/PXNTable/UXNTable
        //         bits in table descriptors are honored.
        //   0b1 = Hierarchical permissions disabled. These table-level bits are
        //         treated as 0 (permissions come only from leaf descriptors), and
        //         some of their bit positions can be reused (see HWU* fields).
        pub(crate) hpd@[24:24],

        // Hardware use of descriptor bit[59] for EL2 stage-1 Block/Page entries
        // (FEAT_HPDS2):
        //   0b0 = bit[59] cannot be used by hardware (reserved/RAZ-WI).
        //   0b1 = bit[59] may be used by hardware for an IMPLEMENTATION DEFINED
        //         purpose, but only when HPD == 1. Effective value is 0 otherwise.
        pub(crate) hwu59@[25:25],

        // Hardware use of descriptor bit[60] (same rules as HWU59).
        pub(crate) hwu60@[26:26],

        // Hardware use of descriptor bit[61] (same rules as HWU59).
        pub(crate) hwu61@[27:27],

        // Hardware use of descriptor bit[62] (same rules as HWU59).
        pub(crate) hwu62@[28:28],

        // Top Byte Ignore Disable for instructions (FEAT_PAuth):
        //   0b0 = TBI applies to both Instruction and Data accesses.
        //   0b1 = TBI applies only to Data accesses; Instruction address top byte
        //         is always checked (used e.g. for pointer authentication).
        pub(crate) tbid@[29:29],

        // Tag Check MAsk for EL2 (FEAT_MTE2):
        //   Controls generation of Tag-Unchecked accesses when logical address
        //   tag in bits[59:56] is zero.
        //   0b0 = No effect on tag checking.
        //   0b1 = EL2 accesses with tag 0b0000 are treated as Unchecked (no tag fault).
        pub(crate) tcma@[30:30],

        // Reserved, must be programmed as 1 (RES1).
        reserved@[31:31] [res1],

        // LPA2 semantics enable (FEAT_LPA2):
        //   0b0 = VMSAv8-64 style descriptors:
        //         * 4KB/16KB granules cannot describe 52-bit outputs (PS=0b110
        //           behaves as 48-bit unless LPA is otherwise allowed).
        //         * Minimum T0SZ is 16; smaller values fault at level 0.
        //   0b1 = Enable LPA2-style descriptors for 4KB/16KB:
        //         * Allows 52-bit output addresses (with PS=0b110 and LPA support).
        //         * Minimum T0SZ is 12; smaller values fault at level 0.
        //         * Some descriptor bits are repurposed for extended address bits
        //           and shareability; TLBI range encodings also change.
        //   For 64KB granule this bit is effectively 0 (RES0) architecturally.
        pub(crate) ds@[32:32],

        // Extended memory tag checking (FEAT_MTE_NO_ADDRESS_TAGS or FEAT_MTE_CANONICAL_TAGS):
        //   Controls how bits[59:56] of a 64-bit VA are treated when EL2 uses
        //   tagged pointers for data accesses through TTBR0_EL2.
        //   0b0 = No extended tag semantics (normal MTE/TBI behavior).
        //   0b1 = Bits[59:56] are treated as a Logical Address Tag and are not
        //         part of the PAC field; canonical tag checking rules apply.
        pub(crate) mtx@[33:33],

        // Remaining bits are Reserved, must be programmed as 0.
        reserved@[63:34] [res0],
    }
}

bitregs! {
    /// TTBR0_EL2 — Translation Table Base Register 0 (EL2)
    ///
    /// Purpose:
    ///     Holds the base address of the EL2 stage-1 translation table pointed to by
    ///     TTBR0_EL2, and (when implemented) an ASID field for EL2 translations.
    ///     Also carries the CnP attribute used to control sharing of TLB entries
    ///     across PEs, analogous in spirit to VTTBR_EL2.
    ///
    /// Notes:
    ///   - Architecturally laid out as:
    ///       [0]   CnP
    ///       [47:1] BADDR (base address, alignment-encoded)
    ///       [63:48] ASID (or RES0 on implementations without EL2 ASID support).
    ///   - Required alignment and effective width of BADDR depend on TCR_EL2
    ///     configuration (T0SZ, TG0, DS/LPA2, IPS).
    pub(crate) struct TTBR0_EL2: u64 {
        // CnP — Common not Private (FEAT_TTCNP):
        //   Controls whether translations derived from this TTBR can be treated
        //   as common across PEs in the same Inner Shareable domain.
        //
        //   0b0 = Translation table pointed to by this TTBR is private to the PE.
        //         TLB entries are treated as per-PE, and non-shareable TLBI
        //         operations are sufficient to invalidate them.
        //
        //   0b1 = Translation table entries are common across PEs in the same
        //         Inner Shareable domain that also have CnP==1 for the matching
        //         ASID. This enables implementations to keep a single shared TLB
        //         entry instead of per-PE copies.
        //
        // If FEAT_TTCNP is not implemented, this bit behaves as RES0/RAZ-WI.
        pub(crate) cnp@[0:0],

        // BADDR — Translation table base address:
        //   Bits A[47:x] of the EL2 stage-1 base address are held here; the low
        //   bits A[(x-1):0] are zero due to alignment of the base table.
        //
        //   - The value of x (and thus the required alignment) is determined by
        //     the translation configuration in TCR_EL2:
        //       * TG0 (granule size),
        //       * T0SZ (input VA size),
        //       * DS (LPA2 semantics) and IPS (output address size).
        //   - Any bits that are architecturally RES0 within [47:1] must be
        //     written as zero; if not, behavior is CONSTRAINED UNPREDICTABLE
        //     (typically the implementation treats them as zero while reads
        //     still return the written value).
        //
        // With 52-bit PA support (e.g. PS=0b110 under appropriate LPA/LPA2
        // conditions), high PA bits are provided via descriptor fields, not
        // by extending TTBR0_EL2 beyond 64 bits.
        pub(crate) baddr@[47:1],

        // ASID — Address Space Identifier for EL2 stage-1:
        //   When EL2 ASIDs are implemented:
        //     - Holds up to a 16-bit ASID for the address space associated with
        //       TTBR0_EL2 (exact number of implemented bits is IMPLEMENTATION
        //       DEFINED; unused high bits read as zero and ignore writes).
        //     - Used as part of the TLB tag so that different EL2 address spaces
        //       can coexist without full TLB invalidation on context switch.
        //
        //   When EL2 ASIDs are not implemented:
        //     - This field is RES0 (writes ignored, reads return zero).
        //     - All EL2 translations effectively share a single ASID, so EL2
        //       context switches generally require broader TLB maintenance.
        pub(crate) asid@[63:48],
    }
}

bitregs! {
    /// SCTLR_EL2 — System Control Register (EL2)
    ///
    /// Purpose:
    ///     Provides top-level control of the system at EL2, including:
    ///       - Enabling/disabling the EL2 (or EL2&0 host) stage-1 MMU.
    ///       - Data/Instruction cacheability control for EL2.
    ///       - Alignment checking and some exception-handling behaviors.
    ///
    /// Notes:
    ///     This is a simplified model that exposes only the most commonly used
    ///     fields for a hypervisor with VMSAv8-64 stage-1 translation at EL2.
    ///     Newer architectural fields (TIDCP, LSMAOE, nTLSMD, BR, EPAN, etc.)
    ///     are omitted here; consult the Arm ARM for full details.
    pub(crate) struct SCTLR_EL2: u64 {
        // Bits [63:26]: Various optional architectural controls (e.g. TIDCP, LSMAOE,
        // nTLSMD, EPAN, etc. on newer cores). Not modeled here.
        reserved@[63:26] [res0],

        // EE — Exception endianness (EL2):
        //   0b0 = Little-endian.
        //   0b1 = Big-endian.
        // Controls endianness when taking exceptions to EL2 and, when EL2 runs as
        // a host (HCR_EL2.{E2H,TGE} == {1,1}), also influences EL0 behavior.
        pub(crate) ee@[25:25] as ExceptionEndianness {
            LittleEndian = 0b0,
            BigEndian = 0b1,
        },

        reserved@[24:23] [res0],

        // EIS — Exception is context synchronizing:
        //   When FEAT_ExS implemented:
        //     0b0 = Exception entry to EL2 is not required to be context-synchronizing.
        //     0b1 = Exception entry to EL2 is context-synchronizing.
        //   Otherwise RES0.
        pub(crate) eis@[22:22] as ExceptionIsSync {
            NotContextSync = 0b0,
            ContextSync = 0b1,
        },

        // IESB — Implicit Error Synchronization Barrier:
        //   When FEAT_IESB implemented:
        //     0b0 = No implicit ESB on exceptions/ERET at EL2.
        //     0b1 = Implicit ESB on every exception entry to, and ERET from, EL2.
        //   Otherwise RES0.
        pub(crate) iesb@[21:21] as ImplicitESB {
            Disabled = 0b0,
            Enabled = 0b1,
        },

        reserved@[20:20] [res0],

        // WXN — Write eXecute Never:
        //   0b0 = Writable regions are not forced XN.
        //   0b1 = Any region writable at EL2 (or EL2&0 host regime) is treated as
        //         execute-never, regardless of page-table XN bits.
        // Only has effect when M == 1; may be cached in TLBs.
        pub(crate) wxn@[19:19] as WriteExecuteNever {
            Disable = 0b0,
            Enable = 0b1,
        },

        // Bits [18:13]: In the full architecture these cover things like Background
        // region control for the EL2 MPU on PMSAv8-64 implementations. Not modeled.
        reserved@[18:13] [res0],

        // I — Instruction cacheability control for EL2:
        //   0b0 = All instruction accesses to Normal memory from EL2 are treated
        //         as Non-cacheable (all I/unified levels).
        //   0b1 = Instruction cacheability follows memory attributes; when M == 0
        //         in EL2&0 regime, accesses typically use WT Normal memory.
        pub(crate) i@[12:12] as InstructionCache {
            NonCacheable = 0b0,
            Cacheable    = 0b1,
        },

        // Bits [11:4]: Other architectural controls (UCT, nTWI, nTWE, etc. on some
        // cores). Not modeled here.
        reserved@[11:4] [res0],

        // SA — SP Alignment check enable:
        //   0b0 = No SP alignment fault for misaligned SP-based accesses at EL2.
        //   0b1 = If an EL2 load/store uses SP and SP is not 16-byte aligned,
        //         an SP alignment fault is taken to EL2.
        pub(crate) sa@[3:3] as SPAlignmentCheck {
            Disable = 0b0,
            Enable  = 0b1,
        },

        // C — Data/unified cacheability control:
        //   0b0 = Data accesses to Normal memory from EL2 (and from EL0 when
        //         running in EL2&0 host regime) are forced Non-cacheable at all
        //         data/unified cache levels.
        //   0b1 = Cacheability follows the memory attributes.
        pub(crate) c@[2:2] as DataCache {
            NonCacheable = 0b0,
            Cacheable    = 0b1,
        },

        // A — Alignment check enable:
        //   0b0 = Most misaligned loads/stores at EL2 do not fault (some insns
        //         still have mandatory alignment checks).
        //   0b1 = Misaligned accesses that are architecturally checked generate
        //         an Alignment fault at EL2.
        pub(crate) a@[1:1] as AlignmentCheck {
            Disable = 0b0,
            Enable  = 0b1,
        },

        // M — MMU enable for EL2 (or EL2&0 host translation regime):
        //   0b0 = EL2 stage-1 (or EL2&0) translation disabled.
        //   0b1 = EL2 stage-1 (or EL2&0) translation enabled, controlled by
        //         TCR_EL2/TTBR0_EL2 and associated tables.
        pub(crate) m@[0:0] as MMUEnable {
            Disable = 0b0,
            Enable  = 0b1,
        },
    }
}

bitregs! {
    /// MAIR_EL2 — Memory Attribute Indirection Register (EL2)
    ///
    /// Purpose:
    ///     Provides memory attribute encodings corresponding to the AttrIndx values
    ///     used in EL2 stage-1 translation table entries (Long-descriptor format).
    ///     Each 8-bit field Attr<n> is selected by AttrIndx==n in the descriptor.
    pub(crate) struct MAIR_EL2: u64 {
        // Attr0 — bits [7:0]
        //   Memory attribute for AttrIndx == 0.
        //   Layout of the 8-bit value:
        //     - For Device memory:
        //         0b0000dd00  = Device, subtype dd (nGnRnE/nGnRE/nGRE/GRE).
        //     - For Normal memory:
        //         0booooiiii  = Normal, outer=oooo, inner=iiii cacheability.
        //   Common encodings:
        //     - 0x00 = Device-nGnRnE
        //     - 0x44 = Normal Non-cacheable (Inner+Outer NC)
        //     - 0xFF = Normal WB Non-transient, Read/Write-Allocate (Inner+Outer)
        pub(crate) attr0@[7:0],

        // Attr1 — bits [15:8]
        //   Same encoding as Attr0, used when AttrIndx == 1.
        //   Typically used for a second memory type, e.g. Normal WB cacheable.
        pub(crate) attr1@[15:8],

        // Attr2 — bits [23:16]
        //   Same encoding as Attr0, for AttrIndx == 2.
        //   Can be used for another Normal/Device pattern as needed by the hypervisor.
        pub(crate) attr2@[23:16],

        // Attr3 — bits [31:24]
        //   Same encoding as Attr0, for AttrIndx == 3.
        pub(crate) attr3@[31:24],

        // Attr4 — bits [39:32]
        //   Same encoding as Attr0, for AttrIndx == 4.
        pub(crate) attr4@[39:32],

        // Attr5 — bits [47:40]
        //   Same encoding as Attr0, for AttrIndx == 5.
        pub(crate) attr5@[47:40],

        // Attr6 — bits [55:48]
        //   Same encoding as Attr0, for AttrIndx == 6.
        pub(crate) attr6@[55:48],

        // Attr7 — bits [63:56]
        //   Same encoding as Attr0, for AttrIndx == 7.
        pub(crate) attr7@[63:56],
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MairDeviceAttr {
    /// 0b0000: Device-nGnRnE
    nGnRnE = 0b0000,
    /// 0b0100: Device-nGnRE
    nGnRE = 0b0100,
    /// 0b1000: Device-nGRE
    nGRE = 0b1000,
    /// 0b1100: Device-GRE
    GRE = 0b1100,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MairNormalAttr {
    /// 0b0100: Non-cacheable
    NonCacheable = 0b0100,

    /// 0b1000: Write-Through
    WriteThrough = 0b1000,
    /// 0b1001: WT + Write-Allocate
    WriteThroughWA = 0b1001,
    /// 0b1010: WT + Read-Allocate
    WriteThroughRA = 0b1010,
    /// 0b1011: WT + Read- / Write-Allocate
    WriteThroughRAWA = 0b1011,

    /// 0b1100: Write-Back
    WriteBack = 0b1100,
    /// 0b1101: WB + Write-Allocate
    WriteBackWA = 0b1101,
    /// 0b1110: WB + Read-Allocate
    WriteBackRA = 0b1110,
    /// 0b1111: WB + Read- / Write-Allocate
    WriteBackRAWA = 0b1111,
}

#[derive(Copy, Clone, Debug)]
pub enum MairEntry {
    Device(MairDeviceAttr),
    Normal {
        outer: MairNormalAttr,
        inner: MairNormalAttr,
    },
}

impl MairEntry {
    pub fn to_u8(self) -> u8 {
        match self {
            MairEntry::Device(attr) => attr as u8,
            MairEntry::Normal { outer, inner } => ((outer as u8) << 4) | inner as u8,
        }
    }
}
