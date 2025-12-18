#![allow(non_camel_case_types)]

use crate::stage2::Stage2PageTypes;
use typestate::bitregs;

bitregs! {
    /// VMSAv8-64 Stage 2 Table descriptor format (48-bit output address)
    /// Applies to 4KB, 16KB, and 64KB granules.
    /// Assumptions:
    ///   - FEAT_LPA2 is NOT in use (i.e., VTCR_EL2.DS == 0): bits[49:48] are RES0 and
    ///     52-bit output addresses are not described by descriptors. See VTCR_EL2.DS.
    ///   - Stage 2 Table descriptors carry no NSTable/APTable/PXNTable/UXNTable fields.
    pub(crate) struct Stage2_48bitTableDescriptor: u64 {
        // Descriptor type for a Table: must be 0b11.
        reserved@[1:0] [res1],

        // Lower attribute bits in a Table descriptor at Stage 2 are ignored by hardware.
        // (e.g., SH[1:0] at [9:8] are ignored for Table descriptors)
        reserved@[11:2] [ignore],

        // Next-level table address (alignment depends on granule)
        //   - 4KB granule:  [47:12] used
        //   - 16KB granule: [47:14] used
        //   - 64KB granule: [47:16] used
        pub(crate) ntla@[47:12],

        // For 48-bit OA (no FEAT_LPA2 / DS==0), these bits are RES0 in translation descriptors.
        reserved@[50:48] [res0],

        // Upper bits in Stage 2 Table descriptors are ignored by hardware.
        reserved@[58:51] [ignore],

        // Stage 2 Table descriptors define no NSTable/APTable/UXNTable/PXNTable:
        // always RES0/ignored irrespective of permission indirection (S2PIE).
        reserved@[62:59] [res0],

        // Bit[63] (NSTable) exists only at Stage 1; at Stage 2 this is RES0.
        reserved@[63:63] [res0],
    }
}

impl Stage2_48bitTableDescriptor {
    /// Build a valid Stage-2 *table* descriptor (DS==0, 48-bit OA).
    /// `next_table` is the PA of the next-level table; lower alignment bits are ignored.
    #[inline]
    pub(crate) fn new_descriptor(next_table: u64) -> u64 {
        // Keep OA within [47:0] and zero below bit 12 (covers 4K superset; 16K/64K alignments are stricter).
        Self::new().set_raw(Self::ntla, next_table).bits()
    }
}

bitregs! {
    /// VMSAv8-64 Stage 2 Block/Page descriptor format (48-bit OA)
    /// Valid for 4KB, 16KB, and 64KB granules.
    /// Leaf entries appear at level 1 or 2 (no blocks at level 3).
    pub(crate) struct Stage2_48bitLeafDescriptor: u64 {
        // Descriptor type = Block (bits[1:0] == 0b01)
        // Descriptor type = Page  (bits[1:0] == 0b11)
        pub(crate) ty@[1:0] as DescriptorType {
            Block = 0b01,
            Page  = 0b11,
        },

        // MemAttr[3:0] — Stage-2 memory type & cacheability (Device/Normal, inner/outer).
        // NOTE (FEAT_S2FWB): When implemented and enabled (HCR_EL2.FWB==1),
        //   the combination rules for S1/S2 cacheability follow S2FWB semantics.
        //   currently only S2FWD is disabled is supported.
        pub(crate) mem_attr@[5:2] as MemAttr {
            // Device-nGnRnE memory
            Device_nGnRnE = 0b0000,
            // Device-nGnRE memory
            Device_nGnRE = 0b0001,
            // Device-nGRE memory
            Device_nGRE = 0b0010,
            // Device-GRE memory
            Device_GRE = 0b0011,
            // When FEAT_MTE_PERM is implemented, Outer/Inner Write-Back Cacheable
            Reserved = 0b0100,
            // Outer/Inner Non-cacheable
            BothNonCacheable = 0b0101,
            // Outer Non-cacheable Inner Write-Through Cacheable
            OuterNonCacheableInnerWriteThroughCacheable = 0b0110,
            // Outer Non-cacheable Inner Write-Back Cacheable
            OuterNonCacheableInnerWriteBackCacheable = 0b0111,
            // Outer Write-Through Cacheable Inner Non-cacheable
            OuterWriteThroughCacheableInnerNonCacheable = 0b1001,
            // Outer/Inner Write-Through Cacheable
            BothWriteThroughCacheable = 0b1010,
            // Outer Write-Through Cacheable Inner Write-Back Cacheable
            OuterWriteThroughCacheableInnerWriteBackCacheable = 0b1011,
            // Outer Write-Back Cacheable Inner Non-cacheable
            OuterWriteBackCacheableInnerNonCacheable = 0b1101,
            // Outer Write-Back Cacheable Inner Write-Through Cacheable
            OuterWriteBackCacheableInnerWriteThroughCacheable = 0b1110,
            // Outer/Inner Write-Back Cacheable,
            BothWriteBackCacheable = 0b1111,
        },

        // S2AP[1:0] — Stage-2 access permissions (combined with Stage-1 permissions).
        // NOTE (FEAT_HAFDBS family): With hardware-managed Access/Dirty state,
        //   DBM can interact with S2AP for write-dirty tracking.
        pub(crate) s2ap@[7:6] as AccessPermission {
            NoDataAccess = 0b00,
            ReadOnly = 0b01,
            WriteOnly = 0b10,
            ReadWrite = 0b11,
        },

        // SH — Shareability for Normal memory:
        //   0b00=Non-shareable, 0b10=Outer Shareable, 0b11=Inner Shareable.
        // NOTE (FEAT_LPA2; VTCR_EL2.DS==1):
        //   bits[9:8] are repurposed as OA[51:50] (upper output address bits);
        //   in that case shareability is selected by VTCR_EL2.SH0 (not in the descriptor).
        pub(crate) sh@[9:8] as Shareability {
            NonSharable = 0b00,
            OuterSharable = 0b10,
            InnerSharable = 0b11,
        },

        // AF — Access Flag:
        //   0: first access takes AF fault (unless hardware AF update is enabled),
        //   1: access permitted (subject to permissions).
        pub(crate) af@[10:10],

        // [11] — not used at Stage 2 (nG is Stage-1 only). Must be RES0.
        reserved@[11:11] [res0],

        union block_and_page@[47:12] {
            view block {
                reserved@[15:12] [res0],
                // nT — “No-translate” hint for size-change sequences.
                //   Requires FEAT_BBML1. When set, implementation may avoid caching this
                //   translation and can fault instead of caching to avoid TLB conflicts.
                //   Otherwise: RES0.
                pub(crate) nt@[16:16],

                reserved@[20:17] [res0],

                // OA base — Output Address (Block address).
                // Block lower bits are zeroed according to level & TG:
                //   TG=4KB : L0->512GiB (OA[47:39] valid) L1->1GiB (OA[47:30] valid), L2->2MiB (OA[47:21] valid)
                //   TG=16KB: L1->512MiB (OA[47:34]),  L2->32MiB (OA[47:25])
                //   TG=64KB: L1->256MiB (OA[47:36]),  L2->512KiB (OA[47:29])
                // We model the superset slice and expect SW to keep the extra low bits zero.
                // NOTE (FEAT_LPA2; VTCR_EL2.DS==1):
                //   OA[49:48] live in descriptor bits[49:48], and OA[51:50] live in bits[9:8].
                pub(crate)block_oab@[47:21],
            }

            view page {
                // OA base — Output Address (Page address).
                // Block lower bits are zeroed according to level & TG:
                //   TG=4KB  : (OA[47:12] valid)
                //   TG=16KB : (OA[47:14] valid)
                //   TG=64KB : (OA[47:16] valid)
                pub(crate) page_oab@[47:12],
            }
        }

        // Keep these RES0 in the 48-bit OA format (they carry OA bits when DS==1).
        // NOTE (FEAT_LPA2; VTCR_EL2.DS==1): bits[49:48] hold OA[49:48].
        reserved@[50:48] [res0],

        // DBM — Dirty Bit Modifier (hardware dirty logging support).
        //   Requires FEAT_HAFDBS (and related dirty-state features). Otherwise: RES0.
        pub(crate) dbm@[51:51],

        // Contiguous — 16 adjacent entries hint a larger mapping.
        //   Performance hint; implementations may ignore.
        //   NOTE (FEAT_BBML1/BBML2): update/relaxation rules for TLB conflicts may differ.
        pub(crate) contiguous@[52:52],

        // Execute-never control:
        //   Without FEAT_XNX: bit[54] is a single XN for all ELs; bit[53] is RES0.
        //   With    FEAT_XNX: [54]=UXN (EL0 XN), [53]=PXN (EL1+ XN).
        pub(crate) xn@[54:53],

        // NS — Security attribute of the *output* address.
        //   Secure state translations only: 0=Secure, 1=Non-secure.
        //   Non-secure translations: architecturally ignored/treated as Non-secure.
        pub(crate) ns@[55:55],

        // Software-reserved (ignored by hardware).
        pub(crate) sw@[57:56],

        // AssuredOnly (bit[58]) — only when FEAT_THE is implemented AND enabled by VTCR_EL2.
        //   If FEAT_THE is not implemented or not enabled for Stage 2: RES0.
        //   NOTE: If the Stage-2 translation system is 128-bit (VTCR_EL2.D128==1),
        //   this field is defined RES0 by the architecture.
        pub(crate) assured_only@[58:58],

        // Implementation-defined / ignored by CPU.
        //   Some SMMUs may internally use these, but the PE treats them as ignored.
        reserved@[59:59] [ignore],
        reserved@[62:60] [ignore],

        // Top bit must be RES0 (kept for forward compatibility).
        reserved@[63:63] [res0],
    }
}

impl Stage2_48bitLeafDescriptor {
    /// Build a Stage-2 *block* descriptor (L1/L2). `level` is the translation level (1 or 2).
    /// We mask to the [47:21] superset and leave finer-grained alignment to the caller.
    #[inline]
    pub(crate) fn new_block(pa: u64, level: i8, types: Stage2PageTypes) -> u64 {
        let _aligned_bits = match level {
            1 => 1 << 30, // 1GiB
            2 => 1 << 21, // 2MiB
            _ => unreachable!(),
        };
        debug_assert_eq!(pa & (_aligned_bits - 1), 0);

        let (mem_attr, sh) = match types {
            Stage2PageTypes::Normal => {
                (MemAttr::BothWriteBackCacheable, Shareability::InnerSharable)
            }
            Stage2PageTypes::Device => (MemAttr::Device_nGnRnE, Shareability::NonSharable),
        };

        Self::new()
            .set_enum(Self::mem_attr, mem_attr)
            .set_enum(Self::s2ap, AccessPermission::ReadWrite)
            .set_enum(Self::sh, sh)
            .set_enum(Self::ty, DescriptorType::Block)
            .set_raw(Self::block_oab, pa)
            .set(Self::af, 0b1)
            .bits()
    }

    /// Build a Stage-2 *page* descriptor (L3). We use the same [47:12] superset.
    #[inline]
    pub(crate) fn new_page(pa: u64, types: Stage2PageTypes) -> u64 {
        let (mem_attr, sh) = match types {
            Stage2PageTypes::Normal => {
                (MemAttr::BothWriteBackCacheable, Shareability::InnerSharable)
            }
            Stage2PageTypes::Device => (MemAttr::Device_nGnRnE, Shareability::NonSharable),
        };

        Self::new()
            .set_enum(Self::mem_attr, mem_attr)
            .set_enum(Self::s2ap, AccessPermission::ReadWrite)
            .set_enum(Self::sh, sh)
            .set_enum(Self::ty, DescriptorType::Page)
            .set_raw(Self::page_oab, pa)
            .set(Self::af, 0b1)
            .bits()
    }
}
