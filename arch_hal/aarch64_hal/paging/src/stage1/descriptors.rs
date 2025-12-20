use typestate::bitregs;

bitregs! {
    /// VMSAv8-64 Stage 1 Table descriptor format (48-bit output address)
    /// Applies to 4KB, 16KB, and 64KB granules.
    ///
    /// Ref: Arm ARM (e.g. DDI 0487L.b), VMSAv8-64 table descriptor format.
    ///
    /// Assumptions:
    ///   - FEAT_LPA2 is NOT in use (DS == 0).
    ///   - Hierarchical attributes (PXNTable, UXNTable, APTable, NSTable) are supported.
    pub(crate) struct Stage1_48bitTableDescriptor: u64 {
        // Descriptor type for a Table:
        //   bit[0] = Valid, bit[1] = 1 => Table descriptor (0b11).
        // This definition assumes "always a valid table entry", so [1:0] is fixed to 0b11.
        reserved@[1:0] [res1],

        // Ignored / software-defined bits in Stage-1 table descriptors.
        // Unlike Stage-2, stage-1 attributes are in the upper bits.
        reserved@[11:2] [ignore],

        // Next-level table address (PA of the next-level table: L1/L2/L3).
        // For 48-bit OA without LPA2:
        //   - 4KB granule:  [47:12] used (4KB-aligned)
        //   - 16KB granule: [47:14] used (16KB-aligned)
        //   - 64KB granule: [47:16] used (64KB-aligned)
        // The caller must ensure `next_table` is aligned for the chosen granule/level.
        pub(crate) nlta@[47:12],

        // For 48-bit OA (no FEAT_LPA2 / DS==0), these bits are RES0.
        reserved@[50:48] [res0],

        // Implementation-defined / ignored in this simplified model.
        reserved@[58:51] [ignore],

        // Hierarchical Controls (apply to subsequent levels of lookup):
        // Effective only for the translation regime that uses this table.

        // PXNTable: Privileged Execute-never for subsequent levels.
        //   0: No effect on PXN of subsequent level entries.
        //   1: Forces PXN on subsequent levels (subject to regime rules).
        pub(crate) pxn_table@[59:59],

        // UXNTable (or XNTable): Unprivileged/Execute-never for subsequent levels.
        //   0: No effect on UXN/XN of subsequent level entries.
        //   1: Forces UXN/XN on subsequent levels.
        pub(crate) uxn_table@[60:60],

        // APTable: Access Permission limit for subsequent levels.
        //
        // (2-EL translation regimeの典型的な意味)
        //   00: No effect.
        //   01: EL0 access not permitted (EL1/EL2/EL3 access follows leaf AP).
        //   10: Writes not permitted at any EL (reads follow leaf AP).
        //   11: Both: EL0 access not permitted, and writes not permitted at any EL.
        //
        // Actual effect is regime-dependent butこの4パターンの制限と考えて良い。
        pub(crate) ap_table@[62:61],

        // NSTable: Security state for subsequent levels (when in Secure state).
        //   Secure state:
        //     0: Table walk for subsequent levels is Secure.
        //     1: Table walk for subsequent levels is Non-secure.
        //   Non-secure state:
        //     Ignored (walk is Non-secure regardless).
        pub(crate) ns_table@[63:63],
    }
}

impl Stage1_48bitTableDescriptor {
    /// Build a valid Stage-1 *table* descriptor.
    /// `next_table` is the PA of the next-level table; must be aligned for the
    /// chosen granule size / level.
    #[inline]
    pub(crate) fn new_descriptor(next_table: u64) -> u64 {
        // NOTE: Alignment is the caller's responsibility. For a 4KB granule you
        // typically require 4KB alignment:
        // debug_assert_eq!(next_table & ((1 << 12) - 1), 0);
        Self::new().set_raw(Self::nlta, next_table).bits()
    }
}

bitregs! {
    /// VMSAv8-64 Stage 1 Block/Page descriptor format (48-bit OA, DS==0)
    ///
    /// Ref: Arm ARM (e.g. DDI 0487L.b), VMSAv8-64 block/page descriptor format.
    ///
    /// Layout is architecturally valid for 4KB / 16KB / 64KB granules.
    /// This implementation's helpers (`new_block`) assume a 4KB granule for
    /// the block-size alignment constants.
    pub(crate) struct Stage1_48bitLeafDescriptor: u64 {
        // Descriptor type:
        //   0b01: Block (only at level 1 or 2)
        //   0b11: Page  (only at level 3)
        pub(crate) ty@[1:0] as DescriptorType {
            Block = 0b01,
            Page  = 0b11,
        },

        // AttrIndx[2:0] — Stage-1 memory attribute index.
        //   Selects MAIR_ELx.Attr[AttrIndx] (0–7).
        //   NOTE: This is an *index* into MAIR, not a direct attribute.
        pub(crate) attr_indx@[4:2],

        // NS — Non-secure bit.
        //   Secure state:
        //     0: Output PA is in Secure address space.
        //     1: Output PA is in Non-secure address space.
        //   Non-secure state:
        //     Ignored (output is Non-secure by definition).
        pub(crate) ns@[5:5],

        // AP[2:1] — Data Access Permissions.
        //   (2-EL translation regime)
        //     0b00: R/W, privileged only (EL1/EL2/EL3).
        //     0b01: R/W, any EL (privileged + EL0).
        //     0b10: R/O, privileged only.
        //     0b11: R/O, any EL.
        pub(crate) ap@[7:6] as Stage1AP {
            // "Privileged" means EL1/EL2/EL3. "Unprivileged" means EL0.
            RW_PrivOnly = 0b00,
            RW_Any      = 0b01,
            RO_PrivOnly = 0b10,
            RO_Any      = 0b11,
        },

        // SH — Shareability attribute.
        //   00: Non-shareable
        //   10: Outer Shareable
        //   11: Inner Shareable
        //   01: Reserved
        pub(crate) sh@[9:8] as Shareability {
            NonSharable   = 0b00,
            OuterSharable = 0b10,
            InnerSharable = 0b11,
        },

        // AF — Access Flag.
        //   0: Access generates a fault (unless hardware AF update is enabled).
        //   1: Access permitted.
        pub(crate) af@[10:10],

        // nG — Not Global.
        //   0: Global mapping (TLB entry independent of ASID).
        //   1: Non-global (TLB entry tagged by ASID).
        // At EL2 without ASIDs, this bit is typically 0 (global).
        pub(crate) ng@[11:11],

        // Address field: block vs page view.
        union block_and_page@[47:12] {
            view block {
                // For block descriptors, some low address bits are implicitly 0
                // due to the block size (granule- and level-dependent).
                // With 4KB granule:
                //   - Level 1 block: 1GiB (bits[29:0] == 0)
                //   - Level 2 block: 2MiB (bits[20:0] == 0)
                reserved@[15:12] [res0],

                // nT — Break-Before-Make hint (FEAT_BBML1).
                //   0: No special BBM handling.
                //   1: Indicates that this entry participates in BBM sequences.
                pub(crate) nt@[16:16],

                // More reserved bits for alignment / implementation-defined use.
                reserved@[20:17] [res0],

                // OA base — Output Address base for a Block.
                //   For a 4KB granule this holds OA[47:21], with OA[20:0] implied 0.
                pub(crate) block_oab@[47:21],
            }

            view page {
                // OA base — Output Address base for a Page.
                //   For a 4KB granule this holds OA[47:12], with OA[11:0] implied 0.
                pub(crate) page_oab@[47:12],
            }
        }

        // Reserved for 48-bit OA when LPA2 (DS) == 0.
        reserved@[49:48] [res0],

        // GP — Guarded Page (FEAT_BTI).
        //   Controls BTI (Branch Target Identification) behavior.
        pub(crate) gp@[50:50],

        // DBM — Dirty Bit Modifier (FEAT_HAFDBS).
        //   When enabled, this bit participates in hardware-managed dirty tracking.
        pub(crate) dbm@[51:51],

        // Contiguous — Hint that a group of entries form a contiguous region.
        pub(crate) contiguous@[52:52],

        // PXN — Privileged Execute-never.
        //   Prevents execution at privileged ELs (e.g. EL1/EL2) through this mapping.
        pub(crate) pxn@[53:53],

        // UXN / XN — Unprivileged Execute-never or Execute-never.
        //   EL1&0 regime: UXN (prevents EL0 execution).
        //   EL2/EL3 regime: XN (prevents execution at that EL).
        pub(crate) uxn_xn@[54:54],

        // Software-use bits (ignored by hardware).
        pub(crate) software@[58:55],

        // PBHA — Page-Based Hardware Attributes (FEAT_HPDS2).
        //   When FEAT_HPDS2 is not implemented, these bits are ignored.
        //   This implementation treats them as reserved/ignored.
        reserved@[62:59] [ignore],

        // Bit [63] is reserved/ignored for 48-bit OA without LPA2.
        reserved@[63:63] [ignore],
    }
}

impl Stage1_48bitLeafDescriptor {
    /// Build a Stage-1 *block* descriptor (L1/L2).
    ///
    /// This helper assumes:
    ///   - 4KB granule (so block sizes are 1GiB at L1, 2MiB at L2).
    ///   - Global mapping (nG=0).
    ///   - Inner-shareable, with AF set.
    ///
    /// `attr_indx`: Index into MAIR_ELx (0-7).
    /// `ap`: Access Permissions (e.g. RW_PrivOnly).
    /// `xn`: Execute Never (maps to bit 54, UXN/XN).
    #[inline]
    pub(crate) fn new_block(pa: u64, level: i8, attr_indx: u8, ap: Stage1AP, xn: bool) -> u64 {
        // 4KB granule block sizes:
        //   L1: 1GiB  (2^30)
        //   L2: 2MiB  (2^21)
        let aligned_bits = match level {
            1 => 1 << 30, // 1GiB
            2 => 1 << 21, // 2MiB
            _ => panic!("Level 0 cannot be Block, Level 3 must be Page"),
        };
        debug_assert_eq!(pa & (aligned_bits - 1), 0);
        debug_assert!(attr_indx < 8);

        Self::new()
            .set(Self::attr_indx, attr_indx as u64)
            .set_enum(Self::ap, ap)
            .set_enum(Self::sh, Shareability::InnerSharable) // Default: Inner Shareable
            .set_enum(Self::ty, DescriptorType::Block)
            .set_raw(Self::block_oab, pa)
            .set(Self::af, 1) // Access Flag set (pre-accessed)
            .set(Self::ng, 0) // Global mapping (all ASIDs)
            .set(Self::uxn_xn, xn as u64)
            .bits()
    }

    /// Build a Stage-1 *page* descriptor (L3).
    ///
    /// This helper assumes:
    ///   - 4KB granule (page size 4KB, so PA must be 4KB-aligned).
    ///   - Global mapping (nG=0).
    ///   - Inner-shareable, with AF set.
    #[inline]
    pub(crate) fn new_page(pa: u64, attr_indx: u8, ap: Stage1AP, xn: bool) -> u64 {
        debug_assert!(attr_indx < 8);
        // 4KB page alignment
        debug_assert_eq!(pa & ((1 << 12) - 1), 0);

        Self::new()
            .set(Self::attr_indx, attr_indx as u64)
            .set_enum(Self::ap, ap)
            .set_enum(Self::sh, Shareability::InnerSharable)
            .set_enum(Self::ty, DescriptorType::Page)
            .set_raw(Self::page_oab, pa)
            .set(Self::af, 1)
            .set(Self::ng, 0)
            .set(Self::uxn_xn, xn as u64)
            .bits()
    }
}
