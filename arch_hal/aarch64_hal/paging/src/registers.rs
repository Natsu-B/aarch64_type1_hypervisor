use typestate::bitregs;

bitregs! {
    /// HCR_EL2 — Hypervisor Configuration Register
    /// Purpose:
    ///     Provides virtualization configuration controls, including whether various
    ///     Non-secure EL1/EL0 operations are trapped to EL2 and how exceptions are routed.
    pub(crate) struct HCR_EL2: u64 {
        // [0..15]
        // Enable stage 2 translation for Non-secure EL1&0.
        //   0b0: Stage 2 translation disabled
        //   0b1: Stage 2 translation enabled
        pub(crate) vm@[0:0],

        // Set/Way Invalidation Override for cache maintenance by set/way.
        pub(crate) swio@[1:1],

        // Permission fault on S1 page-table walks that access Device memory.
        //   0b1: If a stage-1 walk touches Device memory, take a stage-2 Permission fault
        pub(crate) ptw@[2:2],

        // Route physical FIQ/IRQ/SError taken at EL1/EL0 to EL2.
        pub(crate) fmo@[3:3],   // FIQ routing to EL2
        pub(crate) imo@[4:4],   // IRQ routing to EL2
        pub(crate) amo@[5:5],   // SError routing to EL2

        // Inject virtual exceptions for the guest:
        //   VF: vFIQ pending, VI: vIRQ pending, VSE: vSError pending
        pub(crate) vf@[6:6],
        pub(crate) vi@[7:7],
        pub(crate) vse@[8:8],

        // Force broadcast of certain maintenance ops to the required shareability domain.
        pub(crate) fb@[9:9],

        // Barrier Shareability Upgrade for DSB/ISB executed at EL1/EL0.
        pub(crate) bsu@[11:10],

        // Default Cacheability when S1 MMU is disabled at EL1/EL0.
        //   0b1: Treat accesses as Normal WB cacheable
        pub(crate) dc@[12:12],

        // Trap WFI/WFE executed at EL1/EL0 to EL2.
        pub(crate) twi@[13:13], // WFI trap
        pub(crate) twe@[14:14], // WFE trap

        // Trap reads of ID group 0/1/2/3 registers at EL1/EL0 to EL2.
        pub(crate) tid0@[15:15],

        // [16..31]
        pub(crate) tid1@[16:16],
        pub(crate) tid2@[17:17],
        pub(crate) tid3@[18:18],

        // Trap SMC executed at Non-secure EL1/EL0 to EL2.
        pub(crate) tsc@[19:19],

        // Trap IMPLEMENTATION DEFINED system-register accesses at EL1/EL0 to EL2.
        pub(crate) tidcp@[20:20],

        // Trap Auxiliary Control Register accesses at EL1/EL0 to EL2.
        pub(crate) tacr@[21:21],

        // Trap cache maintenance by set/way at EL1/EL0 to EL2.
        pub(crate) tsw@[22:22],

        // Trap cache maintenance to Point of Coherency / Physical Storage at EL1 to EL2.
        pub(crate) tpcp@[23:23],

        // Trap cache maintenance to Point of Unification at EL1 to EL2.
        pub(crate) tpu@[24:24],

        // Trap TLB maintenance instructions at EL1 to EL2.
        pub(crate) ttlb@[25:25],

        // Trap virtual memory control (TTBRx_EL1/TCR_EL1/SCTLR_EL1 writes etc) at EL1 to EL2.
        pub(crate) tvm@[26:26],

        // Route general exceptions from EL0 to EL2 when E2H==1 (VHE mode interaction).
        pub(crate) tge@[27:27],

        // Trap DC ZVA at EL1/EL0 to EL2.
        pub(crate) tdz@[28:28],

        // HVC instruction disable (UNDEFINED at EL1/EL2 when set; does not trap).
        pub(crate) hcd@[29:29],

        // Trap reads of certain virtual memory controls at EL1 to EL2.
        pub(crate) trvm@[30:30],

        // Execution state for the next-lower EL (0 = AArch32, 1 = AArch64).
        pub(crate) rw@[31:31],

        // [32..47]
        // Stage-2 cacheability disable:
        //   CD: force S2 data accesses/table walks to Non-cacheable
        //   ID: force S2 instruction fetches to Non-cacheable
        pub(crate) cd@[32:32],
        pub(crate) id@[33:33],

        // E2H — EL2 as host (VHE). Requires FEAT_VHE.
        //   When FEAT_E2H0 is not implemented, this field can be RES1 (behaves as 1 except on direct read).
        //   Otherwise if FEAT_VHE is not implemented: RES0
        pub(crate) e2h@[34:34],

        // TLOR — Trap LORegion registers to EL2. Requires FEAT_LOR, otherwise RES0.
        pub(crate) tlor@[35:35],

        // TERR — Trap RAS Error Record registers to EL2. Requires FEAT_RAS, otherwise RES0.
        pub(crate) terr@[36:36],

        // TEA — Route synchronous External aborts to EL2. Requires FEAT_RAS, otherwise RES0.
        pub(crate) tea@[37:37],

        // Reserved (was MIOCNCE). RES0.
        reserved@[38:38] [res0],

        // TME — Transactional Memory enable for lower ELs. Requires FEAT_TME, otherwise RES0.
        pub(crate) tme@[39:39],

        // APK/API — Pointer Authentication traps. Require FEAT_PAuth, otherwise RES0.
        pub(crate) apk@[40:40],
        pub(crate) api@[41:41],

        // Nested virtualization controls:
        //   NV  — base nested-virt trap/redirection control (FEAT_NV or FEAT_NV2)
        //   NV1 — additional NV behaviors (FEAT_NV or FEAT_NV2)
        //   AT  — trap AT S1E1* / S1E0* (FEAT_NV; S1E1A additionally requires FEAT_ATS1A)
        //   NV2 — enhanced nested-virt (FEAT_NV2)
        // Not implemented features: corresponding fields are RES0.
        pub(crate) nv@[42:42],
        pub(crate) nv1@[43:43],
        pub(crate) at@[44:44],
        pub(crate) nv2@[45:45],

        // FWB — Stage-2 Forced Write-Back combining. Requires FEAT_S2FWB, otherwise RES0.
        pub(crate) fwb@[46:46],

        // FIEN — RAS Fault Injection enable. Requires FEAT_RASv1p1, otherwise RES0.
        pub(crate) fien@[47:47],

        // [48..63]
        // GPF — Route Granule Protection Faults to EL2. Requires FEAT_RME, otherwise RES0.
        pub(crate) gpf@[48:48],

        // TID4 — Trap ID group 4 to EL2. Requires FEAT_EVT (Enhanced Virtualization Traps), otherwise RES0.
        pub(crate) tid4@[49:49],

        // TICAB — Trap IC IALLUIS/ICIALLUIS to EL2. Requires FEAT_EVT, otherwise RES0.
        pub(crate) ticab@[50:50],

        // AMVOFFEN — AMU virtualization via virtual offsets. Requires FEAT_AMUv1p1, otherwise RES0.
        pub(crate) amvoffen@[51:51],

        // TOCU — Trap cache maintenance to PoU (IC IVAU/IC IALLU/DC CVAU etc.). Requires FEAT_EVT, otherwise RES0.
        pub(crate) tocu@[52:52],

        // EnSCXT — Access to SCXTNUM_EL1/EL0 (no trap when set).
        // Requires FEAT_CSV2_2 or FEAT_CSV2_1p2, otherwise RES0.
        pub(crate) enscxt@[53:53],

        // Fine-grained TLB maintenance traps:
        //   TTLBIS — trap *IS (Inner Shareable) TLBI; requires FEAT_EVT, otherwise RES0.
        //   TTLBOS — trap *OS (Outer Shareable) TLBI; requires FEAT_EVT, otherwise RES0.
        pub(crate) ttlbis@[54:54],
        pub(crate) ttlbos@[55:55],

        // MTE controls for lower ELs:
        //   ATA — Allocation Tag Access control; requires FEAT_MTE2, otherwise RES0.
        //   DCT — Default Cacheability Tagging with HCR_EL2.DC; requires FEAT_MTE2, otherwise RES0.
        pub(crate) ata@[56:56],
        pub(crate) dct@[57:57],

        // TID5 — Trap ID group 5 (e.g., GMID_EL1). Requires FEAT_MTE2, otherwise RES0.
        pub(crate) tid5@[58:58],

        // TWED — Trap WFE Exception Delay:
        //   TWEDEn — enable; TWEDEL — delay encoding 2^(TWEDEL+8) cycles
        //   Both require FEAT_TWED; otherwise RES0.
        pub(crate) tweden@[59:59],
        pub(crate) twedel@[63:60]
    }
}
