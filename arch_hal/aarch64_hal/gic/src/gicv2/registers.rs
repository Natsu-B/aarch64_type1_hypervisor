#![allow(clippy::assertions_on_constants)]
#![allow(non_camel_case_types)]

use core::mem::size_of;
use typestate::ReadOnly;
use typestate::ReadWrite;
use typestate::WriteOnly;
use typestate::bitregs;

// ARM IHI 0048B tables define the offsets; GIC-400 TRM sets the 4KB/8KB GICv2 frame sizes.
const _: () = assert!(size_of::<GicV2Distributor>() == 0x1_000);
const _: () = assert!(size_of::<GicV2CpuInterface>() == 0x2_000);
const _: () = assert!(size_of::<GicV2VirtualInterfaceControl>() == 0x1_000);
const _: () = assert!(size_of::<GicV2VirtualCpuInterface>() == 0x2_000);

bitregs! {
    /// Distributor Control Register, GICD_CTLR.
    ///
    /// Bit assignments depend on:
    /// - whether Security Extensions are implemented (GICD_TYPER.SecurityExtn),
    /// - and if so, whether the visible bank is the Secure copy or the Non-secure copy.
    pub(crate) struct GICD_CTLR: u32 {
        union sec@[1:0] {
            // Security Extensions are NOT implemented (single copy).
            view NoSecurityExt {
                pub(crate) enable_grp0@[0:0],
                pub(crate) enable_grp1@[1:1],
            },

            // Security Extensions ARE implemented: Secure copy.
            view SecureCopy {
                pub(crate) enable_grp0_secure@[0:0],
                pub(crate) enable_grp1_secure@[1:1],
            },

            // Security Extensions ARE implemented: Non-secure copy.
            //
            // Bit[0] is the global enable that controls *only Group 1* forwarding.
            view NonSecureCopy {
                pub(crate) enable_grp1_non_secure@[0:0],
                reserved@[1:1] [res0],
            },
        },

        reserved@[31:2] [res0],
    }
}

bitregs! {
    /// Interrupt Controller Type Register, GICD_TYPER (ARM IHI 0048B Table 4-6).
    pub(crate) struct GICD_TYPER: u32 {
        // ITLinesNumber[4:0].
        //
        // Indicates the maximum number of interrupts that the GIC supports. :contentReference[oaicite:1]{index=1}
        pub(crate) it_lines_number@[4:0],

        // CPUNumber[7:5].
        //
        // Indicates the number of implemented CPU interfaces (value + 1). :contentReference[oaicite:2]{index=2}
        pub(crate) cpu_number@[7:5],

        reserved@[9:8] [res0],

        // SecurityExtn[10].
        //
        // Indicates whether the GIC implements the Security Extensions. :contentReference[oaicite:3]{index=3}
        pub(crate) security_extn@[10:10],

        // LSPI[15:11].
        //
        // If Security Extensions are implemented, maximum number of implemented lockable SPIs;
        // otherwise reserved. :contentReference[oaicite:4]{index=4}
        pub(crate) lspi@[15:11],

        reserved@[31:16] [res0],
    }
}

bitregs! {
    /// Software Generated Interrupt Register, GICD_SGIR
    pub(crate) struct GICD_SGIR: u32 {
        pub(crate) sgi_int_id@[3:0],
        reserved@[14:4] [ignore],
        pub(crate) ns_att@[15:15],
        pub(crate) cpu_target_list@[23:16],
        pub(crate) target_list_filter@[25:24] as TargetListFilter {
            CpuTargetListFieldSpecified = 0b00,
            InterruptAllCpuExceptRequestedCpu = 0b01,
            // 0b10 targets only the requesting CPU interface (self).
            InterruptSelfOnly = 0b10,
        },
        reserved@[31:26] [ignore],
    }
}

bitregs! {
    /// GICC_CTLR (CPU Interface Control Register)
    ///
    /// - Table 4-30: GICv2 + Security Extensions, Non-secure copy
    /// - Table 4-31: No Security Extensions, or Secure copy
    pub(crate) struct GICC_CTLR: u32 {
        union ctlr_bits@[10:0] {
            // Security Extensions not implemented, or Secure copy (Table 4-31).
            view SecureOrNoSecurityExtn {
                pub(crate) enable_grp0@[0:0],
                pub(crate) enable_grp1@[1:1],
                pub(crate) ack_ctl@[2:2],
                pub(crate) fiq_en@[3:3],
                pub(crate) cbpr@[4:4],
                pub(crate) fiq_byp_dis_grp0@[5:5],
                pub(crate) irq_byp_dis_grp0@[6:6],
                pub(crate) fiq_byp_dis_grp1@[7:7],
                pub(crate) irq_byp_dis_grp1@[8:8],
                pub(crate) eoi_mode_s@[9:9],
                pub(crate) eoi_mode_ns@[10:10],
            },

            // Security Extensions implemented, Non-secure copy (Table 4-30).
            view NonSecureCopy {
                pub(crate) enable_grp1_non_secure@[0:0],
                reserved@[4:1] [res0],
                pub(crate) fiq_byp_dis_grp1_non_secure@[5:5],
                pub(crate) irq_byp_dis_grp1_non_secure@[6:6],
                reserved@[8:7] [res0],
                pub(crate) eoi_mode_ns_non_secure@[9:9],
                reserved@[10:10] [res0],
            },
        }

        reserved@[31:11] [res0],
    }
}

bitregs! {
    /// Interrupt Priority Mask Register, GICC_PMR
    pub(crate) struct GICC_PMR: u32 {
        pub(crate) priority@[7:0],
        reserved@[31:8],
    }
}

bitregs! {
    /// Binary Point Register, GICC_BPR
    pub(crate) struct GICC_BPR: u32 {
        // The minimum binary point value is IMPLEMENTATION DEFINED in the range:
        // - 0-3 if the implementation does not include the GIC Security Extensions, and for the
        //  Secure copy of the register if the implementation includes the Security Extensions
        // - 1-4 for the Non-secure copy of the register.
        // An attempt to program the binary point field to a value less than the minimum value sets the
        // field to the minimum value. On a reset, the binary point field is set to the minimum
        // supported value.
        pub(crate) binary_point@[2:0],
        reserved@[31:3],
    }
}

bitregs! {
    /// Aliased Binary Point Register, GICC_ABPR
    pub(crate) struct GICC_ABPR: u32 {
        // A Binary Point Register for handling Group 1 interrupts.
        // The reset value of this register is defined as (minimum GICC_BPR.Binary point + 1),
        // resulting in a permitted range of 0x1-0x4 .
        pub(crate) binary_point@[2:0],
        reserved@[31:3],
    }
}

bitregs! {
    /// End of Interrupt Register, GICC_EOIR
    pub(crate) struct GICC_EOIR: u32 {
        pub(crate) eoi_int_id@[9:0],
        pub(crate) cpu_id@[12:10],
        reserved@[31:13],
    }
}

bitregs! {
    /// Highest Priority Pending Interrupt Register, GICC_HPPIR.
    pub(crate) struct GICC_HPPIR: u32 {
        pub(crate) interrupt_id@[9:0],
        pub(crate) cpu_id@[12:10],
        reserved@[31:13],
    }
}

bitregs! {
    /// Aliased Highest Priority Pending Interrupt Register, GICC_AHPPIR.
    pub(crate) struct GICC_AHPPIR: u32 {
        pub(crate) interrupt_id@[9:0],
        pub(crate) cpu_id@[12:10],
        reserved@[31:13],
    }
}

bitregs! {
    /// Interrupt Acknowledge Register, GICC_IAR
    pub(crate) struct GICC_IAR: u32 {
        pub(crate) interrupt_id@[9:0],
        pub(crate) cpu_id@[12:10],
        reserved@[31:13],
    }
}

bitregs! {
    /// Deactivate Interrupt Register, GICC_DIR
    pub(crate) struct GICC_DIR: u32 {
        pub(crate) interrupt_id@[9:0],
        pub(crate) cpu_id@[12:10],
        reserved@[31:13],
    }
}

bitregs! {
    /// Virtual CPU Interface Control Register bits (ARM IHI 0048B Table 5-10).
    pub(crate) struct GICV_CTLR: u32 {
        // Enable Group0 virtual interrupts
        pub(crate) enable_grp0@[0:0],
        // Enable Group1 virtual interrupts
        pub(crate) enable_grp1@[1:1],
        // Control use of IDs for acknowledgement
        pub(crate) ack_ctl@[2:2],
        // Route Group0 virtual interrupts as FIQ when set
        pub(crate) fiq_en@[3:3],
        // Common Binary Point for both groups
        pub(crate) cbpr@[4:4],
        reserved@[8:5] [res0],
        // EOImode: 0 drops priority and deactivates via EOI (DIR UNPREDICTABLE); 1 drops only (DIR deactivates)
        pub(crate) eoi_mode@[9:9],
        reserved@[31:10] [res0],
    }
}

bitregs! {
    pub(crate) struct GICD_ICPIDR2: u32 {
        reserved@[3:0] [ignore], // Implementation defined
        pub(crate) arch_rev@[7:4], // Architecture Revision
        reserved@[31:8] [ignore], // Implementation defined
    }
}

bitregs! {
    /// GICv2 Hypervisor Control Register bits (ARM IHI 0048B Table 5-2).
    pub(crate) struct GICH_HCR: u32 {
        // Global enable for virtual/maintenance interrupt signalling
        pub(crate) en@[0:0],
        // Underflow Interrupt Enable
        pub(crate) uie@[1:1],
        // List Register Entry Not Present Interrupt Enable
        pub(crate) lrenpie@[2:2],
        // No Pending Interrupt Enable
        pub(crate) npie@[3:3],
        // Virtual Group0 Error Interrupt Enable
        pub(crate) vgrp0eie@[4:4],
        // Virtual Group0 Disable Interrupt Enable
        pub(crate) vgrp0die@[5:5],
        // Virtual Group1 Error Interrupt Enable
        pub(crate) vgrp1eie@[6:6],
        // Virtual Group1 Disable Interrupt Enable
        pub(crate) vgrp1die@[7:7],
        reserved@[26:8] [res0],
        // EOICount (maintenance interrupt source)
        pub(crate) eoicount@[31:27],
    }
}

bitregs! {
    /// Virtualization Type Register, GICH_VTR (ARM IHI 0048B Table 5-3).
    pub(crate) struct GICH_VTR: u32 {
        // ListRegs[5:0] (number of implemented List registers is ListRegs + 1).
        pub(crate) list_regs@[5:0],
        reserved@[22:6] [res0],

        // Pribits[24:23] (actual number of priority bits is Pribits + 1).
        pub(crate) pribits@[24:23],
        reserved@[25:25] [res0],

        // PreBits[28:26] (actual number of preemption bits is PreBits + 1).
        pub(crate) prebits@[28:26],
        reserved@[31:29] [res0],
    }
}

bitregs! {
    /// Virtual Machine Control Register, GICH_VMCR (ARM IHI 0048B Table 5-4).
    pub(crate) struct GICH_VMCR: u32 {
        // VMGrp0En[0]
        pub(crate) vm_grp0_en@[0:0],
        // VMGrp1En[1]
        pub(crate) vm_grp1_en@[1:1],
        // AckCtl[2]
        pub(crate) ack_ctl@[2:2],
        // FIQEn[3]
        pub(crate) fiq_en@[3:3],
        // CBPR[4]
        pub(crate) cbpr@[4:4],
        reserved@[8:5] [res0],
        // EOImode[9]
        pub(crate) eoi_mode@[9:9],
        reserved@[17:10] [res0],
        // BPR[20:18]
        pub(crate) bpr@[20:18],
        // ABPR[23:21]
        pub(crate) abpr@[23:21],
        reserved@[31:24] [res0],
    }
}

bitregs! {
    /// Maintenance Interrupt Status Register, GICH_MISR (ARM IHI 0048B Table 5-5).
    pub(crate) struct GICH_MISR: u32 {
        // EOI[0]
        pub(crate) eoi@[0:0],
        // U[1]
        pub(crate) u@[1:1],
        // LRENP[2]
        pub(crate) lrenp@[2:2],
        // NP[3]
        pub(crate) np@[3:3],
        // VGrp0E[4]
        pub(crate) vgrp0e@[4:4],
        // VGrp0D[5]
        pub(crate) vgrp0d@[5:5],
        // VGrp1E[6]
        pub(crate) vgrp1e@[6:6],
        // VGrp1D[7]
        pub(crate) vgrp1d@[7:7],
        reserved@[31:8] [res0],
    }
}

bitregs! {
    /// End of Interrupt Status Register, GICH_EISR0/1 (ARM IHI 0048B Table 5-6).
    pub(crate) struct GICH_EISR: u32 {
        // EOI status bits [31:0]
        pub(crate) eoi_status@[31:0],
    }
}

bitregs! {
    /// Empty List Register Status Register, GICH_ELRSR0/1 (ARM IHI 0048B Table 5-7).
    pub(crate) struct GICH_ELRSR: u32 {
        // List register status bits [31:0]
        pub(crate) lr_status@[31:0],
    }
}

bitregs! {
    /// Active Priorities Register, GICH_APR (ARM IHI 0048B Table 5-8).
    pub(crate) struct GICH_APR: u32 {
        pub(crate) active_prio@[31:0],
    }
}

bitregs! {
    /// List Register n, GICH_LRn (ARM IHI 0048B Table 5-9).
    pub(crate) struct GICH_LR: u32 {
        // Virtual interrupt ID [9:0]
        pub(crate) virtual_id@[9:0],

        // PhysID / CPUID+EOI overlay [19:10]
        union phys@[19:10] {
            // HW == 0 interpretation.
            view Sw {
                // CPUID[12:10] (source CPU for virtual SGI)
                pub(crate) cpuid@[12:10],
                reserved@[18:13] [res0],
                // EOI[19]
                pub(crate) eoi@[19:19],
            },
            // HW == 1 interpretation.
            view Hw {
                // Physical interrupt ID [19:10]
                pub(crate) physical_id@[19:10],
            },
        }

        reserved@[22:20] [res0],

        // Priority[27:23] (uses implemented priority bits; see GICH_VTR.Pribits)
        pub(crate) priority@[27:23],

        // State[29:28]
        pub(crate) state@[29:28] as LrState {
            Invalid = 0b00,
            Pending = 0b01,
            Active = 0b10,
            PendingAndActive = 0b11,
        },

        // Grp1[30]
        pub(crate) grp1@[30:30],

        // HW[31]
        pub(crate) hw@[31:31],
    }
}

/// GICv2 Distributor register frame (0x1000 bytes) per ARM IHI 0048B Table 4-1;
/// GIC-400 TRM maps this block at 0x1000-0x1FFF in the integrated memory map.
#[repr(C)]
pub(crate) struct GicV2Distributor {
    /// Distributor Control Register; enables forwarding for Group0/Group1.
    pub ctlr: ReadWrite<GICD_CTLR>, // 0x000
    pub typer: ReadOnly<GICD_TYPER>, // 0x004
    pub iidr: ReadOnly<u32>,         // 0x008
    _rsvd_00c_007f: [u8; 0x74],      // 0x00C-0x07F

    /// Interrupt Group Registers; register n covers interrupts 32*n..32*n+31 (Group0 vs Group1 selection).
    ///
    /// Bit value meaning:
    /// - `0` => Group0
    /// - `1` => Group1
    ///
    /// Group interpretation depends on whether Security Extensions are implemented and which copy
    /// of the register bank is visible (Secure vs Non-secure).
    pub igroupr: [ReadWrite<u32>; 32], // 0x080-0x0FC
    /// Interrupt Set-Enable Registers; register n covers interrupts 32*n..32*n+31.
    pub isenabler: [ReadWrite<u32>; 32], // 0x100-0x17C
    /// Interrupt Clear-Enable Registers; register n covers interrupts 32*n..32*n+31.
    pub icenabler: [ReadWrite<u32>; 32], // 0x180-0x1FC
    /// Interrupt Set-Pending Registers; register n covers interrupts 32*n..32*n+31.
    pub ispendr: [ReadWrite<u32>; 32], // 0x200-0x27C
    /// Interrupt Clear-Pending Registers; register n covers interrupts 32*n..32*n+31.
    pub icpendr: [ReadWrite<u32>; 32], // 0x280-0x2FC
    /// Interrupt Set-Active Registers; register n covers interrupts 32*n..32*n+31.
    pub isactiver: [ReadWrite<u32>; 32], // 0x300-0x37C
    /// Interrupt Clear-Active Registers; register n covers interrupts 32*n..32*n+31.
    pub icactiver: [ReadWrite<u32>; 32], // 0x380-0x3FC

    // Priority window: 0x0400..0x07FF (Table 4-1)
    /// Interrupt Priority Registers; four 8-bit priority fields per word.
    pub ipriorityr: [[ReadWrite<u8>; 4]; 255],
    _rsvd_07fc_07ff: [u8; 4],

    // ITARGETSR window: 0x0800..0x0BFF
    /// Interrupt Processor Targets Registers; word n covers interrupts 4*n..4*n+3.
    /// 0x800-0x81C (interrupts 0-31, SGIs/PPIs) are RO and can be banked.
    ///
    /// In particular, ITARGETSR0-7 readback is banked/RO and returns a value corresponding only
    /// to the reading CPU interface (commonly a one-hot CPU target mask).
    /// 0x820-0xBF8 (SPIs) are RW, one byte per interrupt (byte accesses permitted); 0xBFC reserved.
    pub itargetsr0_7: [[ReadOnly<u8>; 4]; 8],
    pub itargetsr: [[ReadWrite<u8>; 4]; 247],
    _rsvd_0bfc_0bff: [u8; 4],

    /// Interrupt Configuration Registers; register n covers interrupts 16*n..16*n+15.
    /// For interrupt m, field F = m mod 16 uses bits [2F+1:2F] (edge vs level).
    pub icfgr: [ReadWrite<u32>; 64], // 0x0C00-0x0CFC
    _rsvd_0d00_0dff: [u8; 0x100], // 0x0D00-0x0DFF
    /// Non-Secure Access Control Registers; register n covers interrupts 16*n..16*n+15.
    pub nsacr: [ReadWrite<u32>; 64], // 0x0E00-0x0EFC

    /// Software Generated Interrupt Register; issues SGIs (effect when Distributor forwarding disabled is IMPLEMENTATION DEFINED; NSATT depends on Security Extensions).
    pub sgir: WriteOnly<GICD_SGIR>, // 0x0F00
    _rsvd_0f04_0f0f: [u8; 0x0C],        // 0x0F04-0x0F0F
    pub cpendsgir: [ReadWrite<u32>; 4], // 0x0F10-0x0F1C
    pub spendsgir: [ReadWrite<u32>; 4], // 0x0F20-0x0F2C
    _rsvd_0f30_0fcf: [u8; 0xA0],        // 0x0F30-0x0FCF

    /// Peripheral ID registers (RO).
    pub pidr: [ReadOnly<u32>; 8], // 0x0FD0-0x0FEC
    /// Component ID registers (RO).
    pub cidr: [ReadOnly<u32>; 4], // 0x0FF0-0x0FFC
}

/// GICv2 CPU interface register frame (0x2000 bytes including DIR at 0x1000) per ARM IHI 0048B Table 4-2;
/// GIC-400 TRM maps CPU interfaces at 0x2000-0x3FFF.
#[repr(C)]
pub(crate) struct GicV2CpuInterface {
    /// CPU Interface Control Register; enables signaling for Group0/Group1 (bit assignments vary with Security Extensions/Secure copy).
    pub ctlr: ReadWrite<GICC_CTLR>, // 0x0000
    pub pmr: ReadWrite<GICC_PMR>, // 0x0004
    pub bpr: ReadWrite<GICC_BPR>, // 0x0008
    /// Interrupt Acknowledge Register; returns interrupt ID to be serviced.
    pub iar: ReadOnly<GICC_IAR>, // 0x000C
    /// End of Interrupt Register; EOImode=0 drops priority and deactivates, EOImode=1 drops only.
    pub eoir: WriteOnly<GICC_EOIR>, // 0x0010
    pub rpr: ReadOnly<u32>,       // 0x0014
    pub hppir: ReadOnly<GICC_HPPIR>, // 0x0018
    pub abpr: ReadWrite<GICC_ABPR>, // 0x001C
    pub aiar: ReadOnly<GICC_IAR>, // 0x0020
    pub aeoir: WriteOnly<u32>,    // 0x0024
    pub ahppir: ReadOnly<GICC_AHPPIR>, // 0x0028
    _rsvd_002c_00cf: [u8; 0xA4],  // 0x002C-0x00CF
    pub apr: [ReadWrite<u32>; 4], // 0x00D0-0x00DC
    pub nsapr: [ReadWrite<u32>; 4], // 0x00E0-0x00EC
    _rsvd_00f0_00fb: [u8; 0x0C],  // 0x00F0-0x00FB
    pub iidr: ReadOnly<u32>,      // 0x00FC
    _rsvd_0100_0fff: [u8; 0xF00], // 0x0100-0x0FFF
    /// Deactivate Interrupt Register; valid when priority drop/deactivate are split (EOImode=1), UNPREDICTABLE otherwise.
    pub dir: WriteOnly<GICC_DIR>, // 0x1000
    _rsvd_1004_1fff: [u8; 0x0FFC], // 0x1004-0x1FFF
}

/// GICv2 Virtual Interface Control block (0x1000 bytes) per ARM IHI 0048B Table 5-1;
/// GIC-400 TRM maps this block at 0x4000-0x5FFF.
#[repr(C)]
pub(crate) struct GicV2VirtualInterfaceControl {
    /// Hypervisor Control Register; En must be set for virtual or maintenance interrupts to assert.
    pub hcr: ReadWrite<GICH_HCR>, // 0x00
    /// Virtualization Type Register.
    ///
    /// `ListRegs` is encoded as `VTR[5:0] + 1` (number of implemented list registers).
    pub vtr: ReadOnly<GICH_VTR>, // 0x04
    /// VMCR alias; bundles virtual CPU view state for save/restore.
    pub vmcr: ReadWrite<GICH_VMCR>, // 0x08
    _rsvd_0c_0f: [u8; 0x04],              // 0x0C-0x0F
    pub misr: ReadOnly<GICH_MISR>,        // 0x10
    _rsvd_14_1f: [u8; 0x0C],              // 0x14-0x1F
    pub eisr: [ReadOnly<GICH_EISR>; 2],   // 0x20-0x24
    _rsvd_028_02f: [u8; 0x08],            // 0x028-0x02F
    pub elrsr: [ReadOnly<GICH_ELRSR>; 2], // 0x30-0x34
    _rsvd_038_0ef: [u8; 0xB8],            // 0x038-0x0EF
    pub apr: ReadWrite<GICH_APR>,         // 0x0F0
    _rsvd_0f4_0ff: [u8; 0x0C],            // 0x0F4-0x0FF
    pub lr: [ReadWrite<GICH_LR>; 64],     // 0x100-0x1FC
    _rsvd_200_fff: [u8; 0xE00],           // 0x200-0xFFF
}

/// GICv2 Virtual CPU interface (0x2000 bytes including DIR) per ARM IHI 0048B Table 5-10;
/// GIC-400 TRM maps virtual CPU interfaces at 0x6000-0x7FFF. Only Group 1 interrupts target the hypervisor in this path.
#[repr(C)]
pub(crate) struct GicV2VirtualCpuInterface {
    /// Virtual CPU Control Register; EOImode controls whether EOI also deactivates (0) or only drops priority (1).
    pub ctlr: ReadWrite<GICV_CTLR>, // 0x0000
    pub pmr: ReadWrite<u32>, // 0x0004
    pub bpr: ReadWrite<u32>, // 0x0008
    /// Virtual Interrupt Acknowledge Register.
    pub iar: ReadOnly<u32>, // 0x000C
    /// Virtual End of Interrupt; EOImode=0 drops priority and deactivates, EOImode=1 drops only.
    pub eoir: WriteOnly<u32>, // 0x0010
    pub rpr: ReadOnly<u32>,  // 0x0014
    pub hppir: ReadOnly<GICC_HPPIR>, // 0x0018
    pub abpr: ReadWrite<u32>, // 0x001C
    pub aiar: ReadOnly<u32>, // 0x0020
    pub aeoir: WriteOnly<u32>, // 0x0024
    pub ahppir: ReadOnly<GICC_AHPPIR>, // 0x0028
    _rsvd_002c_00cf: [u8; 0xA4], // 0x002C-0x00CF
    pub apr: [ReadWrite<u32>; 4], // 0x00D0-0x00DC
    pub nsapr: [ReadWrite<u32>; 4], // 0x00E0-0x00EC
    _rsvd_00f0_00fb: [u8; 0x0C], // 0x00F0-0x00FB
    pub iidr: ReadOnly<u32>, // 0x00FC
    _rsvd_0100_0fff: [u8; 0xF00], // 0x0100-0x0FFF
    /// Virtual Deactivate Interrupt Register; valid when EOImode=1 (otherwise UNPREDICTABLE) to deactivate list register entry.
    pub dir: WriteOnly<u32>, // 0x1000
    _rsvd_1004_1fff: [u8; 0x0FFC], // 0x1004-0x1FFF
}
