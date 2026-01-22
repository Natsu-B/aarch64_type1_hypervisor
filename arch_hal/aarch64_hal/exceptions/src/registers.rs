#![allow(non_camel_case_types)]
use typestate::bitregs;

bitregs! {
    pub(crate) struct VBAR_EL2: u64 {
        reserved@[10:0] [res0],
        // Virtual Base Address
        pub(crate) vba@[63:11],
    }
}

bitregs! {
    /// Vector Base Address Register for EL1.
    pub(crate) struct VBAR_EL1: u64 {
        reserved@[10:0] [res0],
        // Base address for the EL1 vector table; must be 2 KiB aligned.
        pub(crate) vba@[63:11],
    }
}

bitregs! {
    /// Exception Syndrome Register(EL2)
    pub(crate) struct ESR_EL2: u64 {
        union iss@[24:0] {
            view unknown {
                reserved@[24:0] [res0],
            }
            view wf_ {
                // Trapped Instruction
                pub(crate) ti@[1:0] as TI {
                    WFI  = 0b00,
                    WFE  = 0b01,
                    // When FEAT_WFxT is implemented
                    WFIT = 0b10,
                    // When FEAT_WFxT is implemented
                    WFET = 0b11,
                },

                // When FEAT_WFxT is implemented
                pub(crate) rv@[2:2],
                reserved@[4:3] [res0],
                // When FEAT_WFxT is implemented
                pub(crate) rn@[9:5],
                reserved@[19:10] [res0],
                pub(crate) cond@[23:20] as COND {
                    // exception taken from AArch64
                    AArch64 = 0b1110,
                },
                pub(crate) cv@[24:24],
            }

            view data_abort {
                pub(crate) dfsc@[5:0] as DataFaultStatusCade {
                    AddressSizeLevel0                 = 0b000000, // Address size fault, level 0 or translation table base register
                    AddressSizeLevel1                 = 0b000001,
                    AddressSizeLevel2                 = 0b000010,
                    AddressSizeLevel3                 = 0b000011,

                    TranslationLevel0                 = 0b000100, // Translation fault, level 0
                    TranslationLevel1                 = 0b000101,
                    TranslationLevel2                 = 0b000110,
                    TranslationLevel3                 = 0b000111,

                    AccessFlagLevel1                  = 0b001001,
                    AccessFlagLevel2                  = 0b001010,
                    AccessFlagLevel3                  = 0b001011,
                    AccessFlagLevel0                  = 0b001000,

                    PermissionLevel0                  = 0b001100, // When FEAT_LPA2
                    PermissionLevel1                  = 0b001101,
                    PermissionLevel2                  = 0b001110,
                    PermissionLevel3                  = 0b001111,

                    Sev_NotOnTableWalk                = 0b010000, // Synchronous External abort, not on table walk
                    TagCheckFault                     = 0b010001, // Synchronous Tag Check Fault (When FEAT_MTE2)

                    Sev_TableWalkLevelMinus2          = 0b010010,
                    Sev_TableWalkLevelMinus1          = 0b010011, // (When FEAT_D128 for some codes)
                    Sev_TableWalkLevel0               = 0b010100,
                    Sev_TableWalkLevel1               = 0b010101,
                    Sev_TableWalkLevel2               = 0b010110,
                    Sev_TableWalkLevel3               = 0b010111,

                    ParityNotOnTableWalk              = 0b011000, // Synchronous parity/ECC on memory access, not table walk
                    Parity_TableWalkLevelMinus1       = 0b011011,
                    Parity_TableWalkLevel0            = 0b011100,
                    Parity_TableWalkLevel1            = 0b011101,
                    Parity_TableWalkLevel2            = 0b011110,
                    Parity_TableWalkLevel3            = 0b011111,

                    AlignmentFault                    = 0b100001,

                    GranuleProt_TableWalkLevelMinus2  = 0b100010, // Granule Protection Fault (various FEAT_* conditions)
                    GranuleProt_TableWalkLevelMinus1  = 0b100011,
                    GranuleProt_TableWalkLevel0       = 0b100100,
                    GranuleProt_TableWalkLevel1       = 0b100101,
                    GranuleProt_TableWalkLevel2       = 0b100110,
                    GranuleProt_TableWalkLevel3       = 0b100111,

                    GranuleProt_NotOnTableWalk        = 0b101000, // When FEAT_RME
                    AddressSizeLevelMinus1            = 0b101001, // When FEAT_LPA2
                    TranslationLevelMinus2            = 0b101010, // When FEAT_D128
                    TranslationLevelMinus1            = 0b101011, // When FEAT_LPA2
                    AddressSizeLevelMinus2            = 0b101100, // When FEAT_D128

                    TlbConflictAbort                  = 0b110000,
                    UnsupportedAtomicUpdate           = 0b110001, // Unsupported atomic hardware update fault (FEAT_HAFDBS)
                    ImplementationDefined_Lockdown    = 0b110100,
                    ImplementationDefined_UnsupportedExclusiveOrAtomic = 0b110101,

                    // All other values are reserved.
                },
                pub wnr@[6:6] as WriteNotRead {
                    ReadingMemoryAbort = 0b0,
                    WritingMemoryAbort = 0b1,
                },
                pub(crate) s1ptw@[7:7] as S1PTW {
                    // Fault not on a stage 2 translation for a stage 1 translation table walk.
                    FaultAtStage1 = 0b0,
                    // Fault on the stage 2 translation of an access for a stage 1 translation table walk.
                    FaultAtStage2 = 0b1,
                },
                pub(crate) cm@[8:8] as CacheMaintenance {
                    NotCacheMaintenaceInstruction = 0b0,
                    // DC ZVA, DC GVA, DC GZVA are not classified as chache maintenace instruction
                    CacheMaintenaceInstruction    = 0b1,
                },
                // Implementation Defined
                pub(crate) ea@[9:9],
                // Fault Address Register Not Valid
                pub(crate) fnv@[10:10] as FARNotValid {
                    Valid = 0b0,
                    // FAR is not valid, holds UNKNOWN value
                    NotValid = 0b1,
                },
                union bits12_11@[12:11] {
                    // When (DFSC IN {0b00xxxx} || DFSC IN {0b10101x}) && !(DFSC IN {0b0000xx}):
                    view load_store {
                        pub(crate) lst@[12:11] as Load_StoreType {
                            IsNotSpecified        = 0b00,
                            // When FEAT_LS64_V is implemented
                            ST64BVInstruction     = 0b01,
                            // When FEAT_LS64 is implemented
                            LD64BST64BInstruction = 0b10,
                            // When FEAT_LS64_ACCDATA is implemented
                            ST64BV0Instruction    = 0b11,
                        }
                    }
                    // When IsFeatureImplemented(FEAT_RAS) && ((DFSC == 0b010000 || DFSC IN {0b01001x}) || DFSC
                    // IN {0b0101xx}):
                    view ras {
                        pub(crate) sync_error_type@[12:11] as SynchronousErrorType {
                            RecoverableState = 0b00,
                            Uncontainable    = 0b10, // FEAT_RASv2 is not implemented
                            RestartableState = 0b11,
                        },
                    }
                    view other {
                        reserved@[12:11] [res0],
                    }
                }
                // Indicate that the fault came from use of VNCR_EL2 register by EL1 code
                pub(crate) vncr@[13:13],
                union bit14@[14:14] {
                    // When ISV==1
                    view isv {
                        // Acquire/Release
                        pub(crate) ar@[14:14],
                    }
                    // When IsFeatureImplemented(FEAT_PFAR) && ((DFSC == 0b010000 || DFSC IN {0b01001x}) ||
                    // DFSC IN {0b0101xx}):
                    view non_isv {
                        pub(crate) pfv@[14:14],
                    }
                }
                union bit15@[15:15] {
                    view isv {
                        pub sf@[15:15] as InstructionRegisterSize {
                            Instruction32bit = 0b0,
                            Instruction64bit = 0b1,
                        },
                    }
                    view non_isv {
                        pub(crate) fnp@[15:15] as FARNotPrecise {
                            FARHoldsVA = 0b0,
                        },
                    }
                }
                union bits20_16@[20:16] {
                    // When ISV == 1
                    view isv {
                        // Syndrome Register Transfer
                        pub(crate) srt@[20:16],
                    }
                    // When ((ISV == '0') && IsFeatureImplemented(FEAT_RASv2)) && ((DFSC == 0b010000 || DFSC IN
                    // {0b01001x }) || DFSC IN {0b0101xx}):
                    view non_isv {
                        pub(crate) wu@[20:16] as WriteUpdate {
                            NotStoreOrMaybeUpdated = 0b00, // Not a store instruction or translation-table update, or the location might have been updated.
                            StoreDidNotUpdate      = 0b01, // Store instruction or translation-table update that did NOT update the location.
                            StoreUpdated           = 0b10, // Store instruction or translation-table update that DID update the location.
                        }
                    }
                }
                pub(crate) sse@[21:21] as SyndromeSignExtend {
                    // Syndrome Sign Extend. For a byte, halfword, or word load operation, indicates whether the data item
                    // must be sign extended.
                    NotRequireSignExtension = 0b0,
                    RequireSignExtension = 0b1,
                },
                pub sas@[23:22] as SyndromeAccessSize {
                    Byte = 0b00,
                    HalfWord = 0b01,
                    Word = 0b10,
                    DoubleWord = 0b11,
                },
                // Instruction Syndrome Valid
                pub(crate) isv@[24:24],
            }

            view smc_aarch64 {
                pub(crate) imm16@[15:0],
                reserved@[24:16] [res0],
            }
        }
        pub(crate) il@[25:25],
        pub ec@[31:26] as ExceptionClass {
            // unknown reason
            UnknownReason                  = 0b00_0000,
            TrappedWFInstruction           = 0b00_0001,
            InstructionAbortFromLowerLevel = 0b10_0000,
            DataAbortFormLowerLevel        = 0b10_0100,
            // SMC Instruction Exception in Aarch64 state
            SMCInstructionExecution        = 0b01_0111,
            // BRK Instruction Exception in AArch64 state from lower EL
            BrkInstructionAArch64LowerLevel = 0b11_1100,
            // Breakpoint from lower EL (AArch64)
            BreakpointLowerLevel           = 0b11_0000,
            // Software step from lower EL (AArch64)
            SoftwareStepLowerLevel         = 0b11_0010,
            // Watchpoint from lower EL (AArch64)
            WatchpointLowerLevel           = 0b11_0100,
        },
        pub(crate) iss2@[55:32],
        reserved@[63:56] [res0],
    }
}

bitregs! {
    /// Exception Link Register(EL2)
    pub(crate) struct ELR_EL2: u64 {
        pub(crate) resturn_addr@[63:0],
    }
}

pub(crate) const HPFAR_OFFSET: usize = 12;

bitregs! {
    pub(crate) struct HPFAR_EL2: u64 {
        reserved@[3:0] [res0],
        // Faulting Intermediate Physical Address
        // When FEAT_D128 is implemented
        //  FIPA[47:4] -> IPA[55:12]
        // When FEAT_LPA is implemented & FEAT_D128 is not implemented
        //  FIPA[43:4] -> IPA[51:12]
        // Otherwise
        //  FIPA[39:4] -> IPA[47:12]
        pub(crate) fipa@[47:4],
        reserved@[62:48] [res0],
        // When FEAT_SEL2 is implemented
        pub(crate) ns@[63:63],
    }
}

bitregs! {
    pub(crate) struct FAR_EL2: u64 {
        // Faulting Virtual Address
        pub(crate) va@[63:0],
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;

    #[test_case]
    fn esr_el2_brk_ec_decodes() {
        let esr = ESR_EL2::from_bits((0x3c_u64) << 26);
        let ec = esr.get_enum::<_, ExceptionClass>(ESR_EL2::ec);
        assert_eq!(ec, Some(ExceptionClass::BrkInstructionAArch64LowerLevel));
    }
}
