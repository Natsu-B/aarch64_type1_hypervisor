#![no_std]
#![feature(sync_unsafe_cell)]

use core::arch::asm;
use core::cell::SyncUnsafeCell;

use cpu::Registers;
use cpu::{self};

/// PSCI v1.x SMC32/SMC64 function IDs (DEN0022).
#[repr(u64)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PsciFunctionId {
    Version = 0x8400_0000,

    CpuSuspendSmc32 = 0x8400_0001,
    CpuSuspendSmc64 = 0xC400_0001,

    CpuOff = 0x8400_0002,

    CpuOnSmc32 = 0x8400_0003,
    CpuOnSmc64 = 0xC400_0003,

    AffinityInfoSmc32 = 0x8400_0004,
    AffinityInfoSmc64 = 0xC400_0004,

    MigrateSmc32 = 0x8400_0005,
    MigrateSmc64 = 0xC400_0005,

    MigrateInfoType = 0x8400_0006,

    MigrateInfoUpCpuSmc32 = 0x8400_0007,
    MigrateInfoUpCpuSmc64 = 0xC400_0007,

    SystemOff = 0x8400_0008,
    SystemReset = 0x8400_0009,

    PsciFeatures = 0x8400_000A,

    CpuFreeze = 0x8400_000B,

    CpuDefaultSuspendSmc32 = 0x8400_000C,
    CpuDefaultSuspendSmc64 = 0xC400_000C,

    NodeHwStateSmc32 = 0x8400_000D,
    NodeHwStateSmc64 = 0xC400_000D,

    SystemSuspendSmc32 = 0x8400_000E,
    SystemSuspendSmc64 = 0xC400_000E,

    PsciSetSuspendMode = 0x8400_000F,

    StatResidencySmc32 = 0x8400_0010,
    StatResidencySmc64 = 0xC400_0010,

    StatCountSmc32 = 0x8400_0011,
    StatCountSmc64 = 0xC400_0011,

    SystemReset2Smc32 = 0x8400_0012,
    SystemReset2Smc64 = 0xC400_0012,

    MemProtect = 0x8400_0013,

    MemProtectCheckRangeSmc32 = 0x8400_0014,
    MemProtectCheckRangeSmc64 = 0xC400_0014,

    SystemOff2Smc32 = 0x8400_0015,
    SystemOff2Smc64 = 0xC400_0015,
}

/// PSCI return codes that must match the PSCI specification (Linux expects these values in x0).
#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub enum PsciReturnCode {
    Success = 0,
    NotSupported = -1,
    InvalidParameters = -2,
    Denied = -3,
    AlreadyOn = -4,
    OnPending = -5,
    InternalFailure = -6,
    NotPresent = -7,
    Disabled = -8,
    InvalidAddress = -9,
}

impl PsciReturnCode {
    #[inline]
    pub fn to_x0(self) -> u64 {
        self as i32 as u64
    }
}

/// Per-function PSCI handler.
///
/// Contract:
/// - Must NOT modify ELR_EL2. The PSCI dispatcher will advance ELR_EL2 by 4 bytes.
/// - Must write the PSCI result or error code to regs.x0.
pub type PsciHandler = fn(&mut cpu::Registers);
pub type UnknownPsciHandler = fn(u32, &mut cpu::Registers);

const PSCI_HANDLER_COUNT: usize = 35;

static PSCI_HANDLERS: SyncUnsafeCell<[PsciHandler; PSCI_HANDLER_COUNT]> =
    SyncUnsafeCell::new([default_psci_handler; PSCI_HANDLER_COUNT]);
static UNKNOWN_PSCI_HANDLER: SyncUnsafeCell<UnknownPsciHandler> =
    SyncUnsafeCell::new(default_unknown_psci_handler);

pub fn set_psci_handler(fid: PsciFunctionId, handler: PsciHandler) {
    // SAFETY: expected to be called during single-core early init only.
    let idx = handler_index(fid).expect("invalid psci");
    let table = unsafe { &mut *PSCI_HANDLERS.get() };
    table[idx] = handler;
}

pub fn set_unknown_psci_handler(handler: UnknownPsciHandler) {
    // SAFETY: expected to be called during single-core early init only.
    let slot = unsafe { &mut *UNKNOWN_PSCI_HANDLER.get() };
    *slot = handler;
}

fn get_psci_handler(fid: PsciFunctionId) -> Option<PsciHandler> {
    // SAFETY: single writer during init, read-only afterwards.
    handler_index(fid).map(|idx| unsafe { &*PSCI_HANDLERS.get() }[idx])
}

fn get_unknown_psci_handler() -> UnknownPsciHandler {
    // SAFETY: single writer during init, read-only afterwards.
    unsafe { *UNKNOWN_PSCI_HANDLER.get() }
}

fn decode_psci_function_id(fid: u32) -> Option<PsciFunctionId> {
    match fid {
        raw if raw == PsciFunctionId::Version as u32 => Some(PsciFunctionId::Version),

        raw if raw == PsciFunctionId::CpuSuspendSmc32 as u32 => {
            Some(PsciFunctionId::CpuSuspendSmc32)
        }
        raw if raw == PsciFunctionId::CpuSuspendSmc64 as u32 => {
            Some(PsciFunctionId::CpuSuspendSmc64)
        }

        raw if raw == PsciFunctionId::CpuOff as u32 => Some(PsciFunctionId::CpuOff),

        raw if raw == PsciFunctionId::CpuOnSmc32 as u32 => Some(PsciFunctionId::CpuOnSmc32),
        raw if raw == PsciFunctionId::CpuOnSmc64 as u32 => Some(PsciFunctionId::CpuOnSmc64),

        raw if raw == PsciFunctionId::AffinityInfoSmc32 as u32 => {
            Some(PsciFunctionId::AffinityInfoSmc32)
        }
        raw if raw == PsciFunctionId::AffinityInfoSmc64 as u32 => {
            Some(PsciFunctionId::AffinityInfoSmc64)
        }

        raw if raw == PsciFunctionId::MigrateSmc32 as u32 => Some(PsciFunctionId::MigrateSmc32),
        raw if raw == PsciFunctionId::MigrateSmc64 as u32 => Some(PsciFunctionId::MigrateSmc64),

        raw if raw == PsciFunctionId::MigrateInfoType as u32 => {
            Some(PsciFunctionId::MigrateInfoType)
        }

        raw if raw == PsciFunctionId::MigrateInfoUpCpuSmc32 as u32 => {
            Some(PsciFunctionId::MigrateInfoUpCpuSmc32)
        }
        raw if raw == PsciFunctionId::MigrateInfoUpCpuSmc64 as u32 => {
            Some(PsciFunctionId::MigrateInfoUpCpuSmc64)
        }

        raw if raw == PsciFunctionId::SystemOff as u32 => Some(PsciFunctionId::SystemOff),
        raw if raw == PsciFunctionId::SystemReset as u32 => Some(PsciFunctionId::SystemReset),

        raw if raw == PsciFunctionId::PsciFeatures as u32 => Some(PsciFunctionId::PsciFeatures),

        raw if raw == PsciFunctionId::CpuFreeze as u32 => Some(PsciFunctionId::CpuFreeze),

        raw if raw == PsciFunctionId::CpuDefaultSuspendSmc32 as u32 => {
            Some(PsciFunctionId::CpuDefaultSuspendSmc32)
        }
        raw if raw == PsciFunctionId::CpuDefaultSuspendSmc64 as u32 => {
            Some(PsciFunctionId::CpuDefaultSuspendSmc64)
        }

        raw if raw == PsciFunctionId::NodeHwStateSmc32 as u32 => {
            Some(PsciFunctionId::NodeHwStateSmc32)
        }
        raw if raw == PsciFunctionId::NodeHwStateSmc64 as u32 => {
            Some(PsciFunctionId::NodeHwStateSmc64)
        }

        raw if raw == PsciFunctionId::SystemSuspendSmc32 as u32 => {
            Some(PsciFunctionId::SystemSuspendSmc32)
        }
        raw if raw == PsciFunctionId::SystemSuspendSmc64 as u32 => {
            Some(PsciFunctionId::SystemSuspendSmc64)
        }

        raw if raw == PsciFunctionId::PsciSetSuspendMode as u32 => {
            Some(PsciFunctionId::PsciSetSuspendMode)
        }

        raw if raw == PsciFunctionId::StatResidencySmc32 as u32 => {
            Some(PsciFunctionId::StatResidencySmc32)
        }
        raw if raw == PsciFunctionId::StatResidencySmc64 as u32 => {
            Some(PsciFunctionId::StatResidencySmc64)
        }

        raw if raw == PsciFunctionId::StatCountSmc32 as u32 => Some(PsciFunctionId::StatCountSmc32),
        raw if raw == PsciFunctionId::StatCountSmc64 as u32 => Some(PsciFunctionId::StatCountSmc64),

        raw if raw == PsciFunctionId::SystemReset2Smc32 as u32 => {
            Some(PsciFunctionId::SystemReset2Smc32)
        }
        raw if raw == PsciFunctionId::SystemReset2Smc64 as u32 => {
            Some(PsciFunctionId::SystemReset2Smc64)
        }

        raw if raw == PsciFunctionId::MemProtect as u32 => Some(PsciFunctionId::MemProtect),

        raw if raw == PsciFunctionId::MemProtectCheckRangeSmc32 as u32 => {
            Some(PsciFunctionId::MemProtectCheckRangeSmc32)
        }
        raw if raw == PsciFunctionId::MemProtectCheckRangeSmc64 as u32 => {
            Some(PsciFunctionId::MemProtectCheckRangeSmc64)
        }

        raw if raw == PsciFunctionId::SystemOff2Smc32 as u32 => {
            Some(PsciFunctionId::SystemOff2Smc32)
        }
        raw if raw == PsciFunctionId::SystemOff2Smc64 as u32 => {
            Some(PsciFunctionId::SystemOff2Smc64)
        }

        _ => None,
    }
}

const fn handler_index(fid: PsciFunctionId) -> Option<usize> {
    Some(match fid {
        PsciFunctionId::Version => 0,
        PsciFunctionId::CpuSuspendSmc32 => 1,
        PsciFunctionId::CpuSuspendSmc64 => 2,
        PsciFunctionId::CpuOff => 3,
        PsciFunctionId::CpuOnSmc32 => 4,
        PsciFunctionId::CpuOnSmc64 => 5,
        PsciFunctionId::AffinityInfoSmc32 => 6,
        PsciFunctionId::AffinityInfoSmc64 => 7,
        PsciFunctionId::MigrateSmc32 => 8,
        PsciFunctionId::MigrateSmc64 => 9,
        PsciFunctionId::MigrateInfoType => 10,
        PsciFunctionId::MigrateInfoUpCpuSmc32 => 11,
        PsciFunctionId::MigrateInfoUpCpuSmc64 => 12,
        PsciFunctionId::SystemOff => 13,
        PsciFunctionId::SystemReset => 14,
        PsciFunctionId::PsciFeatures => 15,
        PsciFunctionId::CpuFreeze => 16,
        PsciFunctionId::CpuDefaultSuspendSmc32 => 17,
        PsciFunctionId::CpuDefaultSuspendSmc64 => 18,
        PsciFunctionId::NodeHwStateSmc32 => 19,
        PsciFunctionId::NodeHwStateSmc64 => 20,
        PsciFunctionId::SystemSuspendSmc32 => 21,
        PsciFunctionId::SystemSuspendSmc64 => 22,
        PsciFunctionId::PsciSetSuspendMode => 23,
        PsciFunctionId::StatResidencySmc32 => 24,
        PsciFunctionId::StatResidencySmc64 => 25,
        PsciFunctionId::StatCountSmc32 => 26,
        PsciFunctionId::StatCountSmc64 => 27,
        PsciFunctionId::SystemReset2Smc32 => 28,
        PsciFunctionId::SystemReset2Smc64 => 29,
        PsciFunctionId::MemProtect => 30,
        PsciFunctionId::MemProtectCheckRangeSmc32 => 31,
        PsciFunctionId::MemProtectCheckRangeSmc64 => 32,
        PsciFunctionId::SystemOff2Smc32 => 33,
        PsciFunctionId::SystemOff2Smc64 => 34,
    })
}

/// Default behavior: forward to firmware via SMC.
///
/// Does NOT adjust ELR_EL2; the caller must do that.
pub fn default_psci_handler(regs: &mut cpu::Registers) {
    secure_monitor_call(regs);
}

fn default_unknown_psci_handler(_fid_raw: u32, regs: &mut cpu::Registers) {
    default_psci_handler(regs);
}

pub fn handle_secure_monitor_call(regs: &mut Registers) {
    let fid_raw = regs.x0 as u32;

    if let Some(fid) = decode_psci_function_id(fid_raw) {
        let handler = get_psci_handler(fid).unwrap_or(default_psci_handler);
        handler(regs);
    } else {
        get_unknown_psci_handler()(fid_raw, regs);
    }

    let elr = cpu::get_elr_el2();
    cpu::set_elr_el2(elr.wrapping_add(4));
}

pub fn secure_monitor_call(regs: &mut Registers) {
    unsafe {
        asm!(
            "smc #0",
            inout("x0")  regs.x0,
            inout("x1")  regs.x1,
            inout("x2")  regs.x2,
            inout("x3")  regs.x3,
            inout("x4")  regs.x4,
            inout("x5")  regs.x5,
            inout("x6")  regs.x6,
            inout("x7")  regs.x7,
            inout("x8")  regs.x8,
            inout("x9")  regs.x9,
            inout("x10") regs.x10,
            inout("x11") regs.x11,
            inout("x12") regs.x12,
            inout("x13") regs.x13,
            inout("x14") regs.x14,
            inout("x15") regs.x15,
            inout("x16") regs.x16,
            inout("x17") regs.x17,
            clobber_abi("C")
        );
    }
}
