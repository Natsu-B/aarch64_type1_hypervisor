/// Trigger configuration for an interrupt (where configurable).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TriggerMode {
    Level,
    Edge,
}

/// Edge/level semantics for injection bookkeeping.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IrqSense {
    Edge,
    Level,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PirqHookOp {
    Configure {
        group: u8,
        priority: u8,
        trigger: TriggerMode,
        targets: u32,
        enable: bool,
    },
    Eoi,
    Deactivate,
    Resample,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PirqHookError {
    InvalidState,
    Unsupported,
    InvalidInput,
}

pub type PirqHookFn = fn(int_id: u32, op: PirqHookOp) -> Result<(), PirqHookError>;
