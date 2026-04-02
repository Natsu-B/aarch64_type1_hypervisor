//! Target abstraction for debuggable systems.

/// Actions requested by the debugger when resuming execution.
#[derive(Debug)]
pub enum ResumeAction {
    /// Continue execution, optionally at a new address.
    Continue(Option<u64>),
    /// Single-step, optionally at a new address.
    Step(Option<u64>),
}

/// Target-specific error handling for debugger requests.
#[derive(Debug)]
pub enum TargetError<R, U> {
    /// Operation not supported by this target.
    NotSupported,
    /// Recoverable error (can continue debugging).
    Recoverable(R),
    /// Unrecoverable error (must abort debugging session).
    Unrecoverable(U),
}

/// Target capabilities reported to the debugger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetCapabilities(u32);

impl TargetCapabilities {
    /// No capabilities.
    pub const NONE: Self = Self(0);
    /// Software breakpoints.
    pub const SW_BREAK: Self = Self(1 << 0);
    /// Hardware breakpoints.
    pub const HW_BREAK: Self = Self(1 << 1);
    /// Write watchpoints.
    pub const WATCH_W: Self = Self(1 << 2);
    /// Read watchpoints.
    pub const WATCH_R: Self = Self(1 << 3);
    /// Access (read/write) watchpoints.
    pub const WATCH_A: Self = Self(1 << 4);
    /// vCont packet support.
    pub const VCONT: Self = Self(1 << 5);
    /// Feature XML transfer.
    pub const XFER_FEATURES: Self = Self(1 << 6);
    /// Memory map XML transfer.
    pub const XFER_MEMORY_MAP: Self = Self(1 << 7);

    /// Returns an empty capability set.
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// Returns true if all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl Default for TargetCapabilities {
    fn default() -> Self {
        TargetCapabilities::SW_BREAK
    }
}

impl core::ops::BitOr for TargetCapabilities {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for TargetCapabilities {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Watchpoint type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchpointKind {
    /// Write watchpoint.
    Write,
    /// Read watchpoint.
    Read,
    /// Access (read or write) watchpoint.
    Access,
}

/// Abstraction over an architecture-specific debug target.
pub trait Target {
    /// Recoverable error type (e.g., memory access failure).
    type RecoverableError;
    /// Unrecoverable error type (e.g., target disconnected).
    type UnrecoverableError;

    /// Returns the target's capabilities.
    fn capabilities(&self) -> TargetCapabilities {
        TargetCapabilities::default()
    }

    /// Returns an error code for a recoverable error.
    fn recoverable_error_code(&self, _e: &Self::RecoverableError) -> u8 {
        1
    }

    /// Returns target description XML for the given annex.
    fn xfer_features(
        &mut self,
        _annex: &str,
    ) -> Result<Option<&[u8]>, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Ok(None)
    }

    /// Returns memory map XML.
    fn xfer_memory_map(
        &mut self,
    ) -> Result<Option<&[u8]>, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Ok(None)
    }

    /// Handle a `qRcmd` monitor command.
    ///
    /// `cmd` contains decoded bytes from `qRcmd` (typically ASCII).
    /// Return `Ok(0)` for "handled, no output" (server replies `OK`).
    /// Return `Ok(n > 0)` for "handled, output in `out[..n]`" (server replies with hex-encoded output).
    /// Return `Err(TargetError::NotSupported)` to indicate the command is unrecognized (server replies empty).
    fn monitor_command(
        &mut self,
        _cmd: &[u8],
        _out: &mut [u8],
    ) -> Result<usize, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Err(TargetError::NotSupported)
    }

    /// Read all registers into `dst`, returning bytes written.
    fn read_registers(
        &mut self,
        dst: &mut [u8],
    ) -> Result<usize, TargetError<Self::RecoverableError, Self::UnrecoverableError>>;
    /// Write all registers from `src`.
    fn write_registers(
        &mut self,
        src: &[u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>>;

    /// Read a single register identified by GDB's register number.
    fn read_register(
        &mut self,
        regno: u32,
        dst: &mut [u8],
    ) -> Result<usize, TargetError<Self::RecoverableError, Self::UnrecoverableError>>;
    /// Write a single register identified by GDB's register number.
    fn write_register(
        &mut self,
        regno: u32,
        src: &[u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>>;

    /// Read target memory into `dst`.
    fn read_memory(
        &mut self,
        addr: u64,
        dst: &mut [u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>>;
    /// Write target memory from `src`.
    fn write_memory(
        &mut self,
        addr: u64,
        src: &[u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>>;

    /// Insert a software breakpoint at `addr`.
    /// Implementations should be idempotent for repeated requests.
    fn insert_sw_breakpoint(
        &mut self,
        addr: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>>;
    /// Remove a software breakpoint at `addr`.
    /// Implementations should be idempotent for repeated requests.
    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>>;

    /// Insert a hardware breakpoint at `addr`.
    /// Implementations should be idempotent for repeated requests.
    fn insert_hw_breakpoint(
        &mut self,
        _addr: u64,
        _kind: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Err(TargetError::NotSupported)
    }
    /// Remove a hardware breakpoint at `addr`.
    /// Implementations should be idempotent for repeated requests.
    fn remove_hw_breakpoint(
        &mut self,
        _addr: u64,
        _kind: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Err(TargetError::NotSupported)
    }

    /// Insert a watchpoint for the given address range.
    /// Implementations should be idempotent for repeated requests.
    fn insert_watchpoint(
        &mut self,
        _kind: WatchpointKind,
        _addr: u64,
        _len: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Err(TargetError::NotSupported)
    }
    /// Remove a watchpoint for the given address range.
    /// Implementations should be idempotent for repeated requests.
    fn remove_watchpoint(
        &mut self,
        _kind: WatchpointKind,
        _addr: u64,
        _len: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Err(TargetError::NotSupported)
    }
}
