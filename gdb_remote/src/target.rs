/// Actions requested by the debugger when resuming execution.
#[derive(Debug)]
pub enum ResumeAction {
    Continue(Option<u64>), // optional new program counter
    Step(Option<u64>),     // optional new program counter
}

/// Target-specific error handling for debugger requests.
#[derive(Debug)]
pub enum TargetError<R, U> {
    NotSupported,
    Recoverable(R),
    Unrecoverable(U),
}

/// Target capabilities reported to the debugger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetCapabilities(u32);

impl TargetCapabilities {
    pub const NONE: Self = Self(0);
    pub const SW_BREAK: Self = Self(1 << 0);
    pub const HW_BREAK: Self = Self(1 << 1);
    pub const WATCH_W: Self = Self(1 << 2);
    pub const WATCH_R: Self = Self(1 << 3);
    pub const WATCH_A: Self = Self(1 << 4);
    pub const VCONT: Self = Self(1 << 5);
    pub const XFER_FEATURES: Self = Self(1 << 6);

    pub const fn empty() -> Self {
        Self::NONE
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchpointKind {
    Write,
    Read,
    Access,
}

/// Abstraction over an architecture-specific debug target.
pub trait Target {
    type RecoverableError;
    type UnrecoverableError;

    fn capabilities(&self) -> TargetCapabilities {
        TargetCapabilities::default()
    }

    fn recoverable_error_code(&self, _e: &Self::RecoverableError) -> u8 {
        1
    }

    fn xfer_features(
        &mut self,
        _annex: &str,
    ) -> Result<Option<&[u8]>, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Ok(None)
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
