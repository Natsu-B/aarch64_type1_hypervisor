/// Actions requested by the debugger when resuming execution.
pub enum ResumeAction {
    Continue(Option<u64>), // optional new program counter
    Step(Option<u64>),     // optional new program counter
}

/// Abstraction over an architecture-specific debug target.
pub trait Target {
    type Error;

    /// Read all registers into `dst`, returning bytes written.
    fn read_registers(&mut self, dst: &mut [u8]) -> Result<usize, Self::Error>;
    /// Write all registers from `src`.
    fn write_registers(&mut self, src: &[u8]) -> Result<(), Self::Error>;

    /// Read a single register identified by GDB's register number.
    fn read_register(&mut self, regno: u32, dst: &mut [u8]) -> Result<usize, Self::Error>;
    /// Write a single register identified by GDB's register number.
    fn write_register(&mut self, regno: u32, src: &[u8]) -> Result<(), Self::Error>;

    /// Read target memory into `dst`.
    fn read_memory(&mut self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error>;
    /// Write target memory from `src`.
    fn write_memory(&mut self, addr: u64, src: &[u8]) -> Result<(), Self::Error>;

    /// Insert a software breakpoint at `addr`.
    fn insert_sw_breakpoint(&mut self, addr: u64) -> Result<(), Self::Error>;
    /// Remove a software breakpoint at `addr`.
    fn remove_sw_breakpoint(&mut self, addr: u64) -> Result<(), Self::Error>;
}
