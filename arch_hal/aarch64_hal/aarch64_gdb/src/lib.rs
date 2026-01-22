#![no_std]

use aarch64_mutex::RawSpinLockIrqSave;
use core::hint::spin_loop;
use cpu::Registers;
use cpu::registers::MDSCR_EL1;
use exceptions::registers::ExceptionClass;
use gdb_remote::GdbError;
use gdb_remote::GdbServer;
use gdb_remote::ProcessResult;
use gdb_remote::ResumeAction;
use gdb_remote::Target;
use gdb_remote::TargetCapabilities;
use gdb_remote::TargetError;

#[derive(Clone, Copy)]
pub struct DebugIo {
    pub try_read: fn() -> Option<u8>,
    pub try_write: fn(u8) -> bool,
    pub flush: fn(),
}

pub const TARGET_XML: &[u8] = include_bytes!("xml/target.xml");
pub const AARCH64_CORE_XML: &[u8] = include_bytes!("xml/aarch64-core.xml");
pub const AARCH64_SYSTEM_XML: &[u8] = include_bytes!("xml/aarch64-system.xml");

#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64TargetDesc;

impl Aarch64TargetDesc {
    pub const fn new() -> Self {
        Self
    }

    pub fn annex(&self, name: &str) -> Option<&'static [u8]> {
        match name {
            "target.xml" => Some(TARGET_XML),
            "aarch64-core.xml" => Some(AARCH64_CORE_XML),
            "aarch64-system.xml" => Some(AARCH64_SYSTEM_XML),
            _ => None,
        }
    }
}

pub const REG_X0: usize = 0;
pub const REG_X30: usize = 30;
pub const REG_XZR: usize = 31;
pub const REG_SP: usize = 32;
pub const REG_PC: usize = 33;
pub const REG_CPSR: usize = 34;

pub const CORE_REG_COUNT: usize = REG_CPSR + 1;
pub const EXTRA_REG_BASE: usize = CORE_REG_COUNT;

pub const REG_TPIDR_EL0: usize = EXTRA_REG_BASE + 0;
pub const REG_TPIDRRO_EL0: usize = EXTRA_REG_BASE + 1;
pub const REG_TPIDR_EL1: usize = EXTRA_REG_BASE + 2;
pub const REG_MPIDR_EL1: usize = EXTRA_REG_BASE + 3;
pub const REG_SCTLR_EL1: usize = EXTRA_REG_BASE + 4;
pub const REG_TTBR0_EL1: usize = EXTRA_REG_BASE + 5;
pub const REG_TTBR1_EL1: usize = EXTRA_REG_BASE + 6;
pub const REG_TCR_EL1: usize = EXTRA_REG_BASE + 7;
pub const REG_MAIR_EL1: usize = EXTRA_REG_BASE + 8;
pub const REG_MDSCR_EL1: usize = EXTRA_REG_BASE + 9;

pub const EXTRA_REG_COUNT: usize = 10;

pub const CORE_REG_BYTES: usize = (REG_CPSR * 8) + 4;
pub const EXTRA_REG_BYTES: usize = EXTRA_REG_COUNT * 8;
pub const G_PACKET_BYTES: usize = CORE_REG_BYTES + EXTRA_REG_BYTES;

pub const fn core_reg_offset(regnum: usize) -> Option<(usize, usize)> {
    if regnum <= REG_X30 {
        return Some((regnum * 8, 8));
    }
    if regnum == REG_XZR {
        return Some((REG_XZR * 8, 8));
    }
    if regnum == REG_SP {
        return Some((REG_SP * 8, 8));
    }
    if regnum == REG_PC {
        return Some((REG_PC * 8, 8));
    }
    if regnum == REG_CPSR {
        return Some((REG_CPSR * 8, 4));
    }
    None
}

pub const fn extra_reg_offset(index: usize) -> Option<(usize, usize)> {
    if index < EXTRA_REG_COUNT {
        return Some((CORE_REG_BYTES + (index * 8), 8));
    }
    None
}

pub const fn reg_offset(regnum: usize) -> Option<(usize, usize)> {
    if regnum <= REG_CPSR {
        return core_reg_offset(regnum);
    }
    if regnum >= EXTRA_REG_BASE {
        return extra_reg_offset(regnum - EXTRA_REG_BASE);
    }
    None
}

pub const DEFAULT_SW_BREAKPOINTS: usize = 8;
const BRK_INSN: u32 = 0xD420_0000;

pub trait MemoryAccess {
    type Error;

    fn read(&mut self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, addr: u64, src: &[u8]) -> Result<(), Self::Error>;
}

pub struct DirectMemory;

impl DirectMemory {
    pub const fn new() -> Self {
        Self
    }
}

impl MemoryAccess for DirectMemory {
    type Error = ();

    fn read(&mut self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let ptr = addr as *const u8;
        for (idx, slot) in dst.iter_mut().enumerate() {
            // SAFETY: Caller ensures the address range is readable.
            unsafe {
                *slot = core::ptr::read_volatile(ptr.add(idx));
            }
        }
        Ok(())
    }

    fn write(&mut self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let ptr = addr as *mut u8;
        for (idx, byte) in src.iter().copied().enumerate() {
            // SAFETY: Caller ensures the address range is writable.
            unsafe {
                core::ptr::write_volatile(ptr.add(idx), byte);
            }
        }
        Ok(())
    }
}

pub enum Aarch64GdbError<E> {
    Memory(E),
    InvalidRegister,
    BufferTooSmall,
    UnalignedAddress,
    BreakpointTableFull,
}

#[derive(Clone, Copy)]
struct SwBreakpoint {
    addr: u64,
    original: u32,
    used: bool,
    installed: bool,
}

impl SwBreakpoint {
    const fn empty() -> Self {
        Self {
            addr: 0,
            original: 0,
            used: false,
            installed: false,
        }
    }
}

struct SwBreakpointTable<const N: usize> {
    slots: [SwBreakpoint; N],
}

impl<const N: usize> SwBreakpointTable<N> {
    const fn new() -> Self {
        Self {
            slots: [SwBreakpoint::empty(); N],
        }
    }

    fn find(&self, addr: u64) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.used && slot.addr == addr)
    }

    fn find_free(&self) -> Option<usize> {
        self.slots.iter().position(|slot| !slot.used)
    }
}

pub struct Aarch64GdbState<M, const N: usize = DEFAULT_SW_BREAKPOINTS> {
    mem: M,
    breakpoints: SwBreakpointTable<N>,
    desc: Aarch64TargetDesc,
    features_active: bool,
}

impl<M, const N: usize> Aarch64GdbState<M, N> {
    pub fn new(mem: M) -> Self {
        Self {
            mem,
            breakpoints: SwBreakpointTable::new(),
            desc: Aarch64TargetDesc::new(),
            features_active: false,
        }
    }

    pub fn target<'a>(&'a mut self, regs: &'a mut Registers) -> Aarch64GdbTarget<'a, M, N> {
        Aarch64GdbTarget { regs, state: self }
    }
}

impl<M: MemoryAccess, const N: usize> Aarch64GdbState<M, N> {
    fn insert_sw_breakpoint(&mut self, addr: u64) -> Result<(), Aarch64GdbError<M::Error>> {
        if addr & 0x3 != 0 {
            return Err(Aarch64GdbError::UnalignedAddress);
        }
        if let Some(slot) = self.breakpoints.find(addr) {
            if self.breakpoints.slots[slot].installed {
                return Ok(());
            }
            let brk = BRK_INSN.to_le_bytes();
            self.mem
                .write(addr, &brk)
                .map_err(Aarch64GdbError::Memory)?;
            cpu::clean_dcache_poc(addr as usize, 4);
            cpu::invalidate_icache_range(addr as usize, 4);
            self.breakpoints.slots[slot].installed = true;
            return Ok(());
        }
        let Some(slot) = self.breakpoints.find_free() else {
            return Err(Aarch64GdbError::BreakpointTableFull);
        };

        let mut original = [0u8; 4];
        self.mem
            .read(addr, &mut original)
            .map_err(Aarch64GdbError::Memory)?;
        let original = u32::from_le_bytes(original);

        let brk = BRK_INSN.to_le_bytes();
        self.mem
            .write(addr, &brk)
            .map_err(Aarch64GdbError::Memory)?;
        cpu::clean_dcache_poc(addr as usize, 4);
        cpu::invalidate_icache_range(addr as usize, 4);

        self.breakpoints.slots[slot] = SwBreakpoint {
            addr,
            original,
            used: true,
            installed: true,
        };
        Ok(())
    }

    fn remove_sw_breakpoint(&mut self, addr: u64) -> Result<(), Aarch64GdbError<M::Error>> {
        let Some(slot) = self.breakpoints.find(addr) else {
            return Ok(());
        };
        if self.breakpoints.slots[slot].installed {
            let original = self.breakpoints.slots[slot].original;
            let bytes = original.to_le_bytes();
            self.mem
                .write(addr, &bytes)
                .map_err(Aarch64GdbError::Memory)?;
            cpu::clean_dcache_poc(addr as usize, 4);
            cpu::invalidate_icache_range(addr as usize, 4);
        }

        self.breakpoints.slots[slot] = SwBreakpoint::empty();
        Ok(())
    }

    fn disable_sw_breakpoint_at(
        &mut self,
        addr: u64,
    ) -> Result<Option<usize>, Aarch64GdbError<M::Error>> {
        let Some(slot) = self.breakpoints.find(addr) else {
            return Ok(None);
        };
        self.restore_sw_breakpoint_slot(slot)?;
        Ok(Some(slot))
    }

    fn restore_sw_breakpoint_slot(&mut self, slot: usize) -> Result<(), Aarch64GdbError<M::Error>> {
        let entry = &mut self.breakpoints.slots[slot];
        if !entry.used || !entry.installed {
            return Ok(());
        }
        let bytes = entry.original.to_le_bytes();
        self.mem
            .write(entry.addr, &bytes)
            .map_err(Aarch64GdbError::Memory)?;
        cpu::clean_dcache_poc(entry.addr as usize, 4);
        cpu::invalidate_icache_range(entry.addr as usize, 4);
        entry.installed = false;
        Ok(())
    }

    fn reinstall_sw_breakpoint_slot(
        &mut self,
        slot: usize,
    ) -> Result<(), Aarch64GdbError<M::Error>> {
        let entry = &mut self.breakpoints.slots[slot];
        if !entry.used || entry.installed {
            return Ok(());
        }
        let brk = BRK_INSN.to_le_bytes();
        self.mem
            .write(entry.addr, &brk)
            .map_err(Aarch64GdbError::Memory)?;
        cpu::clean_dcache_poc(entry.addr as usize, 4);
        cpu::invalidate_icache_range(entry.addr as usize, 4);
        entry.installed = true;
        Ok(())
    }
}

pub struct Aarch64GdbTarget<'a, M, const N: usize = DEFAULT_SW_BREAKPOINTS> {
    regs: &'a mut Registers,
    state: &'a mut Aarch64GdbState<M, N>,
}

impl<'a, M: MemoryAccess, const N: usize> Target for Aarch64GdbTarget<'a, M, N> {
    type RecoverableError = Aarch64GdbError<M::Error>;
    type UnrecoverableError = core::convert::Infallible;

    fn capabilities(&self) -> TargetCapabilities {
        TargetCapabilities::SW_BREAK | TargetCapabilities::VCONT | TargetCapabilities::XFER_FEATURES
    }

    fn recoverable_error_code(&self, e: &Self::RecoverableError) -> u8 {
        match e {
            Aarch64GdbError::Memory(_) | Aarch64GdbError::UnalignedAddress => 14,
            Aarch64GdbError::BreakpointTableFull => 28,
            Aarch64GdbError::InvalidRegister | Aarch64GdbError::BufferTooSmall => 22,
        }
    }

    fn xfer_features(
        &mut self,
        annex: &str,
    ) -> Result<Option<&[u8]>, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        let data = self.state.desc.annex(annex);
        if data.is_some() {
            self.state.features_active = true;
        }
        Ok(data)
    }

    fn read_registers(
        &mut self,
        dst: &mut [u8],
    ) -> Result<usize, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        let total = if self.state.features_active {
            G_PACKET_BYTES
        } else {
            CORE_REG_BYTES
        };
        if dst.len() < total {
            return Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall));
        }

        let regs = self.regs.as_array();
        let mut offset = 0usize;
        for idx in 0..=REG_X30 {
            dst[offset..offset + 8].copy_from_slice(&regs[idx].to_le_bytes());
            offset += 8;
        }
        dst[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
        offset += 8;

        let sp = cpu::get_sp_el1();
        dst[offset..offset + 8].copy_from_slice(&sp.to_le_bytes());
        offset += 8;

        let pc = cpu::get_elr_el2();
        dst[offset..offset + 8].copy_from_slice(&pc.to_le_bytes());
        offset += 8;

        let cpsr = cpu::get_spsr_el2() as u32;
        dst[offset..offset + 4].copy_from_slice(&cpsr.to_le_bytes());
        offset += 4;

        if self.state.features_active {
            write_extra_regs(dst, offset);
            Ok(G_PACKET_BYTES)
        } else {
            Ok(CORE_REG_BYTES)
        }
    }

    fn write_registers(
        &mut self,
        src: &[u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        let total = if self.state.features_active {
            G_PACKET_BYTES
        } else {
            CORE_REG_BYTES
        };
        if src.len() < total {
            return Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall));
        }
        let src = &src[..total];

        let regs = self.regs.as_array();
        let mut offset = 0usize;
        for idx in 0..=REG_X30 {
            regs[idx] = read_u64(&src[offset..offset + 8])?;
            offset += 8;
        }
        let _ = read_u64(&src[offset..offset + 8])?;
        offset += 8;

        let sp = read_u64(&src[offset..offset + 8])?;
        cpu::set_sp_el1(sp);
        offset += 8;

        let pc = read_u64(&src[offset..offset + 8])?;
        cpu::set_elr_el2(pc);
        offset += 8;

        let cpsr = read_u32(&src[offset..offset + 4])?;
        cpu::set_spsr_el2(cpsr as u64);
        offset += 4;

        if self.state.features_active {
            write_extra_regs_from(src, offset)?;
        }
        Ok(())
    }

    fn read_register(
        &mut self,
        regno: u32,
        dst: &mut [u8],
    ) -> Result<usize, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        match regno as usize {
            REG_X0..=REG_X30 => {
                let regs = self.regs.as_array();
                write_u64(dst, regs[regno as usize])
            }
            REG_XZR => write_u64(dst, 0),
            REG_SP => write_u64(dst, cpu::get_sp_el1()),
            REG_PC => write_u64(dst, cpu::get_elr_el2()),
            REG_CPSR => write_u32(dst, cpu::get_spsr_el2() as u32),
            REG_TPIDR_EL0 => write_u64(dst, cpu::get_tpidr_el0()),
            REG_TPIDRRO_EL0 => write_u64(dst, cpu::get_tpidrro_el0()),
            REG_TPIDR_EL1 => write_u64(dst, cpu::get_tpidr_el1()),
            REG_MPIDR_EL1 => write_u64(dst, cpu::get_mpidr_el1()),
            REG_SCTLR_EL1 => write_u64(dst, cpu::get_sctlr_el1()),
            REG_TTBR0_EL1 => write_u64(dst, cpu::get_ttbr0_el1()),
            REG_TTBR1_EL1 => write_u64(dst, cpu::get_ttbr1_el1()),
            REG_TCR_EL1 => write_u64(dst, cpu::get_tcr_el1()),
            REG_MAIR_EL1 => write_u64(dst, cpu::get_mair_el1()),
            REG_MDSCR_EL1 => write_u64(dst, cpu::get_mdscr_el1().bits()),
            _ => Err(TargetError::Recoverable(Aarch64GdbError::InvalidRegister)),
        }
    }

    fn write_register(
        &mut self,
        regno: u32,
        src: &[u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        match regno as usize {
            REG_X0..=REG_X30 => {
                let regs = self.regs.as_array();
                regs[regno as usize] = read_u64(src)?;
            }
            REG_XZR => {
                let _ = read_u64(src)?;
            }
            REG_SP => {
                let sp = read_u64(src)?;
                cpu::set_sp_el1(sp);
            }
            REG_PC => {
                let pc = read_u64(src)?;
                cpu::set_elr_el2(pc);
            }
            REG_CPSR => {
                let cpsr = read_u32(src)?;
                cpu::set_spsr_el2(cpsr as u64);
            }
            REG_TPIDR_EL0 => cpu::set_tpidr_el0(read_u64(src)?),
            REG_TPIDRRO_EL0 => {}
            REG_TPIDR_EL1 => cpu::set_tpidr_el1(read_u64(src)?),
            REG_MPIDR_EL1 => {}
            REG_SCTLR_EL1 => cpu::set_sctlr_el1(read_u64(src)?),
            REG_TTBR0_EL1 => cpu::set_ttbr0_el1(read_u64(src)?),
            REG_TTBR1_EL1 => cpu::set_ttbr1_el1(read_u64(src)?),
            REG_TCR_EL1 => cpu::set_tcr_el1(read_u64(src)?),
            REG_MAIR_EL1 => cpu::set_mair_el1(read_u64(src)?),
            REG_MDSCR_EL1 => {
                let mdscr = MDSCR_EL1::from_bits(read_u64(src)?);
                cpu::set_mdscr_el1(mdscr);
            }
            _ => return Err(TargetError::Recoverable(Aarch64GdbError::InvalidRegister)),
        }
        Ok(())
    }

    fn read_memory(
        &mut self,
        addr: u64,
        dst: &mut [u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .mem
            .read(addr, dst)
            .map_err(|err| TargetError::Recoverable(Aarch64GdbError::Memory(err)))
    }

    fn write_memory(
        &mut self,
        addr: u64,
        src: &[u8],
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .mem
            .write(addr, src)
            .map_err(|err| TargetError::Recoverable(Aarch64GdbError::Memory(err)))
    }

    fn insert_sw_breakpoint(
        &mut self,
        addr: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .insert_sw_breakpoint(addr)
            .map_err(TargetError::Recoverable)
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .remove_sw_breakpoint(addr)
            .map_err(TargetError::Recoverable)
    }
}

pub trait DebugStub {
    fn enter_debug(&mut self, regs: &mut Registers, cause: DebugEntryCause);
}

#[derive(Clone, Copy, Debug)]
pub enum DebugEntryCause {
    DebugException(ExceptionClass),
    AttachDollar,
    CtrlC,
}

#[derive(Clone, Copy)]
struct DebugStubPtr(*mut dyn DebugStub);

// SAFETY: The global debug stub pointer is registered once and only accessed
// through this module's serialized exception path.
unsafe impl Send for DebugStubPtr {}
unsafe impl Sync for DebugStubPtr {}

static DEBUG_STUB: RawSpinLockIrqSave<Option<DebugStubPtr>> = RawSpinLockIrqSave::new(None);
static DEBUG_IO: RawSpinLockIrqSave<Option<DebugIo>> = RawSpinLockIrqSave::new(None);

pub fn register_debug_stub(stub: &'static mut dyn DebugStub) {
    let ptr: *mut dyn DebugStub = stub;
    let mut guard = DEBUG_STUB.lock_irqsave();
    *guard = Some(DebugStubPtr(ptr));
}

pub fn register_debug_io(io: DebugIo) {
    let mut guard = DEBUG_IO.lock_irqsave();
    *guard = Some(io);
}

fn debug_io() -> Option<DebugIo> {
    let guard = DEBUG_IO.lock_irqsave();
    *guard
}

pub fn debug_entry(regs: &mut Registers, cause: DebugEntryCause) {
    let stub = {
        let guard = DEBUG_STUB.lock_irqsave();
        *guard
    };
    let Some(stub) = stub else {
        return;
    };
    // SAFETY: pointer originates from a registered &mut DebugStub.
    unsafe { &mut *stub.0 }.enter_debug(regs, cause);
}

pub fn debug_exception_entry(regs: &mut Registers, ec: ExceptionClass) {
    debug_entry(regs, DebugEntryCause::DebugException(ec));
}

#[derive(Clone, Copy, Debug)]
enum PendingStepAction {
    Continue,
    Step,
}

#[derive(Clone, Copy, Debug)]
struct StepRestore {
    spsr_d: bool,
    spsr_ss: bool,
    mdscr_ss: bool,
    mdscr_kde: bool,
    mdscr_mde: bool,
}

#[derive(Clone, Copy, Debug)]
struct PendingStep {
    slot: Option<usize>,
    action: PendingStepAction,
    restore: Option<StepRestore>,
}

pub struct Aarch64GdbStub<
    M,
    const MAX_PKT: usize = 2048,
    const TX_CAP: usize = 4096,
    const N: usize = DEFAULT_SW_BREAKPOINTS,
> {
    server: GdbServer<MAX_PKT, TX_CAP>,
    state: Aarch64GdbState<M, N>,
    pending_step: Option<PendingStep>,
}

impl<M: MemoryAccess, const MAX_PKT: usize, const TX_CAP: usize, const N: usize>
    Aarch64GdbStub<M, MAX_PKT, TX_CAP, N>
{
    pub fn new(mem: M) -> Self {
        Self {
            server: GdbServer::new(),
            state: Aarch64GdbState::new(mem),
            pending_step: None,
        }
    }

    pub fn enter_debug(&mut self, regs: &mut Registers, cause: DebugEntryCause) {
        let ec = match cause {
            DebugEntryCause::DebugException(ec) => Some(ec),
            _ => None,
        };
        if self.handle_pending_step(ec) {
            return;
        }
        let Some(io) = debug_io() else {
            return;
        };

        let mut breakpoint_slot = None;
        let mut breakpoint_addr = 0u64;
        if let DebugEntryCause::DebugException(ExceptionClass::BreakpointLowerLevel) = cause {
            let pc = cpu::get_elr_el2();
            if let Ok(Some(slot)) = self.state.disable_sw_breakpoint_at(pc) {
                breakpoint_slot = Some(slot);
                breakpoint_addr = pc;
            } else {
                let pc_prev = pc.wrapping_sub(4);
                if let Ok(Some(slot)) = self.state.disable_sw_breakpoint_at(pc_prev) {
                    breakpoint_slot = Some(slot);
                    breakpoint_addr = pc_prev;
                    cpu::set_elr_el2(pc_prev);
                }
            }
        }

        let mut tx_hold = None;
        let action = 'debug: loop {
            let mut target = self.state.target(regs);
            let mut progress = false;

            if let Some(byte) = tx_hold {
                if (io.try_write)(byte) {
                    tx_hold = None;
                    progress = true;
                }
            }

            while tx_hold.is_none() {
                let Some(byte) = self.server.pop_tx_byte_irq() else {
                    break;
                };
                if (io.try_write)(byte) {
                    progress = true;
                } else {
                    tx_hold = Some(byte);
                    break;
                }
            }

            loop {
                match (io.try_read)() {
                    Some(byte) => {
                        progress = true;
                        match self.server.on_rx_byte_irq(&mut target, byte) {
                            Ok(ProcessResult::Resume(action)) => break 'debug action,
                            Ok(ProcessResult::MonitorExit) => return,
                            Ok(ProcessResult::None) => {}
                            Err(GdbError::MalformedPacket | GdbError::PacketTooLong) => {
                                self.server.resync();
                            }
                            Err(_) => return,
                        }
                    }
                    None => break,
                }
            }

            if progress {
                (io.flush)();
            } else {
                spin_loop();
            }
        };

        let (resume_action, new_pc) = match action {
            ResumeAction::Continue(pc) => (PendingStepAction::Continue, pc),
            ResumeAction::Step(pc) => (PendingStepAction::Step, pc),
        };

        if let Some(pc) = new_pc {
            cpu::set_elr_el2(pc);
        }

        if let Some(slot) = breakpoint_slot {
            let pc = cpu::get_elr_el2();
            if pc == breakpoint_addr {
                self.pending_step = Some(PendingStep {
                    slot: Some(slot),
                    action: resume_action,
                    restore: enable_single_step(),
                });
                return;
            }
            let _ = self.state.reinstall_sw_breakpoint_slot(slot);
        }

        if matches!(resume_action, PendingStepAction::Step) {
            if let Some(restore) = enable_single_step() {
                self.pending_step = Some(PendingStep {
                    slot: None,
                    action: resume_action,
                    restore: Some(restore),
                });
            }
        }
    }

    pub fn handle_debug_exception(&mut self, regs: &mut Registers, ec: ExceptionClass) {
        self.enter_debug(regs, DebugEntryCause::DebugException(ec));
    }

    fn handle_pending_step(&mut self, ec: Option<ExceptionClass>) -> bool {
        if let Some(pending) = self.pending_step.take() {
            if let Some(restore) = pending.restore {
                disable_single_step(restore);
            }
            if let Some(slot) = pending.slot {
                let _ = self.state.reinstall_sw_breakpoint_slot(slot);
            }
            if matches!(pending.action, PendingStepAction::Continue)
                && matches!(ec, Some(ExceptionClass::SoftwareStepLowerLevel))
            {
                return true;
            }
        }
        false
    }
}

impl<M: MemoryAccess, const MAX_PKT: usize, const TX_CAP: usize, const N: usize> DebugStub
    for Aarch64GdbStub<M, MAX_PKT, TX_CAP, N>
{
    fn enter_debug(&mut self, regs: &mut Registers, cause: DebugEntryCause) {
        Aarch64GdbStub::enter_debug(self, regs, cause);
    }
}

const SPSR_DAIF_D: u64 = 1 << 9;
const SPSR_SS: u64 = 1 << 21;

fn enable_single_step() -> Option<StepRestore> {
    let spsr = cpu::get_spsr_el2();
    let mdscr = cpu::get_mdscr_el1();
    let restore = StepRestore {
        spsr_d: (spsr & SPSR_DAIF_D) != 0,
        spsr_ss: (spsr & SPSR_SS) != 0,
        mdscr_ss: mdscr.get(MDSCR_EL1::ss) != 0,
        mdscr_kde: mdscr.get(MDSCR_EL1::kde) != 0,
        mdscr_mde: mdscr.get(MDSCR_EL1::mde) != 0,
    };

    let new_spsr = (spsr & !SPSR_DAIF_D) | SPSR_SS;
    let new_mdscr = mdscr
        .set(MDSCR_EL1::ss, 1)
        .set(MDSCR_EL1::kde, 1)
        .set(MDSCR_EL1::mde, 1);

    cpu::set_spsr_el2(new_spsr);
    cpu::set_mdscr_el1(new_mdscr);

    let verify_spsr = cpu::get_spsr_el2();
    let verify_mdscr = cpu::get_mdscr_el1();
    let spsr_ok = (verify_spsr & SPSR_DAIF_D) == 0 && (verify_spsr & SPSR_SS) != 0;
    let mdscr_ok = verify_mdscr.get(MDSCR_EL1::ss) != 0
        && verify_mdscr.get(MDSCR_EL1::kde) != 0
        && verify_mdscr.get(MDSCR_EL1::mde) != 0;
    if !(spsr_ok && mdscr_ok) {
        disable_single_step(restore);
        return None;
    }
    Some(restore)
}

fn disable_single_step(restore: StepRestore) {
    let mut spsr = cpu::get_spsr_el2();
    if restore.spsr_d {
        spsr |= SPSR_DAIF_D;
    } else {
        spsr &= !SPSR_DAIF_D;
    }
    if restore.spsr_ss {
        spsr |= SPSR_SS;
    } else {
        spsr &= !SPSR_SS;
    }
    cpu::set_spsr_el2(spsr);

    let mdscr = cpu::get_mdscr_el1()
        .set(MDSCR_EL1::ss, restore.mdscr_ss as u64)
        .set(MDSCR_EL1::kde, restore.mdscr_kde as u64)
        .set(MDSCR_EL1::mde, restore.mdscr_mde as u64);
    cpu::set_mdscr_el1(mdscr);
}

fn read_u64<E>(
    src: &[u8],
) -> Result<u64, TargetError<Aarch64GdbError<E>, core::convert::Infallible>> {
    if src.len() < 8 {
        return Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&src[..8]);
    Ok(u64::from_le_bytes(buf))
}

fn read_u32<E>(
    src: &[u8],
) -> Result<u32, TargetError<Aarch64GdbError<E>, core::convert::Infallible>> {
    if src.len() < 4 {
        return Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&src[..4]);
    Ok(u32::from_le_bytes(buf))
}

fn write_u64<E>(
    dst: &mut [u8],
    val: u64,
) -> Result<usize, TargetError<Aarch64GdbError<E>, core::convert::Infallible>> {
    if dst.len() < 8 {
        return Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall));
    }
    dst[..8].copy_from_slice(&val.to_le_bytes());
    Ok(8)
}

fn write_u32<E>(
    dst: &mut [u8],
    val: u32,
) -> Result<usize, TargetError<Aarch64GdbError<E>, core::convert::Infallible>> {
    if dst.len() < 4 {
        return Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall));
    }
    dst[..4].copy_from_slice(&val.to_le_bytes());
    Ok(4)
}

fn write_extra_regs(dst: &mut [u8], offset: usize) {
    let mut off = offset;
    let regs = [
        cpu::get_tpidr_el0(),
        cpu::get_tpidrro_el0(),
        cpu::get_tpidr_el1(),
        cpu::get_mpidr_el1(),
        cpu::get_sctlr_el1(),
        cpu::get_ttbr0_el1(),
        cpu::get_ttbr1_el1(),
        cpu::get_tcr_el1(),
        cpu::get_mair_el1(),
        cpu::get_mdscr_el1().bits(),
    ];

    for value in regs {
        dst[off..off + 8].copy_from_slice(&value.to_le_bytes());
        off += 8;
    }
}

fn write_extra_regs_from<E>(
    src: &[u8],
    offset: usize,
) -> Result<(), TargetError<Aarch64GdbError<E>, core::convert::Infallible>> {
    let mut off = offset;
    cpu::set_tpidr_el0(read_u64(&src[off..off + 8])?);
    off += 8;
    off += 8; // tpidrro_el0 (read-only)
    cpu::set_tpidr_el1(read_u64(&src[off..off + 8])?);
    off += 8;
    off += 8; // mpidr_el1 (read-only)
    cpu::set_sctlr_el1(read_u64(&src[off..off + 8])?);
    off += 8;
    cpu::set_ttbr0_el1(read_u64(&src[off..off + 8])?);
    off += 8;
    cpu::set_ttbr1_el1(read_u64(&src[off..off + 8])?);
    off += 8;
    cpu::set_tcr_el1(read_u64(&src[off..off + 8])?);
    off += 8;
    cpu::set_mair_el1(read_u64(&src[off..off + 8])?);
    off += 8;
    let mdscr = MDSCR_EL1::from_bits(read_u64(&src[off..off + 8])?);
    cpu::set_mdscr_el1(mdscr);
    Ok(())
}
