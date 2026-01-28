#![no_std]

use aarch64_mutex::RawSpinLockIrqSave;
use core::hint::spin_loop;
use cpu::Registers;
use cpu::registers::DBGWCR_EL1;
use cpu::registers::DBGWVR_EL1;
use cpu::registers::MDSCR_EL1;
use exceptions::registers::ExceptionClass;
use gdb_remote::GdbError;
use gdb_remote::GdbServer;
use gdb_remote::ProcessResult;
use gdb_remote::ResumeAction;
use gdb_remote::Target;
use gdb_remote::TargetCapabilities;
use gdb_remote::TargetError;
pub use gdb_remote::WatchpointKind;

#[derive(Clone, Copy)]
pub struct DebugIo {
    pub try_read: fn() -> Option<u8>,
    pub try_write: fn(u8) -> bool,
    pub flush: fn(),
}

pub type MonitorHandler = fn(cmd: &[u8], out: &mut [u8]) -> Option<usize>;

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
pub const DEFAULT_HW_BREAKPOINTS: usize = 8;
const BRK_INSN: u32 = 0xD420_0000;
const DBGBCR_E: u64 = 1 << 0;
const DBGBCR_PMC_SHIFT: u64 = 1;
const DBGBCR_BAS_SHIFT: u64 = 5;
const DBGBCR_PMC_EL0_EL1: u64 = 0b11 << DBGBCR_PMC_SHIFT;
const DBGBCR_BAS_ALL: u64 = 0b1111 << DBGBCR_BAS_SHIFT;
const DBGBCR_INSN: u64 = DBGBCR_E | DBGBCR_PMC_EL0_EL1 | DBGBCR_BAS_ALL;

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
    HwBreakpointSlotsExhausted,
    InvalidBreakpointKind,
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

#[derive(Clone, Copy)]
struct HwBreakpoint {
    addr: u64,
    hw_index: usize,
    used: bool,
}

impl HwBreakpoint {
    const fn empty() -> Self {
        Self {
            addr: 0,
            hw_index: 0,
            used: false,
        }
    }
}

struct HwBreakpointTable<const N: usize> {
    slots: [HwBreakpoint; N],
}

impl<const N: usize> HwBreakpointTable<N> {
    const fn new() -> Self {
        Self {
            slots: [HwBreakpoint::empty(); N],
        }
    }

    fn find(&self, addr: u64) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.used && slot.addr == addr)
    }

    fn find_free(&self, limit: usize) -> Option<usize> {
        self.slots.iter().take(limit).position(|slot| !slot.used)
    }
}

#[derive(Clone, Copy)]
struct HwWatchpoint {
    used: bool,
    installed: bool,
    req_addr: u64,
    req_len: u8,
    req_kind: WatchpointKind,
    seg_base: u64,
    seg_bas: u8,
    slot: usize,
}

impl HwWatchpoint {
    const fn empty() -> Self {
        Self {
            used: false,
            installed: false,
            req_addr: 0,
            req_len: 0,
            req_kind: WatchpointKind::Write,
            seg_base: 0,
            seg_bas: 0,
            slot: 0,
        }
    }
}

struct HwWatchpointTable<const N: usize> {
    slots: [HwWatchpoint; N],
}

impl<const N: usize> HwWatchpointTable<N> {
    const fn new() -> Self {
        Self {
            slots: [HwWatchpoint::empty(); N],
        }
    }

    fn find_segment(
        &self,
        req_addr: u64,
        req_len: u8,
        req_kind: WatchpointKind,
        seg_base: u64,
        seg_bas: u8,
    ) -> Option<usize> {
        for (i, e) in self.slots.iter().enumerate() {
            if e.used
                && e.req_addr == req_addr
                && e.req_len == req_len
                && e.req_kind == req_kind
                && e.seg_base == seg_base
                && e.seg_bas == seg_bas
            {
                return Some(i);
            }
        }
        None
    }

    fn alloc(&mut self) -> Option<usize> {
        for (i, e) in self.slots.iter().enumerate() {
            if !e.used {
                return Some(i);
            }
        }
        None
    }
}

fn bas_is_contiguous(bas: u8) -> bool {
    if bas == 0 {
        return false;
    }
    let lsb = bas.trailing_zeros();
    let shifted = (bas >> lsb) as u16;
    (shifted & (shifted + 1)) == 0
}

fn encode_bwcr(kind: WatchpointKind, bas: u8) -> DBGWCR_EL1 {
    debug_assert!(bas != 0, "BAS must be non-zero");
    debug_assert!(bas_is_contiguous(bas), "BAS must be contiguous");
    let lsc = match kind {
        WatchpointKind::Read => 0b01,
        WatchpointKind::Write => 0b10,
        WatchpointKind::Access => 0b11,
    };
    DBGWCR_EL1::from_bits(0)
        .set(DBGWCR_EL1::e, 1)
        .set(DBGWCR_EL1::pac, 0b11)
        .set(DBGWCR_EL1::lsc, lsc as u64)
        .set(DBGWCR_EL1::bas, bas as u64)
        .set(DBGWCR_EL1::ssc, 0)
        // Do not match EL2: the debugger runs at EL2 and can trip its own watchpoints
        // during m/M packets, wedging the stop loop. Watchpoints should trap the guest.
        .set(DBGWCR_EL1::hmc, 0)
}

fn encode_bwcr_disabled(kind: WatchpointKind, bas: u8) -> DBGWCR_EL1 {
    encode_bwcr(kind, bas).set(DBGWCR_EL1::e, 0)
}

#[derive(Clone, Copy)]
struct MdscrRestore {
    kde: bool,
    mde: bool,
}

pub struct Aarch64GdbState<M, const N: usize = DEFAULT_SW_BREAKPOINTS> {
    mem: M,
    breakpoints: SwBreakpointTable<N>,
    hw_breakpoints: HwBreakpointTable<DEFAULT_HW_BREAKPOINTS>,
    hw_watchpoints: HwWatchpointTable<DEFAULT_HW_BREAKPOINTS>,
    watchpoints_suspended: bool,
    hw_breakpoints_active: usize,
    hw_mdscr_restore: Option<MdscrRestore>,
    desc: Aarch64TargetDesc,
    features_active: bool,
    memory_map: Option<&'static [u8]>,
    monitor_handler: Option<MonitorHandler>,
}

impl<M, const N: usize> Aarch64GdbState<M, N> {
    pub fn new(mem: M) -> Self {
        let mut state = Self {
            mem,
            breakpoints: SwBreakpointTable::new(),
            hw_breakpoints: HwBreakpointTable::new(),
            hw_watchpoints: HwWatchpointTable::new(),
            watchpoints_suspended: false,
            hw_breakpoints_active: 0,
            hw_mdscr_restore: None,
            desc: Aarch64TargetDesc::new(),
            features_active: false,
            memory_map: None,
            monitor_handler: None,
        };

        let wp_slots = core::cmp::min(cpu::watchpoint_count(), DEFAULT_HW_BREAKPOINTS);
        for i in 0..wp_slots {
            let _ = cpu::set_dbgwcr_el1(i, DBGWCR_EL1::from_bits(0));
            let _ = cpu::set_dbgwvr_el1(i, DBGWVR_EL1::from_bits(0));
        }

        state
    }

    pub fn target<'a>(&'a mut self, regs: &'a mut Registers) -> Aarch64GdbTarget<'a, M, N> {
        Aarch64GdbTarget { regs, state: self }
    }

    pub fn set_memory_map(&mut self, data: Option<&'static [u8]>) {
        self.memory_map = data;
    }

    pub fn set_monitor_handler(&mut self, handler: Option<MonitorHandler>) {
        self.monitor_handler = handler;
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

    fn hw_breakpoint_limit(&self) -> usize {
        let available = cpu::breakpoint_count();
        if available < DEFAULT_HW_BREAKPOINTS {
            available
        } else {
            DEFAULT_HW_BREAKPOINTS
        }
    }

    fn validate_hw_breakpoint_kind(&self, kind: u64) -> Result<(), Aarch64GdbError<M::Error>> {
        if matches!(kind, 0 | 2 | 4) {
            Ok(())
        } else {
            Err(Aarch64GdbError::InvalidBreakpointKind)
        }
    }

    fn enable_hw_breakpoints(&mut self) {
        if self.hw_breakpoints_active != 0 {
            return;
        }
        let mdscr = cpu::get_mdscr_el1();
        self.hw_mdscr_restore = Some(MdscrRestore {
            kde: mdscr.get(MDSCR_EL1::kde) != 0,
            mde: mdscr.get(MDSCR_EL1::mde) != 0,
        });
        let mdscr = mdscr.set(MDSCR_EL1::kde, 1).set(MDSCR_EL1::mde, 1);
        cpu::set_mdscr_el1(mdscr);
    }

    fn restore_hw_breakpoints(&mut self) {
        if self.hw_breakpoints_active != 0 {
            return;
        }
        if let Some(restore) = self.hw_mdscr_restore.take() {
            let mdscr = cpu::get_mdscr_el1()
                .set(MDSCR_EL1::kde, restore.kde as u64)
                .set(MDSCR_EL1::mde, restore.mde as u64);
            cpu::set_mdscr_el1(mdscr);
        }
    }

    fn suspend_hw_watchpoints(&mut self) {
        if self.watchpoints_suspended {
            return;
        }
        for entry in self.hw_watchpoints.slots.iter() {
            if !entry.used || !entry.installed {
                continue;
            }
            let wcr = encode_bwcr_disabled(entry.req_kind, entry.seg_bas);
            let _ = cpu::set_dbgwcr_el1(entry.slot, wcr);
        }
        cpu::isb();
        self.watchpoints_suspended = true;
    }

    fn resume_hw_watchpoints(&mut self) {
        if !self.watchpoints_suspended {
            return;
        }
        for entry in self.hw_watchpoints.slots.iter() {
            if !entry.used || !entry.installed {
                continue;
            }
            let _ = cpu::set_dbgwvr_el1(entry.slot, DBGWVR_EL1::from_bits(entry.seg_base));
            let _ = cpu::set_dbgwcr_el1(entry.slot, encode_bwcr(entry.req_kind, entry.seg_bas));
        }
        cpu::isb();
        self.watchpoints_suspended = false;
    }

    fn insert_hw_breakpoint(
        &mut self,
        addr: u64,
        kind: u64,
    ) -> Result<(), Aarch64GdbError<M::Error>> {
        if addr & 0x3 != 0 {
            return Err(Aarch64GdbError::UnalignedAddress);
        }
        self.validate_hw_breakpoint_kind(kind)?;
        if let Some(_) = self.hw_breakpoints.find(addr) {
            return Ok(());
        }

        let limit = self.hw_breakpoint_limit();
        let Some(slot) = self.hw_breakpoints.find_free(limit) else {
            return Err(Aarch64GdbError::BreakpointTableFull);
        };

        self.enable_hw_breakpoints();

        cpu::set_dbgbvr_el1(slot, addr).map_err(|_| Aarch64GdbError::BreakpointTableFull)?;
        cpu::set_dbgbcr_el1(slot, DBGBCR_INSN).map_err(|_| Aarch64GdbError::BreakpointTableFull)?;

        self.hw_breakpoints.slots[slot] = HwBreakpoint {
            addr,
            hw_index: slot,
            used: true,
        };
        self.hw_breakpoints_active += 1;
        Ok(())
    }

    fn rollback_watchpoint_segments(
        &mut self,
        installed: &[Option<usize>; DEFAULT_HW_BREAKPOINTS],
        installed_n: usize,
    ) {
        for i in 0..installed_n {
            if let Some(es) = installed[i] {
                let e = self.hw_watchpoints.slots[es];
                let _ = cpu::set_dbgwcr_el1(e.slot, DBGWCR_EL1::from_bits(0));
                let _ = cpu::set_dbgwvr_el1(e.slot, DBGWVR_EL1::from_bits(0));
                self.hw_watchpoints.slots[es] = HwWatchpoint::empty();
            }
        }
        self.hw_breakpoints_active = self.hw_breakpoints_active.saturating_sub(installed_n);
        self.restore_hw_breakpoints();
    }

    fn insert_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchpointKind,
    ) -> Result<(), Aarch64GdbError<M::Error>> {
        if len == 0 || len > 8 {
            return Err(Aarch64GdbError::UnalignedAddress);
        }
        let len_u8 = len as u8;

        let mut seg_addr = addr;
        let mut remaining = len_u8;

        let mut installed: [Option<usize>; DEFAULT_HW_BREAKPOINTS] = [None; DEFAULT_HW_BREAKPOINTS];
        let mut installed_n = 0usize;

        while remaining != 0 {
            let off = (seg_addr & 0x7) as u8;
            let chunk = core::cmp::min(remaining, 8 - off);

            let base = seg_addr & !0x7;
            let bas = (((1u16 << chunk) - 1) << off) as u8;

            if self
                .hw_watchpoints
                .find_segment(addr, len_u8, kind, base, bas)
                .is_some()
            {
                seg_addr = seg_addr.wrapping_add(chunk as u64);
                remaining -= chunk;
                continue;
            }

            let Some(entry_slot) = self.hw_watchpoints.alloc() else {
                self.rollback_watchpoint_segments(&installed, installed_n);
                return Err(Aarch64GdbError::HwBreakpointSlotsExhausted);
            };

            let hw_slots = core::cmp::min(cpu::watchpoint_count(), DEFAULT_HW_BREAKPOINTS);
            let mut hw_index = None;
            'hw: for i in 0..hw_slots {
                let mut used = false;
                for e in self.hw_watchpoints.slots.iter() {
                    if e.used && e.slot == i {
                        used = true;
                        break;
                    }
                }
                if !used {
                    hw_index = Some(i);
                    break 'hw;
                }
            }
            let Some(hw_index) = hw_index else {
                self.rollback_watchpoint_segments(&installed, installed_n);
                return Err(Aarch64GdbError::HwBreakpointSlotsExhausted);
            };

            self.enable_hw_breakpoints();
            self.hw_breakpoints_active += 1;

            cpu::set_dbgwcr_el1(hw_index, DBGWCR_EL1::from_bits(0))
                .map_err(|_| Aarch64GdbError::HwBreakpointSlotsExhausted)?;
            cpu::set_dbgwvr_el1(hw_index, DBGWVR_EL1::from_bits(base))
                .map_err(|_| Aarch64GdbError::HwBreakpointSlotsExhausted)?;
            let wcr = if self.watchpoints_suspended {
                encode_bwcr_disabled(kind, bas)
            } else {
                encode_bwcr(kind, bas)
            };
            cpu::set_dbgwcr_el1(hw_index, wcr)
                .map_err(|_| Aarch64GdbError::HwBreakpointSlotsExhausted)?;

            self.hw_watchpoints.slots[entry_slot] = HwWatchpoint {
                used: true,
                installed: true,
                req_addr: addr,
                req_len: len_u8,
                req_kind: kind,
                seg_base: base,
                seg_bas: bas,
                slot: hw_index,
            };
            installed[installed_n] = Some(entry_slot);
            installed_n += 1;

            seg_addr = seg_addr.wrapping_add(chunk as u64);
            remaining -= chunk;
        }

        Ok(())
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: u64,
        kind: u64,
    ) -> Result<(), Aarch64GdbError<M::Error>> {
        if addr & 0x3 != 0 {
            return Err(Aarch64GdbError::UnalignedAddress);
        }
        self.validate_hw_breakpoint_kind(kind)?;
        let Some(slot) = self.hw_breakpoints.find(addr) else {
            return Ok(());
        };

        let hw_index = self.hw_breakpoints.slots[slot].hw_index;
        cpu::set_dbgbcr_el1(hw_index, 0).map_err(|_| Aarch64GdbError::BreakpointTableFull)?;
        cpu::set_dbgbvr_el1(hw_index, 0).map_err(|_| Aarch64GdbError::BreakpointTableFull)?;

        self.hw_breakpoints.slots[slot] = HwBreakpoint::empty();
        if self.hw_breakpoints_active > 0 {
            self.hw_breakpoints_active -= 1;
        }
        self.restore_hw_breakpoints();
        Ok(())
    }

    fn remove_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchpointKind,
    ) -> Result<(), Aarch64GdbError<M::Error>> {
        if len == 0 || len > 8 {
            return Ok(());
        }
        let len_u8 = len as u8;

        let mut seg_addr = addr;
        let mut remaining = len_u8;

        while remaining != 0 {
            let off = (seg_addr & 0x7) as u8;
            let chunk = core::cmp::min(remaining, 8 - off);

            let base = seg_addr & !0x7;
            let bas = (((1u16 << chunk) - 1) << off) as u8;

            if let Some(es) = self
                .hw_watchpoints
                .find_segment(addr, len_u8, kind, base, bas)
            {
                let e = self.hw_watchpoints.slots[es];
                if e.installed {
                    let _ = cpu::set_dbgwcr_el1(e.slot, DBGWCR_EL1::from_bits(0));
                    let _ = cpu::set_dbgwvr_el1(e.slot, DBGWVR_EL1::from_bits(0));
                    self.hw_watchpoints.slots[es] = HwWatchpoint::empty();

                    if self.hw_breakpoints_active > 0 {
                        self.hw_breakpoints_active -= 1;
                    }
                    self.restore_hw_breakpoints();
                }
            }

            seg_addr = seg_addr.wrapping_add(chunk as u64);
            remaining -= chunk;
        }

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
        let mut caps = TargetCapabilities::SW_BREAK
            | TargetCapabilities::HW_BREAK
            | TargetCapabilities::WATCH_W
            | TargetCapabilities::WATCH_R
            | TargetCapabilities::WATCH_A
            | TargetCapabilities::VCONT
            | TargetCapabilities::XFER_FEATURES;
        if self.state.memory_map.is_some() {
            caps |= TargetCapabilities::XFER_MEMORY_MAP;
        }
        caps
    }

    fn recoverable_error_code(&self, e: &Self::RecoverableError) -> u8 {
        match e {
            Aarch64GdbError::Memory(_) | Aarch64GdbError::UnalignedAddress => 14,
            Aarch64GdbError::BreakpointTableFull | Aarch64GdbError::HwBreakpointSlotsExhausted => {
                28
            }
            Aarch64GdbError::InvalidRegister
            | Aarch64GdbError::BufferTooSmall
            | Aarch64GdbError::InvalidBreakpointKind => 22,
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

    fn xfer_memory_map(
        &mut self,
    ) -> Result<Option<&[u8]>, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        Ok(self.state.memory_map)
    }

    fn monitor_command(
        &mut self,
        cmd: &[u8],
        out: &mut [u8],
    ) -> Result<usize, TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        let Some(handler) = self.state.monitor_handler else {
            return Err(TargetError::NotSupported);
        };
        match handler(cmd, out) {
            Some(len) => {
                if len > out.len() {
                    Err(TargetError::Recoverable(Aarch64GdbError::BufferTooSmall))
                } else {
                    Ok(len)
                }
            }
            None => Err(TargetError::NotSupported),
        }
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

        let regs = self.regs.gprs_mut();
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

        let regs = self.regs.gprs_mut();
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
                let regs = self.regs.gprs_mut();
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
                let regs = self.regs.gprs_mut();
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

    fn insert_hw_breakpoint(
        &mut self,
        addr: u64,
        kind: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .insert_hw_breakpoint(addr, kind)
            .map_err(TargetError::Recoverable)
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: u64,
        kind: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .remove_hw_breakpoint(addr, kind)
            .map_err(TargetError::Recoverable)
    }

    fn insert_watchpoint(
        &mut self,
        kind: WatchpointKind,
        addr: u64,
        len: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .insert_watchpoint(addr, len, kind)
            .map_err(TargetError::Recoverable)
    }

    fn remove_watchpoint(
        &mut self,
        kind: WatchpointKind,
        addr: u64,
        len: u64,
    ) -> Result<(), TargetError<Self::RecoverableError, Self::UnrecoverableError>> {
        self.state
            .remove_watchpoint(addr, len, kind)
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
    Watchpoint { kind: WatchpointKind, addr: u64 },
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

pub fn debug_watchpoint_entry(regs: &mut Registers, kind: WatchpointKind, addr: u64) {
    debug_entry(regs, DebugEntryCause::Watchpoint { kind, addr });
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

    /// Initialize an uninitialized slot in-place.
    ///
    /// This avoids constructing `GdbServer` on the stack (which contains large fixed buffers),
    /// preventing stack-smash / stack-overflow in very small stack configurations.
    pub fn init_in_place(dst: &mut core::mem::MaybeUninit<Self>, mem: M) {
        Self::init_in_place_with_packet_size(dst, mem, MAX_PKT);
    }

    pub fn init_in_place_with_packet_size(
        dst: &mut core::mem::MaybeUninit<Self>,
        mem: M,
        packet_size: usize,
    ) {
        // SAFETY: caller provides an uninitialized slot which we fully initialize here.
        unsafe {
            let p = dst.as_mut_ptr();
            // Zero everything first so Options are `None` and rings start empty.
            core::ptr::write_bytes(p, 0u8, 1);

            // Initialize embedded GdbServer in-place (no large stack temporaries).
            let server_slot: &mut core::mem::MaybeUninit<GdbServer<MAX_PKT, TX_CAP>> =
                &mut *(core::ptr::addr_of_mut!((*p).server) as *mut _
                    as *mut core::mem::MaybeUninit<_>);
            GdbServer::<MAX_PKT, TX_CAP>::init_in_place_with_packet_size(server_slot, packet_size);

            core::ptr::addr_of_mut!((*p).state).write(Aarch64GdbState::new(mem));
            core::ptr::addr_of_mut!((*p).pending_step).write(None);
        }
    }

    pub fn set_memory_map(&mut self, data: Option<&'static [u8]>) {
        self.state.set_memory_map(data);
    }

    pub fn set_monitor_handler(&mut self, handler: Option<MonitorHandler>) {
        self.state.set_monitor_handler(handler);
    }

    pub fn enter_debug(&mut self, regs: &mut Registers, cause: DebugEntryCause) {
        if let DebugEntryCause::DebugException(ec) = cause {
            if self.handle_pending_step(Some(ec)) {
                return;
            }
        } else {
            self.handle_pending_step(None);
        }
        let Some(io) = debug_io() else {
            return;
        };
        self.state.suspend_hw_watchpoints();

        enum DebugOutcome {
            Resume(ResumeAction),
            Exit,
        }

        #[derive(Clone, Copy)]
        enum StopReply {
            Sigtrap,
            Watchpoint { kind: WatchpointKind, addr: u64 },
        }

        let mut breakpoint_slot = None;
        let mut breakpoint_addr = 0u64;
        if let DebugEntryCause::DebugException(ec) = cause {
            if matches!(
                ec,
                ExceptionClass::BreakpointLowerLevel
                    | ExceptionClass::BrkInstructionAArch64LowerLevel
            ) {
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
        }

        let mut pending_stop_reply = match cause {
            DebugEntryCause::DebugException(_) => Some(StopReply::Sigtrap),
            DebugEntryCause::Watchpoint { kind, addr } => {
                Some(StopReply::Watchpoint { kind, addr })
            }
            _ => None,
        };
        let mut tx_hold = None;
        let outcome = 'debug: loop {
            let mut target = self.state.target(regs);
            let mut progress = false;

            if let Some(reply) = pending_stop_reply {
                let send_result = match reply {
                    StopReply::Sigtrap => self.server.notify_stop_sigtrap(),
                    StopReply::Watchpoint { kind, addr } => {
                        self.server.notify_stop_watch(kind, addr)
                    }
                };
                match send_result {
                    Ok(()) => {
                        pending_stop_reply = None;
                        progress = true;
                    }
                    Err(GdbError::TxOverflow) => {}
                    Err(_) => break 'debug DebugOutcome::Exit,
                }
            }

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
                            Ok(ProcessResult::Resume(action)) => {
                                break 'debug DebugOutcome::Resume(action);
                            }
                            Ok(ProcessResult::MonitorExit) => break 'debug DebugOutcome::Exit,
                            Ok(ProcessResult::None) => {}
                            Err(GdbError::MalformedPacket | GdbError::PacketTooLong) => {
                                self.server.resync();
                            }
                            Err(_) => break 'debug DebugOutcome::Exit,
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

        let (resume_action, new_pc) = match outcome {
            DebugOutcome::Resume(action) => match action {
                ResumeAction::Continue(pc) => (PendingStepAction::Continue, pc),
                ResumeAction::Step(pc) => (PendingStepAction::Step, pc),
            },
            DebugOutcome::Exit => {
                self.state.resume_hw_watchpoints();
                return;
            }
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
                self.state.resume_hw_watchpoints();
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
        self.state.resume_hw_watchpoints();
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
