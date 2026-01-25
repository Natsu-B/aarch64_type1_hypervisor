use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use core::fmt;
use core::fmt::Write;

pub const MAX_IGNORES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemfaultPolicy {
    Off,
    Trap,
    Autoskip,
}

impl MemfaultPolicy {
    fn as_str(self) -> &'static str {
        match self {
            MemfaultPolicy::Off => "off",
            MemfaultPolicy::Trap => "trap",
            MemfaultPolicy::Autoskip => "autoskip",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(MemfaultPolicy::Off),
            "trap" => Some(MemfaultPolicy::Trap),
            "autoskip" => Some(MemfaultPolicy::Autoskip),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MemfaultAccess {
    Read,
    Write,
}

impl MemfaultAccess {
    fn as_char(self) -> char {
        match self {
            MemfaultAccess::Read => 'r',
            MemfaultAccess::Write => 'w',
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MemfaultInfo {
    pub addr: u64,
    pub pc: u64,
    pub access: MemfaultAccess,
    pub size: u8,
    pub esr: u64,
    pub far: u64,
}

#[derive(Clone, Copy)]
struct IgnoreEntry {
    base: u64,
    len: u64,
    valid: bool,
}

impl IgnoreEntry {
    const fn empty() -> Self {
        Self {
            base: 0,
            len: 0,
            valid: false,
        }
    }

    fn contains(&self, addr: u64) -> bool {
        let Some(end) = self.base.checked_add(self.len) else {
            return false;
        };
        addr >= self.base && addr < end
    }

    fn matches(&self, base: u64, len: u64) -> bool {
        self.valid && self.base == base && self.len == len
    }
}

struct MemfaultState {
    policy: MemfaultPolicy,
    pending: bool,
    last: Option<MemfaultInfo>,
    ignores: [IgnoreEntry; MAX_IGNORES],
}

impl MemfaultState {
    const fn new() -> Self {
        Self {
            policy: MemfaultPolicy::Off,
            pending: false,
            last: None,
            ignores: [IgnoreEntry::empty(); MAX_IGNORES],
        }
    }

    fn is_ignored(&self, addr: u64) -> bool {
        self.ignores
            .iter()
            .any(|entry| entry.valid && entry.contains(addr))
    }

    fn add_ignore(&mut self, base: u64, len: u64) -> Result<(), &'static str> {
        if len == 0 {
            return Err("bad_len");
        }
        if base.checked_add(len).is_none() {
            return Err("bad_range");
        }
        if self.ignores.iter().any(|entry| entry.matches(base, len)) {
            return Ok(());
        }
        let Some(slot) = self.ignores.iter_mut().find(|entry| !entry.valid) else {
            return Err("full");
        };
        slot.base = base;
        slot.len = len;
        slot.valid = true;
        Ok(())
    }

    fn del_ignore(&mut self, base: u64, len: u64) -> Result<(), &'static str> {
        for entry in &mut self.ignores {
            if entry.matches(base, len) {
                *entry = IgnoreEntry::empty();
                return Ok(());
            }
        }
        Err("not_found")
    }
}

#[derive(Clone, Copy)]
struct MemfaultSnapshot {
    policy: MemfaultPolicy,
    pending: bool,
    last: Option<MemfaultInfo>,
    ignores: [IgnoreEntry; MAX_IGNORES],
}

static MEMFAULT_STATE: RawSpinLockIrqSave<MemfaultState> =
    RawSpinLockIrqSave::new(MemfaultState::new());

pub struct MemfaultDecision {
    pub policy: MemfaultPolicy,
    pub ignored: bool,
    pub should_trap: bool,
}

pub fn record_memfault(info: MemfaultInfo, can_trap: bool) -> MemfaultDecision {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    guard.last = Some(info);
    let ignored = guard.is_ignored(info.addr);
    let policy = guard.policy;
    let should_trap = can_trap && policy == MemfaultPolicy::Trap && !ignored;
    if should_trap {
        guard.pending = true;
    }
    MemfaultDecision {
        policy,
        ignored,
        should_trap,
    }
}

struct OutBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> OutBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl fmt::Write for OutBuf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.len);
        let copy_len = bytes.len().min(avail);
        if copy_len > 0 {
            self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
            self.len += copy_len;
        }
        Ok(())
    }
}

fn snapshot_state() -> MemfaultSnapshot {
    let guard = MEMFAULT_STATE.lock_irqsave();
    MemfaultSnapshot {
        policy: guard.policy,
        pending: guard.pending,
        last: guard.last,
        ignores: guard.ignores,
    }
}

fn set_policy(policy: MemfaultPolicy) {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    guard.policy = policy;
}

fn clear_pending() {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    guard.pending = false;
}

fn add_ignore(base: u64, len: u64) -> Result<(), &'static str> {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    guard.add_ignore(base, len)
}

fn del_ignore(base: u64, len: u64) -> Result<(), &'static str> {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    guard.del_ignore(base, len)
}

fn add_ignore_last(len: u64) -> Result<u64, &'static str> {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    let Some(info) = guard.last else {
        return Err("no_last");
    };
    let base = info.addr;
    guard.add_ignore(base, len)?;
    Ok(base)
}

fn write_error(out: &mut OutBuf<'_>, reason: &str) {
    let _ = write!(out, "error={}", reason);
}

fn write_memfault_info(out: &mut OutBuf<'_>, info: MemfaultInfo) {
    let _ = write!(
        out,
        "addr=0x{:x} pc=0x{:x} access={} size={} esr=0x{:x} far=0x{:x}",
        info.addr,
        info.pc,
        info.access.as_char(),
        info.size,
        info.esr,
        info.far
    );
}

fn write_ignore_list(out: &mut OutBuf<'_>, ignores: &[IgnoreEntry; MAX_IGNORES]) {
    let mut count = 0usize;
    for entry in ignores.iter().filter(|entry| entry.valid) {
        let _ = entry;
        count += 1;
    }
    let _ = write!(out, "count={} entries=", count);
    let mut first = true;
    for entry in ignores.iter().filter(|entry| entry.valid) {
        if !first {
            let _ = write!(out, ",");
        }
        first = false;
        let _ = write!(out, "0x{:x}+0x{:x}", entry.base, entry.len);
    }
}

fn parse_u64_token(token: &str) -> Option<u64> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        if hex.is_empty() {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else {
        u64::from_str_radix(token, 10).ok()
    }
}

pub fn bootloader_monitor_handler(cmd: &[u8], out: &mut [u8]) -> Option<usize> {
    let Ok(text) = core::str::from_utf8(cmd) else {
        return None;
    };
    let mut parts = text.split_ascii_whitespace();
    let Some(root) = parts.next() else {
        return None;
    };
    if root != "hp" {
        return None;
    }

    let mut out = OutBuf::new(out);
    let Some(area) = parts.next() else {
        write_error(&mut out, "bad_args");
        return Some(out.len());
    };

    match area {
        "memfault?" => {
            if parts.next().is_some() {
                write_error(&mut out, "extra_args");
                return Some(out.len());
            }
            let snapshot = snapshot_state();
            if snapshot.pending {
                let Some(info) = snapshot.last else {
                    let _ = write!(out, "no");
                    return Some(out.len());
                };
                let _ = write!(out, "yes ");
                write_memfault_info(&mut out, info);
            } else {
                let _ = write!(out, "no");
            }
            Some(out.len())
        }
        "memfault" => {
            let Some(cmd) = parts.next() else {
                write_error(&mut out, "bad_args");
                return Some(out.len());
            };
            match cmd {
                "last" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    let snapshot = snapshot_state();
                    if let Some(info) = snapshot.last {
                        write_memfault_info(&mut out, info);
                        let _ = write!(out, " pending={}", if snapshot.pending { 1 } else { 0 });
                    } else {
                        let _ = write!(out, "none");
                    }
                    Some(out.len())
                }
                "clear" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    clear_pending();
                    let _ = write!(out, "ok");
                    Some(out.len())
                }
                "policy" => {
                    let Some(subcmd) = parts.next() else {
                        write_error(&mut out, "bad_args");
                        return Some(out.len());
                    };
                    match subcmd {
                        "get" => {
                            if parts.next().is_some() {
                                write_error(&mut out, "extra_args");
                                return Some(out.len());
                            }
                            let snapshot = snapshot_state();
                            let _ = write!(out, "policy={}", snapshot.policy.as_str());
                            Some(out.len())
                        }
                        "set" => {
                            let Some(policy_str) = parts.next() else {
                                write_error(&mut out, "bad_args");
                                return Some(out.len());
                            };
                            if parts.next().is_some() {
                                write_error(&mut out, "extra_args");
                                return Some(out.len());
                            }
                            let Some(policy) = MemfaultPolicy::parse(policy_str) else {
                                write_error(&mut out, "bad_policy");
                                return Some(out.len());
                            };
                            set_policy(policy);
                            let _ = write!(out, "ok policy={}", policy.as_str());
                            Some(out.len())
                        }
                        _ => {
                            write_error(&mut out, "bad_args");
                            Some(out.len())
                        }
                    }
                }
                "ignore" => {
                    let Some(subcmd) = parts.next() else {
                        write_error(&mut out, "bad_args");
                        return Some(out.len());
                    };
                    match subcmd {
                        "add" => {
                            let Some(addr_str) = parts.next() else {
                                write_error(&mut out, "bad_args");
                                return Some(out.len());
                            };
                            let Some(len_str) = parts.next() else {
                                write_error(&mut out, "bad_args");
                                return Some(out.len());
                            };
                            if parts.next().is_some() {
                                write_error(&mut out, "extra_args");
                                return Some(out.len());
                            }
                            let Some(base) = parse_u64_token(addr_str) else {
                                write_error(&mut out, "bad_addr");
                                return Some(out.len());
                            };
                            let Some(len) = parse_u64_token(len_str) else {
                                write_error(&mut out, "bad_len");
                                return Some(out.len());
                            };
                            match add_ignore(base, len) {
                                Ok(()) => {
                                    let _ = write!(out, "ok addr=0x{:x} len=0x{:x}", base, len);
                                }
                                Err(reason) => write_error(&mut out, reason),
                            }
                            Some(out.len())
                        }
                        "add_last" => {
                            let Some(len_str) = parts.next() else {
                                write_error(&mut out, "bad_args");
                                return Some(out.len());
                            };
                            if parts.next().is_some() {
                                write_error(&mut out, "extra_args");
                                return Some(out.len());
                            }
                            let Some(len) = parse_u64_token(len_str) else {
                                write_error(&mut out, "bad_len");
                                return Some(out.len());
                            };
                            match add_ignore_last(len) {
                                Ok(base) => {
                                    let _ = write!(out, "ok addr=0x{:x} len=0x{:x}", base, len);
                                }
                                Err(reason) => write_error(&mut out, reason),
                            }
                            Some(out.len())
                        }
                        "del" => {
                            let Some(addr_str) = parts.next() else {
                                write_error(&mut out, "bad_args");
                                return Some(out.len());
                            };
                            let Some(len_str) = parts.next() else {
                                write_error(&mut out, "bad_args");
                                return Some(out.len());
                            };
                            if parts.next().is_some() {
                                write_error(&mut out, "extra_args");
                                return Some(out.len());
                            }
                            let Some(base) = parse_u64_token(addr_str) else {
                                write_error(&mut out, "bad_addr");
                                return Some(out.len());
                            };
                            let Some(len) = parse_u64_token(len_str) else {
                                write_error(&mut out, "bad_len");
                                return Some(out.len());
                            };
                            match del_ignore(base, len) {
                                Ok(()) => {
                                    let _ = write!(out, "ok addr=0x{:x} len=0x{:x}", base, len);
                                }
                                Err(reason) => write_error(&mut out, reason),
                            }
                            Some(out.len())
                        }
                        "list" => {
                            if parts.next().is_some() {
                                write_error(&mut out, "extra_args");
                                return Some(out.len());
                            }
                            let snapshot = snapshot_state();
                            write_ignore_list(&mut out, &snapshot.ignores);
                            Some(out.len())
                        }
                        _ => {
                            write_error(&mut out, "bad_args");
                            Some(out.len())
                        }
                    }
                }
                _ => {
                    write_error(&mut out, "bad_args");
                    Some(out.len())
                }
            }
        }
        _ => {
            write_error(&mut out, "bad_args");
            Some(out.len())
        }
    }
}
