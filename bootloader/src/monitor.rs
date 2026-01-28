use crate::guest_mmio_allowlist_contains_range;
use crate::vbar_watch;
use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::cpu;
use core::fmt;
use core::fmt::Write;

pub const MAX_IGNORES: usize = 16;
const MEMFAULT_STORM_LIMIT: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemfaultPolicy {
    Off,
    Warn,
    Trap,
    Autoskip,
}

impl MemfaultPolicy {
    fn as_str(self) -> &'static str {
        match self {
            MemfaultPolicy::Off => "off",
            MemfaultPolicy::Warn => "warn",
            MemfaultPolicy::Trap => "trap",
            MemfaultPolicy::Autoskip => "autoskip",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(MemfaultPolicy::Off),
            "warn" => Some(MemfaultPolicy::Warn),
            "trap" => Some(MemfaultPolicy::Trap),
            "autoskip" => Some(MemfaultPolicy::Autoskip),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    storm: MemfaultStorm,
}

impl MemfaultState {
    const fn new() -> Self {
        Self {
            policy: MemfaultPolicy::Trap,
            pending: false,
            last: None,
            ignores: [IgnoreEntry::empty(); MAX_IGNORES],
            storm: MemfaultStorm::new(),
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
struct MemfaultStorm {
    page: u64,
    access: MemfaultAccess,
    count: u32,
    valid: bool,
}

impl MemfaultStorm {
    const fn new() -> Self {
        Self {
            page: 0,
            access: MemfaultAccess::Read,
            count: 0,
            valid: false,
        }
    }

    fn reset(&mut self) {
        self.valid = false;
        self.count = 0;
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
    pub should_log: bool,
}

pub fn record_memfault(info: MemfaultInfo) -> MemfaultDecision {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    guard.last = Some(info);
    let ignored = guard.is_ignored(info.addr)
        || guest_mmio_allowlist_contains_range(info.addr as usize, info.size as usize);
    let policy = guard.policy;
    let mut storm_trap = false;
    if !ignored && matches!(policy, MemfaultPolicy::Warn | MemfaultPolicy::Autoskip) {
        let page = info.addr & !0xfff;
        let access = info.access;
        if guard.storm.valid && guard.storm.page == page && guard.storm.access == access {
            guard.storm.count = guard.storm.count.saturating_add(1);
        } else {
            guard.storm.page = page;
            guard.storm.access = access;
            guard.storm.count = 1;
            guard.storm.valid = true;
        }
        if guard.storm.count >= MEMFAULT_STORM_LIMIT {
            storm_trap = true;
            guard.storm.reset();
        }
    } else {
        guard.storm.reset();
    }

    let should_trap = (policy == MemfaultPolicy::Trap && !ignored) || storm_trap;
    let should_log = !ignored
        && matches!(policy, MemfaultPolicy::Warn | MemfaultPolicy::Autoskip)
        && !storm_trap;
    let should_pending =
        !ignored && matches!(policy, MemfaultPolicy::Warn | MemfaultPolicy::Autoskip);
    if should_trap || should_pending {
        guard.pending = true;
    }
    MemfaultDecision {
        policy,
        ignored,
        should_trap,
        should_log,
    }
}

/// Enable memfault trapping once a debug session becomes active.
///
/// This ensures watchpoint-style stops even if the policy was set to `Off`.
pub fn enable_memfault_trap_if_off() {
    let mut guard = MEMFAULT_STATE.lock_irqsave();
    if guard.policy == MemfaultPolicy::Off {
        guard.policy = MemfaultPolicy::Trap;
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

    fn try_write_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        if self.buf.len().saturating_sub(self.len) < bytes.len() {
            return Err(fmt::Error);
        }
        let end = self.len + bytes.len();
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn try_write_str(&mut self, s: &str) -> fmt::Result {
        self.try_write_bytes(s.as_bytes())
    }

    fn force_truncated_marker(&mut self) {
        const MARKER: &[u8] = b"...TRUNCATED";
        if self.buf.len() < MARKER.len() {
            return;
        }
        let start = self.buf.len() - MARKER.len();
        self.buf[start..].copy_from_slice(MARKER);
        self.len = self.buf.len();
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

fn write_vbar_usage(out: &mut OutBuf<'_>) {
    let _ = write!(out, "usage=hp vbar <status|last|clear|check|bt?|bt>");
}

fn write_vbar_status(out: &mut OutBuf<'_>) {
    let snapshot = vbar_watch::snapshot_status();
    let live_vbar = cpu::get_vbar_el1();

    let _ = write!(
        out,
        "enabled={} mode={} current_vbar_va=0x{:x} current_vbar_ipa=0x{:x} live_vbar=0x{:x}",
        snapshot.enabled as u8,
        snapshot.mode.as_str(),
        snapshot.current_vbar_va,
        snapshot.current_vbar_ipa,
        live_vbar
    );
    let _ = write!(
        out,
        " pending_repatch={} step_depth={} change_seq={} change_reason={}",
        snapshot.pending_repatch as u8,
        snapshot.step_depth,
        snapshot.last_change_seq,
        snapshot.last_change_reason.as_str()
    );
    if live_vbar != snapshot.current_vbar_va {
        let _ = write!(
            out,
            " warning=vbar_changed pending_repatch={}",
            snapshot.pending_repatch as u8
        );
    }
    if let Some(err) = snapshot.last_error {
        let _ = write!(out, " error={} err_vbar=0x{:x}", err.reason, err.vbar_va);
    }
}

fn write_vbar_last(out: &mut OutBuf<'_>) {
    let Some(hit) = vbar_watch::last_hit_snapshot() else {
        let _ = write!(out, "none");
        return;
    };
    let mode = vbar_watch::spsr_el1_mode_label(hit.origin_spsr_el1);
    let _ = write!(
        out,
        "slot={} offset=0x{:x} brk_pc=0x{:x} esr_el2=0x{:x} elr_el2=0x{:x}",
        hit.slot_index, hit.offset, hit.elr, hit.esr, hit.elr
    );
    let _ = write!(
        out,
        " origin_pc=0x{:x} origin_spsr_el1=0x{:x} origin_mode={}",
        hit.origin_pre_pc, hit.origin_spsr_el1, mode
    );
    match hit.origin_pre_sp {
        Some(sp) => {
            let _ = write!(out, " origin_pre_sp=0x{:x}", sp);
        }
        None => {
            let _ = write!(out, " origin_pre_sp=unknown");
        }
    }
    let _ = write!(
        out,
        " origin_sp_el0=0x{:x} origin_sp_el1=0x{:x} origin_esr_el1=0x{:x} origin_far_el1=0x{:x} nested={}",
        hit.origin_sp_el0,
        hit.origin_sp_el1,
        hit.origin_esr_el1,
        hit.origin_far_el1,
        hit.nested as u8
    );
}

fn push_hex_u8(out: &mut OutBuf<'_>, b: u8) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 2];
    buf[0] = HEX[(b >> 4) as usize];
    buf[1] = HEX[(b & 0xf) as usize];
    out.try_write_bytes(&buf)
}

fn push_hex_bytes(out: &mut OutBuf<'_>, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        push_hex_u8(out, b)?;
    }
    Ok(())
}

fn write_vbar_bt_meta(out: &mut OutBuf<'_>) {
    let Some((seq, depth, nested)) = vbar_watch::snapshot_last_bt_meta() else {
        let _ = write!(out, "none");
        return;
    };
    let _ = write!(
        out,
        "seq={} depth={} nested={} version=1",
        seq, depth, nested as u8
    );
}

fn write_vbar_bt_dump(out: &mut OutBuf<'_>) {
    let Some((seq, depth, frames)) = vbar_watch::snapshot_last_bt_dump() else {
        let _ = write!(out, "none");
        return;
    };
    let _ = write!(
        out,
        "version=1 seq={} depth={} stride=56 fields=pc,sp,fp,lr,spsr,esr,far data=",
        seq, depth
    );
    let mut wrote_all = true;
    for frame in frames.iter().take(depth as usize) {
        let bytes = [
            frame.pc.to_le_bytes(),
            frame.sp.to_le_bytes(),
            frame.fp.to_le_bytes(),
            frame.lr.to_le_bytes(),
            frame.spsr.to_le_bytes(),
            frame.esr.to_le_bytes(),
            frame.far.to_le_bytes(),
        ];
        for chunk in bytes.iter() {
            if push_hex_bytes(out, chunk).is_err() {
                wrote_all = false;
                break;
            }
        }
        if !wrote_all {
            break;
        }
    }
    if !wrote_all {
        out.force_truncated_marker();
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
        "vbar" => {
            let Some(cmd) = parts.next() else {
                write_vbar_usage(&mut out);
                return Some(out.len());
            };
            match cmd {
                "status" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    write_vbar_status(&mut out);
                    Some(out.len())
                }
                "last" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    write_vbar_last(&mut out);
                    Some(out.len())
                }
                "clear" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    vbar_watch::clear_last_hit();
                    let _ = write!(out, "ok");
                    Some(out.len())
                }
                "bt?" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    write_vbar_bt_meta(&mut out);
                    Some(out.len())
                }
                "bt" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    write_vbar_bt_dump(&mut out);
                    Some(out.len())
                }
                "check" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                        return Some(out.len());
                    }
                    vbar_watch::poll_vbar_el1_change();
                    write_vbar_status(&mut out);
                    Some(out.len())
                }
                _ => {
                    write_vbar_usage(&mut out);
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
