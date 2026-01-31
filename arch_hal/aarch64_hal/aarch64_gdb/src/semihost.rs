use aarch64_mutex::RawSpinLockIrqSave;
use core::fmt;
use core::fmt::Write;
use cpu::Registers;

use super::MemoryAccess;

const SEMIHOST_HLT_BASE: u32 = 0xD440_0000;
const SEMIHOST_HLT_MASK: u32 = 0xFFE0_001F;
const SEMIHOST_HLT_IMM: u32 = 0xF000;
const SEMIHOST_READ_MAX: usize = 4096;

const SYS_OPEN: u32 = 0x01;
const SYS_CLOSE: u32 = 0x02;
const SYS_WRITE0: u32 = 0x04;
const SYS_WRITE: u32 = 0x05;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemihostOp {
    Write0,
    Open,
    Write,
    Close,
}

#[derive(Clone, Copy, Debug)]
pub struct SemihostRequest {
    pub op: u64,
    pub args_ptr: u64,
    pub insn_addr: u64,
    pub pc_after: u64,
    pub kind: Option<SemihostOp>,
    pub handle: u64,
    pub buf_ptr: u64,
    pub len: u64,
    pub mode: u64,
    pub decoded_ok: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SemihostCompletion {
    pub result: i64,
    pub errno: i32,
}

struct SemihostState {
    pending: bool,
    req: Option<SemihostRequest>,
    completion: Option<SemihostCompletion>,
    next_handle: u32,
    read_offset: u64,
    read_done: bool,
}

impl SemihostState {
    const fn new() -> Self {
        Self {
            pending: false,
            req: None,
            completion: None,
            next_handle: 3,
            read_offset: 0,
            read_done: false,
        }
    }

    fn clear(&mut self) {
        self.pending = false;
        self.req = None;
        self.completion = None;
        self.read_offset = 0;
        self.read_done = false;
    }

    fn start_request(&mut self, req: SemihostRequest) {
        self.pending = true;
        self.req = Some(req);
        self.completion = None;
        self.read_offset = 0;
        self.read_done = false;
    }

    fn alloc_handle(&mut self) -> u32 {
        let mut handle = self.next_handle;
        if handle == 0 {
            handle = 1;
        }
        self.next_handle = handle.wrapping_add(1);
        if self.next_handle == 0 {
            self.next_handle = 1;
        }
        handle
    }
}

static SEMIHOST: RawSpinLockIrqSave<SemihostState> = RawSpinLockIrqSave::new(SemihostState::new());

#[derive(Clone, Copy, Debug)]
pub enum ResumeGate {
    Hold,
    Proceed(Option<(SemihostRequest, SemihostCompletion)>),
}

fn semihost_op(op: u64) -> Option<SemihostOp> {
    match (op & 0xffff_ffff) as u32 {
        SYS_WRITE0 => Some(SemihostOp::Write0),
        SYS_OPEN => Some(SemihostOp::Open),
        SYS_WRITE => Some(SemihostOp::Write),
        SYS_CLOSE => Some(SemihostOp::Close),
        _ => None,
    }
}

pub fn is_semihost_hlt(insn: u32) -> bool {
    (insn & SEMIHOST_HLT_MASK) == SEMIHOST_HLT_BASE && ((insn >> 5) & 0xffff) == SEMIHOST_HLT_IMM
}

pub fn capture_from_debug<M: MemoryAccess>(mem: &mut M, regs: &Registers, pc: u64) -> bool {
    let mut insn_addr = None;
    if let Ok(insn) = read_insn(mem, pc) {
        if is_semihost_hlt(insn) {
            insn_addr = Some(pc);
        }
    }
    if insn_addr.is_none() && pc >= 4 {
        let pc_prev = pc.wrapping_sub(4);
        if let Ok(insn) = read_insn(mem, pc_prev) {
            if is_semihost_hlt(insn) {
                insn_addr = Some(pc_prev);
            }
        }
    }

    let Some(insn_addr) = insn_addr else {
        return false;
    };

    let req = decode_request(mem, regs, insn_addr);
    let mut guard = SEMIHOST.lock_irqsave();
    guard.start_request(req);
    true
}

pub fn resume_gate() -> ResumeGate {
    let mut guard = SEMIHOST.lock_irqsave();
    if !guard.pending {
        return ResumeGate::Proceed(None);
    }
    if guard.completion.is_none() {
        return ResumeGate::Hold;
    }
    let req = guard.req;
    let completion = guard.completion;
    guard.clear();
    match (req, completion) {
        (Some(req), Some(completion)) => ResumeGate::Proceed(Some((req, completion))),
        _ => ResumeGate::Proceed(None),
    }
}

pub fn monitor_command<M: MemoryAccess>(cmd: &str, out: &mut [u8], mem: &mut M) -> Option<usize> {
    let mut parts = cmd.split_ascii_whitespace();
    let root = parts.next()?;
    if root != "hp" {
        return None;
    }
    let Some(subcmd) = parts.next() else {
        return None;
    };

    let mut out = OutBuf::new(out);
    match subcmd {
        "semihost?" => {
            if parts.next().is_some() {
                write_error(&mut out, "extra_args");
            } else {
                write_semihost_query(&mut out);
            }
            Some(out.len())
        }
        "semihost" => {
            let Some(action) = parts.next() else {
                write_error(&mut out, "bad_args");
                return Some(out.len());
            };
            match action {
                "info" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                    } else {
                        write_semihost_info(&mut out);
                    }
                }
                "read" => {
                    let Some(limit) = parts.next() else {
                        write_error(&mut out, "bad_args");
                        return Some(out.len());
                    };
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                    } else {
                        match parse_usize_token(limit) {
                            Some(limit) => {
                                if let Err(msg) = write_semihost_read(&mut out, mem, limit) {
                                    write_error(&mut out, msg);
                                }
                            }
                            None => write_error(&mut out, "bad_len"),
                        }
                    }
                }
                "reply" => {
                    let Some(result) = parts.next() else {
                        write_error(&mut out, "bad_args");
                        return Some(out.len());
                    };
                    let Some(errno) = parts.next() else {
                        write_error(&mut out, "bad_args");
                        return Some(out.len());
                    };
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                    } else {
                        match (parse_i64_token(result), parse_i32_token(errno)) {
                            (Some(result), Some(errno)) => {
                                if let Err(msg) = store_completion(result, errno) {
                                    write_error(&mut out, msg);
                                } else {
                                    let _ = write!(out, "ok\n");
                                }
                            }
                            _ => write_error(&mut out, "bad_args"),
                        }
                    }
                }
                "alloc_handle" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                    } else {
                        let handle = alloc_handle();
                        let _ = write!(out, "handle={}\n", handle);
                    }
                }
                "reset" => {
                    if parts.next().is_some() {
                        write_error(&mut out, "extra_args");
                    } else {
                        reset_state();
                        let _ = write!(out, "ok\n");
                    }
                }
                _ => write_error(&mut out, "bad_args"),
            }
            Some(out.len())
        }
        _ => None,
    }
}

fn read_insn<M: MemoryAccess>(mem: &mut M, addr: u64) -> Result<u32, M::Error> {
    let mut buf = [0u8; 4];
    mem.read(addr, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn decode_request<M: MemoryAccess>(
    mem: &mut M,
    regs: &Registers,
    insn_addr: u64,
) -> SemihostRequest {
    let op = regs.x0;
    let args_ptr = regs.x1;
    let kind = semihost_op(op);
    let pc_after = insn_addr.wrapping_add(4);
    let mut req = SemihostRequest {
        op,
        args_ptr,
        insn_addr,
        pc_after,
        kind,
        handle: 0,
        buf_ptr: 0,
        len: 0,
        mode: 0,
        decoded_ok: true,
    };

    match kind {
        Some(SemihostOp::Write0) => {
            req.buf_ptr = args_ptr;
        }
        Some(SemihostOp::Open) => match read_args_u64(mem, args_ptr, 3) {
            Ok(fields) => {
                req.buf_ptr = fields[0];
                req.mode = fields[1];
                req.len = fields[2];
            }
            Err(_) => req.decoded_ok = false,
        },
        Some(SemihostOp::Write) => match read_args_u64(mem, args_ptr, 3) {
            Ok(fields) => {
                req.handle = fields[0];
                req.buf_ptr = fields[1];
                req.len = fields[2];
            }
            Err(_) => req.decoded_ok = false,
        },
        Some(SemihostOp::Close) => match read_args_u64(mem, args_ptr, 1) {
            Ok(fields) => {
                req.handle = fields[0];
            }
            Err(_) => req.decoded_ok = false,
        },
        None => req.decoded_ok = false,
    }

    req
}

fn read_args_u64<M: MemoryAccess>(
    mem: &mut M,
    addr: u64,
    count: usize,
) -> Result<[u64; 3], M::Error> {
    let mut buf = [0u8; 24];
    let len = match count {
        1 => 8,
        3 => 24,
        _ => 0,
    };
    if len == 0 {
        return Ok([0u64; 3]);
    }
    mem.read(addr, &mut buf[..len])?;
    let mut fields = [0u64; 3];
    if count >= 1 {
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&buf[0..8]);
        fields[0] = u64::from_le_bytes(tmp);
    }
    if count >= 2 {
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&buf[8..16]);
        fields[1] = u64::from_le_bytes(tmp);
    }
    if count >= 3 {
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&buf[16..24]);
        fields[2] = u64::from_le_bytes(tmp);
    }
    Ok(fields)
}

fn store_completion(result: i64, errno: i32) -> Result<(), &'static str> {
    let mut guard = SEMIHOST.lock_irqsave();
    if !guard.pending {
        return Err("no_pending");
    }
    if guard.completion.is_some() {
        return Err("already_completed");
    }
    guard.completion = Some(SemihostCompletion { result, errno });
    Ok(())
}

fn alloc_handle() -> u32 {
    let mut guard = SEMIHOST.lock_irqsave();
    guard.alloc_handle()
}

fn reset_state() {
    let mut guard = SEMIHOST.lock_irqsave();
    guard.clear();
}

fn write_semihost_query(out: &mut OutBuf<'_>) {
    let guard = SEMIHOST.lock_irqsave();
    if !guard.pending {
        let _ = write!(out, "no\n");
        return;
    }
    let Some(req) = guard.req else {
        let _ = write!(out, "no\n");
        return;
    };
    let op = (req.op & 0xffff_ffff) as u32;
    let _ = write!(
        out,
        "yes op=0x{:x} args=0x{:x} insn=0x{:x}\n",
        op, req.args_ptr, req.insn_addr
    );
}

fn write_semihost_info(out: &mut OutBuf<'_>) {
    let guard = SEMIHOST.lock_irqsave();
    if !guard.pending {
        write_error(out, "no_pending");
        return;
    }
    let Some(req) = guard.req else {
        write_error(out, "no_pending");
        return;
    };
    let Some(kind) = req.kind else {
        write_error(out, "unsupported_op");
        return;
    };
    if !req.decoded_ok && !matches!(kind, SemihostOp::Write0) {
        write_error(out, "decode_failed");
        return;
    }
    match kind {
        SemihostOp::Write0 => {
            let _ = write!(out, "op=write0 str=0x{:x}\n", req.buf_ptr);
        }
        SemihostOp::Open => {
            let _ = write!(
                out,
                "path=0x{:x} len={} mode={}\n",
                req.buf_ptr, req.len, req.mode
            );
        }
        SemihostOp::Write => {
            let _ = write!(
                out,
                "handle={} buf=0x{:x} len={}\n",
                req.handle, req.buf_ptr, req.len
            );
        }
        SemihostOp::Close => {
            let _ = write!(out, "handle={}\n", req.handle);
        }
    }
}

fn write_semihost_read<M: MemoryAccess>(
    out: &mut OutBuf<'_>,
    mem: &mut M,
    limit: usize,
) -> Result<(), &'static str> {
    if limit > SEMIHOST_READ_MAX {
        return Err("too_large");
    }
    let mut guard = SEMIHOST.lock_irqsave();
    if !guard.pending {
        return Err("no_pending");
    }
    let Some(req) = guard.req else {
        return Err("no_pending");
    };
    let Some(kind) = req.kind else {
        return Err("unsupported_op");
    };
    if !req.decoded_ok && !matches!(kind, SemihostOp::Write0) {
        return Err("decode_failed");
    }
    if guard.read_done {
        let _ = write!(out, "hex:\n");
        return Ok(());
    }

    let mut buf = [0u8; SEMIHOST_READ_MAX];
    let mut truncated = false;
    let mut actual_len = 0usize;

    match kind {
        SemihostOp::Write0 => {
            let addr = req
                .buf_ptr
                .checked_add(guard.read_offset)
                .ok_or("addr_overflow")?;
            let read_len = limit;
            if read_len == 0 {
                let _ = write!(out, "hex:\n");
                return Ok(());
            }
            mem.read(addr, &mut buf[..read_len])
                .map_err(|_| "mem_read")?;
            if let Some(pos) = buf[..read_len].iter().position(|&b| b == 0) {
                actual_len = pos;
                guard.read_done = true;
                guard.read_offset = guard.read_offset.saturating_add(pos as u64 + 1);
                truncated = false;
            } else {
                actual_len = read_len;
                guard.read_offset = guard.read_offset.saturating_add(read_len as u64);
                truncated = true;
            }
        }
        SemihostOp::Open | SemihostOp::Write => {
            let total_len = req.len;
            let offset = guard.read_offset;
            if offset >= total_len {
                guard.read_done = true;
                let _ = write!(out, "hex:\n");
                return Ok(());
            }
            let remaining = total_len - offset;
            let read_len = core::cmp::min(remaining, limit as u64) as usize;
            let addr = req.buf_ptr.checked_add(offset).ok_or("addr_overflow")?;
            mem.read(addr, &mut buf[..read_len])
                .map_err(|_| "mem_read")?;
            actual_len = read_len;
            guard.read_offset = offset + read_len as u64;
            truncated = guard.read_offset < total_len;
        }
        SemihostOp::Close => return Err("bad_op"),
    }

    let _ = out.try_write_str("hex:");
    let _ = push_hex_bytes(out, &buf[..actual_len]);
    if truncated {
        let _ = out.try_write_str(" truncated=1\n");
    } else {
        let _ = out.try_write_str("\n");
    }
    Ok(())
}

fn parse_usize_token(token: &str) -> Option<usize> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).ok()
    } else {
        usize::from_str_radix(token, 10).ok()
    }
}

fn parse_i64_token(token: &str) -> Option<i64> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let (neg, rest) = if let Some(rest) = token.strip_prefix('-') {
        (true, rest)
    } else {
        (false, token)
    };
    if rest.is_empty() {
        return None;
    }
    let value = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        u64::from_str_radix(rest, 10).ok()?
    };
    let value = value as i128;
    let value = if neg { -value } else { value };
    if value < i64::MIN as i128 || value > i64::MAX as i128 {
        None
    } else {
        Some(value as i64)
    }
}

fn parse_i32_token(token: &str) -> Option<i32> {
    let value = parse_i64_token(token)?;
    if value < i32::MIN as i64 || value > i32::MAX as i64 {
        None
    } else {
        Some(value as i32)
    }
}

fn write_error(out: &mut OutBuf<'_>, msg: &str) {
    let _ = write!(out, "error {}\n", msg);
}

fn push_hex_bytes(out: &mut OutBuf<'_>, bytes: &[u8]) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 2];
    for &b in bytes {
        buf[0] = HEX[(b >> 4) as usize];
        buf[1] = HEX[(b & 0xf) as usize];
        out.try_write_bytes(&buf)?;
    }
    Ok(())
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
        if self.len >= self.buf.len() {
            return Err(fmt::Error);
        }
        let cap = self.buf.len() - self.len;
        let copy_len = core::cmp::min(cap, bytes.len());
        self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        if copy_len < bytes.len() {
            return Err(fmt::Error);
        }
        Ok(())
    }

    fn try_write_str(&mut self, s: &str) -> fmt::Result {
        self.try_write_bytes(s.as_bytes())
    }
}

impl fmt::Write for OutBuf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.try_write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyMem;

    impl MemoryAccess for DummyMem {
        type Error = ();

        fn read(&mut self, _addr: u64, _dst: &mut [u8]) -> Result<(), Self::Error> {
            Err(())
        }

        fn write(&mut self, _addr: u64, _src: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn reset_for_test() {
        let mut guard = SEMIHOST.lock_irqsave();
        guard.clear();
    }

    #[test]
    fn hlt_decode_matches_semihost() {
        assert!(is_semihost_hlt(0xD45E_0000));
        assert!(!is_semihost_hlt(0xD440_0000));
        assert!(!is_semihost_hlt(0xD420_0000));
    }

    #[test]
    fn resume_gate_transitions() {
        reset_for_test();
        let req = SemihostRequest {
            op: 0x04,
            args_ptr: 0,
            insn_addr: 0x1000,
            pc_after: 0x1004,
            kind: Some(SemihostOp::Write0),
            handle: 0,
            buf_ptr: 0x2000,
            len: 0,
            mode: 0,
            decoded_ok: true,
        };
        {
            let mut guard = SEMIHOST.lock_irqsave();
            guard.start_request(req);
        }
        assert!(matches!(resume_gate(), ResumeGate::Hold));
        {
            let mut guard = SEMIHOST.lock_irqsave();
            guard.completion = Some(SemihostCompletion {
                result: 0,
                errno: 0,
            });
        }
        let gate = resume_gate();
        match gate {
            ResumeGate::Proceed(Some((got_req, _))) => {
                assert_eq!(got_req.insn_addr, req.insn_addr);
            }
            _ => panic!("expected completion"),
        }
        let gate = resume_gate();
        match gate {
            ResumeGate::Proceed(None) => {}
            _ => panic!("expected no pending state"),
        }
    }

    #[test]
    fn monitor_query_has_newline() {
        reset_for_test();
        let mut out = [0u8; 64];
        let mut mem = DummyMem;
        let len = monitor_command("hp semihost?", &mut out, &mut mem).unwrap();
        assert_eq!(&out[..len], b"no\n");
    }

    #[test]
    fn monitor_reply_requires_pending() {
        reset_for_test();
        let mut out = [0u8; 64];
        let mut mem = DummyMem;
        let len = monitor_command("hp semihost reply 0 0", &mut out, &mut mem).unwrap();
        assert!(
            core::str::from_utf8(&out[..len])
                .unwrap_or("")
                .starts_with("error")
        );
    }
}
