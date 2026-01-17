#![no_std]

use byte_stream::ByteStream;
use byte_stream::ByteStreamBlockingExt;
use core::fmt;

#[cfg(feature = "gdb_monitor_debug")]
use core::fmt::Write;

#[macro_export]
macro_rules! gdb_debug {
    ($server:expr, $($arg:tt)*) => {
        $server.debug_console_fmt(core::format_args!($($arg)*));
    };
}

mod target;

pub use target::ResumeAction;
pub use target::Target;
pub use target::TargetCapabilities;
pub use target::TargetError;
pub use target::WatchpointKind;

/// Errors that can occur while speaking the GDB Remote Serial Protocol.
#[derive(Debug)]
pub enum GdbError<SE, R, U> {
    /// Underlying stream error.
    Stream(SE),
    /// Target-specific error.
    Target(TargetError<R, U>),
    /// Received packet exceeded the provided buffer.
    PacketTooLong,
    /// Packet framing or checksum was invalid.
    MalformedPacket,
}

impl<SE, R, U> From<SE> for GdbError<SE, R, U> {
    fn from(err: SE) -> Self {
        GdbError::Stream(err)
    }
}

/// Result of processing a single RSP packet.
pub enum ProcessResult {
    /// Remain in the stop loop.
    None,
    /// Resume execution with the provided action.
    Resume(ResumeAction),
    /// Special-case monitor-exit used by the UEFI test harness.
    ///
    /// Note: This is triggered after `qRcmd "exit 0"` arms an exit request and the client
    /// subsequently sends a session-termination packet (e.g. `vKill`, `D`, or `k`).
    MonitorExit,
}
type TargetErr<T> = TargetError<<T as Target>::RecoverableError, <T as Target>::UnrecoverableError>;
type GdbServerError<S, T> = GdbError<
    <S as ByteStream>::Error,
    <T as Target>::RecoverableError,
    <T as Target>::UnrecoverableError,
>;

/// Minimal GDB RSP server operating on a byte stream.
///
/// The server logic uses blocking helpers and is not IRQ-safe.
pub struct GdbServer<S: ByteStream, const MAX_PKT: usize> {
    stream: S,
    monitor_exit_armed: bool,
}

impl<S: ByteStream, const MAX_PKT: usize> GdbServer<S, MAX_PKT> {
    /// Create a new server wrapping the provided stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            monitor_exit_armed: false,
        }
    }
    #[cfg(feature = "gdb_monitor_debug")]
    pub fn debug_console_fmt(&mut self, args: fmt::Arguments<'_>) {
        // Ensure the message and framing stay within the advertised maximum packet size.
        const MAX_MSG: usize = if MAX_PKT > 1 { (MAX_PKT - 1) / 2 } else { 0 };

        if MAX_MSG == 0 {
            return;
        }

        let mut msg_buf = [0u8; MAX_MSG];
        let mut writer = DebugBufWriter {
            buf: &mut msg_buf,
            pos: 0,
        };

        let _ = writer.write_fmt(args);
        let msg = &msg_buf[..writer.pos];

        let mut payload = [0u8; MAX_PKT];
        payload[0] = b'O';
        let hex_len = hex_encode(msg, &mut payload[1..]);
        let total_len = 1usize.saturating_add(hex_len);

        let _ = send_packet::<S, (), ()>(&self.stream, &payload[..total_len]);
    }

    #[cfg(not(feature = "gdb_monitor_debug"))]
    pub fn debug_console_fmt(&mut self, _args: fmt::Arguments<'_>) {
        let _ = _args;
    }

    fn send<T: Target>(&self, payload: &[u8]) -> Result<(), GdbServerError<S, T>> {
        send_packet::<_, T::RecoverableError, T::UnrecoverableError>(&self.stream, payload)
    }

    fn send_empty<T: Target>(&self) -> Result<(), GdbServerError<S, T>> {
        self.send::<T>(b"")
    }

    fn send_ok<T: Target>(&self) -> Result<(), GdbServerError<S, T>> {
        self.send::<T>(b"OK")
    }

    fn recv<T: Target>(
        &self,
        buf: &mut [u8; MAX_PKT],
    ) -> Result<Option<usize>, GdbServerError<S, T>> {
        recv_packet::<_, MAX_PKT, T::RecoverableError, T::UnrecoverableError>(&self.stream, buf)
    }

    /// Process a single incoming packet.
    pub fn process_one<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let mut buf = [0u8; MAX_PKT];
        let payload_len = loop {
            match self.recv::<T>(&mut buf) {
                Ok(Some(len)) => {
                    gdb_debug!(
                        self,
                        "process_one: recv_packet ok len={} prefix=\"{}\"",
                        len,
                        debug_printable_prefix(&buf[..len])
                    );
                    break len;
                }
                Ok(None) => {
                    gdb_debug!(self, "process_one: recv_packet returned None");
                    continue;
                }
                Err(GdbError::PacketTooLong) => {
                    gdb_debug!(self, "process_one: PacketTooLong (MAX_PKT={})", MAX_PKT);
                    continue;
                }
                Err(GdbError::MalformedPacket) => {
                    gdb_debug!(self, "process_one: MalformedPacket");
                    continue;
                }
                Err(other) => {
                    gdb_debug!(self, "process_one: fatal recv_packet error");
                    return Err(other);
                }
            }
        };
        let payload = &buf[..payload_len];

        gdb_debug!(
            self,
            "process_one: dispatch payload=\"{}\"",
            debug_printable_prefix(payload)
        );

        if payload == b"?" {
            self.send::<T>(b"S05")?;
            return Ok(ProcessResult::None);
        }

        match payload.first().copied() {
            Some(b'q') => {
                gdb_debug!(
                    self,
                    "dispatch: 'q' (query) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_query(target, payload)
            }
            Some(b'D') => {
                // Detach. Reply OK. If a monitor-exit was armed, finish the harness.
                gdb_debug!(self, "dispatch: 'D' (detach)");
                self.send_ok::<T>()?;
                if self.monitor_exit_armed {
                    self.monitor_exit_armed = false;
                    return Ok(ProcessResult::MonitorExit);
                }
                Ok(ProcessResult::None)
            }
            Some(b'k') => {
                // Kill. Reply OK (harmless even if client ignores it).
                // If a monitor-exit was armed, finish the harness.
                gdb_debug!(self, "dispatch: 'k' (kill)");
                self.send_ok::<T>()?;
                if self.monitor_exit_armed {
                    self.monitor_exit_armed = false;
                    return Ok(ProcessResult::MonitorExit);
                }
                Ok(ProcessResult::None)
            }
            Some(b'g') => {
                gdb_debug!(self, "dispatch: 'g' (read all registers)");
                self.handle_read_all_registers(target)
            }
            Some(b'G') => {
                gdb_debug!(self, "dispatch: 'G' (write all registers)");
                self.handle_write_all_registers(target, payload)
            }
            Some(b'p') => {
                gdb_debug!(
                    self,
                    "dispatch: 'p' (read single register) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_read_single_register(target, payload)
            }
            Some(b'P') => {
                gdb_debug!(
                    self,
                    "dispatch: 'P' (write single register) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_write_single_register(target, payload)
            }
            Some(b'm') => {
                gdb_debug!(
                    self,
                    "dispatch: 'm' (read memory) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_read_memory(target, payload)
            }
            Some(b'M') => {
                gdb_debug!(
                    self,
                    "dispatch: 'M' (write memory hex) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_write_memory_hex(target, payload)
            }
            Some(b'X') => {
                gdb_debug!(
                    self,
                    "dispatch: 'X' (write memory binary) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_write_memory_binary(target, payload)
            }
            Some(b'Z') => {
                gdb_debug!(
                    self,
                    "dispatch: 'Z' (insert breakpoint) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_breakpoint(target, payload, true)
            }
            Some(b'z') => {
                gdb_debug!(
                    self,
                    "dispatch: 'z' (remove breakpoint) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_breakpoint(target, payload, false)
            }
            Some(b'c') => {
                gdb_debug!(
                    self,
                    "dispatch: 'c' (continue) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_continue::<T>(payload)
            }
            Some(b's') => {
                gdb_debug!(
                    self,
                    "dispatch: 's' (step) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_step::<T>(payload)
            }
            Some(b'v') => {
                gdb_debug!(
                    self,
                    "dispatch: 'v' (v-packet) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_v_packet(target, payload)
            }
            _ => {
                gdb_debug!(
                    self,
                    "dispatch: unknown first byte {:?}, replying empty",
                    payload.first().copied()
                );
                self.send_empty::<T>()?;
                Ok(ProcessResult::None)
            }
        }
    }

    /// Run until a resume request or monitor-exit is received.
    pub fn run_until_event<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        loop {
            let result = self.process_one(target);
            match result {
                Ok(ProcessResult::None) => continue,
                Ok(event) => return Ok(event),
                Err(GdbError::PacketTooLong) | Err(GdbError::MalformedPacket) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Run until the monitor-exit sequence completes.
    ///
    /// The sequence is:
    /// 1) client sends `qRcmd "exit 0"` (server replies OK and arms an exit)
    /// 2) client sends `vKill` (or `D`/`k`), server replies OK and returns `MonitorExit`
    pub fn run_until_monitor_exit<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<(), GdbServerError<S, T>> {
        loop {
            match self.process_one(target) {
                Ok(ProcessResult::MonitorExit) => {
                    gdb_debug!(self, "run_until_monitor_exit: MonitorExit");
                    return Ok(());
                }
                Ok(ProcessResult::Resume(action)) => {
                    gdb_debug!(self, "run_until_monitor_exit: Resume {:?}", action);
                    self.send_empty::<T>()?;
                }
                Ok(ProcessResult::None) => {
                    gdb_debug!(self, "run_until_monitor_exit: ProcessResult::None");
                }
                Err(GdbError::PacketTooLong) => {
                    gdb_debug!(self, "run_until_monitor_exit: PacketTooLong (ignored)");
                }
                Err(GdbError::MalformedPacket) => {
                    gdb_debug!(self, "run_until_monitor_exit: MalformedPacket (ignored)");
                }
                Err(e) => {
                    gdb_debug!(self, "run_until_monitor_exit: fatal error");
                    return Err(e);
                }
            };
        }
    }

    fn reply_recoverable<T: Target>(
        &mut self,
        target: &T,
        e: &T::RecoverableError,
    ) -> Result<(), GdbServerError<S, T>> {
        let code = target.recoverable_error_code(e);
        let reply = [b'E', HEX[(code >> 4) as usize], HEX[(code & 0xF) as usize]];
        self.send::<T>(&reply)?;
        Ok(())
    }

    fn handle_target_err_core<T: Target, R>(
        &mut self,
        target: &T,
        result: Result<R, TargetErr<T>>,
    ) -> Result<Option<R>, GdbServerError<S, T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(TargetError::Recoverable(e)) => {
                self.reply_recoverable(target, &e)?;
                Ok(None)
            }
            Err(TargetError::NotSupported) => {
                self.send::<T>(b"E01")?;
                Ok(None)
            }
            Err(TargetError::Unrecoverable(e)) => {
                Err(GdbError::Target(TargetError::Unrecoverable(e)))
            }
        }
    }

    fn handle_target_err_optional<T: Target>(
        &mut self,
        target: &T,
        result: Result<(), TargetErr<T>>,
    ) -> Result<bool, GdbServerError<S, T>> {
        match result {
            Ok(()) => Ok(false),
            Err(TargetError::NotSupported) => {
                self.send_empty::<T>()?;
                Ok(true)
            }
            Err(TargetError::Recoverable(e)) => {
                self.reply_recoverable(target, &e)?;
                Ok(true)
            }
            Err(TargetError::Unrecoverable(e)) => {
                Err(GdbError::Target(TargetError::Unrecoverable(e)))
            }
        }
    }

    fn handle_query<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        gdb_debug!(
            self,
            "handle_query: payload=\"{}\"",
            debug_printable_prefix(payload)
        );
        if payload.starts_with(b"qSupported") {
            gdb_debug!(self, "handle_query: qSupported");
            // A new handshake implies a new session. Clear any stale monitor-exit state.
            self.monitor_exit_armed = false;

            let caps = target.capabilities();
            let mut reply = [0u8; 128];
            let mut idx = 0usize;
            append_bytes(&mut reply, &mut idx, b"PacketSize=");
            append_hex_u64(&mut reply, &mut idx, MAX_PKT as u64);
            append_bytes(&mut reply, &mut idx, b";vMustReplyEmpty+;vFlash+");
            if caps.contains(TargetCapabilities::SW_BREAK) {
                append_bytes(&mut reply, &mut idx, b";swbreak+");
            } else {
                append_bytes(&mut reply, &mut idx, b";swbreak-");
            }
            if caps.contains(TargetCapabilities::HW_BREAK) {
                append_bytes(&mut reply, &mut idx, b";hwbreak+");
            } else {
                append_bytes(&mut reply, &mut idx, b";hwbreak-");
            }
            if caps.contains(TargetCapabilities::VCONT) {
                append_bytes(&mut reply, &mut idx, b";vContSupported+");
            } else {
                append_bytes(&mut reply, &mut idx, b";vContSupported-");
            }
            self.send::<T>(&reply[..idx])?;
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"qRcmd,") {
            gdb_debug!(
                self,
                "handle_query: qRcmd raw=\"{}\"",
                debug_printable_prefix(rest)
            );
            let mut decoded = [0u8; 64];
            let decoded_len = match hex_decode(rest, &mut decoded) {
                Ok(len) => len,
                Err(_) => {
                    gdb_debug!(
                        self,
                        "handle_query: qRcmd hex decode failed src_len={} dst_cap={}",
                        rest.len(),
                        decoded.len()
                    );
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            let text = match core::str::from_utf8(&decoded[..decoded_len]) {
                Ok(t) => t,
                Err(_) => {
                    gdb_debug!(self, "handle_query: qRcmd utf8 decode failed");
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            gdb_debug!(
                self,
                "handle_query: qRcmd decoded=\"{}\"",
                debug_printable_prefix(text.as_bytes())
            );
            if text.trim() == "exit 0" {
                self.send_ok::<T>()?;
                // Do NOT terminate immediately: GDB typically sends `vKill` (or `D`)
                // after this command as part of its shutdown path. Exiting here makes
                // the transport disappear mid-teardown (Broken pipe).
                self.monitor_exit_armed = true;
                return Ok(ProcessResult::None);
            }
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }

        gdb_debug!(self, "handle_query: unknown query, replying empty");
        self.send_empty::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_read_all_registers<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let mut regs = [0u8; MAX_PKT];
        let result = target.read_registers(&mut regs);
        let len = match self.handle_target_err_core(target, result)? {
            Some(len) => len,
            None => return Ok(ProcessResult::None),
        };
        gdb_debug!(self, "handle_read_all_registers: total_len={} bytes", len);

        let expected_hex_len = len.saturating_mul(2);
        if expected_hex_len > MAX_PKT {
            gdb_debug!(
                self,
                "handle_read_all_registers: response too large hex_len={} MAX_PKT={}",
                expected_hex_len,
                MAX_PKT
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        let mut out = [0u8; MAX_PKT];
        let hex_len = hex_encode(&regs[..len], &mut out);
        if hex_len < expected_hex_len {
            gdb_debug!(
                self,
                "handle_read_all_registers: hex_encode truncated expected={} actual={}",
                expected_hex_len,
                hex_len
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        self.send::<T>(&out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_all_registers<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let data_hex = &payload[1..];
        gdb_debug!(
            self,
            "handle_write_all_registers: payload_len={} hex_len={}",
            payload.len(),
            data_hex.len()
        );
        let mut regs = [0u8; MAX_PKT];
        let Ok(len) = hex_decode(data_hex, &mut regs) else {
            gdb_debug!(
                self,
                "handle_write_all_registers: hex decode failed src_len={} dst_cap={}",
                data_hex.len(),
                regs.len()
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        };
        gdb_debug!(self, "handle_write_all_registers: decoded_len={}", len);
        let result = target.write_registers(&regs[..len]);
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }
        self.send_ok::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_read_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let regno = match parse_hex_u32(&payload[1..]) {
            Some(r) => r,
            None => {
                gdb_debug!(self, "handle_read_single_register: bad regno payload");
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        gdb_debug!(self, "handle_read_single_register: regno={}", regno);

        let mut reg = [0u8; MAX_PKT];
        let result = target.read_register(regno, &mut reg);
        let len = match self.handle_target_err_core(target, result)? {
            Some(len) => len,
            None => return Ok(ProcessResult::None),
        };
        let expected_hex_len = len.saturating_mul(2);
        if expected_hex_len > MAX_PKT {
            gdb_debug!(
                self,
                "handle_read_single_register: response too large regno={} hex_len={}",
                regno,
                expected_hex_len
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        let mut out = [0u8; MAX_PKT];
        let hex_len = hex_encode(&reg[..len], &mut out);
        if hex_len < expected_hex_len {
            gdb_debug!(
                self,
                "handle_read_single_register: hex_encode truncated regno={} expected={} actual={}",
                regno,
                expected_hex_len,
                hex_len
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        self.send::<T>(&out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let body = &payload[1..];
        let Some(eq_pos) = body.iter().position(|&b| b == b'=') else {
            gdb_debug!(self, "handle_write_single_register: missing '=' separator");
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        };
        let regno_hex = &body[..eq_pos];
        let val_hex = &body[eq_pos + 1..];

        let regno = match parse_hex_u32(regno_hex) {
            Some(r) => r,
            None => {
                gdb_debug!(
                    self,
                    "handle_write_single_register: bad regno payload=\"{}\"",
                    debug_printable_prefix(regno_hex)
                );
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        gdb_debug!(
            self,
            "handle_write_single_register: regno={} val_hex_len={}",
            regno,
            val_hex.len()
        );

        let mut reg = [0u8; MAX_PKT];
        let Ok(len) = hex_decode(val_hex, &mut reg) else {
            gdb_debug!(
                self,
                "handle_write_single_register: hex decode failed src_len={} dst_cap={}",
                val_hex.len(),
                reg.len()
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        };

        gdb_debug!(
            self,
            "handle_write_single_register: decoded_len={} regno={}",
            len,
            regno
        );
        let result = target.write_register(regno, &reg[..len]);
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }
        self.send_ok::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_read_memory<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let (addr, len) =
            match parse_addr_len::<S::Error, T::RecoverableError, T::UnrecoverableError>(payload) {
                Ok(v) => v,
                Err(_) => {
                    gdb_debug!(self, "handle_read_memory: parse_addr_len failed");
                    self.send::<T>(b"E02")?;
                    return Ok(ProcessResult::None);
                }
            };
        gdb_debug!(self, "handle_read_memory: addr=0x{:x} len={}", addr, len);
        if addr.checked_add(len).is_none() {
            // Workaround for a GDB bug that can send wrapped "m" packets like "$mfffffffffffffffc,4#...".
            // If the address+length overflows, treat it as EFAULT (14) and keep the session running.
            gdb_debug!(self, "handle_read_memory: overflow addr+len -> E14");
            self.send::<T>(b"E14")?;
            return Ok(ProcessResult::None);
        }
        let len_usize = match usize::try_from(len) {
            Ok(v) => v,
            Err(_) => {
                gdb_debug!(self, "handle_read_memory: length conversion failed");
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }
        };
        if len_usize > MAX_PKT {
            gdb_debug!(
                self,
                "handle_read_memory: len_usize {} exceeds MAX_PKT {}, sending E01",
                len_usize,
                MAX_PKT
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }

        let expected_hex_len = len_usize.saturating_mul(2);
        if expected_hex_len > MAX_PKT {
            gdb_debug!(
                self,
                "handle_read_memory: hex response too large hex_len={} MAX_PKT={}",
                expected_hex_len,
                MAX_PKT
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }

        let mut data = [0u8; MAX_PKT];
        let result = target.read_memory(addr, &mut data[..len_usize]);
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }

        let mut out = [0u8; MAX_PKT];
        let hex_len = hex_encode(&data[..len_usize], &mut out);
        if hex_len < expected_hex_len {
            gdb_debug!(
                self,
                "handle_read_memory: hex_encode truncated expected={} actual={}",
                expected_hex_len,
                hex_len
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        self.send::<T>(&out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_hex<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            gdb_debug!(self, "handle_write_memory_hex: missing ':' separator");
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let data_hex = &payload[colon + 1..];

        let (addr, len) =
            match parse_addr_len::<S::Error, T::RecoverableError, T::UnrecoverableError>(header) {
                Ok(v) => v,
                Err(_) => {
                    gdb_debug!(self, "handle_write_memory_hex: parse_addr_len failed");
                    self.send::<T>(b"E02")?;
                    return Ok(ProcessResult::None);
                }
            };
        gdb_debug!(
            self,
            "handle_write_memory_hex: addr=0x{:x} len={}",
            addr,
            len
        );

        let mut data = [0u8; MAX_PKT];
        let Ok(decoded) = hex_decode(data_hex, &mut data) else {
            gdb_debug!(
                self,
                "handle_write_memory_hex: hex decode failed src_len={} dst_cap={}",
                data_hex.len(),
                data.len()
            );
            self.send::<T>(b"E03")?;
            return Ok(ProcessResult::None);
        };
        if decoded as u64 != len {
            gdb_debug!(
                self,
                "handle_write_memory_hex: decoded_len {} != header_len {}",
                decoded,
                len
            );
            self.send::<T>(b"E03")?;
            return Ok(ProcessResult::None);
        }

        let result = target.write_memory(addr, &data[..decoded]);
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }
        self.send_ok::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_binary<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            gdb_debug!(self, "handle_write_memory_binary: missing ':' separator");
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let binary = &payload[colon + 1..];

        let (addr, len) =
            match parse_addr_len::<S::Error, T::RecoverableError, T::UnrecoverableError>(header) {
                Ok(v) => v,
                Err(_) => {
                    gdb_debug!(self, "handle_write_memory_binary: parse_addr_len failed");
                    self.send::<T>(b"E02")?;
                    return Ok(ProcessResult::None);
                }
            };
        gdb_debug!(
            self,
            "handle_write_memory_binary: addr=0x{:x} len={}",
            addr,
            len
        );

        let mut decoded = [0u8; MAX_PKT];
        let Ok(decoded_len) = decode_rsp_binary(binary, &mut decoded) else {
            // Malformed escape or output buffer overflow.
            gdb_debug!(
                self,
                "handle_write_memory_binary: binary decode failed src_len={} dst_cap={}",
                binary.len(),
                decoded.len()
            );
            self.send::<T>(b"E03")?;
            return Ok(ProcessResult::None);
        };

        if decoded_len as u64 != len {
            gdb_debug!(
                self,
                "handle_write_memory_binary: decoded_len {} != header_len {}",
                decoded_len,
                len
            );
            self.send::<T>(b"E03")?;
            return Ok(ProcessResult::None);
        }

        let result = target.write_memory(addr, &decoded[..decoded_len]);
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }
        self.send_ok::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_breakpoint<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
        insert: bool,
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let caps = target.capabilities();
        let body = payload.get(1..).unwrap_or(&[]);
        let mut parts = body.splitn(3, |&b| b == b',');
        let type_bytes = parts.next().unwrap_or(&[]);
        let addr_hex = parts.next().unwrap_or(&[]);
        let kind_hex = parts.next().unwrap_or(&[]);

        if type_bytes.is_empty() || addr_hex.is_empty() || kind_hex.is_empty() {
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        }

        let Some(bp_type) = parse_dec_u8(type_bytes) else {
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };
        let Some(addr) = parse_hex_u64(addr_hex) else {
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };
        let Some(len_or_kind) = parse_hex_u64(kind_hex) else {
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };

        let result = match bp_type {
            0 => {
                if !caps.contains(TargetCapabilities::SW_BREAK) {
                    self.send_empty::<T>()?;
                    return Ok(ProcessResult::None);
                }
                if insert {
                    target.insert_sw_breakpoint(addr)
                } else {
                    target.remove_sw_breakpoint(addr)
                }
            }
            1 => {
                if !caps.contains(TargetCapabilities::HW_BREAK) {
                    self.send_empty::<T>()?;
                    return Ok(ProcessResult::None);
                }
                if insert {
                    target.insert_hw_breakpoint(addr, len_or_kind)
                } else {
                    target.remove_hw_breakpoint(addr, len_or_kind)
                }
            }
            2 => {
                if !caps.contains(TargetCapabilities::WATCH_W) {
                    self.send_empty::<T>()?;
                    return Ok(ProcessResult::None);
                }
                if insert {
                    target.insert_watchpoint(WatchpointKind::Write, addr, len_or_kind)
                } else {
                    target.remove_watchpoint(WatchpointKind::Write, addr, len_or_kind)
                }
            }
            3 => {
                if !caps.contains(TargetCapabilities::WATCH_R) {
                    self.send_empty::<T>()?;
                    return Ok(ProcessResult::None);
                }
                if insert {
                    target.insert_watchpoint(WatchpointKind::Read, addr, len_or_kind)
                } else {
                    target.remove_watchpoint(WatchpointKind::Read, addr, len_or_kind)
                }
            }
            4 => {
                if !caps.contains(TargetCapabilities::WATCH_A) {
                    self.send_empty::<T>()?;
                    return Ok(ProcessResult::None);
                }
                if insert {
                    target.insert_watchpoint(WatchpointKind::Access, addr, len_or_kind)
                } else {
                    target.remove_watchpoint(WatchpointKind::Access, addr, len_or_kind)
                }
            }
            _ => {
                self.send_empty::<T>()?;
                return Ok(ProcessResult::None);
            }
        };

        if self.handle_target_err_optional(target, result)? {
            return Ok(ProcessResult::None);
        }

        self.send_ok::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_continue<T: Target>(
        &mut self,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let new_pc = if payload.len() > 1 {
            match parse_hex_u64(&payload[1..]) {
                Some(addr) => Some(addr),
                None => {
                    gdb_debug!(self, "handle_continue: bad pc payload");
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            }
        } else {
            None
        };
        gdb_debug!(self, "handle_continue: Resume Continue pc={:#x?}", new_pc);
        Ok(ProcessResult::Resume(ResumeAction::Continue(new_pc)))
    }

    fn handle_step<T: Target>(
        &mut self,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        let new_pc = if payload.len() > 1 {
            match parse_hex_u64(&payload[1..]) {
                Some(addr) => Some(addr),
                None => {
                    gdb_debug!(self, "handle_step: bad pc payload");
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            }
        } else {
            None
        };
        gdb_debug!(self, "handle_step: Resume Step pc={:#x?}", new_pc);
        Ok(ProcessResult::Resume(ResumeAction::Step(new_pc)))
    }

    fn handle_v_packet<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<S, T>> {
        gdb_debug!(
            self,
            "handle_v_packet: payload=\"{}\"",
            debug_printable_prefix(payload)
        );
        // GDB sends `vKill;...` during shutdown (`quit`). Reply OK so GDB can complete
        // teardown. If `monitor exit 0` was armed, finish the harness now.
        if payload.starts_with(b"vKill") {
            gdb_debug!(self, "handle_v_packet: vKill");
            self.send_ok::<T>()?;
            if self.monitor_exit_armed {
                self.monitor_exit_armed = false;
                return Ok(ProcessResult::MonitorExit);
            }
            return Ok(ProcessResult::None);
        }
        if payload == b"vCont?" {
            if target.capabilities().contains(TargetCapabilities::VCONT) {
                self.send::<T>(b"vCont;c;s")?;
            } else {
                self.send_empty::<T>()?;
            }
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"vCont;") {
            if !target.capabilities().contains(TargetCapabilities::VCONT) {
                self.send_empty::<T>()?;
                return Ok(ProcessResult::None);
            }
            let action = rest.split(|&b| b == b';').next().unwrap_or(&[]);
            let Some((&action_byte, action_tail)) = action.split_first() else {
                self.send_empty::<T>()?;
                return Ok(ProcessResult::None);
            };
            if !action_tail.is_empty() {
                if action_tail[0] != b':' {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            }
            return match action_byte {
                b'c' => Ok(ProcessResult::Resume(ResumeAction::Continue(None))),
                b's' => Ok(ProcessResult::Resume(ResumeAction::Step(None))),
                _ => {
                    self.send_empty::<T>()?;
                    Ok(ProcessResult::None)
                }
            };
        }

        if payload == b"vFlashDone" {
            gdb_debug!(self, "handle_v_packet: vFlashDone");
            self.send_ok::<T>()?;
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"vFlashErase:") {
            if let Some((addr, len)) = parse_flash_header(rest) {
                gdb_debug!(
                    self,
                    "handle_v_packet: vFlashErase addr=0x{:x} len={}",
                    addr,
                    len
                );
                self.send_ok::<T>()?;
            } else {
                gdb_debug!(self, "handle_v_packet: vFlashErase parse failed");
                self.send::<T>(b"E02")?;
            }
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"vFlashWrite:") {
            let Some(colon) = rest.iter().position(|&b| b == b':') else {
                gdb_debug!(self, "handle_v_packet: vFlashWrite missing ':'");
                self.send::<T>(b"E02")?;
                return Ok(ProcessResult::None);
            };
            let header = &rest[..colon];
            let data = &rest[colon + 1..];

            let Some((addr, len)) = parse_flash_header(header) else {
                gdb_debug!(self, "handle_v_packet: vFlashWrite parse failed");
                self.send::<T>(b"E02")?;
                return Ok(ProcessResult::None);
            };
            gdb_debug!(
                self,
                "handle_v_packet: vFlashWrite addr=0x{:x} len={}",
                addr,
                len
            );

            if len as usize > MAX_PKT {
                gdb_debug!(
                    self,
                    "handle_v_packet: vFlashWrite len {} exceeds MAX_PKT {}",
                    len,
                    MAX_PKT
                );
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }

            let mut decoded = [0u8; MAX_PKT];
            let Ok(decoded_len) = decode_rsp_binary(data, &mut decoded) else {
                gdb_debug!(
                    self,
                    "handle_v_packet: vFlashWrite decode failed src_len={} dst_cap={}",
                    data.len(),
                    decoded.len()
                );
                self.send::<T>(b"E03")?;
                return Ok(ProcessResult::None);
            };

            if decoded_len as u64 != len {
                gdb_debug!(
                    self,
                    "handle_v_packet: vFlashWrite decoded_len {} != header_len {}",
                    decoded_len,
                    len
                );
                self.send::<T>(b"E03")?;
                return Ok(ProcessResult::None);
            }

            let result = target.write_memory(addr, &decoded[..decoded_len]);
            if self.handle_target_err_core(target, result)?.is_none() {
                return Ok(ProcessResult::None);
            }
            self.send_ok::<T>()?;
            return Ok(ProcessResult::None);
        }

        self.send_empty::<T>()?;
        Ok(ProcessResult::None)
    }
}

#[cfg(feature = "gdb_monitor_debug")]
struct DebugBufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

#[cfg(feature = "gdb_monitor_debug")]
impl<'a> fmt::Write for DebugBufWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.pos);
        if remaining == 0 {
            return Ok(());
        }
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}

const DEBUG_PRINTABLE_BUF: usize = 64;
const DEBUG_PRINTABLE_TRUNC: usize = 48;

struct DebugPrintable {
    buf: [u8; DEBUG_PRINTABLE_BUF],
    len: usize,
}

impl DebugPrintable {
    fn new(data: &[u8]) -> Self {
        let mut buf = [0u8; DEBUG_PRINTABLE_BUF];
        let mut len = 0usize;
        let limit = DEBUG_PRINTABLE_TRUNC.min(DEBUG_PRINTABLE_BUF);

        for &b in data.iter().take(limit) {
            if len >= buf.len() {
                break;
            }
            buf[len] = match b {
                0x20..=0x7e => b,
                _ => b'.',
            };
            len += 1;
        }

        if data.len() > limit {
            for &ch in b"..." {
                if len >= buf.len() {
                    break;
                }
                buf[len] = ch;
                len += 1;
            }
        }

        Self { buf, len }
    }
}

fn debug_printable_prefix(data: &[u8]) -> DebugPrintable {
    DebugPrintable::new(data)
}

impl fmt::Display for DebugPrintable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Buffer only contains printable ASCII.
        // SAFETY: DebugPrintable::new only writes ASCII bytes into the buffer.
        let s = unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) };
        f.write_str(s)
    }
}

/// Receive a single RSP packet into `buf`, returning the payload length.
/// If a Ctrl-C (0x03) is observed, a stop reply is sent and `None` is returned.
pub fn recv_packet<S: ByteStream, const N: usize, R, U>(
    stream: &S,
    buf: &mut [u8; N],
) -> Result<Option<usize>, GdbError<S::Error, R, U>> {
    // Wait for '$' start marker.
    loop {
        let byte = stream.read_blocking().map_err(GdbError::Stream)?;
        match byte {
            b'$' => break,
            0x03 => {
                // Ctrl-C interrupt.
                send_packet::<_, R, U>(stream, b"S05")?;
                return Ok(None);
            }
            _ => {}
        }
    }

    let mut idx = 0usize;
    loop {
        let byte = stream.read_blocking().map_err(GdbError::Stream)?;
        match byte {
            b'#' => break,
            b => {
                if idx < buf.len() {
                    buf[idx] = b;
                }
                idx = idx.saturating_add(1);
            }
        }
    }

    let mut checksum_bytes = [0u8; 2];
    for slot in checksum_bytes.iter_mut() {
        *slot = stream.read_blocking().map_err(GdbError::Stream)?;
    }

    if idx > buf.len() {
        // Consume overlong packet, send NAK, and signal an error.
        stream.write_blocking(b'-').map_err(GdbError::Stream)?;
        return Err(GdbError::PacketTooLong);
    }

    let mut checksum_calc: u8 = 0;
    for &b in &buf[..idx] {
        checksum_calc = checksum_calc.wrapping_add(b);
    }

    let high = from_hex_digit(checksum_bytes[0]).map_err(|_| GdbError::MalformedPacket)?;
    let low = from_hex_digit(checksum_bytes[1]).map_err(|_| GdbError::MalformedPacket)?;
    let checksum_recv = (high << 4) | low;

    if checksum_calc == checksum_recv {
        stream.write_blocking(b'+').map_err(GdbError::Stream)?;
        Ok(Some(idx))
    } else {
        stream.write_blocking(b'-').map_err(GdbError::Stream)?;
        Err(GdbError::MalformedPacket)
    }
}

/// Send an RSP packet containing `payload`.
pub fn send_packet<S: ByteStream, R, U>(
    stream: &S,
    payload: &[u8],
) -> Result<(), GdbError<S::Error, R, U>> {
    let mut checksum: u8 = 0;
    for &b in payload {
        checksum = checksum.wrapping_add(b);
    }

    stream.write_blocking(b'$').map_err(GdbError::Stream)?;
    stream
        .write_all_blocking(payload)
        .map_err(GdbError::Stream)?;
    stream.write_blocking(b'#').map_err(GdbError::Stream)?;
    stream
        .write_blocking(HEX[(checksum >> 4) as usize])
        .map_err(GdbError::Stream)?;
    stream
        .write_blocking(HEX[(checksum & 0xF) as usize])
        .map_err(GdbError::Stream)?;
    stream.flush().map_err(GdbError::Stream)?;
    Ok(())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn from_hex_digit(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(()),
    }
}

fn parse_hex_u64(buf: &[u8]) -> Option<u64> {
    if buf.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    for &b in buf {
        let digit = from_hex_digit(b).ok()? as u64;
        val = val.checked_mul(16)?;
        val = val.checked_add(digit)?;
    }
    Some(val)
}

fn parse_hex_u32(buf: &[u8]) -> Option<u32> {
    parse_hex_u64(buf).and_then(|v| u32::try_from(v).ok())
}

fn parse_dec_u8(buf: &[u8]) -> Option<u8> {
    if buf.is_empty() {
        return None;
    }
    let mut val: u32 = 0;
    for &b in buf {
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        val = val.checked_mul(10)?;
        val = val.checked_add((b - b'0') as u32)?;
        if val > u8::MAX as u32 {
            return None;
        }
    }
    Some(val as u8)
}

fn parse_flash_header(buf: &[u8]) -> Option<(u64, u64)> {
    let mut parts = buf.splitn(2, |&b| b == b',');
    let addr = parse_hex_u64(parts.next()?)?;
    let len = parse_hex_u64(parts.next()?)?;
    Some((addr, len))
}

fn parse_addr_len<SE, R, U>(payload: &[u8]) -> Result<(u64, u64), GdbError<SE, R, U>> {
    let body = payload.get(1..).ok_or(GdbError::MalformedPacket)?;
    let Some(comma) = body.iter().position(|&b| b == b',') else {
        return Err(GdbError::MalformedPacket);
    };
    let addr_hex = &body[..comma];
    let len_hex = &body[comma + 1..];
    let addr = parse_hex_u64(addr_hex).ok_or(GdbError::MalformedPacket)?;
    let len = parse_hex_u64(len_hex).ok_or(GdbError::MalformedPacket)?;
    Ok((addr, len))
}

fn append_bytes(buf: &mut [u8], idx: &mut usize, src: &[u8]) {
    let end = idx.saturating_add(src.len());
    if end > buf.len() {
        return;
    }
    buf[*idx..end].copy_from_slice(src);
    *idx = end;
}

fn append_hex_u64(buf: &mut [u8], idx: &mut usize, mut val: u64) {
    let mut tmp = [0u8; 16];
    let mut len = 0usize;

    if val == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while val != 0 {
            let digit = (val & 0xF) as usize;
            tmp[len] = HEX[digit];
            len += 1;
            val >>= 4;
        }
    }

    let end = idx.saturating_add(len);
    if end > buf.len() {
        return;
    }

    for i in 0..len {
        buf[*idx + i] = tmp[len - 1 - i];
    }
    *idx = end;
}

fn hex_encode(src: &[u8], dst: &mut [u8]) -> usize {
    let mut idx = 0usize;
    for &b in src {
        if idx + 2 > dst.len() {
            break;
        }
        dst[idx] = HEX[(b >> 4) as usize];
        dst[idx + 1] = HEX[(b & 0xF) as usize];
        idx += 2;
    }
    idx
}

/// Decode ASCII hex in `src` into raw bytes in `dst`.
/// Returns decoded length on success.
pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, ()> {
    if src.len() % 2 != 0 {
        return Err(());
    }
    let mut out = 0usize;
    for chunk in src.chunks_exact(2) {
        if out >= dst.len() {
            return Err(());
        }
        let hi = from_hex_digit(chunk[0])?;
        let lo = from_hex_digit(chunk[1])?;
        dst[out] = (hi << 4) | lo;
        out += 1;
    }
    Ok(out)
}

/// Decode RSP binary data (with 0x7d escaping) into `dst`.
/// Returns decoded length on success.
fn decode_rsp_binary(src: &[u8], dst: &mut [u8]) -> Result<usize, ()> {
    let mut in_idx = 0usize;
    let mut out_idx = 0usize;

    while in_idx < src.len() {
        if out_idx >= dst.len() {
            return Err(());
        }

        let b = src[in_idx];
        if b == b'}' {
            in_idx += 1;
            if in_idx >= src.len() {
                return Err(());
            }
            dst[out_idx] = src[in_idx] ^ 0x20;
        } else {
            dst[out_idx] = b;
        }

        in_idx += 1;
        out_idx += 1;
    }

    Ok(out_idx)
}
