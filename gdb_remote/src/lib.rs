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

/// Errors that can occur while speaking the GDB Remote Serial Protocol.
#[derive(Debug)]
pub enum GdbError<SE, TE> {
    /// Underlying stream error.
    Stream(SE),
    /// Target-specific error.
    Target(TE),
    /// Received packet exceeded the provided buffer.
    PacketTooLong,
    /// Packet framing or checksum was invalid.
    MalformedPacket,
}

impl<SE, TE> From<SE> for GdbError<SE, TE> {
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
    /// Special-case monitor exit used by the UEFI test harness.
    MonitorExit,
}

/// Minimal GDB RSP server operating on a byte stream.
///
/// The server logic uses blocking helpers and is not IRQ-safe.
pub struct GdbServer<S: ByteStream, const MAX_PKT: usize> {
    stream: S,
}

impl<S: ByteStream, const MAX_PKT: usize> GdbServer<S, MAX_PKT> {
    /// Create a new server wrapping the provided stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
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

        let _ = send_packet::<S, ()>(&self.stream, &payload[..total_len]);
    }

    #[cfg(not(feature = "gdb_monitor_debug"))]
    pub fn debug_console_fmt(&mut self, _args: fmt::Arguments<'_>) {
        let _ = _args;
    }

    /// Process a single incoming packet.
    pub fn process_one<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let mut buf = [0u8; MAX_PKT];
        let payload_len = loop {
            match recv_packet::<_, MAX_PKT, T::Error>(&self.stream, &mut buf) {
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
            send_packet::<_, T::Error>(&self.stream, b"S05")?;
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
                send_packet::<_, T::Error>(&self.stream, b"")?;
                Ok(ProcessResult::None)
            }
        }
    }

    /// Run until a resume request or monitor-exit is received.
    pub fn run_until_event<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
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

    /// Run until a qRcmd "exit 0" request is received.
    pub fn run_until_monitor_exit<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<(), GdbError<S::Error, T::Error>> {
        loop {
            match self.process_one(target) {
                Ok(ProcessResult::MonitorExit) => {
                    gdb_debug!(self, "run_until_monitor_exit: MonitorExit");
                    return Ok(());
                }
                Ok(ProcessResult::Resume(action)) => {
                    gdb_debug!(self, "run_until_monitor_exit: Resume {:?}", action);
                    send_packet::<_, T::Error>(&self.stream, b"")?;
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

    fn handle_query<T: Target>(
        &mut self,
        _target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        gdb_debug!(
            self,
            "handle_query: payload=\"{}\"",
            debug_printable_prefix(payload)
        );
        if payload.starts_with(b"qSupported") {
            gdb_debug!(self, "handle_query: qSupported");
            send_packet::<_, T::Error>(
                &self.stream,
                b"PacketSize=400;swbreak+;hwbreak-;vMustReplyEmpty+;vFlash+",
            )?;
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
                    send_packet::<_, T::Error>(&self.stream, b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            let text = match core::str::from_utf8(&decoded[..decoded_len]) {
                Ok(t) => t,
                Err(_) => {
                    gdb_debug!(self, "handle_query: qRcmd utf8 decode failed");
                    send_packet::<_, T::Error>(&self.stream, b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            gdb_debug!(
                self,
                "handle_query: qRcmd decoded=\"{}\"",
                debug_printable_prefix(text.as_bytes())
            );
            if text.trim() == "exit 0" {
                send_packet::<_, T::Error>(&self.stream, b"OK")?;
                return Ok(ProcessResult::MonitorExit);
            }
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }

        gdb_debug!(self, "handle_query: unknown query, replying empty");
        send_packet::<_, T::Error>(&self.stream, b"")?;
        Ok(ProcessResult::None)
    }

    fn handle_read_all_registers<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let mut regs = [0u8; MAX_PKT];
        let len = target.read_registers(&mut regs).map_err(GdbError::Target)?;
        gdb_debug!(self, "handle_read_all_registers: total_len={} bytes", len);

        let expected_hex_len = len.saturating_mul(2);
        if expected_hex_len > MAX_PKT {
            gdb_debug!(
                self,
                "handle_read_all_registers: response too large hex_len={} MAX_PKT={}",
                expected_hex_len,
                MAX_PKT
            );
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }
        send_packet::<_, T::Error>(&self.stream, &out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_all_registers<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
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
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };
        gdb_debug!(self, "handle_write_all_registers: decoded_len={}", len);
        target
            .write_registers(&regs[..len])
            .map_err(GdbError::Target)?;
        send_packet::<_, T::Error>(&self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_read_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let regno = match parse_hex_u32(&payload[1..]) {
            Some(r) => r,
            None => {
                gdb_debug!(self, "handle_read_single_register: bad regno payload");
                send_packet::<_, T::Error>(&self.stream, b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        gdb_debug!(self, "handle_read_single_register: regno={}", regno);

        let mut reg = [0u8; MAX_PKT];
        let len = target
            .read_register(regno, &mut reg)
            .map_err(GdbError::Target)?;
        let expected_hex_len = len.saturating_mul(2);
        if expected_hex_len > MAX_PKT {
            gdb_debug!(
                self,
                "handle_read_single_register: response too large regno={} hex_len={}",
                regno,
                expected_hex_len
            );
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }
        send_packet::<_, T::Error>(&self.stream, &out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let body = &payload[1..];
        let Some(eq_pos) = body.iter().position(|&b| b == b'=') else {
            gdb_debug!(self, "handle_write_single_register: missing '=' separator");
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
                send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };

        gdb_debug!(
            self,
            "handle_write_single_register: decoded_len={} regno={}",
            len,
            regno
        );
        target
            .write_register(regno, &reg[..len])
            .map_err(GdbError::Target)?;
        send_packet::<_, T::Error>(&self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_read_memory<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let (addr, len) = match parse_addr_len::<S::Error, T::Error>(payload) {
            Ok(v) => v,
            Err(_) => {
                gdb_debug!(self, "handle_read_memory: parse_addr_len failed");
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
                return Ok(ProcessResult::None);
            }
        };
        gdb_debug!(self, "handle_read_memory: addr=0x{:x} len={}", addr, len);
        if addr.checked_add(len).is_none() {
            // Workaround for a GDB bug that can send wrapped "m" packets like "$mfffffffffffffffc,4#...".
            // If the address+length overflows, treat it as EFAULT (14) and keep the session running.
            gdb_debug!(self, "handle_read_memory: overflow addr+len -> E14");
            send_packet::<_, T::Error>(&self.stream, b"E14")?;
            return Ok(ProcessResult::None);
        }
        let len_usize = match usize::try_from(len) {
            Ok(v) => v,
            Err(_) => {
                gdb_debug!(self, "handle_read_memory: length conversion failed");
                send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }

        let mut data = [0u8; MAX_PKT];
        target
            .read_memory(addr, &mut data[..len_usize])
            .map_err(GdbError::Target)?;

        let mut out = [0u8; MAX_PKT];
        let hex_len = hex_encode(&data[..len_usize], &mut out);
        if hex_len < expected_hex_len {
            gdb_debug!(
                self,
                "handle_read_memory: hex_encode truncated expected={} actual={}",
                expected_hex_len,
                hex_len
            );
            send_packet::<_, T::Error>(&self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }
        send_packet::<_, T::Error>(&self.stream, &out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_hex<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            gdb_debug!(self, "handle_write_memory_hex: missing ':' separator");
            send_packet::<_, T::Error>(&self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let data_hex = &payload[colon + 1..];

        let (addr, len) = match parse_addr_len::<S::Error, T::Error>(header) {
            Ok(v) => v,
            Err(_) => {
                gdb_debug!(self, "handle_write_memory_hex: parse_addr_len failed");
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        };
        if decoded as u64 != len {
            gdb_debug!(
                self,
                "handle_write_memory_hex: decoded_len {} != header_len {}",
                decoded,
                len
            );
            send_packet::<_, T::Error>(&self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        }

        match target.write_memory(addr, &data[..decoded]) {
            Ok(()) => {}
            Err(e) => {
                gdb_debug!(self, "handle_write_memory_hex: target error");
                return Err(GdbError::Target(e));
            }
        }
        send_packet::<_, T::Error>(&self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_binary<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            gdb_debug!(self, "handle_write_memory_binary: missing ':' separator");
            send_packet::<_, T::Error>(&self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let binary = &payload[colon + 1..];

        let (addr, len) = match parse_addr_len::<S::Error, T::Error>(header) {
            Ok(v) => v,
            Err(_) => {
                gdb_debug!(self, "handle_write_memory_binary: parse_addr_len failed");
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
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
            send_packet::<_, T::Error>(&self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        };

        if decoded_len as u64 != len {
            gdb_debug!(
                self,
                "handle_write_memory_binary: decoded_len {} != header_len {}",
                decoded_len,
                len
            );
            send_packet::<_, T::Error>(&self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        }

        match target.write_memory(addr, &decoded[..decoded_len]) {
            Ok(()) => {}
            Err(e) => {
                gdb_debug!(self, "handle_write_memory_binary: target error");
                return Err(GdbError::Target(e));
            }
        }
        send_packet::<_, T::Error>(&self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_breakpoint<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
        insert: bool,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        if payload.len() < 2 || payload[1] != b'0' {
            send_packet::<_, T::Error>(&self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        }
        let mut body = &payload[2..];
        if let Some(stripped) = body.strip_prefix(&[b',']) {
            body = stripped;
        }
        let Some(comma) = body.iter().position(|&b| b == b',') else {
            send_packet::<_, T::Error>(&self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        };
        let addr_hex = &body[..comma];
        let addr = match parse_hex_u64(addr_hex) {
            Some(a) => a,
            None => {
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
                return Ok(ProcessResult::None);
            }
        };

        if insert {
            target
                .insert_sw_breakpoint(addr)
                .map_err(GdbError::Target)?;
        } else {
            target
                .remove_sw_breakpoint(addr)
                .map_err(GdbError::Target)?;
        }

        send_packet::<_, T::Error>(&self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_continue<T: Target>(
        &mut self,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let new_pc = if payload.len() > 1 {
            match parse_hex_u64(&payload[1..]) {
                Some(addr) => Some(addr),
                None => {
                    gdb_debug!(self, "handle_continue: bad pc payload");
                    send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let new_pc = if payload.len() > 1 {
            match parse_hex_u64(&payload[1..]) {
                Some(addr) => Some(addr),
                None => {
                    gdb_debug!(self, "handle_step: bad pc payload");
                    send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        gdb_debug!(
            self,
            "handle_v_packet: payload=\"{}\"",
            debug_printable_prefix(payload)
        );
        if payload == b"vFlashDone" {
            gdb_debug!(self, "handle_v_packet: vFlashDone");
            send_packet::<_, T::Error>(&self.stream, b"OK")?;
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
                send_packet::<_, T::Error>(&self.stream, b"OK")?;
            } else {
                gdb_debug!(self, "handle_v_packet: vFlashErase parse failed");
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
            }
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"vFlashWrite:") {
            let Some(colon) = rest.iter().position(|&b| b == b':') else {
                gdb_debug!(self, "handle_v_packet: vFlashWrite missing ':'");
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
                return Ok(ProcessResult::None);
            };
            let header = &rest[..colon];
            let data = &rest[colon + 1..];

            let Some((addr, len)) = parse_flash_header(header) else {
                gdb_debug!(self, "handle_v_packet: vFlashWrite parse failed");
                send_packet::<_, T::Error>(&self.stream, b"E02")?;
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
                send_packet::<_, T::Error>(&self.stream, b"E01")?;
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
                send_packet::<_, T::Error>(&self.stream, b"E03")?;
                return Ok(ProcessResult::None);
            };

            if decoded_len as u64 != len {
                gdb_debug!(
                    self,
                    "handle_v_packet: vFlashWrite decoded_len {} != header_len {}",
                    decoded_len,
                    len
                );
                send_packet::<_, T::Error>(&self.stream, b"E03")?;
                return Ok(ProcessResult::None);
            }

            match target.write_memory(addr, &decoded[..decoded_len]) {
                Ok(()) => {}
                Err(e) => {
                    gdb_debug!(self, "handle_v_packet: vFlashWrite target error");
                    return Err(GdbError::Target(e));
                }
            }
            send_packet::<_, T::Error>(&self.stream, b"OK")?;
            return Ok(ProcessResult::None);
        }

        send_packet::<_, T::Error>(&self.stream, b"")?;
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
        let s = unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) };
        f.write_str(s)
    }
}

/// Receive a single RSP packet into `buf`, returning the payload length.
/// If a Ctrl-C (0x03) is observed, a stop reply is sent and `None` is returned.
pub fn recv_packet<S: ByteStream, const N: usize, TE>(
    stream: &S,
    buf: &mut [u8; N],
) -> Result<Option<usize>, GdbError<S::Error, TE>> {
    // Wait for '$' start marker.
    loop {
        let byte = stream.read_blocking().map_err(GdbError::Stream)?;
        match byte {
            b'$' => break,
            0x03 => {
                // Ctrl-C interrupt.
                send_packet::<_, TE>(stream, b"S05")?;
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
pub fn send_packet<S: ByteStream, TE>(
    stream: &S,
    payload: &[u8],
) -> Result<(), GdbError<S::Error, TE>> {
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

fn parse_flash_header(buf: &[u8]) -> Option<(u64, u64)> {
    let mut parts = buf.splitn(2, |&b| b == b',');
    let addr = parse_hex_u64(parts.next()?)?;
    let len = parse_hex_u64(parts.next()?)?;
    Some((addr, len))
}

fn parse_addr_len<SE, TE>(payload: &[u8]) -> Result<(u64, u64), GdbError<SE, TE>> {
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
