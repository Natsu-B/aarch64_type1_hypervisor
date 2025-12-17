#![no_std]

use byte_stream::ByteStream;

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

/// Minimal GDB RSP server operating on a blocking byte stream.
pub struct GdbServer<S: ByteStream, const MAX_PKT: usize> {
    stream: S,
}

impl<S: ByteStream, const MAX_PKT: usize> GdbServer<S, MAX_PKT> {
    /// Create a new server wrapping the provided stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Process a single incoming packet.
    pub fn process_one<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let mut buf = [0u8; MAX_PKT];
        let payload_len = loop {
            match recv_packet::<_, MAX_PKT, T::Error>(&mut self.stream, &mut buf) {
                Ok(Some(len)) => break len,
                Ok(None) => continue,
                Err(GdbError::PacketTooLong) | Err(GdbError::MalformedPacket) => continue,
                Err(other) => return Err(other),
            }
        };
        let payload = &buf[..payload_len];

        if payload == b"?" {
            send_packet::<_, T::Error>(&mut self.stream, b"S05")?;
            return Ok(ProcessResult::None);
        }

        match payload.first().copied() {
            Some(b'q') => self.handle_query(target, payload),
            Some(b'g') => self.handle_read_all_registers(target),
            Some(b'G') => self.handle_write_all_registers(target, payload),
            Some(b'p') => self.handle_read_single_register(target, payload),
            Some(b'P') => self.handle_write_single_register(target, payload),
            Some(b'm') => self.handle_read_memory(target, payload),
            Some(b'M') => self.handle_write_memory_hex(target, payload),
            Some(b'X') => self.handle_write_memory_binary(target, payload),
            Some(b'Z') => self.handle_breakpoint(target, payload, true),
            Some(b'z') => self.handle_breakpoint(target, payload, false),
            Some(b'c') => self.handle_continue::<T>(payload),
            Some(b's') => self.handle_step::<T>(payload),
            Some(b'v') => {
                send_packet::<_, T::Error>(&mut self.stream, b"")?;
                Ok(ProcessResult::None)
            }
            _ => {
                send_packet::<_, T::Error>(&mut self.stream, b"")?;
                Ok(ProcessResult::None)
            }
        }
    }

    /// Run until a qRcmd "exit 0" request is received.
    pub fn run_until_monitor_exit<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<(), GdbError<S::Error, T::Error>> {
        loop {
            let result = self.process_one(target);
            match result {
                Ok(ProcessResult::MonitorExit) => return Ok(()),
                Ok(ProcessResult::Resume(_)) => {
                    send_packet::<_, T::Error>(&mut self.stream, b"")?;
                }
                Ok(ProcessResult::None) => {}
                Err(GdbError::PacketTooLong) | Err(GdbError::MalformedPacket) => {
                    // Ignore and continue listening.
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn handle_query<T: Target>(
        &mut self,
        _target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        if payload.starts_with(b"qSupported") {
            send_packet::<_, T::Error>(
                &mut self.stream,
                b"PacketSize=400;swbreak+;hwbreak-;vMustReplyEmpty+",
            )?;
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"qRcmd,") {
            let mut decoded = [0u8; 64];
            let decoded_len = match hex_decode(rest, &mut decoded) {
                Ok(len) => len,
                Err(_) => {
                    send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            let text = match core::str::from_utf8(&decoded[..decoded_len]) {
                Ok(t) => t,
                Err(_) => {
                    send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            if text.trim() == "exit 0" {
                send_packet::<_, T::Error>(&mut self.stream, b"OK")?;
                return Ok(ProcessResult::MonitorExit);
            }
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }

        send_packet::<_, T::Error>(&mut self.stream, b"")?;
        Ok(ProcessResult::None)
    }

    fn handle_read_all_registers<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let mut regs = [0u8; MAX_PKT];
        let len = target.read_registers(&mut regs).map_err(GdbError::Target)?;
        if len.saturating_mul(2) > MAX_PKT {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }
        let mut out = [0u8; MAX_PKT];
        let Some(hex_len) = hex_encode(&regs[..len], &mut out) else {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };
        send_packet::<_, T::Error>(&mut self.stream, &out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_all_registers<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let data_hex = &payload[1..];
        let mut regs = [0u8; MAX_PKT];
        let Ok(len) = hex_decode(data_hex, &mut regs) else {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };
        target
            .write_registers(&regs[..len])
            .map_err(GdbError::Target)?;
        send_packet::<_, T::Error>(&mut self.stream, b"OK")?;
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
                send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        let mut reg = [0u8; MAX_PKT];
        let len = target
            .read_register(regno, &mut reg)
            .map_err(GdbError::Target)?;
        if len.saturating_mul(2) > MAX_PKT {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }
        let mut out = [0u8; MAX_PKT];
        let Some(hex_len) = hex_encode(&reg[..len], &mut out) else {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };
        send_packet::<_, T::Error>(&mut self.stream, &out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let body = &payload[1..];
        let Some(eq_pos) = body.iter().position(|&b| b == b'=') else {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };
        let regno_hex = &body[..eq_pos];
        let val_hex = &body[eq_pos + 1..];

        let regno = match parse_hex_u32(regno_hex) {
            Some(r) => r,
            None => {
                send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        let mut reg = [0u8; MAX_PKT];
        let Ok(len) = hex_decode(val_hex, &mut reg) else {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };

        target
            .write_register(regno, &reg[..len])
            .map_err(GdbError::Target)?;
        send_packet::<_, T::Error>(&mut self.stream, b"OK")?;
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
                send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
                return Ok(ProcessResult::None);
            }
        };
        if addr.checked_add(len).is_none() {
            // Workaround for a GDB bug that can send wrapped "m" packets like "$mfffffffffffffffc,4#...".
            // If the address+length overflows, treat it as EFAULT (14) and keep the session running.
            send_packet::<_, T::Error>(&mut self.stream, b"E14")?;
            return Ok(ProcessResult::None);
        }
        let len_usize = match usize::try_from(len) {
            Ok(v) => v,
            Err(_) => {
                send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                return Ok(ProcessResult::None);
            }
        };
        if len_usize > MAX_PKT {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        }

        let mut data = [0u8; MAX_PKT];
        target
            .read_memory(addr, &mut data[..len_usize])
            .map_err(GdbError::Target)?;

        let mut out = [0u8; MAX_PKT];
        let Some(hex_len) = hex_encode(&data[..len_usize], &mut out) else {
            send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
            return Ok(ProcessResult::None);
        };
        send_packet::<_, T::Error>(&mut self.stream, &out[..hex_len])?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_hex<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let data_hex = &payload[colon + 1..];

        let (addr, len) = match parse_addr_len::<S::Error, T::Error>(header) {
            Ok(v) => v,
            Err(_) => {
                send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
                return Ok(ProcessResult::None);
            }
        };

        let mut data = [0u8; MAX_PKT];
        let Ok(decoded) = hex_decode(data_hex, &mut data) else {
            send_packet::<_, T::Error>(&mut self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        };
        if decoded as u64 != len {
            send_packet::<_, T::Error>(&mut self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        }

        target
            .write_memory(addr, &data[..decoded])
            .map_err(GdbError::Target)?;
        send_packet::<_, T::Error>(&mut self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_binary<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let binary = &payload[colon + 1..];

        let (addr, len) = match parse_addr_len::<S::Error, T::Error>(header) {
            Ok(v) => v,
            Err(_) => {
                send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
                return Ok(ProcessResult::None);
            }
        };

        let mut decoded = [0u8; MAX_PKT];
        let Ok(decoded_len) = decode_rsp_binary(binary, &mut decoded) else {
            // Malformed escape or output buffer overflow.
            send_packet::<_, T::Error>(&mut self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        };

        if decoded_len as u64 != len {
            send_packet::<_, T::Error>(&mut self.stream, b"E03")?;
            return Ok(ProcessResult::None);
        }

        target
            .write_memory(addr, &decoded[..decoded_len])
            .map_err(GdbError::Target)?;
        send_packet::<_, T::Error>(&mut self.stream, b"OK")?;
        Ok(ProcessResult::None)
    }

    fn handle_breakpoint<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
        insert: bool,
    ) -> Result<ProcessResult, GdbError<S::Error, T::Error>> {
        if payload.len() < 2 || payload[1] != b'0' {
            send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        }
        let mut body = &payload[2..];
        if let Some(stripped) = body.strip_prefix(b",") {
            body = stripped;
        }
        let Some(comma) = body.iter().position(|&b| b == b',') else {
            send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
            return Ok(ProcessResult::None);
        };
        let addr_hex = &body[..comma];
        let addr = match parse_hex_u64(addr_hex) {
            Some(a) => a,
            None => {
                send_packet::<_, T::Error>(&mut self.stream, b"E02")?;
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

        send_packet::<_, T::Error>(&mut self.stream, b"OK")?;
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
                    send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                    return Ok(ProcessResult::None);
                }
            }
        } else {
            None
        };
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
                    send_packet::<_, T::Error>(&mut self.stream, b"E01")?;
                    return Ok(ProcessResult::None);
                }
            }
        } else {
            None
        };
        Ok(ProcessResult::Resume(ResumeAction::Step(new_pc)))
    }
}

/// Receive a single RSP packet into `buf`, returning the payload length.
/// If a Ctrl-C (0x03) is observed, a stop reply is sent and `None` is returned.
pub fn recv_packet<S: ByteStream, const N: usize, TE>(
    stream: &mut S,
    buf: &mut [u8; N],
) -> Result<Option<usize>, GdbError<S::Error, TE>> {
    // Wait for '$' start marker.
    loop {
        let byte = stream.read().map_err(GdbError::Stream)?;
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
        let byte = stream.read().map_err(GdbError::Stream)?;
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
        *slot = stream.read().map_err(GdbError::Stream)?;
    }

    if idx > buf.len() {
        // Consume overlong packet, send NAK, and signal an error.
        stream.write(b'-').map_err(GdbError::Stream)?;
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
        stream.write(b'+').map_err(GdbError::Stream)?;
        Ok(Some(idx))
    } else {
        stream.write(b'-').map_err(GdbError::Stream)?;
        Err(GdbError::MalformedPacket)
    }
}

/// Send an RSP packet containing `payload`.
pub fn send_packet<S: ByteStream, TE>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), GdbError<S::Error, TE>> {
    let mut checksum: u8 = 0;
    for &b in payload {
        checksum = checksum.wrapping_add(b);
    }

    stream.write(b'$').map_err(GdbError::Stream)?;
    stream.write_all(payload).map_err(GdbError::Stream)?;
    stream.write(b'#').map_err(GdbError::Stream)?;
    stream
        .write(HEX[(checksum >> 4) as usize])
        .map_err(GdbError::Stream)?;
    stream
        .write(HEX[(checksum & 0xF) as usize])
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

fn hex_encode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    if dst.len() < src.len().saturating_mul(2) {
        return None;
    }
    let mut idx = 0usize;
    for &b in src {
        dst[idx] = HEX[(b >> 4) as usize];
        dst[idx + 1] = HEX[(b & 0xF) as usize];
        idx += 2;
    }
    Some(idx)
}

/// Decode ASCII hex in `src` into raw bytes in `dst`.
/// Returns decoded length on success.
pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, ()> {
    if !src.len().is_multiple_of(2) {
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
