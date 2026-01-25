#![no_std]

use core::convert::Infallible;
use core::fmt;

#[cfg(any(feature = "gdb_monitor_debug", test))]
use core::fmt::Write;

#[macro_export]
macro_rules! gdb_debug {
    ($server:expr, $($arg:tt)*) => {
        $server.debug_console_fmt(core::format_args!($($arg)*));
    };
}

mod rsp_framing;
mod target;

use rsp_framing::RspFrameByteKind;

pub use rsp_framing::RspFrameAssembler;
pub use rsp_framing::RspFrameEvent;
pub use target::ResumeAction;
pub use target::Target;
pub use target::TargetCapabilities;
pub use target::TargetError;
pub use target::WatchpointKind;

/// Errors that can occur while speaking the GDB Remote Serial Protocol.
#[derive(Debug)]
pub enum GdbError<R, U> {
    /// Target-specific error.
    Target(TargetError<R, U>),
    /// Received packet exceeded the provided buffer.
    PacketTooLong,
    /// Packet framing or checksum was invalid.
    MalformedPacket,
    /// TX ring was full while queueing output.
    TxOverflow,
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
type GdbServerError<T> =
    GdbError<<T as Target>::RecoverableError, <T as Target>::UnrecoverableError>;

/// IRQ-facing transport-agnostic interface for the RSP engine.
pub trait RspIrqEndpoint<T: Target> {
    fn on_rx_byte_irq(
        &mut self,
        target: &mut T,
        byte: u8,
    ) -> Result<ProcessResult, GdbServerError<T>>;
    fn pop_tx_byte_irq(&mut self) -> Option<u8>;
    fn has_tx_pending(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TxOverflow;

struct TxRing<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
    full: bool,
}

impl<const N: usize> TxRing<N> {
    const fn new() -> Self {
        Self {
            buf: [0u8; N],
            head: 0,
            tail: 0,
            full: false,
        }
    }

    fn is_empty(&self) -> bool {
        !self.full && self.head == self.tail
    }

    fn len(&self) -> usize {
        if N == 0 {
            return 0;
        }
        if self.full {
            return N;
        }
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            N - (self.tail - self.head)
        }
    }

    fn available(&self) -> usize {
        if N == 0 { 0 } else { N - self.len() }
    }

    fn push(&mut self, byte: u8) -> Result<(), TxOverflow> {
        if N == 0 || self.full {
            return Err(TxOverflow);
        }
        self.buf[self.head] = byte;
        self.head = (self.head + 1) % N;
        if self.head == self.tail {
            self.full = true;
        }
        Ok(())
    }

    fn push_slice(&mut self, data: &[u8]) -> Result<(), TxOverflow> {
        if data.len() > self.available() {
            return Err(TxOverflow);
        }
        for &b in data {
            self.push(b)?;
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<u8> {
        if N == 0 || self.is_empty() {
            return None;
        }
        let byte = self.buf[self.tail];
        self.tail = (self.tail + 1) % N;
        self.full = false;
        Some(byte)
    }
}

/// Minimal GDB RSP engine with IRQ-driven I/O.
pub struct GdbServer<const MAX_PKT: usize, const TX_CAP: usize> {
    rsp: RspFrameAssembler,
    rx_buf: [u8; MAX_PKT],
    scratch_a: [u8; MAX_PKT],
    scratch_b: [u8; MAX_PKT],
    #[cfg(any(feature = "gdb_monitor_debug", test))]
    debug_in: [u8; 256],
    #[cfg(any(feature = "gdb_monitor_debug", test))]
    debug_out: [u8; 1 + 256 * 2],
    rx_len: usize,
    rx_checksum: u8,
    rx_checksum_bytes: [u8; 2],
    rx_checksum_len: usize,
    rx_overflow: bool,
    tx: TxRing<TX_CAP>,
    monitor_exit_armed: bool,
    advertised_packet_size: usize,
    ack_mode: bool,
}

impl<const MAX_PKT: usize, const TX_CAP: usize> GdbServer<MAX_PKT, TX_CAP> {
    /// Create a new server with the default advertised packet size.
    pub fn new() -> Self {
        Self::new_with_packet_size(MAX_PKT)
    }

    /// Create a new server with an explicitly advertised packet size.
    pub fn new_with_packet_size(packet_size: usize) -> Self {
        let advertised_packet_size = Self::clamp_packet_size(packet_size);
        Self {
            rsp: RspFrameAssembler::new(),
            rx_buf: [0; MAX_PKT],
            scratch_a: [0; MAX_PKT],
            scratch_b: [0; MAX_PKT],
            #[cfg(any(feature = "gdb_monitor_debug", test))]
            debug_in: [0; 256],
            #[cfg(any(feature = "gdb_monitor_debug", test))]
            debug_out: [0; 1 + 256 * 2],
            rx_len: 0,
            rx_checksum: 0,
            rx_checksum_bytes: [0u8; 2],
            rx_checksum_len: 0,
            rx_overflow: false,
            tx: TxRing::new(),
            monitor_exit_armed: false,
            advertised_packet_size,
            ack_mode: true,
        }
    }

    /// Initialize an uninitialized slot in-place without constructing large stack temporaries.
    ///
    /// NOTE: `new()` / `new_with_packet_size()` may require a large stack frame due to the
    /// internal fixed-size buffers. Prefer this API for bare-metal / tiny-stack environments.
    pub fn init_in_place(dst: &mut core::mem::MaybeUninit<Self>) {
        Self::init_in_place_with_packet_size(dst, MAX_PKT);
    }

    pub fn init_in_place_with_packet_size(
        dst: &mut core::mem::MaybeUninit<Self>,
        packet_size: usize,
    ) {
        let advertised_packet_size = Self::clamp_packet_size(packet_size);
        // SAFETY: caller provides an uninitialized slot which we fully initialize here.
        unsafe {
            let p = dst.as_mut_ptr();
            // Zero everything first so rings/buffers start empty and Option/bool fields are sane.
            core::ptr::write_bytes(p, 0u8, 1);
            // Re-init fields that must not rely on "all-zero" being a valid state.
            core::ptr::addr_of_mut!((*p).rsp).write(RspFrameAssembler::new());
            core::ptr::addr_of_mut!((*p).advertised_packet_size).write(advertised_packet_size);
            core::ptr::addr_of_mut!((*p).ack_mode).write(true);
        }
    }

    fn clamp_packet_size(packet_size: usize) -> usize {
        let mut size = packet_size;
        if size == 0 {
            size = 1;
        }
        if size > MAX_PKT {
            size = MAX_PKT;
        }
        size
    }

    fn out_payload_cap(&self) -> usize {
        self.advertised_packet_size.min(MAX_PKT)
    }
    #[cfg(any(feature = "gdb_monitor_debug", test))]
    pub fn debug_console_fmt(&mut self, args: fmt::Arguments<'_>) {
        let out_cap = self.out_payload_cap();
        let max_msg = out_cap.saturating_sub(1) / 2;
        if max_msg == 0 {
            return;
        }

        let cap = core::cmp::min(self.debug_in.len(), max_msg);
        let mut writer = DebugBufWriter::new(&mut self.debug_in, cap);
        let _ = writer.write_fmt(args);
        let msg_len = writer.len();
        if msg_len == 0 {
            return;
        }

        self.debug_out[0] = b'O';
        let hex_len = hex_encode(&self.debug_in[..msg_len], &mut self.debug_out[1..]);
        let total_len = 1usize.saturating_add(hex_len);
        if total_len > out_cap {
            return;
        }
        let _ = Self::queue_packet(&mut self.tx, &self.debug_out[..total_len]);
    }

    #[cfg(all(not(feature = "gdb_monitor_debug"), not(test)))]
    pub fn debug_console_fmt(&mut self, _args: fmt::Arguments<'_>) {
        let _ = _args;
    }

    fn reset_rx_buffers(&mut self) {
        self.rx_len = 0;
        self.rx_checksum = 0;
        self.rx_checksum_len = 0;
        self.rx_overflow = false;
    }

    fn reset_rx_full(&mut self) {
        self.reset_rx_buffers();
        self.rsp.reset();
    }

    /// Reset framing/receive state to wait for the next '$' packet start.
    pub fn resync(&mut self) {
        self.reset_rx_full();
    }

    fn push_payload_byte(&mut self, byte: u8) {
        self.rx_checksum = self.rx_checksum.wrapping_add(byte);
        if self.rx_len < self.rx_buf.len() {
            self.rx_buf[self.rx_len] = byte;
            self.rx_len = self.rx_len.saturating_add(1);
        } else {
            self.rx_overflow = true;
        }
    }

    fn push_checksum_byte(&mut self, byte: u8) {
        if self.rx_checksum_len < self.rx_checksum_bytes.len() {
            self.rx_checksum_bytes[self.rx_checksum_len] = byte;
            self.rx_checksum_len = self.rx_checksum_len.saturating_add(1);
        }
    }

    fn queue_ack(tx: &mut TxRing<TX_CAP>, ok: bool) -> Result<(), TxOverflow> {
        let byte = if ok { b'+' } else { b'-' };
        tx.push(byte)
    }

    fn queue_packet(tx: &mut TxRing<TX_CAP>, payload: &[u8]) -> Result<(), TxOverflow> {
        let needed = payload.len().saturating_add(4);
        if needed > tx.available() {
            return Err(TxOverflow);
        }

        let mut checksum: u8 = 0;
        for &b in payload {
            checksum = checksum.wrapping_add(b);
        }

        tx.push(b'$')?;
        tx.push_slice(payload)?;
        tx.push(b'#')?;
        tx.push(HEX[(checksum >> 4) as usize])?;
        tx.push(HEX[(checksum & 0xF) as usize])?;
        Ok(())
    }

    fn send<T: Target>(&mut self, payload: &[u8]) -> Result<(), GdbServerError<T>> {
        if payload.len() > self.out_payload_cap() {
            return Err(GdbError::PacketTooLong);
        }
        Self::queue_packet(&mut self.tx, payload).map_err(|_| GdbError::TxOverflow)
    }

    fn send_empty<T: Target>(&mut self) -> Result<(), GdbServerError<T>> {
        self.send::<T>(b"")
    }

    fn send_ok<T: Target>(&mut self) -> Result<(), GdbServerError<T>> {
        self.send::<T>(b"OK")
    }

    fn send_scratch_b<T: Target>(&mut self, len: usize) -> Result<(), GdbServerError<T>> {
        let payload = &self.scratch_b[..len];
        Self::queue_packet(&mut self.tx, payload).map_err(|_| GdbError::TxOverflow)
    }

    pub fn notify_stop_sigtrap(&mut self) -> Result<(), GdbError<Infallible, Infallible>> {
        let out_cap = self.out_payload_cap();
        let signal = 5u8;
        let payload = [
            b'S',
            HEX[(signal >> 4) as usize],
            HEX[(signal & 0xF) as usize],
        ];
        if payload.len() > out_cap {
            return Err(GdbError::PacketTooLong);
        }
        Self::queue_packet(&mut self.tx, &payload).map_err(|_| GdbError::TxOverflow)
    }

    fn finish_frame<T: Target>(
        &mut self,
        target: &mut T,
    ) -> Result<ProcessResult, GdbServerError<T>> {
        if self.rx_overflow || self.rx_len > MAX_PKT {
            if self.ack_mode {
                Self::queue_ack(&mut self.tx, false).map_err(|_| GdbError::TxOverflow)?;
            }
            return Err(GdbError::PacketTooLong);
        }

        if self.rx_checksum_len != self.rx_checksum_bytes.len() {
            if self.ack_mode {
                Self::queue_ack(&mut self.tx, false).map_err(|_| GdbError::TxOverflow)?;
            }
            return Err(GdbError::MalformedPacket);
        }

        let high = match from_hex_digit(self.rx_checksum_bytes[0]) {
            Ok(v) => v,
            Err(_) => {
                if self.ack_mode {
                    Self::queue_ack(&mut self.tx, false).map_err(|_| GdbError::TxOverflow)?;
                }
                return Err(GdbError::MalformedPacket);
            }
        };
        let low = match from_hex_digit(self.rx_checksum_bytes[1]) {
            Ok(v) => v,
            Err(_) => {
                if self.ack_mode {
                    Self::queue_ack(&mut self.tx, false).map_err(|_| GdbError::TxOverflow)?;
                }
                return Err(GdbError::MalformedPacket);
            }
        };
        let checksum_recv = (high << 4) | low;

        if self.rx_checksum != checksum_recv {
            if self.ack_mode {
                Self::queue_ack(&mut self.tx, false).map_err(|_| GdbError::TxOverflow)?;
            }
            return Err(GdbError::MalformedPacket);
        }

        if self.ack_mode {
            Self::queue_ack(&mut self.tx, true).map_err(|_| GdbError::TxOverflow)?;
        }

        let payload_len = self.rx_len;
        let payload_ptr = self.rx_buf.as_ptr();
        // SAFETY: payload_ptr points to rx_buf for payload_len bytes. dispatch_payload only
        // reads from the payload slice, and handlers use scratch_a/scratch_b for decoding and
        // replies, so rx_buf is not mutated until dispatch completes.
        let payload = unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) };
        self.dispatch_payload(target, payload)
    }

    fn dispatch_payload<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<T>> {
        gdb_debug!(
            self,
            "dispatch: payload=\"{}\"",
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
            Some(b'H') => {
                gdb_debug!(
                    self,
                    "dispatch: 'H' (set thread) payload=\"{}\"",
                    debug_printable_prefix(payload)
                );
                self.handle_set_thread::<T>(payload)
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

    /// Accept a received byte (RX IRQ path).
    pub fn on_rx_byte_irq<T: Target>(
        &mut self,
        target: &mut T,
        byte: u8,
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let (event, kind) = self.rsp.push_with_kind(byte);

        match kind {
            RspFrameByteKind::Payload => self.push_payload_byte(byte),
            RspFrameByteKind::Checksum => self.push_checksum_byte(byte),
            RspFrameByteKind::None => {}
        }

        match event {
            RspFrameEvent::Ignore | RspFrameEvent::NeedMore => Ok(ProcessResult::None),
            RspFrameEvent::Resync => {
                self.reset_rx_buffers();
                Ok(ProcessResult::None)
            }
            RspFrameEvent::CtrlC => {
                self.reset_rx_full();
                self.send::<T>(b"S05")?;
                Ok(ProcessResult::None)
            }
            RspFrameEvent::FrameComplete => {
                let result = self.finish_frame(target);
                self.reset_rx_full();
                result
            }
        }
    }

    /// Pop the next pending TX byte (TX IRQ path).
    pub fn pop_tx_byte_irq(&mut self) -> Option<u8> {
        self.tx.pop()
    }

    pub fn has_tx_pending(&self) -> bool {
        !self.tx.is_empty()
    }

    fn reply_recoverable<T: Target>(
        &mut self,
        target: &T,
        e: &T::RecoverableError,
    ) -> Result<(), GdbServerError<T>> {
        let code = target.recoverable_error_code(e);
        let reply = [b'E', HEX[(code >> 4) as usize], HEX[(code & 0xF) as usize]];
        self.send::<T>(&reply)?;
        Ok(())
    }

    fn handle_target_err_core<T: Target, R>(
        &mut self,
        target: &T,
        result: Result<R, TargetErr<T>>,
    ) -> Result<Option<R>, GdbServerError<T>> {
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
    ) -> Result<bool, GdbServerError<T>> {
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
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
            let wants_aarch64_xml = caps.contains(TargetCapabilities::XFER_FEATURES)
                && qsupported_has_xml_registers(payload, b"aarch64");
            let mut reply = [0u8; 128];
            let mut idx = 0usize;
            append_bytes(&mut reply, &mut idx, b"PacketSize=");
            // PacketSize is advertised as lowercase hex without a 0x prefix.
            append_hex_u64(&mut reply, &mut idx, self.out_payload_cap() as u64);
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
            if caps.contains(TargetCapabilities::XFER_FEATURES) {
                append_bytes(&mut reply, &mut idx, b";qXfer:features:read+");
            }
            if caps.contains(TargetCapabilities::XFER_MEMORY_MAP) {
                append_bytes(&mut reply, &mut idx, b";qXfer:memory-map:read+");
            }
            if wants_aarch64_xml {
                append_bytes(&mut reply, &mut idx, b";xmlRegisters=aarch64");
            }
            self.send::<T>(&reply[..idx])?;
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"qXfer:features:read:") {
            if !target
                .capabilities()
                .contains(TargetCapabilities::XFER_FEATURES)
            {
                self.send_empty::<T>()?;
                return Ok(ProcessResult::None);
            }
            let Some((annex, offset, length)) = parse_qxfer_read(rest, false) else {
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            };
            let annex = match core::str::from_utf8(annex) {
                Ok(value) => value,
                Err(_) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };

            let data = match target.xfer_features(annex) {
                Ok(Some(data)) => data,
                Ok(None) | Err(TargetError::NotSupported) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
                Err(TargetError::Recoverable(e)) => {
                    self.reply_recoverable(target, &e)?;
                    return Ok(ProcessResult::None);
                }
                Err(TargetError::Unrecoverable(e)) => {
                    return Err(GdbError::Target(TargetError::Unrecoverable(e)));
                }
            };

            let offset = match usize::try_from(offset) {
                Ok(value) => value,
                Err(_) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            let length = match usize::try_from(length) {
                Ok(value) => value,
                Err(_) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };

            if offset >= data.len() {
                self.send::<T>(b"l")?;
                return Ok(ProcessResult::None);
            }

            let max_len = core::cmp::min(length, data.len() - offset);
            if max_len == 0 {
                let prefix = if offset < data.len() { b'm' } else { b'l' };
                let reply = [prefix];
                self.send::<T>(&reply)?;
                return Ok(ProcessResult::None);
            }

            let cap = self.out_payload_cap();
            if cap < 1 {
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }

            let (consumed, encoded_len) = {
                let reply = &mut self.scratch_b;
                encode_rsp_binary(&data[offset..offset + max_len], &mut reply[1..cap])
            };
            if consumed == 0 {
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }

            let more = offset + consumed < data.len();
            self.scratch_b[0] = if more { b'm' } else { b'l' };
            self.send_scratch_b::<T>(1 + encoded_len)?;
            return Ok(ProcessResult::None);
        }

        if let Some(rest) = payload.strip_prefix(b"qXfer:memory-map:read:") {
            if !target
                .capabilities()
                .contains(TargetCapabilities::XFER_MEMORY_MAP)
            {
                self.send_empty::<T>()?;
                return Ok(ProcessResult::None);
            }
            let Some((_annex, offset, length)) = parse_qxfer_read(rest, true) else {
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            };

            let data = match target.xfer_memory_map() {
                Ok(Some(data)) => data,
                Ok(None) | Err(TargetError::NotSupported) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
                Err(TargetError::Recoverable(e)) => {
                    self.reply_recoverable(target, &e)?;
                    return Ok(ProcessResult::None);
                }
                Err(TargetError::Unrecoverable(e)) => {
                    return Err(GdbError::Target(TargetError::Unrecoverable(e)));
                }
            };

            let offset = match usize::try_from(offset) {
                Ok(value) => value,
                Err(_) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };
            let length = match usize::try_from(length) {
                Ok(value) => value,
                Err(_) => {
                    self.send::<T>(b"E01")?;
                    return Ok(ProcessResult::None);
                }
            };

            if offset >= data.len() {
                self.send::<T>(b"l")?;
                return Ok(ProcessResult::None);
            }

            let max_len = core::cmp::min(length, data.len() - offset);
            if max_len == 0 {
                let prefix = if offset < data.len() { b'm' } else { b'l' };
                let reply = [prefix];
                self.send::<T>(&reply)?;
                return Ok(ProcessResult::None);
            }

            let cap = self.out_payload_cap();
            if cap < 1 {
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }

            let (consumed, encoded_len) = {
                let reply = &mut self.scratch_b;
                encode_rsp_binary(&data[offset..offset + max_len], &mut reply[1..cap])
            };
            if consumed == 0 {
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }

            let more = offset + consumed < data.len();
            self.scratch_b[0] = if more { b'm' } else { b'l' };
            self.send_scratch_b::<T>(1 + encoded_len)?;
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let result = {
            let regs = &mut self.scratch_a;
            target.read_registers(regs)
        };
        let len = match self.handle_target_err_core(target, result)? {
            Some(len) => len,
            None => return Ok(ProcessResult::None),
        };
        gdb_debug!(self, "handle_read_all_registers: total_len={} bytes", len);

        let out_cap = self.out_payload_cap();
        let expected_hex_len = len.saturating_mul(2);
        if expected_hex_len > out_cap {
            gdb_debug!(
                self,
                "handle_read_all_registers: response too large hex_len={} out_cap={}",
                expected_hex_len,
                out_cap
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        let hex_len = {
            let out = &mut self.scratch_b[..out_cap];
            let regs = &self.scratch_a[..len];
            hex_encode(regs, out)
        };
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
        self.send_scratch_b::<T>(hex_len)?;
        Ok(ProcessResult::None)
    }

    fn handle_write_all_registers<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let data_hex = &payload[1..];
        gdb_debug!(
            self,
            "handle_write_all_registers: payload_len={} hex_len={}",
            payload.len(),
            data_hex.len()
        );
        let len = match {
            let regs = &mut self.scratch_a;
            hex_decode(data_hex, regs)
        } {
            Ok(len) => len,
            Err(_) => {
                gdb_debug!(
                    self,
                    "handle_write_all_registers: hex decode failed src_len={} dst_cap={}",
                    data_hex.len(),
                    self.scratch_a.len()
                );
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }
        };
        gdb_debug!(self, "handle_write_all_registers: decoded_len={}", len);
        let result = target.write_registers(&self.scratch_a[..len]);
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }
        self.send_ok::<T>()?;
        Ok(ProcessResult::None)
    }

    fn handle_set_thread<T: Target>(
        &mut self,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let Some(kind) = payload.get(1).copied() else {
            self.send_empty::<T>()?;
            return Ok(ProcessResult::None);
        };

        match kind {
            b'c' | b'g' => {
                self.send_ok::<T>()?;
                Ok(ProcessResult::None)
            }
            _ => {
                self.send_empty::<T>()?;
                Ok(ProcessResult::None)
            }
        }
    }

    fn handle_read_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let regno = match parse_hex_u32(&payload[1..]) {
            Some(r) => r,
            None => {
                gdb_debug!(self, "handle_read_single_register: bad regno payload");
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        gdb_debug!(self, "handle_read_single_register: regno={}", regno);

        let result = {
            let reg = &mut self.scratch_a;
            target.read_register(regno, reg)
        };
        let len = match self.handle_target_err_core(target, result)? {
            Some(len) => len,
            None => return Ok(ProcessResult::None),
        };
        let out_cap = self.out_payload_cap();
        let expected_hex_len = len.saturating_mul(2);
        if expected_hex_len > out_cap {
            gdb_debug!(
                self,
                "handle_read_single_register: response too large regno={} hex_len={} out_cap={}",
                regno,
                expected_hex_len,
                out_cap
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }
        let hex_len = {
            let out = &mut self.scratch_b[..out_cap];
            let reg = &self.scratch_a[..len];
            hex_encode(reg, out)
        };
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
        self.send_scratch_b::<T>(hex_len)?;
        Ok(ProcessResult::None)
    }

    fn handle_write_single_register<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<T>> {
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

        let len = match {
            let reg = &mut self.scratch_a;
            hex_decode(val_hex, reg)
        } {
            Ok(len) => len,
            Err(_) => {
                gdb_debug!(
                    self,
                    "handle_write_single_register: hex decode failed src_len={} dst_cap={}",
                    val_hex.len(),
                    self.scratch_a.len()
                );
                self.send::<T>(b"E01")?;
                return Ok(ProcessResult::None);
            }
        };

        gdb_debug!(
            self,
            "handle_write_single_register: decoded_len={} regno={}",
            len,
            regno
        );
        let result = target.write_register(regno, &self.scratch_a[..len]);
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let (addr, len) =
            match parse_addr_len::<T::RecoverableError, T::UnrecoverableError>(payload) {
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
        let out_cap = self.out_payload_cap();
        if len_usize > out_cap {
            gdb_debug!(
                self,
                "handle_read_memory: len_usize {} exceeds out_cap {}, sending E01",
                len_usize,
                out_cap
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }

        let expected_hex_len = len_usize.saturating_mul(2);
        if expected_hex_len > out_cap {
            gdb_debug!(
                self,
                "handle_read_memory: hex response too large hex_len={} out_cap={}",
                expected_hex_len,
                out_cap
            );
            self.send::<T>(b"E01")?;
            return Ok(ProcessResult::None);
        }

        let result = {
            let data = &mut self.scratch_a;
            target.read_memory(addr, &mut data[..len_usize])
        };
        if self.handle_target_err_core(target, result)?.is_none() {
            return Ok(ProcessResult::None);
        }

        let hex_len = {
            let out = &mut self.scratch_b[..out_cap];
            let data = &self.scratch_a[..len_usize];
            hex_encode(data, out)
        };
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
        self.send_scratch_b::<T>(hex_len)?;
        Ok(ProcessResult::None)
    }

    fn handle_write_memory_hex<T: Target>(
        &mut self,
        target: &mut T,
        payload: &[u8],
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            gdb_debug!(self, "handle_write_memory_hex: missing ':' separator");
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let data_hex = &payload[colon + 1..];

        let (addr, len) = match parse_addr_len::<T::RecoverableError, T::UnrecoverableError>(header)
        {
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

        let decoded = match {
            let data = &mut self.scratch_a;
            hex_decode(data_hex, data)
        } {
            Ok(len) => len,
            Err(_) => {
                gdb_debug!(
                    self,
                    "handle_write_memory_hex: hex decode failed src_len={} dst_cap={}",
                    data_hex.len(),
                    self.scratch_a.len()
                );
                self.send::<T>(b"E03")?;
                return Ok(ProcessResult::None);
            }
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

        let result = target.write_memory(addr, &self.scratch_a[..decoded]);
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
        let Some(colon) = payload.iter().position(|&b| b == b':') else {
            gdb_debug!(self, "handle_write_memory_binary: missing ':' separator");
            self.send::<T>(b"E02")?;
            return Ok(ProcessResult::None);
        };
        let header = &payload[..colon];
        let binary = &payload[colon + 1..];

        // RSP "X" packet: X<addr_hex>,<len_hex>:<binary-data>.
        // Addresses and lengths are hex per the GDB RSP overview.
        let (addr, len) = match parse_addr_len::<T::RecoverableError, T::UnrecoverableError>(header)
        {
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

        let len_usize = match usize::try_from(len) {
            Ok(value) => value,
            Err(_) => {
                gdb_debug!(self, "handle_write_memory_binary: len overflow");
                self.send::<T>(b"E03")?;
                return Ok(ProcessResult::None);
            }
        };

        // Decode RSP binary data after checksum validation. The on-wire payload uses 0x7d
        // escaping (no RLE expansion for incoming data).
        if len_usize > self.scratch_a.len() {
            gdb_debug!(
                self,
                "handle_write_memory_binary: len {} exceeds MAX_PKT {}",
                len_usize,
                self.scratch_a.len()
            );
            self.send::<T>(b"E03")?;
            return Ok(ProcessResult::None);
        }
        let decoded_len = match {
            let decoded = &mut self.scratch_a;
            decode_rsp_binary(binary, &mut decoded[..len_usize])
        } {
            Ok(len) => len,
            Err(_) => {
                // Malformed escape or output buffer overflow.
                gdb_debug!(
                    self,
                    "handle_write_memory_binary: binary decode failed src_len={} dst_cap={}",
                    binary.len(),
                    len_usize
                );
                self.send::<T>(b"E03")?;
                return Ok(ProcessResult::None);
            }
        };

        if decoded_len != len_usize {
            gdb_debug!(
                self,
                "handle_write_memory_binary: decoded_len {} != header_len {}",
                decoded_len,
                len_usize
            );
            self.send::<T>(b"E03")?;
            return Ok(ProcessResult::None);
        }

        let result = target.write_memory(addr, &self.scratch_a[..decoded_len]);
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
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
    ) -> Result<ProcessResult, GdbServerError<T>> {
        gdb_debug!(
            self,
            "handle_v_packet: payload=\"{}\"",
            debug_printable_prefix(payload)
        );
        if payload == b"vMustReplyEmpty" {
            self.send_empty::<T>()?;
            return Ok(ProcessResult::None);
        }
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

            let decoded_len = match {
                let decoded = &mut self.scratch_a;
                decode_rsp_binary(data, decoded)
            } {
                Ok(len) => len,
                Err(_) => {
                    gdb_debug!(
                        self,
                        "handle_v_packet: vFlashWrite decode failed src_len={} dst_cap={}",
                        data.len(),
                        self.scratch_a.len()
                    );
                    self.send::<T>(b"E03")?;
                    return Ok(ProcessResult::None);
                }
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

            let result = target.write_memory(addr, &self.scratch_a[..decoded_len]);
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

impl<T: Target, const MAX_PKT: usize, const TX_CAP: usize> RspIrqEndpoint<T>
    for GdbServer<MAX_PKT, TX_CAP>
{
    fn on_rx_byte_irq(
        &mut self,
        target: &mut T,
        byte: u8,
    ) -> Result<ProcessResult, GdbServerError<T>> {
        GdbServer::on_rx_byte_irq(self, target, byte)
    }

    fn pop_tx_byte_irq(&mut self) -> Option<u8> {
        GdbServer::pop_tx_byte_irq(self)
    }

    fn has_tx_pending(&self) -> bool {
        GdbServer::has_tx_pending(self)
    }
}

#[cfg(any(feature = "gdb_monitor_debug", test))]
struct DebugBufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    cap: usize,
}

#[cfg(any(feature = "gdb_monitor_debug", test))]
impl<'a> DebugBufWriter<'a> {
    fn new(buf: &'a mut [u8], cap: usize) -> Self {
        Self { buf, pos: 0, cap }
    }

    fn len(&self) -> usize {
        self.pos
    }
}

#[cfg(any(feature = "gdb_monitor_debug", test))]
impl<'a> fmt::Write for DebugBufWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.cap == 0 {
            return Ok(());
        }

        let mut bytes = s.as_bytes();
        while !bytes.is_empty() {
            let remaining = self.cap.saturating_sub(self.pos);
            if remaining == 0 {
                break;
            }
            let to_copy = bytes.len().min(remaining);
            self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.pos += to_copy;
            bytes = &bytes[to_copy..];
            if self.pos == self.cap {
                break;
            }
        }
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

fn parse_qxfer_read(buf: &[u8], allow_empty_annex: bool) -> Option<(&[u8], u64, u64)> {
    let mut parts = buf.splitn(2, |&b| b == b':');
    let annex = parts.next()?;
    let rest = parts.next()?;

    if annex.is_empty() && !allow_empty_annex {
        return None;
    }

    let mut range = rest.splitn(2, |&b| b == b',');
    let offset_hex = range.next()?;
    let len_hex = range.next()?;
    let offset = parse_hex_u64(offset_hex)?;
    let len = parse_hex_u64(len_hex)?;
    Some((annex, offset, len))
}

fn qsupported_has_xml_registers(payload: &[u8], arch: &[u8]) -> bool {
    let Some(rest) = payload.strip_prefix(b"qSupported") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(b":") else {
        return false;
    };

    for item in rest.split(|&b| b == b';') {
        let mut parts = item.splitn(2, |&b| b == b'=');
        let key = parts.next().unwrap_or(&[]);
        if key != b"xmlRegisters" {
            continue;
        }
        let list = parts.next().unwrap_or(&[]);
        for value in list.split(|&b| b == b',') {
            if value == arch {
                return true;
            }
        }
    }
    false
}

fn parse_addr_len<R, U>(payload: &[u8]) -> Result<(u64, u64), GdbError<R, U>> {
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
/// Per the GDB RSP overview, '#' '$' '}' are escaped by prefixing '}' and XOR 0x20.
/// Returns decoded length on success.
pub fn decode_rsp_binary(src: &[u8], dst: &mut [u8]) -> Result<usize, ()> {
    let mut in_idx = 0usize;
    let mut out_idx = 0usize;

    while in_idx < src.len() {
        let b = src[in_idx];
        if b == b'}' {
            in_idx += 1;
            if in_idx >= src.len() {
                return Err(());
            }
            let val = src[in_idx] ^ 0x20;
            if out_idx >= dst.len() {
                return Err(());
            }
            dst[out_idx] = val;
            in_idx += 1;
            out_idx += 1;
            continue;
        } else {
            if out_idx >= dst.len() {
                return Err(());
            }
            dst[out_idx] = b;
        }

        in_idx += 1;
        out_idx += 1;
    }

    Ok(out_idx)
}

/// Encode RSP binary data (with 0x7d escaping) into `dst`.
/// Returns (bytes_consumed, bytes_written).
fn encode_rsp_binary(src: &[u8], dst: &mut [u8]) -> (usize, usize) {
    let mut in_idx = 0usize;
    let mut out_idx = 0usize;

    while in_idx < src.len() {
        let b = src[in_idx];
        // Escape '$', '#', '}' per RSP; escape '*' to avoid triggering GDB RLE parsing.
        let needs_escape = b == b'$' || b == b'#' || b == b'}' || b == b'*';
        let needed = if needs_escape { 2 } else { 1 };

        if out_idx + needed > dst.len() {
            break;
        }

        if needs_escape {
            dst[out_idx] = b'}';
            dst[out_idx + 1] = b ^ 0x20;
            out_idx += 2;
        } else {
            dst[out_idx] = b;
            out_idx += 1;
        }

        in_idx += 1;
    }

    (in_idx, out_idx)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::GdbServer;
    use super::HEX;
    use super::ProcessResult;
    use super::Target;
    use super::TargetError;
    use core::convert::Infallible;
    use std::vec::Vec;

    const REG_BYTES: usize = 356;

    struct DummyTarget;

    type DummyError = TargetError<Infallible, Infallible>;

    impl Target for DummyTarget {
        type RecoverableError = Infallible;
        type UnrecoverableError = Infallible;

        fn read_registers(&mut self, dst: &mut [u8]) -> Result<usize, DummyError> {
            if dst.len() < REG_BYTES {
                return Err(TargetError::NotSupported);
            }
            for (idx, byte) in dst[..REG_BYTES].iter_mut().enumerate() {
                *byte = (idx & 0xff) as u8;
            }
            Ok(REG_BYTES)
        }

        fn write_registers(&mut self, _src: &[u8]) -> Result<(), DummyError> {
            Ok(())
        }

        fn read_register(&mut self, _regno: u32, _dst: &mut [u8]) -> Result<usize, DummyError> {
            Ok(0)
        }

        fn write_register(&mut self, _regno: u32, _src: &[u8]) -> Result<(), DummyError> {
            Ok(())
        }

        fn read_memory(&mut self, _addr: u64, _dst: &mut [u8]) -> Result<(), DummyError> {
            Ok(())
        }

        fn write_memory(&mut self, _addr: u64, _src: &[u8]) -> Result<(), DummyError> {
            Ok(())
        }

        fn insert_sw_breakpoint(&mut self, _addr: u64) -> Result<(), DummyError> {
            Ok(())
        }

        fn remove_sw_breakpoint(&mut self, _addr: u64) -> Result<(), DummyError> {
            Ok(())
        }
    }

    fn build_frame(payload: &[u8]) -> Vec<u8> {
        let checksum = payload.iter().fold(0u8, |sum, &b| sum.wrapping_add(b));
        let mut frame = Vec::new();
        frame.push(b'$');
        frame.extend_from_slice(payload);
        frame.push(b'#');
        frame.push(HEX[(checksum >> 4) as usize]);
        frame.push(HEX[(checksum & 0xF) as usize]);
        frame
    }

    fn is_hex(b: u8) -> bool {
        matches!(b, b'0'..=b'9' | b'a'..=b'f')
    }

    struct Packet {
        payload: Vec<u8>,
        checksum: [u8; 2],
    }

    fn parse_packets(tx: &[u8]) -> Vec<Packet> {
        let mut packets = Vec::new();
        let mut idx = 0usize;
        while idx < tx.len() {
            if tx[idx] != b'$' {
                idx += 1;
                continue;
            }
            idx = idx.saturating_add(1);
            let start = idx;
            while idx < tx.len() && tx[idx] != b'#' {
                idx += 1;
            }
            if idx >= tx.len() {
                panic!("unterminated packet in tx stream");
            }
            let payload = tx[start..idx].to_vec();
            if idx + 2 >= tx.len() {
                panic!("missing checksum in tx stream");
            }
            let checksum = [tx[idx + 1], tx[idx + 2]];
            idx += 3;
            packets.push(Packet { payload, checksum });
        }
        packets
    }

    #[test]
    fn g_packet_queues_register_reply() {
        let mut server: GdbServer<8192, 2048> = GdbServer::new();
        let mut target = DummyTarget;
        let frame = build_frame(b"g");

        let mut last = ProcessResult::None;
        for &byte in &frame {
            last = server
                .on_rx_byte_irq(&mut target, byte)
                .expect("rsp handling failed");
        }
        assert!(matches!(last, ProcessResult::None));

        let mut tx = Vec::new();
        while let Some(byte) = server.pop_tx_byte_irq() {
            tx.push(byte);
        }

        let packets = parse_packets(&tx);
        let packet = packets
            .iter()
            .find(|packet| {
                packet.payload.len() == REG_BYTES * 2 && packet.payload.iter().all(|&b| is_hex(b))
            })
            .expect("missing register response packet");

        let expected = packet
            .payload
            .iter()
            .fold(0u8, |sum, &b| sum.wrapping_add(b));
        let expected_hex = [
            HEX[(expected >> 4) as usize],
            HEX[(expected & 0xF) as usize],
        ];
        assert!(packet.checksum.iter().all(|&b| is_hex(b)));
        assert_eq!(packet.checksum, expected_hex);
    }

    #[test]
    fn no_max_pkt_stack_buffers() {
        let src = include_str!("lib.rs");
        let needle = concat!("[0u8; ", "MAX_PKT]");
        assert!(
            !src.contains(needle),
            "gdb_remote/src/lib.rs should avoid MAX_PKT stack buffers"
        );
    }
}
