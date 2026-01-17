#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use byte_stream::ByteStream;
use core::cell::Cell;
use core::cell::UnsafeCell;
use core::convert::Infallible;
use gdb_remote::GdbServer;
use gdb_remote::ProcessResult;
use gdb_remote::Target;
use gdb_remote::TargetCapabilities;
use gdb_remote::TargetError;

const HEX: &[u8; 16] = b"0123456789abcdef";
const TARGET_XML: &[u8] = b"<?xml version=\"1.0\"?><target version=\"1.0\"></target>";

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    let mut stream = MockStream::<512, 1024>::new();
    if !stream.push_packet(b"qSupported") {
        exit_failure();
    }
    if !stream.push_packet(b"qXfer:features:read:target.xml:0,400") {
        exit_failure();
    }

    let mut server: GdbServer<&MockStream<512, 1024>, 256> = GdbServer::new(&stream);
    let mut target = DummyTarget;

    for _ in 0..2 {
        match server.process_one(&mut target) {
            Ok(ProcessResult::None) => {}
            _ => exit_failure(),
        }
    }

    let tx = stream.tx_bytes();
    let mut idx = 0usize;
    let mut payload = [0u8; 256];

    let Some(len) = next_payload(tx, &mut idx, &mut payload) else {
        exit_failure();
    };
    if !contains(&payload[..len], b"qXfer:features:read+") {
        exit_failure();
    }

    let Some(len) = next_payload(tx, &mut idx, &mut payload) else {
        exit_failure();
    };
    if len == 0 {
        exit_failure();
    }
    if payload[0] != b'm' && payload[0] != b'l' {
        exit_failure();
    }
    if !contains(&payload[..len], b"<target") {
        exit_failure();
    }

    exit_success();
}

struct DummyTarget;

type DummyError = TargetError<Infallible, Infallible>;

impl Target for DummyTarget {
    type RecoverableError = Infallible;
    type UnrecoverableError = Infallible;

    fn capabilities(&self) -> TargetCapabilities {
        TargetCapabilities::SW_BREAK | TargetCapabilities::XFER_FEATURES
    }

    fn xfer_features(&mut self, annex: &str) -> Result<Option<&[u8]>, DummyError> {
        if annex == "target.xml" {
            return Ok(Some(TARGET_XML));
        }
        Ok(None)
    }

    fn read_registers(&mut self, _dst: &mut [u8]) -> Result<usize, DummyError> {
        Ok(0)
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

struct MockStream<const RX: usize, const TX: usize> {
    rx: [u8; RX],
    rx_len: Cell<usize>,
    rx_pos: Cell<usize>,
    tx: UnsafeCell<[u8; TX]>,
    tx_len: Cell<usize>,
}

impl<const RX: usize, const TX: usize> MockStream<RX, TX> {
    const fn new() -> Self {
        Self {
            rx: [0u8; RX],
            rx_len: Cell::new(0),
            rx_pos: Cell::new(0),
            tx: UnsafeCell::new([0u8; TX]),
            tx_len: Cell::new(0),
        }
    }

    fn push_packet(&mut self, payload: &[u8]) -> bool {
        let needed = 1 + payload.len() + 3;
        let mut idx = self.rx_len.get();
        if idx + needed > RX {
            return false;
        }

        self.rx[idx] = b'$';
        idx += 1;
        self.rx[idx..idx + payload.len()].copy_from_slice(payload);
        idx += payload.len();
        self.rx[idx] = b'#';
        idx += 1;

        let sum = checksum(payload);
        self.rx[idx] = HEX[(sum >> 4) as usize];
        self.rx[idx + 1] = HEX[(sum & 0xF) as usize];
        idx += 2;

        self.rx_len.set(idx);
        true
    }

    fn tx_bytes(&self) -> &[u8] {
        let len = self.tx_len.get();
        let ptr = self.tx.get() as *const u8;
        // SAFETY: `tx` points to a TX-sized buffer, `len` never exceeds TX,
        // and we only read after all writes finish in this single-threaded test.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

impl<const RX: usize, const TX: usize> ByteStream for &MockStream<RX, TX> {
    type Error = Infallible;

    fn try_read(&self) -> Result<Option<u8>, Self::Error> {
        let pos = self.rx_pos.get();
        let len = self.rx_len.get();
        if pos >= len {
            return Ok(None);
        }
        self.rx_pos.set(pos + 1);
        Ok(Some(self.rx[pos]))
    }

    fn try_write(&self, byte: u8) -> Result<bool, Self::Error> {
        let len = self.tx_len.get();
        if len >= TX {
            return Ok(false);
        }
        // SAFETY: `tx_len` ensures we write within bounds, and the test
        // executes single-threaded with no concurrent access.
        unsafe {
            (*self.tx.get())[len] = byte;
        }
        self.tx_len.set(len + 1);
        Ok(true)
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn checksum(payload: &[u8]) -> u8 {
    let mut sum = 0u8;
    for &b in payload {
        sum = sum.wrapping_add(b);
    }
    sum
}

fn next_payload(tx: &[u8], idx: &mut usize, out: &mut [u8]) -> Option<usize> {
    while *idx < tx.len() && tx[*idx] != b'$' {
        *idx += 1;
    }
    if *idx >= tx.len() {
        return None;
    }
    *idx += 1;
    let start = *idx;
    while *idx < tx.len() && tx[*idx] != b'#' {
        *idx += 1;
    }
    if *idx >= tx.len() {
        return None;
    }
    let payload = &tx[start..*idx];
    let len = payload.len().min(out.len());
    out[..len].copy_from_slice(&payload[..len]);
    *idx = (*idx + 3).min(tx.len());
    Some(len)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = info;
    exit_failure();
}
