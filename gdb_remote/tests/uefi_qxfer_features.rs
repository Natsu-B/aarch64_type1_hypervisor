#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use core::convert::Infallible;
use gdb_remote::GdbServer;
use gdb_remote::ProcessResult;
use gdb_remote::Target;
use gdb_remote::TargetCapabilities;
use gdb_remote::TargetError;

const HEX: &[u8; 16] = b"0123456789abcdef";
const TARGET_XML: &[u8] = b"<?xml version=\"1.0\"?><target version=\"1.0\"></target>";
const RX_BUF: usize = 512;
const TX_BUF: usize = 2048;
const MAX_PKT: usize = 256;
const TX_CAP: usize = 1024;

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    let mut server: GdbServer<MAX_PKT, TX_CAP> = GdbServer::new();
    let mut target = DummyTarget;

    let mut rx = [0u8; RX_BUF];
    let len = match encode_packet(&mut rx, b"qSupported") {
        Some(len) => len,
        None => exit_failure(),
    };
    if !feed_bytes(&mut server, &mut target, &rx[..len]) {
        exit_failure();
    }

    let len = match encode_packet(&mut rx, b"qXfer:features:read:target.xml:0,400") {
        Some(len) => len,
        None => exit_failure(),
    };
    if !feed_bytes(&mut server, &mut target, &rx[..len]) {
        exit_failure();
    }

    let mut tx = [0u8; TX_BUF];
    let tx_len = drain_tx(&mut server, &mut tx);
    let mut idx = 0usize;
    let mut payload = [0u8; MAX_PKT];

    let Some(len) = next_payload(&tx[..tx_len], &mut idx, &mut payload) else {
        exit_failure();
    };
    if !contains(&payload[..len], b"qXfer:features:read+") {
        exit_failure();
    }

    let Some(len) = next_payload(&tx[..tx_len], &mut idx, &mut payload) else {
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

fn encode_packet(buf: &mut [u8], payload: &[u8]) -> Option<usize> {
    let needed = payload.len().saturating_add(4);
    if needed > buf.len() {
        return None;
    }

    let mut idx = 0usize;
    buf[idx] = b'$';
    idx += 1;
    buf[idx..idx + payload.len()].copy_from_slice(payload);
    idx += payload.len();
    buf[idx] = b'#';
    idx += 1;

    let sum = checksum(payload);
    buf[idx] = HEX[(sum >> 4) as usize];
    buf[idx + 1] = HEX[(sum & 0xF) as usize];
    idx += 2;

    Some(idx)
}

fn feed_bytes<T: Target, const MAX: usize, const TX: usize>(
    server: &mut GdbServer<MAX, TX>,
    target: &mut T,
    bytes: &[u8],
) -> bool {
    for &byte in bytes {
        match server.on_rx_byte_irq(target, byte) {
            Ok(ProcessResult::None) => {}
            Ok(_) | Err(_) => return false,
        }
    }
    true
}

fn drain_tx<const MAX: usize, const TX: usize>(
    server: &mut GdbServer<MAX, TX>,
    out: &mut [u8],
) -> usize {
    let mut idx = 0usize;
    while let Some(byte) = server.pop_tx_byte_irq() {
        if idx >= out.len() {
            break;
        }
        out[idx] = byte;
        idx += 1;
    }
    idx
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
