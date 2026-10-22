//! RSP packet helpers shared by the UEFI `GdbServer` integration tests.

use gdb_remote::GdbServer;
use gdb_remote::ProcessResult;
use gdb_remote::Target;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Frames `payload` as `$payload#cs` into `buf`, returning the encoded length.
pub fn encode_packet(buf: &mut [u8], payload: &[u8]) -> Option<usize> {
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

/// Feeds `bytes` to the server's RX path; fails if any byte produces a non-`None` result.
pub fn feed_bytes<T: Target, const MAX: usize, const TX: usize>(
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

/// Copies queued TX bytes into `out` until the queue or `out` is exhausted.
pub fn drain_tx<const MAX: usize, const TX: usize>(
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

/// RSP modulo-256 checksum of `payload`.
pub fn checksum(payload: &[u8]) -> u8 {
    let mut sum = 0u8;
    for &b in payload {
        sum = sum.wrapping_add(b);
    }
    sum
}

/// Extracts the next `$...#cs` payload from `tx` starting at `*idx` into `out`.
pub fn next_payload(tx: &[u8], idx: &mut usize, out: &mut [u8]) -> Option<usize> {
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

/// Returns whether `needle` occurs anywhere in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
