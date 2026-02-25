use io_api::ethernet::MacAddr;

use super::EncodeError;
use super::ParseError;
use super::read_be_u16;
use super::write_be_u16;

pub const HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_MIN_ETHERNET_II: u16 = 0x0600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetHeader {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ethertype: u16,
}

/// Parses an Ethernet II frame header and returns `(header, payload)`.
///
/// Frames with length/type values below `0x0600` are rejected as non-Ethernet-II.
pub fn parse_ethernet_ii(frame: &[u8]) -> Result<(EthernetHeader, &[u8]), ParseError> {
    if frame.len() < HEADER_LEN {
        return Err(ParseError::FrameTooShort);
    }

    let ethertype = read_be_u16(frame, 12);
    if ethertype < ETHERTYPE_MIN_ETHERNET_II {
        return Err(ParseError::NonEthernetII);
    }

    let dst_mac = MacAddr([frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]]);
    let src_mac = MacAddr([frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]]);
    let header = EthernetHeader {
        dst_mac,
        src_mac,
        ethertype,
    };
    Ok((header, &frame[HEADER_LEN..]))
}

/// Encodes an Ethernet II header into `buf`.
///
/// Returns the encoded header length on success.
pub fn encode_ethernet_ii(
    buf: &mut [u8],
    dst_mac: MacAddr,
    src_mac: MacAddr,
    ethertype: u16,
) -> Result<usize, EncodeError> {
    if buf.len() < HEADER_LEN {
        return Err(EncodeError::BufferTooShort);
    }

    buf[0..6].copy_from_slice(&dst_mac.0);
    buf[6..12].copy_from_slice(&src_mac.0);
    write_be_u16(buf, 12, ethertype);
    Ok(HEADER_LEN)
}
