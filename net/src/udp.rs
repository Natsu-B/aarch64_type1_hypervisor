use super::EncodeError;
use super::ParseError;
use super::read_be_u16;
use super::write_be_u16;

pub const HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpHeaderView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parses a UDP datagram from an IPv4 payload slice.
///
/// Payload slicing follows the UDP length field and ignores trailing bytes.
pub fn parse_udp_datagram(payload: &[u8]) -> Result<UdpHeaderView<'_>, ParseError> {
    if payload.len() < HEADER_LEN {
        return Err(ParseError::UdpHeaderTooShort);
    }

    let udp_len = usize::from(read_be_u16(payload, 4));
    if udp_len < HEADER_LEN || udp_len > payload.len() {
        return Err(ParseError::UdpLenInvalid);
    }

    let src_port = read_be_u16(payload, 0);
    let dst_port = read_be_u16(payload, 2);
    let user_payload = &payload[HEADER_LEN..udp_len];
    Ok(UdpHeaderView {
        src_port,
        dst_port,
        payload: user_payload,
    })
}

/// Encodes a UDP datagram into `buf` with checksum set to zero (IPv4-legal).
///
/// Returns the encoded datagram length on success.
pub fn encode_udp_datagram(
    buf: &mut [u8],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<usize, EncodeError> {
    let total_len = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(EncodeError::PayloadTooLong)?;
    if total_len > u16::MAX as usize {
        return Err(EncodeError::PayloadTooLong);
    }
    if buf.len() < total_len {
        return Err(EncodeError::BufferTooShort);
    }

    write_be_u16(buf, 0, src_port);
    write_be_u16(buf, 2, dst_port);
    write_be_u16(buf, 4, total_len as u16);
    write_be_u16(buf, 6, 0);
    buf[HEADER_LEN..total_len].copy_from_slice(payload);
    Ok(total_len)
}
