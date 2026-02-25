use super::EncodeError;
use super::Ipv4Addr;
use super::ParseError;
use super::checksum::ipv4_header_checksum;
use super::checksum::ipv4_header_checksum_is_valid;
use super::read_be_u16;
use super::write_be_u16;

pub const HEADER_LEN_NO_OPTIONS: usize = 20;
pub const IPV4_PROTOCOL_UDP: u8 = 17;
const VERSION: u8 = 4;
const MIN_IHL_WORDS: usize = 5;
const TTL_DEFAULT: u8 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4HeaderView<'a> {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
    pub header_len: usize,
}

/// Parses an IPv4 packet and returns a checked view of the header and payload.
///
/// This validates version/IHL, total length bounds, fragmentation flags, and header checksum.
pub fn parse_ipv4_packet(packet: &[u8]) -> Result<Ipv4HeaderView<'_>, ParseError> {
    if packet.len() < HEADER_LEN_NO_OPTIONS {
        return Err(ParseError::Ipv4HeaderTooShort);
    }

    let version = packet[0] >> 4;
    let ihl_words = usize::from(packet[0] & 0x0F);
    if version != VERSION || ihl_words < MIN_IHL_WORDS {
        return Err(ParseError::Ipv4IhlInvalid);
    }

    let header_len = ihl_words * 4;
    if packet.len() < header_len {
        return Err(ParseError::Ipv4IhlInvalid);
    }

    let total_len = usize::from(read_be_u16(packet, 2));
    if total_len < header_len || total_len > packet.len() {
        return Err(ParseError::Ipv4TotalLenInvalid);
    }

    if !ipv4_header_checksum_is_valid(&packet[..header_len]) {
        return Err(ParseError::Ipv4ChecksumMismatch);
    }

    let flags_fragment = read_be_u16(packet, 6);
    let more_fragments = (flags_fragment & 0x2000) != 0;
    let fragment_offset = flags_fragment & 0x1FFF;
    if more_fragments || fragment_offset != 0 {
        return Err(ParseError::Ipv4Fragmented);
    }

    let protocol = packet[9];
    let src_ip = [packet[12], packet[13], packet[14], packet[15]];
    let dst_ip = [packet[16], packet[17], packet[18], packet[19]];
    let payload = &packet[header_len..total_len];

    Ok(Ipv4HeaderView {
        src_ip,
        dst_ip,
        protocol,
        payload,
        header_len,
    })
}

/// Encodes an IPv4 header without options (`IHL=5`) into `buf`.
///
/// Returns the encoded header length on success.
pub fn encode_ipv4_header(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    payload_len: usize,
) -> Result<usize, EncodeError> {
    if buf.len() < HEADER_LEN_NO_OPTIONS {
        return Err(EncodeError::BufferTooShort);
    }

    let total_len = HEADER_LEN_NO_OPTIONS
        .checked_add(payload_len)
        .ok_or(EncodeError::PayloadTooLong)?;
    if total_len > u16::MAX as usize {
        return Err(EncodeError::PayloadTooLong);
    }

    buf[0] = (VERSION << 4) | (MIN_IHL_WORDS as u8);
    buf[1] = 0;
    write_be_u16(buf, 2, total_len as u16);
    write_be_u16(buf, 4, 0);
    write_be_u16(buf, 6, 0);
    buf[8] = TTL_DEFAULT;
    buf[9] = protocol;
    write_be_u16(buf, 10, 0);
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);

    let checksum = ipv4_header_checksum(&buf[..HEADER_LEN_NO_OPTIONS]);
    write_be_u16(buf, 10, checksum);
    Ok(HEADER_LEN_NO_OPTIONS)
}
