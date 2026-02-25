use io_api::ethernet::MacAddr;

use super::EncodeError;
use super::Ipv4Addr;
use super::ParseError;
use super::eth;
use super::read_be_u16;
use super::write_be_u16;

pub const ARP_PAYLOAD_LEN: usize = 28;
const ARP_HWTYPE_ETHERNET: u16 = 1;
const ARP_OPERATION_REQUEST: u16 = 1;
const ARP_OPERATION_REPLY: u16 = 2;
const ARP_HLEN_ETHERNET: u8 = 6;
const ARP_PLEN_IPV4: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpRequestView {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

/// Parses an ARP request frame for Ethernet/IPv4 (`htype=1`, `ptype=0x0800`).
pub fn parse_arp_request(frame: &[u8]) -> Result<ArpRequestView, ParseError> {
    let (eth_header, payload) = eth::parse_ethernet_ii(frame)?;
    if eth_header.ethertype != eth::ETHERTYPE_ARP {
        return Err(ParseError::UnsupportedEthertype);
    }
    if payload.len() < ARP_PAYLOAD_LEN {
        return Err(ParseError::ArpPacketTooShort);
    }

    let hw_type = read_be_u16(payload, 0);
    let proto_type = read_be_u16(payload, 2);
    let hlen = payload[4];
    let plen = payload[5];
    if hw_type != ARP_HWTYPE_ETHERNET
        || proto_type != eth::ETHERTYPE_IPV4
        || hlen != ARP_HLEN_ETHERNET
        || plen != ARP_PLEN_IPV4
    {
        return Err(ParseError::ArpUnsupportedFormat);
    }

    let operation = read_be_u16(payload, 6);
    if operation != ARP_OPERATION_REQUEST {
        return Err(ParseError::ArpNotRequest);
    }

    let sender_mac = MacAddr([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
    ]);
    let sender_ip = [payload[14], payload[15], payload[16], payload[17]];
    let target_mac = MacAddr([
        payload[18],
        payload[19],
        payload[20],
        payload[21],
        payload[22],
        payload[23],
    ]);
    let target_ip = [payload[24], payload[25], payload[26], payload[27]];

    Ok(ArpRequestView {
        src_mac: eth_header.src_mac,
        dst_mac: eth_header.dst_mac,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// Encodes an Ethernet/IPv4 ARP reply frame into `buf`.
///
/// Returns the final frame length on success.
pub fn encode_arp_reply(
    buf: &mut [u8],
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    peer_mac: MacAddr,
    peer_ip: Ipv4Addr,
) -> Result<usize, EncodeError> {
    let frame_len = eth::HEADER_LEN + ARP_PAYLOAD_LEN;
    if buf.len() < frame_len {
        return Err(EncodeError::BufferTooShort);
    }

    let _ = eth::encode_ethernet_ii(buf, peer_mac, local_mac, eth::ETHERTYPE_ARP)?;
    let payload = &mut buf[eth::HEADER_LEN..frame_len];

    write_be_u16(payload, 0, ARP_HWTYPE_ETHERNET);
    write_be_u16(payload, 2, eth::ETHERTYPE_IPV4);
    payload[4] = ARP_HLEN_ETHERNET;
    payload[5] = ARP_PLEN_IPV4;
    write_be_u16(payload, 6, ARP_OPERATION_REPLY);
    payload[8..14].copy_from_slice(&local_mac.0);
    payload[14..18].copy_from_slice(&local_ip);
    payload[18..24].copy_from_slice(&peer_mac.0);
    payload[24..28].copy_from_slice(&peer_ip);
    Ok(frame_len)
}
