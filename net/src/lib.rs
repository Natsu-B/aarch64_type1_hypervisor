#![no_std]

use io_api::ethernet::MacAddr;

pub mod arp;
pub mod checksum;
pub mod eth;
pub mod ipv4;
pub mod udp;

pub type Ipv4Addr = [u8; 4];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    FrameTooShort,
    NonEthernetII,
    UnsupportedEthertype,
    Ipv4HeaderTooShort,
    Ipv4IhlInvalid,
    Ipv4TotalLenInvalid,
    Ipv4ChecksumMismatch,
    Ipv4Fragmented,
    NotUdp,
    UdpHeaderTooShort,
    UdpLenInvalid,
    ArpPacketTooShort,
    ArpUnsupportedFormat,
    ArpNotRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    BufferTooShort,
    PayloadTooLong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpIpv4DatagramView<'a> {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub use arp::ArpRequestView;

/// Parses an Ethernet frame and returns a validated UDP-over-IPv4 datagram view.
pub fn parse_udp_ipv4_frame(frame: &[u8]) -> Result<UdpIpv4DatagramView<'_>, ParseError> {
    let (eth_header, payload) = eth::parse_ethernet_ii(frame)?;
    if eth_header.ethertype != eth::ETHERTYPE_IPV4 {
        return Err(ParseError::UnsupportedEthertype);
    }

    let ipv4_header = ipv4::parse_ipv4_packet(payload)?;
    if ipv4_header.protocol != ipv4::IPV4_PROTOCOL_UDP {
        return Err(ParseError::NotUdp);
    }

    let udp_header = udp::parse_udp_datagram(ipv4_header.payload)?;
    Ok(UdpIpv4DatagramView {
        src_mac: eth_header.src_mac,
        dst_mac: eth_header.dst_mac,
        src_ip: ipv4_header.src_ip,
        dst_ip: ipv4_header.dst_ip,
        src_port: udp_header.src_port,
        dst_port: udp_header.dst_port,
        payload: udp_header.payload,
    })
}

/// Encodes an Ethernet + IPv4 + UDP frame into a caller-provided buffer.
///
/// Returns the final frame length on success.
pub fn encode_udp_ipv4_frame(
    buf: &mut [u8],
    local_mac: MacAddr,
    remote_mac: MacAddr,
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
    payload: &[u8],
) -> Result<usize, EncodeError> {
    let udp_total_len = udp::HEADER_LEN
        .checked_add(payload.len())
        .ok_or(EncodeError::PayloadTooLong)?;
    if udp_total_len > u16::MAX as usize {
        return Err(EncodeError::PayloadTooLong);
    }

    let ipv4_total_len = ipv4::HEADER_LEN_NO_OPTIONS
        .checked_add(udp_total_len)
        .ok_or(EncodeError::PayloadTooLong)?;
    if ipv4_total_len > u16::MAX as usize {
        return Err(EncodeError::PayloadTooLong);
    }

    let frame_len = eth::HEADER_LEN
        .checked_add(ipv4_total_len)
        .ok_or(EncodeError::PayloadTooLong)?;
    if buf.len() < frame_len {
        return Err(EncodeError::BufferTooShort);
    }

    let _ = eth::encode_ethernet_ii(buf, remote_mac, local_mac, eth::ETHERTYPE_IPV4)?;

    let udp_offset = eth::HEADER_LEN + ipv4::HEADER_LEN_NO_OPTIONS;
    let udp_len = udp::encode_udp_datagram(
        &mut buf[udp_offset..frame_len],
        local_port,
        remote_port,
        payload,
    )?;
    let udp_checksum = udp::compute_ipv4_udp_checksum(
        local_ip,
        remote_ip,
        &buf[udp_offset..udp_offset + udp_len],
    )?;
    write_be_u16(buf, udp_offset + 6, udp_checksum);

    let _ = ipv4::encode_ipv4_header(
        &mut buf[eth::HEADER_LEN..udp_offset],
        local_ip,
        remote_ip,
        ipv4::IPV4_PROTOCOL_UDP,
        udp_total_len,
    )?;

    Ok(frame_len)
}

/// Parses an ARP request frame.
pub fn parse_arp_request(frame: &[u8]) -> Result<ArpRequestView, ParseError> {
    arp::parse_arp_request(frame)
}

/// Encodes an ARP reply frame.
pub fn encode_arp_reply(
    buf: &mut [u8],
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    peer_mac: MacAddr,
    peer_ip: Ipv4Addr,
) -> Result<usize, EncodeError> {
    arp::encode_arp_reply(buf, local_mac, local_ip, peer_mac, peer_ip)
}

pub(crate) fn read_be_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

pub(crate) fn write_be_u16(data: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_be_bytes();
    data[offset] = bytes[0];
    data[offset + 1] = bytes[1];
}
