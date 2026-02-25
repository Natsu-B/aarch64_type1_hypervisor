use io_api::ethernet::MacAddr;
use net::EncodeError;
use net::ParseError;
use net::arp::ARP_PAYLOAD_LEN;
use net::encode_arp_reply;
use net::encode_udp_ipv4_frame;
use net::parse_arp_request;
use net::parse_udp_ipv4_frame;

const ETH_LEN: usize = 14;
const IPV4_MIN_LEN: usize = 20;
const UDP_LEN: usize = 8;

const SRC_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x11]);
const DST_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x22]);
const SRC_IP: [u8; 4] = [10, 0, 0, 1];
const DST_IP: [u8; 4] = [10, 0, 0, 2];
const SRC_PORT: u16 = 1234;
const DST_PORT: u16 = 10000;

fn read_be_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn write_be_u16(data: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_be_bytes();
    data[offset] = bytes[0];
    data[offset + 1] = bytes[1];
}

fn ipv4_checksum_local(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut idx = 0usize;
    while idx + 1 < header.len() {
        sum += u16::from_be_bytes([header[idx], header[idx + 1]]) as u32;
        idx += 2;
    }
    if idx < header.len() {
        sum += u16::from_be_bytes([header[idx], 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ihl_bytes(frame: &[u8]) -> usize {
    usize::from(frame[ETH_LEN] & 0x0F) * 4
}

fn recompute_ipv4_checksum(frame: &mut [u8]) {
    let ihl = ihl_bytes(frame);
    frame[ETH_LEN + 10] = 0;
    frame[ETH_LEN + 11] = 0;
    let checksum = ipv4_checksum_local(&frame[ETH_LEN..ETH_LEN + ihl]);
    write_be_u16(frame, ETH_LEN + 10, checksum);
}

fn build_valid_ipv4_udp_frame(payload: &[u8], ihl_words: u8, trailing: &[u8]) -> Vec<u8> {
    assert!(ihl_words >= 5);
    let ihl_bytes = usize::from(ihl_words) * 4;
    let udp_len = UDP_LEN + payload.len();
    let ip_total_len = ihl_bytes + udp_len;

    let mut frame = vec![0u8; ETH_LEN + ip_total_len + trailing.len()];
    frame[0..6].copy_from_slice(&DST_MAC.0);
    frame[6..12].copy_from_slice(&SRC_MAC.0);
    write_be_u16(&mut frame, 12, 0x0800);

    frame[ETH_LEN] = (4u8 << 4) | ihl_words;
    frame[ETH_LEN + 1] = 0;
    write_be_u16(&mut frame, ETH_LEN + 2, ip_total_len as u16);
    write_be_u16(&mut frame, ETH_LEN + 4, 0x1234);
    write_be_u16(&mut frame, ETH_LEN + 6, 0);
    frame[ETH_LEN + 8] = 64;
    frame[ETH_LEN + 9] = 17;
    write_be_u16(&mut frame, ETH_LEN + 10, 0);
    frame[ETH_LEN + 12..ETH_LEN + 16].copy_from_slice(&SRC_IP);
    frame[ETH_LEN + 16..ETH_LEN + 20].copy_from_slice(&DST_IP);
    for (idx, byte) in frame[ETH_LEN + IPV4_MIN_LEN..ETH_LEN + ihl_bytes]
        .iter_mut()
        .enumerate()
    {
        *byte = 0xA0 + idx as u8;
    }

    let udp_start = ETH_LEN + ihl_bytes;
    write_be_u16(&mut frame, udp_start, SRC_PORT);
    write_be_u16(&mut frame, udp_start + 2, DST_PORT);
    write_be_u16(&mut frame, udp_start + 4, udp_len as u16);
    write_be_u16(&mut frame, udp_start + 6, 0);
    frame[udp_start + UDP_LEN..udp_start + UDP_LEN + payload.len()].copy_from_slice(payload);

    let checksum = ipv4_checksum_local(&frame[ETH_LEN..ETH_LEN + ihl_bytes]);
    write_be_u16(&mut frame, ETH_LEN + 10, checksum);

    let trailing_start = ETH_LEN + ip_total_len;
    frame[trailing_start..trailing_start + trailing.len()].copy_from_slice(trailing);
    frame
}

fn build_arp_request(sender_mac: MacAddr, sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0u8; ETH_LEN + ARP_PAYLOAD_LEN];
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&sender_mac.0);
    write_be_u16(&mut frame, 12, 0x0806);

    write_be_u16(&mut frame, ETH_LEN, 1);
    write_be_u16(&mut frame, ETH_LEN + 2, 0x0800);
    frame[ETH_LEN + 4] = 6;
    frame[ETH_LEN + 5] = 4;
    write_be_u16(&mut frame, ETH_LEN + 6, 1);
    frame[ETH_LEN + 8..ETH_LEN + 14].copy_from_slice(&sender_mac.0);
    frame[ETH_LEN + 14..ETH_LEN + 18].copy_from_slice(&sender_ip);
    frame[ETH_LEN + 18..ETH_LEN + 24].fill(0);
    frame[ETH_LEN + 24..ETH_LEN + 28].copy_from_slice(&target_ip);
    frame
}

#[test]
fn parse_minimal_valid_udp_ipv4_frame() {
    let payload = b"gdb";
    let frame = build_valid_ipv4_udp_frame(payload, 5, &[]);
    let view = parse_udp_ipv4_frame(&frame).unwrap();

    assert_eq!(view.src_mac, SRC_MAC);
    assert_eq!(view.dst_mac, DST_MAC);
    assert_eq!(view.src_ip, SRC_IP);
    assert_eq!(view.dst_ip, DST_IP);
    assert_eq!(view.src_port, SRC_PORT);
    assert_eq!(view.dst_port, DST_PORT);
    assert_eq!(view.payload, payload);
}

#[test]
fn parse_ipv4_with_options() {
    let payload = b"hello options";
    let frame = build_valid_ipv4_udp_frame(payload, 7, &[]);
    let view = parse_udp_ipv4_frame(&frame).unwrap();
    assert_eq!(view.payload, payload);
    assert_eq!(view.src_port, SRC_PORT);
    assert_eq!(view.dst_port, DST_PORT);
}

#[test]
fn parse_ignores_trailing_bytes_beyond_ipv4_total_len() {
    let payload = b"payload";
    let frame = build_valid_ipv4_udp_frame(payload, 5, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let view = parse_udp_ipv4_frame(&frame).unwrap();
    assert_eq!(view.payload, payload);
}

#[test]
fn reject_too_short_ethernet_frame() {
    let frame = [0u8; ETH_LEN - 1];
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::FrameTooShort
    );
}

#[test]
fn reject_unsupported_ethertype() {
    let mut frame = build_valid_ipv4_udp_frame(b"x", 5, &[]);
    write_be_u16(&mut frame, 12, 0x86DD);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::UnsupportedEthertype
    );
}

#[test]
fn reject_invalid_ihl_cases() {
    let mut frame = build_valid_ipv4_udp_frame(b"x", 5, &[]);
    frame[ETH_LEN] = (4u8 << 4) | 4;
    recompute_ipv4_checksum(&mut frame);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::Ipv4IhlInvalid
    );

    let mut frame = build_valid_ipv4_udp_frame(b"x", 5, &[]);
    frame[ETH_LEN] = (4u8 << 4) | 15;
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::Ipv4IhlInvalid
    );
}

#[test]
fn reject_ipv4_total_len_smaller_than_header_len() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    write_be_u16(&mut frame, ETH_LEN + 2, 19);
    recompute_ipv4_checksum(&mut frame);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::Ipv4TotalLenInvalid
    );
}

#[test]
fn reject_ipv4_total_len_exceeding_available_bytes() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    let current = read_be_u16(&frame, ETH_LEN + 2);
    write_be_u16(&mut frame, ETH_LEN + 2, current + 1);
    recompute_ipv4_checksum(&mut frame);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::Ipv4TotalLenInvalid
    );
}

#[test]
fn reject_ipv4_checksum_mismatch() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    frame[ETH_LEN + 8] ^= 0x01;
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::Ipv4ChecksumMismatch
    );
}

#[test]
fn reject_ipv4_fragments() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    write_be_u16(&mut frame, ETH_LEN + 6, 0x2000);
    recompute_ipv4_checksum(&mut frame);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::Ipv4Fragmented
    );
}

#[test]
fn reject_non_udp_protocol() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    frame[ETH_LEN + 9] = 6;
    recompute_ipv4_checksum(&mut frame);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::NotUdp
    );
}

#[test]
fn reject_udp_len_smaller_than_header() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    let udp_start = ETH_LEN + ihl_bytes(&frame);
    write_be_u16(&mut frame, udp_start + 4, 7);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::UdpLenInvalid
    );
}

#[test]
fn reject_udp_len_exceeding_ipv4_payload() {
    let mut frame = build_valid_ipv4_udp_frame(b"abc", 5, &[]);
    let udp_start = ETH_LEN + ihl_bytes(&frame);
    let ipv4_payload_len = usize::from(read_be_u16(&frame, ETH_LEN + 2)) - ihl_bytes(&frame);
    write_be_u16(&mut frame, udp_start + 4, (ipv4_payload_len + 1) as u16);
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::UdpLenInvalid
    );
}

#[test]
fn reject_truncated_udp_header() {
    let mut frame = build_valid_ipv4_udp_frame(b"", 5, &[]);
    let ihl = ihl_bytes(&frame);
    let truncated_total = (ihl + UDP_LEN - 1) as u16;
    write_be_u16(&mut frame, ETH_LEN + 2, truncated_total);
    recompute_ipv4_checksum(&mut frame);
    frame.truncate(ETH_LEN + usize::from(truncated_total));
    assert_eq!(
        parse_udp_ipv4_frame(&frame).unwrap_err(),
        ParseError::UdpHeaderTooShort
    );
}

#[test]
fn encode_parse_round_trip_and_checksum() {
    let payload = b"round-trip-payload";
    let mut frame = [0u8; 512];
    let frame_len = encode_udp_ipv4_frame(
        &mut frame, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, payload,
    )
    .unwrap();

    let parsed = parse_udp_ipv4_frame(&frame[..frame_len]).unwrap();
    assert_eq!(parsed.src_mac, SRC_MAC);
    assert_eq!(parsed.dst_mac, DST_MAC);
    assert_eq!(parsed.src_ip, SRC_IP);
    assert_eq!(parsed.dst_ip, DST_IP);
    assert_eq!(parsed.src_port, SRC_PORT);
    assert_eq!(parsed.dst_port, DST_PORT);
    assert_eq!(parsed.payload, payload);

    let mut ip_header = [0u8; IPV4_MIN_LEN];
    ip_header.copy_from_slice(&frame[ETH_LEN..ETH_LEN + IPV4_MIN_LEN]);
    ip_header[10] = 0;
    ip_header[11] = 0;
    let expected = ipv4_checksum_local(&ip_header);
    let actual = read_be_u16(&frame, ETH_LEN + 10);
    assert_eq!(actual, expected);
}

#[test]
fn parse_arp_request_and_encode_reply() {
    let sender_mac = MacAddr([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01]);
    let sender_ip = [192, 168, 10, 55];
    let local_mac = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let local_ip = [192, 168, 10, 2];

    let request = build_arp_request(sender_mac, sender_ip, local_ip);
    let parsed = parse_arp_request(&request).unwrap();
    assert_eq!(parsed.sender_mac, sender_mac);
    assert_eq!(parsed.sender_ip, sender_ip);
    assert_eq!(parsed.target_ip, local_ip);

    let mut reply = [0u8; 64];
    let reply_len = encode_arp_reply(
        &mut reply,
        local_mac,
        local_ip,
        parsed.sender_mac,
        parsed.sender_ip,
    )
    .unwrap();
    assert_eq!(reply_len, ETH_LEN + ARP_PAYLOAD_LEN);

    assert_eq!(&reply[0..6], &sender_mac.0);
    assert_eq!(&reply[6..12], &local_mac.0);
    assert_eq!(read_be_u16(&reply, 12), 0x0806);
    assert_eq!(read_be_u16(&reply, ETH_LEN), 1);
    assert_eq!(read_be_u16(&reply, ETH_LEN + 2), 0x0800);
    assert_eq!(reply[ETH_LEN + 4], 6);
    assert_eq!(reply[ETH_LEN + 5], 4);
    assert_eq!(read_be_u16(&reply, ETH_LEN + 6), 2);
    assert_eq!(&reply[ETH_LEN + 8..ETH_LEN + 14], &local_mac.0);
    assert_eq!(&reply[ETH_LEN + 14..ETH_LEN + 18], &local_ip);
    assert_eq!(&reply[ETH_LEN + 18..ETH_LEN + 24], &sender_mac.0);
    assert_eq!(&reply[ETH_LEN + 24..ETH_LEN + 28], &sender_ip);
}

#[test]
fn encode_rejects_too_small_buffer() {
    let mut frame = [0u8; ETH_LEN + IPV4_MIN_LEN + UDP_LEN - 1];
    let err = encode_udp_ipv4_frame(
        &mut frame, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, b"",
    )
    .unwrap_err();
    assert_eq!(err, EncodeError::BufferTooShort);
}
