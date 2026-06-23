//! A bounded, no-allocation TFTP read-request client.
//!
//! The client uses ARP followed by IPv4/UDP TFTP transfers over a polling
//! [`EthernetFrameIo`].  It intentionally implements the RFC 1350 base
//! protocol only: octet-mode RRQ, 512-byte blocks, and no options.

use io_api::ethernet::EthernetFrameIo;
use io_api::ethernet::MacAddr;

use crate::EncodeError;
use crate::Ipv4Addr;
use crate::ParseError;
use crate::arp;
use crate::eth;
use crate::ipv4;
use crate::read_be_u16;
use crate::udp;
use crate::write_be_u16;

/// TFTP read-request opcode.
pub const OP_RRQ: u16 = 1;
/// TFTP data opcode.
pub const OP_DATA: u16 = 3;
/// TFTP acknowledgement opcode.
pub const OP_ACK: u16 = 4;
/// TFTP error opcode.
pub const OP_ERROR: u16 = 5;

/// Well-known UDP port for TFTP requests.
pub const TFTP_PORT: u16 = 69;
/// TFTP base-protocol data payload length.
pub const DATA_BLOCK_LEN: usize = 512;

const CLIENT_PORT: u16 = 49_152;
const MAX_FRAME_LEN: usize = 1536;
const MAX_REQUEST_LEN: usize = 512;
const MAX_POLLS_PER_WAIT: usize = 1_000_000;

/// Monotonic time source used to bound polling waits.
pub trait TftpClock {
    /// Returns a monotonically increasing microsecond counter.
    fn now_us(&self) -> u64;
}

/// Parameters for a TFTP download.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TftpConfig<'a> {
    /// Local IPv4 address assigned to the Ethernet interface.
    pub local_ip: Ipv4Addr,
    /// IPv4 address of the TFTP server.
    pub server_ip: Ipv4Addr,
    /// Initial server UDP port; use [`TFTP_PORT`] for standard TFTP.
    pub server_port: u16,
    /// Filename sent in the octet-mode RRQ.
    pub filename: &'a str,
    /// Per-attempt receive timeout in microseconds.
    pub timeout_us: u64,
    /// Number of retries after each initial send.
    pub max_retries: usize,
}

/// A parsed TFTP DATA packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPacket<'a> {
    /// TFTP block number.
    pub block: u16,
    /// Data bytes for this block.
    pub payload: &'a [u8],
}

/// A parsed TFTP ERROR packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorPacket<'a> {
    /// Server-provided TFTP error code.
    pub code: u16,
    /// Optional error text.  Unterminated text is exposed through the end of
    /// the datagram because it is safe to inspect and RFC 1350 peers can omit
    /// the optional terminator in error cases.
    pub message: Option<&'a [u8]>,
}

/// Errors returned by the bounded TFTP client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TftpError {
    /// The supplied configuration is not usable for a bounded download.
    InvalidConfig,
    /// The RRQ filename is empty.
    EmptyFilename,
    /// The RRQ filename contains a NUL byte.
    FilenameContainsNul,
    /// A caller-supplied packet buffer is too short.
    BufferTooShort,
    /// The received opcode does not match the expected packet kind.
    UnexpectedOpcode(u16),
    /// A TFTP packet is too short for its mandatory fields.
    PacketTooShort,
    /// ARP resolution did not complete before retries were exhausted.
    ArpTimeout,
    /// A packet could not be sent to the Ethernet backend.
    TransmitFailed,
    /// A request or acknowledgement timed out after bounded retries.
    TransferTimeout,
    /// A matching TFTP DATA packet carried an unexpected block number.
    UnexpectedBlock {
        /// Block number required to continue the transfer.
        expected: u16,
        /// Block number received from the server.
        received: u16,
    },
    /// The output destination cannot hold the complete TFTP transfer.
    DestinationTooSmall,
    /// More than `u16::MAX` blocks would be needed for this transfer.
    BlockNumberOverflow,
    /// The server returned a TFTP ERROR packet.
    ServerError {
        /// Server-provided RFC 1350 error code.
        code: u16,
    },
    /// A matching IP or UDP packet was malformed.
    Network(ParseError),
    /// Frame construction failed before transmission.
    Encode(EncodeError),
}

impl From<EncodeError> for TftpError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

/// Encodes an octet-mode TFTP read request without options.
pub fn encode_rrq(buf: &mut [u8], filename: &str) -> Result<usize, TftpError> {
    if filename.is_empty() {
        return Err(TftpError::EmptyFilename);
    }
    if filename.as_bytes().contains(&0) {
        return Err(TftpError::FilenameContainsNul);
    }
    let len = 2usize
        .checked_add(filename.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(5))
        .and_then(|value| value.checked_add(1))
        .ok_or(TftpError::BufferTooShort)?;
    if buf.len() < len {
        return Err(TftpError::BufferTooShort);
    }
    write_be_u16(buf, 0, OP_RRQ);
    buf[2..2 + filename.len()].copy_from_slice(filename.as_bytes());
    let mode_offset = 2 + filename.len();
    buf[mode_offset] = 0;
    buf[mode_offset + 1..mode_offset + 6].copy_from_slice(b"octet");
    buf[mode_offset + 6] = 0;
    Ok(len)
}

/// Parses a TFTP DATA packet.
pub fn parse_data(packet: &[u8]) -> Result<DataPacket<'_>, TftpError> {
    if packet.len() < 4 {
        return Err(TftpError::PacketTooShort);
    }
    let opcode = read_be_u16(packet, 0);
    if opcode != OP_DATA {
        return Err(TftpError::UnexpectedOpcode(opcode));
    }
    Ok(DataPacket {
        block: read_be_u16(packet, 2),
        payload: &packet[4..],
    })
}

/// Returns whether a DATA packet completes a base-protocol transfer.
pub const fn is_final_data_block(payload_len: usize) -> bool {
    payload_len < DATA_BLOCK_LEN
}

/// Encodes a fixed-size TFTP acknowledgement packet.
pub fn encode_ack(buf: &mut [u8], block: u16) -> Result<usize, TftpError> {
    if buf.len() < 4 {
        return Err(TftpError::BufferTooShort);
    }
    write_be_u16(buf, 0, OP_ACK);
    write_be_u16(buf, 2, block);
    Ok(4)
}

/// Parses a TFTP ERROR packet.
pub fn parse_error(packet: &[u8]) -> Result<ErrorPacket<'_>, TftpError> {
    if packet.len() < 4 {
        return Err(TftpError::PacketTooShort);
    }
    let opcode = read_be_u16(packet, 0);
    if opcode != OP_ERROR {
        return Err(TftpError::UnexpectedOpcode(opcode));
    }
    let text = &packet[4..];
    let message = if text.is_empty() {
        None
    } else if let Some(end) = text.iter().position(|byte| *byte == 0) {
        Some(&text[..end])
    } else {
        Some(text)
    };
    Ok(ErrorPacket {
        code: read_be_u16(packet, 2),
        message,
    })
}

/// Downloads a base-protocol TFTP file into `out`.
///
/// This function performs ARP resolution, sends an RRQ, accepts the server's
/// selected transfer port on first DATA, acknowledges every accepted DATA
/// block, and retries the RRQ or most recent ACK within `max_retries`.
pub fn download_into(
    eth_io: &mut dyn EthernetFrameIo,
    clock: &dyn TftpClock,
    cfg: &TftpConfig<'_>,
    out: &mut [u8],
) -> Result<usize, TftpError> {
    if cfg.timeout_us == 0 || cfg.server_port == 0 {
        return Err(TftpError::InvalidConfig);
    }
    if eth_io.max_frame_len() < eth::HEADER_LEN + arp::ARP_PAYLOAD_LEN {
        return Err(TftpError::InvalidConfig);
    }

    let local_mac = eth_io.mac_addr();
    let server_mac = resolve_server_mac(eth_io, clock, cfg, local_mac)?;
    let mut packet = [0u8; MAX_REQUEST_LEN];
    let mut packet_len = encode_rrq(&mut packet, cfg.filename)?;
    let mut expected_block = 1u16;
    let mut transfer_port = None;
    let mut written = 0usize;
    let mut rx = [0u8; MAX_FRAME_LEN];

    loop {
        let mut received_expected_data = false;
        for _ in 0..=cfg.max_retries {
            if !send_udp_packet(
                eth_io,
                local_mac,
                server_mac,
                cfg.local_ip,
                cfg.server_ip,
                CLIENT_PORT,
                transfer_port.unwrap_or(cfg.server_port),
                &packet[..packet_len],
            )? {
                return Err(TftpError::TransmitFailed);
            }

            let start = clock.now_us();
            for _ in 0..MAX_POLLS_PER_WAIT {
                if clock.now_us().wrapping_sub(start) >= cfg.timeout_us {
                    break;
                }
                let Some(frame_len) = eth_io.try_recv_frame(&mut rx) else {
                    continue;
                };
                if frame_len > rx.len() {
                    continue;
                }
                let datagram = match parse_tftp_datagram(&rx[..frame_len]) {
                    Ok(datagram) => datagram,
                    Err(_) => continue,
                };
                if datagram.src_mac != server_mac
                    || datagram.src_ip != cfg.server_ip
                    || datagram.dst_ip != cfg.local_ip
                    || datagram.dst_port != CLIENT_PORT
                {
                    continue;
                }
                if let Some(port) = transfer_port {
                    if datagram.src_port != port {
                        continue;
                    }
                }

                if datagram.payload.len() < 2 {
                    return Err(TftpError::PacketTooShort);
                }
                match read_be_u16(datagram.payload, 0) {
                    OP_ERROR => {
                        let error = parse_error(datagram.payload)?;
                        return Err(TftpError::ServerError { code: error.code });
                    }
                    OP_DATA => {
                        let data = parse_data(datagram.payload)?;
                        if transfer_port.is_none() {
                            transfer_port = Some(datagram.src_port);
                        }
                        if data.block == expected_block.wrapping_sub(1) {
                            if !send_udp_packet(
                                eth_io,
                                local_mac,
                                server_mac,
                                cfg.local_ip,
                                cfg.server_ip,
                                CLIENT_PORT,
                                datagram.src_port,
                                &packet[..packet_len],
                            )? {
                                return Err(TftpError::TransmitFailed);
                            }
                            continue;
                        }
                        if data.block != expected_block {
                            return Err(TftpError::UnexpectedBlock {
                                expected: expected_block,
                                received: data.block,
                            });
                        }
                        let end = written
                            .checked_add(data.payload.len())
                            .ok_or(TftpError::DestinationTooSmall)?;
                        if end > out.len() {
                            return Err(TftpError::DestinationTooSmall);
                        }
                        out[written..end].copy_from_slice(data.payload);
                        written = end;
                        packet_len = encode_ack(&mut packet, data.block)?;
                        if !send_udp_packet(
                            eth_io,
                            local_mac,
                            server_mac,
                            cfg.local_ip,
                            cfg.server_ip,
                            CLIENT_PORT,
                            datagram.src_port,
                            &packet[..packet_len],
                        )? {
                            return Err(TftpError::TransmitFailed);
                        }
                        if is_final_data_block(data.payload.len()) {
                            return Ok(written);
                        }
                        expected_block = expected_block
                            .checked_add(1)
                            .ok_or(TftpError::BlockNumberOverflow)?;
                        received_expected_data = true;
                        break;
                    }
                    _ => continue,
                }
            }
            if received_expected_data {
                break;
            }
        }
        if !received_expected_data {
            return Err(TftpError::TransferTimeout);
        }
    }
}

fn resolve_server_mac(
    eth_io: &mut dyn EthernetFrameIo,
    clock: &dyn TftpClock,
    cfg: &TftpConfig<'_>,
    local_mac: MacAddr,
) -> Result<MacAddr, TftpError> {
    let mut request = [0u8; eth::HEADER_LEN + arp::ARP_PAYLOAD_LEN];
    let request_len =
        arp::encode_arp_request(&mut request, local_mac, cfg.local_ip, cfg.server_ip)?;
    let mut rx = [0u8; MAX_FRAME_LEN];
    for _ in 0..=cfg.max_retries {
        if !eth_io.try_send_frame(&request[..request_len]) {
            return Err(TftpError::TransmitFailed);
        }
        let start = clock.now_us();
        for _ in 0..MAX_POLLS_PER_WAIT {
            if clock.now_us().wrapping_sub(start) >= cfg.timeout_us {
                break;
            }
            let Some(frame_len) = eth_io.try_recv_frame(&mut rx) else {
                continue;
            };
            if frame_len > rx.len() {
                continue;
            }
            if let Ok(mac) = arp::parse_arp_reply(&rx[..frame_len], cfg.local_ip, cfg.server_ip) {
                return Ok(mac);
            }
        }
    }
    Err(TftpError::ArpTimeout)
}

fn send_udp_packet(
    eth_io: &mut dyn EthernetFrameIo,
    local_mac: MacAddr,
    server_mac: MacAddr,
    local_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    local_port: u16,
    server_port: u16,
    payload: &[u8],
) -> Result<bool, TftpError> {
    let mut frame = [0u8; MAX_FRAME_LEN];
    let len = crate::encode_udp_ipv4_frame(
        &mut frame,
        local_mac,
        server_mac,
        local_ip,
        server_ip,
        local_port,
        server_port,
        payload,
    )?;
    Ok(eth_io.try_send_frame(&frame[..len]))
}

fn parse_tftp_datagram(frame: &[u8]) -> Result<crate::UdpIpv4DatagramView<'_>, TftpError> {
    let (_, ethernet_payload) = eth::parse_ethernet_ii(frame).map_err(TftpError::Network)?;
    let ip = ipv4::parse_ipv4_packet(ethernet_payload).map_err(TftpError::Network)?;
    if ip.protocol != ipv4::IPV4_PROTOCOL_UDP {
        return Err(TftpError::Network(ParseError::NotUdp));
    }
    udp::validate_ipv4_udp_checksum(ip.src_ip, ip.dst_ip, ip.payload)
        .map_err(TftpError::Network)?;
    crate::parse_udp_ipv4_frame(frame).map_err(TftpError::Network)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 1]);
    const SERVER_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv4Addr = [192, 0, 2, 10];
    const SERVER_IP: Ipv4Addr = [192, 0, 2, 1];

    struct Clock;

    impl TftpClock for Clock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    struct TestEthernet {
        frames: [[u8; MAX_FRAME_LEN]; 2],
        frame_lens: [usize; 2],
        next_frame: usize,
        sent: usize,
    }

    impl EthernetFrameIo for TestEthernet {
        fn max_frame_len(&self) -> usize {
            MAX_FRAME_LEN
        }

        fn mac_addr(&self) -> MacAddr {
            LOCAL_MAC
        }

        fn try_recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
            let len = *self.frame_lens.get(self.next_frame)?;
            buf[..len].copy_from_slice(&self.frames[self.next_frame][..len]);
            self.next_frame += 1;
            Some(len)
        }

        fn try_send_frame(&mut self, _frame: &[u8]) -> bool {
            self.sent += 1;
            true
        }
    }

    fn tftp_config() -> TftpConfig<'static> {
        TftpConfig {
            local_ip: LOCAL_IP,
            server_ip: SERVER_IP,
            server_port: TFTP_PORT,
            filename: "BCM2712.img",
            timeout_us: 1,
            max_retries: 0,
        }
    }

    #[test]
    fn rrq_encodes_octet_request() {
        let mut out = [0u8; 32];
        let len = encode_rrq(&mut out, "kernel.img").unwrap();
        assert_eq!(&out[..len], b"\0\x01kernel.img\0octet\0");
    }

    #[test]
    fn rrq_rejects_empty_filename() {
        assert_eq!(encode_rrq(&mut [0; 16], ""), Err(TftpError::EmptyFilename));
    }

    #[test]
    fn rrq_rejects_nul_filename() {
        assert_eq!(
            encode_rrq(&mut [0; 16], "bad\0name"),
            Err(TftpError::FilenameContainsNul)
        );
    }

    #[test]
    fn rrq_rejects_small_buffer() {
        assert_eq!(
            encode_rrq(&mut [0; 8], "kernel.img"),
            Err(TftpError::BufferTooShort)
        );
    }

    #[test]
    fn data_packet_parses() {
        assert_eq!(
            parse_data(&[0, 3, 0, 2, 1, 2]),
            Ok(DataPacket {
                block: 2,
                payload: &[1, 2]
            })
        );
    }

    #[test]
    fn data_packet_rejects_short_packet() {
        assert_eq!(parse_data(&[0, 3, 0]), Err(TftpError::PacketTooShort));
    }

    #[test]
    fn acknowledgement_encodes() {
        let mut out = [0u8; 4];
        assert_eq!(encode_ack(&mut out, 0x1234), Ok(4));
        assert_eq!(out, [0, 4, 0x12, 0x34]);
    }

    #[test]
    fn error_packet_parses() {
        assert_eq!(
            parse_error(&[0, 5, 0, 1, b'o', b'o', b'p', b's', 0]),
            Ok(ErrorPacket {
                code: 1,
                message: Some(b"oops")
            })
        );
    }

    #[test]
    fn final_data_block_detection() {
        assert!(is_final_data_block(511));
        assert!(!is_final_data_block(512));
    }

    #[test]
    fn destination_overflow_is_reported() {
        let mut frames = [[0u8; MAX_FRAME_LEN]; 2];
        let arp_len =
            arp::encode_arp_reply(&mut frames[0], SERVER_MAC, SERVER_IP, LOCAL_MAC, LOCAL_IP)
                .unwrap();
        let mut data = [0u8; 4 + DATA_BLOCK_LEN];
        write_be_u16(&mut data, 0, OP_DATA);
        write_be_u16(&mut data, 2, 1);
        let data_len = crate::encode_udp_ipv4_frame(
            &mut frames[1],
            SERVER_MAC,
            LOCAL_MAC,
            SERVER_IP,
            LOCAL_IP,
            20_000,
            CLIENT_PORT,
            &data,
        )
        .unwrap();
        let mut eth = TestEthernet {
            frames,
            frame_lens: [arp_len, data_len],
            next_frame: 0,
            sent: 0,
        };
        assert_eq!(
            download_into(&mut eth, &Clock, &tftp_config(), &mut [0]),
            Err(TftpError::DestinationTooSmall)
        );
        assert_eq!(eth.sent, 2);
    }
}
