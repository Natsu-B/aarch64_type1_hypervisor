use net_proto::Ipv4Addr;

/// Local IPv4 used by the bootloader UDP/ARP stack.
/// Change this value to fit your LAN.
pub const LOCAL_IP: Ipv4Addr = [192, 168, 2, 2];
