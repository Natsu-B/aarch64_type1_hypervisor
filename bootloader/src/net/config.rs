use net_proto::Ipv4Addr;

/// Local IPv4 used by the bootloader UDP/ARP stack.
/// Change this value to fit your LAN.
#[cfg(feature = "rpi4_net")]
pub const LOCAL_IP: Ipv4Addr = [192, 168, 2, 2];
#[cfg(feature = "virtio_net")]
pub const LOCAL_IP: Ipv4Addr = [10, 0, 2, 15];
