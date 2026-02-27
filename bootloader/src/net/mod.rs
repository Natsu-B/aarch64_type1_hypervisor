#[cfg(any(feature = "rpi4_net", feature = "virtio_net"))]
pub mod config;
#[cfg(feature = "rpi4_net")]
pub mod rpi4;
#[cfg(any(feature = "rpi4_net", feature = "virtio_net"))]
pub mod udp_uart;
#[cfg(feature = "virtio_net")]
pub mod virtio;
