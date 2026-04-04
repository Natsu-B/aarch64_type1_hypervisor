//! Block-device API traits and MMIO modeling helpers.

#![no_std]

pub use io_api::block_device::*;
pub mod virtio_blk_mmio;
