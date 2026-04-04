//! Block-device implementations built on top of transport crates.

#![no_std]

mod virtio_blk;

pub use virtio_blk::VirtIoBlk;
