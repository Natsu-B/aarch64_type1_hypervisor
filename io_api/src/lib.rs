//! Generic I/O abstraction layer for various device types.
//!
//! This crate provides trait definitions for:
//! - Block devices (storage)
//! - Serial I/O (UART)
//! - Ethernet interfaces
//! - Generic byte streams

#![no_std]

pub mod block_device;
pub mod ethernet;
pub mod serial;
pub mod stream;
