//! Block device abstraction for storage I/O.

use core::mem::MaybeUninit;

/// Logical Block Address type for block device operations.
pub type Lba = u64;

/// Error types for block device I/O operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// The caller supplied invalid parameters (e.g., zero length, wrong units).
    InvalidParam,
    /// The request exceeds device capacity or addresses an invalid LBA.
    OutOfRange,
    /// The buffer size or address does not meet device alignment constraints.
    Align,
    /// The device/controller cannot accept more requests at the moment.
    Busy,
    /// The operation did not complete within the expected time.
    Timeout,
    /// The device or transport reported a hardware error.
    Device,
    /// The target media or device is read-only.
    ReadOnly,
    /// The requested operation is not supported by this device.
    Unsupported,
    /// The system could not allocate required resources (e.g., bounce buffers).
    NoMemory,
    /// A generic I/O failure not covered by other variants.
    Io,
    /// The device/transport violated the expected protocol (bad magic, wrong version, etc.).
    Protocol,
    /// The device isn't ready (e.g., uninitialized, requires reinitialization).
    NotReady,
    /// Internal queues/data structures are corrupted or inconsistent.
    Corrupted,
}

/// Generic trait for block-addressable storage devices (virtio-blk, SDIO, SATA, NVMe, ...).
///
/// The API is synchronous and thread-safe; implementations should use internal
/// synchronization as needed. I/O is defined as all-or-nothing (no partial transfers).
pub trait BlockDevice: Send + Sync {
    /// Initializes the block device.
    ///
    /// # Errors
    /// Returns an error if device initialization fails.
    fn init(&mut self) -> Result<(), IoError>;

    /// Returns the logical block size in bytes.
    ///
    /// Must be a power of two and typically >= 512.
    fn block_size(&self) -> usize;

    /// Returns the total number of addressable logical blocks.
    ///
    /// Capacity in bytes is `block_size() as u128 * num_blocks() as u128`.
    fn num_blocks(&self) -> u64;

    /// Reads data starting at `lba` into `buf`.
    ///
    /// # Requirements
    /// - `buf.len()` must be a multiple of `block_size()`.
    /// - The range `lba .. lba + (buf.len() / block_size())` must be in-bounds.
    ///
    /// # Errors
    /// Returns an error if the read operation fails.
    ///
    /// On success, the entire buffer is filled. On error, no data is considered transferred.
    fn read_at(&self, lba: Lba, buf: &mut [MaybeUninit<u8>]) -> Result<(), IoError>;

    /// Writes data starting at `lba` from `buf`.
    ///
    /// # Requirements
    /// Requirements mirror `read_at`:
    ///
    /// - `buf.len()` must be a multiple of `block_size()`.
    /// - The target range must be in-bounds.
    ///
    /// # Errors
    /// Returns `IoError::ReadOnly` if the device is not writable.
    ///
    /// On success, the entire buffer is written. On error, no data is considered transferred.
    fn write_at(&self, lba: Lba, buf: &[u8]) -> Result<(), IoError>;

    /// Flushes any volatile write caches to non-volatile media.
    ///
    /// # Errors
    /// Returns an error if the flush operation fails.
    ///
    /// Devices without a write cache may return `Ok(())`.
    fn flush(&self) -> Result<(), IoError>;

    /// Returns the maximum number of bytes accepted in a single I/O request.
    ///
    /// # Semantics
    /// - `Ok(Some(n))`: the driver exposes a known upper bound `n` (bytes).
    /// - `Ok(None)`: no explicit bound is known/advertised; callers should use a
    ///   conservative chunk size policy (e.g., 128–256 KiB) and respect block alignment.
    ///
    /// # Errors
    /// Returns `Err(NotReady)` if the device is not initialized yet.
    fn max_io_bytes(&self) -> Result<Option<usize>, IoError>;

    /// Indicates whether the device/media is read-only.
    ///
    /// # Errors
    /// Returns an error if the device state cannot be determined.
    fn is_read_only(&self) -> Result<bool, IoError>;

    /// Uninstalls and releases the device.
    fn uninstall(&self);
}
