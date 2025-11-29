#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use block_device::VirtIoBlk;
use block_device_api::BlockDevice;
use block_device_api::IoError;
use filesystem::FileSystemErr;

mod partition;
use partition::PartitionIndex;

pub use allocator::AlignedSliceBox;
pub use filesystem::filesystem::FileHandle;
pub use filesystem::filesystem::OpenOptions;

pub struct StorageDevice {
    dev: Arc<dyn BlockDevice>,
    partition: PartitionIndex,
}

impl StorageDevice {
    pub fn new_virtio(mmio: usize) -> Result<Self, StorageDeviceErr> {
        let mut io = VirtIoBlk::new(mmio).map_err(error_from_ioerror)?;
        io.init().map_err(error_from_ioerror)?;
        let dev = Arc::new(io);
        let partition = PartitionIndex::new(dev.as_ref())?;
        Ok(Self { partition, dev })
    }

    pub fn open(
        &self,
        partition_idx: u8,
        path: &str,
        opts: &OpenOptions,
    ) -> Result<FileHandle, StorageDeviceErr> {
        self.partition
            .open(&self.dev, partition_idx, path, opts)
            .map_err(error_from_file_system_err)
    }

    pub fn create_file(
        &self,
        partition_idx: u8,
        path: &str,
    ) -> Result<FileHandle, StorageDeviceErr> {
        self.partition
            .create_file(&self.dev, partition_idx, path)
            .map_err(error_from_file_system_err)
    }

    pub fn remove_file(&self, partition_idx: u8, path: &str) -> Result<(), StorageDeviceErr> {
        self.partition
            .remove_file(&self.dev, partition_idx, path)
            .map_err(error_from_file_system_err)
    }

    pub fn copy(&self, partition_idx: u8, from: &str, to: &str) -> Result<(), StorageDeviceErr> {
        self.partition
            .copy(&self.dev, partition_idx, from, to)
            .map_err(error_from_file_system_err)
    }

    pub fn rename(&self, partition_idx: u8, from: &str, to: &str) -> Result<(), StorageDeviceErr> {
        self.partition
            .rename(&self.dev, partition_idx, from, to)
            .map_err(error_from_file_system_err)
    }

    pub fn create_dir(&self, partition_idx: u8, path: &str) -> Result<(), StorageDeviceErr> {
        self.partition
            .create_dir(&self.dev, partition_idx, path)
            .map_err(error_from_file_system_err)
    }

    pub fn remove_dir(&self, partition_idx: u8, path: &str) -> Result<(), StorageDeviceErr> {
        self.partition
            .remove_dir(&self.dev, partition_idx, path)
            .map_err(error_from_file_system_err)
    }
}

impl Drop for StorageDevice {
    fn drop(&mut self) {
        self.dev.uninstall();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDeviceErr {
    IoErr(IoError),
    FileSystemErr(FileSystemErr),
    StillUsed,
}

fn error_from_ioerror(err: IoError) -> StorageDeviceErr {
    StorageDeviceErr::IoErr(err)
}

fn error_from_file_system_err(err: FileSystemErr) -> StorageDeviceErr {
    StorageDeviceErr::FileSystemErr(err)
}
