use core::mem::MaybeUninit;
use core::usize;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::sync::Weak;
use block_device_api::BlockDevice;

use crate::FileSystemErr;
use crate::aligned_box::AlignedSliceBox;
use crate::filesystem::fat::FatType;
use crate::filesystem::fat::FatVolume;
use crate::filesystem::fat32::FAT32FileSystem;
use crate::from_io_err;

pub(crate) mod fat;
pub(crate) mod fat32;

pub(crate) mod file_system {
    use super::*;

    trait FileSystemDriver: Sync {
        fn try_mount(
            &self,
            block_device: &Arc<dyn BlockDevice>,
            start_sector: u64,
            total_sector: u64,
            boot_sector: &[u8],
        ) -> Result<Option<Arc<dyn FileSystemTrait>>, FileSystemErr>;
    }

    struct FatDriver;
    static FAT_DRIVER: FatDriver = FatDriver;
    static FILE_SYSTEM_DRIVERS: &[&dyn FileSystemDriver] = &[&FAT_DRIVER];

    pub fn new(
        block_device: &Arc<dyn BlockDevice>,
        start_sector: u64,
        total_sector: u64,
    ) -> Result<Arc<dyn FileSystemTrait>, FileSystemErr> {
        let mut boot_sector: Box<[MaybeUninit<u8>]> =
            Box::new_uninit_slice(block_device.block_size());
        block_device
            .read_at(start_sector, &mut boot_sector)
            .map_err(from_io_err)?;
        // The device promises the buffer is fully initialized on success
        let boot_sector_bytes: Box<[u8]> = unsafe { boot_sector.assume_init() };
        for driver in FILE_SYSTEM_DRIVERS {
            if let Some(fs) =
                driver.try_mount(block_device, start_sector, total_sector, &boot_sector_bytes)?
            {
                return Ok(fs);
            }
        }
        Err(FileSystemErr::UnsupportedFileSystem)
    }

    impl FileSystemDriver for FatDriver {
        fn try_mount(
            &self,
            block_device: &Arc<dyn BlockDevice>,
            start_sector: u64,
            total_sector: u64,
            boot_sector: &[u8],
        ) -> Result<Option<Arc<dyn FileSystemTrait>>, FileSystemErr> {
            let Some(volume) = FatVolume::from_boot_sector(
                block_device.block_size(),
                boot_sector,
                start_sector,
                total_sector,
            )?
            else {
                return Ok(None);
            };
            match volume.kind {
                FatType::Fat32 => {
                    let fat32_filesystem = FAT32FileSystem::new(volume)?;
                    Ok(Some(Arc::new(fat32_filesystem)))
                }
                FatType::Fat12 | FatType::Fat16 => Ok(None),
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpenOptions {
    Read,
    Write,
}

pub(crate) trait FileSystemTrait {
    // file
    fn open(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        file_system: &Arc<dyn FileSystemTrait>,
        path: &str,
        opts: &OpenOptions,
    ) -> Result<FileHandle, FileSystemErr>;
    fn remove_file(&self, path: &str) -> Result<(), FileSystemErr>;
    fn copy(&self, from: &str, to: &str) -> Result<(), FileSystemErr>;
    fn rename(&self, from: &str, to: &str) -> Result<(), FileSystemErr>;

    // dir
    fn create_dir(&self, path: &str) -> Result<(), FileSystemErr>;
    fn remove_dir(&self, path: &str) -> Result<(), FileSystemErr>;

    fn read(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        align: usize,
        meta: &DirMeta,
    ) -> Result<AlignedSliceBox<u8>, FileSystemErr>;

    fn read_at(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        offset: u64,
        buf: &mut [MaybeUninit<u8>],
        meta: &DirMeta,
    ) -> Result<u64, FileSystemErr>;

    fn write_at(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        offset: u64,
        buf: &[u8],
        meta: &mut DirMeta,
    ) -> Result<u64, FileSystemErr>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirMeta {
    is_dir: bool,
    is_readonly: bool,
    first_cluster: u32,
    file_size: u32,
    entry_lba: u64,
    entry_offset: u16,
}

#[derive(Debug, Clone)]
pub struct FileHandle {
    dev_handle: Weak<dyn BlockDevice>,
    file_handle: Weak<dyn FileSystemTrait>,
    meta: DirMeta,
    opts: OpenOptions,
}

impl FileHandle {
    pub fn read(&self, align: usize) -> Result<AlignedSliceBox<u8>, FileSystemErr> {
        let Some(dev) = self.dev_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        let Some(file) = self.file_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        file.read(&dev, align, &self.meta)
    }

    pub fn read_at(&self, offset: u64, buf: &mut [MaybeUninit<u8>]) -> Result<u64, FileSystemErr> {
        let Some(dev) = self.dev_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        let Some(file) = self.file_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        file.read_at(&dev, offset, buf, &self.meta)
    }

    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<u64, FileSystemErr> {
        if self.opts != OpenOptions::Write {
            return Err(FileSystemErr::ReadOnly);
        }
        let Some(dev) = self.dev_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        let Some(file) = self.file_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        file.write_at(&dev, offset, buf, &mut self.meta)
    }

    pub fn size(&self) -> Result<u64, FileSystemErr> {
        Ok(self.meta.file_size as u64)
    }

    pub fn flush(&self) -> Result<(), FileSystemErr> {
        let Some(dev) = self.dev_handle.upgrade() else {
            return Err(FileSystemErr::Closed);
        };
        dev.flush().map_err(from_io_err)
    }
}
