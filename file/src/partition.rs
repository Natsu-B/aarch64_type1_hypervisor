use core::ptr::addr_of;

use alloc::sync::Arc;
use alloc::vec::Vec;
use block_device_api::BlockDevice;
use filesystem::FileSystemErr;
use filesystem::aligned_box::AlignedSliceBox;
use filesystem::filesystem::FileHandle;
use filesystem::filesystem::FileSystemTrait;
use filesystem::filesystem::OpenOptions;
use filesystem::mount_filesystem;
use mutex::SpinLock;
use typestate::Le;
use typestate::Unaligned;
use typestate::unalign_read;

use crate::StorageDeviceErr;

pub(crate) struct PartitionIndex {
    sector_kind: BootSector,
    partitions: SpinLock<Vec<(u8, Arc<dyn FileSystemTrait>)>>,
}

impl PartitionIndex {
    pub(crate) const BOOT_SIGNATURE: u16 = 0xAA55;

    pub(crate) fn new<D>(block_device: &D) -> Result<Self, StorageDeviceErr>
    where
        D: BlockDevice,
    {
        let mut buffer =
            AlignedSliceBox::<u8>::new_uninit_with_align(block_device.block_size(), 1).unwrap();
        block_device
            .read_at(0, &mut buffer)
            .map_err(StorageDeviceErr::IoErr)?;
        let mut buffer = unsafe { buffer.assume_init() };
        let boot_record = buffer.as_mut_ptr() as *mut bootsector::mbr::MasterBootRecord;
        if unalign_read!((*boot_record).boot_signature => Le<Unaligned<u16>>)
            != Self::BOOT_SIGNATURE
        {
            return Ok(Self {
                sector_kind: BootSector::Unknown,
                partitions: SpinLock::new(Vec::with_capacity(1)),
            });
        }
        let config = bootsector::MBRConfig {
            partition: [
                bootsector::MBRPartition {
                    kind: unsafe { *addr_of!((*boot_record).first_partition.kind) },
                    first_sector: unalign_read!((*boot_record).first_partition.lba_first_sector => Le<Unaligned<u32>>),
                    total_sector: unalign_read!((*boot_record).first_partition.num_of_total_sector => Le<Unaligned<u32>>),
                },
                bootsector::MBRPartition {
                    kind: unsafe { *addr_of!((*boot_record).second_partition.kind) },
                    first_sector: unalign_read!((*boot_record).second_partition.lba_first_sector => Le<Unaligned<u32>>),
                    total_sector: unalign_read!((*boot_record).second_partition.num_of_total_sector => Le<Unaligned<u32>>),
                },
                bootsector::MBRPartition {
                    kind: unsafe { *addr_of!((*boot_record).third_partition.kind) },
                    first_sector: unalign_read!((*boot_record).third_partition.lba_first_sector => Le<Unaligned<u32>>),
                    total_sector: unalign_read!((*boot_record).third_partition.num_of_total_sector => Le<Unaligned<u32>>),
                },
                bootsector::MBRPartition {
                    kind: unsafe { *addr_of!((*boot_record).fourth_partition.kind) },
                    first_sector: unalign_read!((*boot_record).fourth_partition.lba_first_sector => Le<Unaligned<u32>>),
                    total_sector: unalign_read!((*boot_record).fourth_partition.num_of_total_sector => Le<Unaligned<u32>>),
                },
            ],
        };
        Ok(Self {
            sector_kind: match config.partition[0].kind {
                bootsector::mbr::MasterBootRecordPartitionKind::TYPE_GPT => {
                    // TODO GPT check
                    todo!();
                    // BootSector::GPT
                }
                _ => BootSector::MBR(config),
            },
            partitions: SpinLock::new(Vec::with_capacity(2)),
        })
    }

    fn get_partition_start_total_sector(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
    ) -> Result<(u64, u64), FileSystemErr> {
        match &self.sector_kind {
            BootSector::MBR(x) => {
                if partition_idx >= 4 {
                    return Err(FileSystemErr::UnknownPartition);
                }
                if x.partition[partition_idx as usize].kind
                    == bootsector::mbr::MasterBootRecordPartitionKind::UNUSED
                {
                    return Err(FileSystemErr::UnusedPartition);
                }
                let start = x.partition[partition_idx as usize].first_sector;
                let total = x.partition[partition_idx as usize].total_sector;
                Ok((start as u64, total as u64))
            }
            BootSector::GPT => {
                todo!()
            }
            BootSector::Unknown => {
                if partition_idx == 0 {
                    Ok((0, block_device.num_blocks()))
                } else {
                    Err(FileSystemErr::UnknownPartition)
                }
            }
        }
    }

    fn get_partition_driver(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
    ) -> Result<Arc<dyn FileSystemTrait>, FileSystemErr> {
        if let Some(partition_driver) = self.partitions.lock().iter().find(|x| x.0 == partition_idx)
        {
            return Ok(partition_driver.1.clone());
        };
        let (start_sector, total_sector) =
            self.get_partition_start_total_sector(block_device, partition_idx)?;
        let file_driver = mount_filesystem(block_device, start_sector, total_sector)?;
        self.partitions
            .lock()
            .push((partition_idx, file_driver.clone()));
        Ok(file_driver)
    }

    pub(crate) fn open(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        path: &str,
        opts: &OpenOptions,
    ) -> Result<FileHandle, FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.open(block_device, &file_driver, path, opts)
    }

    pub(crate) fn create_file(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        path: &str,
    ) -> Result<FileHandle, FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.create_file(block_device, &file_driver, path)
    }

    pub(crate) fn remove_file(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        path: &str,
    ) -> Result<(), FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.remove_file(block_device, path)
    }

    pub(crate) fn copy(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        from: &str,
        to: &str,
    ) -> Result<(), FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.copy(block_device, from, to)
    }

    pub(crate) fn rename(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        from: &str,
        to: &str,
    ) -> Result<(), FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.rename(block_device, from, to)
    }

    pub(crate) fn create_dir(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        path: &str,
    ) -> Result<(), FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.create_dir(block_device, path)
    }

    pub(crate) fn remove_dir(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        partition_idx: u8,
        path: &str,
    ) -> Result<(), FileSystemErr> {
        let file_driver = self.get_partition_driver(block_device, partition_idx)?;
        file_driver.remove_dir(block_device, path)
    }
}

enum BootSector {
    MBR(bootsector::MBRConfig),
    GPT,
    Unknown,
}

mod bootsector {
    pub(crate) mod mbr {
        use core::mem::size_of;
        use typestate::Le;
        use typestate::Unaligned;
        use typestate_macro::RawReg;

        #[allow(clippy::assertions_on_constants)]
        const _: () = assert!(size_of::<MasterBootRecord>() == 512);

        #[repr(packed)]
        pub(crate) struct MasterBootRecord {
            loader: [u8; 446],
            pub(crate) first_partition: MasterBootRecordPartitionTable,
            pub(crate) second_partition: MasterBootRecordPartitionTable,
            pub(crate) third_partition: MasterBootRecordPartitionTable,
            pub(crate) fourth_partition: MasterBootRecordPartitionTable,
            pub(crate) boot_signature: Le<Unaligned<u16>>,
        }

        #[repr(C)]
        pub(crate) struct MasterBootRecordPartitionTable {
            boot_flags: u8,
            chs_first_sector: [u8; 3],
            pub(crate) kind: MasterBootRecordPartitionKind,
            chs_last_sector: [u8; 3],
            pub(crate) lba_first_sector: Le<Unaligned<u32>>,
            pub(crate) num_of_total_sector: Le<Unaligned<u32>>,
        }

        #[repr(transparent)]
        #[derive(Clone, Copy, RawReg, PartialEq)]
        pub(crate) struct MasterBootRecordPartitionKind(u8);

        impl MasterBootRecordPartitionKind {
            pub(crate) const UNUSED: Self = Self(0);
            pub(crate) const TYPE_FAT32: Self = Self(0x0C); // LBA
            pub(crate) const TYPE_GPT: Self = Self(0xEE);
        }
    }

    pub(crate) struct MBRPartition {
        pub(crate) kind: mbr::MasterBootRecordPartitionKind,
        pub(crate) first_sector: u32,
        pub(crate) total_sector: u32,
    }

    pub(crate) struct MBRConfig {
        pub(crate) partition: [MBRPartition; 4],
    }
}
