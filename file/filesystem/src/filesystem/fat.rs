use core::mem::size_of;

use typestate::Le;
use typestate::Unaligned;
use typestate::unalign_read;

use crate::FileSystemErr;
use crate::filesystem::fat32::sector::FAT32BootSector;

const FAT_BOOT_SIGNATURE: u16 = 0xAA55;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FatVolume {
    pub(crate) kind: FatType,
    pub(crate) bytes_per_sector: u16,
    pub(crate) sectors_per_cluster: u8,
    pub(crate) reserved_sectors: u16,
    pub(crate) num_fats: u8,
    pub(crate) sectors_per_fat: u32,
    pub(crate) root_dir_entries: u16,
    pub(crate) root_dir_sectors: u32,
    pub(crate) hidden_sectors: u32,
    pub(crate) total_sectors: u32,
    pub(crate) count_of_clusters: u32,
    pub(crate) root_dir_cluster: Option<u32>,
    pub(crate) fs_info_sector: Option<u16>,
}

impl FatVolume {
    pub(crate) fn from_boot_sector(
        block_size: usize,
        boot_sector: &[u8],
        start_sector: u64,
        partition_total_sectors: u64,
    ) -> Result<Option<Self>, FileSystemErr> {
        if boot_sector.len() < size_of::<FAT32BootSector>() {
            return Ok(None);
        }
        let boot = unsafe { &*(boot_sector.as_ptr() as *const FAT32BootSector) };
        if unalign_read!(boot.bs_boot_sign => Le<Unaligned<u16>>) != FAT_BOOT_SIGNATURE {
            return Ok(None);
        }

        let bytes_per_sector = unalign_read!(boot.bpb_bytes_per_sec => Le<Unaligned<u16>>);
        match bytes_per_sector {
            512 | 1024 | 2048 | 4096 => {}
            _ => return Err(FileSystemErr::Corrupted),
        }
        if bytes_per_sector as usize != block_size {
            return Err(FileSystemErr::Corrupted);
        }

        let sectors_per_cluster = boot.bpb_sec_per_clus;
        match sectors_per_cluster {
            1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 => {}
            _ => return Err(FileSystemErr::Corrupted),
        }

        let reserved_sectors = unalign_read!(boot.bpb_rsvd_sec_cnt => Le<Unaligned<u16>>);
        if reserved_sectors == 0 {
            return Err(FileSystemErr::Corrupted);
        }
        let num_fats = boot.bpb_num_fats;
        if num_fats == 0 {
            return Err(FileSystemErr::Corrupted);
        }
        let root_dir_entries = unalign_read!(boot.bpb_root_ent_cnt => Le<Unaligned<u16>>);
        let total_sectors = match unalign_read!(boot.bpb_tot_sec_16 => Le<Unaligned<u16>>) {
            0 => unalign_read!(boot.bpb_tot_sec_32 => Le<Unaligned<u32>>),
            v => v as u32,
        };
        if total_sectors == 0 {
            return Err(FileSystemErr::Corrupted);
        }
        if partition_total_sectors != 0 && total_sectors as u64 > partition_total_sectors {
            return Err(FileSystemErr::Corrupted);
        }

        let sectors_per_fat = match unalign_read!(boot.bpb_fat_sz16 => Le<Unaligned<u16>>) {
            0 => unalign_read!(boot.bpb_fat_sz_32 => Le<Unaligned<u32>>),
            v => v as u32,
        };
        if sectors_per_fat == 0 {
            return Err(FileSystemErr::Corrupted);
        }

        let root_dir_sectors = (root_dir_entries as u32 * 32 + (bytes_per_sector as u32 - 1))
            / bytes_per_sector as u32;
        let fat_region = reserved_sectors as u32 + num_fats as u32 * sectors_per_fat;
        let total_system = fat_region
            .checked_add(root_dir_sectors)
            .ok_or(FileSystemErr::Corrupted)?;
        let data_sectors = total_sectors
            .checked_sub(total_system)
            .ok_or(FileSystemErr::Corrupted)?;
        let count_of_clusters = data_sectors / sectors_per_cluster as u32;
        if count_of_clusters == 0 {
            return Err(FileSystemErr::Corrupted);
        }

        let kind = if count_of_clusters < 4_085 {
            FatType::Fat12
        } else if count_of_clusters < 65_525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };
        let hidden_sectors = unalign_read!(boot.bpb_hidd_sec => Le<Unaligned<u32>>);
        if hidden_sectors as u64 != start_sector {
            return Err(FileSystemErr::Corrupted);
        }

        let root_dir_cluster = if kind == FatType::Fat32 {
            Some(unalign_read!(boot.bpb_root_clus => Le<Unaligned<u32>>))
        } else {
            None
        };
        let fs_info_sector = if kind == FatType::Fat32 {
            Some(unalign_read!(boot.bpb_fs_info => Le<Unaligned<u16>>))
        } else {
            None
        };

        Ok(Some(Self {
            kind,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat,
            root_dir_entries,
            root_dir_sectors,
            hidden_sectors,
            total_sectors,
            count_of_clusters,
            root_dir_cluster,
            fs_info_sector,
        }))
    }

    #[inline]
    pub(crate) fn cluster_size_bytes(&self) -> usize {
        self.bytes_per_sector as usize * self.sectors_per_cluster as usize
    }

    #[inline]
    pub(crate) fn first_data_sector(&self) -> u64 {
        self.reserved_sectors as u64
            + (self.num_fats as u64 * self.sectors_per_fat as u64)
            + self.root_dir_sectors as u64
    }

    #[inline]
    pub(crate) fn cluster_to_lba(&self, cluster: u32) -> Result<u64, FileSystemErr> {
        if cluster < 2 || cluster > self.count_of_clusters + 1 {
            return Err(FileSystemErr::Corrupted);
        }
        Ok(self.hidden_sectors as u64
            + self.first_data_sector()
            + (cluster as u64 - 2) * self.sectors_per_cluster as u64)
    }

    #[inline]
    pub(crate) fn fat_region_lba(&self) -> u64 {
        self.hidden_sectors as u64 + self.reserved_sectors as u64
    }
}
