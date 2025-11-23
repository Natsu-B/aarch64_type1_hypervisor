use crate::FileSystemErr;
use crate::aligned_box::AlignedSliceBox;
use crate::filesystem::DirMeta;
use crate::filesystem::FileHandle;
use crate::filesystem::FileSystemTrait;
use crate::filesystem::OpenOptions;
use crate::filesystem::fat::FatType;
use crate::filesystem::fat::FatVolume;
use crate::filesystem::fat32::fat::FAT32FAT;
use crate::filesystem::fat32::fat::FAT32FATIter;
use crate::filesystem::fat32::sector::FAT32ByteDirectoryEntry;
use crate::filesystem::fat32::sector::FAT32DirectoryEntryAttribute;
use crate::filesystem::fat32::sector::FAT32LongDirectoryEntry;
use crate::from_io_err;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use block_device_api::BlockDevice;
use core::cmp;
use core::convert::TryInto;
use core::mem::MaybeUninit;
use core::mem::size_of;
mod fat;
pub(crate) mod sector;

pub(crate) struct FAT32FileSystem {
    volume: FatVolume,
    root_dir_cluster: u32,
}

impl FAT32FileSystem {
    pub(crate) fn new(volume: FatVolume) -> Result<Self, FileSystemErr> {
        if volume.kind != FatType::Fat32 {
            return Err(FileSystemErr::UnsupportedFileSystem);
        }
        let Some(root) = volume.root_dir_cluster else {
            return Err(FileSystemErr::Corrupted);
        };
        Ok(Self {
            volume,
            root_dir_cluster: root,
        })
    }

    fn cluster_size_bytes(&self) -> usize {
        self.volume.cluster_size_bytes()
    }

    fn is_encode_83(name: &str) -> Result<Option<(&str, &str)>, FileSystemErr> {
        let mut ret8: MaybeUninit<&str> = MaybeUninit::uninit();
        let mut ret3: &str = core::default::Default::default();
        if !name.is_ascii() {
            return Err(FileSystemErr::InvalidInput);
        }

        for i in name.bytes() {
            if !match i {
                i if i.is_ascii_alphanumeric() => true,
                b'.' | b'$' | b'%' | b'`' | b'-' | b'_' | b'@' | b'~' | b'\'' | b'!' | b'('
                | b')' | b'{' | b'}' | b'^' | b'#' | b'&' => true,
                b'+' | b',' | b';' | b'=' | b'[' | b']' | b' ' => false,
                _ => return Err(FileSystemErr::InvalidInput),
            } {
                return Ok(None);
            }
        }

        for (i, chars) in name.split('.').enumerate() {
            match i {
                0 => {
                    if chars.is_empty() || chars.len() > 8 {
                        return Ok(None);
                    }
                    ret8.write(chars);
                }
                1 => {
                    if chars.is_empty() || chars.len() > 3 {
                        return Ok(None);
                    }
                    ret3 = chars;
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(unsafe { (ret8.assume_init(), ret3) }))
    }

    fn calculate_next_dir(
        sde: &FAT32ByteDirectoryEntry,
        entry_lba: u64,
        entry_offset: u16,
    ) -> DirMeta {
        let cluster =
            ((sde.dir_fst_clus_hi.read() as u32) << 16) | sde.dir_fst_clus_lo.read() as u32;
        DirMeta {
            is_dir: sde.dir_attr & FAT32DirectoryEntryAttribute::ATTR_DIRECTORY
                == FAT32DirectoryEntryAttribute::ATTR_DIRECTORY,
            is_readonly: sde.dir_attr & FAT32DirectoryEntryAttribute::ATTR_READ_ONLY
                == FAT32DirectoryEntryAttribute::ATTR_READ_ONLY,
            first_cluster: cluster,
            file_size: sde.dir_file_size.read(),
            entry_lba,
            entry_offset,
        }
    }

    /// compare utf16 and ascii
    /// when return false or utf16 has null terminator, ascii &str pointer is undefined
    fn compare_utf16_and_ascii(utf16: &[u8], ascii: &mut &str) -> Result<bool, FileSystemErr> {
        let mut chunks = match utf16.chunks_exact(2) {
            c if c.remainder().is_empty() => c,
            _ => unreachable!(),
        };

        let ascii_bytes = ascii.as_bytes();
        let mut idx = 0;

        for pair in &mut chunks {
            let u = u16::from_le_bytes([pair[0], pair[1]]);

            match u {
                0x0000 => {
                    *ascii = core::str::from_utf8(&ascii_bytes[idx..]).unwrap();
                    return Ok(idx == ascii_bytes.len());
                }
                0xFFFF => {
                    continue;
                }
                0x0001..=0x007F => {
                    if idx >= ascii_bytes.len() {
                        *ascii = core::str::from_utf8(&ascii_bytes[idx..]).unwrap();
                        return Ok(false);
                    }
                    let a = ascii_bytes[idx];
                    let u8v = u as u8;
                    if !a.eq_ignore_ascii_case(&u8v) {
                        *ascii = core::str::from_utf8(&ascii_bytes[idx..]).unwrap();
                        return Ok(false);
                    }
                    idx += 1;
                }
                _ => {
                    return Err(FileSystemErr::UnsupportedFileName);
                }
            }
        }
        *ascii = core::str::from_utf8(&ascii_bytes[idx..]).unwrap();
        Ok(true)
    }

    fn search_file_name_with_cluster_dir(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        dir_cluster: u32,
        file_name: &str,
    ) -> Result<Option<DirMeta>, FileSystemErr> {
        let is_short_name = Self::is_encode_83(file_name)?;
        let cluster_bytes = self.cluster_size_bytes();
        let sector_bytes = self.volume.bytes_per_sector as usize;

        for cluster in FAT32FATIter::new(block_device, self, dir_cluster) {
            let cluster = cluster?;
            let mut data = AlignedSliceBox::<u8>::new_uninit_with_align(cluster_bytes, 2).unwrap();
            block_device
                .read_at(cluster.lba, &mut data)
                .map_err(from_io_err)?;
            let data = unsafe { data.assume_init() };
            let mut lde_num = 0;
            'outer: for entry_off in
                (0..cluster_bytes).step_by(size_of::<FAT32ByteDirectoryEntry>())
            {
                let entry_ptr = unsafe { data.as_ptr().add(entry_off) };
                let name0 = unsafe { *entry_ptr };

                if name0 == 0x00 {
                    break;
                }
                if name0 == 0xE5 {
                    lde_num = 0;
                    continue;
                }

                if FAT32DirectoryEntryAttribute::is_sde(data.as_ptr() as usize + entry_off) {
                    let lde = lde_num;
                    lde_num = 0;
                    let sde = unsafe {
                        &*((data.as_ptr() as usize + entry_off) as *const FAT32ByteDirectoryEntry)
                    };
                    let entry_lba = cluster.lba + (entry_off / sector_bytes) as u64;
                    let entry_offset = (entry_off % sector_bytes) as u16;
                    if sde.dir_attr & FAT32DirectoryEntryAttribute::ATTR_VOLUME_ID
                        == FAT32DirectoryEntryAttribute::ATTR_VOLUME_ID
                    {
                        continue;
                    }
                    if let Some((name, extension)) = is_short_name {
                        for i in 0..8 {
                            if let Some(char) = name.as_bytes().get(i) {
                                if char.to_ascii_uppercase() != sde.dir_name[i] {
                                    continue 'outer;
                                }
                            } else if sde.dir_name[i] != b' ' {
                                continue 'outer;
                            }
                        }
                        for i in 0..3 {
                            if let Some(char) = extension.as_bytes().get(i) {
                                if char.to_ascii_uppercase() != sde.dir_name[i + 8] {
                                    continue 'outer;
                                }
                            } else if sde.dir_name[i + 8] != b' ' {
                                continue 'outer;
                            }
                        }
                        return Ok(Some(Self::calculate_next_dir(sde, entry_lba, entry_offset)));
                    }
                    if lde == 0 {
                        continue;
                    }
                    if lde != file_name.len().div_ceil(13) {
                        continue;
                    }
                    let mut check_sum: u8 = 0;
                    for i in 0..11 {
                        check_sum = check_sum.rotate_right(1).wrapping_add(sde.dir_name[i]);
                    }
                    let mut long_name = file_name;
                    for j in 0..lde {
                        let lde_ref = unsafe {
                            &*((data.as_ptr() as usize + entry_off
                                - (j + 1) * size_of::<FAT32LongDirectoryEntry>())
                                as *const FAT32LongDirectoryEntry)
                        };
                        let ord = lde_ref.ldir_ord;
                        let seq = ord & 0x3F;
                        let last = (ord & 0x40) != 0;
                        let expected = (j + 1) as u8;

                        if seq != expected {
                            return Err(FileSystemErr::Corrupted);
                        }
                        if j == lde - 1 {
                            if !last {
                                return Err(FileSystemErr::Corrupted);
                            }
                        } else if last {
                            return Err(FileSystemErr::Corrupted);
                        }
                        if lde_ref.ldir_chksum != check_sum || lde_ref.ldir_fst_clus_lo != 0 {
                            return Err(FileSystemErr::Corrupted);
                        }
                        if !Self::compare_utf16_and_ascii(&lde_ref.ldir_name1, &mut long_name)? {
                            continue 'outer;
                        }
                        if long_name.is_empty() || long_name.bytes().all(|c| c == b' ' || c == b'.')
                        {
                            if j == lde - 1 {
                                return Ok(Some(Self::calculate_next_dir(
                                    sde,
                                    entry_lba,
                                    entry_offset,
                                )));
                            } else {
                                continue 'outer;
                            }
                        }
                        if !Self::compare_utf16_and_ascii(&lde_ref.ldir_name2, &mut long_name)? {
                            continue 'outer;
                        }
                        if long_name.is_empty() || long_name.bytes().all(|c| c == b' ' || c == b'.')
                        {
                            if j == lde - 1 {
                                return Ok(Some(Self::calculate_next_dir(
                                    sde,
                                    entry_lba,
                                    entry_offset,
                                )));
                            } else {
                                continue 'outer;
                            }
                        }
                        if !Self::compare_utf16_and_ascii(&lde_ref.ldir_name3, &mut long_name)? {
                            continue 'outer;
                        }
                        if long_name.is_empty() || long_name.bytes().all(|c| c == b' ' || c == b'.')
                        {
                            if j == lde - 1 {
                                return Ok(Some(Self::calculate_next_dir(
                                    sde,
                                    entry_lba,
                                    entry_offset,
                                )));
                            } else {
                                continue 'outer;
                            }
                        }
                    }
                } else {
                    lde_num += 1;
                }
            }
        }
        Ok(None)
    }

    fn collect_cluster_chain(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        first_cluster: u32,
    ) -> Result<Vec<u32>, FileSystemErr> {
        let mut chain = Vec::new();
        if first_cluster == 0 {
            return Ok(chain);
        }
        for entry in FAT32FATIter::new(block_device, self, first_cluster) {
            chain.push(entry?.cluster);
        }
        Ok(chain)
    }

    fn ensure_cluster_capacity(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        chain: &mut Vec<u32>,
        needed: usize,
        meta: &mut DirMeta,
    ) -> Result<(), FileSystemErr> {
        if needed == 0 || chain.len() >= needed {
            if meta.first_cluster == 0 && !chain.is_empty() {
                meta.first_cluster = chain[0];
            }
            return Ok(());
        }
        let mut last = chain.last().copied();
        while chain.len() < needed {
            let new_cluster = self.find_free_cluster(block_device)?;
            self.write_fat_entry(block_device, new_cluster, FAT32FAT::END_OF_CHAIN)?;
            if let Some(prev) = last {
                self.write_fat_entry(block_device, prev, new_cluster)?;
            } else if meta.first_cluster != 0 {
                self.write_fat_entry(block_device, meta.first_cluster, new_cluster)?;
            } else {
                meta.first_cluster = new_cluster;
            }
            self.zero_cluster(block_device, new_cluster)?;
            chain.push(new_cluster);
            last = Some(new_cluster);
        }
        if meta.first_cluster == 0 && !chain.is_empty() {
            meta.first_cluster = chain[0];
        }
        Ok(())
    }

    fn find_free_cluster(&self, block_device: &Arc<dyn BlockDevice>) -> Result<u32, FileSystemErr> {
        let mut sector_cache = vec![0u8; self.volume.bytes_per_sector as usize];
        let mut cached_sector = None;
        let max_cluster = self.volume.count_of_clusters + 1;
        for cluster in 2..=max_cluster {
            let entry_byte = cluster as u64 * size_of::<FAT32FAT>() as u64;
            let sector_index = entry_byte / self.volume.bytes_per_sector as u64;
            if cached_sector != Some(sector_index) {
                let lba = self.fat_lba(0, sector_index);
                let mut uninit = slice_as_uninit(&mut sector_cache);
                block_device
                    .read_at(lba, &mut uninit)
                    .map_err(from_io_err)?;
                cached_sector = Some(sector_index);
            }
            let offset = (entry_byte % self.volume.bytes_per_sector as u64) as usize;
            let value = u32::from_le_bytes(
                sector_cache[offset..offset + size_of::<FAT32FAT>()]
                    .try_into()
                    .unwrap(),
            ) & FAT32FAT::MASK;
            if value == 0 {
                return Ok(cluster);
            }
        }
        Err(FileSystemErr::NoSpace)
    }

    fn write_fat_entry(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        cluster: u32,
        value: u32,
    ) -> Result<(), FileSystemErr> {
        let entry_byte = cluster as u64 * size_of::<FAT32FAT>() as u64;
        let sector_index = entry_byte / self.volume.bytes_per_sector as u64;
        let offset = (entry_byte % self.volume.bytes_per_sector as u64) as usize;
        let mut sector_buf = vec![0u8; self.volume.bytes_per_sector as usize];
        for fat_idx in 0..self.volume.num_fats {
            let lba = self.fat_lba(fat_idx, sector_index);
            let mut uninit = slice_as_uninit(&mut sector_buf);
            block_device
                .read_at(lba, &mut uninit)
                .map_err(from_io_err)?;
            sector_buf[offset..offset + size_of::<FAT32FAT>()]
                .copy_from_slice(&(value & FAT32FAT::MASK).to_le_bytes());
            block_device
                .write_at(lba, &sector_buf)
                .map_err(from_io_err)?;
        }
        Ok(())
    }

    fn fat_lba(&self, fat_idx: u8, sector_index: u64) -> u64 {
        self.volume.fat_region_lba()
            + sector_index
            + fat_idx as u64 * self.volume.sectors_per_fat as u64
    }

    fn zero_cluster(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        cluster: u32,
    ) -> Result<(), FileSystemErr> {
        let buf = vec![0u8; self.cluster_size_bytes()];
        let lba = self.volume.cluster_to_lba(cluster)?;
        block_device.write_at(lba, &buf).map_err(from_io_err)
    }

    fn update_dir_entry(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        meta: &DirMeta,
    ) -> Result<(), FileSystemErr> {
        if meta.entry_lba == 0 {
            return Err(FileSystemErr::Corrupted);
        }
        let mut sector = vec![0u8; self.volume.bytes_per_sector as usize];
        let mut uninit = slice_as_uninit(&mut sector);
        block_device
            .read_at(meta.entry_lba, &mut uninit)
            .map_err(from_io_err)?;
        let offset = meta.entry_offset as usize;
        if offset + size_of::<FAT32ByteDirectoryEntry>() > sector.len() {
            return Err(FileSystemErr::Corrupted);
        }
        let entry_ptr = unsafe { sector.as_mut_ptr().add(offset) as *mut FAT32ByteDirectoryEntry };
        let entry = unsafe { &mut *entry_ptr };
        entry.dir_file_size.write(meta.file_size);
        entry.dir_fst_clus_lo.write(meta.first_cluster as u16);
        entry
            .dir_fst_clus_hi
            .write(((meta.first_cluster >> 16) & 0xFFFF) as u16);
        block_device
            .write_at(meta.entry_lba, &sector)
            .map_err(from_io_err)
    }
}

fn slice_as_uninit(buf: &mut [u8]) -> &mut [MaybeUninit<u8>] {
    unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len()) }
}

impl FileSystemTrait for FAT32FileSystem {
    fn open(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        file_system: &Arc<dyn FileSystemTrait>,
        path: &str,
        opts: &super::OpenOptions,
    ) -> Result<FileHandle, FileSystemErr> {
        let mut path = path.chars();
        match path.next() {
            Some('/') => {}
            Some(_) => return Err(FileSystemErr::NotRootDir),
            None => return Err(FileSystemErr::InvalidInput),
        }
        let mut dir_clusters = self.root_dir_cluster;
        let mut meta = DirMeta {
            is_readonly: false,
            is_dir: false,
            first_cluster: 0,
            file_size: 0,
            entry_lba: 0,
            entry_offset: 0,
        };
        for dir_name in path.as_str().split('/') {
            if dir_name.is_empty() {
                return Err(FileSystemErr::InvalidInput);
            }
            let Some(dir_meta) =
                self.search_file_name_with_cluster_dir(block_device, dir_clusters, dir_name)?
            else {
                return Err(FileSystemErr::NotFound);
            };
            dir_clusters = dir_meta.first_cluster;
            meta = dir_meta;
        }
        if meta.is_dir {
            return Err(FileSystemErr::IsDir);
        }
        if *opts == OpenOptions::Write
            && (meta.is_readonly || block_device.is_read_only().map_err(from_io_err)?)
        {
            return Err(FileSystemErr::ReadOnly);
        }
        Ok(FileHandle {
            dev_handle: Arc::downgrade(block_device),
            file_handle: Arc::downgrade(file_system),
            meta,
            opts: *opts,
        })
    }

    fn remove_file(&self, path: &str) -> Result<(), FileSystemErr> {
        todo!()
    }

    fn copy(&self, from: &str, to: &str) -> Result<(), FileSystemErr> {
        todo!()
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), FileSystemErr> {
        todo!()
    }

    fn create_dir(&self, path: &str) -> Result<(), FileSystemErr> {
        todo!()
    }

    fn remove_dir(&self, path: &str) -> Result<(), FileSystemErr> {
        todo!()
    }

    fn read(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        align: usize,
        meta: &DirMeta,
    ) -> Result<AlignedSliceBox<u8>, FileSystemErr> {
        let mut data =
            AlignedSliceBox::new_uninit_with_align(meta.file_size as usize, align).unwrap();
        let len = self.read_at(block_device, 0, data.deref_uninit_u8_mut(), meta)?;
        assert_eq!(data.len() as u64, len);
        Ok(unsafe { data.assume_init() })
    }

    fn read_at(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        offset: u64,
        buf: &mut [MaybeUninit<u8>],
        meta: &DirMeta,
    ) -> Result<u64, FileSystemErr> {
        let file_size = meta.file_size as u64;
        let bs = block_device.block_size();
        let spc = self.volume.sectors_per_cluster as usize;
        let bpc = (bs * spc) as u64;

        if offset > file_size {
            return Err(FileSystemErr::InvalidInput);
        }
        let max_read = (file_size - offset) as usize;
        if buf.len() > max_read {
            return Err(FileSystemErr::TooBigBuffer);
        }
        let to_read = buf.len();

        let start_cluster = (offset / bpc) as usize;
        let cluster_off = (offset % bpc) as usize;
        let start_sector_off = cluster_off / bs;
        let start_byte_in_sector = cluster_off % bs;

        let total_bytes_from_first_sector = start_byte_in_sector + to_read;
        let sectors_needed = total_bytes_from_first_sector.div_ceil(bs);

        let mut tmp = Box::new_uninit_slice(sectors_needed * bs);

        let mut sectors_remaining = sectors_needed;
        let mut tmp_ptr_sectors = 0usize;

        for (i, info) in FAT32FATIter::new(block_device, self, meta.first_cluster).enumerate() {
            let info = info?;
            if i < start_cluster {
                continue;
            }
            if sectors_remaining == 0 {
                break;
            }

            let first_sector_in_this_cluster = if i == start_cluster {
                start_sector_off
            } else {
                0
            };

            let can_read_in_this_cluster = spc - first_sector_in_this_cluster;
            let read_sectors = can_read_in_this_cluster.min(sectors_remaining);

            let byte_off = tmp_ptr_sectors * bs;
            let byte_len = read_sectors * bs;
            block_device
                .read_at(
                    info.lba + first_sector_in_this_cluster as u64,
                    &mut tmp[byte_off..byte_off + byte_len],
                )
                .map_err(from_io_err)?;

            tmp_ptr_sectors += read_sectors;
            sectors_remaining -= read_sectors;
        }

        if sectors_remaining != 0 {
            return Err(FileSystemErr::IncompleteRead);
        }

        let start = start_byte_in_sector;
        let end = start + to_read;
        let src = unsafe { core::slice::from_raw_parts(tmp.as_ptr() as *const u8, tmp.len()) };
        let src = &src[start..end];

        let dst =
            unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len()) };
        dst.copy_from_slice(src);

        Ok(to_read as u64)
    }

    fn write_at(
        &self,
        block_device: &Arc<dyn BlockDevice>,
        offset: u64,
        buf: &[u8],
        meta: &mut DirMeta,
    ) -> Result<u64, FileSystemErr> {
        if buf.is_empty() {
            return Ok(0);
        }
        if meta.is_dir {
            return Err(FileSystemErr::IsDir);
        }
        if meta.is_readonly || block_device.is_read_only().map_err(from_io_err)? {
            return Err(FileSystemErr::ReadOnly);
        }
        if offset > meta.file_size as u64 {
            return Err(FileSystemErr::InvalidInput);
        }
        let new_size = offset
            .checked_add(buf.len() as u64)
            .ok_or(FileSystemErr::TooBigBuffer)?;
        if new_size > u32::MAX as u64 {
            return Err(FileSystemErr::TooBigBuffer);
        }
        let cluster_size = self.cluster_size_bytes();
        let required_clusters = if new_size == 0 {
            0
        } else {
            ((new_size + cluster_size as u64 - 1) / cluster_size as u64) as usize
        };
        let mut chain = self.collect_cluster_chain(block_device, meta.first_cluster)?;
        self.ensure_cluster_capacity(block_device, &mut chain, required_clusters, meta)?;

        let mut remaining = buf.len();
        let mut buf_offset = 0usize;
        let mut current_offset = offset;
        if remaining == 0 {
            return Ok(0);
        }
        let mut cluster_buf = Vec::with_capacity(cluster_size);
        unsafe {
            cluster_buf.set_len(cluster_size);
        }
        while remaining > 0 {
            let cluster_index = if cluster_size == 0 {
                0
            } else {
                (current_offset / cluster_size as u64) as usize
            };
            let cluster = *chain.get(cluster_index).ok_or(FileSystemErr::Corrupted)?;
            let lba = self.volume.cluster_to_lba(cluster)?;
            let mut uninit = slice_as_uninit(cluster_buf.as_mut_slice());
            block_device
                .read_at(lba, &mut uninit)
                .map_err(from_io_err)?;
            let within_cluster = (current_offset % cluster_size as u64) as usize;
            let writable = cmp::min(cluster_size - within_cluster, remaining);
            cluster_buf[within_cluster..within_cluster + writable]
                .copy_from_slice(&buf[buf_offset..buf_offset + writable]);
            block_device
                .write_at(lba, &cluster_buf)
                .map_err(from_io_err)?;
            remaining -= writable;
            buf_offset += writable;
            current_offset += writable as u64;
        }

        let mut need_update_entry = false;
        if new_size > meta.file_size as u64 {
            meta.file_size = new_size as u32;
            need_update_entry = true;
        }
        if meta.first_cluster == 0 && !chain.is_empty() {
            meta.first_cluster = chain[0];
            need_update_entry = true;
        }

        if need_update_entry {
            self.update_dir_entry(block_device, meta)?;
        }
        Ok(buf.len() as u64)
    }
}
