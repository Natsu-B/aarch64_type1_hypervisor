#![no_std]
#![recursion_limit = "1024"]

use crate::descriptor::Stage2_48bitLeafDescriptor;
use crate::descriptor::Stage2_48bitTableDescriptor;
use crate::registers::ID_AA64MMFR0_EL1;
use crate::registers::InnerCache;
use crate::registers::OuterCache;
use crate::registers::PARange;
use crate::registers::PhysicalAddressSize;
use crate::registers::SL0;
use crate::registers::Shareability;
use crate::registers::TG0;
use crate::registers::VTCR_EL2;
use core::alloc::Layout;
use core::slice;

extern crate alloc;

mod descriptor;
mod registers;

pub struct Stage2Paging;

pub struct Stage2PagingSetting {
    pub ipa: usize,
    pub pa: usize,
    pub size: usize,
}

const PAGE_TABLE_SIZE: usize = 1usize << 12; // 4KiB

impl Stage2Paging {
    /// initialize stage2 paging
    /// 4KiB granule
    /// - level 0 table: 512GiB 2^39
    /// - level 1 table: 1GiB 2^30
    /// - level 2 table: 2MiB 2^21
    /// - level 3 table: 4KiB 2^12
    ///
    /// # safety
    ///     data must be ascending order
    pub fn init_stage2paging(data: &[Stage2PagingSetting]) -> Result<(), PagingErr> {
        if data.is_empty() {
            return Err(PagingErr::Corrupted);
        }
        let id_aa64mmfr0_el1 = ID_AA64MMFR0_EL1::from_bits(cpu::get_id_aa64mmfr0_el1());
        let parange: Option<PARange> = id_aa64mmfr0_el1.get_enum(ID_AA64MMFR0_EL1::parange);

        // Concatenated translation tables (AArch64, Stage-2)
        // --------------------------------------------------
        // WHAT
        // • At the initial lookup of a Stage-2 translation you may replace the top level with
        //   multiple same-level tables concatenated side-by-side, and start the walk from
        //   the *next* lookup level (skipping one level).
        //
        // HOW MANY
        // • Up to 16 tables can be concatenated.
        // • If the initial lookup resolves n extra IA bits (beyond that level’s baseline),
        //   you must concatenate 2^n tables (n ≤ 4).
        //
        // WHEN (rule of thumb)
        // • If the table at the nominal initial level would need ≤ 16 entries for your IPA size
        //   and granule, you can “pull” those top bits into the initial lookup and start at the
        //   next level with 2^n concatenated tables.
        //
        // CONFIGURATION (software responsibilities)
        // • Program VTCR_EL2.SL0 (and SL2 when DS=1) to the *level you actually want to start from*
        //   — i.e., the *lower* level when using concatenation. Hardware does not auto-decrement
        //   the level; you choose it via SL0(/SL2).
        // • Program VTTBR_EL2 to the base of the *first* table in the concatenated set and satisfy
        //   the alignment implied by the concatenated size.
        // • Ensure DS (VTCR_EL2.DS) and IPS/PS settings are consistent with the address size used.
        //
        // 4KB GRANULE EXAMPLES (Stage-2)
        // • Initial level L1 baseline covers IA[38:12]. With concatenation:
        //   - IA[39:12] → 2 tables, IA[40:12] → 4 tables, IA[41:12] → 8 tables, IA[42:12] → 16 tables.
        // • Initial level L0 baseline covers IA[47:12]. With DS=1 for >48-bit IA:
        //   - IA[48:12] → 2 tables, IA[49:12] → 4 tables, IA[50:12] → 8 tables, IA[51:12] → 16 tables.
        //   (Plain 48-bit at L0 needs no concatenation.)
        //
        // WHY
        // • Eliminates one top-level lookup, reducing table-walk overhead.
        let (ps, t0sz, initial_lookup_level, initial_lookup_level_i8, num_of_tables) = match parange
        {
            Some(pa) => {
                match pa {
                    // pa size == ipa size
                    PARange::PA32bits4GB => {
                        (PhysicalAddressSize::AddressSize32b, 32, SL0::Level1, 1, 1)
                    }
                    PARange::PA36bits64GB => {
                        (PhysicalAddressSize::AddressSize36b, 28, SL0::Level1, 1, 1)
                    }
                    PARange::PA40bits1TB => {
                        (PhysicalAddressSize::AddressSize40b, 24, SL0::Level1, 1, 2)
                    }
                    PARange::PA42bits4TB => {
                        (PhysicalAddressSize::AddressSize42b, 22, SL0::Level1, 1, 8)
                    }
                    PARange::PA44bits16TB => {
                        (PhysicalAddressSize::AddressSize44b, 20, SL0::Level0, 0, 1)
                    }
                    PARange::PA48bits256TB => {
                        (PhysicalAddressSize::AddressSize48b, 16, SL0::Level0, 0, 1)
                    }
                    // ipa 52bit is not supported
                    // ipa size == 48bit
                    PARange::PA52bits4PB => {
                        (PhysicalAddressSize::AddressSize52b, 16, SL0::Level0, 0, 1)
                    }
                    PARange::PA56bits64PB => {
                        (PhysicalAddressSize::AddressSize56b, 16, SL0::Level0, 0, 1)
                    }
                }
            }
            None => return Err(PagingErr::Corrupted),
        };

        // mapping page table
        let table = Self::setup_stage2_translation(data, initial_lookup_level_i8, num_of_tables)?;

        let vtcr_el2 = VTCR_EL2::new()
            .set(VTCR_EL2::t0sz, t0sz)
            .set_enum(VTCR_EL2::sl0, initial_lookup_level)
            .set_enum(VTCR_EL2::irgn0, InnerCache::WBRAnWACacheable)
            .set_enum(VTCR_EL2::orgn0, OuterCache::WBRAnWACacheable)
            .set_enum(VTCR_EL2::sh0, Shareability::InnerSharable)
            .set_enum(VTCR_EL2::tg0, TG0::Granule4KB)
            .set_enum(VTCR_EL2::ps, ps)
            .bits();

        cpu::set_vtcr_el2(vtcr_el2);
        cpu::set_vttbr_el2(table as u64);
        cpu::dsb_ish();
        cpu::isb();
        Ok(())
    }

    fn setup_stage2_translation(
        data: &[Stage2PagingSetting],
        top_table_level: i8,
        num_of_tables: usize,
    ) -> Result<usize, PagingErr> {
        let table_addr = allocator::allocate_with_size_and_align(
            PAGE_TABLE_SIZE * num_of_tables,
            PAGE_TABLE_SIZE * num_of_tables,
        )
        .map_err(|_| PagingErr::OutOfMemory)?;
        let table =
            unsafe { slice::from_raw_parts_mut(table_addr as *mut u64, num_of_tables * 512) };
        // initialize page table
        for i in &mut *table {
            *i = 0;
        }

        let top_level_offset = (3 - top_table_level) as usize * 9 + 12;
        let top_level = 1 << top_level_offset;

        let mut i = 0;
        let mut pa = data[0].pa;
        let mut ipa = data[0].ipa;
        let mut size = data[0].size;
        if (data[0].pa | data[0].ipa | data[0].size) & (PAGE_TABLE_SIZE - 1) != 0 {
            return Err(PagingErr::UnalignedPage);
        }
        loop {
            if i == data.len() {
                break;
            }
            let idx = initial_index_with_concat(ipa, top_table_level, num_of_tables);
            debug_assert!(idx < num_of_tables * 512);
            // is block descriptor
            if top_table_level != 0 && (pa | ipa) & (top_level - 1) == 0 && size >= top_level {
                // block descriptor
                table[idx] = Stage2_48bitLeafDescriptor::new_block(pa as u64, top_table_level);
                pa += top_level;
                ipa += top_level;
                size -= top_level;
                if size == 0 {
                    Self::increment_and_check(&mut i, data, &mut pa, &mut ipa, &mut size)?;
                }
            } else {
                // table descriptor
                let next_level_table_addr = unsafe {
                    alloc::alloc::alloc(Layout::from_size_align_unchecked(
                        PAGE_TABLE_SIZE,
                        PAGE_TABLE_SIZE,
                    ))
                };
                if next_level_table_addr.is_null() {
                    return Err(PagingErr::OutOfMemory);
                }
                let next_level_table_addr = next_level_table_addr as usize;
                let next_level_table =
                    unsafe { slice::from_raw_parts_mut(next_level_table_addr as *mut u64, 512) };
                for j in &mut *next_level_table {
                    *j = 0;
                }
                table[idx] =
                    Stage2_48bitTableDescriptor::new_descriptor(next_level_table_addr as u64);
                let start_ipa = ipa & !(top_level - 1);
                Self::setup_stage2_translation_recursive(
                    &mut i,
                    data,
                    top_table_level + 1,
                    next_level_table,
                    start_ipa,
                    &mut pa,
                    &mut ipa,
                    &mut size,
                )?;
            }
        }
        cpu::clean_dcache_poc(table_addr, PAGE_TABLE_SIZE * num_of_tables);
        Ok(table_addr)
    }

    fn setup_stage2_translation_recursive(
        i: &mut usize,
        data: &[Stage2PagingSetting],
        table_level: i8,
        table_addr: &mut [u64],
        start_ipa: usize,
        pa: &mut usize,
        ipa: &mut usize,
        size: &mut usize,
    ) -> Result<(), PagingErr> {
        let table_level_offset = (3 - table_level) as usize * 9 + 12;
        let table_level_size = 1 << table_level_offset;

        let table_limit = start_ipa + table_level_size * 512;

        while *i < data.len() && *ipa < table_limit {
            // is block descriptor
            if table_level == 3
                || ((*pa | *ipa) & (table_level_size - 1) == 0 && *size >= table_level_size)
            {
                // check table level 3 is aligned PAGE_SIZE
                debug_assert_eq!((*pa | *ipa | *size) & (PAGE_TABLE_SIZE - 1), 0);
                // block descriptor
                table_addr[(*ipa - start_ipa) >> table_level_offset] = if table_level == 3 {
                    Stage2_48bitLeafDescriptor::new_page(*pa as u64)
                } else {
                    Stage2_48bitLeafDescriptor::new_block(*pa as u64, table_level)
                };
                *pa += table_level_size;
                *ipa += table_level_size;
                *size -= table_level_size;
                if *size == 0 {
                    Self::increment_and_check(i, data, pa, ipa, size)?;
                }
            } else {
                // table descriptor
                let next_level_table_addr = unsafe {
                    alloc::alloc::alloc(Layout::from_size_align_unchecked(
                        PAGE_TABLE_SIZE,
                        PAGE_TABLE_SIZE,
                    ))
                };
                if next_level_table_addr.is_null() {
                    return Err(PagingErr::OutOfMemory);
                }
                let next_level_table_addr = next_level_table_addr as usize;
                let next_level_table =
                    unsafe { slice::from_raw_parts_mut(next_level_table_addr as *mut u64, 512) };
                for j in &mut *next_level_table {
                    *j = 0;
                }
                table_addr[(*ipa - start_ipa) >> table_level_offset] =
                    Stage2_48bitTableDescriptor::new_descriptor(next_level_table_addr as u64);
                let start_ipa = *ipa & !(table_level_size - 1);
                Self::setup_stage2_translation_recursive(
                    i,
                    data,
                    table_level + 1,
                    next_level_table,
                    start_ipa,
                    pa,
                    ipa,
                    size,
                )?;
            }
        }
        cpu::clean_dcache_poc(table_addr.as_ptr() as usize, PAGE_TABLE_SIZE);
        Ok(())
    }

    fn increment_and_check(
        i: &mut usize,
        data: &[Stage2PagingSetting],
        pa: &mut usize,
        ipa: &mut usize,
        size: &mut usize,
    ) -> Result<(), PagingErr> {
        *i += 1;
        if *i == data.len() {
            return Ok(());
        }
        if (data[*i].pa | data[*i].ipa | data[*i].size) & (PAGE_TABLE_SIZE - 1) != 0 {
            return Err(PagingErr::UnalignedPage);
        }
        *pa = data[*i].pa;
        *ipa = data[*i].ipa;
        *size = data[*i].size;
        Ok(())
    }
}

#[inline]
fn initial_index_with_concat(ipa: usize, level: i8, num_concat: usize) -> usize {
    debug_assert!(num_concat.is_power_of_two());
    let shift = 12 + 9 * (3 - level as usize);
    let normal = (ipa >> shift) & 0x1ff;
    if num_concat > 1 {
        let n = num_concat.trailing_zeros() as usize; // num_concat = 2^n
        let extra = (ipa >> (shift + 9)) & ((1 << n) - 1);
        (extra << 9) | normal
    } else {
        normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingErr {
    Corrupted,
    UnalignedPage,
    UnsupportedPARange,
    OutOfMemory,
}
