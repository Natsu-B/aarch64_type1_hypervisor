use alloc::vec::Vec;
use core::alloc::Layout;
use core::cmp::max;
use core::cmp::min;
use core::fmt;
use core::mem::size_of;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ptr::copy_nonoverlapping;
use core::slice;
use intrusive_linked_list::IntrusiveLinkedList;

pub(crate) const MINIMUM_ALLOCATABLE_BYTES: usize = size_of::<IntrusiveLinkedList>();
const EMPTY_REGION: MemoryRegions = MemoryRegions {
    address: 0,
    size: 0,
};

fn checked_align_up(value: usize, alignment: usize) -> Option<usize> {
    value.checked_next_multiple_of(alignment)
}

enum RegionData {
    Global([MemoryRegions; 128]),
    Heap(&'static mut [MemoryRegions]),
}

struct RegionContainer(RegionData);

impl Deref for RegionContainer {
    type Target = [MemoryRegions];

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            RegionData::Global(slice) => slice,
            RegionData::Heap(heap) => heap,
        }
    }
}

impl DerefMut for RegionContainer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.0 {
            RegionData::Global(slice) => slice,
            RegionData::Heap(heap) => heap,
        }
    }
}

pub(crate) struct MemoryBlock {
    regions: RegionContainer,
    reserved_regions: RegionContainer,
    region_size: u32,
    reserved_region_size: u32,
    region_capacity: u32,
    reserved_region_capacity: u32,
    allocatable: bool,
    /// Upper bound on live allocations (including pieces left by partial releases).
    /// Each owns one spare slot in BOTH arrays, even when reserved ranges merge.
    /// Thus `array live count + deallocation_credits <= capacity` for each array.
    /// A complete release adds at most one entry to either list and consumes
    /// one credit, preserving the inequality without allocating any metadata.
    deallocation_credits: u32,
}

/// A prevalidated replacement of a contiguous section of a metadata array.
/// Applying it never needs a temporary slot beyond the final live count.
struct RegionEdit {
    index: usize,
    removed: usize,
    first: Option<MemoryRegions>,
    second: Option<MemoryRegions>,
}

impl RegionEdit {
    fn new_len(&self, old_len: u32) -> u32 {
        old_len - self.removed as u32
            + u32::from(self.first.is_some())
            + u32::from(self.second.is_some())
    }

    /// Caller checks final capacity before committing any edits.
    fn commit(self, regions: &mut [MemoryRegions], len: &mut u32) {
        let new_len = self.new_len(*len);
        let inserted = usize::from(self.first.is_some()) + usize::from(self.second.is_some());
        regions.copy_within(
            self.index + self.removed..*len as usize,
            self.index + inserted,
        );
        if let Some(first) = self.first {
            regions[self.index] = first;
        }
        if let Some(second) = self.second {
            regions[self.index + 1] = second;
        }
        if new_len < *len {
            regions[new_len as usize..*len as usize].fill(EMPTY_REGION);
        }
        *len = new_len;
    }
}

/// Both edits are calculated before either array is changed.
struct RegionPlan {
    free: RegionEdit,
    reserved: RegionEdit,
    address: usize,
}

impl fmt::Debug for MemoryBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryBlock")
            .field("regions", &&self.regions[..self.region_size as usize])
            .field(
                "reserved_regions",
                &&self.reserved_regions[..self.reserved_region_size as usize],
            )
            .field("allocatable", &self.allocatable)
            .finish()
    }
}

impl MemoryBlock {
    pub fn init() -> MemoryBlock {
        MemoryBlock {
            regions: RegionContainer(RegionData::Global([EMPTY_REGION; 128])),
            reserved_regions: RegionContainer(RegionData::Global([EMPTY_REGION; 128])),
            region_size: 0,
            reserved_region_size: 0,
            region_capacity: 128,
            reserved_region_capacity: 128,
            allocatable: false,
            deallocation_credits: 0,
        }
    }

    // Indicates whether allocation from regions is enabled (i.e., finalized).
    pub(crate) fn is_finalized(&self) -> bool {
        self.allocatable
    }

    pub fn add_region(&mut self, region: &MemoryRegions) -> Result<(), &'static str> {
        self.add_region_internal(false, region)
    }

    pub fn add_reserved_region(&mut self, region: &MemoryRegions) -> Result<(), &'static str> {
        self.add_region_internal(true, region)
    }

    fn insert_region(
        regions_slice: &mut [MemoryRegions],
        size_ref: &mut u32,
        insertion_point: usize,
        region_to_insert: &MemoryRegions,
    ) -> Result<(), &'static str> {
        if insertion_point > 0 {
            let pre_region = &regions_slice[insertion_point - 1];
            let pre_end = pre_region.end_checked()?;
            if pre_end > region_to_insert.address {
                return Err("region overlap");
            }
        }
        let ins_end = region_to_insert.end_checked()?;
        if insertion_point < *size_ref as usize {
            let next_region = &regions_slice[insertion_point];
            if ins_end > next_region.address {
                return Err("region overlap");
            }
        }

        regions_slice.copy_within(insertion_point..*size_ref as usize, insertion_point + 1);
        regions_slice[insertion_point] = *region_to_insert;
        *size_ref += 1;
        Ok(())
    }

    fn add_and_merge_region(
        regions_slice: &mut [MemoryRegions],
        size_ref: &mut u32,
        x: usize, // insertion_point
        region: &MemoryRegions,
    ) -> Result<(), &'static str> {
        let pre_region_end = if x > 0 {
            Some(regions_slice[x - 1].end_checked()?)
        } else {
            None
        };
        let next_region_end = if x < *size_ref as usize {
            Some(regions_slice[x].end_checked()?)
        } else {
            None
        };
        let region_end = region.end_checked()?;

        // Adjacency also joins regions, keeping both ordered neighbors in one range.
        let pre_region_overlaps = pre_region_end.is_some_and(|pre_end| region.address <= pre_end);
        let next_region_overlaps = x < *size_ref as usize && region_end >= regions_slice[x].address;

        match (pre_region_overlaps, next_region_overlaps) {
            (false, false) => {
                // No overlap, just insert the new region
                MemoryBlock::insert_region(regions_slice, size_ref, x, region)?;
            }
            (true, false) => {
                // Overlap with pre_region only
                let pre_region = &mut regions_slice[x - 1];
                let pre_region_end = pre_region_end.ok_or("region end overflow")?;

                if region_end > pre_region_end {
                    pre_region.size = region_end
                        .checked_sub(pre_region.address)
                        .ok_or("region size underflow")?;
                }
            }
            (false, true) => {
                // Overlap with next_region only
                let next_region = &mut regions_slice[x];
                let old_end = next_region_end.ok_or("region end overflow")?;

                next_region.address = region.address;
                next_region.size = old_end
                    .max(region_end)
                    .checked_sub(region.address)
                    .ok_or("region end overflow")?;
            }
            (true, true) => {
                // Overlap with both pre_region and next_region
                let pre_region = &mut regions_slice[x - 1];
                let new_end = pre_region_end
                    .ok_or("region end overflow")?
                    .max(region_end)
                    .max(next_region_end.ok_or("region end overflow")?);

                pre_region.size = new_end
                    .checked_sub(pre_region.address)
                    .ok_or("region size underflow")?;

                regions_slice.copy_within(x + 1..*size_ref as usize, x);
                regions_slice[*size_ref as usize - 1] = EMPTY_REGION;
                *size_ref -= 1;
            }
        }
        Ok(())
    }

    fn add_region_internal(
        &mut self,
        is_reserved: bool,
        region: &MemoryRegions,
    ) -> Result<(), &'static str> {
        if region.size == 0 {
            return Ok(());
        }
        region.end_checked()?;
        // Get mutable slices and references to sizes
        let (regions_slice, size_ref, capacity) = if is_reserved {
            (
                &mut self.reserved_regions[..], // Take a mutable slice
                &mut self.reserved_region_size,
                self.reserved_region_capacity,
            )
        } else {
            (
                &mut self.regions[..], // Take a mutable slice
                &mut self.region_size,
                self.region_capacity,
            )
        };

        if *size_ref + 1 > capacity {
            return Err("region size overflow");
        }

        let valid_regions = &mut regions_slice[0..*size_ref as usize];

        // The following must be guaranteed for `valid_regions`:
        // - It is sorted in ascending order of address.
        // - There are no overlapping memory ranges.
        let search_result = valid_regions.binary_search_by_key(&region.address, |r| r.address);

        // High-level logic for adding a region:
        // - If a region with the same address exists:
        //     - If the new region is larger, update the existing one.
        //         - If the updated region now overlaps with the *next* region, merge them.
        //     - If the new region is smaller or equal, do nothing.
        // - If no region with the same address exists (an `Err` from binary_search):
        //     - Find the insertion point.
        //     - Check for overlaps with the previous and next regions.
        //     - Based on the overlap, either:
        //         - Insert the new region without merging.
        //         - Merge with the previous region.
        //         - Merge with the next region.
        //         - Merge with both previous and next regions.
        match search_result {
            Ok(x) => {
                // Exact address match found.
                let new_size = region.size;
                let old_size = regions_slice[x].size;

                if new_size > old_size {
                    // The new region is larger. Check for merging with the next region.
                    let next_region_data = if x + 1 < *size_ref as usize {
                        Some(regions_slice[x + 1]) // Copy the data, not a borrow
                    } else {
                        None
                    };

                    if let Some(next_region) = next_region_data {
                        let new_end = region
                            .address
                            .checked_add(new_size)
                            .ok_or("region end overflow")?;
                        if new_end >= next_region.address {
                            // Overlaps with next, so merge.
                            let merged_end = new_end.max(
                                next_region
                                    .address
                                    .checked_add(next_region.size)
                                    .ok_or("region end overflow")?,
                            );
                            regions_slice[x].size = merged_end
                                .checked_sub(regions_slice[x].address)
                                .ok_or("region end overflow")?;

                            // Remove the next_region
                            regions_slice.copy_within(x + 2..*size_ref as usize, x + 1);
                            regions_slice[*size_ref as usize - 1] = EMPTY_REGION;
                            *size_ref -= 1;
                        } else {
                            // No overlap, just update size.
                            regions_slice[x].size = new_size;
                        }
                    } else {
                        // No next region, just update size.
                        regions_slice[x].size = new_size;
                    }
                }
                // If new_size <= old_size, do nothing.
                Ok(())
            }
            Err(x) => MemoryBlock::add_and_merge_region(regions_slice, size_ref, x, region),
        }
    }

    pub fn add_reserved_region_dynamic(
        &mut self,
        size: usize,
        align: Option<usize>,
        alloc_range: Option<(usize, usize)>,
    ) -> Result<Option<usize>, &'static str> {
        // Enforce pre-finalize usage only
        if self.allocatable {
            return Err("allocator already finalized");
        }
        // Normalize inputs
        if size == 0 {
            return Ok(None);
        }
        let alignment = align.unwrap_or(1).max(1);

        // Iterate free regions to find a fitting spot respecting range and alignment.
        let regions_len = self.region_size as usize;
        'regions: for i in 0..regions_len {
            let mut reg_addr = self.regions[i].address;
            let mut reg_end = self.regions[i]
                .address
                .checked_add(self.regions[i].size)
                .ok_or("region end overflow")?;

            let region_start = loop {
                // Check if the region is suitable
                let region_start = if let Some((range_start, range_size)) = alloc_range {
                    let range_end = range_start
                        .checked_add(range_size)
                        .ok_or("alloc_range overflow")?;
                    if range_end < reg_addr {
                        return Ok(None);
                    }
                    if reg_end < range_start {
                        continue 'regions;
                    }
                    let region_start = match checked_align_up(max(reg_addr, range_start), alignment)
                    {
                        Some(addr) => addr,
                        None => continue 'regions,
                    };
                    let end = region_start
                        .checked_add(size)
                        .ok_or("requested size overflow")?;
                    if end > range_end {
                        continue 'regions;
                    }
                    region_start
                } else {
                    match checked_align_up(reg_addr, alignment) {
                        Some(addr) => addr,
                        None => continue 'regions,
                    }
                };
                let alloc_end = region_start
                    .checked_add(size)
                    .ok_or("requested size overflow")?;
                if alloc_end > reg_end {
                    continue 'regions;
                }

                // Check whether the region overlaps with reserved memory regions
                let slice = &self.reserved_regions[0..self.reserved_region_size as usize];
                let (prev_end, next_start) =
                    match slice.binary_search_by_key(&region_start, |x| x.address) {
                        Ok(i) => {
                            let prev_end = slice[i]
                                .address
                                .checked_add(slice[i].size)
                                .ok_or("region end overflow")?;
                            let next_start = if i + 1 < slice.len() {
                                slice[i + 1].address
                            } else {
                                usize::MAX
                            };
                            (prev_end, next_start)
                        }
                        Err(i) => {
                            let prev_end = if i > 0 {
                                slice[i - 1]
                                    .address
                                    .checked_add(slice[i - 1].size)
                                    .ok_or("region end overflow")?
                            } else {
                                0
                            };
                            let next_start = if i < slice.len() {
                                slice[i].address
                            } else {
                                usize::MAX
                            };
                            (prev_end, next_start)
                        }
                    };
                if prev_end > region_start || alloc_end > next_start {
                    reg_addr = max(reg_addr, prev_end);
                    reg_end = min(reg_end, next_start);
                    if reg_addr >= reg_end {
                        continue 'regions;
                    }
                    continue;
                }
                break region_start;
            };
            // Found a candidate. Commit it differently depending on finalized state.
            let new_region = MemoryRegions {
                address: region_start,
                size,
            };
            self.add_region_internal(true, &new_region)?;
            return Ok(Some(region_start));
        }

        Ok(None)
    }

    /// Subtracts the reserved memory regions from the available memory regions.
    ///
    /// This function operates under the following assumption:
    /// 1.  **Caller-Guaranteed Sort**: The `regions` and `reserved_regions` slices
    ///     are guaranteed by the caller to be pre-sorted by their base address.
    /// 2.  Reserved regions may partially overlap or span multiple regions; only the
    ///     overlapping portions are subtracted. Non-overlapping parts are ignored.
    pub fn check_regions(&mut self) -> Result<(), &'static str> {
        const MAX_REGIONS: usize = 120; // A safe upper limit to allow for splits.
        if self.region_size as usize > MAX_REGIONS
            || self.reserved_region_size as usize > MAX_REGIONS
        {
            return Err("memory regions and reserved regions are too big");
        }
        if self.reserved_region_size == 0 {
            self.allocatable = true;
            return Ok(()); // Nothing to do if there are no reserved regions.
        }

        let mut region_idx: usize = 0;

        for i in 0..self.reserved_region_size as usize {
            let reserved_region = self.reserved_regions[i];
            let mut cursor = reserved_region.address;
            let reserved_end = reserved_region.end_checked()?;
            let mut processed = false;

            while cursor < reserved_end {
                while region_idx < self.region_size as usize
                    && self.regions[region_idx].end_checked()? <= cursor
                {
                    region_idx += 1;
                }

                if region_idx == self.region_size as usize {
                    // Remaining reserved portion lies outside the known available regions.
                    cursor = reserved_end;
                    processed = true;
                    break;
                }

                if reserved_end <= self.regions[region_idx].address {
                    cursor = reserved_end;
                    processed = true;
                    break;
                }

                let clipped_start = max(cursor, self.regions[region_idx].address);
                let clipped_end = min(reserved_end, self.regions[region_idx].end_checked()?);

                if clipped_start >= clipped_end {
                    cursor = clipped_end;
                    continue;
                }

                processed = true;
                self.subtract_reserved_segment(&mut region_idx, clipped_start, clipped_end)?;
                cursor = clipped_end;
            }

            if cursor < reserved_end && !processed {
                return Err("invalid reserved region: located outside of all available regions");
            }
        }

        // clean reserved memory region
        self.reserved_regions = RegionContainer(RegionData::Global([EMPTY_REGION; 128]));
        self.reserved_region_size = 0;

        self.allocatable = true;
        Ok(())
    }

    fn subtract_reserved_segment(
        &mut self,
        region_idx: &mut usize,
        start: usize,
        end: usize,
    ) -> Result<(), &'static str> {
        debug_assert!(start < end);

        let idx = *region_idx;
        let regions = &mut self.regions;
        let region_address = regions[idx].address;
        let region_end = regions[idx].end_checked()?;

        debug_assert!(start >= region_address);
        debug_assert!(end <= region_end);

        let starts_at_same_address = region_address == start;
        let ends_at_same_address = region_end == end;
        let subtracted_size = end - start;

        match (starts_at_same_address, ends_at_same_address) {
            (true, true) => {
                regions.copy_within((idx + 1)..(self.region_size as usize), idx);
                self.region_size -= 1;
                let last_idx = self.region_size as usize;
                regions[last_idx] = EMPTY_REGION;
            }
            (true, false) => {
                regions[idx].address += subtracted_size;
                regions[idx].size -= subtracted_size;
            }
            (false, true) => {
                regions[idx].size -= subtracted_size;
            }
            (false, false) => {
                let new_region_count = self.region_size as usize + 1;
                if new_region_count > self.region_capacity as usize {
                    return Err("region buffer overflow after splitting");
                }

                let original_end = region_end;
                regions[idx].size = start - region_address;

                let insert_idx = idx + 1;
                regions.copy_within(insert_idx..self.region_size as usize, insert_idx + 1);
                regions[insert_idx] = MemoryRegions {
                    address: end,
                    size: original_end - end,
                };

                self.region_size += 1;
                *region_idx += 1;
            }
        }

        Ok(())
    }

    /// Plans a union without touching the array, including all joined neighbors.
    fn plan_insert(
        regions: &[MemoryRegions],
        region: MemoryRegions,
    ) -> Result<RegionEdit, &'static str> {
        let mut start = region.address;
        let mut end = region.end_checked()?;
        let mut index = regions.partition_point(|r| r.address < start);
        if index > 0 && regions[index - 1].end_checked()? >= start {
            index -= 1;
            start = regions[index].address;
            end = end.max(regions[index].end_checked()?);
        }
        let mut next = index;
        while next < regions.len() && regions[next].address <= end {
            end = end.max(regions[next].end_checked()?);
            next += 1;
        }
        Ok(RegionEdit {
            index,
            removed: next - index,
            first: Some(MemoryRegions::from_parts(start, end - start)),
            second: None,
        })
    }

    /// Plans removal only when the complete range belongs to one reserved entry.
    fn plan_reserved_removal(
        &self,
        address: usize,
        size: usize,
    ) -> Result<RegionEdit, &'static str> {
        let end = address.checked_add(size).ok_or("dealloc end overflow")?;
        let reserved = &self.reserved_regions[..self.reserved_region_size as usize];
        let next = reserved.partition_point(|r| r.address <= address);
        let index = next
            .checked_sub(1)
            .ok_or("deallocation outside reserved region")?;
        let region = reserved[index];
        let region_end = region.end_checked()?;
        if end > region_end {
            return Err("deallocation outside reserved region");
        }
        let left = (address > region.address).then_some(MemoryRegions::from_parts(
            region.address,
            address - region.address,
        ));
        let right = (end < region_end).then_some(MemoryRegions::from_parts(end, region_end - end));
        Ok(RegionEdit {
            index,
            removed: 1,
            first: left.or(right),
            second: if left.is_some() { right } else { None },
        })
    }

    fn plan_allocation(&self, size: usize, alignment: usize) -> Option<RegionPlan> {
        if size == 0 || alignment == 0 {
            return None;
        }
        for (i, region) in self.regions[..self.region_size as usize].iter().enumerate() {
            let end = region.end_checked().ok()?;
            let Some(address) = checked_align_up(region.address, alignment) else {
                continue;
            };
            let Some(alloc_end) = address.checked_add(size) else {
                continue;
            };
            if alloc_end > end {
                continue;
            }
            let left = (address > region.address).then_some(MemoryRegions::from_parts(
                region.address,
                address - region.address,
            ));
            let right =
                (alloc_end < end).then_some(MemoryRegions::from_parts(alloc_end, end - alloc_end));
            return Some(RegionPlan {
                free: RegionEdit {
                    index: i,
                    removed: 1,
                    first: left.or(right),
                    second: if left.is_some() { right } else { None },
                },
                reserved: Self::plan_insert(
                    &self.reserved_regions[..self.reserved_region_size as usize],
                    MemoryRegions::from_parts(address, size),
                )
                .ok()?,
                address,
            });
        }
        None
    }

    fn commit_plan(&mut self, plan: RegionPlan) -> usize {
        plan.free.commit(&mut self.regions, &mut self.region_size);
        plan.reserved
            .commit(&mut self.reserved_regions, &mut self.reserved_region_size);
        plan.address
    }

    /// Raw allocation for permanent metadata; it does not acquire a release credit.
    fn allocate_region_internal(&mut self, size: usize, alignment: usize) -> Option<usize> {
        let plan = self.plan_allocation(size, alignment)?;
        if plan.free.new_len(self.region_size) > self.region_capacity
            || plan.reserved.new_len(self.reserved_region_size) > self.reserved_region_capacity
        {
            return None;
        }
        Some(self.commit_plan(plan))
    }

    /// Every live allocation reserves a worst-case insertion in BOTH arrays.
    fn ensure_overflow_headroom(
        &self,
        plan: &RegionPlan,
        credits: u32,
    ) -> Result<(), &'static str> {
        let free = plan.free.new_len(self.region_size).checked_add(credits);
        let reserved = plan
            .reserved
            .new_len(self.reserved_region_size)
            .checked_add(credits);
        if free.is_none_or(|n| n > self.region_capacity)
            || reserved.is_none_or(|n| n > self.reserved_region_capacity)
        {
            return Err("insufficient deallocation metadata headroom");
        }
        Ok(())
    }

    fn ensure_deallocation_headroom(
        &self,
        address: usize,
        size: usize,
        whole_allocation: bool,
    ) -> Result<(RegionPlan, u32), &'static str> {
        address.checked_add(size).ok_or("dealloc end overflow")?;
        let reserved = self.plan_reserved_removal(address, size)?;
        let credits = if whole_allocation || reserved.first.is_none() {
            self.deallocation_credits
                .checked_sub(1)
                .ok_or("deallocation without an allocation credit")?
        } else if reserved.second.is_some() {
            // A partial release can turn one live allocation into two pieces.
            self.deallocation_credits
                .checked_add(1)
                .ok_or("deallocation credit overflow")?
        } else {
            self.deallocation_credits
        };
        let plan = RegionPlan {
            free: Self::plan_insert(
                &self.regions[..self.region_size as usize],
                MemoryRegions::from_parts(address, size),
            )?,
            reserved,
            address,
        };
        Ok((plan, credits))
    }

    /// Stages growth in the new backing allocation before changing either old array.
    /// If the requested operation fails, restore the original arrays and counters.
    fn overflow_wrapping<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let new_regions_capacity = self
            .region_capacity
            .checked_mul(2)
            .ok_or("region capacity overflow")?;
        let new_reserved_capacity = self
            .reserved_region_capacity
            .checked_mul(2)
            .ok_or("reserved region capacity overflow")?;
        let allocate_size = (new_regions_capacity as usize)
            .checked_add(new_reserved_capacity as usize)
            .and_then(|capacity| capacity.checked_mul(size_of::<MemoryRegions>()))
            .filter(|&bytes| bytes <= isize::MAX as usize)
            .ok_or("region metadata allocation size overflow")?;
        let plan = self
            .plan_allocation(allocate_size, 4096)
            .ok_or("out of memory for region metadata")?;
        if plan.free.new_len(self.region_size) > new_regions_capacity
            || plan.reserved.new_len(self.reserved_region_size) > new_reserved_capacity
        {
            return Err("region metadata is full");
        }
        let new_region = plan.address;
        let new_regions_ptr = new_region as *mut MemoryRegions;
        let new_reserved_ptr = (new_region
            + new_regions_capacity as usize * size_of::<MemoryRegions>())
            as *mut MemoryRegions;
        // SAFETY: The plan selects a disjoint writable free range, aligned to
        // 4096 (which satisfies MemoryRegions alignment), with allocate_size
        // bytes and a checked end. No old metadata resides in this free range.
        // All-zero usize fields form valid EMPTY_REGION values. Initialize every
        // slot before constructing references, then copy the initialized live
        // entries into disjoint arrays whose capacities were checked above.
        // Access stays exclusive under &mut self. Successful growth permanently
        // reserves the backing; rollback discards both staging references.
        let (regions, reserved_regions) = unsafe {
            core::ptr::write_bytes(new_region as *mut u8, 0, allocate_size);
            copy_nonoverlapping(
                self.regions.as_ptr(),
                new_regions_ptr,
                self.region_size as usize,
            );
            copy_nonoverlapping(
                self.reserved_regions.as_ptr(),
                new_reserved_ptr,
                self.reserved_region_size as usize,
            );
            (
                RegionContainer(RegionData::Heap(slice::from_raw_parts_mut(
                    new_regions_ptr,
                    new_regions_capacity as usize,
                ))),
                RegionContainer(RegionData::Heap(slice::from_raw_parts_mut(
                    new_reserved_ptr,
                    new_reserved_capacity as usize,
                ))),
            )
        };
        let old_regions = core::mem::replace(&mut self.regions, regions);
        let old_reserved = core::mem::replace(&mut self.reserved_regions, reserved_regions);
        let old_state = (
            self.region_size,
            self.reserved_region_size,
            self.region_capacity,
            self.reserved_region_capacity,
            self.deallocation_credits,
        );
        self.region_capacity = new_regions_capacity;
        self.reserved_region_capacity = new_reserved_capacity;
        self.allocate_region_internal(allocate_size, 4096)
            .expect("the staged metadata plan fits the expanded arrays");
        match operation(self) {
            Ok(value) => Ok(value),
            Err(error) => {
                // Discard staging references and restore both arrays and all counters
                // before another allocator operation can observe the free range.
                self.regions = old_regions;
                self.reserved_regions = old_reserved;
                (
                    self.region_size,
                    self.reserved_region_size,
                    self.region_capacity,
                    self.reserved_region_capacity,
                    self.deallocation_credits,
                ) = old_state;
                Err(error)
            }
        }
    }

    /// Commits an allocation only after reserving its eventual release metadata.
    fn allocate_with_headroom(&mut self, size: usize, align: usize) -> Result<usize, &'static str> {
        let plan = self
            .plan_allocation(size, align)
            .ok_or("allocation failed")?;
        let credits = self
            .deallocation_credits
            .checked_add(1)
            .ok_or("deallocation credit overflow")?;
        self.ensure_overflow_headroom(&plan, credits)?;
        let address = self.commit_plan(plan);
        self.deallocation_credits = credits;
        Ok(address)
    }

    pub fn allocate_region(&mut self, size: usize, align: usize) -> Option<usize> {
        if !self.allocatable {
            return None;
        }
        // Do not grow if no free range fits the request to begin with.
        let plan = self.plan_allocation(size, align)?;
        let credits = self.deallocation_credits.checked_add(1)?;
        if self.ensure_overflow_headroom(&plan, credits).is_ok() {
            let address = self.commit_plan(plan);
            self.deallocation_credits = credits;
            return Some(address);
        }
        self.overflow_wrapping(|block| block.allocate_with_headroom(size, align))
            .ok()
    }

    /// Releases a reserved subrange transactionally. `whole_allocation` may be
    /// true only for a complete live allocation returned by allocate_region;
    /// such a release always has headroom. For a partial release, retain credits
    /// for the remaining pieces and grow before committing if necessary.
    pub fn try_deallocate_region(
        &mut self,
        ptr: usize,
        layout: Layout,
        whole_allocation: bool,
    ) -> Result<(), &'static str> {
        if !self.allocatable {
            return Err("allocator not allocatable");
        }
        if layout.size() == 0 {
            return Ok(());
        }
        let (plan, credits) =
            self.ensure_deallocation_headroom(ptr, layout.size(), whole_allocation)?;
        if self.ensure_overflow_headroom(&plan, credits).is_ok() {
            self.commit_plan(plan);
            self.deallocation_credits = credits;
            return Ok(());
        }
        self.overflow_wrapping(|block| {
            let (plan, credits) =
                block.ensure_deallocation_headroom(ptr, layout.size(), whole_allocation)?;
            block.ensure_overflow_headroom(&plan, credits)?;
            block.commit_plan(plan);
            block.deallocation_credits = credits;
            Ok(())
        })
    }

    /// Releases one complete live allocation. Its credit pays for at most one
    /// new free entry AND one reserved split, so this never needs growth for a
    /// valid allocation, regardless of fragmentation or available heap bytes.
    /// The assertion diagnoses an invalid release or corrupted invariant;
    /// resource exhaustion is handled when the allocation is requested.
    pub fn deallocate_region(&mut self, ptr: usize, layout: Layout) {
        self.try_deallocate_region(ptr, layout, true)
            .expect("a complete live allocation owns deallocation metadata headroom");
    }

    /// Trims the allocator metadata and returns reserved regions for boot handoff.
    ///
    /// # Safety
    /// Allocates a `Vec` while `self` is exclusively borrowed under the allocator
    /// lock; callers must ensure this path only runs before `enable_raw_atomics`
    /// (when `RawSpinLock::lock()` is a no-op) and while execution is
    /// single-threaded. After atomic locking is enabled, re-entering the global
    /// allocator here may deadlock or spin forever.
    pub fn trim_for_boot(
        &mut self,
        reserve_bytes: usize,
    ) -> Result<Vec<(usize, usize)>, &'static str> {
        if !self.allocatable {
            return Err("allocator not allocatable");
        }

        let layout =
            Layout::from_size_align(reserve_bytes, 1).map_err(|_| "invalid reserve size")?;
        let allocate = self
            .allocate_region(reserve_bytes, 1)
            .ok_or("allocation failed")?;

        // Allocates while holding the guard; only valid in the pre-atomic/no-op lock phase.
        let mut vec = Vec::with_capacity(self.reserved_region_size as usize);

        self.allocatable = false;

        for region in self
            .reserved_regions
            .iter()
            .take(self.reserved_region_size as usize)
        {
            vec.push((region.address, region.size));
        }

        // clean memory region (free list)
        self.regions.fill(EMPTY_REGION);
        self.region_capacity = self.regions.len() as u32; // 128 for inline storage.
        self.region_size = 0;

        self.allocatable = true;

        self.deallocate_region(allocate, layout);
        Ok(vec)
    }

    pub fn for_each_free_region<F: FnMut(usize, usize)>(&self, mut f: F) {
        for region in &self.regions[..self.region_size as usize] {
            f(region.address, region.size);
        }
    }

    pub fn for_each_reserved_region<F: FnMut(usize, usize)>(&self, mut f: F) {
        for region in &self.reserved_regions[..self.reserved_region_size as usize] {
            f(region.address, region.size);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MemoryRegions {
    address: usize,
    size: usize,
}

impl MemoryRegions {
    // Internal constructor for building regions from raw parts.
    pub(crate) fn from_parts(address: usize, size: usize) -> Self {
        Self { address, size }
    }

    fn end_checked(&self) -> Result<usize, &'static str> {
        self.address
            .checked_add(self.size)
            .ok_or("region end overflow")
    }
}

/// Debug assertion macro (evaluates in test builds only).
#[cfg(test)]
#[macro_export]
macro_rules! debug_assert {
    ($($arg:tt)*) => (
        assert!($($arg)*);
    )
}

/// Debug assertion macro (no-op in release builds).
#[cfg(not(test))]
#[macro_export]
macro_rules! debug_assert {
    ($($arg:tt)*) => {};
}

#[cfg(test)]
mod tests {

    /// Real writable backing for tests that can grow metadata.
    struct TestHeap {
        address: usize,
        layout: Layout,
    }

    impl TestHeap {
        fn new(size: usize) -> Self {
            let layout = Layout::from_size_align(size, 4096).unwrap();
            // SAFETY: layout is nonzero and valid; the system allocator owns
            // this backing independently of the allocator under test.
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Self {
                address: ptr as usize,
                layout,
            }
        }
    }

    impl Drop for TestHeap {
        fn drop(&mut self) {
            // SAFETY: address is the live system allocation made in new with
            // exactly this layout. Each test drops its MemoryBlock first.
            unsafe { std::alloc::dealloc(self.address as *mut u8, self.layout) };
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        free: Vec<MemoryRegions>,
        reserved: Vec<MemoryRegions>,
        counts: (u32, u32),
        capacities: (u32, u32),
        credits: u32,
    }

    fn snapshot(block: &MemoryBlock) -> Snapshot {
        Snapshot {
            free: block.regions.to_vec(),
            reserved: block.reserved_regions.to_vec(),
            counts: (block.region_size, block.reserved_region_size),
            capacities: (block.region_capacity, block.reserved_region_capacity),
            credits: block.deallocation_credits,
        }
    }

    fn assert_headroom(block: &MemoryBlock) {
        assert!(block.region_size + block.deallocation_credits <= block.region_capacity);
        assert!(
            block.reserved_region_size + block.deallocation_credits
                <= block.reserved_region_capacity
        );
        for list in [
            &block.regions[..block.region_size as usize],
            &block.reserved_regions[..block.reserved_region_size as usize],
        ] {
            for region in list {
                assert!(region.size > 0);
                region.end_checked().unwrap();
            }
            for pair in list.windows(2) {
                assert!(pair[0].end_checked().unwrap() < pair[1].address);
            }
        }
        for free in &block.regions[..block.region_size as usize] {
            for reserved in &block.reserved_regions[..block.reserved_region_size as usize] {
                assert!(
                    free.end_checked().unwrap() <= reserved.address
                        || reserved.end_checked().unwrap() <= free.address
                );
            }
        }
    }

    fn fragmented_block(count: usize, stride: usize, size: usize) -> MemoryBlock {
        let mut block = MemoryBlock::init();
        for i in 0..count {
            block
                .add_region(&MemoryRegions::from_parts(0x1000 + i * stride, size))
                .unwrap();
        }
        block.check_regions().unwrap();
        block
    }

    use super::*;

    #[test]
    fn add_single_region() {
        let mut allocator = MemoryBlock::init();
        let region = MemoryRegions {
            address: 0x1000,
            size: 0x100,
        };
        assert_eq!(allocator.add_region(&region), Ok(()));
        assert_eq!(allocator.region_size, 1);
        assert_eq!(allocator.regions[0], region);
    }

    #[test]
    fn add_two_separate_regions() {
        let mut allocator = MemoryBlock::init();
        let region1 = MemoryRegions {
            address: 0x1000,
            size: 0x100,
        };
        let region2 = MemoryRegions {
            address: 0x2000,
            size: 0x100,
        };
        assert_eq!(allocator.add_region(&region1), Ok(()));
        assert_eq!(allocator.add_region(&region2), Ok(()));
        assert_eq!(allocator.region_size, 2);
        assert_eq!(allocator.regions[0], region1);
        assert_eq!(allocator.regions[1], region2);
    }

    #[test]
    fn add_adjacent_regions_merge() {
        let mut allocator = MemoryBlock::init();
        let region1 = MemoryRegions {
            address: 0x1000,
            size: 0x100,
        };
        let region2 = MemoryRegions {
            address: 0x1100,
            size: 0x100,
        };
        assert_eq!(allocator.add_region(&region1), Ok(()));
        assert_eq!(allocator.add_region(&region2), Ok(()));

        assert_eq!(allocator.region_size, 1);
        let expected_region = MemoryRegions {
            address: 0x1000,
            size: 0x200,
        };
        assert_eq!(allocator.regions[0], expected_region);
    }

    #[test]
    fn add_overlapping_regions_merge() {
        let mut allocator = MemoryBlock::init();
        let region1 = MemoryRegions {
            address: 0x1000,
            size: 0x200,
        };
        let region2 = MemoryRegions {
            address: 0x1100,
            size: 0x200,
        };
        assert_eq!(allocator.add_region(&region1), Ok(()));
        assert_eq!(allocator.add_region(&region2), Ok(()));

        assert_eq!(allocator.region_size, 1);
        let expected_region = MemoryRegions {
            address: 0x1000,
            size: 0x300,
        };
        assert_eq!(allocator.regions[0], expected_region);
    }

    #[test]
    fn add_region_that_spans_two_existing_regions() {
        let mut allocator = MemoryBlock::init();
        let region1 = MemoryRegions {
            address: 0x1000,
            size: 0x100,
        };
        let region3 = MemoryRegions {
            address: 0x2000,
            size: 0x100,
        };
        assert_eq!(allocator.add_region(&region1), Ok(()));
        assert_eq!(allocator.add_region(&region3), Ok(()));
        assert_eq!(allocator.region_size, 2);

        // Add a region that connects region1 and region3
        let region2 = MemoryRegions {
            address: 0x1000,
            size: 0x1100,
        };
        assert_eq!(allocator.add_region(&region2), Ok(()));

        assert_eq!(allocator.region_size, 1);
        let expected_region = MemoryRegions {
            address: 0x1000,
            size: 0x1100,
        };
        assert_eq!(allocator.regions[0], expected_region);
    }

    #[test]
    fn add_reserved_region() {
        let mut allocator = MemoryBlock::init();
        let region = MemoryRegions {
            address: 0x1000,
            size: 0x100,
        };
        assert_eq!(allocator.add_reserved_region(&region), Ok(()));
        assert_eq!(allocator.reserved_region_size, 1);
        assert_eq!(allocator.reserved_regions[0], region);
    }

    #[test]
    fn add_region_that_is_contained_in_existing_region() {
        let mut allocator = MemoryBlock::init();
        let outer_region = MemoryRegions {
            address: 0x1000,
            size: 0x1000,
        };
        assert_eq!(allocator.add_region(&outer_region), Ok(()));
        assert_eq!(allocator.region_size, 1);

        let inner_region = MemoryRegions {
            address: 0x1100,
            size: 0x100,
        };
        assert_eq!(allocator.add_region(&inner_region), Ok(()));

        // The size should not change, and the region should remain the same
        assert_eq!(allocator.region_size, 1);
        assert_eq!(allocator.regions[0], outer_region);
    }

    #[test]
    fn check_regions_no_reserved() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 1);
        assert!(allocator.allocatable);
    }

    #[test]
    fn check_regions_perfect_match() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();

        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 0);
        assert!(allocator.allocatable);
    }

    #[test]
    fn check_regions_starts_at_same_address() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1000,
                size: 0x100,
            })
            .unwrap();

        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1100,
                size: 0xF00
            }
        );
        assert!(allocator.allocatable);
    }

    #[test]
    fn check_regions_ends_at_same_address() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1F00,
                size: 0x100,
            })
            .unwrap();

        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0xF00
            }
        );
        assert!(allocator.allocatable);
    }

    #[test]
    fn check_regions_split() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1100,
                size: 0x100,
            })
            .unwrap();

        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 2);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1200,
                size: 0xE00
            }
        );
        assert!(allocator.allocatable);
    }

    #[test]
    fn check_regions_multiple_reserved() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_region(&MemoryRegions {
                address: 0x3000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1100,
                size: 0x100,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x3200,
                size: 0x100,
            })
            .unwrap();

        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 4);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1200,
                size: 0xE00
            }
        );
        assert_eq!(
            allocator.regions[2],
            MemoryRegions {
                address: 0x3000,
                size: 0x200
            }
        );
        assert_eq!(
            allocator.regions[3],
            MemoryRegions {
                address: 0x3300,
                size: 0xD00
            }
        );
    }

    #[test]
    fn check_regions_does_not_align_without_reserved_regions() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1234,
                size: 0x5000,
            })
            .unwrap();

        allocator.check_regions().expect("reconcile pass failed");

        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1234,
                size: 0x5000
            }
        );
    }

    #[test]
    fn allocations_are_page_aligned() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x0,
                size: 0x3FC0_0000,
            })
            .unwrap();
        allocator
            .add_region(&MemoryRegions {
                address: 0x4000_0000,
                size: 0xC000_0000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x0,
                size: 0x80_000,
            })
            .unwrap();
        allocator
            .add_reserved_region_dynamic(0x4000_000, None, Some((0, 0x4000_0000)))
            .unwrap()
            .expect("dynamic reserved region allocation failed");
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x3FD1_67A0,
                size: 0xA1,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x80_000,
                size: 0x3E0_0000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x2000_0000,
                size: 0x13B29,
            })
            .unwrap();

        allocator.check_regions().unwrap();

        let addr_big = allocator
            .allocate_region_internal(0x8000, 0x8000)
            .expect("failed to allocate 32KiB aligned block");
        assert_eq!(addr_big & 0x7FFF, 0);

        for _ in 0..0x1000 {
            let addr = allocator
                .allocate_region_internal(0x1_000, 0x1000)
                .expect("failed to allocate 4KiB page");
            assert_eq!(addr & 0xFFF, 0);
        }
    }

    #[test]
    fn check_regions_error_outside() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x2000,
                size: 0x100,
            })
            .unwrap();
        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x1000
            }
        );
    }

    #[test]
    fn check_regions_error_not_contained() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x100,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1000,
                size: 0x200,
            })
            .unwrap();
        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 0);
    }

    #[test]
    fn check_regions_multiple_reserved_in_one_region() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1100,
                size: 0x100,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1300,
                size: 0x100,
            })
            .unwrap();

        assert_eq!(allocator.check_regions(), Ok(()));
        assert_eq!(allocator.region_size, 3);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1200,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[2],
            MemoryRegions {
                address: 0x1400,
                size: 0xC00
            }
        );
    }

    #[test]
    fn test_allocate_region_before_check_regions() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        assert_eq!(allocator.allocate_region(0x100, 0x10), None);
    }

    #[test]
    fn test_allocate_region_simple() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let ptr = allocator.allocate_region(0x100, 0x10);
        assert_eq!(ptr, Some(0x1000));
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1100,
                size: 0xF00
            }
        );
    }

    #[test]
    fn test_allocate_region_no_sufficient_space() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x100,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        assert_eq!(allocator.allocate_region(0x200, 0x10), None);
    }

    #[test]
    fn test_allocate_region_respects_reserved_region() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1000,
                size: 0x100,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let ptr = allocator.allocate_region(0x100, 0x10);
        assert_eq!(ptr, Some(0x1100));
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1200,
                size: 0xE00
            }
        );
    }

    #[test]
    fn test_allocate_region_with_alignment() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1001,
                size: 0x1000,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let ptr = allocator.allocate_region(0x100, 0x100);
        assert_eq!(ptr, Some(0x1100));

        // Check that the original region is split correctly
        assert_eq!(allocator.region_size, 2);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1001,
                size: 0xFF
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1200,
                size: 0xE01
            }
        );
    }

    #[test]
    fn test_overflow_wrapping() {
        let heap = TestHeap::new(0x200000);
        let mut allocator = MemoryBlock::init();
        // Add a large region with an unaligned address.
        allocator
            .add_region(&MemoryRegions {
                address: heap.address,
                size: 0x200000, // 2MB
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let initial_region_capacity = allocator.region_capacity;
        let initial_reserved_capacity = allocator.reserved_region_capacity;
        assert_eq!(initial_region_capacity, 128);

        for _ in 0..120 {
            assert!(allocator.allocate_region(0x10, 0x1000).is_some());
            assert_headroom(&allocator);
        }
        assert!(allocator.region_capacity > initial_region_capacity);
        assert!(allocator.reserved_region_capacity > initial_reserved_capacity);
        assert!(
            allocator.regions[allocator.region_size as usize..]
                .iter()
                .all(|&region| region == EMPTY_REGION)
        );
        assert!(
            allocator.reserved_regions[allocator.reserved_region_size as usize..]
                .iter()
                .all(|&region| region == EMPTY_REGION)
        );

        // region_size should be 120 now.
        assert_eq!(allocator.region_size, 120);

        // Verify that we can still allocate after wrapping.
        assert!(allocator.allocate_region(0x10, 0x1000).is_some());
        assert_eq!(allocator.region_size, 121);

        let capacity = allocator.region_capacity;
        let reserved = allocator.trim_for_boot(0x10).unwrap();
        assert_eq!(reserved.len(), 121);
        assert_eq!(allocator.region_capacity, capacity);
        assert_eq!(allocator.region_size, 1);
        assert!(allocator.regions[1..].iter().all(|&r| r == EMPTY_REGION));
    }

    #[test]
    fn test_allocation_uses_spare_slots_without_metadata_growth_space() {
        let mut allocator = MemoryBlock::init();
        for i in 0..119 {
            allocator
                .add_region(&MemoryRegions {
                    address: 0x1000 + i * 0x1000,
                    size: 0x100,
                })
                .unwrap();
        }
        allocator.check_regions().unwrap();

        // No free range can hold the expanded arrays, but there is enough
        // metadata headroom for the allocation itself.
        assert_eq!(allocator.allocate_region(0x10, 0x10), Some(0x1000));
        assert_eq!(allocator.region_size, 119);
        assert_eq!(allocator.reserved_region_size, 1);
        assert_eq!(allocator.region_capacity, 128);
        assert_eq!(allocator.reserved_region_capacity, 128);
        assert_eq!(
            allocator.reserved_regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x10
            }
        );
    }

    #[test]
    fn test_allocation_splits_with_spare_slot_without_metadata_growth_space() {
        let mut allocator = MemoryBlock::init();
        for i in 0..119 {
            allocator
                .add_region(&MemoryRegions {
                    address: 0x1001 + i * 0x1000,
                    size: 0x100,
                })
                .unwrap();
        }
        allocator.check_regions().unwrap();

        // Aligning the candidate requires one additional free-list entry.
        // This succeeds without a larger metadata backing allocation.
        assert_eq!(allocator.allocate_region(0x10, 0x20), Some(0x1020));
        assert_eq!(allocator.region_size, 120);
        assert_eq!(allocator.reserved_region_size, 1);
        assert_eq!(allocator.region_capacity, 128);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1001,
                size: 0x1f
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1030,
                size: 0xd1
            }
        );
    }

    #[test]
    fn test_deallocation_uses_existing_metadata_slots() {
        let mut allocator = MemoryBlock::init();
        for i in 0..119 {
            allocator
                .add_region(&MemoryRegions {
                    address: 0x1000 + i * 0x1000,
                    size: 0x100,
                })
                .unwrap();
        }
        allocator.check_regions().unwrap();

        // Simulate a live allocation made before the free list fragmented.
        let addr = allocator.allocate_region(0x10, 0x10).unwrap();
        allocator
            .try_deallocate_region(addr, Layout::from_size_align(0x10, 0x10).unwrap(), true)
            .unwrap();
        assert_eq!(allocator.region_capacity, 128);
        assert_eq!(allocator.region_size, 119);
        assert_eq!(allocator.reserved_region_size, 0);
    }

    #[test]
    fn test_deallocation_at_full_capacity_can_merge() {
        let mut allocator = fragmented_block(119, 0x1000, 0x100);
        let addr = allocator.allocate_region(0x10, 0x10).unwrap();
        // Artificially constrain the backing array to its live count. This
        // exercises the capacity boundary without bypassing finalization's limit.
        allocator.region_capacity = allocator.region_size;
        allocator
            .try_deallocate_region(addr, Layout::from_size_align(0x10, 0x10).unwrap(), true)
            .unwrap();
        assert_eq!(allocator.region_size, 119);
        assert_eq!(allocator.reserved_region_size, 0);
        assert_eq!(allocator.region_capacity, 119);
        assert_headroom(&allocator);
    }

    #[test]
    fn test_deallocation_reports_metadata_exhaustion() {
        let mut allocator = fragmented_block(119, 0x1000, 0x100);
        let addr = allocator.allocate_region(0x80, 1).unwrap();
        allocator.region_capacity = allocator.region_size;
        // Release an interior portion of one allocation: this needs a new free
        // entry and splits the reserved entry. No fragment can hold metadata.
        let before = snapshot(&allocator);
        let result = allocator.try_deallocate_region(
            addr + 0x20,
            Layout::from_size_align(0x20, 1).unwrap(),
            false,
        );
        assert_eq!(result, Err("out of memory for region metadata"));
        assert_eq!(snapshot(&allocator), before);
    }

    #[test]
    fn allocation_reserves_release_slots_when_fragmented_metadata_cannot_grow() {
        let mut allocator = fragmented_block(119, 0x1000, 0x100);
        let original = snapshot(&allocator);
        let layout = Layout::from_size_align(0x20, 1).unwrap();
        for _ in 0..4 {
            let mut allocated = Vec::new();
            loop {
                let before = snapshot(&allocator);
                let Some(address) = allocator.allocate_region(layout.size(), layout.align()) else {
                    assert_eq!(snapshot(&allocator), before);
                    break;
                };
                allocated.push(address);
                assert_headroom(&allocator);
            }
            assert!(allocated.len() > 1);
            assert_eq!(allocator.region_capacity, 128);
            // There are still fitting byte ranges; the limiting resource is
            // capacity reserved for future deallocations, not available bytes.
            assert!(
                allocator
                    .plan_allocation(layout.size(), layout.align())
                    .is_some()
            );
            // Release alternating interior allocations first to force holes and
            // splits in merged reserved entries, using only existing metadata.
            for parity in [1, 0] {
                for &address in allocated.iter().skip(parity).step_by(2) {
                    allocator.deallocate_region(address, layout);
                    assert_headroom(&allocator);
                    assert_eq!(allocator.region_capacity, 128);
                }
            }
            assert_eq!(snapshot(&allocator), original);
        }
    }

    #[test]
    fn complete_deallocation_can_fill_the_last_free_metadata_slot() {
        let mut allocator = fragmented_block(119, 0x1000, 0x100);
        let layout = Layout::from_size_align(0x100, 1).unwrap();
        let address = allocator.allocate_region(layout.size(), 1).unwrap();
        assert_eq!(allocator.region_size, 118);
        // Exactly one slot remains, owned by the live allocation. No byte range
        // can hold larger metadata. Returning this isolated region fills it.
        allocator.region_capacity = 119;
        assert_headroom(&allocator);
        allocator.deallocate_region(address, layout);
        assert_eq!(allocator.region_size, allocator.region_capacity);
        assert_eq!(allocator.deallocation_credits, 0);
        assert_headroom(&allocator);
    }

    #[test]
    fn partial_deallocation_splits_one_allocation_and_preserves_remaining_pieces() {
        let mut allocator = fragmented_block(1, 0x1000, 0x100);
        let address = allocator.allocate_region(0x80, 1).unwrap();
        allocator
            .try_deallocate_region(
                address + 0x20,
                Layout::from_size_align(0x20, 1).unwrap(),
                false,
            )
            .unwrap();
        assert_eq!(allocator.deallocation_credits, 2);
        assert_eq!(allocator.reserved_region_size, 2);
        assert_eq!(
            allocator.reserved_regions[0],
            MemoryRegions::from_parts(address, 0x20)
        );
        assert_eq!(
            allocator.reserved_regions[1],
            MemoryRegions::from_parts(address + 0x40, 0x40)
        );
        assert_headroom(&allocator);
        // The original allocation was split; return its remaining pieces using
        // the partial-release interface, rather than the original full layout.
        allocator
            .try_deallocate_region(address, Layout::from_size_align(0x20, 1).unwrap(), false)
            .unwrap();
        allocator
            .try_deallocate_region(
                address + 0x40,
                Layout::from_size_align(0x40, 1).unwrap(),
                false,
            )
            .unwrap();
        assert_headroom(&allocator);
        assert_eq!(allocator.deallocation_credits, 0);
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions::from_parts(0x1000, 0x100)
        );
    }

    #[test]
    fn partial_deallocation_grows_both_full_metadata_arrays() {
        let heap = TestHeap::new(0x20000);
        let mut allocator = MemoryBlock::init();
        // Deliberately construct the boundary state left possible by the old
        // allocator. Normal allocations now reserve credits before reaching it.
        for i in 0..127 {
            allocator
                .add_region(&MemoryRegions::from_parts(heap.address + i * 0x200, 0x80))
                .unwrap();
        }
        allocator
            .add_region(&MemoryRegions::from_parts(heap.address + 0x10001, 0xFFFF))
            .unwrap();
        for i in 0..128 {
            allocator
                .add_reserved_region(&MemoryRegions::from_parts(
                    heap.address + i * 0x200 + 0x100,
                    0x80,
                ))
                .unwrap();
        }
        allocator.allocatable = true;
        allocator.deallocation_credits = 1;
        let address = heap.address + 0x120;
        allocator
            .try_deallocate_region(address, Layout::from_size_align(0x20, 1).unwrap(), false)
            .unwrap();
        assert_eq!(allocator.region_capacity, 256);
        assert_eq!(allocator.reserved_region_capacity, 256);
        // Metadata alignment itself splits a free range and creates a reserved
        // entry. The release then adds a hole and splits a reserved entry.
        assert_eq!(allocator.region_size, 130);
        assert_eq!(allocator.reserved_region_size, 130);
        assert_headroom(&allocator);
        assert!(
            allocator.regions[allocator.region_size as usize..]
                .iter()
                .all(|&r| r == EMPTY_REGION)
        );
        assert!(
            allocator.reserved_regions[allocator.reserved_region_size as usize..]
                .iter()
                .all(|&r| r == EMPTY_REGION)
        );
        let reused = allocator.allocate_region(0x20, 1).unwrap();
        allocator.deallocate_region(reused, Layout::from_size_align(0x20, 1).unwrap());
        assert_headroom(&allocator);
    }

    #[test]
    fn metadata_growth_rolls_back_when_it_consumes_the_callers_only_fit() {
        let heap = TestHeap::new(0x3000);
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions::from_parts(heap.address, 0x3000))
            .unwrap();
        allocator.check_regions().unwrap();
        let mut allocated = Vec::new();
        let first = Layout::from_size_align(0x1000 - 126 * 0x10, 1).unwrap();
        allocated.push((allocator.allocate_region(first.size(), 1).unwrap(), first));
        let small = Layout::from_size_align(0x10, 1).unwrap();
        for _ in 0..126 {
            allocated.push((allocator.allocate_region(0x10, 1).unwrap(), small));
        }
        assert_eq!(allocator.deallocation_credits, 127);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions::from_parts(heap.address + 0x1000, 0x2000)
        );
        assert_headroom(&allocator);
        let before = snapshot(&allocator);
        // Expanded arrays fit, but leave no bytes for the user's allocation.
        assert_eq!(allocator.allocate_region(0x2000, 1), None);
        assert_eq!(snapshot(&allocator), before);
        for (address, layout) in allocated {
            allocator.deallocate_region(address, layout);
            assert_headroom(&allocator);
        }
        assert_eq!(allocator.allocate_region(0x3000, 1), Some(heap.address));
        allocator.deallocate_region(heap.address, Layout::from_size_align(0x3000, 1).unwrap());
        assert_headroom(&allocator);
    }

    #[test]
    fn deallocation_validation_failure_does_not_remove_reserved_record() {
        let mut allocator = fragmented_block(1, 0x1000, 0x100);
        let address = allocator.allocate_region(0x80, 1).unwrap();
        // A corrupt neighboring free range must be diagnosed before the
        // prevalidated reserved removal is committed.
        allocator.regions[0] = MemoryRegions::from_parts(address - 1, usize::MAX);
        let before = snapshot(&allocator);
        assert_eq!(
            allocator.try_deallocate_region(
                address,
                Layout::from_size_align(0x80, 1).unwrap(),
                true,
            ),
            Err("region end overflow")
        );
        assert_eq!(snapshot(&allocator), before);
    }

    #[test]
    fn raw_allocation_at_full_capacity_does_not_need_a_temporary_split_slot() {
        let mut allocator = fragmented_block(119, 0x1000, 0x100);
        allocator.region_capacity = allocator.region_size;
        allocator.regions[0] = MemoryRegions::from_parts(0x1001, 0xFF);
        // Alignment leaves a prefix but consumes the entire suffix. The final
        // free count is unchanged even though the old algorithm inserted first.
        assert_eq!(allocator.allocate_region_internal(0xE0, 0x20), Some(0x1020));
        assert_eq!(allocator.region_size, 119);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions::from_parts(0x1001, 0x1F)
        );
    }

    #[test]
    fn repeated_metadata_growth_then_deallocations_and_reuse() {
        let heap = TestHeap::new(0x400000);
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions::from_parts(heap.address, 0x400000))
            .unwrap();
        allocator.check_regions().unwrap();
        let layout = Layout::from_size_align(0x10, 0x1000).unwrap();
        let mut allocated = Vec::new();
        for _ in 0..600 {
            let address = allocator
                .allocate_region(layout.size(), layout.align())
                .unwrap();
            assert_eq!(address % layout.align(), 0);
            allocated.push(address);
            assert_headroom(&allocator);
        }
        assert!(allocator.region_capacity >= 2048); // At least four doublings.
        let capacity = allocator.region_capacity;
        for parity in [1, 0] {
            for &address in allocated.iter().skip(parity).step_by(2) {
                allocator.deallocate_region(address, layout);
                assert_headroom(&allocator);
            }
        }
        assert_eq!(allocator.deallocation_credits, 0);
        assert_eq!(allocator.region_capacity, capacity);
        let before = snapshot(&allocator);
        let large = Layout::from_size_align(0x4000, 0x1000).unwrap();
        let address = allocator
            .allocate_region(large.size(), large.align())
            .unwrap();
        allocator.deallocate_region(address, large);
        assert_eq!(snapshot(&allocator), before);
    }

    #[test]
    fn public_allocator_apis_grow_release_and_reuse_memory() {
        use crate::DefaultAllocator;
        use core::alloc::GlobalAlloc;

        static ALLOCATOR: DefaultAllocator = DefaultAllocator::new();
        let heap = TestHeap::new(0x400000);
        ALLOCATOR.init();
        assert_eq!(
            ALLOCATOR.allocate_with_size_and_align(0x10, 1),
            Err("allocator not finalized")
        );
        ALLOCATOR
            .add_available_region(heap.address, heap.layout.size())
            .unwrap();
        ALLOCATOR.add_reserved_region(heap.address, 0x1000).unwrap();
        ALLOCATOR.finalize().unwrap();
        ALLOCATOR.finalize().unwrap();
        assert_eq!(
            ALLOCATOR.add_available_region(heap.address, 0x1000),
            Err("allocator already finalized")
        );
        let layout = Layout::from_size_align(0x1800, 0x1000).unwrap();
        let small = Layout::from_size_align(0x20, 0x20).unwrap();
        let explicit = ALLOCATOR
            .allocate_with_size_and_align(layout.size(), layout.align())
            .unwrap();
        let mut allocated = Vec::new();
        for _ in 0..300 {
            // SAFETY: The allocator has exclusive use of the live writable
            // test heap, and layout is nonzero with valid power-of-two alignment.
            let ptr = unsafe { ALLOCATOR.alloc(layout) };
            assert!(!ptr.is_null());
            assert_eq!(ptr as usize % layout.align(), 0);
            // SAFETY: This is a live returned allocation of layout.size bytes.
            unsafe { ptr.write_bytes(0xA5, layout.size()) };
            allocated.push(ptr);
        }
        // SAFETY: The initialized allocator owns enough writable test backing
        // for this valid layout; this request exercises its buddy allocator.
        let buddy = unsafe { ALLOCATOR.alloc(small) };
        assert!(!buddy.is_null());
        let before_failure = snapshot(ALLOCATOR.range_list_allocator.lock().get().unwrap());
        let huge = Layout::from_size_align(heap.layout.size() * 2, 0x1000).unwrap();
        // SAFETY: huge is a valid nonzero layout. Exhaustion must return null
        // without changing any metadata or invalidating earlier allocations.
        assert!(unsafe { ALLOCATOR.alloc(huge) }.is_null());
        assert_eq!(
            ALLOCATOR.allocate_with_size_and_align(huge.size(), huge.align()),
            Err("failed to allocate")
        );
        assert_eq!(
            snapshot(ALLOCATOR.range_list_allocator.lock().get().unwrap()),
            before_failure
        );
        for &ptr in &allocated {
            // SAFETY: Each pointer still owns layout.size bytes written above.
            unsafe {
                assert_eq!(ptr.read(), 0xA5);
                assert_eq!(ptr.add(layout.size() - 1).read(), 0xA5);
            }
        }
        let mut observed_reserved = 0;
        ALLOCATOR
            .for_each_reserved_region(|_, _| observed_reserved += 1)
            .unwrap();
        assert!(observed_reserved > 1);
        for parity in [1, 0] {
            for &ptr in allocated.iter().skip(parity).step_by(2) {
                // SAFETY: Each pointer is a distinct live allocation with this
                // exact layout, and the two parity passes release it once.
                unsafe { ALLOCATOR.dealloc(ptr, layout) };
            }
        }
        // SAFETY: explicit came from the public range API with this large
        // layout (the same range path used by GlobalAlloc); buddy is a live
        // allocation made with small. Neither has been released yet.
        unsafe {
            ALLOCATOR.dealloc(explicit as *mut u8, layout);
            ALLOCATOR.dealloc(buddy, small);
        }
        let mut free_bytes = 0;
        ALLOCATOR
            .for_each_free_region(|_, size| free_bytes += size)
            .unwrap();
        assert!(free_bytes > 0x300000);
        // Clear the static's metadata references before TestHeap frees backing.
        ALLOCATOR.buddy_allocator.lock().take();
        ALLOCATOR.range_list_allocator.lock().take();
    }

    #[test]
    fn public_global_allocator_metadata_exhaustion_preserves_all_live_deallocations() {
        use crate::MemoryAllocator;
        use core::alloc::GlobalAlloc;

        static ALLOCATOR: MemoryAllocator<64, { crate::levels!(64) }> = MemoryAllocator::new();
        let heap = TestHeap::new(0x80000);
        ALLOCATOR.init();
        for i in 0..119 {
            ALLOCATOR
                .add_available_region(heap.address + i * 0x1000, 0x100)
                .unwrap();
        }
        ALLOCATOR.finalize().unwrap();
        let original = snapshot(ALLOCATOR.range_list_allocator.lock().get().unwrap());
        // Requests above the buddy limit take the range path. Each fragment
        // holds two adjacent allocations, so freeing the first creates a hole.
        let layout = Layout::from_size_align(0x80, 0x80).unwrap();
        for _ in 0..3 {
            let mut allocated = Vec::new();
            loop {
                let before = snapshot(ALLOCATOR.range_list_allocator.lock().get().unwrap());
                // SAFETY: The initialized allocator exclusively manages this
                // live writable backing and layout is valid and nonzero.
                let ptr = unsafe { ALLOCATOR.alloc(layout) };
                if ptr.is_null() {
                    assert_eq!(
                        snapshot(ALLOCATOR.range_list_allocator.lock().get().unwrap()),
                        before
                    );
                    break;
                }
                allocated.push(ptr);
            }
            assert!(allocated.len() > 2);
            for parity in [0, 1] {
                for &ptr in allocated.iter().skip(parity).step_by(2) {
                    // SAFETY: Each distinct pointer came from this allocator
                    // with this layout, and is released exactly once.
                    unsafe { ALLOCATOR.dealloc(ptr, layout) };
                    assert_headroom(ALLOCATOR.range_list_allocator.lock().get().unwrap());
                }
            }
            assert_eq!(
                snapshot(ALLOCATOR.range_list_allocator.lock().get().unwrap()),
                original
            );
        }
        ALLOCATOR.buddy_allocator.lock().take();
        ALLOCATOR.range_list_allocator.lock().take();
    }

    #[test]
    fn metadata_capacity_overflow_does_not_mutate_lists() {
        let mut allocator = fragmented_block(1, 0x1000, 0x100);
        allocator.region_capacity = 1 << 31;
        let before = snapshot(&allocator);
        assert_eq!(
            allocator.overflow_wrapping(|_| Ok(())),
            Err("region capacity overflow")
        );
        assert_eq!(snapshot(&allocator), before);
    }

    #[test]
    fn test_deallocate_region_simple_roundtrip() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let layout = Layout::from_size_align(0x100, 0x10).unwrap();
        let ptr = allocator
            .allocate_region(0x100, 0x10)
            .expect("alloc failed");
        assert_eq!(ptr, 0x1000);
        // After alloc: regions becomes [0x1100, 0xF00]
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1100,
                size: 0xF00
            }
        );

        // Deallocate and expect full region restored
        allocator.deallocate_region(ptr, layout);
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x1000
            }
        );
    }

    #[test]
    fn test_deallocate_region_adjacent_allocations_merge_back() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let l = Layout::from_size_align(0x100, 0x100).unwrap();
        let p1 = allocator.allocate_region(0x100, 0x100).unwrap(); // 0x1000..0x1100
        let p2 = allocator.allocate_region(0x100, 0x100).unwrap(); // 0x1100..0x1200
        assert_eq!(p1, 0x1000);
        assert_eq!(p2, 0x1100);

        // Now free regions should begin at 0x1200..0x2000 (single region)
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1200,
                size: 0xE00
            }
        );

        // Deallocate first block; should create a separate free region at 0x1000..0x1100
        allocator.deallocate_region(p1, l);
        assert_eq!(allocator.region_size, 2);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1200,
                size: 0xE00
            }
        );

        // Deallocate second block; free regions should merge into a single 0x1000..0x2000
        allocator.deallocate_region(p2, l);
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x1000
            }
        );
    }

    #[test]
    fn test_deallocate_region_middle_split_reserved() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        // Allocate three adjacent blocks so reserved merges into one
        let l = Layout::from_size_align(0x100, 0x100).unwrap();
        let p1 = allocator.allocate_region(0x100, 0x100).unwrap(); // 0x1000..0x1100
        let p2 = allocator.allocate_region(0x100, 0x100).unwrap(); // 0x1100..0x1200
        let p3 = allocator.allocate_region(0x100, 0x100).unwrap(); // 0x1200..0x1300
        assert_eq!((p1, p2, p3), (0x1000, 0x1100, 0x1200));

        // Free list: [0x1300, 0xD00]
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1300,
                size: 0xD00
            }
        );

        // Dealloc middle block; reserved should split, free list gains 0x1100..0x1200 as a new region
        allocator.deallocate_region(p2, l);
        assert_eq!(allocator.region_size, 2);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1100,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1300,
                size: 0xD00
            }
        );

        // Dealloc ends; after both, the free list should merge fully back
        allocator.deallocate_region(p1, l);
        allocator.deallocate_region(p3, l);
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x1000
            }
        );
    }

    #[test]
    fn test_add_reserved_region_dynamic_pre_finalize_basic() {
        let mut allocator = MemoryBlock::init();
        // Add a single free region [0x1000, 0x2000)
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();

        // Request 0x100 bytes aligned to 0x100 within [0x1010, 0x1510)
        let addr = allocator
            .add_reserved_region_dynamic(0x100, Some(0x100), Some((0x1010, 0x500)))
            .unwrap();

        // Alignment rounds up 0x1010 to 0x1100
        assert_eq!(addr, Some(0x1100));
        assert_eq!(allocator.reserved_region_size, 1);
        assert_eq!(
            allocator.reserved_regions[0],
            MemoryRegions {
                address: 0x1100,
                size: 0x100
            }
        );

        // Finalize and ensure the reserved area is subtracted
        allocator.check_regions().unwrap();
        assert_eq!(allocator.region_size, 2);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x1000,
                size: 0x100
            }
        );
        assert_eq!(
            allocator.regions[1],
            MemoryRegions {
                address: 0x1200,
                size: 0xE00
            }
        );
    }

    #[test]
    fn test_add_reserved_region_dynamic_pre_finalize_overlap_returns_none() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        // Pre-existing reserved at [0x1100, 0x1200)
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1100,
                size: 0x100,
            })
            .unwrap();

        // Range [0x1080, 0x1280) rounds up to 0x1100 which overlaps, implementation skips this region
        let addr = allocator
            .add_reserved_region_dynamic(0x100, Some(0x100), Some((0x1080, 0x200)))
            .unwrap();
        assert_eq!(addr, None);
    }

    #[test]
    fn test_add_reserved_region_dynamic_post_finalize_returns_err() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        // After finalize, dynamic reserved add should return Err
        let res = allocator.add_reserved_region_dynamic(0x100, Some(0x80), Some((0x1000, 0x1000)));
        assert!(res.is_err());
    }

    #[test]
    fn test_add_reserved_region_dynamic_err_index_equal_len_should_succeed_when_fixed() {
        let mut allocator = MemoryBlock::init();

        // Two pre-existing reserved regions below the free region range
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x1000,
                size: 0x100,
            })
            .unwrap();
        allocator
            .add_reserved_region(&MemoryRegions {
                address: 0x2000,
                size: 0x100,
            })
            .unwrap();

        // Free regions: provide small regions covering the two existing reserved
        // areas so that finalization can succeed, plus a larger region after them
        // to exercise Err(len) in binary_search for region_start = 0x5000.
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x100, // covers [0x1000,0x1100)
            })
            .unwrap();
        allocator
            .add_region(&MemoryRegions {
                address: 0x2000,
                size: 0x100, // covers [0x2000,0x2100)
            })
            .unwrap();
        allocator
            .add_region(&MemoryRegions {
                address: 0x5000,
                size: 0x1000, // [0x5000, 0x6000)
            })
            .unwrap();

        // With a correct implementation, this returns Some(0x5000) and records
        // the reservation into reserved_regions at the end.
        let addr = allocator
            .add_reserved_region_dynamic(0x80, Some(0x80), None)
            .expect("unexpected Err from pre-finalize dynamic reserve");
        assert_eq!(addr, Some(0x5000));

        // Verify reservation recorded as the last reserved region
        assert_eq!(allocator.reserved_region_size, 3);
        assert_eq!(
            allocator.reserved_regions[2],
            MemoryRegions {
                address: 0x5000,
                size: 0x80
            }
        );

        // Finalize; available region should have the reserved [0x5000,0x5080) subtracted
        allocator.check_regions().unwrap();
        // Two small regions are fully consumed by the earlier fixed reservations,
        // the third region is partially consumed by the dynamic reservation.
        assert_eq!(allocator.region_size, 1);
        assert_eq!(
            allocator.regions[0],
            MemoryRegions {
                address: 0x5080,
                size: 0xF80
            }
        );
    }

    #[test]
    fn allocate_region_alignment_overflow_returns_none() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: usize::MAX - 0xF,
                size: 0x8,
            })
            .unwrap();
        allocator.check_regions().unwrap();

        let addr = allocator.allocate_region(0x4, 0x20);
        assert_eq!(addr, None);
    }

    #[test]
    fn add_reserved_region_dynamic_alloc_range_overflow_returns_err() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: 0x1000,
                size: 0x1000,
            })
            .unwrap();

        let res = allocator.add_reserved_region_dynamic(
            0x10,
            Some(0x10),
            Some((usize::MAX - 0x10, 0x20)),
        );
        assert_eq!(res, Err("alloc_range overflow"));
    }

    #[test]
    fn add_reserved_region_dynamic_align_up_overflow_returns_none() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions {
                address: usize::MAX - 0xF,
                size: 0x8,
            })
            .unwrap();

        let res = allocator.add_reserved_region_dynamic(0x8, Some(0x20), None);
        assert_eq!(res, Ok(None));
        assert_eq!(allocator.reserved_region_size, 0);
    }

    #[test]
    fn add_region_rejects_end_overflow() {
        let mut allocator = MemoryBlock::init();
        let res = allocator.add_region(&MemoryRegions::from_parts(usize::MAX - 0x10, 0x20));
        assert_eq!(res, Err("region end overflow"));
    }

    #[test]
    fn check_regions_returns_err_on_corrupt_reserved_region_end_overflow() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions::from_parts(0x1000, 0x1000))
            .unwrap();
        allocator.reserved_regions[0] = MemoryRegions::from_parts(usize::MAX - 0x10, 0x20);
        allocator.reserved_region_size = 1;

        let res = allocator.check_regions();
        assert_eq!(res, Err("region end overflow"));
    }

    #[test]
    fn try_deallocate_region_err_on_dealloc_end_overflow_no_mutation() {
        let mut allocator = MemoryBlock::init();
        allocator
            .add_region(&MemoryRegions::from_parts(0x1000, 0x1000))
            .unwrap();
        allocator.check_regions().unwrap();

        let _alloc_layout = Layout::from_size_align(0x100, 0x10).unwrap();
        let alloc_ptr = allocator
            .allocate_region(0x100, 0x10)
            .expect("allocation should succeed");

        let pre_region_size = allocator.region_size;
        let pre_reserved_size = allocator.reserved_region_size;

        let res = allocator.try_deallocate_region(
            usize::MAX - 0x8,
            Layout::from_size_align(0x20, 1).unwrap(),
            true,
        );
        assert_eq!(res, Err("dealloc end overflow"));
        assert_eq!(allocator.region_size, pre_region_size);
        assert_eq!(allocator.reserved_region_size, pre_reserved_size);
        assert_eq!(
            allocator.reserved_regions[0],
            MemoryRegions::from_parts(alloc_ptr, 0x100)
        );
    }

    #[test]
    fn add_and_merge_region_err_on_preexisting_region_end_overflow() {
        let mut allocator = MemoryBlock::init();
        allocator.regions[0] = MemoryRegions::from_parts(usize::MAX - 0x10, 0x20);
        allocator.region_size = 1;

        let res = allocator.add_region(&MemoryRegions::from_parts(0x1000, 0x1000));
        assert_eq!(res, Err("region end overflow"));
    }
}

#[cfg(test)]
mod stateful_fuzz;
