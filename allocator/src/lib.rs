//! Memory allocator for bare-metal environments.
//!
//! This crate provides a two-tier allocator: a buddy allocator for small allocations
//! and a range-list allocator for large/aligned allocations.

#![cfg_attr(not(any(test, doctest)), no_std)]
#![feature(generic_const_exprs)]
#![cfg_attr(not(test), feature(alloc_error_handler))]

extern crate alloc;
mod aligned_box;
mod buddy_allocator;
mod range_list_allocator;
pub use aligned_box::AlignedSliceBox;
use alloc::vec::Vec;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::cell::OnceCell;
use core::cmp::max;
use core::ptr::null_mut;

use mutex::RawSpinLock;

use crate::buddy_allocator::BuddyAllocator;
use crate::range_list_allocator::MemoryBlock;
use crate::range_list_allocator::MemoryRegions;

/// Debug print macro (no-op in release builds).
#[cfg(all(not(feature = "debug-assertions"), not(test)))]
#[macro_export]
macro_rules! pr_debug {
    ($($arg:tt)*) => {};
}

#[cfg(test)]
#[macro_export]
macro_rules! pr_debug {
    ($($arg:tt)*) => (std::println!("[info] (alloc) {} ({}:{})", format_args!($($arg)*), file!(), line!()));
}

#[cfg(all(feature = "debug-assertions", not(test)))]
#[macro_export]
macro_rules! pr_debug {
    ($($arg:tt)*) => {};
}

/// Minimum allocatable block size in bytes.
pub const MINIMUM_ALLOCATABLE_BYTES: usize = range_list_allocator::MINIMUM_ALLOCATABLE_BYTES;

/// Computes the number of buddy levels needed for the given maximum block size.
#[must_use]
pub const fn levels_value(max: usize) -> usize {
    max.trailing_zeros() as usize - MINIMUM_ALLOCATABLE_BYTES.trailing_zeros() as usize + 1
}

/// Macro to compute buddy levels at compile time.
#[macro_export]
macro_rules! levels {
    ($max:expr) => {
        $crate::levels_value($max as usize)
    };
}

/// Number of `MAX_ALLOCATABLE_BYTES` blocks the buddy allocator takes from the
/// range-list allocator per refill.
const BUDDY_REFILL_BLOCKS: usize = 16;

/// Default allocator with 4096-byte maximum block size.
pub type DefaultAllocator = MemoryAllocator<4096, { levels!(4096) }>;

/// A two-tier memory allocator combining buddy and range-list algorithms.
pub struct MemoryAllocator<const MAX_ALLOCATABLE_BYTES: usize, const LEVELS: usize> {
    range_list_allocator: RawSpinLock<OnceCell<MemoryBlock>>,
    buddy_allocator: RawSpinLock<OnceCell<BuddyAllocator<MAX_ALLOCATABLE_BYTES, LEVELS>>>,
}

unsafe impl<const MAX_ALLOCATABLE_BYTES: usize, const LEVELS: usize> Sync
    for MemoryAllocator<MAX_ALLOCATABLE_BYTES, LEVELS>
{
}

impl<const MAX_ALLOCATABLE_BYTES: usize, const LEVELS: usize> Default
    for MemoryAllocator<MAX_ALLOCATABLE_BYTES, LEVELS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_ALLOCATABLE_BYTES: usize, const LEVELS: usize>
    MemoryAllocator<MAX_ALLOCATABLE_BYTES, LEVELS>
{
    /// Creates a new uninitialized allocator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            range_list_allocator: RawSpinLock::new(OnceCell::new()),
            buddy_allocator: RawSpinLock::new(OnceCell::new()),
        }
    }

    /// Initializes the allocator.
    ///
    /// # Panics
    /// Panics if initialization fails unexpectedly (should not happen with correct usage).
    pub fn init(&'static self) {
        // Initialize the range list allocator.
        let range_list_allocator_guard = self.range_list_allocator.lock();
        if range_list_allocator_guard.get().is_none() {
            let range_list_allocator = range_list_allocator::MemoryBlock::init();
            // NOTE: Memory regions should be added here before initializing the buddy allocator.
            range_list_allocator_guard
                .set(range_list_allocator)
                .unwrap();
        }

        // Initialize the buddy allocator.
        let buddy_allocator_guard = self.buddy_allocator.lock();
        if buddy_allocator_guard.get().is_none() {
            let new_buddy_allocator = BuddyAllocator::<MAX_ALLOCATABLE_BYTES, LEVELS>::new();
            buddy_allocator_guard.set(new_buddy_allocator).unwrap();
        }
    }

    /// Allocates backing for the buddy allocator from the range-list allocator.
    ///
    /// Buddy pages are never returned to the range list, so refilling several
    /// pages at once keeps them physically together and spends one range-list
    /// allocation (and its release credit) per chunk instead of per page.
    /// Falls back to a single page when no chunk-sized range is available.
    /// Returns the chunk address and size.
    pub fn alloc_for_buddy_allocator(&self) -> Option<(usize, usize)> {
        let mut range_list_allocator_guard = self.range_list_allocator.lock();
        let range_list_allocator = range_list_allocator_guard.get_mut()?;
        [BUDDY_REFILL_BLOCKS, 1].into_iter().find_map(|blocks| {
            let size = MAX_ALLOCATABLE_BYTES.checked_mul(blocks)?;
            range_list_allocator
                .allocate_region(size, MAX_ALLOCATABLE_BYTES)
                .map(|address| (address, size))
        })
    }

    /// Rounds a range-list request to buddy-page granularity.
    ///
    /// Keeping every range-list allocation a multiple of `MAX_ALLOCATABLE_BYTES`
    /// in size and alignment keeps free-list boundaries on that granule, so the
    /// free list never holds sub-page fragments that neither a buddy refill nor
    /// a range-list request could use. `alloc` and `dealloc` derive the same
    /// value from the same layout.
    fn range_request(size: usize, align: usize) -> Option<(usize, usize)> {
        let size = size.checked_next_multiple_of(MAX_ALLOCATABLE_BYTES)?;
        let align = max(align, MAX_ALLOCATABLE_BYTES);
        Layout::from_size_align(size, align).ok()?;
        Some((size, align))
    }
}

unsafe impl<const MAX_ALLOCATABLE_BYTES: usize, const LEVELS: usize> GlobalAlloc
    for MemoryAllocator<MAX_ALLOCATABLE_BYTES, LEVELS>
{
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if max(layout.size(), layout.align()) > MAX_ALLOCATABLE_BYTES {
            let mut range_list_allocator_guard = self.range_list_allocator.lock();
            if let Some((size, align)) = Self::range_request(layout.size(), layout.align())
                && let Some(range_list_allocator) = range_list_allocator_guard.get_mut()
                && let Some(heap_mem) = range_list_allocator.allocate_region(size, align)
            {
                return heap_mem as *mut u8;
            }
        } else {
            let mut buddy_allocator_guard = self.buddy_allocator.lock();
            let alloc_for_buddy = || self.alloc_for_buddy_allocator();
            if let Some(buddy_allocator) = buddy_allocator_guard.get_mut()
                && let Ok(heap_mem) = buddy_allocator.alloc(layout, Some(&alloc_for_buddy))
            {
                return heap_mem as *mut u8;
            }
        }
        null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        if max(layout.size(), layout.align()) > MAX_ALLOCATABLE_BYTES {
            let result = {
                let mut range_list_allocator_guard = self.range_list_allocator.lock();
                if let Some((size, align)) = Self::range_request(layout.size(), layout.align())
                    && let Some(range_list_allocator) = range_list_allocator_guard.get_mut()
                {
                    // Successful range allocations reserve metadata for both a
                    // free-list insertion and a reserved-list split on release.
                    // This path therefore never needs to allocate metadata.
                    // SAFETY: range_request validated this size/alignment pair.
                    let layout = unsafe { Layout::from_size_align_unchecked(size, align) };
                    range_list_allocator.try_deallocate_region(ptr as usize, layout, true)
                } else {
                    Ok(())
                }
            };
            // Panic only after the lock is released so the panic path can
            // still use the allocator.
            if let Err(error) = result {
                panic!("invalid range-list deallocation: {error}");
            }
        } else {
            let mut buddy_allocator_guard = self.buddy_allocator.lock();
            if let Some(buddy_allocator) = buddy_allocator_guard.get_mut() {
                buddy_allocator.dealloc(ptr as usize, layout);
            }
        }
    }
}

impl<const MAX_ALLOCATABLE_BYTES: usize, const LEVELS: usize>
    MemoryAllocator<MAX_ALLOCATABLE_BYTES, LEVELS>
{
    /// Add an available memory region before finalization.
    ///
    /// # Errors
    /// Returns `Err` if called after finalization or if allocator is not initialized.
    pub fn add_available_region(&self, address: usize, size: usize) -> Result<(), &'static str> {
        let mut guard = self.range_list_allocator.lock();
        let block = guard.get_mut().ok_or("allocator not initialized")?;
        if block.is_finalized() {
            return Err("allocator already finalized");
        }
        block.add_region(&MemoryRegions::from_parts(address, size))
    }

    /// Add a reserved memory region before finalization.
    ///
    /// # Errors
    /// Returns `Err` if called after finalization or if allocator is not initialized.
    pub fn add_reserved_region(&self, address: usize, size: usize) -> Result<(), &'static str> {
        let mut guard = self.range_list_allocator.lock();
        let block = guard.get_mut().ok_or("allocator not initialized")?;
        if block.is_finalized() {
            return Err("allocator already finalized");
        }
        block.add_reserved_region(&MemoryRegions::from_parts(address, size))
    }

    /// Allocates a reserved region dynamically.
    ///
    /// # Errors
    /// Returns `Err` if the allocator is not initialized.
    pub fn allocate_dynamic_reserved_region(
        &self,
        size: usize,
        align: Option<usize>,
        alloc_range: Option<(usize, usize)>,
    ) -> Result<Option<usize>, &'static str> {
        let mut guard = self.range_list_allocator.lock();
        let block = guard.get_mut().ok_or("allocator not initialized")?;
        block.add_reserved_region_dynamic(size, align, alloc_range)
    }

    /// Finalize the allocator by subtracting reserved regions and enabling allocation.
    ///
    /// # Errors
    /// Returns `Err` if allocator is not initialized.
    /// Safe to call multiple times; after the first success, it’s a no-op.
    pub fn finalize(&self) -> Result<(), &'static str> {
        let mut guard = self.range_list_allocator.lock();
        let block = guard.get_mut().ok_or("allocator not initialized")?;
        if block.is_finalized() {
            return Ok(());
        }
        // Do not force-align free regions; just reconcile regions.
        block.check_regions()
    }

    /// Allocates memory with specified size and alignment.
    ///
    /// # Errors
    /// Returns `Err` if allocator is not initialized, not finalized, or allocation fails.
    pub fn allocate_with_size_and_align(
        &self,
        size: usize,
        align: usize,
    ) -> Result<usize, &'static str> {
        let mut guard = self.range_list_allocator.lock();
        let block = guard.get_mut().ok_or("allocator not initialized")?;
        if !block.is_finalized() {
            return Err("allocator not finalized");
        }

        let (size, align) = Self::range_request(size, align).ok_or("invalid size or alignment")?;
        block
            .allocate_region(size, align)
            .ok_or("failed to allocate")
    }

    /// Trims an already-finalized allocator before boot handoff.
    ///
    /// This function should be called right before transferring execution
    /// to another kernel or ELF payload (e.g., Linux), after `finalize()`
    /// has succeeded.
    ///
    /// The returned `Vec` is allocated while the range-list lock is released,
    /// so trimming never re-enters the global allocator under that lock.
    ///
    /// # Errors
    /// Returns `Err` if allocator is not initialized or not finalized.
    pub fn trim_for_boot(&self, reserve_bytes: usize) -> Result<Vec<(usize, usize)>, &'static str> {
        let mut required = 0;
        loop {
            // Allocating the buffer can add reserved entries (e.g. a buddy refill),
            // so re-check the requirement under the lock and retry if it grew.
            let mut reserved = Vec::with_capacity(required);
            let mut guard = self.range_list_allocator.lock();
            let block = guard.get_mut().ok_or("allocator not initialized")?;
            if !block.is_finalized() {
                return Err("allocator not finalized");
            }
            let needed = block.trim_for_boot_capacity();
            if reserved.capacity() >= needed {
                let (reserve_bytes, align) =
                    Self::range_request(reserve_bytes, 1).ok_or("invalid reserve size")?;
                block.trim_for_boot(reserve_bytes, align, &mut reserved)?;
                return Ok(reserved);
            }
            // Leave slack for entries added by the next buffer allocation.
            required = needed + 4;
        }
    }

    /// Iterates over each free memory region.
    ///
    /// # Errors
    /// Returns `Err` if allocator is not initialized.
    pub fn for_each_free_region<F: FnMut(usize, usize)>(&self, f: F) -> Result<(), &'static str> {
        let guard = self.range_list_allocator.lock();
        let block = guard.get().ok_or("allocator not initialized")?;
        block.for_each_free_region(f);
        Ok(())
    }

    /// Iterates over each reserved memory region.
    ///
    /// # Errors
    /// Returns `Err` if allocator is not initialized.
    pub fn for_each_reserved_region<F: FnMut(usize, usize)>(
        &self,
        f: F,
    ) -> Result<(), &'static str> {
        let guard = self.range_list_allocator.lock();
        let block = guard.get().ok_or("allocator not initialized")?;
        block.for_each_reserved_region(f);
        Ok(())
    }
}

#[cfg(all(not(test), not(feature = "no-alloc-error-handler")))]
#[alloc_error_handler]
fn panic(_layout: Layout) -> ! {
    pr_debug!("allocator panicked!!: {:?}", _layout);
    loop {}
}

/// Macro to define a global allocator with the specified page size.
#[macro_export]
macro_rules! define_global_allocator {
    ($name:ident, $page_size:expr) => {
        #[global_allocator]
        static $name: $crate::MemoryAllocator<{ $page_size }, { $crate::levels!($page_size) }> =
            $crate::MemoryAllocator::new();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[global_allocator]
    static TEST_ALLOCATOR: std::alloc::System = std::alloc::System;

    static GLOBAL_ALLOCATOR: MemoryAllocator<4096, { levels!(4096) }> = MemoryAllocator::new();

    #[test]
    fn allocate_4k_page_after_finalize_with_unaligned_reserved_region() {
        use core::alloc::Layout;

        const PRIMARY_SIZE: usize = 0x80_000;
        const SECONDARY_SIZE: usize = 0x20_000;

        #[repr(align(4096))]
        struct PrimaryHeap([u8; PRIMARY_SIZE]);
        #[repr(align(4096))]
        struct SecondaryHeap([u8; SECONDARY_SIZE]);

        let mut primary = PrimaryHeap([0; PRIMARY_SIZE]);
        let mut secondary = SecondaryHeap([0; SECONDARY_SIZE]);

        let primary_base = primary.0.as_mut_ptr() as usize;
        let secondary_base = secondary.0.as_mut_ptr() as usize;

        GLOBAL_ALLOCATOR.init();
        GLOBAL_ALLOCATOR
            .add_available_region(primary_base, PRIMARY_SIZE)
            .unwrap();
        GLOBAL_ALLOCATOR
            .add_available_region(secondary_base, SECONDARY_SIZE)
            .unwrap();

        GLOBAL_ALLOCATOR
            .add_reserved_region(primary_base, 0x2_000)
            .unwrap();
        let dynamic_addr = GLOBAL_ALLOCATOR
            .allocate_dynamic_reserved_region(0x8_000, None, Some((primary_base, 0x20_000)))
            .unwrap()
            .expect("dynamic reserved region allocation failed");
        assert_eq!(
            dynamic_addr & 0xFFF,
            0,
            "dynamic reserved region is not 4KiB aligned"
        );
        GLOBAL_ALLOCATOR
            .add_reserved_region(primary_base + 0x3C_000, 0xA0)
            .unwrap();
        GLOBAL_ALLOCATOR
            .add_reserved_region(primary_base + 0x2_000, 0x12_000)
            .unwrap();
        GLOBAL_ALLOCATOR
            .add_reserved_region(primary_base + 0x20_000, 0x329)
            .unwrap();

        GLOBAL_ALLOCATOR.finalize().unwrap();

        let page = GLOBAL_ALLOCATOR
            .allocate_with_size_and_align(0x1_000, 0x1_000)
            .expect("allocate_with_size_and_align failed");
        assert_eq!(page & 0xFFF, 0, "range allocator returned unaligned page");

        let layout = Layout::from_size_align(0x1_000, 0x1_000).unwrap();
        let mut allocated = alloc::vec::Vec::new();
        for _ in 0..8 {
            let ptr = unsafe { GLOBAL_ALLOCATOR.alloc(layout) };
            assert!(
                !ptr.is_null(),
                "GlobalAlloc::alloc failed to hand out a 4KiB page"
            );
            assert_eq!(
                ptr as usize & 0xFFF,
                0,
                "GlobalAlloc handed out a non-4KiB-aligned page"
            );
            allocated.push(ptr);
        }

        for ptr in allocated {
            unsafe {
                GLOBAL_ALLOCATOR.dealloc(ptr, layout);
            }
        }
    }

    #[test]
    fn trim_for_boot_reports_live_allocations_and_keeps_reserve_free() {
        const HEAP_SIZE: usize = 0x3_000;

        #[repr(align(4096))]
        struct Heap([u8; HEAP_SIZE]);

        static TRIM_ALLOCATOR: MemoryAllocator<4096, { levels!(4096) }> = MemoryAllocator::new();

        let mut heap = Heap([0; HEAP_SIZE]);
        let heap_base = heap.0.as_mut_ptr() as usize;

        TRIM_ALLOCATOR.init();
        TRIM_ALLOCATOR
            .add_available_region(heap_base, HEAP_SIZE)
            .unwrap();
        TRIM_ALLOCATOR.finalize().unwrap();

        let page = TRIM_ALLOCATOR
            .allocate_with_size_and_align(0x1_000, 0x1_000)
            .unwrap();

        let reserved = TRIM_ALLOCATOR.trim_for_boot(0x1_000).unwrap();
        // The reserve chunk is still allocated when the snapshot is taken.
        assert_eq!(reserved, [(page, 0x2_000)]);

        let mut free = Vec::new();
        TRIM_ALLOCATOR
            .for_each_free_region(|address, size| free.push((address, size)))
            .unwrap();
        assert_eq!(free, [(page + 0x1_000, 0x1_000)]);
    }

    #[test]
    fn range_path_keeps_free_list_page_granular() {
        const HEAP_SIZE: usize = 0x3_000;

        #[repr(align(4096))]
        struct Heap([u8; HEAP_SIZE]);

        static GRANULE_ALLOCATOR: MemoryAllocator<4096, { levels!(4096) }> = MemoryAllocator::new();

        let mut heap = Heap([0; HEAP_SIZE]);
        let heap_base = heap.0.as_mut_ptr() as usize;

        GRANULE_ALLOCATOR.init();
        GRANULE_ALLOCATOR
            .add_available_region(heap_base, HEAP_SIZE)
            .unwrap();
        GRANULE_ALLOCATOR.finalize().unwrap();

        // Just above the buddy limit: an exact-size allocation would leave a
        // 0xFFF-byte hole and the following page could not be handed out.
        let large = Layout::from_size_align(0x1_001, 8).unwrap();
        let page = Layout::from_size_align(0x1_000, 0x1_000).unwrap();
        let large_ptr = unsafe { GRANULE_ALLOCATOR.alloc(large) };
        let page_ptr = unsafe { GRANULE_ALLOCATOR.alloc(page) };
        assert_eq!(large_ptr as usize, heap_base);
        assert_eq!(page_ptr as usize, heap_base + 0x2_000);

        let mut free_regions = 0;
        GRANULE_ALLOCATOR
            .for_each_free_region(|_, _| free_regions += 1)
            .unwrap();
        assert_eq!(free_regions, 0);

        unsafe { GRANULE_ALLOCATOR.dealloc(large_ptr, large) };
        let mut free = Vec::new();
        GRANULE_ALLOCATOR
            .for_each_free_region(|address, size| free.push((address, size)))
            .unwrap();
        assert_eq!(free, [(heap_base, 0x2_000)]);
    }

    #[test]
    fn buddy_refills_in_chunks_and_falls_back_to_single_pages() {
        const PAGE: usize = 0x1_000;
        const CHUNK: usize = PAGE * BUDDY_REFILL_BLOCKS;

        static REFILL_ALLOCATOR: MemoryAllocator<PAGE, { levels!(PAGE) }> = MemoryAllocator::new();

        fn free_bytes() -> usize {
            let mut bytes = 0;
            REFILL_ALLOCATOR
                .for_each_free_region(|_, size| bytes += size)
                .unwrap();
            bytes
        }

        let heap_layout = Layout::from_size_align(CHUNK + PAGE, PAGE).unwrap();
        // SAFETY: heap_layout is nonzero; the system allocator owns this
        // backing independently of the allocator under test.
        let heap = unsafe { std::alloc::alloc_zeroed(heap_layout) };
        assert!(!heap.is_null());

        REFILL_ALLOCATOR.init();
        REFILL_ALLOCATOR
            .add_available_region(heap as usize, heap_layout.size())
            .unwrap();
        REFILL_ALLOCATOR.finalize().unwrap();

        let page = Layout::from_size_align(PAGE, PAGE).unwrap();
        let mut pages = Vec::new();
        for _ in 0..BUDDY_REFILL_BLOCKS {
            // SAFETY: the allocator manages live writable backing; page is valid.
            let ptr = unsafe { REFILL_ALLOCATOR.alloc(page) };
            assert!(!ptr.is_null());
            pages.push(ptr);
        }
        // One chunk served every page so far.
        assert_eq!(free_bytes(), PAGE);

        // No chunk-sized range remains, so the refill takes a single page.
        // SAFETY: as above.
        let ptr = unsafe { REFILL_ALLOCATOR.alloc(page) };
        assert!(!ptr.is_null());
        pages.push(ptr);
        assert_eq!(free_bytes(), 0);
        // SAFETY: as above.
        assert!(unsafe { REFILL_ALLOCATOR.alloc(page) }.is_null());

        for ptr in pages {
            // SAFETY: each pointer came from this allocator with this layout.
            unsafe { REFILL_ALLOCATOR.dealloc(ptr, page) };
        }
        // Clear the static's metadata references before freeing the backing.
        REFILL_ALLOCATOR.buddy_allocator.lock().take();
        REFILL_ALLOCATOR.range_list_allocator.lock().take();
        // SAFETY: heap was allocated above with heap_layout.
        unsafe { std::alloc::dealloc(heap, heap_layout) };
    }
}
