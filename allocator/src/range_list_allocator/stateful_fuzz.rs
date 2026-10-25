//! Reproducible stateful allocator fuzz tests, without third-party crates.

use super::{MemoryBlock, MemoryRegions, RegionData};
use core::mem::size_of;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::vec::Vec;

struct Arena {
    base: usize,
    layout: Layout,
}

impl Arena {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 4096).unwrap();
        // SAFETY: The layout is valid and nonzero. The system allocator
        // provides writable memory until the Arena is dropped.
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        Self {
            base: ptr as usize,
            layout,
        }
    }

    fn end(&self) -> usize {
        self.base + self.layout.size()
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: This is the original live allocation with its exact layout.
        // The MemoryBlock using this backing is dropped before the Arena.
        unsafe { dealloc(self.base as *mut u8, self.layout) };
    }
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[derive(Clone, Copy)]
struct Live {
    address: usize,
    layout: Layout,
    pattern: u8,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    free: Vec<MemoryRegions>,
    reserved: Vec<MemoryRegions>,
    capacities: (u32, u32),
    credits: u32,
}

fn snapshot(block: &MemoryBlock) -> Snapshot {
    Snapshot {
        free: block.regions.to_vec(),
        reserved: block.reserved_regions.to_vec(),
        capacities: (block.region_capacity, block.reserved_region_capacity),
        credits: block.deallocation_credits,
    }
}

fn validate(block: &MemoryBlock, arena: &Arena, live: &[Live], seed: u64, step: usize) {
    let context = || format!("seed={seed:#x}, step={step}");
    assert_eq!(
        block.deallocation_credits as usize,
        live.len(),
        "{}: allocation credits lost or duplicated",
        context()
    );
    assert!(
        block.region_size
            .checked_add(block.deallocation_credits)
            .is_some_and(|n| n <= block.region_capacity),
        "{}: free metadata headroom exhausted",
        context()
    );
    assert!(
        block.reserved_region_size
            .checked_add(block.deallocation_credits)
            .is_some_and(|n| n <= block.reserved_region_capacity),
        "{}: reserved metadata headroom exhausted",
        context()
    );

    let free = &block.regions[..block.region_size as usize];
    let reserved = &block.reserved_regions[..block.reserved_region_size as usize];
    let mut partition = Vec::with_capacity(free.len() + reserved.len());
    for region in free.iter().chain(reserved.iter()) {
        let end = region.end_checked().unwrap();
        assert!(
            region.size > 0 && region.address >= arena.base && end <= arena.end(),
            "{}: invalid memory interval",
            context()
        );
        partition.push((region.address, end));
    }
    partition.sort_unstable_by_key(|r| r.0);
    let mut cursor = arena.base;
    for (start, end) in partition {
        assert_eq!(
            start,
            cursor,
            "{}: free and reserved intervals overlap or leave a gap",
            context()
        );
        cursor = end;
    }
    assert_eq!(cursor, arena.end(), "{}: missing arena tail", context());

    let mut used = Vec::with_capacity(live.len());
    for entry in live {
        let end = entry.address.checked_add(entry.layout.size()).unwrap();
        assert!(
            entry.address >= arena.base && end <= arena.end(),
            "{}: allocation outside the arena",
            context()
        );
        assert_eq!(
            entry.address % entry.layout.align(),
            0,
            "{}: misaligned allocation",
            context()
        );
        assert!(
            reserved
                .iter()
                .any(|r| r.address <= entry.address && r.end_checked().unwrap() >= end),
            "{}: live allocation is not reserved",
            context()
        );
        used.push((entry.address, end));

        // SAFETY: This live block was allocated within the writable Arena and
        // has not been released. Its original byte length is still valid.
        let bytes =
            unsafe { core::slice::from_raw_parts(entry.address as *const u8, entry.layout.size()) };
        assert!(
            bytes.iter().all(|&b| b == entry.pattern),
            "{}: live allocation contents corrupted at {:#x}",
            context(),
            entry.address
        );
    }
    used.sort_unstable_by_key(|r| r.0);
    for pair in used.windows(2) {
        assert!(
            pair[0].1 <= pair[1].0,
            "{}: overlapping live allocations",
            context()
        );
    }

    // Metadata arrays are backed by permanent reserved memory after growth.
    for storage in [&block.regions.0, &block.reserved_regions.0] {
        if let RegionData::Heap(entries) = storage {
            let start = entries.as_ptr() as usize;
            let end = start.checked_add(entries.len() * size_of::<MemoryRegions>()).unwrap();
            assert!(
                reserved
                    .iter()
                    .any(|r| r.address <= start && r.end_checked().unwrap() >= end),
                "{}: active metadata array was not reserved",
                context()
            );
        }
    }
}

fn seed_from_environment(value: &str) -> u64 {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).expect("invalid ALLOCATOR_FUZZ_SEED")
    } else {
        value.parse().expect("invalid ALLOCATOR_FUZZ_SEED")
    }
}

#[test]
fn randomized_allocate_free_state_transitions() {
    const SEEDS: [u64; 4] = [
        0x19a4_d7e2_87bf_6431,
        0x775e_d2c3_1327_9a40,
        0xc50b_783d_ffa2_1087,
        0xfeca_b357_1130_945c,
    ];
    let seeds = std::env::var("ALLOCATOR_FUZZ_SEED")
        .map(|value| std::vec![seed_from_environment(&value)])
        .unwrap_or_else(|_| SEEDS.to_vec());
    let steps = std::env::var("ALLOCATOR_FUZZ_STEPS")
        .map(|value| value.parse::<usize>().expect("invalid ALLOCATOR_FUZZ_STEPS"))
        .unwrap_or(2_000);

    for seed in seeds {
        // Metadata growth writes to the managed area, so fake addresses
        // are not suitable test fixtures.
        let arena = Arena::new(if seed & 1 == 0 { 0x1_0000 } else { 0x8_0000 });
        let mut block = MemoryBlock::init();
        block
            .add_region(&MemoryRegions::from_parts(arena.base, arena.layout.size()))
            .unwrap();
        block.check_regions().unwrap();
        let mut rng = Rng::new(seed);
        let mut live = Vec::<Live>::new();
        std::eprintln!("allocator fuzz seed={seed:#x}, steps={steps}");

        for step in 0..steps {
            if live.is_empty() || (live.len() < 400 && rng.next() % 100 < 63) {
                let alignment = 1usize << (rng.next() % 10);
                let size = match rng.next() % 16 {
                    0 => 4096,
                    1 | 2 => 1024,
                    _ => 1 + (rng.next() % 256) as usize,
                };
                let layout = Layout::from_size_align(size, alignment).unwrap();
                let first_fit =
                    block.regions[..block.region_size as usize]
                        .iter()
                        .find_map(|r| {
                            let address = r.address.checked_next_multiple_of(alignment)?;
                            let end = address.checked_add(size)?;
                            (end <= r.end_checked().ok()?).then_some(address)
                        });
                let old_capacities = (block.region_capacity, block.reserved_region_capacity);
                let before = snapshot(&block);
                match block.allocate_region(size, alignment) {
                    Some(address) => {
                        let end = address.checked_add(size).expect("allocation end overflow");
                        assert!(
                            address >= arena.base && end <= arena.end(),
                            "seed={seed:#x}, step={step}: allocation outside test backing"
                        );
                        assert_eq!(
                            address % alignment,
                            0,
                            "seed={seed:#x}, step={step}: invalid alignment"
                        );
                        for entry in &live {
                            let live_end = entry.address + entry.layout.size();
                            assert!(
                                end <= entry.address || live_end <= address,
                                "seed={seed:#x}, step={step}: duplicate allocation"
                            );
                        }
                        for storage in [&block.regions.0, &block.reserved_regions.0] {
                            if let RegionData::Heap(entries) = storage {
                                let start = entries.as_ptr() as usize;
                                let metadata_end = start + entries.len() * size_of::<MemoryRegions>();
                                assert!(
                                    end <= start || metadata_end <= address,
                                    "seed={seed:#x}, step={step}: allocation overlaps metadata"
                                );
                            }
                        }
                        if old_capacities
                            == (block.region_capacity, block.reserved_region_capacity)
                        {
                            assert_eq!(
                                Some(address),
                                first_fit,
                                "seed={seed:#x}, step={step}: not first-fit"
                            );
                        }
                        let pattern = rng.next() as u8;
                        // SAFETY: The returned allocation contains size writable
                        // bytes in the Arena, and remains live until release.
                        unsafe { core::ptr::write_bytes(address as *mut u8, pattern, size) };
                        live.push(Live {
                            address,
                            layout,
                            pattern,
                        });
                    }
                    None => {
                        assert_eq!(
                            snapshot(&block),
                            before,
                            "seed={seed:#x}, step={step}: failed allocation changed state"
                        );
                    }
                }
            } else {
                let index = (rng.next() as usize) % live.len();
                let entry = live.swap_remove(index);
                block.deallocate_region(entry.address, entry.layout);
            }

            // An invalid external release must leave both metadata arrays
            // and all outstanding allocation credits unchanged.
            if rng.next() % 97 == 0 {
                let before = snapshot(&block);
                let invalid = arena.end() + 0x1000;
                assert!(
                    block
                        .try_deallocate_region(
                            invalid,
                            Layout::from_size_align(16, 1).unwrap(),
                            true,
                        )
                        .is_err(),
                    "seed={seed:#x}, step={step}: accepted an invalid release"
                );
                assert_eq!(snapshot(&block), before);
            }
            if step % 8 == 0 {
                validate(&block, &arena, &live, seed, step);
            }
        }

        validate(&block, &arena, &live, seed, steps);
        while !live.is_empty() {
            let index = (rng.next() as usize) % live.len();
            let entry = live.swap_remove(index);
            block.deallocate_region(entry.address, entry.layout);
        }
        validate(&block, &arena, &live, seed, steps + 1);
        assert_eq!(block.deallocation_credits, 0);
    }
}
