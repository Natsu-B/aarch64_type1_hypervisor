#![no_std]
#![recursion_limit = "1024"]
#![feature(generic_const_exprs)]

extern crate alloc;

mod registers;
pub mod stage1;
pub mod stage2;
pub use stage1::*;
pub use stage2::*;

const PAGE_TABLE_SIZE: usize = 1usize << 12; // 4KiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingErr {
    Corrupted,
    UnalignedPage,
    ZeroSizedPage,
    UnsupportedPARange,
    OutOfMemory,
}
