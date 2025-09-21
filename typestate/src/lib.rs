#![no_std]
//! MMIO typestate wrapper.
//!
//! This crate provides small wrapper types around MMIO registers that encode
//! readable / writable capabilities at the type level (typestate).
//!
//! All reads and writes are performed with volatile operations to prevent the
//! compiler from eliding or reordering access to memory-mapped registers.
//!
//! # Typestates
//! - [`ReadOnly<T>`]: readable, no write API is exposed. Reads **may** have side effects.
//! - [`ReadPure<T>`]: readable **without side effects** (safe to poll). Still uses volatile reads.
//! - [`WriteOnly<T>`]: writable, no read API is exposed.
//! - [`ReadWrite<T>`]: both readable and writable.
//! - [`Le<T>`] / [`Be<T>`]: endianness-aware wrappers that convert to host endianness on read/write.
//! - [`Unaligned<T>`]: unaligned access helper that performs byte-wise volatile I/O.
//!
//! # Safety
//! These wrappers do not validate that the underlying address actually maps to
//! device registers. It is **your** responsibility to place these wrappers at
//! the correct, valid MMIO address and to follow the device's access rules.

mod endianness;
mod read_write;
mod unaligned;

pub use endianness::Be;
pub use endianness::Le;
pub use read_write::ReadOnly;
pub use read_write::ReadPure;
pub use read_write::ReadWrite;
pub use read_write::Readable;
pub use read_write::Writable;
pub use read_write::WriteOnly;
pub use unaligned::Unaligned;

pub unsafe trait RawReg:
    Copy + core::ops::BitOr + core::ops::BitAnd + core::ops::Not + core::ops::BitXor
{
    type Raw;
    fn to_raw(self) -> Self::Raw;
    fn from_raw(raw: Self::Raw) -> Self;
    fn to_le(self) -> Self;
    fn from_le(self) -> Self;
    fn to_be(self) -> Self;
    fn from_be(self) -> Self;
}

macro_rules! impl_raw { ($($t:ty),* $(,)?) => {$(
    unsafe impl RawReg for $t {
        type Raw = $t;
        #[inline] fn to_raw(self) -> Self::Raw {self}
        #[inline] fn from_raw(raw: Self::Raw) -> Self {raw}
        #[inline] fn to_le(self)->Self{Self::to_le(self)}
        #[inline] fn from_le(self)->Self{Self::from_le(self)}
        #[inline] fn to_be(self)->Self{Self::to_be(self)}
        #[inline] fn from_be(self)->Self{Self::from_be(self)}
    }
)*}}
impl_raw!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);
