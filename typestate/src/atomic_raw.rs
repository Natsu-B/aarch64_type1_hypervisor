use core::sync::atomic::Ordering;

pub trait AtomicRaw: Copy + 'static {
    type Atomic;

    /// # Safety
    /// - `ptr` must be aligned to `align_of::<Self::Atomic>()`.
    /// - `ptr` must be valid for reads/writes for the returned lifetime.
    /// - Do not mix conflicting atomic and non-atomic accesses without synchronization.
    unsafe fn from_ptr<'a>(ptr: *mut Self) -> &'a Self::Atomic;

    fn load(a: &Self::Atomic, order: Ordering) -> Self;

    fn store(a: &Self::Atomic, v: Self, order: Ordering);

    fn swap(a: &Self::Atomic, v: Self, order: Ordering) -> Self;

    fn compare_exchange(
        a: &Self::Atomic,
        current: Self,
        new: Self,
        success: Ordering,
        failure: Ordering,
    ) -> Result<Self, Self>;

    fn compare_exchange_weak(
        a: &Self::Atomic,
        current: Self,
        new: Self,
        success: Ordering,
        failure: Ordering,
    ) -> Result<Self, Self>;

    fn fetch_or(a: &Self::Atomic, v: Self, order: Ordering) -> Self;

    fn fetch_and(a: &Self::Atomic, v: Self, order: Ordering) -> Self;

    fn fetch_xor(a: &Self::Atomic, v: Self, order: Ordering) -> Self;
}

macro_rules! impl_atomic_raw {
    ($raw:ty, $atomic:ty) => {
        impl AtomicRaw for $raw {
            type Atomic = $atomic;

            #[inline(always)]
            unsafe fn from_ptr<'a>(ptr: *mut Self) -> &'a Self::Atomic {
                // SAFETY: caller upholds the Atomic*::from_ptr contract.
                unsafe { <$atomic>::from_ptr(ptr) }
            }

            #[inline(always)]
            fn load(a: &Self::Atomic, order: Ordering) -> Self {
                a.load(order)
            }

            #[inline(always)]
            fn store(a: &Self::Atomic, v: Self, order: Ordering) {
                a.store(v, order)
            }

            #[inline(always)]
            fn swap(a: &Self::Atomic, v: Self, order: Ordering) -> Self {
                a.swap(v, order)
            }

            #[inline(always)]
            fn compare_exchange(
                a: &Self::Atomic,
                current: Self,
                new: Self,
                success: Ordering,
                failure: Ordering,
            ) -> Result<Self, Self> {
                a.compare_exchange(current, new, success, failure)
            }

            #[inline(always)]
            fn compare_exchange_weak(
                a: &Self::Atomic,
                current: Self,
                new: Self,
                success: Ordering,
                failure: Ordering,
            ) -> Result<Self, Self> {
                a.compare_exchange_weak(current, new, success, failure)
            }

            #[inline(always)]
            fn fetch_or(a: &Self::Atomic, v: Self, order: Ordering) -> Self {
                a.fetch_or(v, order)
            }

            #[inline(always)]
            fn fetch_and(a: &Self::Atomic, v: Self, order: Ordering) -> Self {
                a.fetch_and(v, order)
            }

            #[inline(always)]
            fn fetch_xor(a: &Self::Atomic, v: Self, order: Ordering) -> Self {
                a.fetch_xor(v, order)
            }
        }
    };
}

#[cfg(target_has_atomic = "8")]
mod impl8 {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicI8;
    use core::sync::atomic::AtomicU8;

    impl_atomic_raw!(bool, AtomicBool);
    impl_atomic_raw!(u8, AtomicU8);
    impl_atomic_raw!(i8, AtomicI8);
}

#[cfg(target_has_atomic = "16")]
mod impl16 {
    use super::*;
    use core::sync::atomic::AtomicI16;
    use core::sync::atomic::AtomicU16;

    impl_atomic_raw!(u16, AtomicU16);
    impl_atomic_raw!(i16, AtomicI16);
}

#[cfg(target_has_atomic = "32")]
mod impl32 {
    use super::*;
    use core::sync::atomic::AtomicI32;
    use core::sync::atomic::AtomicU32;

    impl_atomic_raw!(u32, AtomicU32);
    impl_atomic_raw!(i32, AtomicI32);
}

#[cfg(target_has_atomic = "64")]
mod impl64 {
    use super::*;
    use core::sync::atomic::AtomicI64;
    use core::sync::atomic::AtomicU64;

    impl_atomic_raw!(u64, AtomicU64);
    impl_atomic_raw!(i64, AtomicI64);
}

#[cfg(target_has_atomic = "ptr")]
mod implptr {
    use super::*;
    use core::sync::atomic::AtomicIsize;
    use core::sync::atomic::AtomicUsize;

    impl_atomic_raw!(usize, AtomicUsize);
    impl_atomic_raw!(isize, AtomicIsize);
}
