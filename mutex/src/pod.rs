use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use typestate::RawReg;
use typestate::atomic_raw::AtomicRaw;

// ===== RawAtomicPod =======================================================
//
// A bring-up friendly atomic cell:
// - Before enable_raw_atomics(): non-atomic plain memory access (single-core bring-up).
// - After enable_raw_atomics(): atomic operations via Atomic*::from_ptr().
//
// This is intentionally "raw": enable_raw_atomics() is not synchronized and must be
// called before introducing concurrent access.

/// A "raw" atomic POD that starts as non-atomic until atomics are enabled.
///
/// - Before `enable_raw_atomics()`: operations are performed non-atomically (intended for single-core bring-up).
/// - After `enable_raw_atomics()`: operations use Atomic* on the same storage without requiring IRQ masking.
///
/// # Safety / Invariants
/// - `enable_raw_atomics()` must be called only during a phase where no concurrent accesses exist.
/// - Using these operations concurrently before raw atomics are enabled is unsupported and can
///   cause data races or aliasing UB.
/// - After `enable_raw_atomics()`, you must not perform conflicting non-atomic accesses to the same value.
///   (This includes taking `&mut` to the underlying storage while other cores use atomics.)
pub struct RawAtomicPod<T: RawReg>
where
    T::Raw: AtomicRaw,
{
    raw: UnsafeCell<T::Raw>,
    _phantom: PhantomData<T>,
}

unsafe impl<T: RawReg> Sync for RawAtomicPod<T> where T::Raw: AtomicRaw + Send {}
unsafe impl<T: RawReg> Send for RawAtomicPod<T> where T::Raw: AtomicRaw + Send {}

impl<T: RawReg> RawAtomicPod<T>
where
    T::Raw: AtomicRaw,
{
    const _LAYOUT_OK: () = {
        // Atomic* types guarantee same size/bit validity as the underlying scalar.
        // AtomicBool additionally guarantees same alignment as bool. :contentReference[oaicite:6]{index=6}
        // AtomicU32 guarantees same size, but alignment may be larger than u32 on some targets. :contentReference[oaicite:7]{index=7}
        // We enforce Raw's alignment is sufficient for its Atomic mapping.
        assert!(size_of::<T::Raw>() == size_of::<<T::Raw as AtomicRaw>::Atomic>());
        assert!(align_of::<T::Raw>() >= align_of::<<T::Raw as AtomicRaw>::Atomic>());
    };

    #[inline]
    pub const fn new_raw(init: T::Raw) -> Self {
        let _ = Self::_LAYOUT_OK;
        Self {
            raw: UnsafeCell::new(init),
            _phantom: PhantomData,
        }
    }

    #[inline]
    pub fn new(init: T) -> Self {
        let _ = Self::_LAYOUT_OK;
        Self {
            raw: UnsafeCell::new(init.to_raw()),
            _phantom: PhantomData,
        }
    }

    #[inline(always)]
    fn atomic_ref(&self) -> &<T::Raw as AtomicRaw>::Atomic {
        let ptr = self.raw.get() as *mut T::Raw;
        debug_assert!(ptr.cast::<<T::Raw as AtomicRaw>::Atomic>().is_aligned());
        // SAFETY: `raw` is properly aligned by construction (_LAYOUT_OK),
        // and the returned reference is bounded by `&self`.
        unsafe { <T::Raw as AtomicRaw>::from_ptr(ptr) }
    }

    #[inline]
    pub fn load(&self, order: Ordering) -> T {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            T::from_raw(<T::Raw as AtomicRaw>::load(a, order))
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            T::from_raw(unsafe { *self.raw.get() })
        }
    }

    #[inline]
    pub fn store(&self, val: T, order: Ordering) {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            <T::Raw as AtomicRaw>::store(a, val.to_raw(), order);
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            unsafe { *self.raw.get() = val.to_raw() };
        }
    }

    #[inline]
    pub fn swap(&self, val: T, order: Ordering) -> T {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            T::from_raw(<T::Raw as AtomicRaw>::swap(a, val.to_raw(), order))
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            let old = unsafe { *self.raw.get() };
            unsafe { *self.raw.get() = val.to_raw() };
            T::from_raw(old)
        }
    }

    #[inline]
    pub fn fetch_or(&self, val: T, order: Ordering) -> T
    where
        T::Raw: core::ops::BitOr<Output = T::Raw>,
    {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            T::from_raw(<T::Raw as AtomicRaw>::fetch_or(a, val.to_raw(), order))
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            let old = unsafe { *self.raw.get() };
            let new = old | val.to_raw();
            unsafe { *self.raw.get() = new };
            T::from_raw(old)
        }
    }

    #[inline]
    pub fn fetch_and(&self, val: T, order: Ordering) -> T
    where
        T::Raw: core::ops::BitAnd<Output = T::Raw>,
    {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            T::from_raw(<T::Raw as AtomicRaw>::fetch_and(a, val.to_raw(), order))
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            let old = unsafe { *self.raw.get() };
            let new = old & val.to_raw();
            unsafe { *self.raw.get() = new };
            T::from_raw(old)
        }
    }

    #[inline]
    pub fn fetch_xor(&self, val: T, order: Ordering) -> T
    where
        T::Raw: core::ops::BitXor<Output = T::Raw>,
    {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            T::from_raw(<T::Raw as AtomicRaw>::fetch_xor(a, val.to_raw(), order))
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            let old = unsafe { *self.raw.get() };
            let new = old ^ val.to_raw();
            unsafe { *self.raw.get() = new };
            T::from_raw(old)
        }
    }

    #[inline]
    pub fn get_mut_raw(&mut self) -> &mut T::Raw {
        // This is always safe because &mut self guarantees exclusivity.
        self.raw.get_mut()
    }
}

impl<T: RawReg> RawAtomicPod<T>
where
    T::Raw: AtomicRaw + PartialEq,
{
    #[inline]
    pub fn compare_exchange(
        &self,
        current: T,
        new: T,
        success: Ordering,
        failure: Ordering,
    ) -> Result<T, T> {
        if crate::raw_atomics_enabled() {
            let a = self.atomic_ref();
            <T::Raw as AtomicRaw>::compare_exchange(
                a,
                current.to_raw(),
                new.to_raw(),
                success,
                failure,
            )
            .map(T::from_raw)
            .map_err(T::from_raw)
        } else {
            // SAFETY: Non-atomic bring-up phase must ensure exclusive access externally.
            let cur = unsafe { *self.raw.get() };
            if cur == current.to_raw() {
                unsafe { *self.raw.get() = new.to_raw() };
                Ok(T::from_raw(cur))
            } else {
                Err(T::from_raw(cur))
            }
        }
    }
}
