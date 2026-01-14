#![cfg_attr(not(test), no_std)]
#![feature(sync_unsafe_cell)]

use core::cell::SyncUnsafeCell;
use core::cell::UnsafeCell;
use core::fmt;
use core::ops::Deref;
use core::ops::DerefMut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

pub mod pod;

static RAW_ATOMICS_ENABLED: SyncUnsafeCell<bool> = SyncUnsafeCell::new(false);

#[inline]
fn raw_atomics_enabled() -> bool {
    // SAFETY: `RAW_ATOMICS_ENABLED` is only written during single-core bring-up,
    // and reads are allowed as a simple flag check after that point.
    unsafe { *RAW_ATOMICS_ENABLED.get() }
}

/// Enables raw atomic operations globally for this crate.
///
/// # Invariants
/// - Call only after paging/caches/memory attributes are enabled. If called too early,
///   subsequent lock/atomic operations will execute atomic RMW instructions while the
///   platform still forbids them, which can trap or lead to unpredictable memory behavior.
/// - Call before secondary cores start and before any concurrent lock usage. If called
///   concurrently with readers, some operations may remain non-atomic while others become
///   atomic, leading to data races, lost updates, or aliasing UB.
/// - This function is intentionally unsynchronized and must only run during single-core
///   bring-up to avoid races with `raw_atomics_enabled()` readers.
#[inline]
pub fn enable_raw_atomics() {
    // SAFETY: callers must uphold the bring-up sequencing and single-core invariants above.
    unsafe {
        *RAW_ATOMICS_ENABLED.get() = true;
    }
}

pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }

    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(_g) = self.try_lock() {
            f.debug_struct("SpinLock")
                .field("data", unsafe { &*self.data.get() })
                .finish()
        } else {
            f.debug_struct("SpinLock")
                .field("data", &"<locked>")
                .finish()
        }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

#[inline(always)]
fn lock_atomic(locked: &AtomicBool) {
    while locked
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline(always)]
fn unlock_atomic(locked: &AtomicBool) {
    locked.store(false, Ordering::Release);
}

const WRITE_FLAG: usize = 1 << (usize::BITS - 1);

#[inline(always)]
fn rw_read_lock_atomic(state: &AtomicUsize) {
    loop {
        let current_state = state.load(Ordering::Relaxed);
        if current_state & WRITE_FLAG != 0 {
            core::hint::spin_loop();
            continue;
        }

        let next_state = match current_state.checked_add(1) {
            Some(next) => next,
            None => {
                core::hint::spin_loop();
                continue;
            }
        };

        if next_state & WRITE_FLAG != 0 {
            core::hint::spin_loop();
            continue;
        }

        if state
            .compare_exchange_weak(
                current_state,
                next_state,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
}

#[inline(always)]
fn rw_read_unlock_atomic(state: &AtomicUsize) {
    state.fetch_sub(1, Ordering::Release);
}

#[inline(always)]
fn rw_write_lock_atomic(state: &AtomicUsize) {
    loop {
        let current_state = state.load(Ordering::Relaxed);
        if current_state & WRITE_FLAG != 0 {
            core::hint::spin_loop();
            continue;
        }

        if state
            .compare_exchange_weak(
                current_state,
                current_state | WRITE_FLAG,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            while state.load(Ordering::Relaxed) & !WRITE_FLAG != 0 {
                core::hint::spin_loop();
            }
            break;
        }
        core::hint::spin_loop();
    }
}

#[inline(always)]
fn rw_write_unlock_atomic(state: &AtomicUsize) {
    state.fetch_and(!WRITE_FLAG, Ordering::Release);
}

pub struct RawSpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

pub struct RawSpinLockGuard<'a, T> {
    lock: &'a RawSpinLock<T>,
    unlock_on_drop: bool,
}

unsafe impl<T: ?Sized + Send> Send for RawSpinLock<T> {}
unsafe impl<T: ?Sized + Send> Sync for RawSpinLock<T> {}

impl<T> RawSpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> RawSpinLockGuard<'_, T> {
        let unlock_on_drop = raw_atomics_enabled();
        if unlock_on_drop {
            lock_atomic(&self.locked);
        }
        RawSpinLockGuard {
            lock: self,
            unlock_on_drop,
        }
    }

    /// Returns a guard without acquiring the lock or modifying lock state.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no other CPU/thread can access the protected
    /// value concurrently (including via [`lock`](Self::lock)), and that no
    /// other guard exists that could produce references to the same `T`.
    /// Breaking these requirements can cause data races or aliasing UB.
    pub unsafe fn no_lock(&self) -> RawSpinLockGuard<'_, T> {
        RawSpinLockGuard {
            lock: self,
            unlock_on_drop: false,
        }
    }
}

#[cfg(test)]
impl<T: ?Sized> RawSpinLock<T> {
    fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Acquire)
    }
}

impl<T> Drop for RawSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        if self.unlock_on_drop {
            unlock_atomic(&self.lock.locked);
        }
    }
}

impl<T> Deref for RawSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for RawSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

/// Raw reader-writer lock that starts as a no-op until raw atomics are enabled.
///
/// Before [`enable_raw_atomics`](crate::enable_raw_atomics) is called, lock/unlock
/// operations are intentionally no-ops so the lock can be used during single-core
/// bring-up where mutual exclusion is enforced externally (for example, by masking
/// interrupts).
pub struct RawRwLock<T: ?Sized> {
    state: AtomicUsize,
    data: UnsafeCell<T>,
}

pub struct RawRwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RawRwLock<T>,
    unlock_on_drop: bool,
}

pub struct RawRwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RawRwLock<T>,
    unlock_on_drop: bool,
}

unsafe impl<T: ?Sized + Send + Sync> Sync for RawRwLock<T> {}
unsafe impl<T: ?Sized + Send> Send for RawRwLock<T> {}

impl<T> RawRwLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn read(&self) -> RawRwLockReadGuard<'_, T> {
        let unlock_on_drop = raw_atomics_enabled();
        if unlock_on_drop {
            rw_read_lock_atomic(&self.state);
        }
        RawRwLockReadGuard {
            lock: self,
            unlock_on_drop,
        }
    }

    pub fn write(&self) -> RawRwLockWriteGuard<'_, T> {
        let unlock_on_drop = raw_atomics_enabled();
        if unlock_on_drop {
            rw_write_lock_atomic(&self.state);
        }
        RawRwLockWriteGuard {
            lock: self,
            unlock_on_drop,
        }
    }
}

#[cfg(test)]
impl<T: ?Sized> RawRwLock<T> {
    fn raw_state(&self) -> usize {
        self.state.load(Ordering::Acquire)
    }

    fn is_write_locked(&self) -> bool {
        self.raw_state() & WRITE_FLAG != 0
    }

    fn read_count(&self) -> usize {
        self.raw_state() & !WRITE_FLAG
    }
}

impl<T: ?Sized> Drop for RawRwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        if self.unlock_on_drop {
            rw_read_unlock_atomic(&self.lock.state);
        }
    }
}

impl<T: ?Sized> Deref for RawRwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RawRwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        if self.unlock_on_drop {
            rw_write_unlock_atomic(&self.lock.state);
        }
    }
}

impl<T: ?Sized> Deref for RawRwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RawRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

pub struct RwLock<T> {
    /// The most significant bit is the write lock flag.
    /// The other bits are the read count.
    read_count_write_lock_flag: AtomicUsize,
    data: UnsafeCell<T>,
}

pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

unsafe impl<T: Send + Sync> Sync for RwLock<T> {}
unsafe impl<T: Send> Send for RwLock<T> {}

impl<T> RwLock<T> {
    const WRITE_FLAG: usize = 1 << (usize::BITS - 1);
    pub const fn new(data: T) -> Self {
        Self {
            read_count_write_lock_flag: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let current_state = self.read_count_write_lock_flag.load(Ordering::Relaxed);
            // If no write lock is held or requested, try to acquire a read lock.
            if current_state & Self::WRITE_FLAG == 0
                && self
                    .read_count_write_lock_flag
                    .compare_exchange_weak(
                        current_state,
                        current_state + 1,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                return RwLockReadGuard { lock: self };
            }
            core::hint::spin_loop();
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            let current_state = self.read_count_write_lock_flag.load(Ordering::Relaxed);
            // If no write lock is held, try to acquire one.
            if current_state & Self::WRITE_FLAG == 0 {
                // Attempt to set the write flag.
                if self
                    .read_count_write_lock_flag
                    .compare_exchange_weak(
                        current_state,
                        current_state | Self::WRITE_FLAG,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    // Wait for all existing readers to finish.
                    while self.read_count_write_lock_flag.load(Ordering::Relaxed)
                        & !Self::WRITE_FLAG
                        != 0
                    {
                        core::hint::spin_loop();
                    }
                    return RwLockWriteGuard { lock: self };
                }
            }
            // Spin if a write lock is already held or if CAS failed.
            core::hint::spin_loop();
        }
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock
            .read_count_write_lock_flag
            .fetch_sub(1, Ordering::Release);
    }
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock
            .read_count_write_lock_flag
            .fetch_and(!RwLock::<T>::WRITE_FLAG, Ordering::Release);
    }
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use std::thread;

    fn with_raw_atomics_mode(enabled: bool, f: impl FnOnce()) {
        static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = TEST_MUTEX.get_or_init(|| Mutex::new(())).lock().unwrap();
        let prev = raw_atomics_enabled();
        // SAFETY: the test mutex serializes access and tests are single-threaded in this scope.
        unsafe {
            *RAW_ATOMICS_ENABLED.get() = enabled;
        }
        f();
        // SAFETY: restore the prior state while still holding the test mutex.
        unsafe {
            *RAW_ATOMICS_ENABLED.get() = prev;
        }
        drop(guard);
    }

    #[test]
    fn raw_spinlock_defaults_to_noop_locking() {
        with_raw_atomics_mode(false, || {
            let lock = RawSpinLock::new(0usize);

            let guard1 = lock.lock();
            {
                let mut guard2 = lock.lock();
                *guard2 = 1;
            }

            assert_eq!(*guard1, 1);
            drop(guard1);

            let guard = lock.lock();
            assert_eq!(*guard, 1);
            drop(guard);
        });
    }

    #[test]
    fn raw_spinlock_global_raw_atomics_controls_locking() {
        with_raw_atomics_mode(false, || {
            let lock = RawSpinLock::new(0u32);
            assert!(!lock.is_locked());

            {
                let _guard = lock.lock();
                // No locking applied yet.
                assert!(!lock.is_locked());
            }
        });

        with_raw_atomics_mode(true, || {
            let lock = RawSpinLock::new(0u32);
            let guard = lock.lock();
            assert!(lock.is_locked());
            drop(guard);

            assert!(!lock.is_locked());

            let guard = lock.lock();
            assert!(lock.is_locked());
            drop(guard);
            assert!(!lock.is_locked());
        });
    }

    #[test]
    fn raw_rwlock_defaults_to_noop_locking() {
        with_raw_atomics_mode(false, || {
            let lock = RawRwLock::new(0usize);

            {
                let mut writer = lock.write();
                *writer = 1;
            }

            let reader = lock.read();
            assert_eq!(*reader, 1);
            drop(reader);
        });
    }

    #[test]
    fn raw_rwlock_global_raw_atomics_controls_locking() {
        with_raw_atomics_mode(false, || {
            let lock = RawRwLock::new(0u32);

            assert_eq!(lock.raw_state(), 0);

            {
                let _reader = lock.read();
                assert_eq!(lock.raw_state(), 0);
            }

            {
                let mut writer = lock.write();
                *writer = 1;
                assert_eq!(lock.raw_state(), 0);
            }

            assert_eq!(lock.raw_state(), 0);
        });

        with_raw_atomics_mode(true, || {
            let lock = RawRwLock::new(0u32);

            {
                let _reader = lock.read();
                assert_eq!(lock.read_count(), 1);
                assert!(!lock.is_write_locked());
            }

            assert_eq!(lock.read_count(), 0);

            {
                let _reader_one = lock.read();
                let _reader_two = lock.read();
                assert_eq!(lock.read_count(), 2);
            }

            assert_eq!(lock.read_count(), 0);

            {
                let mut writer = lock.write();
                assert!(lock.is_write_locked());
                *writer = 2;
                assert_eq!(lock.read_count(), 0);
            }

            assert!(!lock.is_write_locked());
            assert_eq!(lock.read_count(), 0);
        });
    }

    #[test]
    fn raw_rwlock_multithreaded_after_enabling_atomic() {
        with_raw_atomics_mode(true, || {
            let lock = Arc::new(RawRwLock::new(0usize));

            let mut handles = vec![];

            let writer_lock = Arc::clone(&lock);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let mut writer = writer_lock.write();
                    *writer += 1;
                    thread::sleep(Duration::from_millis(1));
                }
            }));

            for _ in 0..10 {
                let reader_lock = Arc::clone(&lock);
                handles.push(thread::spawn(move || {
                    for _ in 0..50 {
                        let reader = reader_lock.read();
                        let value = *reader;
                        assert!(value <= 100);
                        thread::sleep(Duration::from_millis(1));
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(*lock.read(), 100);
        });
    }

    #[test]
    fn raw_spinlock_no_lock_does_not_unlock_in_atomic_mode() {
        with_raw_atomics_mode(true, || {
            let lock = RawSpinLock::new(0u32);
            lock.locked.store(true, Ordering::Relaxed);

            {
                let _guard = unsafe { lock.no_lock() };
            }

            assert!(lock.locked.load(Ordering::Relaxed));
            lock.locked.store(false, Ordering::Relaxed);
        });
    }

    #[test]
    fn raw_spinlock_lock_still_unlocks_in_atomic_mode() {
        with_raw_atomics_mode(true, || {
            let lock = RawSpinLock::new(0u32);

            {
                let _guard = lock.lock();
                assert!(lock.is_locked());
            }

            assert!(!lock.is_locked());
        });
    }

    #[test]
    fn spinlock_test() {
        let spinlock = Arc::new(SpinLock::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let spinlock_clone = Arc::clone(&spinlock);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let mut guard = spinlock_clone.lock();
                    *guard += 1;
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(*spinlock.lock(), 10 * 1000);
    }

    #[test]
    fn rw_lock_test() {
        let lock = Arc::new(RwLock::new(0));
        let mut handles = vec![];

        // A single writer thread that increments the value.
        let writer_lock_clone = Arc::clone(&lock);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut writer = writer_lock_clone.write();
                *writer += 1;
                thread::sleep(Duration::from_millis(1));
            }
        }));

        // Multiple reader threads that read the value.
        for _ in 0..10 {
            let reader_lock_clone = Arc::clone(&lock);
            handles.push(thread::spawn(move || {
                // Read multiple times to increase the chance of observing different values.
                for _ in 0..50 {
                    let reader = reader_lock_clone.read();
                    let value = *reader;
                    // The value should be within the expected range.
                    assert!(value >= 0 && value <= 100);
                    thread::sleep(Duration::from_millis(1));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // After all threads are done, the final value should be 100.
        assert_eq!(*lock.read(), 100);
    }
}
