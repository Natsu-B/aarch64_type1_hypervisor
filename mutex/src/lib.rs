#![cfg_attr(not(test), no_std)]

use core::cell::Cell;
use core::cell::UnsafeCell;
use core::fmt;
use core::ops::Deref;
use core::ops::DerefMut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

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
fn lock_none(_: &AtomicBool) {}

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

#[inline(always)]
fn rw_read_lock_none(_: &AtomicUsize) {}

#[inline(always)]
fn rw_read_unlock_none(_: &AtomicUsize) {}

#[inline(always)]
fn rw_write_lock_none(_: &AtomicUsize) {}

#[inline(always)]
fn rw_write_unlock_none(_: &AtomicUsize) {}

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

type LockFn = fn(&AtomicBool);
type UnLockFn = fn(&AtomicBool);
type ReadLockFn = fn(&AtomicUsize);
type ReadUnlockFn = fn(&AtomicUsize);
type WriteLockFn = fn(&AtomicUsize);
type WriteUnlockFn = fn(&AtomicUsize);

pub struct RawSpinLock<T: ?Sized> {
    lock_fn: Cell<LockFn>,
    unlock_fn: Cell<UnLockFn>,
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
            lock_fn: Cell::new(lock_none),
            unlock_fn: Cell::new(lock_none),
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> RawSpinLockGuard<'_, T> {
        self.lock_fn.get()(&self.locked);
        RawSpinLockGuard {
            lock: self,
            unlock_on_drop: true,
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

    /// Switches the lock into an atomic spin lock once multiple CPUs are active.
    ///
    /// Until this is called, [`lock`](Self::lock) is effectively a no-op so the
    /// raw lock can be used during single-threaded bring-up without paying the
    /// cost of atomic instructions.
    pub fn enable_atomic(&self) {
        self.lock_fn.set(lock_atomic);
        self.unlock_fn.set(unlock_atomic);
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
            self.lock.unlock_fn.get()(&self.lock.locked);
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

/// Raw reader-writer lock that starts as a no-op until atomics are enabled.
///
/// Before [`enable_atomic`](Self::enable_atomic) is called, lock/unlock operations are
/// intentionally no-ops so the lock can be used during single-core bring-up where mutual
/// exclusion is enforced externally (for example, by masking interrupts).
pub struct RawRwLock<T: ?Sized> {
    read_lock_fn: Cell<ReadLockFn>,
    read_unlock_fn: Cell<ReadUnlockFn>,
    write_lock_fn: Cell<WriteLockFn>,
    write_unlock_fn: Cell<WriteUnlockFn>,
    state: AtomicUsize,
    data: UnsafeCell<T>,
}

pub struct RawRwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RawRwLock<T>,
}

pub struct RawRwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RawRwLock<T>,
}

unsafe impl<T: ?Sized + Send + Sync> Sync for RawRwLock<T> {}
unsafe impl<T: ?Sized + Send> Send for RawRwLock<T> {}

impl<T> RawRwLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            read_lock_fn: Cell::new(rw_read_lock_none),
            read_unlock_fn: Cell::new(rw_read_unlock_none),
            write_lock_fn: Cell::new(rw_write_lock_none),
            write_unlock_fn: Cell::new(rw_write_unlock_none),
            state: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn read(&self) -> RawRwLockReadGuard<'_, T> {
        self.read_lock_fn.get()(&self.state);
        RawRwLockReadGuard { lock: self }
    }

    pub fn write(&self) -> RawRwLockWriteGuard<'_, T> {
        self.write_lock_fn.get()(&self.state);
        RawRwLockWriteGuard { lock: self }
    }

    /// Switches the lock into an atomic reader-writer lock once multiple CPUs are active.
    ///
    /// Until this is called, locking is effectively a no-op so the raw lock can be used
    /// during single-threaded bring-up without paying the cost of atomic instructions.
    pub fn enable_atomic(&self) {
        self.read_lock_fn.set(rw_read_lock_atomic);
        self.read_unlock_fn.set(rw_read_unlock_atomic);
        self.write_lock_fn.set(rw_write_lock_atomic);
        self.write_unlock_fn.set(rw_write_unlock_atomic);
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
        self.lock.read_unlock_fn.get()(&self.lock.state);
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
        self.lock.write_unlock_fn.get()(&self.lock.state);
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
    use std::thread;

    #[test]
    fn raw_spinlock_defaults_to_noop_locking() {
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
    }

    #[test]
    fn raw_spinlock_enable_atomic_switches_to_atomic() {
        let lock = RawSpinLock::new(0u32);

        assert!(!lock.is_locked());

        {
            let _guard = lock.lock();
            // No locking applied yet.
            assert!(!lock.is_locked());
        }

        lock.enable_atomic();

        let guard = lock.lock();
        assert!(lock.is_locked());
        drop(guard);

        assert!(!lock.is_locked());

        let guard = lock.lock();
        assert!(lock.is_locked());
        drop(guard);
        assert!(!lock.is_locked());
    }

    #[test]
    fn raw_rwlock_defaults_to_noop_locking() {
        let lock = RawRwLock::new(0usize);

        {
            let mut writer = lock.write();
            *writer = 1;
        }

        let reader = lock.read();
        assert_eq!(*reader, 1);
        drop(reader);
    }

    #[test]
    fn raw_rwlock_enable_atomic_switches_to_atomic() {
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

        lock.enable_atomic();

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
    }

    #[test]
    fn raw_rwlock_multithreaded_after_enabling_atomic() {
        let lock = Arc::new(RawRwLock::new(0usize));
        lock.enable_atomic();

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
    }

    #[test]
    fn raw_spinlock_no_lock_does_not_unlock_in_atomic_mode() {
        let lock = RawSpinLock::new(0u32);
        lock.enable_atomic();
        lock.locked.store(true, Ordering::Relaxed);

        {
            let _guard = unsafe { lock.no_lock() };
        }

        assert!(lock.locked.load(Ordering::Relaxed));
        lock.locked.store(false, Ordering::Relaxed);
    }

    #[test]
    fn raw_spinlock_lock_still_unlocks_in_atomic_mode() {
        let lock = RawSpinLock::new(0u32);
        lock.enable_atomic();

        {
            let _guard = lock.lock();
            assert!(lock.is_locked());
        }

        assert!(!lock.is_locked());
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
