#![no_std]

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::ptr::{self};

use cpu::get_tpidr_el2;
use cpu::set_tpidr_el2;

/// Minimum alignment required for per-CPU TLS buffers.
pub const PERCPU_MIN_ALIGN: usize = 64;

unsafe extern "C" {
    static __el2_tls_start: u8;
    static __el2_tls_end: u8;
}

/// Errors that can occur while initializing per-CPU TLS storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsInitError {
    BufferTooSmall { need: usize, have: usize },
    Misaligned { required: usize, actual: usize },
}

/// Wrapper for a value that is instantiated once per CPU.
///
/// # Safety
/// * `init_current_cpu` must be called once on each CPU before reading or
///   mutating any `PerCpu` value on that CPU.
/// * The caller must ensure each CPU uses distinct backing storage in
///   `init_current_cpu` to avoid data races.
/// * `current_mut` is unsafe because the caller must guarantee exclusive
///   access on the current CPU (e.g. interrupts masked or higher-level
///   synchronization).
#[repr(transparent)]
pub struct PerCpu<T> {
    value: UnsafeCell<T>,
}

// SAFETY: Each CPU observes its own copy of the TLS region. Requiring `T: Send`
// ensures the contained value can be moved between contexts without violating
// sendability assumptions.
unsafe impl<T: Send> Sync for PerCpu<T> {}

impl<T> PerCpu<T> {
    /// Construct a new per-CPU value.
    pub const fn new(val: T) -> Self {
        Self {
            value: UnsafeCell::new(val),
        }
    }

    #[inline(always)]
    fn cell_ptr(&'static self) -> *const UnsafeCell<T> {
        let base = self as *const Self as usize;
        let offset = read_tpidr_el2();
        let addr = base.wrapping_add(offset);
        addr as *const UnsafeCell<T>
    }

    /// Pointer to the current CPU's instance of this value.
    #[inline(always)]
    pub fn current_ptr(&'static self) -> *mut T {
        let cell = self.cell_ptr();
        // SAFETY: `cell` is derived from the per-CPU offset in TPIDR_EL2 and
        // points into the caller-provided backing storage once
        // `init_current_cpu` has executed on this CPU.
        unsafe { (&*cell).get() }
    }

    /// Shared reference to the current CPU's instance.
    ///
    /// # Safety
    /// The caller must guarantee `init_current_cpu` was executed on this CPU
    /// with a unique backing buffer.
    #[inline(always)]
    pub fn current(&'static self) -> &'static T {
        // SAFETY: caller is responsible for one-time initialization per CPU.
        unsafe { &*self.current_ptr() }
    }

    /// Exclusive reference to the current CPU's instance.
    ///
    /// # Safety
    /// Caller must ensure per-CPU initialization has completed and that no
    /// other code on this CPU can access the value concurrently.
    #[inline(always)]
    pub unsafe fn current_mut(&'static self) -> &'static mut T {
        // SAFETY: caller guarantees exclusivity on this CPU and prior init.
        unsafe { &mut *self.current_ptr() }
    }
}

/// Define a per-CPU TLS variable placed in the `.el2_tls` linker section.
#[macro_export]
macro_rules! percpu {
    ( $(#[$meta:meta])* $vis:vis static $name:ident : $ty:ty = $init:expr ; ) => {
        $(#[$meta])*
        #[used]
        #[link_section = ".el2_tls"]
        $vis static $name: $crate::PerCpu<$ty> = $crate::PerCpu::new($init);
    };
}

/// Size in bytes of the TLS template emitted by the linker.
#[inline(always)]
pub fn template_size() -> usize {
    let start = template_start();
    let end = template_end();
    end.wrapping_sub(start)
}

/// Pointer to the TLS template and its size.
#[inline(always)]
pub fn template_range() -> (*const u8, usize) {
    (template_start() as *const u8, template_size())
}

#[inline(always)]
fn template_start() -> usize {
    core::ptr::addr_of!(__el2_tls_start) as usize
}

#[inline(always)]
fn template_end() -> usize {
    core::ptr::addr_of!(__el2_tls_end) as usize
}

/// Read TPIDR_EL2 (EL2 TLS offset).
#[inline(always)]
pub fn read_tpidr_el2() -> usize {
    get_tpidr_el2() as usize
}

/// Write TPIDR_EL2 with an offset from `__el2_tls_start`.
#[inline(always)]
pub fn write_tpidr_el2(value: usize) {
    // SAFETY: caller must provide the per-CPU offset computed during
    // initialization for the current CPU. The CPU register write is
    // performed inside the `cpu` crate.
    set_tpidr_el2(value as u64);
}

/// Initialize TLS for the current CPU using caller-provided storage.
///
/// * `percpu_base` must point to writable memory unique to the current CPU.
/// * `percpu_len` must be at least `template_size()`.
/// * `percpu_base` must be aligned to `PERCPU_MIN_ALIGN` bytes.
///
/// On success, `TPIDR_EL2` is set so that each `PerCpu` variable resolves to
/// the copy inside `percpu_base`.
///
/// # Safety
/// Caller guarantees the buffer is unique to this CPU, lives for the remainder
/// of execution, and that initialization runs exactly once per CPU.
pub unsafe fn init_current_cpu(
    percpu_base: NonNull<u8>,
    percpu_len: usize,
) -> Result<(), TlsInitError> {
    let need = template_size();
    if percpu_len < need {
        return Err(TlsInitError::BufferTooSmall {
            need,
            have: percpu_len,
        });
    }

    let base = percpu_base.as_ptr() as usize;
    if base % PERCPU_MIN_ALIGN != 0 {
        return Err(TlsInitError::Misaligned {
            required: PERCPU_MIN_ALIGN,
            actual: base % PERCPU_MIN_ALIGN,
        });
    }

    let tpl_start = template_start() as *const u8;
    // SAFETY: caller promises `percpu_base` is valid writable memory that does
    // not alias the template, and the size check above guarantees the copy
    // fits.
    unsafe { ptr::copy_nonoverlapping(tpl_start, percpu_base.as_ptr(), need) };

    let offset = base.wrapping_sub(template_start());
    write_tpidr_el2(offset);
    Ok(())
}
