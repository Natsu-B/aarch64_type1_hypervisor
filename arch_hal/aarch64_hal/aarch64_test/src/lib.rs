#![no_std]

#[cfg(feature = "bump-allocator")]
extern crate alloc;

use core::arch::asm;

#[cfg(feature = "bump-allocator")]
mod allocator {
    use core::alloc::GlobalAlloc;
    use core::alloc::Layout;
    use core::ptr::null_mut;
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;

    const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64 MiB scratch allocator space

    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

    pub struct BumpAllocator {
        next: AtomicUsize,
    }

    impl BumpAllocator {
        pub const fn new() -> Self {
            Self {
                next: AtomicUsize::new(0),
            }
        }
    }

    unsafe impl GlobalAlloc for BumpAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let heap_start = core::ptr::addr_of_mut!(HEAP) as usize;
            let heap_end = heap_start + HEAP_SIZE;

            let mut current_offset = self.next.load(Ordering::Relaxed);

            loop {
                let current_addr = heap_start + current_offset;
                let aligned_addr = current_addr.next_multiple_of(layout.align());
                let aligned_offset = aligned_addr - heap_start;

                let allocation_end = match aligned_offset.checked_add(layout.size()) {
                    Some(end) => heap_start + end,
                    None => return null_mut(),
                };

                if allocation_end > heap_end {
                    return null_mut();
                }

                let new_offset = allocation_end - heap_start;

                match self.next.compare_exchange(
                    current_offset,
                    new_offset,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return aligned_addr as *mut u8,
                    Err(offset) => current_offset = offset,
                }
            }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocator doesn't support deallocation
        }
    }

    unsafe impl Sync for BumpAllocator {}

    #[global_allocator]
    pub static ALLOCATOR: BumpAllocator = BumpAllocator::new();
}

pub fn exit_success() -> ! {
    exit_with_code(0)
}

pub fn exit_failure() -> ! {
    exit_with_code(1)
}

pub extern "C" fn exit_with_code(code: u32) -> ! {
    // A64 SYS_EXIT (0x18) takes a parameter block and can return an exit status.
    // Using SYS_EXIT keeps compatibility with implementations that may not support SYS_EXIT_EXTENDED.
    const SYS_EXIT: u64 = 0x18; // semihosting op
    const ADP_APP_EXIT: u64 = 0x20026; // ADP_Stopped_ApplicationExit

    #[repr(C)]
    struct ExitArgs {
        // AArch64 semihosting parameter blocks are interpreted as target_ulong words (64-bit on A64).
        // Field 0: reason code (e.g. ADP_Stopped_ApplicationExit)
        // Field 1: subcode (exit status)
        reason: u64,
        subcode: u64,
    }

    let args = ExitArgs {
        reason: ADP_APP_EXIT,
        subcode: code as u64,
    };
    let ptr = core::ptr::addr_of!(args) as usize;

    unsafe {
        asm!(
            "hlt #0xf000",                 // AArch64 semihosting trap
            in("x0") SYS_EXIT,             // op
            in("x1") ptr,                  // &ExitArgs { reason, subcode }
            options(noreturn)
        );
    }
}

#[repr(C)]
struct SemihostOpenArgs {
    path: u64,
    mode: u64,
    len: u64,
}

#[repr(C)]
struct SemihostWriteArgs {
    handle: u64,
    buf: u64,
    len: u64,
}

#[repr(C)]
struct SemihostCloseArgs {
    handle: u64,
}

fn semihost_call(op: u64, args: u64) -> u64 {
    let mut x0 = op;
    // SAFETY: caller provides valid semihosting arguments for the guest.
    unsafe {
        asm!(
            "hlt #0xf000",
            inout("x0") x0,
            in("x1") args,
            options(nostack)
        );
    }
    x0
}

/// Writes a null-terminated string to the semihosting console.
pub fn semihost_write0(ptr: *const u8) {
    const SYS_WRITE0: u64 = 0x04;
    let _ = semihost_call(SYS_WRITE0, ptr as u64);
}

/// Opens a host file and returns a semihosting handle, or -1 on failure.
pub fn semihost_open(path: *const u8, len: usize, mode: u64) -> i32 {
    const SYS_OPEN: u64 = 0x01;
    let args = SemihostOpenArgs {
        path: path as u64,
        mode,
        len: len as u64,
    };
    semihost_call(SYS_OPEN, core::ptr::addr_of!(args) as u64) as i32
}

/// Writes a buffer to a semihosting handle. Returns bytes not written.
pub fn semihost_write(handle: i32, buf: *const u8, len: usize) -> i32 {
    const SYS_WRITE: u64 = 0x05;
    let args = SemihostWriteArgs {
        handle: handle as u64,
        buf: buf as u64,
        len: len as u64,
    };
    semihost_call(SYS_WRITE, core::ptr::addr_of!(args) as u64) as i32
}

/// Closes a semihosting handle and returns 0 on success or -1 on failure.
pub fn semihost_close(handle: i32) -> i32 {
    const SYS_CLOSE: u64 = 0x02;
    let args = SemihostCloseArgs {
        handle: handle as u64,
    };
    semihost_call(SYS_CLOSE, core::ptr::addr_of!(args) as u64) as i32
}
