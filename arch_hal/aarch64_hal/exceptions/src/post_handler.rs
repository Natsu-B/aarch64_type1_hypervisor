use core::cell::SyncUnsafeCell;

use cpu::Registers;

static POST_HANDLER: SyncUnsafeCell<Option<fn(&mut Registers)>> = SyncUnsafeCell::new(None);

pub fn set_post_handler(handler: fn(&mut Registers)) {
    unsafe {
        *POST_HANDLER.get() = Some(handler);
    }
}

// This lightweight probe lets the naked asm epilogue skip calling into Rust
// entirely when no post-handler has been installed.
#[inline(always)]
pub(crate) extern "C" fn has_post_handler() -> u64 {
    // Returns 1 if a post handler is installed, else 0.
    // Intended for hot-path branching in naked asm.
    if unsafe { (&*POST_HANDLER.get()).is_some() } {
        1
    } else {
        0
    }
}

pub(crate) extern "C" fn post_handler(reg: *mut Registers) {
    if let Some(handler) = unsafe { &*POST_HANDLER.get() } {
        // SAFETY: `reg` points to the saved exception frame and remains valid
        // for the duration of this callback.
        handler(unsafe { &mut *reg });
    }
}
