use core::cell::SyncUnsafeCell;

use cpu::Registers;

static POST_HANDLER: SyncUnsafeCell<Option<fn(&mut Registers)>> = SyncUnsafeCell::new(None);

pub fn set_post_handler(handler: fn(&mut Registers)) {
    unsafe {
        *POST_HANDLER.get() = Some(handler);
    }
}

pub(crate) extern "C" fn post_handler(reg: *mut Registers) {
    if let Some(handler) = unsafe { &*POST_HANDLER.get() } {
        // SAFETY: `reg` points to the saved exception frame and remains valid
        // for the duration of this callback.
        handler(unsafe { &mut *reg });
    }
}
