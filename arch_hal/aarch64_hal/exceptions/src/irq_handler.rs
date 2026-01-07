use core::cell::SyncUnsafeCell;

use crate::common_handler::common_handler;
use cpu::Registers;

static IRQ_HANDLER: SyncUnsafeCell<Option<fn()>> = SyncUnsafeCell::new(None);

pub fn set_irq_handler(handler: fn()) {
    unsafe {
        *IRQ_HANDLER.get() = Some(handler);
    }
}

pub(crate) extern "C" fn irq_handler(reg: *mut Registers) {
    if let Some(handler) = unsafe { &*IRQ_HANDLER.get() } {
        handler();
        return;
    }
    common_handler(reg, "irq_handler" as *const _ as *const u8);
}
