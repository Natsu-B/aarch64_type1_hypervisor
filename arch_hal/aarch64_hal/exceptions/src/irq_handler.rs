use core::cell::SyncUnsafeCell;

use crate::common_handler::common_handler;
use cpu::Registers;

static IRQ_HANDLER: SyncUnsafeCell<Option<fn(&mut Registers)>> = SyncUnsafeCell::new(None);

pub fn set_irq_handler(handler: fn(&mut Registers)) {
    unsafe {
        *IRQ_HANDLER.get() = Some(handler);
    }
}

pub(crate) extern "C" fn irq_handler(reg: *mut Registers) {
    if let Some(handler) = unsafe { &*IRQ_HANDLER.get() } {
        // SAFETY: `reg` points to the saved exception frame for this IRQ and
        // remains valid for the duration of the handler call.
        handler(unsafe { &mut *reg });
        return;
    }
    common_handler(reg, "irq_handler" as *const _ as *const u8);
}
