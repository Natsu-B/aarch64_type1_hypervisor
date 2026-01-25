use crate::common_handler;
use cpu::Registers;

static IRQ_HANDLER_NAME: &[u8] = b"irq_handler\0";

pub(crate) extern "C" fn irq_handler(reg: *mut Registers) {
    common_handler(reg, IRQ_HANDLER_NAME.as_ptr());
}
