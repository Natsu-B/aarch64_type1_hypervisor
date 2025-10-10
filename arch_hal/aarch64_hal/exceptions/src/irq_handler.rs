use crate::Registers;
use crate::common_handler::common_handler;

pub(crate) extern "C" fn irq_handler(reg: *mut Registers) {
    common_handler(reg, "irq_handler" as *const _ as *const u8);
}
