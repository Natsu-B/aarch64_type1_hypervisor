use core::cell::SyncUnsafeCell;

use crate::Registers;
use crate::registers;
use crate::registers::ESR_EL2;
use crate::registers::ExceptionClass;
use crate::registers::HPFAR_EL2;
use crate::registers::InstructionRegisterSize;
use crate::registers::SyndromeAccessSize;
use crate::registers::WriteNotRead;

pub type DataAbortHandler =
    fn(&mut u64, u64, InstructionRegisterSize, SyndromeAccessSize, WriteNotRead);

static SYNCHRONOUS_HANDLER: SyncUnsafeCell<SynchronousHandler> =
    SyncUnsafeCell::new(SynchronousHandler {
        data_abort_func: None,
    });

struct SynchronousHandler {
    data_abort_func: Option<DataAbortHandler>,
}

pub fn set_data_abort_handler(handler: DataAbortHandler) {
    unsafe { &mut *SYNCHRONOUS_HANDLER.get() }.data_abort_func = Some(handler);
}

pub(crate) extern "C" fn synchronous_handler(reg: *mut Registers) {
    let reg = unsafe { &mut *reg };
    let esr_el2 = ESR_EL2::from_bits(cpu::get_esr_el2());
    match esr_el2.get_enum::<_, ExceptionClass>(ESR_EL2::ec) {
        Some(ec) if ec == ExceptionClass::DataAbortFormLowerLevel => {
            // Data Abort
            if esr_el2.get(ESR_EL2::isv) == 0 {
                panic!("Data Abort Info is not available");
            }
            let reg_size: InstructionRegisterSize = esr_el2.get_enum(ESR_EL2::sf).unwrap();
            let access_width: SyndromeAccessSize = esr_el2.get_enum(ESR_EL2::sas).unwrap();
            let write_access: WriteNotRead = esr_el2.get_enum(ESR_EL2::wnr).unwrap();
            let reg_num = esr_el2.get(ESR_EL2::srt);

            let register: &mut u64 =
                &mut unsafe { &mut *(reg as *mut _ as usize as *mut [u64; 32]) }[reg_num as usize];
            let addr = HPFAR_EL2::from_bits(cpu::get_hpfar_el2()).get(HPFAR_EL2::fipa)
                << registers::HPFAR_OFFSET
                | (cpu::get_far_el2() & ((1 << registers::HPFAR_OFFSET) - 1));

            unsafe { &*SYNCHRONOUS_HANDLER.get() }
                .data_abort_func
                .unwrap()(register, addr, reg_size, access_width, write_access);
        }
        _ => panic!("unkown ESR_EL2 EC value: {}", esr_el2.get(ESR_EL2::ec)),
    }
}
