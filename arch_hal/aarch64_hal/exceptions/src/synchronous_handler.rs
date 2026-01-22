use core::cell::SyncUnsafeCell;
use core::u64;

use crate::registers;
use crate::registers::ESR_EL2;
use crate::registers::ExceptionClass;
use crate::registers::HPFAR_EL2;
use crate::registers::InstructionRegisterSize;
use crate::registers::SyndromeAccessSize;
use crate::registers::WriteNotRead;
use cpu::Registers;
use cpu::get_elr_el2;
use cpu::get_far_el2;
use cpu::va_to_ipa_el2;
use print::println;
use psci::handle_secure_monitor_call;

pub type DataAbortHandler =
    fn(&mut u64, u64, InstructionRegisterSize, SyndromeAccessSize, WriteNotRead);
pub type DebugExceptionHandler = fn(&mut Registers, ExceptionClass);

static SYNCHRONOUS_HANDLER: SyncUnsafeCell<SynchronousHandler> =
    SyncUnsafeCell::new(SynchronousHandler {
        data_abort_func: None,
        debug_func: None,
    });

struct SynchronousHandler {
    data_abort_func: Option<DataAbortHandler>,
    debug_func: Option<DebugExceptionHandler>,
}

pub fn set_data_abort_handler(handler: DataAbortHandler) {
    unsafe { &mut *SYNCHRONOUS_HANDLER.get() }.data_abort_func = Some(handler);
}

pub fn set_debug_handler(handler: DebugExceptionHandler) {
    unsafe { &mut *SYNCHRONOUS_HANDLER.get() }.debug_func = Some(handler);
}

pub(crate) extern "C" fn synchronous_handler(reg: *mut Registers) {
    let reg = unsafe { &mut *reg };
    let esr_el2 = ESR_EL2::from_bits(cpu::get_esr_el2());
    match esr_el2.get_enum::<_, ExceptionClass>(ESR_EL2::ec) {
        Some(ec) => {
            match ec {
                ExceptionClass::DataAbortFormLowerLevel => {
                    // Data Abort
                    if esr_el2.get(ESR_EL2::isv) == 0 {
                        panic!(
                            "Data Abort Info is not available\naddr: va: 0x{:X} pa: 0x{:X}\ninstruction addr: va: 0x{:X} pa: 0x{:X}\ninstruction: 0x{:X}\n",
                            get_far_el2(),
                            HPFAR_EL2::from_bits(cpu::get_hpfar_el2()).get(HPFAR_EL2::fipa)
                                << registers::HPFAR_OFFSET
                                | (cpu::get_far_el2() & ((1 << registers::HPFAR_OFFSET) - 1)),
                            get_elr_el2(),
                            va_to_ipa_el2(get_elr_el2()).unwrap(),
                            unsafe { *(va_to_ipa_el2(get_elr_el2()).unwrap() as *const u32) }
                        );
                    }
                    let reg_size: InstructionRegisterSize = esr_el2.get_enum(ESR_EL2::sf).unwrap();
                    let access_width: SyndromeAccessSize = esr_el2.get_enum(ESR_EL2::sas).unwrap();
                    let write_access: WriteNotRead = esr_el2.get_enum(ESR_EL2::wnr).unwrap();
                    let reg_num = esr_el2.get(ESR_EL2::srt);

                    let register = reg.as_array();

                    let addr = HPFAR_EL2::from_bits(cpu::get_hpfar_el2()).get(HPFAR_EL2::fipa)
                        << registers::HPFAR_OFFSET
                        | (cpu::get_far_el2() & ((1 << registers::HPFAR_OFFSET) - 1));

                    unsafe { &*SYNCHRONOUS_HANDLER.get() }
                        .data_abort_func
                        .unwrap()(
                        &mut register[reg_num as usize],
                        addr,
                        reg_size,
                        access_width,
                        write_access,
                    );
                }
                ExceptionClass::SMCInstructionExecution => {
                    let imm16 = esr_el2.get(ESR_EL2::imm16);
                    if imm16 != 0 {
                        // vender specific smc call
                        println!("unknown SMC imm value: 0x{:X}", imm16);
                        reg.x0 = u64::MAX; // SMCCC_RET_NOT_SUPPORTED(-1)
                        return;
                    }
                    handle_secure_monitor_call(reg);
                }
                ExceptionClass::BreakpointLowerLevel
                | ExceptionClass::BrkInstructionAArch64LowerLevel
                | ExceptionClass::SoftwareStepLowerLevel
                | ExceptionClass::WatchpointLowerLevel => {
                    unsafe { &*SYNCHRONOUS_HANDLER.get() }
                        .debug_func
                        .expect("debug handler not registered")(reg, ec);
                }
                _ => panic!("unexpected ESR_EL2 EC value: {:?}", ec),
            }
        }
        _ => panic!("unkown ESR_EL2 EC value: {}", esr_el2.get(ESR_EL2::ec)),
    }
}
