use core::ffi::CStr;
use cpu::Registers;
use print::println;

#[inline(always)]
fn cstr_safe(ptr: *const u8) -> &'static str {
    if ptr.is_null() {
        return "<null>";
    }
    unsafe {
        match CStr::from_ptr(ptr).to_str() {
            Ok(s) => s,
            Err(_) => "<invalid-utf8>",
        }
    }
}

pub(crate) extern "C" fn common_handler(reg: *mut Registers, name: *const u8) -> ! {
    let name = cstr_safe(name);
    println!("\n\n=== EXCEPTION: {} ===", name);
    unsafe {
        let r = &*reg;
        println!(
            "x0 =0x{:016x} x1 =0x{:016x} x2 =0x{:016x} x3 =0x{:016x}",
            r.x0, r.x1, r.x2, r.x3
        );
        println!(
            "x4 =0x{:016x} x5 =0x{:016x} x6 =0x{:016x} x7 =0x{:016x}",
            r.x4, r.x5, r.x6, r.x7
        );
        println!(
            "x8 =0x{:016x} x9 =0x{:016x} x10=0x{:016x} x11=0x{:016x}",
            r.x8, r.x9, r.x10, r.x11
        );
        println!(
            "x12=0x{:016x} x13=0x{:016x} x14=0x{:016x} x15=0x{:016x}",
            r.x12, r.x13, r.x14, r.x15
        );
        println!(
            "x16=0x{:016x} x17=0x{:016x} x18=0x{:016x} x19=0x{:016x}",
            r.x16, r.x17, r.x18, r.x19
        );
        println!(
            "x20=0x{:016x} x21=0x{:016x} x22=0x{:016x} x23=0x{:016x}",
            r.x20, r.x21, r.x22, r.x23
        );
        println!(
            "x24=0x{:016x} x25=0x{:016x} x26=0x{:016x} x27=0x{:016x}",
            r.x24, r.x25, r.x26, r.x27
        );
        println!(
            "x28=0x{:016x} fp =0x{:016x} lr =0x{:016x} xzr=0x{:016x}",
            r.x28, r.x29, r.x30, r.x31
        );

        let (mut spsr, mut elr, mut esr, mut far): (u64, u64, u64, u64);
        core::arch::asm!(
            "mrs {0}, spsr_el2",
            "mrs {1}, elr_el2",
            "mrs {2}, esr_el2",
            "mrs {3}, far_el2",
            out(reg) spsr, out(reg) elr, out(reg) esr, out(reg) far
        );
        println!(
            "SPSR=0x{:016x} ELR=0x{:016x} ESR=0x{:08x} FAR=0x{:016x}",
            spsr, elr, esr as u32 as u64, far
        );
    }
    panic!("exception: {}", name);
}
