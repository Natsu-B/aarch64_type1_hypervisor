use core::arch::asm;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

const CANARY_QWORDS: usize = 8; // 8 * 8 = 64 bytes
const CANARY_VALUE: u64 = 0xC0FFEE00_DEAD_BEEFu64;

unsafe extern "C" {
    static __stack_bottom: u8;
    static __stack_top: u8;
}

#[inline(always)]
fn sp() -> usize {
    let sp: usize;
    unsafe {
        asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

#[inline(always)]
fn uart_write_byte(byte: u8) {
    // SAFETY: `no_lock()` requires no concurrent access. The u-boot unit-test harness
    // runs single-core and is expected to use the debug UART from one context here.
    let mut guard = unsafe { print::DEBUG_UART.no_lock() };
    if let Some(uart) = guard.get_mut() {
        uart.write_byte(byte);
    }
}

#[inline(always)]
fn uart_write_str(s: &str) {
    for &b in s.as_bytes() {
        uart_write_byte(b);
    }
}

#[inline(always)]
fn uart_write_hex_usize(v: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    uart_write_str("0x");
    let nibbles = core::mem::size_of::<usize>() * 2;
    for i in (0..nibbles).rev() {
        let shift = i * 4;
        let nib = ((v >> shift) & 0xF) as usize;
        uart_write_byte(HEX[nib]);
    }
}

#[inline(always)]
fn uart_write_nl() {
    uart_write_byte(b'\n');
}

pub fn init() {
    let bottom = core::ptr::addr_of!(__stack_bottom) as usize;
    let top = core::ptr::addr_of!(__stack_top) as usize;

    // Basic sanity
    if bottom == 0 || top == 0 || bottom >= top {
        uart_write_str("stack_canary: invalid stack symbols\n");
        return;
    }

    // Write canary region at the bottom of stack.
    // SAFETY: `bottom..bottom+CANARY_QWORDS*8` must be inside the stack region and writable.
    unsafe {
        let p = bottom as *mut u64;
        for i in 0..CANARY_QWORDS {
            write_volatile(p.add(i), CANARY_VALUE);
        }
    }
}

pub fn check_or_abort(context: &'static str) {
    let bottom = core::ptr::addr_of!(__stack_bottom) as usize;
    let top = core::ptr::addr_of!(__stack_top) as usize;

    // SAFETY: same as init(); read-only here.
    let ok = unsafe {
        let p = bottom as *const u64;
        (0..CANARY_QWORDS).all(|i| read_volatile(p.add(i)) == CANARY_VALUE)
    };

    if ok {
        return;
    }

    uart_write_str("\n*** STACK CANARY CORRUPTED ***\ncontext=");
    uart_write_str(context);
    uart_write_nl();

    uart_write_str("stack_bottom=");
    uart_write_hex_usize(bottom);
    uart_write_str(" stack_top=");
    uart_write_hex_usize(top);
    uart_write_str(" sp=");
    uart_write_hex_usize(sp());
    uart_write_nl();

    // Stop immediately to avoid further corruption.
    aarch64_test::exit_failure();
}
