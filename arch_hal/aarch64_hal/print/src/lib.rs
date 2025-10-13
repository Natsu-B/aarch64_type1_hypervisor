#![no_std]
#![feature(once_cell_get_mut)]
#![feature(sync_unsafe_cell)]

pub mod pl011;
use core::cell::SyncUnsafeCell;
use core::fmt::Write;
use core::fmt::{self};

use pl011::Pl011Uart;

#[deprecated(note = "DEBUG_UART uses SyncUnsafeCell so do not use it in multicore system")]
pub static DEBUG_UART: SyncUnsafeCell<Option<Pl011Uart>> = SyncUnsafeCell::new(None);

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($fmt:expr, $($arg:tt)+) => ($crate::print!(concat!($fmt, "\n"), $($arg)*));
    ($fmt:expr) => ($crate::print!(concat!($fmt, "\n")));
}

#[macro_export]
macro_rules! pr_trace {
    () => {
        $crate::print!("{}:{}\n", file!(), line!())
    };
}

pub mod debug_uart {
    use pl011::Pl011Uart;

    use crate::DEBUG_UART;
    use crate::pl011;

    pub fn init(base_address: usize) {
        let uart = Pl011Uart::new(base_address);
        let debug_uart = unsafe { &mut *DEBUG_UART.get() };
        *debug_uart = Some(uart);
    }
}

pub fn _print(args: fmt::Arguments) {
    let uart = unsafe { &mut *(DEBUG_UART.get()) };
    let uart = uart.get_or_insert_with(|| Pl011Uart::new(0x10_7D00_1000));
    uart.write_fmt(args).unwrap();
}
