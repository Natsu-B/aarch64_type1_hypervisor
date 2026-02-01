#![no_std]

pub mod pl011;
use core::cell::OnceCell;
use core::fmt::Write;
use core::fmt::{self};

use mutex::RawSpinLock;

pub use pl011::Pl011Uart;

pub static DEBUG_UART: RawSpinLock<DebugUart> = RawSpinLock::new(DebugUart::new());

pub struct DebugUart {
    uart: OnceCell<Pl011Uart>,
}

impl Default for DebugUart {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugUart {
    pub const fn new() -> DebugUart {
        DebugUart {
            uart: OnceCell::new(),
        }
    }

    pub fn init(&mut self, uart_peripherals: usize, uart_clk: u64, baud_rate: u32) {
        let mut uart = Pl011Uart::new(uart_peripherals, uart_clk);
        uart.init(baud_rate);

        match self.uart.set(uart) {
            Ok(_) => (),
            Err(_) => panic!("UART already initialized"),
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut Pl011Uart> {
        self.uart.get_mut()
    }
}

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
macro_rules! print_force {
    ($($arg:tt)*) => {
        ($crate::_print_force(format_args!($($arg)*)));
    };
}

#[macro_export]
macro_rules! println_force {
    () => {$crate::print_force!("\n");};
    ($fmt:expr, $($arg:tt)+) => {
        $crate::print_force!(concat!($fmt, "\n"), $($arg)*);
    };
    ($fmt:expr) => {
        $crate::print_force!(concat!($fmt, "\n"));
    };
}

#[macro_export]
macro_rules! pr_trace {
    () => {
        $crate::print!("{}:{}\n", file!(), line!())
    };
}

pub fn init(uart_peripherals: usize, uart_clk: u64, baud_rate: u32) {
    DEBUG_UART
        .lock()
        .init(uart_peripherals, uart_clk, baud_rate);
}

pub fn write(args: fmt::Arguments) {
    DEBUG_UART
        .lock()
        .get_mut()
        .unwrap()
        .write_fmt(args)
        .unwrap();
}

pub fn _print(args: fmt::Arguments) {
    write(args);
}

pub fn _print_force(args: fmt::Arguments) {
    // SAFETY: Caller must ensure this is only used in contexts where taking the lock
    // would deadlock (e.g. panic path), and accept potential interleaving.
    unsafe { DEBUG_UART.no_lock() }
        .get_mut()
        .unwrap()
        .write_fmt(args)
        .unwrap();
}

pub fn flush() {
    DEBUG_UART.lock().get_mut().unwrap().flush();
}

pub mod debug_uart {
    use super::*;

    pub fn init(uart_peripherals: usize, uart_clk: u64, baud_rate: u32) {
        super::init(uart_peripherals, uart_clk, baud_rate);
    }

    pub fn write(s: &str) {
        let mut guard = DEBUG_UART.lock();
        if let Some(uart) = guard.get_mut() {
            uart.write(s);
        }
    }

    pub fn print_force(args: fmt::Arguments) {
        // SAFETY: Caller must ensure this is only used in contexts where taking the lock
        // would deadlock (e.g. panic path), and accept potential interleaving.
        unsafe { DEBUG_UART.no_lock() }
            .get_mut()
            .unwrap()
            .write_fmt(args)
            .unwrap();
    }

    /// Configure PL011 RX-related interrupts (FIFO trigger + timeout).
    ///
    /// Intended for early bring-up. This function takes the lock.
    pub fn enable_rx_interrupts(level: pl011::FifoLevel, enable_timeout: bool) {
        let mut guard = DEBUG_UART.lock();
        let Some(uart) = guard.get_mut() else { return };

        uart.enable_rx_interrupts(level, enable_timeout);
    }

    /// IRQ-context RX handler that never takes the lock.
    ///
    /// # Safety
    /// This uses `no_lock()` to avoid deadlocks if IRQs can preempt code holding the lock.
    /// The caller must accept concurrent access/interleaving on the UART MMIO.
    pub fn handle_rx_irq_force(mut on_byte: impl FnMut(u8)) {
        // SAFETY: see doc comment.
        let mut guard = unsafe { DEBUG_UART.no_lock() };
        let Some(uart) = guard.get_mut() else { return };

        uart.handle_rx_irq(&mut on_byte);
    }
}
