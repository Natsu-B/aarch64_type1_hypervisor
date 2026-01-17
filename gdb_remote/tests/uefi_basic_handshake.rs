#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use core::convert::Infallible;
use gdb_remote::GdbServer;
use gdb_remote::Target;
use gdb_remote::TargetCapabilities;
use gdb_remote::TargetError;
use print::debug_uart;
use print::pl011::Pl011Uart;
use print::stream::Pl011Stream;

const UART_BASE: usize = 0x900_0000;
const UART_CLOCK_HZ: u32 = 48 * 1_000_000;

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    debug_uart::init(UART_BASE, UART_CLOCK_HZ as u64, 115200);

    let mut uart = Pl011Uart::new(UART_BASE, UART_CLOCK_HZ as u64);
    uart.init(115200);
    uart.drain_rx(); // drop any firmware banner noise before speaking RSP
    let stream = Pl011Stream::new(&uart);
    let mut server: GdbServer<_, 1024> = GdbServer::new(stream);
    let mut target = DummyTarget;

    match server.run_until_monitor_exit(&mut target) {
        Ok(()) => {
            exit_success();
        }
        Err(_) => {
            exit_failure();
        }
    }
}

struct DummyTarget;

type DummyError = TargetError<Infallible, Infallible>;

impl Target for DummyTarget {
    type RecoverableError = Infallible;
    type UnrecoverableError = Infallible;

    fn capabilities(&self) -> TargetCapabilities {
        TargetCapabilities::SW_BREAK | TargetCapabilities::VCONT
    }

    fn read_registers(&mut self, dst: &mut [u8]) -> Result<usize, DummyError> {
        dst.fill(0);
        Ok(dst.len().min(16))
    }

    fn write_registers(&mut self, _src: &[u8]) -> Result<(), DummyError> {
        Ok(())
    }

    fn read_register(&mut self, _regno: u32, dst: &mut [u8]) -> Result<usize, DummyError> {
        if !dst.is_empty() {
            dst[0] = 0;
            return Ok(1);
        }
        Ok(0)
    }

    fn write_register(&mut self, _regno: u32, _src: &[u8]) -> Result<(), DummyError> {
        Ok(())
    }

    fn read_memory(&mut self, _addr: u64, dst: &mut [u8]) -> Result<(), DummyError> {
        dst.fill(0);
        Ok(())
    }

    fn write_memory(&mut self, _addr: u64, _src: &[u8]) -> Result<(), DummyError> {
        Ok(())
    }

    fn insert_sw_breakpoint(&mut self, _addr: u64) -> Result<(), DummyError> {
        Ok(())
    }

    fn remove_sw_breakpoint(&mut self, _addr: u64) -> Result<(), DummyError> {
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = info;
    exit_failure();
}
