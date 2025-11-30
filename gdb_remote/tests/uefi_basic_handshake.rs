#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use allocator;
use core::convert::Infallible;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use gdb_remote::GdbServer;
use gdb_remote::Target;
use print::debug_uart;
use print::pl011::Pl011Uart;
use print::stream::Pl011Stream;

const UART_BASE: usize = 0x900_0000;
const UART_CLOCK_HZ: u32 = 48 * 1_000_000;

const TEST_HEAP_SIZE: usize = 2 * 1024 * 1024;
static mut TEST_HEAP: [u8; TEST_HEAP_SIZE] = [0; TEST_HEAP_SIZE];
static HEAP_READY: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    debug_uart::init(UART_BASE, UART_CLOCK_HZ);

    if let Err(err) = setup_allocator() {
        let _ = err;
        exit_failure();
    }

    let uart = Pl011Uart::new(UART_BASE);
    uart.init(UART_CLOCK_HZ, 115200);
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

fn setup_allocator() -> Result<(), &'static str> {
    if HEAP_READY.load(Ordering::SeqCst) {
        return Ok(());
    }

    allocator::init();
    let heap_start = unsafe { core::ptr::addr_of_mut!(TEST_HEAP) as usize };
    allocator::add_available_region(heap_start, TEST_HEAP_SIZE)?;
    allocator::finalize()?;
    HEAP_READY.store(true, Ordering::SeqCst);
    Ok(())
}

struct DummyTarget;

impl Target for DummyTarget {
    type Error = Infallible;

    fn read_registers(&mut self, dst: &mut [u8]) -> Result<usize, Self::Error> {
        dst.fill(0);
        Ok(dst.len().min(16))
    }

    fn write_registers(&mut self, _src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn read_register(&mut self, _regno: u32, dst: &mut [u8]) -> Result<usize, Self::Error> {
        if !dst.is_empty() {
            dst[0] = 0;
            return Ok(1);
        }
        Ok(0)
    }

    fn write_register(&mut self, _regno: u32, _src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn read_memory(&mut self, _addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(0);
        Ok(())
    }

    fn write_memory(&mut self, _addr: u64, _src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn insert_sw_breakpoint(&mut self, _addr: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn remove_sw_breakpoint(&mut self, _addr: u64) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = info;
    exit_failure();
}
