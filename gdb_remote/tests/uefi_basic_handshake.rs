#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use aarch64_test::exit_failure;
use aarch64_test::exit_success;
use core::convert::Infallible;
use core::hint::spin_loop;
use gdb_remote::GdbServer;
use gdb_remote::ProcessResult;
use gdb_remote::Target;
use gdb_remote::TargetCapabilities;
use gdb_remote::TargetError;
use print::debug_uart;
use print::pl011::Pl011Uart;

// Use the 2nd PL011 (UART1) on QEMU virt for the RSP channel.
// UART0 is typically used as the UEFI firmware console and can inject non-RSP output.
const UART_BASE: usize = 0x904_0000;
// QEMU virt PL011 UARTs run at 24MHz.
const UART_CLOCK_HZ: u32 = 24 * 1_000_000;

// AArch64 core regset (x0-x30, sp, pc, cpsr).
const CORE_REG_BYTES: usize = 31 * 8 + 8 + 8 + 4;

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    debug_uart::init(UART_BASE, UART_CLOCK_HZ as u64, 115200);

    let mut uart = Pl011Uart::new(UART_BASE, UART_CLOCK_HZ as u64);
    uart.init(115200);
    // Drain any stale bytes (should be empty for UART1, but keep it defensive).
    uart.drain_rx();
    let mut server: GdbServer<2048, 4096> = GdbServer::new();
    let mut target = DummyTarget;
    let mut tx_hold: Option<u8> = None;

    loop {
        let mut progress = false;

        while let Some(byte) = uart.try_read_byte() {
            progress = true;
            match server.on_rx_byte_irq(&mut target, byte) {
                Ok(ProcessResult::MonitorExit) => exit_success(),
                Ok(ProcessResult::Resume(_)) => {}
                Ok(ProcessResult::None) => {}
                Err(_) => exit_failure(),
            }
        }

        if let Some(byte) = tx_hold {
            if uart.try_write_byte(byte) {
                tx_hold = None;
                progress = true;
            }
        }

        while tx_hold.is_none() {
            let Some(byte) = server.pop_tx_byte_irq() else {
                break;
            };
            if uart.try_write_byte(byte) {
                progress = true;
            } else {
                tx_hold = Some(byte);
                break;
            }
        }

        if !progress {
            spin_loop();
        }
    }
}

struct DummyTarget;

type DummyError = TargetError<Infallible, Infallible>;

const DUMMY_REG: u64 = 0x0000_0000_4000_0000;

impl Target for DummyTarget {
    type RecoverableError = Infallible;
    type UnrecoverableError = Infallible;

    fn capabilities(&self) -> TargetCapabilities {
        TargetCapabilities::SW_BREAK | TargetCapabilities::VCONT
    }

    fn read_registers(&mut self, dst: &mut [u8]) -> Result<usize, DummyError> {
        if dst.len() < CORE_REG_BYTES {
            return Err(TargetError::NotSupported);
        }
        // Fill a minimal AArch64 core regset:
        // x0..x30, sp, pc are 64-bit; cpsr is 32-bit.
        let r64 = DUMMY_REG.to_le_bytes();
        let mut off = 0usize;
        // 33 x 64-bit regs: x0..x30 (31) + sp (1) + pc (1)
        for _ in 0..=32 {
            dst[off..off + 8].copy_from_slice(&r64);
            off += 8;
        }
        // cpsr (32-bit)
        dst[off..off + 4].copy_from_slice(&(DUMMY_REG as u32).to_le_bytes());
        Ok(CORE_REG_BYTES)
    }

    fn write_registers(&mut self, _src: &[u8]) -> Result<(), DummyError> {
        Ok(())
    }

    fn read_register(&mut self, _regno: u32, dst: &mut [u8]) -> Result<usize, DummyError> {
        // Match the same minimal AArch64 core regset:
        // 0..=30: x0..x30 (8 bytes)
        // 31: sp (8 bytes)
        // 32: pc (8 bytes)
        // 33: cpsr (4 bytes)
        let need = match _regno {
            0..=32 => 8,
            33 => 4,
            _ => return Err(TargetError::NotSupported),
        };
        if dst.len() < need {
            return Err(TargetError::NotSupported);
        }
        let r64 = DUMMY_REG.to_le_bytes();
        dst[..need].copy_from_slice(&r64[..need]);
        Ok(need)
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

    fn insert_hw_breakpoint(&mut self, _addr: u64, _kind: u64) -> Result<(), DummyError> {
        Err(TargetError::NotSupported)
    }

    fn remove_hw_breakpoint(&mut self, _addr: u64, _kind: u64) -> Result<(), DummyError> {
        Err(TargetError::NotSupported)
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = info;
    exit_failure();
}
