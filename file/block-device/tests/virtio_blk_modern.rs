#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use arch_hal::debug_uart;
use arch_hal::exit_failure;
use arch_hal::exit_success;
use arch_hal::println;
use block_device::VirtIoBlk;
use block_device_api::BlockDevice;
use core::mem::MaybeUninit;
use core::slice;

const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    debug_uart::init(0x900_0000, 48 * 1000 * 1000, 115200);
    match run() {
        Ok(()) => {
            println!("virtio-blk modern interface test: PASS");
            exit_success();
        }
        Err(err) => {
            println!("virtio-blk modern interface test: FAIL: {}", err);
            exit_failure();
        }
    }
}

fn run() -> Result<(), &'static str> {
    const TOTAL_BYTES: usize = 3 * 512;

    println!("Starting virtio_blk test");
    let mut device = VirtIoBlk::new(VIRTIO_MMIO_BASE).unwrap();
    println!("new() succeeded");
    device.init().unwrap();
    println!("init() succeeded");
    if device.is_read_only().unwrap() {
        return Err("device unexpectedly read-only");
    }
    assert_eq!(device.num_blocks(), 3);

    let block_size = device.block_size();
    if block_size == 0 {
        return Err("block size is zero");
    }
    if block_size > 4096 {
        return Err("block size too large for test buffer");
    }
    println!("Attempting to read...");
    let mut buffer: [MaybeUninit<u8>; 512] = [MaybeUninit::uninit(); 512];
    device.read_at(0, &mut buffer).unwrap();
    // SAFETY: `read_at()` succeeded, so the block device contract guarantees every byte in
    // `buffer` was initialized and may be viewed as a mutable `[u8]`.
    let slice = unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len()) };
    let text = str::from_utf8(slice).unwrap();
    println!("device text: {}", text);
    assert_eq!(
        "This is a simple test message. If you are reading these words, it means that the program is working correctly. There is nothing important here, only a demonstration to check the output. Please ignore this text, because it is written only for testing and debugging purposes. Thank you for your patience! In fact, this message has no real meaning other than to confirm that everything is running as expected. You might see it on your screen, in a console, or inside a log file. The exact place does not matter, bec",
        text
    );

    println!("Attempting multi-sector write/read with chunking...");
    let mut write_pattern = [0u8; TOTAL_BYTES];
    for (idx, byte) in write_pattern.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(13).wrapping_add(7);
    }
    device.write_at(0, &write_pattern).unwrap();

    let mut verify: [MaybeUninit<u8>; TOTAL_BYTES] = [MaybeUninit::uninit(); TOTAL_BYTES];
    device.read_at(0, &mut verify).unwrap();
    // SAFETY: `read_at()` succeeded, so the block device contract guarantees every byte in
    // `verify` was initialized and may be viewed as an immutable `[u8]`.
    let verify_bytes = unsafe { slice::from_raw_parts(verify.as_ptr() as *const u8, verify.len()) };
    assert_eq!(verify_bytes, &write_pattern);

    device.flush().unwrap();
    Ok(())
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info);
    exit_failure()
}
