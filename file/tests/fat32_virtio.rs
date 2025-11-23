#![no_std]
#![no_main]

#[cfg(not(target_arch = "aarch64"))]
compile_error!("This test is intended to run on aarch64 targets only");

use arch_hal::debug_uart;
use arch_hal::exit_failure;
use arch_hal::exit_success;
use arch_hal::println;
use core::str;
use file::StorageDevice;
use file::StorageDeviceErr;
use filesystem::FileSystemErr;

const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;
const HELLO_TXT: &str = "HelloWorld, from FAT32 txt file!!!";
const HELLO_WRITE_PAYLOAD: &str =
    "FAT32 write path updated this file with a longer piece of text to verify overwrites.";
const HELLO_APPEND_PAYLOAD: &str =
    " Additional appended payload to ensure extending a file is also supported.";
const HELLO_FINAL_TXT: &str = "FAT32 write path updated this file with a longer piece of text to verify overwrites. Additional appended payload to ensure extending a file is also supported.";

#[unsafe(no_mangle)]
extern "C" fn efi_main() -> ! {
    debug_uart::init(0x900_0000, 48 * 1000 * 1000);
    match run() {
        Ok(()) => {
            println!("fat32_virtio test: PASS");
            exit_success();
        }
        Err(err) => {
            println!("fat32_virtio test: FAIL: {}", err);
            exit_failure();
        }
    }
}

fn run() -> Result<(), &'static str> {
    println!("Starting fat32_virtio test");
    let device = StorageDevice::new_virtio(VIRTIO_MMIO_BASE).unwrap();
    println!("fat32_virtio init success");
    let handle = device
        .open(0, "/hello.txt", &file::OpenOptions::Read)
        .unwrap();
    let txt = handle.read(1).unwrap();
    let txt = str::from_utf8(&txt).unwrap();
    println!("device text: {}", txt);
    assert_eq!(HELLO_TXT, txt);
    handle.flush().unwrap();
    assert_eq!(handle.size().unwrap(), txt.len() as u64);

    // FAT32 write tests
    let mut hello_writer = device
        .open(0, "/hello.txt", &file::OpenOptions::Write)
        .unwrap();
    let written = hello_writer
        .write_at(0, HELLO_WRITE_PAYLOAD.as_bytes())
        .unwrap();
    assert_eq!(written as usize, HELLO_WRITE_PAYLOAD.len());
    hello_writer.flush().unwrap();
    assert_eq!(
        hello_writer.size().unwrap(),
        HELLO_WRITE_PAYLOAD.len() as u64
    );
    let read_back = device
        .open(0, "/hello.txt", &file::OpenOptions::Read)
        .unwrap();
    let txt = read_back.read(1).unwrap();
    let txt = str::from_utf8(&txt).unwrap();
    assert_eq!(HELLO_WRITE_PAYLOAD, txt);

    let append_written = hello_writer
        .write_at(
            HELLO_WRITE_PAYLOAD.len() as u64,
            HELLO_APPEND_PAYLOAD.as_bytes(),
        )
        .unwrap();
    assert_eq!(append_written as usize, HELLO_APPEND_PAYLOAD.len());
    hello_writer.flush().unwrap();
    assert_eq!(hello_writer.size().unwrap(), HELLO_FINAL_TXT.len() as u64);
    let read_back = device
        .open(0, "/hello.txt", &file::OpenOptions::Read)
        .unwrap();
    let txt = read_back.read(1).unwrap();
    let txt = str::from_utf8(&txt).unwrap();
    assert_eq!(HELLO_FINAL_TXT, txt);

    let handle = device
        .open(
            0,
            "/very_long_long_example_text.TXT",
            &file::OpenOptions::Read,
        )
        .unwrap();
    let txt = &handle.read(1).unwrap();
    let txt = str::from_utf8(txt).unwrap();
    println!("long long text: {}", txt);
    assert_eq!(
        "This is a simple test message. If you are reading these words, it means that the program is working correctly. There is nothing important here, only a demonstration to check the output. Please ignore this text, because it is written only for testing and debugging purposes. Thank you for your patience! In fact, this message has no real meaning other than to confirm that everything is running as expected. You might see it on your screen, in a console, or inside a log file. The exact place does not matter, because the purpose is always the same: to provide a harmless, human-readable signal that the system is alive. If you see this text, you can be confident that the process of displaying or printing strings is functioning.Once again, please remember that this is not real content. It is just a placeholder, sometimes called a “dummy message” or “sample output.” Developers often use texts like this to make sure their tools, devices, or programs are responding. If you read it twice or even three times, you will still find nothing new, because repetition is part of the test. The message is intentionally long, so that you can check how wrapping, spacing, and formatting behave when more than a few sentences are displayed.",
        txt
    );
    assert_eq!(
        device
            .open(0, "/EFI/hoge", &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );
    let efi = device
        .open(0, "/EFI/BOOT/BOOTAA64.EFI", &file::OpenOptions::Read)
        .unwrap();
    efi.read(1).unwrap();

    test_dir_and_file_ops(&device)?;

    // Create a file and directory to check from host
    device.create_dir(0, "/testdir").unwrap();
    let mut handle = device.create_file(0, "/testdir/testfile.txt").unwrap();
    handle.write_at(0, "test content".as_bytes()).unwrap();
    handle.flush().unwrap();

    Ok(())
}

fn test_dir_and_file_ops(device: &StorageDevice) -> Result<(), &'static str> {
    println!("Testing directory and file operations");

    // 8.3 directory
    let dir_8_3 = "/DIR83";
    device.create_dir(0, dir_8_3).unwrap();
    // create long name file
    let file_name = "/DIR83/very_long_long_example_text.TXT";
    device.create_file(0, file_name).unwrap();
    let mut file_handle = device
        .open(0, file_name, &file::OpenOptions::Write)
        .unwrap();
    assert_eq!(file_handle.size().unwrap(), 0);
    let write_txt = "hello fat32 world!!!!!!!";
    assert_eq!(
        file_handle.write_at(0, write_txt.as_bytes()).unwrap(),
        write_txt.len() as u64
    );
    assert_eq!(file_handle.size().unwrap(), write_txt.len() as u64);
    assert_eq!(
        str::from_utf8(&*file_handle.read(1).unwrap()).unwrap(),
        write_txt
    );
    device.remove_file(0, file_name).unwrap();
    device
        .open(0, file_name, &file::OpenOptions::Read)
        .unwrap_err();

    device.remove_dir(0, dir_8_3).unwrap();
    assert_eq!(
        device
            .open(0, dir_8_3, &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );

    // Long name directory
    let dir_long = "/long_dir_name";
    device.create_dir(0, dir_long).unwrap();
    device.remove_dir(0, dir_long).unwrap();
    assert_eq!(
        device
            .open(0, dir_long, &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );

    // 8.3 file
    let file_8_3 = "/FILE83.TXT";
    let handle = device.create_file(0, file_8_3).unwrap();
    handle.flush().unwrap();
    device.open(0, file_8_3, &file::OpenOptions::Read).unwrap();
    device.remove_file(0, file_8_3).unwrap();
    assert_eq!(
        device
            .open(0, file_8_3, &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );

    // Long name file
    let file_long = "/long_file_name.txt";
    let handle = device.create_file(0, file_long).unwrap();
    handle.flush().unwrap();
    device.open(0, file_long, &file::OpenOptions::Read).unwrap();
    device.remove_file(0, file_long).unwrap();
    assert_eq!(
        device
            .open(0, file_long, &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );

    // Rename file
    let rename_from = "/rename_from.txt";
    let rename_to = "/rename_to.txt";
    let mut handle = device.create_file(0, rename_from).unwrap();
    let content = "rename test";
    handle.write_at(0, content.as_bytes()).unwrap();
    handle.flush().unwrap();
    device.rename(0, rename_from, rename_to).unwrap();
    assert_eq!(
        device
            .open(0, rename_from, &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );
    let handle = device.open(0, rename_to, &file::OpenOptions::Read).unwrap();
    let read_content = handle.read(1).unwrap();
    assert_eq!(str::from_utf8(&read_content).unwrap(), content);
    device.remove_file(0, rename_to).unwrap();

    // Rename directory
    let rename_dir_from = "/rename_dir_from";
    let rename_dir_to = "/rename_dir_to";
    device.create_dir(0, rename_dir_from).unwrap();
    device.rename(0, rename_dir_from, rename_dir_to).unwrap();
    assert_eq!(
        device
            .open(0, rename_dir_from, &file::OpenOptions::Read)
            .unwrap_err(),
        StorageDeviceErr::FileSystemErr(FileSystemErr::NotFound)
    );
    device.remove_dir(0, rename_dir_to).unwrap();

    // Copy file
    let copy_from = "/copy_from.txt";
    let copy_to = "/copy_to.txt";
    let mut handle = device.create_file(0, copy_from).unwrap();
    let content = "copy test";
    handle.write_at(0, content.as_bytes()).unwrap();
    handle.flush().unwrap();
    device.copy(0, copy_from, copy_to).unwrap();
    let handle_from = device.open(0, copy_from, &file::OpenOptions::Read).unwrap();
    let handle_to = device.open(0, copy_to, &file::OpenOptions::Read).unwrap();
    let content_from = handle_from.read(1).unwrap();
    let content_to = handle_to.read(1).unwrap();
    assert_eq!(str::from_utf8(&content_from).unwrap(), content);
    assert_eq!(str::from_utf8(&content_to).unwrap(), content);
    device.remove_file(0, copy_from).unwrap();
    device.remove_file(0, copy_to).unwrap();

    println!("Directory and file operations test: PASS");
    Ok(())
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("PANIC: {}", info);
    exit_failure()
}
