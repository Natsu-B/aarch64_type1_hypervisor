//! Standalone Raspberry Pi 5 RP1 PCIe/UART/DMA-window bring-up validator.

#![no_std]
#![no_main]

use arch_hal::Pl011Uart;
use arch_hal::MirrorOps;
use arch_hal::cpu;
use arch_hal::set_mirror;
use arch_hal::soc::bcm2712;
use arch_hal::soc::bcm2712::rp1::Rp1PeripheralMap;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::arch::asm;
use core::arch::naked_asm;
use core::fmt;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr::null_mut;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use dtb::DtbParser;

const UART_CLOCK_HZ: u64 = 48_000_000;
const UART_BAUD: u32 = 115_200;
const DTB_PTR: usize = 0x2000_0000;
const HEAP_SIZE: usize = 1024 * 1024;
const SEMIHOST_SYS_WRITE: u64 = 0x05;

unsafe extern "C" {
    static mut _BSS_START: usize;
    static mut _BSS_END: usize;
    static mut _STACK_TOP: usize;
}

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAllocator = BumpAllocator;

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        let align_mask = layout.align().saturating_sub(1);
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(layout.size()) else {
                return null_mut();
            };
            if next > HEAP_SIZE {
                return null_mut();
            }

            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: `HEAP` is a dedicated static backing store for this allocator.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() };
                    // SAFETY: `aligned` was bounds-checked against `HEAP_SIZE` above.
                    return unsafe { base.add(aligned) };
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[repr(C, align(64))]
struct DmaPreflightArea {
    tx_buffer: [u8; 64],
    descriptor: [u8; 64],
}

static DMA_PREFLIGHT_AREA: DmaPreflightArea = DmaPreflightArea {
    tx_buffer: [0; 64],
    descriptor: [0; 64],
};

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    naked_asm!(
        r#"
        msr spsel, #1
        isb
        ldr x9, =_STACK_TOP
        mov sp, x9
    clear_bss:
        ldr x9, =_BSS_START
        ldr x10, =_BSS_END
    clear_bss_loop:
        cmp x9, x10
        beq clear_bss_end
        str xzr, [x9], #8
        b clear_bss_loop
    clear_bss_end:
        bl main
    loop:
        wfe
        b loop
        "#
    )
}

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    set_mirror(Some(MirrorOps {
        write: semihost_mirror_write,
        flush: semihost_flush,
    }));
    semihost_log(format_args!("[rpi5-rp1-init] start"));
    semihost_log(format_args!(
        "[rpi5-rp1-init] current EL {}",
        cpu::get_current_el()
    ));
    semihost_log(format_args!("[rpi5-rp1-init] DTB pointer 0x{:x}", DTB_PTR));

    let dtb = match DtbParser::init(DTB_PTR) {
        Ok(dtb) => dtb,
        Err(err) => fail(format_args!("DTB parse failed: {}", err)),
    };

    semihost_log(format_args!("[rpi5-rp1-init] init RP1..."));
    let rp1 = match bcm2712::init_rp1(&dtb) {
        Ok(rp1) => rp1,
        Err(err) => fail(format_args!("RP1 init failed: {:?}", err)),
    };

    log_rp1_config(&rp1);

    let rp1_map = match Rp1PeripheralMap::from_config(&rp1) {
        Ok(map) => map,
        Err(err) => fail(format_args!("RP1 peripheral BAR invalid: {:?}", err)),
    };
    let uart0_base = match rp1_map.rp1_uart0_base() {
        Ok(base) => base,
        Err(err) => fail(format_args!("RP1 UART0 BAR offset invalid: {:?}", err)),
    };
    semihost_log(format_args!("[rpi5-rp1-init] RP1 UART0 base 0x{:x}", uart0_base));

    let gem_base = match rp1_map.rp1_gem_base() {
        Ok(base) => base,
        Err(err) => fail(format_args!("RP1 GEM BAR offset invalid: {:?}", err)),
    };
    semihost_log(format_args!("[rpi5-rp1-init] RP1 GEM base 0x{:x}", gem_base));

    if let Err(reason) = dma_preflight(&rp1) {
        fail(format_args!("DMA PREFLIGHT FAIL: {:?}", reason));
    }
    semihost_log(format_args!("[rpi5-rp1-init] DMA PREFLIGHT PASS"));

    let mut rp1_uart0 = Pl011Uart::new(uart0_base, UART_CLOCK_HZ);
    rp1_uart0.init(UART_BAUD);
    rp1_uart0.write("[rpi5-rp1-init] RP1 UART0 TX PASS\n");

    semihost_log(format_args!(
        "[rpi5-rp1-init] UART DMA SKIP: missing verified RP1 DMA controller registers, DREQ IDs, and channel completion status"
    ));
    semihost_log(format_args!("[rpi5-rp1-init] semihosting still alive"));
    semihost_log(format_args!("[rpi5-rp1-init] PASS"));
    wait_forever()
}

fn log_rp1_config(rp1: &bcm2712::Rp1Config) {
    match rp1.pcie_base {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] PCIe controller 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] PCIe controller unknown")),
    }
    match rp1.peripheral_addr {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] RP1 peripheral BAR 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] RP1 peripheral BAR missing")),
    }
    match rp1.shared_sram_addr {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] RP1 shared SRAM BAR 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] RP1 shared SRAM BAR missing")),
    }
    match rp1.msi_x_table_addr {
        Some((base, size)) => semihost_log(format_args!(
            "[rpi5-rp1-init] RP1 MSI-X table 0x{:x} size 0x{:x}",
            base, size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] RP1 MSI-X table missing")),
    }
    match rp1.dma_window {
        Some(window) => semihost_log(format_args!(
            "[rpi5-rp1-init] DMA window pcie_base=0x{:x} cpu_base=0x{:x} size=0x{:x}",
            window.pcie_base, window.cpu_base, window.size
        )),
        None => semihost_log(format_args!("[rpi5-rp1-init] DMA window missing")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmaPreflightError {
    MissingWindow,
    VaToPaFailed,
    AddressNotCovered,
}

fn dma_preflight(rp1: &bcm2712::Rp1Config) -> Result<(), DmaPreflightError> {
    let window = rp1.dma_window.ok_or(DmaPreflightError::MissingWindow)?;
    let va = core::ptr::addr_of!(DMA_PREFLIGHT_AREA) as *const u8 as usize;
    let len = size_of::<DmaPreflightArea>();
    let phys = cpu::va_to_pa_el2_read(va as u64).ok_or(DmaPreflightError::VaToPaFailed)?;
    let dma = window
        .cpu_phys_to_dma(
            phys,
            u64::try_from(len).map_err(|_| DmaPreflightError::AddressNotCovered)?,
        )
        .map_err(|_| DmaPreflightError::AddressNotCovered)?;

    semihost_log(format_args!(
        "[rpi5-rp1-init] DMA buffer va=0x{:x} cpu_phys=0x{:x} dma=0x{:x} len=0x{:x}",
        va, phys, dma, len
    ));
    semihost_log(format_args!(
        "[rpi5-rp1-init] DMA window base=0x{:x} cpu_base=0x{:x} size=0x{:x}",
        window.pcie_base, window.cpu_base, window.size
    ));
    cpu::clean_dcache_range(va as *const u8, len);
    // No device transaction is started in this preflight, so no device-written cache lines
    // exist to invalidate before a CPU read. A future RX DMA path must invalidate before use.
    Ok(())
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    semihost_log(format_args!("panic: {}", info));
    wait_forever()
}

fn fail(args: fmt::Arguments<'_>) -> ! {
    semihost_log(format_args!("[rpi5-rp1-init] FAIL: {}", args));
    wait_forever()
}

struct SemihostWriter {
    bytes: [u8; 256],
    len: usize,
}

impl SemihostWriter {
    const fn new() -> Self {
        Self {
            bytes: [0; 256],
            len: 0,
        }
    }
}

impl fmt::Write for SemihostWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn semihost_log(args: fmt::Arguments<'_>) {
    let mut writer = SemihostWriter::new();
    if fmt::write(&mut writer, args).is_ok() {
        semihost_write(&writer.bytes[..writer.len]);
    } else {
        semihost_write(b"[rpi5-rp1-init] log line too long");
    }
    semihost_write(b"\n");
}

fn semihost_write(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }

    let args = [1_u64, bytes.as_ptr() as u64, bytes.len() as u64];
    // SAFETY: This is the AArch64 semihosting `SYS_WRITE` ABI. OpenOCD handles the HLT
    // trap while the debug probe is attached; `args` and `bytes` stay valid for the call.
    unsafe {
        asm!(
            "hlt #0xf000",
            inlateout("x0") SEMIHOST_SYS_WRITE => _,
            in("x1") args.as_ptr() as u64,
            options(nostack),
        );
    }
}

fn semihost_mirror_write(text: &str) {
    semihost_write(text.as_bytes());
}

fn semihost_flush() {}

fn wait_forever() -> ! {
    loop {
        // SAFETY: `wfe` is used as a low-power idle wait in this single-core spin loop.
        unsafe {
            asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}
