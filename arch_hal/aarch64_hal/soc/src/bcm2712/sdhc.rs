use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;
use core::time::Duration;

use dtb::DtbParser;
use dtb::WalkError;
use io_api::block_device::BlockDevice;
use io_api::block_device::IoError;
use io_api::block_device::Lba;
use mutex::pod::RawAtomicPod;
use mutex::SpinLock;
use print::println;

#[cfg(test)]
extern crate std;

#[cfg(target_arch = "aarch64")]
use timer::read_counter;
#[cfg(target_arch = "aarch64")]
use timer::SystemTimer;

#[cfg(not(target_arch = "aarch64"))]
use self::timer_compat::read_counter;
#[cfg(not(target_arch = "aarch64"))]
use self::timer_compat::SystemTimer;

#[cfg(not(target_arch = "aarch64"))]
mod timer_compat {
    use core::num::NonZeroU64;
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::Ordering;
    use core::time::Duration;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct SystemTimer {
        counter_frequency: Option<NonZeroU64>,
    }

    impl SystemTimer {
        pub const fn new() -> Self {
            Self {
                counter_frequency: None,
            }
        }

        pub fn init(&mut self) {
            self.counter_frequency = NonZeroU64::new(1_000_000);
        }

        pub fn counter_frequency_hz(&self) -> NonZeroU64 {
            self.counter_frequency
                .expect("before calling wait function call init")
        }

        pub fn wait(&self, duration: Duration) {
            let ticks = duration.as_micros() as u64;
            COUNTER.fetch_add(ticks.max(1), Ordering::Relaxed);
        }
    }

    pub fn read_counter() -> u64 {
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

const DT_COMPAT_BCM2712_SDHCI: &str = "brcm,bcm2712-sdhci";
const DT_COMPAT_BRCMSTB_SDHCI: &str = "brcm,sdhci-brcmstb";
const SDHC_DEFAULT_MIN_CLOCK_HZ: u32 = 400_000;
const SDHC_DEFAULT_MAX_CLOCK_HZ: u32 = 100_000_000;
const SDHC_BLOCK_SIZE: usize = 512;
const SDHC_MAX_TRANSFER_BLOCKS_PER_CMD: usize = 1024;
const SDHC_CMD_TIMEOUT_US: u64 = 100_000;
const SDHC_DATA_TIMEOUT_US: u64 = 1_000_000;
const SDHC_CLOCK_TIMEOUT_US: u64 = 20_000;
const SDHC_RESET_TIMEOUT_US: u64 = 100_000;
const SDHC_ACMD41_RETRY_MAX: usize = 1000;
const SDHC_ACMD41_POLL_DELAY_US: u64 = 10;
const SDHC_MAX_DT_CANDIDATES: usize = 8;
const SDHC_MAX_REG_ENTRIES: usize = 8;
const SDHC_MAX_CLOCK_DIVIDER: u16 = 0x03ff;
const BCM2712_SD_SLOT_HOST_BASE: usize = 0x10_00ff_f000;

const SDHCI_BLOCK_SIZE: usize = 0x04;
const SDHCI_BLOCK_COUNT: usize = 0x06;
const SDHCI_ARGUMENT: usize = 0x08;
const SDHCI_TRANSFER_MODE: usize = 0x0c;
const SDHCI_COMMAND: usize = 0x0e;
const SDHCI_RESPONSE: usize = 0x10;
const SDHCI_BUFFER: usize = 0x20;
const SDHCI_PRESENT_STATE: usize = 0x24;
const SDHCI_POWER_CONTROL: usize = 0x29;
const SDHCI_CLOCK_CONTROL: usize = 0x2c;
const SDHCI_TIMEOUT_CONTROL: usize = 0x2e;
const SDHCI_SOFTWARE_RESET: usize = 0x2f;
const SDHCI_INT_STATUS: usize = 0x30;
const SDHCI_INT_ENABLE: usize = 0x34;
const SDHCI_SIGNAL_ENABLE: usize = 0x38;

const SDHCI_MAKE_BLKSZ: u16 = 0x7000;
const SDHCI_TRNS_BLK_CNT_EN: u16 = 1 << 1;
const SDHCI_TRNS_READ: u16 = 1 << 4;
const SDHCI_TRNS_MULTI: u16 = 1 << 5;
const SDHCI_CMD_RESP_NONE: u16 = 0x00;
const SDHCI_CMD_RESP_LONG: u16 = 0x01;
const SDHCI_CMD_RESP_SHORT: u16 = 0x02;
const SDHCI_CMD_RESP_SHORT_BUSY: u16 = 0x03;
const SDHCI_CMD_CRC: u16 = 0x08;
const SDHCI_CMD_INDEX: u16 = 0x10;
const SDHCI_CMD_DATA: u16 = 0x20;
const SDHCI_CMD_INHIBIT: u32 = 1 << 0;
const SDHCI_DATA_INHIBIT: u32 = 1 << 1;
const SDHCI_SPACE_AVAILABLE: u32 = 1 << 10;
const SDHCI_DATA_AVAILABLE: u32 = 1 << 11;
const SDHCI_CARD_PRESENT: u32 = 1 << 16;
const SDHCI_CARD_STATE_STABLE: u32 = 1 << 17;
const SDHCI_WRITE_PROTECT: u32 = 1 << 19;
const SDHCI_POWER_ON: u8 = 0x01;
const SDHCI_POWER_330: u8 = 0x0e;
const SDHCI_CLOCK_CARD_EN: u16 = 1 << 2;
const SDHCI_CLOCK_INT_STABLE: u16 = 1 << 1;
const SDHCI_CLOCK_INT_EN: u16 = 1 << 0;
const SDHCI_DIVIDER_SHIFT: u16 = 8;
const SDHCI_DIVIDER_HI_SHIFT: u16 = 6;
const SDHCI_DIV_MASK: u16 = 0x00ff;
const SDHCI_DIV_HI_MASK: u16 = 0x0300;
const SDHCI_RESET_ALL: u8 = 0x01;
const SDHCI_RESET_CMD: u8 = 0x02;
const SDHCI_RESET_DATA: u8 = 0x04;
const SDHCI_INT_RESPONSE: u32 = 1 << 0;
const SDHCI_INT_DATA_END: u32 = 1 << 1;
const SDHCI_INT_DMA_END: u32 = 1 << 3;
const SDHCI_INT_SPACE_AVAIL: u32 = 1 << 4;
const SDHCI_INT_DATA_AVAIL: u32 = 1 << 5;
const SDHCI_INT_ERROR: u32 = 1 << 15;
const SDHCI_INT_TIMEOUT: u32 = 1 << 16;
const SDHCI_INT_DATA_TIMEOUT: u32 = 1 << 20;
const SDHCI_INT_CMD_MASK: u32 =
    SDHCI_INT_RESPONSE | SDHCI_INT_TIMEOUT | (1 << 17) | (1 << 18) | (1 << 19);
const SDHCI_INT_DATA_MASK: u32 = SDHCI_INT_DATA_END
    | SDHCI_INT_DMA_END
    | SDHCI_INT_SPACE_AVAIL
    | SDHCI_INT_DATA_AVAIL
    | SDHCI_INT_DATA_TIMEOUT
    | (1 << 21)
    | (1 << 22)
    | (1 << 25);
const SDHCI_INT_ALL_MASK: u32 = u32::MAX;

const SDIO_CFG_CTRL: usize = 0x00;
const SDIO_CFG_CTRL_SDCD_N_TEST_EN: u32 = 1 << 31;
const SDIO_CFG_CTRL_SDCD_N_TEST_LEV: u32 = 1 << 30;
const SDIO_CFG_CLOCK_REGS_OFFSET: usize = 0x04;
const SDIO_CFG_MODE: usize = SDIO_CFG_CLOCK_REGS_OFFSET + 0x00;
const SDIO_CFG_LOCAL: usize = SDIO_CFG_CLOCK_REGS_OFFSET + 0x08;
const SDIO_CFG_USE_LOCAL: usize = SDIO_CFG_CLOCK_REGS_OFFSET + 0x0c;
const SDIO_CFG_SD_DELAY: usize = SDIO_CFG_CLOCK_REGS_OFFSET + 0x10;
const SDIO_CFG_RX_DELAY: usize = SDIO_CFG_CLOCK_REGS_OFFSET + 0x14;
const SDIO_CFG_CS: usize = SDIO_CFG_CLOCK_REGS_OFFSET + 0x1c;
const SDIO_CFG_SD_PIN_SEL: usize = 0x44;
const SDIO_CFG_SD_PIN_SEL_MASK: u32 = 0x3;
const SDIO_CFG_SD_PIN_SEL_CARD: u32 = 1 << 1;
const SDIO_CFG_MODE_SRC_SEL_SHIFT: u32 = 16;
const SDIO_CFG_MODE_SRC_SEL_PLL_SYS_VCO: u32 = 2;
const SDIO_CFG_MODE_STEPS_SHIFT: u32 = 28;
const SDIO_CFG_MODE_STEPS_20_CYCLES: u32 = 0;
const SDIO_CFG_LOCAL_FREQ_SEL_MASK: u32 = 0x03ff;
const SDIO_CFG_LOCAL_CLK_GEN_SEL: u32 = 1 << 12;
const SDIO_CFG_LOCAL_CARD_CLK_EN: u32 = 1 << 16;
const SDIO_CFG_LOCAL_CLK2CARD_ON: u32 = 1 << 18;
const SDIO_CFG_USE_LOCAL_FREQ_SEL: u32 = 1 << 0;
const SDIO_CFG_USE_LOCAL_CLK_GEN_SEL: u32 = 1 << 12;
const SDIO_CFG_USE_LOCAL_CARD_CLK_EN: u32 = 1 << 16;
const SDIO_CFG_USE_LOCAL_CLK2CARD_ON: u32 = 1 << 18;
const SDIO_CFG_SD_DELAY_STEP_MASK: u32 = 0x1f;
const SDIO_CFG_SD_DELAY_STEP_DEFAULT: u32 = 5;
const SDIO_CFG_RX_DELAY_FIXED_MASK: u32 = 0x1f;
const SDIO_CFG_RX_DELAY_FIXED_DEFAULT: u32 = 6;
const SDIO_CFG_RX_DELAY_MAP_SHIFT: u32 = 8;
const SDIO_CFG_RX_DELAY_MAP_STRETCH: u32 = 2;
const SDIO_CFG_RX_DELAY_OVERFLOW_SHIFT: u32 = 12;
const SDIO_CFG_RX_DELAY_OVERFLOW_CLAMP: u32 = 1;
const SDIO_CFG_CS_RESET: u32 = 1 << 0;
const SDIO_CFG_CS_TX_CLK_RUNNING: u32 = 1 << 8;
const SDIO_CFG_CS_SD_CLK_RUNNING: u32 = 1 << 12;
const SDIO_CFG_CS_RX_CLK_RUNNING: u32 = 1 << 16;
const SDIO_CFG_CS_CLOCKS_RUNNING: u32 =
    SDIO_CFG_CS_TX_CLK_RUNNING | SDIO_CFG_CS_SD_CLK_RUNNING | SDIO_CFG_CS_RX_CLK_RUNNING;
const BCM2712_SDIO1_SRC_CLOCK_HZ: u32 = 1_000_000_000;
const BCM2712_SDIO1_CORE_CLOCK_HZ: u32 = 50_000_000;
const BCM2712_SDIO1_INIT_CLOCK_HZ: u32 = 400_000;
const BCM2712_SDIO1_CLOCK_START_TIMEOUT_US: u64 = 1_000;

const MMC_CMD_GO_IDLE_STATE: u8 = 0;
const MMC_CMD_ALL_SEND_CID: u8 = 2;
const MMC_CMD_SET_RELATIVE_ADDR: u8 = 3;
const MMC_CMD_SELECT_CARD: u8 = 7;
const MMC_CMD_SEND_IF_COND: u8 = 8;
const MMC_CMD_SEND_CSD: u8 = 9;
const MMC_CMD_STOP_TRANSMISSION: u8 = 12;
const MMC_CMD_SET_BLOCKLEN: u8 = 16;
const MMC_CMD_READ_SINGLE_BLOCK: u8 = 17;
const MMC_CMD_READ_MULTIPLE_BLOCK: u8 = 18;
const MMC_CMD_WRITE_SINGLE_BLOCK: u8 = 24;
const MMC_CMD_WRITE_MULTIPLE_BLOCK: u8 = 25;
const MMC_CMD_APP_CMD: u8 = 55;
const SD_CMD_APP_SEND_OP_COND: u8 = 41;

const OCR_BUSY: u32 = 1 << 31;
const OCR_HCS: u32 = 1 << 30;
const OCR_3V2_3V4: u32 = 0x0030_0000;
const OCR_3V3_3V4: u32 = 0x0020_0000;
const OCR_3V2_3V3: u32 = 0x0010_0000;
const OCR_REQUEST: u32 = OCR_HCS | OCR_3V2_3V4 | OCR_3V3_3V4 | OCR_3V2_3V3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdhcError {
    DtbParse(&'static str),
    DtbNotFound,
    DtbInvalid(&'static str),
    InvalidParam,
    InvalidClock,
    InvalidState,
    Timeout,
    NotReady,
    NoCard,
    ReadOnly,
    Unsupported,
    Io,
    OutOfRange,
    Align,
}

impl From<SdhcError> for IoError {
    fn from(value: SdhcError) -> Self {
        match value {
            SdhcError::InvalidParam | SdhcError::InvalidClock | SdhcError::DtbInvalid(_) => {
                IoError::InvalidParam
            }
            SdhcError::Timeout => IoError::Timeout,
            SdhcError::NotReady => IoError::NotReady,
            SdhcError::NoCard => IoError::NotReady,
            SdhcError::ReadOnly => IoError::ReadOnly,
            SdhcError::Unsupported => IoError::Unsupported,
            SdhcError::OutOfRange => IoError::OutOfRange,
            SdhcError::Align => IoError::Align,
            SdhcError::Io => IoError::Io,
            SdhcError::DtbParse(_) | SdhcError::DtbNotFound | SdhcError::InvalidState => {
                IoError::NotReady
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HostRegion {
    base: usize,
    size: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SdhcConfig {
    host: HostRegion,
    cfg: HostRegion,
    max_clock_hz: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NamedRegions {
    host: Option<HostRegion>,
    cfg: Option<HostRegion>,
    busisol: Option<HostRegion>,
    lcpll: Option<HostRegion>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SdhcRegName {
    Host,
    Cfg,
    BusIsol,
    LcPll,
    #[default]
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SdhcDtCandidate {
    host: Option<HostRegion>,
    cfg: Option<HostRegion>,
    busisol: Option<HostRegion>,
    lcpll: Option<HostRegion>,
    max_clock_hz: u32,
    has_brcmstb_compat: bool,
    status_okay: bool,
    bus_width: u32,
    non_removable: bool,
    has_wifi_child: bool,
}

impl SdhcDtCandidate {
    fn is_supported_shape(&self) -> bool {
        self.status_okay && self.host.is_some() && self.cfg.is_some()
    }

    fn host_base(&self) -> Option<usize> {
        self.host.map(|region| region.base)
    }

    fn is_viable_sd_slot(&self) -> bool {
        self.host_base() == Some(BCM2712_SD_SLOT_HOST_BASE)
            || (!self.non_removable && !self.has_wifi_child)
    }

    fn into_config(self) -> Result<SdhcConfig, SdhcError> {
        let host = self
            .host
            .ok_or(SdhcError::DtbInvalid("sdhc: missing host reg"))?;
        let cfg = self
            .cfg
            .ok_or(SdhcError::DtbInvalid("sdhc: missing cfg reg"))?;
        Ok(SdhcConfig {
            host,
            cfg,
            max_clock_hz: self.max_clock_hz,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct CardState {
    high_capacity: bool,
    capacity_blocks: u64,
    read_only: bool,
}

pub struct Bcm2712Sdhc {
    host: *mut u8,
    cfg: *mut u8,
    max_clock_hz: u32,
    min_clock_hz: u32,
    card: SpinLock<Option<CardState>>,
}

// SAFETY: The controller is accessed through volatile MMIO and serialized state transitions.
unsafe impl Send for Bcm2712Sdhc {}
// SAFETY: Methods synchronize mutable shared state with `SpinLock`.
unsafe impl Sync for Bcm2712Sdhc {}

// SAFETY: `bool` has no invalid bit patterns; `false` is canonical for `RawAtomicPod<bool>`.
static TAKEN: RawAtomicPod<bool> = unsafe { RawAtomicPod::new_raw_unchecked(false) };
// SAFETY: `bool` has no invalid bit patterns; `false` is canonical for `RawAtomicPod<bool>`.
static READY: RawAtomicPod<bool> = unsafe { RawAtomicPod::new_raw_unchecked(false) };
static STATE: SyncUnsafeCell<MaybeUninit<Bcm2712Sdhc>> = SyncUnsafeCell::new(MaybeUninit::uninit());

impl Bcm2712Sdhc {
    pub fn init_from_dtb(dtb: &DtbParser) -> Result<&'static Self, SdhcError> {
        if TAKEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SdhcError::InvalidState);
        }
        let result = Self::init_from_dtb_inner(dtb);
        if result.is_err() {
            READY.store(false, Ordering::Release);
            TAKEN.store(false, Ordering::Release);
        }
        result
    }

    fn init_from_dtb_inner(dtb: &DtbParser) -> Result<&'static Self, SdhcError> {
        let cfg = parse_from_dtb(dtb)?;
        if cfg.host.base == 0 || cfg.host.size < 0x100 {
            return Err(SdhcError::DtbInvalid("sdhc: invalid host region"));
        }
        if cfg.cfg.base == 0 || cfg.cfg.size < 0x48 {
            return Err(SdhcError::DtbInvalid("sdhc: invalid cfg region"));
        }
        if cfg.max_clock_hz == 0 {
            return Err(SdhcError::InvalidClock);
        }
        let instance = Bcm2712Sdhc {
            host: cfg.host.base as *mut u8,
            cfg: cfg.cfg.base as *mut u8,
            max_clock_hz: cfg.max_clock_hz.min(SDHC_DEFAULT_MAX_CLOCK_HZ),
            min_clock_hz: SDHC_DEFAULT_MIN_CLOCK_HZ,
            card: SpinLock::new(None),
        };
        instance.configure_bcm2712_sdio1_clock()?;
        instance.reset(SDHCI_RESET_ALL)?;
        instance.configure_card_detect()?;
        instance.power_on()?;
        instance.set_clock(instance.min_clock_hz)?;
        instance.enable_interrupt_masks();
        instance.card_init_sequence()?;

        // SAFETY: guarded by `TAKEN`; this is one-time initialization.
        unsafe {
            (*STATE.get()).write(instance);
        }
        READY.store(true, Ordering::Release);
        // SAFETY: `READY` is published only after full initialization.
        let state = unsafe { (&*STATE.get()).assume_init_ref() };
        Ok(state)
    }

    fn now_ticks() -> u64 {
        read_counter()
    }

    fn elapsed_us(timer: &SystemTimer, start: u64) -> u64 {
        let now = Self::now_ticks();
        let ticks = now.wrapping_sub(start) as u128;
        let hz = timer.counter_frequency_hz().get() as u128;
        ((ticks * 1_000_000u128) / hz) as u64
    }

    fn wait_until(
        &self,
        timeout_us: u64,
        mut condition: impl FnMut(&Self) -> bool,
    ) -> Result<(), SdhcError> {
        let mut timer = SystemTimer::new();
        timer.init();
        let start = Self::now_ticks();
        while !condition(self) {
            if Self::elapsed_us(&timer, start) >= timeout_us {
                return Err(SdhcError::Timeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    fn reg_read_u8(&self, offset: usize) -> u8 {
        // SAFETY: `self.host` points to mapped SDHCI MMIO base for the lifetime of this driver.
        unsafe { core::ptr::read_volatile(self.host.wrapping_add(offset) as *const u8) }
    }

    fn reg_read_u16(&self, offset: usize) -> u16 {
        // SAFETY: `self.host` points to mapped SDHCI MMIO base for the lifetime of this driver.
        unsafe { core::ptr::read_volatile(self.host.wrapping_add(offset) as *const u16) }
    }

    fn reg_read_u32(&self, offset: usize) -> u32 {
        // SAFETY: `self.host` points to mapped SDHCI MMIO base for the lifetime of this driver.
        unsafe { core::ptr::read_volatile(self.host.wrapping_add(offset) as *const u32) }
    }

    fn reg_write_u8(&self, offset: usize, value: u8) {
        // SAFETY: `self.host` points to mapped SDHCI MMIO base for the lifetime of this driver.
        unsafe { core::ptr::write_volatile(self.host.wrapping_add(offset), value) };
    }

    fn reg_write_u16(&self, offset: usize, value: u16) {
        // SAFETY: `self.host` points to mapped SDHCI MMIO base for the lifetime of this driver.
        unsafe { core::ptr::write_volatile(self.host.wrapping_add(offset) as *mut u16, value) };
    }

    fn reg_write_u32(&self, offset: usize, value: u32) {
        // SAFETY: `self.host` points to mapped SDHCI MMIO base for the lifetime of this driver.
        unsafe { core::ptr::write_volatile(self.host.wrapping_add(offset) as *mut u32, value) };
    }

    fn cfg_read_u32(&self, offset: usize) -> u32 {
        // SAFETY: `self.cfg` points to mapped controller-specific CFG MMIO region.
        unsafe { core::ptr::read_volatile(self.cfg.wrapping_add(offset) as *const u32) }
    }

    fn cfg_write_u32(&self, offset: usize, value: u32) {
        // SAFETY: `self.cfg` points to mapped controller-specific CFG MMIO region.
        unsafe { core::ptr::write_volatile(self.cfg.wrapping_add(offset) as *mut u32, value) };
    }

    fn configure_bcm2712_sdio1_clock(&self) -> Result<(), SdhcError> {
        let steps = match BCM2712_SDIO1_SRC_CLOCK_HZ / BCM2712_SDIO1_CORE_CLOCK_HZ {
            20 => SDIO_CFG_MODE_STEPS_20_CYCLES,
            _ => return Err(SdhcError::InvalidClock),
        };

        let local_divider = bcm2712_sdio1_local_divider(BCM2712_SDIO1_INIT_CLOCK_HZ)?;
        let mode = (SDIO_CFG_MODE_SRC_SEL_PLL_SYS_VCO << SDIO_CFG_MODE_SRC_SEL_SHIFT)
            | (steps << SDIO_CFG_MODE_STEPS_SHIFT);
        let rx_delay = (SDIO_CFG_RX_DELAY_FIXED_DEFAULT & SDIO_CFG_RX_DELAY_FIXED_MASK)
            | (SDIO_CFG_RX_DELAY_MAP_STRETCH << SDIO_CFG_RX_DELAY_MAP_SHIFT)
            | (SDIO_CFG_RX_DELAY_OVERFLOW_CLAMP << SDIO_CFG_RX_DELAY_OVERFLOW_SHIFT);
        let sd_delay = SDIO_CFG_SD_DELAY_STEP_DEFAULT & SDIO_CFG_SD_DELAY_STEP_MASK;
        let use_local = SDIO_CFG_USE_LOCAL_FREQ_SEL
            | SDIO_CFG_USE_LOCAL_CLK_GEN_SEL
            | SDIO_CFG_USE_LOCAL_CARD_CLK_EN
            | SDIO_CFG_USE_LOCAL_CLK2CARD_ON;
        let local = (local_divider & SDIO_CFG_LOCAL_FREQ_SEL_MASK)
            | SDIO_CFG_LOCAL_CLK_GEN_SEL
            | SDIO_CFG_LOCAL_CARD_CLK_EN
            | SDIO_CFG_LOCAL_CLK2CARD_ON;

        self.cfg_write_u32(SDIO_CFG_CS, SDIO_CFG_CS_RESET);
        self.cfg_write_u32(SDIO_CFG_MODE, mode);
        self.cfg_write_u32(SDIO_CFG_RX_DELAY, rx_delay);
        self.cfg_write_u32(SDIO_CFG_SD_DELAY, sd_delay);
        self.cfg_write_u32(SDIO_CFG_USE_LOCAL, use_local);
        self.cfg_write_u32(SDIO_CFG_LOCAL, local);
        self.cfg_write_u32(SDIO_CFG_CS, 0);

        self.wait_until(BCM2712_SDIO1_CLOCK_START_TIMEOUT_US, |s| {
            (s.cfg_read_u32(SDIO_CFG_CS) & SDIO_CFG_CS_CLOCKS_RUNNING) == SDIO_CFG_CS_CLOCKS_RUNNING
        })
    }

    fn reset(&self, mask: u8) -> Result<(), SdhcError> {
        self.reg_write_u8(SDHCI_SOFTWARE_RESET, mask);
        self.wait_until(SDHC_RESET_TIMEOUT_US, |s| {
            s.reg_read_u8(SDHCI_SOFTWARE_RESET) & mask == 0
        })
    }

    fn configure_card_detect(&self) -> Result<(), SdhcError> {
        // The Raspberry Pi 5 SD-slot path we support here still relies on firmware-prepared
        // regulator state and does not expose a runtime hotplug controller through the DT we
        // consume at EL2, so we explicitly force the SD-slot routing instead of guessing.
        let mut ctrl = self.cfg_read_u32(SDIO_CFG_CTRL);
        ctrl &= !SDIO_CFG_CTRL_SDCD_N_TEST_LEV;
        ctrl |= SDIO_CFG_CTRL_SDCD_N_TEST_EN;
        self.cfg_write_u32(SDIO_CFG_CTRL, ctrl);

        let mut pin_sel = self.cfg_read_u32(SDIO_CFG_SD_PIN_SEL);
        pin_sel &= !SDIO_CFG_SD_PIN_SEL_MASK;
        pin_sel |= SDIO_CFG_SD_PIN_SEL_CARD;
        self.cfg_write_u32(SDIO_CFG_SD_PIN_SEL, pin_sel);
        Ok(())
    }

    fn power_on(&self) -> Result<(), SdhcError> {
        self.reg_write_u8(SDHCI_POWER_CONTROL, SDHCI_POWER_330 | SDHCI_POWER_ON);
        Ok(())
    }

    fn set_clock(&self, clock_hz: u32) -> Result<(), SdhcError> {
        if clock_hz == 0 || self.max_clock_hz == 0 {
            return Err(SdhcError::InvalidClock);
        }

        self.wait_until(SDHC_CMD_TIMEOUT_US, |s| {
            let state = s.reg_read_u32(SDHCI_PRESENT_STATE);
            (state & (SDHCI_CMD_INHIBIT | SDHCI_DATA_INHIBIT)) == 0
        })?;

        self.reg_write_u16(SDHCI_CLOCK_CONTROL, 0);

        let encoded_divider = encode_clock_divider(clock_hz, self.max_clock_hz)?;
        let mut clk: u16 = pack_clock_control_divider(encoded_divider) | SDHCI_CLOCK_INT_EN;
        self.reg_write_u16(SDHCI_CLOCK_CONTROL, clk);
        self.wait_until(SDHC_CLOCK_TIMEOUT_US, |s| {
            (s.reg_read_u16(SDHCI_CLOCK_CONTROL) & SDHCI_CLOCK_INT_STABLE) != 0
        })?;
        clk |= SDHCI_CLOCK_CARD_EN;
        self.reg_write_u16(SDHCI_CLOCK_CONTROL, clk);
        Ok(())
    }

    fn enable_interrupt_masks(&self) {
        self.reg_write_u32(SDHCI_INT_ENABLE, SDHCI_INT_CMD_MASK | SDHCI_INT_DATA_MASK);
        self.reg_write_u32(SDHCI_SIGNAL_ENABLE, 0);
        self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);
    }

    fn card_present(&self) -> bool {
        let state = self.reg_read_u32(SDHCI_PRESENT_STATE);
        (state & SDHCI_CARD_PRESENT) != 0 && (state & SDHCI_CARD_STATE_STABLE) != 0
    }

    fn card_read_only(&self) -> bool {
        (self.reg_read_u32(SDHCI_PRESENT_STATE) & SDHCI_WRITE_PROTECT) != 0
    }

    fn io_chunk_blocks(&self) -> usize {
        SDHC_MAX_TRANSFER_BLOCKS_PER_CMD
    }

    fn cmd_flags(resp_type: RespType, data: bool) -> u16 {
        let mut flags = match resp_type {
            RespType::None => SDHCI_CMD_RESP_NONE,
            RespType::R2 => SDHCI_CMD_RESP_LONG | SDHCI_CMD_CRC,
            RespType::R1 => SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC | SDHCI_CMD_INDEX,
            RespType::R1b => SDHCI_CMD_RESP_SHORT_BUSY | SDHCI_CMD_CRC | SDHCI_CMD_INDEX,
            RespType::R3 => SDHCI_CMD_RESP_SHORT,
            RespType::R6 => SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC | SDHCI_CMD_INDEX,
            RespType::R7 => SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC | SDHCI_CMD_INDEX,
        };
        if data {
            flags |= SDHCI_CMD_DATA;
        }
        flags
    }

    fn send_command(
        &self,
        cmd_idx: u8,
        arg: u32,
        resp_type: RespType,
        mut data: Option<DataTransfer<'_>>,
    ) -> Result<[u32; 4], SdhcError> {
        let mask = if cmd_idx == MMC_CMD_STOP_TRANSMISSION {
            SDHCI_CMD_INHIBIT
        } else {
            SDHCI_CMD_INHIBIT | SDHCI_DATA_INHIBIT
        };
        self.wait_until(SDHC_CMD_TIMEOUT_US, |s| {
            (s.reg_read_u32(SDHCI_PRESENT_STATE) & mask) == 0
        })?;

        self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);

        let has_data = data.is_some();
        let mut interrupt_mask = SDHCI_INT_RESPONSE;
        if matches!(resp_type, RespType::R1b) {
            interrupt_mask |= SDHCI_INT_DATA_END;
        }

        if let Some(transfer) = data.as_ref() {
            self.reg_write_u8(SDHCI_TIMEOUT_CONTROL, 0x0e);
            let mut mode: u16 = SDHCI_TRNS_BLK_CNT_EN;
            if transfer.blocks > 1 {
                mode |= SDHCI_TRNS_MULTI;
            }
            if transfer.read {
                mode |= SDHCI_TRNS_READ;
            }
            self.reg_write_u16(
                SDHCI_BLOCK_SIZE,
                SDHCI_MAKE_BLKSZ | (transfer.block_size as u16 & 0x0fff),
            );
            self.reg_write_u16(SDHCI_BLOCK_COUNT, transfer.blocks as u16);
            self.reg_write_u16(SDHCI_TRANSFER_MODE, mode);
        }

        self.reg_write_u32(SDHCI_ARGUMENT, arg);
        let cmd = ((cmd_idx as u16) << 8) | Self::cmd_flags(resp_type, has_data);
        self.reg_write_u16(SDHCI_COMMAND, cmd);

        self.wait_until(SDHC_CMD_TIMEOUT_US, |s| {
            let stat = s.reg_read_u32(SDHCI_INT_STATUS);
            (stat & SDHCI_INT_ERROR) != 0 || (stat & interrupt_mask) == interrupt_mask
        })?;

        let status = self.reg_read_u32(SDHCI_INT_STATUS);
        if (status & SDHCI_INT_ERROR) != 0 {
            self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);
            self.reset(SDHCI_RESET_CMD)?;
            self.reset(SDHCI_RESET_DATA)?;
            if (status & SDHCI_INT_TIMEOUT) != 0 {
                return Err(SdhcError::Timeout);
            }
            return Err(SdhcError::Io);
        }

        let resp = if matches!(resp_type, RespType::R2) {
            [
                (self.reg_read_u32(SDHCI_RESPONSE + 12) << 8)
                    | u32::from(self.reg_read_u8(SDHCI_RESPONSE + 11)),
                (self.reg_read_u32(SDHCI_RESPONSE + 8) << 8)
                    | u32::from(self.reg_read_u8(SDHCI_RESPONSE + 7)),
                (self.reg_read_u32(SDHCI_RESPONSE + 4) << 8)
                    | u32::from(self.reg_read_u8(SDHCI_RESPONSE + 3)),
                self.reg_read_u32(SDHCI_RESPONSE) << 8,
            ]
        } else {
            [self.reg_read_u32(SDHCI_RESPONSE), 0, 0, 0]
        };
        if let Some(transfer) = data.take() {
            self.transfer_data_pio(transfer)?;
            self.wait_until(SDHC_DATA_TIMEOUT_US, |s| {
                let stat = s.reg_read_u32(SDHCI_INT_STATUS);
                (stat & SDHCI_INT_ERROR) != 0 || (stat & SDHCI_INT_DATA_END) != 0
            })?;
            let stat = self.reg_read_u32(SDHCI_INT_STATUS);
            if (stat & SDHCI_INT_ERROR) != 0 {
                self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);
                self.reset(SDHCI_RESET_CMD)?;
                self.reset(SDHCI_RESET_DATA)?;
                return Err(SdhcError::Io);
            }
        }
        self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_ALL_MASK);
        Ok(resp)
    }

    fn transfer_data_pio(&self, transfer: DataTransfer<'_>) -> Result<(), SdhcError> {
        let mut remaining_blocks = transfer.blocks;
        let mut offset = 0usize;
        while remaining_blocks > 0 {
            self.wait_until(SDHC_DATA_TIMEOUT_US, |s| {
                let stat = s.reg_read_u32(SDHCI_INT_STATUS);
                if (stat & SDHCI_INT_ERROR) != 0 {
                    return true;
                }
                if transfer.read {
                    (s.reg_read_u32(SDHCI_PRESENT_STATE) & SDHCI_DATA_AVAILABLE) != 0
                } else {
                    (s.reg_read_u32(SDHCI_PRESENT_STATE) & SDHCI_SPACE_AVAILABLE) != 0
                }
            })?;

            let stat = self.reg_read_u32(SDHCI_INT_STATUS);
            if (stat & SDHCI_INT_ERROR) != 0 {
                return Err(SdhcError::Io);
            }

            let block_end = offset
                .checked_add(transfer.block_size)
                .ok_or(SdhcError::OutOfRange)?;
            if transfer.read {
                let slice = transfer
                    .buffer
                    .get_mut(offset..block_end)
                    .ok_or(SdhcError::OutOfRange)?;
                for chunk in slice.chunks_exact_mut(4) {
                    let data = self.reg_read_u32(SDHCI_BUFFER);
                    let bytes = data.to_le_bytes();
                    chunk.copy_from_slice(&bytes);
                }
            } else {
                let slice = transfer
                    .buffer
                    .get(offset..block_end)
                    .ok_or(SdhcError::OutOfRange)?;
                for chunk in slice.chunks_exact(4) {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(chunk);
                    self.reg_write_u32(SDHCI_BUFFER, u32::from_le_bytes(bytes));
                }
            }

            if transfer.read {
                self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_DATA_AVAIL);
            } else {
                self.reg_write_u32(SDHCI_INT_STATUS, SDHCI_INT_SPACE_AVAIL);
            }
            remaining_blocks -= 1;
            offset = block_end;
        }
        Ok(())
    }

    fn card_init_sequence(&self) -> Result<(), SdhcError> {
        if !self.card_present() {
            return Err(SdhcError::NoCard);
        }

        self.send_command(MMC_CMD_GO_IDLE_STATE, 0, RespType::None, None)?;
        self.send_command(MMC_CMD_SEND_IF_COND, 0x1aa, RespType::R7, None)?;

        let mut ocr = 0u32;
        let mut ready = false;
        let mut timer = SystemTimer::new();
        timer.init();
        for _ in 0..SDHC_ACMD41_RETRY_MAX {
            self.send_command(MMC_CMD_APP_CMD, 0, RespType::R1, None)?;
            let resp =
                self.send_command(SD_CMD_APP_SEND_OP_COND, OCR_REQUEST, RespType::R3, None)?;
            ocr = resp[0];
            if (ocr & OCR_BUSY) != 0 {
                ready = true;
                break;
            }
            timer.wait(Duration::from_micros(SDHC_ACMD41_POLL_DELAY_US));
        }
        if !ready {
            return Err(SdhcError::Timeout);
        }
        let high_capacity = (ocr & OCR_HCS) != 0;

        let _cid = self.send_command(MMC_CMD_ALL_SEND_CID, 0, RespType::R2, None)?;
        let rca_resp = self.send_command(MMC_CMD_SET_RELATIVE_ADDR, 0, RespType::R6, None)?;
        let rca = (rca_resp[0] >> 16) as u16;
        let csd = self.send_command(MMC_CMD_SEND_CSD, u32::from(rca) << 16, RespType::R2, None)?;
        let select_card = select_card_command(rca);
        self.send_command(
            select_card.idx,
            select_card.arg,
            select_card.resp_type,
            None,
        )?;
        self.send_command(
            MMC_CMD_SET_BLOCKLEN,
            SDHC_BLOCK_SIZE as u32,
            RespType::R1,
            None,
        )?;
        self.set_clock(25_000_000)?;

        let capacity_blocks = decode_capacity_blocks(&csd, high_capacity)?;
        let read_only = self.card_read_only();
        let mut guard = self.card.lock();
        *guard = Some(CardState {
            high_capacity,
            capacity_blocks,
            read_only,
        });
        println!(
            "sdhc: initialized rca=0x{:x} high_capacity={} blocks={}",
            rca, high_capacity, capacity_blocks
        );
        Ok(())
    }

    fn checked_card(&self) -> Result<CardState, SdhcError> {
        let guard = self.card.lock();
        (*guard).ok_or(SdhcError::NotReady)
    }

    fn run_rw(&self, lba: u64, buf: &mut [u8], write: bool) -> Result<(), SdhcError> {
        let card = self.checked_card()?;
        if buf.is_empty() {
            return Err(SdhcError::InvalidParam);
        }
        if (buf.len() % SDHC_BLOCK_SIZE) != 0 {
            return Err(SdhcError::Align);
        }
        let blocks =
            u64::try_from(buf.len() / SDHC_BLOCK_SIZE).map_err(|_| SdhcError::OutOfRange)?;
        if lba
            .checked_add(blocks)
            .filter(|end| *end <= card.capacity_blocks)
            .is_none()
        {
            return Err(SdhcError::OutOfRange);
        }
        if write && card.read_only {
            return Err(SdhcError::ReadOnly);
        }
        let mut current_lba = lba;
        let mut offset = 0usize;
        let total_blocks = usize::try_from(blocks).map_err(|_| SdhcError::OutOfRange)?;
        let max_blocks = self.io_chunk_blocks();
        while offset < buf.len() {
            let remaining_blocks = (buf.len() - offset) / SDHC_BLOCK_SIZE;
            let chunk_blocks = remaining_blocks.min(max_blocks);
            let chunk_end = offset
                .checked_add(chunk_blocks * SDHC_BLOCK_SIZE)
                .ok_or(SdhcError::OutOfRange)?;
            let chunk = buf
                .get_mut(offset..chunk_end)
                .ok_or(SdhcError::OutOfRange)?;
            let multi = chunk_blocks > 1;
            let cmd = match (write, multi) {
                (false, false) => MMC_CMD_READ_SINGLE_BLOCK,
                (false, true) => MMC_CMD_READ_MULTIPLE_BLOCK,
                (true, false) => MMC_CMD_WRITE_SINGLE_BLOCK,
                (true, true) => MMC_CMD_WRITE_MULTIPLE_BLOCK,
            };
            let arg = if card.high_capacity {
                u32::try_from(current_lba).map_err(|_| SdhcError::OutOfRange)?
            } else {
                let byte_addr = current_lba
                    .checked_mul(SDHC_BLOCK_SIZE as u64)
                    .ok_or(SdhcError::OutOfRange)?;
                u32::try_from(byte_addr).map_err(|_| SdhcError::OutOfRange)?
            };
            let transfer = DataTransfer {
                read: !write,
                blocks: chunk_blocks,
                block_size: SDHC_BLOCK_SIZE,
                buffer: chunk,
            };
            self.send_command(cmd, arg, RespType::R1, Some(transfer))?;
            if multi {
                self.send_command(MMC_CMD_STOP_TRANSMISSION, 0, RespType::R1b, None)?;
            }
            current_lba = current_lba
                .checked_add(u64::try_from(chunk_blocks).map_err(|_| SdhcError::OutOfRange)?)
                .ok_or(SdhcError::OutOfRange)?;
            offset = chunk_end;
        }
        debug_assert_eq!(offset, total_blocks * SDHC_BLOCK_SIZE);
        Ok(())
    }
}

impl BlockDevice for Bcm2712Sdhc {
    fn init(&mut self) -> Result<(), IoError> {
        self.configure_bcm2712_sdio1_clock()
            .map_err(IoError::from)?;
        self.reset(SDHCI_RESET_ALL).map_err(IoError::from)?;
        self.configure_card_detect().map_err(IoError::from)?;
        self.power_on().map_err(IoError::from)?;
        self.set_clock(self.min_clock_hz).map_err(IoError::from)?;
        self.enable_interrupt_masks();
        self.card_init_sequence().map_err(IoError::from)
    }

    fn block_size(&self) -> usize {
        SDHC_BLOCK_SIZE
    }

    fn num_blocks(&self) -> u64 {
        let guard = self.card.lock();
        guard.as_ref().map(|card| card.capacity_blocks).unwrap_or(0)
    }

    fn read_at(&self, lba: Lba, buf: &mut [MaybeUninit<u8>]) -> Result<(), IoError> {
        if !READY.load(Ordering::Acquire) {
            return Err(IoError::NotReady);
        }
        // SAFETY: `MaybeUninit<u8>` and `u8` share layout; read path fully initializes bytes.
        let raw =
            unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len()) };
        self.run_rw(lba, raw, false).map_err(IoError::from)
    }

    fn write_at(&self, lba: Lba, buf: &[u8]) -> Result<(), IoError> {
        if !READY.load(Ordering::Acquire) {
            return Err(IoError::NotReady);
        }
        if buf.is_empty() {
            return Err(IoError::InvalidParam);
        }
        if (buf.len() % SDHC_BLOCK_SIZE) != 0 {
            return Err(IoError::Align);
        }
        let mut local = [0u8; SDHC_BLOCK_SIZE * 8];
        let mut offset = 0usize;
        let mut current_lba = lba;
        while offset < buf.len() {
            let chunk_len = (buf.len() - offset).min(local.len());
            let chunk_end = offset.checked_add(chunk_len).ok_or(IoError::OutOfRange)?;
            local[..chunk_len].copy_from_slice(&buf[offset..chunk_end]);
            self.run_rw(current_lba, &mut local[..chunk_len], true)
                .map_err(IoError::from)?;
            current_lba = current_lba
                .checked_add((chunk_len / SDHC_BLOCK_SIZE) as u64)
                .ok_or(IoError::OutOfRange)?;
            offset = chunk_end;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), IoError> {
        Ok(())
    }

    fn max_io_bytes(&self) -> Result<Option<usize>, IoError> {
        Ok(None)
    }

    fn is_read_only(&self) -> Result<bool, IoError> {
        let guard = self.card.lock();
        guard
            .as_ref()
            .map(|card| card.read_only)
            .ok_or(IoError::NotReady)
    }

    fn uninstall(&self) {}
}

pub fn init_from_dtb(dtb: &DtbParser) -> Result<&'static dyn BlockDevice, SdhcError> {
    let dev = Bcm2712Sdhc::init_from_dtb(dtb)?;
    Ok(dev)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RespType {
    None,
    R1,
    R1b,
    R2,
    R3,
    R6,
    R7,
}

struct DataTransfer<'a> {
    read: bool,
    blocks: usize,
    block_size: usize,
    buffer: &'a mut [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommandSpec {
    idx: u8,
    arg: u32,
    resp_type: RespType,
}

fn decode_capacity_blocks(csd: &[u32; 4], high_capacity: bool) -> Result<u64, SdhcError> {
    if high_capacity {
        let c_size = ((u64::from(csd[1]) & 0x3f) << 16) | ((u64::from(csd[2]) & 0xffff_0000) >> 16);
        let bytes = (c_size + 1)
            .checked_shl(10)
            .ok_or(SdhcError::OutOfRange)?
            .checked_mul(SDHC_BLOCK_SIZE as u64)
            .ok_or(SdhcError::OutOfRange)?;
        return Ok(bytes / SDHC_BLOCK_SIZE as u64);
    }

    let c_size = ((u64::from(csd[1]) & 0x3ff) << 2) | ((u64::from(csd[2]) & 0xc000_0000) >> 30);
    let c_mult = (u64::from(csd[2]) & 0x0003_8000) >> 15;
    let read_bl_len_shift = ((csd[1] >> 16) & 0xf) as u32;
    let read_bl_len = 1u64
        .checked_shl(read_bl_len_shift)
        .ok_or(SdhcError::OutOfRange)?;
    let bytes = (c_size + 1)
        .checked_shl((c_mult + 2) as u32)
        .ok_or(SdhcError::OutOfRange)?
        .checked_mul(read_bl_len)
        .ok_or(SdhcError::OutOfRange)?;
    Ok(bytes / SDHC_BLOCK_SIZE as u64)
}

fn bcm2712_sdio1_local_divider(clock_hz: u32) -> Result<u32, SdhcError> {
    if clock_hz == 0 || clock_hz > BCM2712_SDIO1_CORE_CLOCK_HZ {
        return Err(SdhcError::InvalidClock);
    }

    let divider = BCM2712_SDIO1_CORE_CLOCK_HZ / clock_hz;
    let freq_sel = divider.checked_sub(1).ok_or(SdhcError::InvalidClock)?;
    if freq_sel > SDIO_CFG_LOCAL_FREQ_SEL_MASK {
        return Err(SdhcError::InvalidClock);
    }
    Ok(freq_sel)
}

fn encode_clock_divider(requested_clock_hz: u32, max_clock_hz: u32) -> Result<u16, SdhcError> {
    if requested_clock_hz == 0 || max_clock_hz == 0 {
        return Err(SdhcError::InvalidClock);
    }
    if requested_clock_hz >= max_clock_hz {
        return Ok(0);
    }

    let denominator = u64::from(requested_clock_hz)
        .checked_mul(2)
        .ok_or(SdhcError::InvalidClock)?;
    let mut encoded = u64::from(max_clock_hz).div_ceil(denominator);
    if encoded == 0 {
        encoded = 1;
    }
    if encoded > u64::from(SDHC_MAX_CLOCK_DIVIDER) {
        encoded = u64::from(SDHC_MAX_CLOCK_DIVIDER);
    }
    u16::try_from(encoded).map_err(|_| SdhcError::InvalidClock)
}

fn pack_clock_control_divider(encoded_divider: u16) -> u16 {
    ((encoded_divider & SDHCI_DIV_MASK) << SDHCI_DIVIDER_SHIFT)
        | (((encoded_divider & SDHCI_DIV_HI_MASK) >> 8) << SDHCI_DIVIDER_HI_SHIFT)
}

fn select_card_command(rca: u16) -> CommandSpec {
    CommandSpec {
        idx: MMC_CMD_SELECT_CARD,
        arg: u32::from(rca) << 16,
        resp_type: RespType::R1b,
    }
}

fn property_string_matches(
    view: &dtb::DtbNodeView<'_, '_>,
    key: &str,
    expected: &str,
    invalid_msg: &'static str,
) -> Result<bool, SdhcError> {
    let Some(bytes) = view.property_bytes(key).map_err(SdhcError::DtbParse)? else {
        return Ok(false);
    };
    let value = bytes.split(|byte| *byte == 0).next().unwrap_or(bytes);
    let value = core::str::from_utf8(value).map_err(|_| SdhcError::DtbInvalid(invalid_msg))?;
    Ok(value == expected)
}

fn property_u32_or_default(
    view: &dtb::DtbNodeView<'_, '_>,
    key: &str,
    default: u32,
    invalid_msg: &'static str,
) -> Result<u32, SdhcError> {
    match view.property_u32_be(key) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Ok(default),
        Err(_) => Err(SdhcError::DtbInvalid(invalid_msg)),
    }
}

fn decode_reg_name(name: &str) -> SdhcRegName {
    match name {
        "host" => SdhcRegName::Host,
        "cfg" => SdhcRegName::Cfg,
        "busisol" => SdhcRegName::BusIsol,
        "lcpll" => SdhcRegName::LcPll,
        _ => SdhcRegName::Other,
    }
}

fn parse_reg_names(
    bytes: &[u8],
) -> Result<([SdhcRegName; SDHC_MAX_REG_ENTRIES], usize), SdhcError> {
    let mut names = [SdhcRegName::Other; SDHC_MAX_REG_ENTRIES];
    let mut count = 0usize;
    let mut start = 0usize;
    while start < bytes.len() {
        let end =
            start
                + bytes[start..].iter().position(|byte| *byte == 0).ok_or(
                    SdhcError::DtbInvalid("sdhc: reg-names missing NUL terminator"),
                )?;
        if count >= names.len() {
            return Err(SdhcError::DtbInvalid("sdhc: too many reg-names entries"));
        }
        let name = core::str::from_utf8(&bytes[start..end])
            .map_err(|_| SdhcError::DtbInvalid("sdhc: reg-names contains invalid UTF-8"))?;
        names[count] = decode_reg_name(name);
        count += 1;
        start = end + 1;
    }
    Ok((names, count))
}

fn assign_region(
    slot: &mut Option<HostRegion>,
    region: HostRegion,
    duplicate_msg: &'static str,
) -> Result<(), SdhcError> {
    if slot.replace(region).is_some() {
        return Err(SdhcError::DtbInvalid(duplicate_msg));
    }
    Ok(())
}

fn parse_named_regions(view: &dtb::DtbNodeView<'_, '_>) -> Result<NamedRegions, SdhcError> {
    let Some(reg_names_bytes) = view
        .property_bytes("reg-names")
        .map_err(SdhcError::DtbParse)?
    else {
        return Ok(NamedRegions::default());
    };
    let (reg_names, reg_name_count) = parse_reg_names(reg_names_bytes)?;

    let mut regs = [HostRegion::default(); SDHC_MAX_REG_ENTRIES];
    let mut reg_count = 0usize;
    let mut reg_iter = view.reg_iter().map_err(SdhcError::DtbParse)?;
    while let Some(entry) = reg_iter.next() {
        if reg_count >= regs.len() {
            return Err(SdhcError::DtbInvalid("sdhc: too many reg entries"));
        }
        let (base, size) = entry.map_err(SdhcError::DtbParse)?;
        regs[reg_count] = HostRegion { base, size };
        reg_count += 1;
    }
    if reg_count != reg_name_count {
        return Err(SdhcError::DtbInvalid("sdhc: reg/reg-names length mismatch"));
    }

    let mut named = NamedRegions::default();
    for index in 0..reg_count {
        match reg_names[index] {
            SdhcRegName::Host => {
                assign_region(&mut named.host, regs[index], "sdhc: duplicate host reg")?
            }
            SdhcRegName::Cfg => {
                assign_region(&mut named.cfg, regs[index], "sdhc: duplicate cfg reg")?
            }
            SdhcRegName::BusIsol => assign_region(
                &mut named.busisol,
                regs[index],
                "sdhc: duplicate busisol reg",
            )?,
            SdhcRegName::LcPll => {
                assign_region(&mut named.lcpll, regs[index], "sdhc: duplicate lcpll reg")?
            }
            SdhcRegName::Other => {}
        }
    }
    Ok(named)
}

fn has_wifi_child(view: &dtb::DtbNodeView<'_, '_>) -> Result<bool, SdhcError> {
    let mut found = false;
    let walk = view.for_each_child_view(&mut |child| {
        if child.name() == "wifi@1" {
            found = true;
            return Ok(core::ops::ControlFlow::Break(()));
        }
        Ok(core::ops::ControlFlow::Continue(()))
    });
    match walk {
        Ok(core::ops::ControlFlow::Break(())) | Ok(core::ops::ControlFlow::Continue(())) => {
            Ok(found)
        }
        Err(WalkError::Dtb(err)) => Err(SdhcError::DtbParse(err)),
        Err(WalkError::User(err)) => Err(err),
    }
}

fn parse_candidate_from_view(
    view: &dtb::DtbNodeView<'_, '_>,
    dtb: &DtbParser,
) -> Result<SdhcDtCandidate, SdhcError> {
    let named = parse_named_regions(view)?;
    Ok(SdhcDtCandidate {
        host: named.host,
        cfg: named.cfg,
        busisol: named.busisol,
        lcpll: named.lcpll,
        max_clock_hz: find_clock_frequency(view, dtb)?,
        has_brcmstb_compat: view
            .compatible_contains(DT_COMPAT_BRCMSTB_SDHCI)
            .map_err(SdhcError::DtbParse)?,
        status_okay: property_string_matches(
            view,
            "status",
            "okay",
            "sdhc: invalid status property",
        )?,
        bus_width: property_u32_or_default(
            view,
            "bus-width",
            0,
            "sdhc: invalid bus-width property",
        )?,
        non_removable: view
            .property_bytes("non-removable")
            .map_err(SdhcError::DtbParse)?
            .is_some(),
        has_wifi_child: has_wifi_child(view)?,
    })
}

fn matching_candidate_indices(
    candidates: &[SdhcDtCandidate],
    predicate: impl Fn(&SdhcDtCandidate) -> bool,
) -> ([usize; SDHC_MAX_DT_CANDIDATES], usize) {
    let mut indices = [usize::MAX; SDHC_MAX_DT_CANDIDATES];
    let mut count = 0usize;
    for (index, candidate) in candidates.iter().enumerate() {
        if predicate(candidate) {
            indices[count] = index;
            count += 1;
        }
    }
    (indices, count)
}

fn prefer_candidate_subset(
    candidates: &[SdhcDtCandidate],
    indices: &mut [usize; SDHC_MAX_DT_CANDIDATES],
    len: usize,
    predicate: impl Fn(&SdhcDtCandidate) -> bool,
) -> usize {
    let mut preferred = [usize::MAX; SDHC_MAX_DT_CANDIDATES];
    let mut preferred_len = 0usize;
    for position in 0..len {
        let index = indices[position];
        if predicate(&candidates[index]) {
            preferred[preferred_len] = index;
            preferred_len += 1;
        }
    }
    if preferred_len == 0 {
        return len;
    }
    indices[..preferred_len].copy_from_slice(&preferred[..preferred_len]);
    preferred_len
}

#[cfg(test)]
fn log_dt_candidates(candidates: &[SdhcDtCandidate]) {
    for (index, candidate) in candidates.iter().enumerate() {
        std::println!(
            "sdhc: dt candidate[{}] host={:?} cfg={:?} bus_width={} non_removable={} has_wifi_child={} has_brcmstb_compat={}",
            index,
            candidate.host,
            candidate.cfg,
            candidate.bus_width,
            candidate.non_removable,
            candidate.has_wifi_child,
            candidate.has_brcmstb_compat
        );
    }
}

#[cfg(all(not(test), debug_assertions))]
fn log_dt_candidates(candidates: &[SdhcDtCandidate]) {
    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "sdhc: dt candidate[{}] host={:?} cfg={:?} bus_width={} non_removable={} has_wifi_child={} has_brcmstb_compat={}",
            index,
            candidate.host,
            candidate.cfg,
            candidate.bus_width,
            candidate.non_removable,
            candidate.has_wifi_child,
            candidate.has_brcmstb_compat
        );
    }
}

#[cfg(not(any(test, debug_assertions)))]
fn log_dt_candidates(_candidates: &[SdhcDtCandidate]) {}

fn select_sd_slot_candidate(candidates: &[SdhcDtCandidate]) -> Result<SdhcConfig, SdhcError> {
    let (mut indices, mut len) =
        matching_candidate_indices(candidates, |candidate| candidate.is_supported_shape());
    if len == 0 {
        return Err(SdhcError::DtbInvalid("sdhc: no valid SD-slot candidate"));
    }

    len = prefer_candidate_subset(candidates, &mut indices, len, |candidate| {
        candidate.host_base() == Some(BCM2712_SD_SLOT_HOST_BASE)
    });
    if len > 1 {
        len = prefer_candidate_subset(candidates, &mut indices, len, |candidate| {
            !candidate.non_removable
        });
    }
    if len > 1 {
        len = prefer_candidate_subset(candidates, &mut indices, len, |candidate| {
            !candidate.has_wifi_child
        });
    }
    if len > 1 {
        len = prefer_candidate_subset(candidates, &mut indices, len, |candidate| {
            candidate.has_brcmstb_compat
        });
    }

    match len {
        1 => {
            let candidate = candidates[indices[0]];
            if !candidate.is_viable_sd_slot() {
                return Err(SdhcError::DtbInvalid("sdhc: no valid SD-slot candidate"));
            }
            candidate.into_config()
        }
        0 => Err(SdhcError::DtbInvalid("sdhc: no valid SD-slot candidate")),
        _ => Err(SdhcError::DtbInvalid(
            "sdhc: ambiguous DT candidate selection",
        )),
    }
}

fn parse_from_dtb(dtb: &DtbParser) -> Result<SdhcConfig, SdhcError> {
    let mut candidates = [SdhcDtCandidate::default(); SDHC_MAX_DT_CANDIDATES];
    let mut count = 0usize;
    let walk =
        dtb.find_nodes_by_compatible_view(DT_COMPAT_BCM2712_SDHCI, &mut |view, _node_name| {
            if count >= candidates.len() {
                return Err(WalkError::User(SdhcError::DtbInvalid(
                    "sdhc: too many compatible nodes",
                )));
            }
            candidates[count] = parse_candidate_from_view(view, dtb).map_err(WalkError::User)?;
            count += 1;
            Ok(core::ops::ControlFlow::Continue(()))
        });

    match walk {
        Ok(core::ops::ControlFlow::Break(())) | Ok(core::ops::ControlFlow::Continue(())) => {}
        Err(WalkError::Dtb(err)) => return Err(SdhcError::DtbParse(err)),
        Err(WalkError::User(err)) => return Err(err),
    }
    if count == 0 {
        return Err(SdhcError::DtbNotFound);
    }
    log_dt_candidates(&candidates[..count]);
    select_sd_slot_candidate(&candidates[..count])
}

fn find_clock_frequency(
    view: &dtb::DtbNodeView<'_, '_>,
    dtb: &DtbParser,
) -> Result<u32, SdhcError> {
    let Some(clocks) = view.property_bytes("clocks").map_err(SdhcError::DtbParse)? else {
        return Ok(SDHC_DEFAULT_MAX_CLOCK_HZ);
    };
    if clocks.len() < 4 {
        return Err(SdhcError::DtbInvalid("sdhc: clocks property too short"));
    }
    let phandle = u32::from_be_bytes(
        clocks[0..4]
            .try_into()
            .map_err(|_| SdhcError::DtbInvalid("sdhc: invalid clocks phandle"))?,
    );
    let maybe_hz = dtb
        .property_u32_be_by_phandle(phandle, "clock-frequency")
        .map_err(SdhcError::DtbParse)?;
    Ok(maybe_hz.unwrap_or(SDHC_DEFAULT_MAX_CLOCK_HZ))
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use dtb::DeviceTree;
    use dtb::DeviceTreeEditExt;
    use dtb::DtbParser;
    use dtb::NameRef;
    use dtb::NodeEditExt;
    use dtb::ValueRef;

    use super::decode_capacity_blocks;
    use super::encode_clock_divider;
    use super::pack_clock_control_divider;
    use super::parse_from_dtb;
    use super::select_card_command;
    use super::select_sd_slot_candidate;
    use super::RespType;
    use super::SdhcConfig;
    use super::SdhcDtCandidate;
    use super::SdhcError;
    use super::BCM2712_SD_SLOT_HOST_BASE;
    use super::DT_COMPAT_BCM2712_SDHCI;
    use super::DT_COMPAT_BRCMSTB_SDHCI;
    use super::MMC_CMD_SELECT_CARD;
    use super::SDHC_BLOCK_SIZE;
    use super::SDHC_MAX_TRANSFER_BLOCKS_PER_CMD;

    #[derive(Clone, Copy)]
    struct TestNodeSpec<'a> {
        name: &'a str,
        reg_names: &'a [&'a str],
        regs: &'a [(u64, u64)],
        non_removable: bool,
        wifi_child: bool,
        status: &'a str,
        bus_width: u32,
        has_brcmstb_compat: bool,
    }

    fn u32_prop(value: u32) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    fn string_prop(value: &str) -> Vec<u8> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }

    fn string_list(values: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    fn reg_prop(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (addr, size) in entries {
            bytes.extend_from_slice(&((*addr >> 32) as u32).to_be_bytes());
            bytes.extend_from_slice(&(*addr as u32).to_be_bytes());
            bytes.extend_from_slice(&((*size >> 32) as u32).to_be_bytes());
            bytes.extend_from_slice(&(*size as u32).to_be_bytes());
        }
        bytes
    }

    fn compatible_prop(has_brcmstb_compat: bool) -> Vec<u8> {
        if has_brcmstb_compat {
            string_list(&[DT_COMPAT_BCM2712_SDHCI, DT_COMPAT_BRCMSTB_SDHCI])
        } else {
            string_list(&[DT_COMPAT_BCM2712_SDHCI])
        }
    }

    fn set_property<'dtb>(
        tree: &mut dtb::DeviceTree<'dtb, dtb::Owned>,
        node: usize,
        name: &'dtb str,
        value: Vec<u8>,
    ) {
        tree.node_mut(node)
            .unwrap()
            .set_property(NameRef::Borrowed(name), ValueRef::Owned(value));
    }

    fn build_test_dtb(nodes: &[TestNodeSpec<'_>]) -> impl core::ops::Deref<Target = [u8]> {
        let mut tree = DeviceTree::with_root(NameRef::Borrowed("/"));
        tree.header.version = 17;
        tree.header.last_comp_version = 16;

        let root = tree.root;
        set_property(&mut tree, root, "#address-cells", u32_prop(2));
        set_property(&mut tree, root, "#size-cells", u32_prop(2));

        let clocks = tree.add_child(root, NameRef::Borrowed("clocks")).unwrap();
        set_property(&mut tree, clocks, "phandle", u32_prop(1));
        set_property(&mut tree, clocks, "clock-frequency", u32_prop(100_000_000));

        for spec in nodes {
            let node = tree.add_child(root, NameRef::Borrowed(spec.name)).unwrap();
            set_property(
                &mut tree,
                node,
                "compatible",
                compatible_prop(spec.has_brcmstb_compat),
            );
            set_property(&mut tree, node, "status", string_prop(spec.status));
            set_property(&mut tree, node, "bus-width", u32_prop(spec.bus_width));
            set_property(&mut tree, node, "reg", reg_prop(spec.regs));
            set_property(&mut tree, node, "reg-names", string_list(spec.reg_names));
            set_property(&mut tree, node, "clocks", u32_prop(1));

            if spec.non_removable {
                set_property(&mut tree, node, "non-removable", Vec::new());
            }
            if spec.wifi_child {
                let _ = tree.add_child(node, NameRef::Borrowed("wifi@1")).unwrap();
            }
        }

        tree.into_dtb_box().unwrap()
    }

    fn parse_test_config(nodes: &[TestNodeSpec<'_>]) -> Result<SdhcConfig, SdhcError> {
        let dtb = build_test_dtb(nodes);
        let parser = DtbParser::init((&*dtb).as_ptr() as usize).unwrap();
        parse_from_dtb(&parser)
    }

    #[test]
    fn decode_capacity_high_capacity() {
        let csd = [0u32, 0x3f, 0xffff_0000, 0];
        let blocks = decode_capacity_blocks(&csd, true).unwrap();
        assert!(blocks > 0);
    }

    #[test]
    fn decode_capacity_standard_capacity() {
        let csd = [0, 0x03ff_0000, 0xc003_8000, 0];
        let blocks = decode_capacity_blocks(&csd, false).unwrap();
        assert!(blocks > 0);
    }

    #[test]
    fn chunk_limit_matches_expected_max_io() {
        assert_eq!(SDHC_MAX_TRANSFER_BLOCKS_PER_CMD, 1024);
        assert_eq!(
            SDHC_MAX_TRANSFER_BLOCKS_PER_CMD * SDHC_BLOCK_SIZE,
            512 * 1024
        );
    }

    #[test]
    fn invalid_param_maps_to_io_invalid_param() {
        let mapped = io_api::block_device::IoError::from(SdhcError::InvalidParam);
        assert_eq!(mapped, io_api::block_device::IoError::InvalidParam);
    }

    #[test]
    fn dt_selector_prefers_sd_slot_when_both_mmc_nodes_exist() {
        let wifi_regs = &[(0x10_0110_0000, 0x104), (0x10_0110_1000, 0x80)];
        let slot_regs = &[
            (BCM2712_SD_SLOT_HOST_BASE as u64, 0x104),
            (0x10_00ff_f200, 0x80),
        ];
        let nodes = [
            TestNodeSpec {
                name: "mmc@1100000",
                reg_names: &["host", "cfg"],
                regs: wifi_regs,
                non_removable: true,
                wifi_child: true,
                status: "okay",
                bus_width: 4,
                has_brcmstb_compat: true,
            },
            TestNodeSpec {
                name: "mmc@fff000",
                reg_names: &["host", "cfg"],
                regs: slot_regs,
                non_removable: false,
                wifi_child: false,
                status: "okay",
                bus_width: 4,
                has_brcmstb_compat: true,
            },
        ];

        let config = parse_test_config(&nodes).unwrap();
        assert_eq!(config.host.base, BCM2712_SD_SLOT_HOST_BASE);
        assert_eq!(config.cfg.base, 0x10_00ff_f200);
    }

    #[test]
    fn wifi_candidate_without_slot_host_base_is_rejected() {
        let candidates = [SdhcDtCandidate {
            host: Some(super::HostRegion {
                base: 0x10_0110_0000,
                size: 0x104,
            }),
            cfg: Some(super::HostRegion {
                base: 0x10_0110_1000,
                size: 0x80,
            }),
            busisol: None,
            lcpll: None,
            max_clock_hz: 100_000_000,
            has_brcmstb_compat: true,
            status_okay: true,
            bus_width: 4,
            non_removable: true,
            has_wifi_child: true,
        }];

        let err = select_sd_slot_candidate(&candidates).unwrap_err();
        assert_eq!(
            err,
            SdhcError::DtbInvalid("sdhc: no valid SD-slot candidate")
        );
    }

    #[test]
    fn sd_slot_host_base_accepts_bus_width_eight_without_optional_regions() {
        let regs = &[
            (BCM2712_SD_SLOT_HOST_BASE as u64, 0x104),
            (0x10_00ff_f200, 0x80),
        ];
        let nodes = [TestNodeSpec {
            name: "mmc@fff000",
            reg_names: &["host", "cfg"],
            regs,
            non_removable: false,
            wifi_child: false,
            status: "okay",
            bus_width: 8,
            has_brcmstb_compat: false,
        }];

        let config = parse_test_config(&nodes).unwrap();
        assert_eq!(config.host.base, BCM2712_SD_SLOT_HOST_BASE);
        assert_eq!(config.cfg.base, 0x10_00ff_f200);
    }

    #[test]
    fn reg_names_mapping_is_independent_of_reg_order() {
        let regs = &[
            (0x10_00ff_f200, 0x80),
            (BCM2712_SD_SLOT_HOST_BASE as u64, 0x104),
        ];
        let nodes = [TestNodeSpec {
            name: "mmc@fff000",
            reg_names: &["cfg", "host"],
            regs,
            non_removable: false,
            wifi_child: false,
            status: "okay",
            bus_width: 4,
            has_brcmstb_compat: true,
        }];

        let config = parse_test_config(&nodes).unwrap();
        assert_eq!(config.host.base, BCM2712_SD_SLOT_HOST_BASE);
        assert_eq!(config.cfg.base, 0x10_00ff_f200);
    }

    #[test]
    fn ambiguous_structurally_valid_candidates_fail() {
        let candidates = [
            SdhcDtCandidate {
                host: Some(super::HostRegion {
                    base: 0x10_0200_0000,
                    size: 0x104,
                }),
                cfg: Some(super::HostRegion {
                    base: 0x10_0200_1000,
                    size: 0x80,
                }),
                busisol: None,
                lcpll: None,
                max_clock_hz: 100_000_000,
                has_brcmstb_compat: true,
                status_okay: true,
                bus_width: 4,
                non_removable: false,
                has_wifi_child: false,
            },
            SdhcDtCandidate {
                host: Some(super::HostRegion {
                    base: 0x10_0300_0000,
                    size: 0x104,
                }),
                cfg: Some(super::HostRegion {
                    base: 0x10_0300_1000,
                    size: 0x80,
                }),
                busisol: None,
                lcpll: None,
                max_clock_hz: 100_000_000,
                has_brcmstb_compat: true,
                status_okay: true,
                bus_width: 8,
                non_removable: false,
                has_wifi_child: false,
            },
        ];

        let err = select_sd_slot_candidate(&candidates).unwrap_err();
        assert_eq!(
            err,
            SdhcError::DtbInvalid("sdhc: ambiguous DT candidate selection")
        );
    }

    #[test]
    fn divider_encoding_returns_zero_when_requested_clock_meets_or_exceeds_max() {
        assert_eq!(encode_clock_divider(100_000_000, 100_000_000).unwrap(), 0);
        assert_eq!(encode_clock_divider(150_000_000, 100_000_000).unwrap(), 0);
    }

    #[test]
    fn divider_packing_uses_low_and_high_bits() {
        let encoded = encode_clock_divider(100_000, 200_000_000).unwrap();
        assert_eq!(encoded, 1000);
        assert_eq!(pack_clock_control_divider(encoded), 0xe8c0);
    }

    #[test]
    fn cmd7_select_card_uses_r1b() {
        let command = select_card_command(0x1234);
        assert_eq!(command.idx, MMC_CMD_SELECT_CARD);
        assert_eq!(command.arg, 0x1234_0000);
        assert_eq!(command.resp_type, RespType::R1b);
    }
}
