use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use dtb::DtbParser;
use dtb::WalkError;
use io_api::block_device::BlockDevice;
use io_api::block_device::IoError;
use io_api::block_device::Lba;
use mutex::pod::RawAtomicPod;
use mutex::SpinLock;
use print::println;
use timer::SystemTimer;

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
const SDIO_CFG_SD_PIN_SEL: usize = 0x44;
const SDIO_CFG_SD_PIN_SEL_MASK: u32 = 0x3;
const SDIO_CFG_SD_PIN_SEL_CARD: u32 = 1 << 1;

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

#[derive(Clone, Copy, Debug, Default)]
struct HostRegion {
    base: usize,
    size: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct SdhcConfig {
    host: HostRegion,
    cfg: HostRegion,
    max_clock_hz: u32,
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
        timer::read_counter()
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

    fn reset(&self, mask: u8) -> Result<(), SdhcError> {
        self.reg_write_u8(SDHCI_SOFTWARE_RESET, mask);
        self.wait_until(SDHC_RESET_TIMEOUT_US, |s| {
            s.reg_read_u8(SDHCI_SOFTWARE_RESET) & mask == 0
        })
    }

    fn configure_card_detect(&self) -> Result<(), SdhcError> {
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

        let div = if self.max_clock_hz <= clock_hz {
            1u16
        } else {
            let mut d = 2u16;
            while d < 2046 {
                if self.max_clock_hz / (u32::from(d)) <= clock_hz {
                    break;
                }
                d = d.saturating_add(2);
            }
            d >> 1
        };

        let mut clk: u16 = ((div & SDHCI_DIV_MASK) << SDHCI_DIVIDER_SHIFT)
            | (((div & SDHCI_DIV_HI_MASK) >> 8) << SDHCI_DIVIDER_HI_SHIFT)
            | SDHCI_CLOCK_INT_EN;
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
        for _ in 0..SDHC_ACMD41_RETRY_MAX {
            self.send_command(MMC_CMD_APP_CMD, 0, RespType::R1, None)?;
            let resp =
                self.send_command(SD_CMD_APP_SEND_OP_COND, OCR_REQUEST, RespType::R3, None)?;
            ocr = resp[0];
            if (ocr & OCR_BUSY) != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(SdhcError::Timeout);
        }
        let high_capacity = (ocr & OCR_HCS) != 0;

        let _cid = self.send_command(MMC_CMD_ALL_SEND_CID, 0, RespType::R2, None)?;
        let rca_resp = self.send_command(MMC_CMD_SET_RELATIVE_ADDR, 0, RespType::R6, None)?;
        let rca = (rca_resp[0] >> 16) as u16;
        let csd = self.send_command(MMC_CMD_SEND_CSD, u32::from(rca) << 16, RespType::R2, None)?;
        self.send_command(
            MMC_CMD_SELECT_CARD,
            u32::from(rca) << 16,
            RespType::R1,
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

#[derive(Clone, Copy, Debug)]
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

fn parse_from_dtb(dtb: &DtbParser) -> Result<SdhcConfig, SdhcError> {
    let mut result = None;
    let walk = dtb.find_nodes_by_compatible_view(DT_COMPAT_BCM2712_SDHCI, &mut |view, _name| {
        if !view
            .compatible_contains(DT_COMPAT_BRCMSTB_SDHCI)
            .map_err(WalkError::Dtb)?
        {
            return Ok(core::ops::ControlFlow::Continue(()));
        }

        let mut reg_iter = view.reg_iter().map_err(WalkError::Dtb)?;
        let host = reg_iter
            .next()
            .ok_or(SdhcError::DtbInvalid("sdhc: missing host reg"))
            .map_err(WalkError::User)?;
        let host = host.map_err(WalkError::Dtb)?;
        let cfg = reg_iter
            .next()
            .ok_or(SdhcError::DtbInvalid("sdhc: missing cfg reg"))
            .map_err(WalkError::User)?;
        let cfg = cfg.map_err(WalkError::Dtb)?;

        let max_clock_hz = find_clock_frequency(view, dtb).map_err(WalkError::User)?;
        result = Some(SdhcConfig {
            host: HostRegion {
                base: host.0,
                size: host.1,
            },
            cfg: HostRegion {
                base: cfg.0,
                size: cfg.1,
            },
            max_clock_hz,
        });
        Ok(core::ops::ControlFlow::Break(()))
    });

    match walk {
        Ok(core::ops::ControlFlow::Break(())) => {}
        Ok(core::ops::ControlFlow::Continue(())) => return Err(SdhcError::DtbNotFound),
        Err(WalkError::Dtb(err)) => return Err(SdhcError::DtbParse(err)),
        Err(WalkError::User(err)) => return Err(err),
    }
    result.ok_or(SdhcError::DtbNotFound)
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
    use super::SDHC_BLOCK_SIZE;
    use super::SDHC_MAX_TRANSFER_BLOCKS_PER_CMD;
    use super::SdhcError;
    use super::decode_capacity_blocks;

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
}
