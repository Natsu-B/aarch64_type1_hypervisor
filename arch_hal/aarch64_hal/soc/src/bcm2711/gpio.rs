use core::cmp::max;
use core::mem::offset_of;
use core::mem::size_of;
use core::ops::ControlFlow;

use dtb::DtbParser;
use dtb::WalkError;
use typestate::ReadOnly;
use typestate::ReadWrite;
use typestate::Readable;
use typestate::Writable;
use typestate::WriteOnly;

pub const DT_COMPAT_BCM2835_GPIO: &str = "brcm,bcm2835-gpio";
pub const GPIO_PIN_MAX: u8 = 57;
pub const GPIO_MMIO_MIN_SIZE: usize = 0x1000;

pub const UART2_TXD: u8 = 0;
pub const UART2_RXD: u8 = 1;
pub const UART2_CTS: u8 = 2;
pub const UART2_RTS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bcm2711GpioError {
    DtbParseError(&'static str),
    DtbDeviceNotFound,
    InvalidPin(u8),
    InvalidMmioRegion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Function {
    Input = 0b000,
    Output = 0b001,
    Alt0 = 0b100,
    Alt1 = 0b101,
    Alt2 = 0b110,
    Alt3 = 0b111,
    Alt4 = 0b011,
    Alt5 = 0b010,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Pull {
    None = 0b00,
    Up = 0b01,
    Down = 0b10,
}

#[repr(C)]
struct Registers {
    gpfsel: [ReadWrite<u32>; 6],    // 0x00..0x14
    _reserved_0x18: [u32; 1],       // 0x18
    gpset: [WriteOnly<u32>; 2],     // 0x1c..0x20
    _reserved_0x24: [u32; 1],       // 0x24
    gpclr: [WriteOnly<u32>; 2],     // 0x28..0x2c
    _reserved_0x30: [u32; 1],       // 0x30
    gplev: [ReadOnly<u32>; 2],      // 0x34..0x38
    _reserved_0x3c: [u32; 1],       // 0x3c
    gpeds: [ReadWrite<u32>; 2],     // 0x40..0x44
    _reserved_0x48: [u32; 1],       // 0x48
    gpren: [ReadWrite<u32>; 2],     // 0x4c..0x50
    _reserved_0x54: [u32; 1],       // 0x54
    gpfen: [ReadWrite<u32>; 2],     // 0x58..0x5c
    _reserved_0x60: [u32; 1],       // 0x60
    gphen: [ReadWrite<u32>; 2],     // 0x64..0x68
    _reserved_0x6c: [u32; 1],       // 0x6c
    gplen: [ReadWrite<u32>; 2],     // 0x70..0x74
    _reserved_0x78: [u32; 1],       // 0x78
    gparen: [ReadWrite<u32>; 2],    // 0x7c..0x80
    _reserved_0x84: [u32; 1],       // 0x84
    gpafen: [ReadWrite<u32>; 2],    // 0x88..0x8c
    _reserved_0x90_0xe0: [u32; 21], // 0x90..0xe0
    gppupdn: [ReadWrite<u32>; 4],   // 0xe4..0xf0
}

const _: () = assert!(offset_of!(Registers, gpfsel) == 0x00);
const _: () = assert!(offset_of!(Registers, gpset) == 0x1c);
const _: () = assert!(offset_of!(Registers, gpclr) == 0x28);
const _: () = assert!(offset_of!(Registers, gplev) == 0x34);
const _: () = assert!(offset_of!(Registers, gpeds) == 0x40);
const _: () = assert!(offset_of!(Registers, gpren) == 0x4c);
const _: () = assert!(offset_of!(Registers, gpfen) == 0x58);
const _: () = assert!(offset_of!(Registers, gphen) == 0x64);
const _: () = assert!(offset_of!(Registers, gplen) == 0x70);
const _: () = assert!(offset_of!(Registers, gparen) == 0x7c);
const _: () = assert!(offset_of!(Registers, gpafen) == 0x88);
const _: () = assert!(offset_of!(Registers, gppupdn) == 0xe4);
const _: () = assert!(size_of::<Registers>() == 0xf4);

pub struct Bcm2711Gpio {
    regs: &'static Registers,
}

impl Bcm2711Gpio {
    #[inline]
    fn validate_pin(pin: u8) -> Result<(), Bcm2711GpioError> {
        if pin > GPIO_PIN_MAX {
            return Err(Bcm2711GpioError::InvalidPin(pin));
        }
        Ok(())
    }

    #[inline]
    fn word_bit(pin: u8) -> (usize, u32) {
        let word = (pin / 32) as usize;
        let bit = 1u32 << (pin % 32);
        (word, bit)
    }

    fn disable_detect_sources(&self, pin: u8) -> Result<(), Bcm2711GpioError> {
        Self::validate_pin(pin)?;
        let (word, bit) = Self::word_bit(pin);
        self.regs.gpren[word].clear_bits(bit);
        self.regs.gpfen[word].clear_bits(bit);
        self.regs.gphen[word].clear_bits(bit);
        self.regs.gplen[word].clear_bits(bit);
        self.regs.gparen[word].clear_bits(bit);
        self.regs.gpafen[word].clear_bits(bit);
        Ok(())
    }

    /// Creates a GPIO controller view from a mapped register base address.
    ///
    /// # Safety
    /// `mmio_base` must point to the BCM2711 GPIO register block, be mapped as
    /// device memory, remain valid for the lifetime of this instance, and must
    /// not be used with conflicting mutable aliasing by other code.
    pub unsafe fn new(mmio_base: usize) -> Self {
        // SAFETY: The caller guarantees that `mmio_base` is a valid, properly
        // mapped pointer to a `Registers`-compatible BCM2711 GPIO frame with
        // non-conflicting aliasing for the lifetime of the returned instance.
        let regs = unsafe { &*(mmio_base as *const Registers) };
        Self { regs }
    }

    pub fn set_function(&self, pin: u8, func: Function) -> Result<(), Bcm2711GpioError> {
        Self::validate_pin(pin)?;

        let reg_index = (pin / 10) as usize;
        let shift = ((pin % 10) * 3) as u32;
        let mask = 0b111u32 << shift;
        let value = (func as u32) << shift;

        self.regs.gpfsel[reg_index].update_bits(mask, value);
        Ok(())
    }

    pub fn set_pull(&self, pin: u8, pull: Pull) -> Result<(), Bcm2711GpioError> {
        Self::validate_pin(pin)?;

        let reg_index = (pin / 16) as usize;
        let shift = ((pin % 16) * 2) as u32;
        let mask = 0b11u32 << shift;
        let value = (pull as u32) << shift;

        self.regs.gppupdn[reg_index].update_bits(mask, value);
        Ok(())
    }

    pub fn write_pin(&self, pin: u8, high: bool) -> Result<(), Bcm2711GpioError> {
        Self::validate_pin(pin)?;
        let (word, bit) = Self::word_bit(pin);
        if high {
            self.regs.gpset[word].write(bit);
        } else {
            self.regs.gpclr[word].write(bit);
        }
        Ok(())
    }

    pub fn read_level(&self, pin: u8) -> Result<bool, Bcm2711GpioError> {
        Self::validate_pin(pin)?;
        let (word, bit) = Self::word_bit(pin);
        Ok((self.regs.gplev[word].read() & bit) != 0)
    }

    pub fn clear_event(&self, pin: u8) -> Result<(), Bcm2711GpioError> {
        Self::validate_pin(pin)?;
        let (word, bit) = Self::word_bit(pin);
        self.regs.gpeds[word].write(bit);
        Ok(())
    }

    pub fn is_event_pending(&self, pin: u8) -> Result<bool, Bcm2711GpioError> {
        Self::validate_pin(pin)?;
        let (word, bit) = Self::word_bit(pin);
        Ok((self.regs.gpeds[word].read() & bit) != 0)
    }

    /// Configures GPIO muxing and pulls for UART2 on BCM2711.
    ///
    /// GPIO0/1 are also used by HAT ID EEPROM (I2C0) on many boards, so using
    /// UART2 there is board-specific and may conflict with HAT probing.
    ///
    /// This function only programs GPIO mux/pull/event-detect state; it does
    /// not enable or configure the UART2 PL011 peripheral itself.
    pub fn configure_uart2_pins(
        &self,
        flow_control: bool,
        pull_rx: Pull,
    ) -> Result<(), Bcm2711GpioError> {
        Self::validate_pin(UART2_TXD)?;
        Self::validate_pin(UART2_RXD)?;
        if flow_control {
            Self::validate_pin(UART2_CTS)?;
            Self::validate_pin(UART2_RTS)?;
        }

        for pin in [UART2_TXD, UART2_RXD] {
            self.clear_event(pin)?;
            self.disable_detect_sources(pin)?;
        }
        if flow_control {
            for pin in [UART2_CTS, UART2_RTS] {
                self.clear_event(pin)?;
                self.disable_detect_sources(pin)?;
            }
        }

        self.set_pull(UART2_TXD, Pull::None)?;
        self.set_pull(UART2_RXD, pull_rx)?;
        self.set_function(UART2_TXD, Function::Alt4)?;
        self.set_function(UART2_RXD, Function::Alt4)?;

        if flow_control {
            self.set_pull(UART2_CTS, Pull::None)?;
            self.set_pull(UART2_RTS, Pull::None)?;
            self.set_function(UART2_CTS, Function::Alt4)?;
            self.set_function(UART2_RTS, Function::Alt4)?;
        }

        Ok(())
    }
}

pub fn gpio_mmio_from_dtb(dtb: &DtbParser) -> Result<common::MmioRegion, Bcm2711GpioError> {
    let result = dtb.find_nodes_by_compatible_view(DT_COMPAT_BCM2835_GPIO, &mut |view, _name| {
        let reg = view
            .reg_iter()
            .map_err(WalkError::Dtb)?
            .next()
            .ok_or(Bcm2711GpioError::InvalidMmioRegion)?
            .map_err(WalkError::Dtb)?;

        let base = reg.0 as usize;
        let dt_size = reg.1 as usize;
        if base == 0 || dt_size == 0 {
            return Err(Bcm2711GpioError::InvalidMmioRegion.into());
        }
        let size = max(dt_size, GPIO_MMIO_MIN_SIZE);
        Ok(ControlFlow::Break(common::MmioRegion { base, size }))
    });

    match result {
        Ok(ControlFlow::Break(region)) => Ok(region),
        Ok(ControlFlow::Continue(())) => Err(Bcm2711GpioError::DtbDeviceNotFound),
        Err(WalkError::Dtb(err)) => Err(Bcm2711GpioError::DtbParseError(err)),
        Err(WalkError::User(err)) => Err(err),
    }
}
