//! RP1 BAR-relative peripheral mapping helpers for BCM2712.

use crate::bcm2712::Bcm2712Error;
use crate::bcm2712::Rp1Config;
use crate::bcm2712::pcie_validation;
use cpu::dsb_sy;

pub const RP1_PERIPHERAL_SIZE: u64 = pcie_validation::RP1_PERIPHERAL_SIZE;
/// RP1 `dma-ranges` maps local APB0 peripherals from this 40-bit system
/// address. The RP1 DW AXI DMAC must use this address, not the CPU BAR alias.
pub const RP1_PERIPHERAL_DMA_BASE: u64 = pcie_validation::RP1_PERIPHERAL_DMA_BASE;
// Verified by the existing Raspberry Pi 5 boot path and pIRQ hook in this repository.
pub const RP1_UART0_OFFSET: u64 = 0x0003_0000;
pub const RP1_UART1_OFFSET: u64 = 0x0003_4000;
pub const RP1_CLOCKS_OFFSET: u64 = 0x0001_8000;
pub const RP1_GPIO_BANK0_OFFSET: u64 = 0x000d_0000;
/// RP1 RIO bank 0.  Bank 1 registers follow at a 0x20-byte stride and
/// control GPIOs 28..53, including the Ethernet PHY reset pin GPIO32.
pub const RP1_RIO_BANK0_OFFSET: u64 = 0x000e_0000;
pub const RP1_PAD_BANK0_OFFSET: u64 = 0x000f_0000;
pub const RP1_DMA_OFFSET: u64 = 0x0018_8000;
pub const RP1_GEM_OFFSET: u64 = 0x0010_0000;
pub const RP1_GEM_CFG_OFFSET: u64 = 0x0010_4000;
// Verified by the existing Raspberry Pi 5 UART pinmux path in `rpi_boot`.
pub const RP1_GPIO_OFFSET: u64 = RP1_GPIO_BANK0_OFFSET;

const RP1_GPIO_CTRL_FUNCSEL_MASK: u32 = 0x0000_001f;
const RP1_GPIO_CTRL_OUTOVER_MASK: u32 = 0x0000_3000;
const RP1_GPIO_CTRL_OEOVER_MASK: u32 = 0x0000_c000;
const RP1_GPIO_CTRL_INOVER_MASK: u32 = 0x0003_0000;
const RP1_GPIO_CTRL_OVERRIDE_MASK: u32 =
    RP1_GPIO_CTRL_OUTOVER_MASK | RP1_GPIO_CTRL_OEOVER_MASK | RP1_GPIO_CTRL_INOVER_MASK;

const RP1_GPIO_FUNCSEL_UART0: u32 = 4;
// Linux RP1 function-select numbering: alt0..alt4 occupy 0..4, and the
// software-controlled RIO GPIO function is select 5.
const RP1_GPIO_FUNCSEL_GPIO: u32 = 5;

const RP1_RIO_BANK_STRIDE: usize = 0x4000;
const RP1_RIO_OUT_SET_OFFSET: usize = 0x2000;
const RP1_RIO_OUT_CLR_OFFSET: usize = 0x3000;
const RP1_RIO_OE_SET_OFFSET: usize = 0x2004;

const RP1_PAD_SCHMITT: u32 = 1 << 1;
const RP1_PAD_PULL_SHIFT: u32 = 2;
const RP1_PAD_PULL_MASK: u32 = 0b11 << RP1_PAD_PULL_SHIFT;
const RP1_PAD_PULL_UP: u32 = 2 << RP1_PAD_PULL_SHIFT;
const RP1_PAD_INPUT_ENABLE: u32 = 1 << 6;
const RP1_PAD_OUTPUT_DISABLE: u32 = 1 << 7;

const RP1_CLK_UART_CTRL_OFFSET: usize = 0x54;
const RP1_CLK_UART_DIV_INT_OFFSET: usize = 0x58;
const RP1_CLK_UART_SEL_OFFSET: usize = 0x60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rp1PeripheralMap {
    base: u64,
    size: u64,
}

impl Rp1PeripheralMap {
    pub fn from_config(config: &Rp1Config) -> Result<Self, Bcm2712Error> {
        let (base, size) = config.peripheral_addr.ok_or(Bcm2712Error::InvalidWindow)?;
        if size == 0 || size > RP1_PERIPHERAL_SIZE {
            return Err(Bcm2712Error::InvalidWindow);
        }
        Ok(Self { base, size })
    }

    pub const fn new(base: u64, size: u64) -> Self {
        Self { base, size }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn mmio_base(&self, offset: u64, size: u64) -> Result<usize, Bcm2712Error> {
        if size == 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let end = offset
            .checked_add(size)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        if end > self.size || end > RP1_PERIPHERAL_SIZE {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let addr = self
            .base
            .checked_add(offset)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        usize::try_from(addr).map_err(|_| Bcm2712Error::InvalidWindow)
    }

    pub fn rp1_uart0_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_UART0_OFFSET, 0x1000)
    }

    pub fn rp1_uart1_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_UART1_OFFSET, 0x1000)
    }

    pub fn rp1_gpio_bank0_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_GPIO_BANK0_OFFSET, 0x1000)
    }

    pub fn rp1_pad_bank0_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_PAD_BANK0_OFFSET, 0x1000)
    }

    pub fn rp1_clocks_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_CLOCKS_OFFSET, 0x1000)
    }

    pub fn rp1_dmac_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_DMA_OFFSET, 0x1000)
    }

    pub fn rp1_rio_bank0_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_RIO_BANK0_OFFSET, 0x1000)
    }

    pub fn rp1_gem_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_GEM_OFFSET, 0x4000)
    }

    pub fn rp1_gem_cfg_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_GEM_CFG_OFFSET, 0x1000)
    }

    /// Translate a CPU BAR1 MMIO address to RP1's local DMA address space.
    /// The caller supplies an address previously validated as belonging to
    /// this BAR1 map; the result matches the RP1 `dma-ranges` APB0 mapping.
    pub fn peripheral_dma_addr(&self, cpu_mmio: u64, size: u64) -> Result<u64, Bcm2712Error> {
        if self.size > RP1_PERIPHERAL_SIZE {
            return Err(Bcm2712Error::InvalidWindow);
        }
        pcie_validation::rp1_peripheral_dma_address(self.base, cpu_mmio, size)
            .ok_or(Bcm2712Error::InvalidWindow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rp1Pull {
    None,
    Up,
    Down,
}

#[derive(Debug, Clone, Copy)]
pub struct Rp1GpioBank0 {
    gpio_base: usize,
    rio_base: usize,
    pad_base: usize,
}

impl Rp1GpioBank0 {
    pub fn from_map(map: &Rp1PeripheralMap) -> Result<Self, Bcm2712Error> {
        Ok(Self {
            gpio_base: map.rp1_gpio_bank0_base()?,
            rio_base: map.rp1_rio_bank0_base()?,
            pad_base: map.rp1_pad_bank0_base()?,
        })
    }

    /// Configure an RP1 GPIO as a normal software-controlled output.
    ///
    /// The RP1 GPIO block keeps GPIO28..GPIO53 in bank 1; GPIO32 is bank 1,
    /// bit 4.  The GPIO control and pad registers remain indexed by the
    /// absolute GPIO number, while RIO uses the bank-local bit number.
    pub fn configure_gpio_output(&self, pin: usize) -> Result<(), Bcm2712Error> {
        let (bank, bit) = Self::rio_bank_bit(pin)?;
        let ctrl_offset = bank * RP1_RIO_BANK_STRIDE + bit * 8 + 4;
        let ctrl = read32(self.gpio_base + ctrl_offset)
            & !(RP1_GPIO_CTRL_FUNCSEL_MASK | RP1_GPIO_CTRL_OVERRIDE_MASK);
        write32(self.gpio_base + ctrl_offset, ctrl | RP1_GPIO_FUNCSEL_GPIO);

        let pad_offset = bank * RP1_RIO_BANK_STRIDE + 0x04 + bit * 4;
        let pad =
            (read32(self.pad_base + pad_offset) | RP1_PAD_INPUT_ENABLE) & !RP1_PAD_OUTPUT_DISABLE;
        write32(self.pad_base + pad_offset, pad);

        write32(
            self.rio_base + bank * RP1_RIO_BANK_STRIDE + RP1_RIO_OE_SET_OFFSET,
            1u32 << bit,
        );
        dsb_sy();
        Ok(())
    }

    /// Drive a GPIO configured by [`Self::configure_gpio_output`] low or high.
    pub fn set_gpio_output(&self, pin: usize, high: bool) -> Result<(), Bcm2712Error> {
        let (bank, bit) = Self::rio_bank_bit(pin)?;
        let offset = if high {
            RP1_RIO_OUT_SET_OFFSET
        } else {
            RP1_RIO_OUT_CLR_OFFSET
        };
        write32(
            self.rio_base + bank * RP1_RIO_BANK_STRIDE + offset,
            1u32 << bit,
        );
        dsb_sy();
        Ok(())
    }

    fn rio_bank_bit(pin: usize) -> Result<(usize, usize), Bcm2712Error> {
        // RP1 has three internal I/O banks. GPIO32 is bank 1, pin offset 4.
        if pin < 28 {
            Ok((0, pin))
        } else if pin < 34 {
            Ok((1, pin - 28))
        } else if pin < 54 {
            Ok((2, pin - 34))
        } else {
            Err(Bcm2712Error::InvalidWindow)
        }
    }

    pub fn configure_uart0_14_15_like_linux(&self) {
        for pin in [14usize, 15usize] {
            let ctrl_offset = pin * 8 + 4;
            let ctrl = read32(self.gpio_base + ctrl_offset)
                & !(RP1_GPIO_CTRL_FUNCSEL_MASK | RP1_GPIO_CTRL_OVERRIDE_MASK);
            write32(self.gpio_base + ctrl_offset, ctrl | RP1_GPIO_FUNCSEL_UART0);

            let pad_offset = 0x04 + pin * 4;
            let pad = (read32(self.pad_base + pad_offset) | RP1_PAD_INPUT_ENABLE)
                & !RP1_PAD_OUTPUT_DISABLE;
            write32(self.pad_base + pad_offset, pad);
        }

        // GPIO14 TXD0 uses the Linux DT bias-disable configuration.
        let tx_pad_offset = 0x04 + 14 * 4;
        let tx_pad = read32(self.pad_base + tx_pad_offset) & !RP1_PAD_PULL_MASK;
        write32(self.pad_base + tx_pad_offset, tx_pad | RP1_PAD_INPUT_ENABLE);

        // GPIO15 RXD0 uses the Linux DT pull-up and Schmitt configuration.
        let rx_pad_offset = 0x04 + 15 * 4;
        let rx_pad = read32(self.pad_base + rx_pad_offset) & !RP1_PAD_PULL_MASK;
        write32(
            self.pad_base + rx_pad_offset,
            rx_pad | RP1_PAD_SCHMITT | RP1_PAD_PULL_UP | RP1_PAD_INPUT_ENABLE,
        );

        dsb_sy();
    }

    pub fn gpio_ctrl(&self, pin: usize) -> u32 {
        read32(self.gpio_base + pin * 8 + 4)
    }

    pub fn pad_ctrl(&self, pin: usize) -> u32 {
        read32(self.pad_base + 0x04 + pin * 4)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rp1UartClockSnapshot {
    pub ctrl: u32,
    pub div_int: u32,
    pub sel: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Rp1Clocks {
    base: usize,
}

impl Rp1Clocks {
    pub fn from_map(map: &Rp1PeripheralMap) -> Result<Self, Bcm2712Error> {
        Ok(Self {
            base: map.rp1_clocks_base()?,
        })
    }

    pub fn uart_snapshot(&self) -> Rp1UartClockSnapshot {
        Rp1UartClockSnapshot {
            ctrl: read32(self.base + RP1_CLK_UART_CTRL_OFFSET),
            div_int: read32(self.base + RP1_CLK_UART_DIV_INT_OFFSET),
            sel: read32(self.base + RP1_CLK_UART_SEL_OFFSET),
        }
    }
}

fn read32(addr: usize) -> u32 {
    // SAFETY: caller passes a valid, naturally aligned RP1 32-bit MMIO address.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn write32(addr: usize, value: u32) {
    // SAFETY: caller passes a valid, naturally aligned RP1 32-bit MMIO address.
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}
