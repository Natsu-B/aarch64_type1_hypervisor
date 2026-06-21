//! RP1 BAR-relative peripheral mapping helpers for BCM2712.

use crate::bcm2712::Bcm2712Error;
use crate::bcm2712::Rp1Config;

pub const RP1_PERIPHERAL_SIZE: u64 = 0x40_0000;
// Verified by the existing Raspberry Pi 5 boot path and pIRQ hook in this repository.
pub const RP1_UART0_OFFSET: u64 = 0x3_0000;
pub const RP1_GEM_OFFSET: u64 = 0x0010_0000;
pub const RP1_GEM_CFG_OFFSET: u64 = 0x0010_4000;
// Verified by the existing Raspberry Pi 5 UART pinmux path in `rpi_boot`.
pub const RP1_GPIO_OFFSET: u64 = 0x000d_0000;

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

    pub fn rp1_gem_base(&self) -> Result<usize, Bcm2712Error> {
        self.mmio_base(RP1_GEM_OFFSET, 0x4000)
    }
}
