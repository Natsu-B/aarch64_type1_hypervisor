#![allow(dead_code)]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::ptr::read_volatile;
use core::ptr::slice_from_raw_parts;
use core::ptr::slice_from_raw_parts_mut;
use core::ptr::write_volatile;
use core::time::Duration;
use pci::PCIConfigRegType0;
use pci::PCIConfigRegType1;
use pci::PciCapPtr;
use pci::PciCapabilityHead;
use pci::PciCmdStatus;
use pci::msix::PciCapabilityMsiX;
use pci::msix::PciCapabilityMsiXConfigurations;
use pci::msix::PciMsiXTable;
use pci::msix::PciMsiXTableVectorControl;
use print::println;
use typestate::ReadWrite;
use typestate::Readable;
use typestate::Writable;
use typestate::bitregs;

use crate::bcm2712::Bcm2712Error;
use crate::bcm2712::MsiXTablePtr;
use crate::bcm2712::pcie_validation;
use timer::SystemTimer;

const _: () = assert!(offset_of!(BrcmStb, reserved_0x1000) == 0x1000);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x2000) == 0x2000);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x4000) == 0x4000);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x4050) == 0x4050);
const _: () = assert!(offset_of!(BrcmStb, pcie_ctrl) == 0x4064);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x40a0) == 0x40a0);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x40c4) == 0x40c4);
const _: () = assert!(offset_of!(BrcmStb, inbound_bar4_10) == 0x40d4);
const _: () = assert!(offset_of!(BrcmStb, ubus_bar4_10) == 0x410c);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x4144) == 0x4144);
const _: () = assert!(offset_of!(BrcmStb, legacy_msi_int2_status) == 0x4400);
const _: () = assert!(offset_of!(BrcmStb, legacy_msi_int2_mask_set) == 0x4410);
const _: () = assert!(offset_of!(BrcmStb, non_legacy_msi_int2_status) == 0x4500);
const _: () = assert!(offset_of!(BrcmStb, non_legacy_msi_int2_mask_set) == 0x4510);
const _: () = assert!(offset_of!(BrcmStb, reserved_0x5000) == 0x5000);
const _: () = assert!(offset_of!(BrcmStb, config_data) == 0x8000);
const _: () = assert!(offset_of!(BrcmStb, config_address) == 0x9000);
const _: () = assert!(core::mem::size_of::<BrcmStb>() == 0x10000);

const SHIFT_1MB: u64 = 20;
pub const RP1_EXPECTED_DMA_PCIE_BASE: u64 = 0x10_0000_0000;
pub const RP1_EXPECTED_DMA_CPU_BASE: u64 = 0;
pub const RP1_EXPECTED_DMA_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
/// The RP1 endpoint's firmware and Linux DTB describe BAR1 at PCI address
/// zero.  It is an intentional, valid mapping in the local full-RC layout.
const RP1_BAR1_PCIE_BASE: u64 = 0x0000_0000;
const RP1_BAR2_PCIE_BASE: u64 = 0x0040_0000;
const RP1_BAR0_PCIE_BASE: u64 = 0x0080_0000;

// BCM2712 BRCM STB PCIe offsets.  These are deliberately kept as narrow raw
// MMIO constants rather than making the `repr(C)` view more fragile.
const REG_BRCM_PCIE_CAP: usize = 0x00ac;
const REG_RC_CFG_PRIV1_ID_VAL3: usize = 0x043c;
const REG_RC_CFG_PRIV1_LINK_CAPABILITY: usize = 0x04dc;
const REG_RC_TL_VDM_CTL1: usize = 0x0a0c;
const REG_RC_TL_VDM_CTL0: usize = 0x0a20;
const REG_RC_DL_MDIO_ADDR: usize = 0x1100;
const REG_RC_DL_MDIO_WR_DATA: usize = 0x1104;
const REG_RC_PL_PHY_CTL_15: usize = 0x184c;
const REG_MISC_CTRL: usize = 0x4008;
const REG_CPU_TO_PCIE_MEM_WIN0_LO: usize = 0x400c;
const REG_CPU_TO_PCIE_MEM_WIN0_HI: usize = 0x4010;
const REG_RC_CONFIG_RETRY_TIMEOUT: usize = 0x405c;
const REG_PCIE_CTRL: usize = 0x4064;
const REG_PCIE_STATUS: usize = 0x4068;
const REG_CPU_TO_PCIE_MEM_WIN0_BASE_LIMIT: usize = 0x4070;
const REG_CPU_TO_PCIE_MEM_WIN0_BASE_HI: usize = 0x4080;
const REG_CPU_TO_PCIE_MEM_WIN0_LIMIT_HI: usize = 0x4084;
const REG_MISC_CTRL_1: usize = 0x40a0;
const REG_UBUS_CTRL: usize = 0x40a4;
const REG_UBUS_TIMEOUT: usize = 0x40a8;
const REG_VDM_PRIORITY_TO_QOS_MAP_HI: usize = 0x4164;
const REG_VDM_PRIORITY_TO_QOS_MAP_LO: usize = 0x4168;
const REG_AXI_INTF_CTRL: usize = 0x416c;
const REG_AXI_READ_ERROR_DATA: usize = 0x4170;
const REG_HARD_DEBUG: usize = 0x4304;
const REG_CONFIG_DATA: usize = 0x8000;
const REG_CONFIG_ADDRESS: usize = 0x9000;
const REG_RGR1_SW_INIT_1: usize = 0x9210;

/// PCI BDF used by the BCM2712 root complex configuration aperture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcieBdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// The RP1 is the first endpoint below the BCM2712 PCIe x4 root port.
pub const RP1_BDF: PcieBdf = PcieBdf {
    bus: 1,
    device: 0,
    function: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieLinkSpeed {
    Gen1 = 1,
    Gen2 = 2,
    Gen3 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bcm2712PcieSetup {
    pub outbound_cpu_base: u64,
    pub outbound_pcie_base: u64,
    pub outbound_size: u64,
    pub inbound_dma_window: PcieDmaWindow,
    pub target_link_speed: Option<PcieLinkSpeed>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Window<L, H> {
    pub lower: L,
    pub higher: H,
}

#[repr(C)]
pub struct BrcmStb {
    pub(crate) pci_config: PCIConfigRegType1,
    pub(crate) pcie_space: ReadWrite<[u8; 0xfc0]>,
    reserved_0x1000: [u8; 0x1000],
    reserved_0x2000: [u8; 0x2000],
    // 0x4000
    reserved_0x4000: [u8; 8],
    pub(crate) misc_ctrl: ReadWrite<MiscCtrl>,
    // outbound windows
    pub(crate) outbound_bus_window: [Window<ReadWrite<u32>, ReadWrite<u32>>; 4],
    pub(crate) inbound_bar1_3: [Window<ReadWrite<InboundBarLower>, ReadWrite<u32>>; 3],
    pub(crate) msi_bar: Window<ReadWrite<u32>, ReadWrite<u32>>,
    pub(crate) msi_data: ReadWrite<MsiData>,
    reserved_0x4050: [u8; 20],
    pub(crate) pcie_ctrl: ReadWrite<PcieCtrl>,
    pub(crate) pcie_status: ReadWrite<PcieStatus>,
    pub(crate) pcie_revision: ReadWrite<PcieRevision>,
    pub(crate) outbound_cpu_window_limit: [ReadWrite<OutBoundWinLimit>; 4],
    pub(crate) outbound_cpu_window: [Window<ReadWrite<OutBoundWin>, ReadWrite<OutBoundWin>>; 4],
    pub(crate) reserved_0x40a0: [u8; 12],
    pub(crate) ubus_bar1_3: [Window<ReadWrite<InboundUbusLower>, ReadWrite<u32>>; 3],
    reserved_0x40c4: [u8; 16],
    pub(crate) inbound_bar4_10: [Window<ReadWrite<InboundBarLower>, ReadWrite<u32>>; 7],
    pub(crate) ubus_bar4_10: [Window<ReadWrite<InboundUbusLower>, ReadWrite<u32>>; 7],
    reserved_0x4144: [u8; 0x2bc],
    // 0x4400
    pub(crate) legacy_msi_int2_status: ReadWrite<u32>,
    reserved_0x4404: [u8; 4],
    pub(crate) legacy_msi_int2_clr: ReadWrite<u32>,
    reserved_0x440c: [u8; 4],
    pub(crate) legacy_msi_int2_mask_set: ReadWrite<u32>,
    pub(crate) legacy_msi_int2_mask_clr: ReadWrite<u32>,
    reserved_0x4418: [u8; 0xe8],
    // 0x4500
    pub(crate) non_legacy_msi_int2_status: ReadWrite<u32>,
    reserved_0x4504: [u8; 4],
    pub(crate) non_legacy_msi_int2_clr: ReadWrite<u32>,
    reserved_0x450c: [u8; 4],
    pub(crate) non_legacy_msi_int2_mask_set: ReadWrite<u32>,
    pub(crate) non_legacy_msi_int2_mask_clr: ReadWrite<u32>,
    reserved_0x4518: [u8; 0xe8],
    reserved_0x4600: [u8; 0xa00],
    // 0x5000
    reserved_0x5000: [u8; 0x3000],
    // 0x8000
    pub(crate) config_data: UnsafeCell<[u8; 0x1000]>,
    // 0x9000
    pub(crate) config_address: ReadWrite<ConfigAddress>,
    reserved_0x9004: [u8; 0x6ffc],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutBoundData {
    pub pcie_base: u64,
    pub cpu_base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InBoundData {
    pub pcie_base: u64,
    pub cpu_base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcieDmaWindow {
    pub pcie_base: u64,
    pub cpu_base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
struct PcieBarProbe {
    bar: u8,
    original_low: u32,
    original_high: Option<u32>,
    probe_mask_low: u32,
    probe_mask_high: Option<u32>,
    size: u64,
}

impl PcieDmaWindow {
    pub const fn expected_rp1() -> Self {
        Self {
            pcie_base: RP1_EXPECTED_DMA_PCIE_BASE,
            cpu_base: RP1_EXPECTED_DMA_CPU_BASE,
            size: RP1_EXPECTED_DMA_SIZE,
        }
    }

    pub fn contains_cpu_phys(&self, phys: u64, len: u64) -> bool {
        range_contains(self.cpu_base, self.size, phys, len)
    }

    pub fn contains_dma_addr(&self, dma: u64, len: u64) -> bool {
        range_contains(self.pcie_base, self.size, dma, len)
    }

    pub fn cpu_phys_to_dma(&self, phys: u64, len: u64) -> Result<u64, Bcm2712Error> {
        if !self.contains_cpu_phys(phys, len) {
            return Err(Bcm2712Error::InvalidWindow);
        }

        let offset = phys
            .checked_sub(self.cpu_base)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        let dma = self
            .pcie_base
            .checked_add(offset)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        if !self.contains_dma_addr(dma, len) {
            return Err(Bcm2712Error::InvalidWindow);
        }
        Ok(dma)
    }

    pub fn dma_to_cpu_phys(&self, dma: u64, len: u64) -> Result<u64, Bcm2712Error> {
        if !self.contains_dma_addr(dma, len) {
            return Err(Bcm2712Error::InvalidWindow);
        }

        let offset = dma
            .checked_sub(self.pcie_base)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        let phys = self
            .cpu_base
            .checked_add(offset)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        if !self.contains_cpu_phys(phys, len) {
            return Err(Bcm2712Error::InvalidWindow);
        }
        Ok(phys)
    }
}

fn range_contains(base: u64, size: u64, addr: u64, len: u64) -> bool {
    if size == 0 || len == 0 {
        return false;
    }
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    let Some(window_end) = base.checked_add(size) else {
        return false;
    };
    addr >= base && end <= window_end
}

impl From<InBoundData> for PcieDmaWindow {
    fn from(window: InBoundData) -> Self {
        Self {
            pcie_base: window.pcie_base,
            cpu_base: window.cpu_base,
            size: window.size,
        }
    }
}

impl From<PcieDmaWindow> for InBoundData {
    fn from(window: PcieDmaWindow) -> Self {
        Self {
            pcie_base: window.pcie_base,
            cpu_base: window.cpu_base,
            size: window.size,
        }
    }
}

impl BrcmStb {
    pub(crate) fn new(addr: usize) -> &'static Self {
        // SAFETY: The caller passes the MMIO base from the DTB `reg` entry for the BCM2712 PCIe
        // controller, and `BrcmStb` is a register-layout view over that mapped region.
        unsafe { &*(addr as *const Self) }
    }

    pub fn read_outbound_window(&self, num: u8) -> Result<Option<OutBoundData>, Bcm2712Error> {
        if !(1..=4).contains(&num) {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let bus_lower = self.outbound_bus_window[num as usize - 1].lower.read();
        let bus_higher = self.outbound_bus_window[num as usize - 1].higher.read();
        let cpu_lower = self.outbound_cpu_window[num as usize - 1].lower.read();
        let cpu_higher = self.outbound_cpu_window[num as usize - 1].higher.read();
        let cpu_window = self.outbound_cpu_window_limit[num as usize - 1].read();
        if bus_lower == 0
            && bus_higher == 0
            && cpu_lower.bits() == 0
            && cpu_higher.bits() == 0
            && cpu_window.bits() == 0
        {
            return Ok(None);
        }
        let pcie_base = (bus_higher as u64) << 32 | bus_lower as u64;
        let cpu_addr_mb_lower = cpu_window.get(OutBoundWinLimit::cpu_addr_mb) as u64;
        let limit_addr_mb_lower = cpu_window.get(OutBoundWinLimit::limit_addr_mb) as u64;
        let cpu_addr_mb_higher = cpu_lower.get(OutBoundWin::outbound_hi) as u64;
        let limit_addr_mb_higher = cpu_higher.get(OutBoundWin::outbound_hi) as u64;

        let cpu_mb = cpu_addr_mb_lower | cpu_addr_mb_higher << 12;
        let limit_mb = limit_addr_mb_lower | limit_addr_mb_higher << 12;

        println!(
            "PCIE: outbound window {} cpu_addr_mb: 0x{:x} limit_addr_mb: 0x{:x}",
            num, cpu_mb, limit_mb
        );
        let size = (limit_mb
            .checked_sub(cpu_mb)
            .ok_or(Bcm2712Error::InvalidWindow)?
            + 1)
            << SHIFT_1MB;
        let cpu_base = cpu_mb << SHIFT_1MB;

        Ok(Some(OutBoundData {
            pcie_base,
            cpu_base,
            size,
        }))
    }

    /// Program one CPU-to-PCIe outbound aperture and verify its readback.
    ///
    /// `cpu_base`, `pcie_base`, and `size` are expressed in bytes.  Hardware
    /// represents the CPU range in 1 MiB units, so accepting a partial MiB
    /// would silently map a different range.
    pub fn set_outbound_window(
        &self,
        num: u8,
        cpu_base: u64,
        pcie_base: u64,
        size: u64,
    ) -> Result<(), Bcm2712Error> {
        if !(1..=4).contains(&num)
            || !pcie_validation::outbound_window_is_valid(cpu_base, pcie_base, size)
        {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let cpu_last = cpu_base
            .checked_add(size - 1)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        let cpu_mb = cpu_base >> SHIFT_1MB;
        let limit_mb = cpu_last >> SHIFT_1MB;
        // The lower register stores 12 MB bits and the high registers store
        // another eight, matching Linux's BCM2712 BRCM STB programming.
        if cpu_mb > 0x000f_ffff || limit_mb > 0x000f_ffff {
            return Err(Bcm2712Error::InvalidWindow);
        }

        let index = (num - 1) as usize;
        self.outbound_bus_window[index]
            .lower
            .write(pcie_base as u32);
        self.outbound_bus_window[index]
            .higher
            .write((pcie_base >> 32) as u32);

        let mut limit = self.outbound_cpu_window_limit[index].read();
        limit = limit
            .set(OutBoundWinLimit::cpu_addr_mb, (cpu_mb & 0x0fff) as u32)
            .set(OutBoundWinLimit::limit_addr_mb, (limit_mb & 0x0fff) as u32);
        self.outbound_cpu_window_limit[index].write(limit);

        let mut base_hi = self.outbound_cpu_window[index].lower.read();
        base_hi = base_hi.set(OutBoundWin::outbound_hi, (cpu_mb >> 12) as u32);
        self.outbound_cpu_window[index].lower.write(base_hi);
        let mut limit_hi = self.outbound_cpu_window[index].higher.read();
        limit_hi = limit_hi.set(OutBoundWin::outbound_hi, (limit_mb >> 12) as u32);
        self.outbound_cpu_window[index].higher.write(limit_hi);
        cpu::dsb_sy();

        let programmed = self
            .read_outbound_window(num)?
            .ok_or(Bcm2712Error::InvalidWindow)?;
        println!(
            "PCIE: outbound window {} readback cpu=0x{:x} pcie=0x{:x} size=0x{:x}",
            num, programmed.cpu_base, programmed.pcie_base, programmed.size
        );
        if programmed
            != (OutBoundData {
                cpu_base,
                pcie_base,
                size,
            })
        {
            return Err(Bcm2712Error::InvalidWindow);
        }
        Ok(())
    }

    pub(crate) fn read_inbound_window(&self, num: u8) -> Result<Option<InBoundData>, Bcm2712Error> {
        let bar_lower;
        let bar_higher;
        let ubus_lower;
        let ubus_higher;
        match num {
            1..=3 => {
                bar_lower = self.inbound_bar1_3[num as usize - 1].lower.read();
                bar_higher = self.inbound_bar1_3[num as usize - 1].higher.read();
                ubus_lower = self.ubus_bar1_3[num as usize - 1].lower.read();
                ubus_higher = self.ubus_bar1_3[num as usize - 1].higher.read();
            }
            4..=10 => {
                bar_lower = self.inbound_bar4_10[num as usize - 4].lower.read();
                bar_higher = self.inbound_bar4_10[num as usize - 4].higher.read();
                ubus_lower = self.ubus_bar4_10[num as usize - 4].lower.read();
                ubus_higher = self.ubus_bar4_10[num as usize - 4].higher.read();
            }
            _ => {
                return Err(Bcm2712Error::InvalidWindow);
            }
        }
        if bar_lower.bits() == 0 && bar_higher == 0 && ubus_lower.bits() == 0 && ubus_higher == 0
            || ubus_lower.get(InboundUbusLower::en) == 0
            || bar_lower.get(InboundBarLower::size) == 0
        {
            return Ok(None);
        }
        let pcie_base =
            bar_lower.get_raw(InboundBarLower::offset) as u64 | (bar_higher as u64) << 32;
        let cpu_base =
            ubus_lower.get_raw(InboundUbusLower::addr) as u64 | (ubus_higher as u64) << 32;
        println!(
            "PCIE: inbound window {} pcie_base: 0x{:x} cpu_base: 0x{:x} bar_lower: 0x{:x} bar_higher: 0x{:x} ubus_lower: 0x{:x} ubus_higher: 0x{:x}",
            num,
            pcie_base,
            cpu_base,
            bar_lower.bits(),
            bar_higher,
            ubus_lower.bits(),
            ubus_higher,
        );
        let size = InboundBarLower::decode_size(bar_lower)?;
        Ok(Some(InBoundData {
            pcie_base,
            cpu_base,
            size,
        }))
    }

    pub(crate) fn set_inbound_window(
        &self,
        num: u8,
        inbound_window: InBoundData,
    ) -> Result<(), Bcm2712Error> {
        let (bar_win, ubus_win) = match num {
            1..=3 => (
                &self.inbound_bar1_3[num as usize - 1],
                &self.ubus_bar1_3[num as usize - 1],
            ),
            4..=10 => (
                &self.inbound_bar4_10[num as usize - 4],
                &self.ubus_bar4_10[num as usize - 4],
            ),
            _ => return Err(Bcm2712Error::InvalidWindow),
        };

        if inbound_window.size == 0 {
            ubus_win.lower.write(InboundUbusLower::from_bits(0)); // en=0
            ubus_win.higher.write(0);
            bar_win.lower.write(InboundBarLower::from_bits(0)); // size=0, offset=0
            bar_win.higher.write(0);
            return Ok(());
        }

        // size encoding is non-linear; follow Linux brcmstb driver mapping.
        let size_enc = InboundBarLower::encode_size(inbound_window.size)?;

        // inbound view constraints (power-of-two size, base aligned to size).
        let size = inbound_window.size;
        if (size & (size - 1)) != 0
            || (inbound_window.pcie_base & (size - 1)) != 0
            || (inbound_window.cpu_base & (size - 1)) != 0
        {
            return Err(Bcm2712Error::InvalidWindow);
        }

        // register field granularity:
        // - InboundBarLower::offset is [31:5]  -> at least 32-byte aligned
        // - InboundUbusLower::addr is [31:12]  -> 4KB aligned
        if (inbound_window.pcie_base & 0x1f) != 0 || (inbound_window.cpu_base & 0xfff) != 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }

        let pcie_lo = inbound_window.pcie_base as u32;
        let pcie_hi = (inbound_window.pcie_base >> 32) as u32;
        let cpu_lo = inbound_window.cpu_base as u32;
        let cpu_hi = (inbound_window.cpu_base >> 32) as u32;

        // Disable first to avoid transient enable with inconsistent parameters.
        ubus_win.lower.write(InboundUbusLower::from_bits(0)); // en=0
        bar_win.lower.write(InboundBarLower::from_bits(0)); // size=0

        // Program high parts first, then lows, then enable last.
        bar_win.higher.write(pcie_hi);
        ubus_win.higher.write(cpu_hi);

        let bar_lower = InboundBarLower::new()
            .set(InboundBarLower::size, size_enc)
            .set_raw(InboundBarLower::offset, pcie_lo & 0xffff_ffe0);

        let ubus_lower = InboundUbusLower::new()
            .set(InboundUbusLower::en, 1)
            .set_raw(InboundUbusLower::addr, cpu_lo & 0xffff_f000);

        bar_win.lower.write(bar_lower);
        ubus_win.lower.write(ubus_lower);

        Ok(())
    }

    pub fn find_dma_window(
        &self,
        expected_pcie_base: u64,
        expected_cpu_base: u64,
        min_size: u64,
    ) -> Result<Option<PcieDmaWindow>, Bcm2712Error> {
        if min_size == 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }

        for num in 1..=10 {
            let Some(inbound) = self.read_inbound_window(num)? else {
                continue;
            };
            if inbound.pcie_base == expected_pcie_base
                && inbound.cpu_base == expected_cpu_base
                && inbound.size >= min_size
            {
                println!("PCIE: DMA inbound window {} selected", num);
                return Ok(Some(inbound.into()));
            }
        }

        Ok(None)
    }

    pub fn ensure_dma_window(
        &self,
        num_preference: Option<u8>,
        window: PcieDmaWindow,
    ) -> Result<PcieDmaWindow, Bcm2712Error> {
        if window.size == 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }

        if let Some(num) = num_preference {
            match self.read_inbound_window(num)? {
                Some(existing) if PcieDmaWindow::from(existing) == window => {
                    println!("PCIE: DMA inbound window {} already matches", num);
                    return Ok(window);
                }
                Some(_) => return Err(Bcm2712Error::InvalidWindow),
                None => {
                    println!("PCIE: Setting DMA inbound window {}...", num);
                    self.set_inbound_window(num, window.into())?;
                    cpu::dsb_sy();
                    return Ok(window);
                }
            }
        }

        let mut first_free = None;
        for num in 1..=10 {
            match self.read_inbound_window(num)? {
                Some(existing) if PcieDmaWindow::from(existing) == window => {
                    println!("PCIE: DMA inbound window {} already matches", num);
                    return Ok(window);
                }
                Some(_) => {}
                None if first_free.is_none() => first_free = Some(num),
                None => {}
            }
        }

        let Some(num) = first_free else {
            println!("PCIE: inbound windows are full; cannot install DMA window");
            return Err(Bcm2712Error::InvalidWindow);
        };
        println!("PCIE: Setting DMA inbound window {}...", num);
        self.set_inbound_window(num, window.into())?;
        cpu::dsb_sy();
        Ok(window)
    }

    /// have to ensure that config windows are mapped rp1 config space
    unsafe fn read_bar_raw_u32(&self, num: u8) -> Result<u32, Bcm2712Error> {
        if num > 5 {
            return Err(Bcm2712Error::InvalidSettings);
        }
        // SAFETY: `set_config_window` must have selected RP1 config space beforehand and
        // `config_data` points to that 4KB PCIe config region for function 0.
        let config = unsafe { &mut *(self.config_data.get() as *mut PCIConfigRegType0) };
        Ok(config.bar[num as usize].read())
    }

    /// have to ensure that config windows are mapped rp1 config space
    pub(crate) unsafe fn read_bar_address(&self, num: u8) -> Result<u64, Bcm2712Error> {
        if num > 5 {
            return Err(Bcm2712Error::InvalidSettings);
        }

        // SAFETY: this method requires the RP1 config window to remain selected for the
        // duration of the BAR read, which is the caller contract.
        let raw = unsafe { self.read_bar_raw_u32(num) }?;
        if (raw & 0x1) != 0 {
            return Err(Bcm2712Error::InvalidSettings);
        }

        let bar_type = (raw >> 1) & 0x3;
        match bar_type {
            0b00 => Ok((raw & 0xffff_fff0) as u64),
            0b10 => {
                if num >= 5 {
                    return Err(Bcm2712Error::InvalidSettings);
                }
                // SAFETY: the high dword is part of the same selected RP1 config space.
                let hi = unsafe { self.read_bar_raw_u32(num + 1) }?;
                Ok(((hi as u64) << 32) | ((raw & 0xffff_fff0) as u64))
            }
            0b01 | 0b11 => Err(Bcm2712Error::InvalidSettings),
            _ => Err(Bcm2712Error::InvalidSettings),
        }
    }

    pub const fn config_window_value(bdf: PcieBdf) -> u32 {
        match pcie_validation::encode_config_bdf(bdf.bus, bdf.device, bdf.function) {
            Some(value) => value,
            None => 0,
        }
    }

    /// Select a Type-0 endpoint configuration aperture for `bdf`.
    ///
    /// The caller must serialize access to the single controller aperture and
    /// must not retain the returned reference across another config selection.
    pub fn set_config_window_for(
        &self,
        bdf: PcieBdf,
    ) -> Result<&mut PCIConfigRegType0, Bcm2712Error> {
        if bdf.function > 7 || bdf.device > 31 {
            return Err(Bcm2712Error::InvalidSettings);
        }
        // SAFETY: the barrier does not dereference memory; it orders this core's MMIO writes
        // before programming the configuration address register.
        unsafe { asm!("dmb oshst") };
        self.config_address.write(
            ConfigAddress::new()
                .set(ConfigAddress::bus_num, bdf.bus as u32)
                .set(ConfigAddress::device_num, bdf.device as u32)
                .set(ConfigAddress::function_num, bdf.function as u32),
        );
        cpu::dsb_sy();
        // SAFETY: `config_data` is the controller's 4KB configuration-space aperture and the
        // address register above selected RP1 function 0 before this typed register view.
        let config = unsafe { &mut *(self.config_data.get() as *mut PCIConfigRegType0) };
        if config.id.read().bits() == !0 || config.bhlc.read().bits() == !0 {
            return Err(Bcm2712Error::DtbDeviceNotFound);
        }
        Ok(config)
    }

    /// Compatibility endpoint selector.  RP1 sits at bus 1, device 0,
    /// function 0 after root-complex bridge enumeration.
    pub(crate) fn set_config_window(&self) -> Result<&mut PCIConfigRegType0, Bcm2712Error> {
        self.set_config_window_for(RP1_BDF)
    }

    /// return value: PciCapabilityMsiX are only valid until the config window are change
    pub(crate) unsafe fn get_msi_x_capability(
        &self,
    ) -> Result<&'static PciCapabilityMsiX, Bcm2712Error> {
        let config = self.set_config_window()?;
        if config
            .cmd_status
            .read()
            .get(PciCmdStatus::capabilities_list)
            == 0
        {
            // if capabilities list is not present, return err
            println!("PCIE: Capabilities list not present");
            return Err(Bcm2712Error::InvalidSettings);
        }
        let cap = config.cap_ptr.read().get(PciCapPtr::capabilities_ptr);
        if cap < size_of::<PCIConfigRegType0>() as u32 || cap & 0b11 != 0
        /* require 32 bit align */
        {
            println!("PCIE: Invalid capabilities pointer: 0x{:x}", cap);
            return Err(Bcm2712Error::InvalidSettings);
        }
        // SAFETY: `config_data` is exactly a 4KB config aperture, which provides 256 aligned
        // u32 words while the selected RP1 function remains unchanged in this call.
        let config_data =
            unsafe { &*slice_from_raw_parts_mut(self.config_data.get() as *mut u32, 256) };
        let mut cap = cap;
        let mut count = 0;
        // search MSI-X capability
        loop {
            if count > 48 {
                println!("PCIE: capability list TTL exceeded");
                return Err(Bcm2712Error::InvalidSettings);
            }
            if cap == 0 {
                println!("PCIE: MSI-X capability not found (end-of-list)");
                return Err(Bcm2712Error::InvalidSettings);
            }
            if cap < size_of::<PCIConfigRegType0>() as u32 || (cap & 0b11) != 0 || cap >= 0x100 {
                println!("PCIE: invalid capability pointer: 0x{:x}", cap);
                return Err(Bcm2712Error::InvalidSettings);
            }
            let capability_header =
                PciCapabilityHead::from_bits(config_data[cap as usize / size_of::<u32>()]);
            if capability_header.get(PciCapabilityHead::id) == 0x11 {
                break;
            }
            cap = capability_header.get(PciCapabilityHead::next_ptr);
            if cap == 0 {
                println!("PCIE: MSI-X capability not found (end-of-list)");
                return Err(Bcm2712Error::InvalidSettings);
            }
            count += 1;
        }
        PciCapabilityMsiX::from_array(&config_data[cap as usize / size_of::<u32>()..])
            .ok_or(Bcm2712Error::InvalidWindow)
    }

    pub(crate) unsafe fn msi_x_table_bar_addr(
        &self,
        msi_x: &PciCapabilityMsiX,
    ) -> Result<(u64 /* bar_addr */, u64 /* entries */), Bcm2712Error> {
        let table_offset = msi_x.table_offset.read();
        let bir = table_offset.get(pci::msix::PciCapabilityMsiXTableOffset::bir);
        if bir > 5 {
            return Err(Bcm2712Error::InvalidSettings);
        }
        let offset_bytes = table_offset.offset_bytes() as u64;
        println!("PCIE: MSI-X bar is bar[{}]", bir);
        println!("PCIE: MSI-X table offset bytes: 0x{:x}", offset_bytes);
        // SAFETY: the caller provides an MSI-X capability from the currently selected RP1
        // config window, so reading its referenced BAR uses the same selected function.
        let bar_addr = unsafe { self.read_bar_address(bir as u8) }?;
        println!("PCIE: MSI-X bar decoded base: 0x{:x}", bar_addr);
        Ok((
            bar_addr
                .checked_add(offset_bytes)
                .ok_or(Bcm2712Error::InvalidWindow)?,
            msi_x.configurations.read().table_entry_count() as u64,
        ))
    }

    pub(crate) unsafe fn init_rp1_msi_x_settings(
        &self,
        msi_x: &PciCapabilityMsiX,
        msi_x_table_addr: u64,
        msi_x_pci_addr: u64,
    ) -> Result<MsiXTablePtr, Bcm2712Error> {
        msi_x.configurations.clear_bits(
            PciCapabilityMsiXConfigurations::new()
                .set(PciCapabilityMsiXConfigurations::msi_x_enable, 1),
        );
        let size = msi_x.configurations.read().table_entry_count();
        if size == 0 || size > 2048 {
            return Err(Bcm2712Error::InvalidSettings);
        }
        let msi_x_tables = unsafe {
            // SAFETY: `msi_x_table_addr` is an MMIO mapping to the RP1 MSI-X table BAR and
            // `size` is validated from MSI-X capability (1..=2048 entries), so the range
            // covers `size * size_of::<PciMsiXTable>()` bytes of properly aligned table entries.
            &*slice_from_raw_parts(msi_x_table_addr as usize as *const PciMsiXTable, size)
        };
        for (i, table) in msi_x_tables.iter().enumerate() {
            table.message_address_low.write(msi_x_pci_addr as u32);
            table
                .message_address_high
                .write((msi_x_pci_addr >> 32) as u32);
            table.message_data.write(i as u32);
            table
                .vector_control
                .write(PciMsiXTableVectorControl::new().set(PciMsiXTableVectorControl::mask, 1));
        }
        // enable msi-x
        msi_x.configurations.update_bits(
            PciCapabilityMsiXConfigurations::new()
                .set(PciCapabilityMsiXConfigurations::msi_x_enable, 1)
                .set(PciCapabilityMsiXConfigurations::function_mask, 1),
            PciCapabilityMsiXConfigurations::new()
                .set(PciCapabilityMsiXConfigurations::msi_x_enable, 1),
        );

        Ok(MsiXTablePtr {
            base: msi_x_table_addr as *const PciMsiXTable,
            len: size,
        })
    }

    /// Read a 32-bit BCM2712 BRCM STB register.
    ///
    /// Safety invariant: `self` was constructed from the DTB PCIe controller
    /// MMIO base and every caller uses a documented, 32-bit-aligned register
    /// offset within the 64 KiB controller register map.
    fn read_reg32(&self, offset: usize) -> u32 {
        debug_assert_eq!(offset & 3, 0);
        debug_assert!(offset < 0x1_0000);
        // SAFETY: upheld by the method invariant above; volatile access is
        // required because this is a device register, not normal memory.
        unsafe { read_volatile((self as *const Self as *const u8).add(offset) as *const u32) }
    }

    /// Write a 32-bit BCM2712 BRCM STB register; see `read_reg32` for the
    /// MMIO mapping and offset safety invariant.
    fn write_reg32(&self, offset: usize, value: u32) {
        debug_assert_eq!(offset & 3, 0);
        debug_assert!(offset < 0x1_0000);
        // SAFETY: upheld by the method invariant above.  A volatile store
        // ensures the write reaches hardware and is not coalesced away.
        unsafe {
            write_volatile(
                (self as *const Self as *mut u8).add(offset) as *mut u32,
                value,
            )
        };
    }

    fn update_reg32(&self, offset: usize, clear: u32, set: u32) -> u32 {
        let value = (self.read_reg32(offset) & !clear) | set;
        self.write_reg32(offset, value);
        value
    }

    fn wait_us(us: u64) {
        let mut timer = SystemTimer::new();
        timer.init();
        timer.wait(Duration::from_micros(us));
    }

    pub fn link_is_up(&self) -> bool {
        let status = self.read_reg32(0x4068);
        status & (0x10 | 0x20) == (0x10 | 0x20)
    }

    pub fn link_status_raw(&self) -> u32 {
        self.read_reg32(0x4068)
    }

    pub fn reset_bcm2712_pcie(&self) -> Result<(), Bcm2712Error> {
        println!("PCIE: assert PERST");
        self.update_reg32(0x4064, 0x4, 0);
        println!("PCIE: reset bridge");
        self.update_reg32(0x9210, 0x2, 0x2);
        Self::wait_us(200);
        self.update_reg32(0x9210, 0x2, 0);
        Self::wait_us(200);
        // HARD_DEBUG.SERDES_IDDQ must be clear before MDIO tuning and link training.
        self.update_reg32(0x4304, 0x0800_0000, 0);
        Self::wait_us(200);
        Ok(())
    }

    /// BCM2712 RC DL-MDIO write, bounded to a 1 ms completion timeout.
    fn mdio_write(&self, addr: u16, data: u16) -> Result<(), Bcm2712Error> {
        // Linux encodes port 0, register address, and a write command (zero)
        // in this word; completion is reported by DONE becoming clear in WR_DATA.
        self.write_reg32(0x1100, addr as u32);
        let _ = self.read_reg32(0x1100);
        self.write_reg32(0x1104, 0x8000_0000 | data as u32);
        for _ in 0..100 {
            let wr = self.read_reg32(0x1104);
            if wr & 0x8000_0000 == 0 {
                return Ok(());
            }
            Self::wait_us(10);
        }
        println!(
            "PCIE: MDIO timeout addr=0x{:08x} wr=0x{:08x}",
            self.read_reg32(0x1100),
            self.read_reg32(0x1104)
        );
        Err(Bcm2712Error::MdioTimeout)
    }

    pub fn configure_bcm2712_post_setup(&self) -> Result<(), Bcm2712Error> {
        println!("PCIE: configure MDIO refclk");
        self.mdio_write(0x1f, 0x1600)?;
        for (reg, data) in [
            (0x16, 0x50b9),
            (0x17, 0xbda1),
            (0x18, 0x0094),
            (0x19, 0x97b4),
            (0x1b, 0x5030),
            (0x1c, 0x5030),
            (0x1e, 0x0007),
        ] {
            self.mdio_write(reg, data)?;
        }
        Self::wait_us(200);
        self.update_reg32(0x184c, 0xff, 0x12);

        println!("PCIE: configure BCM2712 post-setup");
        // Linux BCM2712/BCM7712 uses 512-byte max burst (encoding 2).
        self.update_reg32(0x4008, 0x0030_0000, 0x0030_3480);
        // Suppress UBUS aborted-access errors and make missing-device reads all ones.
        self.update_reg32(0x40a4, 0, (1 << 13) | (1 << 19));
        self.write_reg32(0x4170, 0xffff_ffff);
        self.write_reg32(0x40a8, 0x0b2d_0000);
        self.write_reg32(0x405c, 0x0aba_0000);

        // BCM2712 QoS/chicken-bit programming from the BCM2712 U-Boot
        // reference.  Disable broken QoS propagation, then enable the RCLK,
        // timing, and master-gating fixes.  C1 may hardwire timing-fix to zero.
        let axi = self.update_reg32(0x416c, 1 << 7, (1 << 11) | (1 << 12) | (1 << 13));
        if axi & (1 << 12) == 0 {
            println!("PCIE: QoS timing fix reserved-zero; max-outstanding fallback");
            self.update_reg32(0x416c, 0x3f, 15);
        }
        // Disable VDM QoS control unless a verified board-specific map exists.
        self.update_reg32(0x40a0, 1 << 5, 0);
        Ok(())
    }

    fn configure_root_bridge(&self, cfg: &Bcm2712PcieSetup) -> Result<(), Bcm2712Error> {
        // RC class code: PCI-to-PCI bridge, class 06/subclass 04/interface 00.
        self.update_reg32(0x043c, 0x00ff_ffff, 0x0006_0400);
        // PCIe-to-SCB BAR2 endian mode: little endian.
        self.update_reg32(0x0188, 0x0000_000c, 0);

        let root = &self.pci_config;
        root.bus_numbers.write(
            pci::PciBusNumbers::new()
                .set(pci::PciBusNumbers::primary_bus_number, 0)
                .set(pci::PciBusNumbers::secondary_bus_number, 1)
                .set(pci::PciBusNumbers::subordinate_bus_number, 1),
        );
        let end = cfg
            .outbound_pcie_base
            .checked_add(cfg.outbound_size - 1)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        if cfg.outbound_pcie_base > u32::MAX as u64 || end > u32::MAX as u64 {
            return Err(Bcm2712Error::InvalidWindow);
        }
        // Type-1 memory base/limit are in 1 MiB units in bits 15:4/31:20.
        self.write_reg32(
            0x20,
            (((cfg.outbound_pcie_base >> 16) as u32) & 0xfff0)
                | ((((end >> 16) as u32) & 0xfff0) << 16),
        );
        self.update_reg32(0x04, 0, (1 << 1) | (1 << 2));
        let command = self.read_reg32(0x04);
        println!(
            "PCIE: bridge cmd readback=0x{:08x} buses=0x{:08x} mem=0x{:08x}",
            command,
            self.read_reg32(0x18),
            self.read_reg32(0x20),
        );
        Ok(())
    }

    fn verify_root_bridge_command(&self) -> Result<(), Bcm2712Error> {
        let command = self.read_reg32(0x04);
        if command & ((1 << 1) | (1 << 2)) != ((1 << 1) | (1 << 2)) {
            println!(
                "PCIE: bridge command enable did not stick: 0x{:08x}",
                command
            );
            return Err(Bcm2712Error::InvalidSettings);
        }
        Ok(())
    }

    pub fn start_link(&self, timeout_ms: u32) -> Result<(), Bcm2712Error> {
        println!("PCIE: deassert PERST");
        self.update_reg32(0x4064, 0, 0x4);
        Self::wait_us(100_000);
        let polls = timeout_ms
            .checked_mul(10)
            .ok_or(Bcm2712Error::InvalidSettings)?;
        for _ in 0..polls {
            if self.link_is_up() {
                println!("PCIE: link up");
                return Ok(());
            }
            Self::wait_us(100);
        }
        println!("PCIE: link timeout status=0x{:08x}", self.link_status_raw());
        Err(Bcm2712Error::LinkTimeout)
    }

    pub fn init_bcm2712_root_complex(&self, cfg: &Bcm2712PcieSetup) -> Result<(), Bcm2712Error> {
        if cfg.outbound_size == 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }
        self.reset_bcm2712_pcie()?;
        self.configure_bcm2712_post_setup()?;
        println!("PCIE: configure outbound window from DTB ranges");
        self.set_outbound_window(
            1,
            cfg.outbound_cpu_base,
            cfg.outbound_pcie_base,
            cfg.outbound_size,
        )?;
        println!("PCIE: configure inbound DMA window");
        self.ensure_dma_window(Some(1), cfg.inbound_dma_window)?;
        self.configure_root_bridge(cfg)?;
        if let Some(link_speed) = cfg.target_link_speed {
            self.update_reg32(0x04dc, 0x0f, link_speed as u32);
            // Link Control 2 Target Link Speed is at capability 0xac + 0x30.
            self.update_reg32(0x00dc, 0x0f, link_speed as u32);
        }
        self.start_link(100)?;
        // BCM2712 may clear command bits while the port comes out of reset.
        // Reapply and verify the bridge header only after LTSSM is active.
        self.configure_root_bridge(cfg)?;
        self.verify_root_bridge_command()
    }

    fn probe_bar_size(&self, bar: u8) -> Result<PcieBarProbe, Bcm2712Error> {
        if bar > 5 {
            return Err(Bcm2712Error::InvalidSettings);
        }
        let config = self.set_config_window_for(RP1_BDF)?;
        let saved_command = config.cmd_status.read();
        let original_low = config.bar[bar as usize].read();
        let is_64 = (original_low & 0x6) == 0x4;
        if is_64 && bar >= 5 {
            return Err(Bcm2712Error::InvalidSettings);
        }
        let original_high = is_64.then(|| config.bar[bar as usize + 1].read());

        // PCI BAR probing is valid only with memory decoding off.  Restore all
        // endpoint state before returning, including on an invalid mask.
        config.cmd_status.update_bits(
            PciCmdStatus::new().set(PciCmdStatus::memory_space, 1),
            PciCmdStatus::new(),
        );
        config.bar[bar as usize].write(u32::MAX);
        if is_64 {
            config.bar[bar as usize + 1].write(u32::MAX);
        }
        let probe_mask_low = config.bar[bar as usize].read();
        let probe_mask_high = is_64.then(|| config.bar[bar as usize + 1].read());
        config.bar[bar as usize].write(original_low);
        if let Some(high) = original_high {
            config.bar[bar as usize + 1].write(high);
        }
        config.cmd_status.write(saved_command);

        let size = if let Some(high) = probe_mask_high {
            let mask = ((high as u64) << 32) | (probe_mask_low as u64 & !0xf);
            (!mask).wrapping_add(1)
        } else {
            (!(probe_mask_low & !0xf)).wrapping_add(1) as u64
        };
        if size == 0 || !size.is_power_of_two() {
            return Err(Bcm2712Error::InvalidWindow);
        }
        println!(
            "PCIE: BAR{} probe size=0x{:x} mask=0x{:08x}{:08x}",
            bar,
            size,
            probe_mask_high.unwrap_or(0),
            probe_mask_low,
        );
        Ok(PcieBarProbe {
            bar,
            original_low,
            original_high,
            probe_mask_low,
            probe_mask_high,
            size,
        })
    }

    fn assign_bar(
        &self,
        probe: PcieBarProbe,
        outbound: OutBoundData,
        pcie_address: u64,
    ) -> Result<(), Bcm2712Error> {
        if pcie_address & (probe.size - 1) != 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let assigned_end = pcie_address
            .checked_add(probe.size)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        let outbound_end = outbound
            .pcie_base
            .checked_add(outbound.size)
            .ok_or(Bcm2712Error::InvalidWindow)?;
        if pcie_address < outbound.pcie_base || assigned_end > outbound_end {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let config = self.set_config_window_for(RP1_BDF)?;
        let flags = probe.original_low & 0xf;
        config.bar[probe.bar as usize].write((pcie_address as u32 & !0xf) | flags);
        if probe.original_high.is_some() {
            config.bar[probe.bar as usize + 1].write((pcie_address >> 32) as u32);
        }
        let low = config.bar[probe.bar as usize].read();
        let high = probe
            .original_high
            .map(|_| config.bar[probe.bar as usize + 1].read());
        let readback = ((high.unwrap_or(0) as u64) << 32) | (low as u64 & !0xf);
        let probe_mask = ((probe.probe_mask_high.unwrap_or(0) as u64) << 32)
            | (probe.probe_mask_low as u64 & !0xf);
        if readback != pcie_address || readback == probe_mask || low == probe.probe_mask_low {
            println!(
                "PCIE: BAR{} assignment FAIL wrote=0x{:x} read=0x{:x} probe=0x{:x}",
                probe.bar, pcie_address, readback, probe_mask
            );
            return Err(Bcm2712Error::InvalidWindow);
        }
        println!(
            "PCIE: BAR{} assigned pcie=0x{:x} cpu=0x{:x} size=0x{:x}",
            probe.bar,
            readback,
            outbound
                .cpu_base
                .checked_add(readback - outbound.pcie_base)
                .ok_or(Bcm2712Error::InvalidWindow)?,
            probe.size,
        );
        Ok(())
    }

    /// Probe, restore, then assign RP1 BAR0/BAR1/BAR2.  Memory decoding is
    /// enabled only after every assignment has read back as a real address.
    pub fn configure_rp1_endpoint(&self, outbound: OutBoundData) -> Result<(), Bcm2712Error> {
        let config = self.set_config_window_for(RP1_BDF)?;
        let id = config.id.read().bits();
        if id == 0 || id == u32::MAX {
            return Err(Bcm2712Error::PcieEndpointNotFound);
        }
        println!(
            "PCIE: RP1 vendor=0x{:04x} device=0x{:04x}",
            id & 0xffff,
            id >> 16
        );
        let probes = [
            self.probe_bar_size(0)?,
            self.probe_bar_size(1)?,
            self.probe_bar_size(2)?,
        ];
        // Assign in the RP1/Linux low-address layout.  BAR1=0 is deliberate:
        // the RP1 child bus in the firmware DTB maps its peripheral region
        // from PCI address zero.  BAR0 is assigned last so MSI-X never
        // affects BAR1/BAR2 placement.
        for (probe, address) in [
            (probes[1], RP1_BAR1_PCIE_BASE),
            (probes[2], RP1_BAR2_PCIE_BASE),
            (probes[0], RP1_BAR0_PCIE_BASE),
        ] {
            if probe.original_high.is_some() {
                // `probe_bar_size` has fully restored the paired dword, but
                // this fixed three-BAR layout cannot safely consume an
                // adjacent BAR as a 64-bit high dword.
                return Err(Bcm2712Error::InvalidSettings);
            }
            self.assign_bar(probe, outbound, address)?;
        }
        let config = self.set_config_window_for(RP1_BDF)?;
        config.cmd_status.update_bits(
            PciCmdStatus::new()
                .set(PciCmdStatus::memory_space, 1)
                .set(PciCmdStatus::bus_master, 1)
                .set(PciCmdStatus::interrupt_disable, 1),
            PciCmdStatus::new()
                .set(PciCmdStatus::memory_space, 1)
                .set(PciCmdStatus::bus_master, 1)
                .set(PciCmdStatus::interrupt_disable, 1),
        );
        for bar in 0..=2 {
            println!("PCIE: RP1 BAR{}=0x{:08x}", bar, config.bar[bar].read());
        }
        println!(
            "PCIE: RP1 command=0x{:08x}",
            config.cmd_status.read().bits()
        );
        Ok(())
    }

    /// Emit the bounded RC and RP1 state needed to diagnose a failed full-init
    /// attempt.  This never writes configuration space or changes link state.
    pub fn dump_diagnostics(&self) {
        println!(
            "PCIE: diag ctrl=0x{:08x} status=0x{:08x} hard_debug=0x{:08x} sw_init=0x{:08x}",
            self.read_reg32(REG_PCIE_CTRL),
            self.read_reg32(REG_PCIE_STATUS),
            self.read_reg32(REG_HARD_DEBUG),
            self.read_reg32(REG_RGR1_SW_INIT_1),
        );
        println!(
            "PCIE: diag bridge cmd=0x{:08x} buses=0x{:08x} mem=0x{:08x}",
            self.read_reg32(0x04),
            self.read_reg32(0x18),
            self.read_reg32(0x20),
        );
        println!(
            "PCIE: diag rc-aer ext100=0x{:08x} ext104=0x{:08x} ext110=0x{:08x}",
            self.read_reg32(0x100),
            self.read_reg32(0x104),
            self.read_reg32(0x110),
        );
        for window in 1..=4 {
            match self.read_outbound_window(window) {
                Ok(Some(value)) => println!(
                    "PCIE: diag out{} cpu=0x{:x} pcie=0x{:x} size=0x{:x}",
                    window, value.cpu_base, value.pcie_base, value.size
                ),
                Ok(None) => println!("PCIE: diag out{} empty", window),
                Err(err) => println!("PCIE: diag out{} err={:?}", window, err),
            }
        }
        for window in 1..=10 {
            if let Ok(Some(value)) = self.read_inbound_window(window) {
                println!(
                    "PCIE: diag in{} pcie=0x{:x} cpu=0x{:x} size=0x{:x}",
                    window, value.pcie_base, value.cpu_base, value.size
                );
            }
        }
        match self.set_config_window_for(RP1_BDF) {
            Ok(config) => {
                println!(
                    "PCIE: diag ep id=0x{:08x} cmd=0x{:08x} hdr=0x{:08x}",
                    config.id.read().bits(),
                    config.cmd_status.read().bits(),
                    config.bhlc.read().bits(),
                );
                for bar in 0..=2 {
                    println!("PCIE: diag ep bar{}=0x{:08x}", bar, config.bar[bar].read());
                }
                // The extended capability header has ID in bits 15:0 and a
                // dword-aligned next pointer in bits 31:20.  Walk only a
                // bounded number of nodes so a malformed endpoint cannot
                // turn a failure diagnostic into an infinite loop.
                let mut offset = 0x100usize;
                for _ in 0..16 {
                    let header = self.read_config_dword(offset);
                    if header == 0 || header == u32::MAX {
                        break;
                    }
                    let id = header & 0xffff;
                    let next = ((header >> 20) & 0xffc) as usize;
                    println!(
                        "PCIE: diag ep extcap off=0x{:03x} id=0x{:04x} hdr=0x{:08x}",
                        offset, id, header
                    );
                    // PCIe extended capability ID 0x0001 is AER.  Emit its
                    // uncorrectable and correctable status words verbatim.
                    if id == 0x0001 {
                        println!(
                            "PCIE: diag ep AER uncorr=0x{:08x} corr=0x{:08x} root=0x{:08x}",
                            self.read_config_dword(offset + 0x04),
                            self.read_config_dword(offset + 0x10),
                            self.read_config_dword(offset + 0x30),
                        );
                    }
                    if next < 0x100 || next == offset {
                        break;
                    }
                    offset = next;
                }
            }
            Err(err) => println!("PCIE: diag endpoint config unavailable: {:?}", err),
        }
    }

    /// Read one dword from the currently selected configuration aperture.
    /// `dump_diagnostics` selects RP1 immediately before using this helper.
    fn read_config_dword(&self, offset: usize) -> u32 {
        debug_assert!(offset <= 0xffc && offset & 3 == 0);
        // SAFETY: the offset is bounded to the 4 KiB config aperture and
        // `config_data` is MMIO, so every access must be volatile.
        unsafe { read_volatile((self.config_data.get() as *const u8).add(offset) as *const u32) }
    }
}

bitregs! {
    pub struct InboundBarLower: u32 {
        pub size@[4:0],
        // offset are full bits
        pub offset@[31:5],
    }
}

bitregs! {
    pub struct InboundUbusLower: u32 {
        pub en@[0:0],
        reserved@[11:1] [res0],
        pub addr@[31:12],
    }
}

impl InboundBarLower {
    fn decode_size(bar: Self) -> Result<u64, Bcm2712Error> {
        let enc = bar.get(InboundBarLower::size) as u64;
        if enc == 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }
        Ok(1u64
            << if (0x1c..=0x1f).contains(&enc) {
                (enc - 0x1c) + 12
            } else if (1..=21).contains(&enc) {
                enc + 15
            } else {
                return Err(Bcm2712Error::InvalidWindow);
            })
    }

    fn encode_size(size: u64) -> Result<u32, Bcm2712Error> {
        if size == 0 || (size & (size - 1)) != 0 {
            return Err(Bcm2712Error::InvalidWindow);
        }
        let log2 = size.trailing_zeros() as u32;

        // Linux brcmstb: 4KB..32KB => 0x1c..0x1f, 64KB..64GB => 1..21 :contentReference[oaicite:5]{index=5}
        let enc = if (12..=15).contains(&log2) {
            (log2 - 12) + 0x1c
        } else if (16..=36).contains(&log2) {
            log2 - 15
        } else {
            return Err(Bcm2712Error::InvalidWindow);
        };

        Ok(enc)
    }
}

bitregs! {
    pub struct OutBoundWinLimit: u32 {
        reserved@[3:0] [res0],
        pub cpu_addr_mb@[15:4],
        reserved@[19:16] [res0],
        pub limit_addr_mb@[31:20],
    }
}

bitregs! {
    pub struct OutBoundWin: u32 {
        pub outbound_hi@[7:0],
        reserved@[31:8] [res0],
    }
}

bitregs! {
    pub struct MiscCtrl: u32 {
        pub scb2_size@[4:0],
        reserved@[6:5] [res0],
        pub rcb_64b_mode@[7:7],
        reserved@[9:8] [res0],
        pub rcb_mps_mode@[10:10],
        reserved@[11:11] [res0],
        pub scb_access_en@[12:12],
        pub cfg_read_ur_mode@[13:13],
        reserved@[19:14] [res0],
        pub max_burst_size@[21:20] as MaxBurstSize {
            Size128 = 0b01,
            Size256 = 0b10,
            Size512 = 0b11,
        },
        pub scb1_size@[26:22],
        pub scb0_size@[31:27],
    }
}

bitregs! {
    pub struct MsiData: u32 {
        pub msi_data@[31:0] as MsiDataValue {
            Val32 = 0xffe06540,
            Val8 = 0xfff86540,
        }
    }
}

bitregs! {
    pub struct PcieCtrl: u32 {
        pub l23_request@[0:0],
        reserved@[1:1] [res0],
        pub perstb@[2:2],
        reserved@[31:3] [res0],
    }
}

bitregs! {
    pub struct PcieStatus: u32  {
        reserved@[3:0] [res0],
        pub phy_linkup@[4:4],
        pub dl_active@[5:5],
        pub link_in_l23@[6:6],
        pub port_mask@[7:7],
        reserved@[31:8] [res0],
    }
}

bitregs! {
    pub struct PcieRevision: u32 {
        pub revision@[31:0] as PcieHwRev {
            Rev33 = 0x0303,
            Rev3_20 = 0x0320,
        }
    }

}

bitregs! {
    pub struct ConfigAddress: u32 {
        reserved@[11:0] [res0],
        pub function_num@[14:12],
        pub device_num@[19:15],
        pub bus_num@[27:20],
        reserved@[31:28] [res0],
    }
}
