#![allow(dead_code)]

use core::mem::offset_of;
use pci::PCIConfigRegType1;
use typestate::RawReg;
use typestate::ReadWrite;
use typestate::Readable;
use typestate::bitregs;

use crate::bcm2712::Bcm2712Error;

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

const BRCM_PCIE_HW_REV_33: u32 = 0x0303;
const SHIFT_1MB: u64 = 20;

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
    pub(crate) config_data: ReadWrite<[u8; 0x1000]>,
    // 0x9000
    pub(crate) config_address: ReadWrite<u32>,
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

impl BrcmStb {
    pub(crate) fn new(addr: usize) -> &'static Self {
        unsafe { &*(addr as *const Self) }
    }

    pub(crate) fn read_outbound_window(
        &self,
        num: u8,
    ) -> Result<Option<OutBoundData>, Bcm2712Error> {
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
        {
            return Ok(None);
        }
        let pcie_base =
            bar_lower.get_raw(InboundBarLower::offset) as u64 | (bar_higher as u64) << 32;
        let cpu_base =
            ubus_lower.get_raw(InboundUbusLower::addr) as u64 | (ubus_higher as u64) << 32;
        let size = InboundBarLower::decode_size(bar_lower)?;
        Ok(Some(InBoundData {
            pcie_base,
            cpu_base,
            size,
        }))
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
