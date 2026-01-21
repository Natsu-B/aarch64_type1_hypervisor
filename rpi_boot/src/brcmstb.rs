use core::mem::offset_of;
use typestate::ReadWrite;
use typestate::bitregs;

use crate::pci_config::PCIConfigRegType1;

const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x1000) == 0x1000);
const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x2000) == 0x2000);
const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x4000) == 0x4000);
const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x4050) == 0x4050);
const _: () = assert!(offset_of!(BrcmStbReg, pcie_ctrl) == 0x4064);
const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x40a0) == 0x40a0);
const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x40c4) == 0x40c4);
const _: () = assert!(offset_of!(BrcmStbReg, inbound_bar4) == 0x40d4);
const _: () = assert!(offset_of!(BrcmStbReg, ubus_bar4) == 0x410c);
const _: () = assert!(offset_of!(BrcmStbReg, reserved_0x4144) == 0x4144);
const _: () = assert!(offset_of!(BrcmStbReg, msi_int2_status) == 0x4500);
const _: () = assert!(offset_of!(BrcmStbReg, msi_int2_mask_set) == 0x4510);

#[repr(C)]
// [ReadWrite<u32>;2] for each BAR (low/high)
pub struct BrcmStbReg {
    pci_config: PCIConfigRegType1,
    pcie_space: ReadWrite<[u8; 0xfc0]>,
    reserved_0x1000: [u8; 0x1000],
    reserved_0x2000: [u8; 0x2000],
    reserved_0x4000: [u8; 8],
    misc_ctrl: ReadWrite<MiscCtrl>,
    outbound_bus_window: [[ReadWrite<u32>; 2]; 4],
    inbound_bar1: [ReadWrite<u32>; 2],
    inbound_bar2: [ReadWrite<u32>; 2],
    inbound_bar3: [ReadWrite<u32>; 2],
    msi_bar: [ReadWrite<u32>; 2],
    msi_data: ReadWrite<MsiData>,
    reserved_0x4050: [u8; 20],
    pcie_ctrl: ReadWrite<PcieCtrl>,
    pcie_status: ReadWrite<PcieStatus>,
    pcie_revision: ReadWrite<PcieRevision>,
    outbound_cpu_window_limit: [ReadWrite<u32>; 4],
    outbound_cpu_window: [[ReadWrite<u32>; 2]; 4],
    reserved_0x40a0: [u8; 12],
    ubus_bar1: [ReadWrite<u32>; 2],
    ubus_bar2: [ReadWrite<u32>; 2],
    ubus_bar3: [ReadWrite<u32>; 2],
    reserved_0x40c4: [u8; 16],
    inbound_bar4: [ReadWrite<u32>; 2],
    inbound_bar5: [ReadWrite<u32>; 2],
    inbound_bar6: [ReadWrite<u32>; 2],
    inbound_bar7: [ReadWrite<u32>; 2],
    inbound_bar8: [ReadWrite<u32>; 2],
    inbound_bar9: [ReadWrite<u32>; 2],
    inbound_bar10: [ReadWrite<u32>; 2],
    ubus_bar4: [ReadWrite<u32>; 2],
    ubus_bar5: [ReadWrite<u32>; 2],
    ubus_bar6: [ReadWrite<u32>; 2],
    ubus_bar7: [ReadWrite<u32>; 2],
    ubus_bar8: [ReadWrite<u32>; 2],
    ubus_bar9: [ReadWrite<u32>; 2],
    ubus_bar10: [ReadWrite<u32>; 2],
    reserved_0x4144: [u8; 0x3bc],
    msi_int2_status: ReadWrite<u32>,
    reserved_0x414c: [u8; 4],
    msi_int2_clr: ReadWrite<u32>,
    reserved_0x4158: [u8; 4],
    msi_int2_mask_set: ReadWrite<u32>,
    msi_int2_mask_clr: ReadWrite<u32>,
    
}

bitregs! {
    pub struct MiscCtrl: u32 {
        pub scb2_size@[4:0],
        reserved@[7:5] [res0],
        pub rcb_64b_mode@[8:8],
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
        reserved@[4:0] [res0],
        pub phy_linkup@[5:5],
        pub dl_active@[6:6],
        pub link_in_l23@[7:7],
        pub port_mask@[8:8],
        reserved@[31:9] [res0],
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
