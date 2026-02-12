// BCM2712 MSI-X Interrupt Peripheral

#![allow(dead_code)]

use typestate::ReadWrite;
use typestate::Writable;

const _: () = assert!(core::mem::size_of::<Bcm2712MIP>() == 0xc0);

pub(crate) struct Bcm2712MIP {
    raise: ReadWrite<u32>,
    reserved_0x04: [u8; 0xc],
    clear: ReadWrite<u32>,
    reserved_0x14: [u8; 0xc],
    cfgl_host: ReadWrite<u32>,
    reserved_0x24: [u8; 0xc],
    cfgh_host: ReadWrite<u32>,
    reserved_0x34: [u8; 0xc],
    maskl_host: ReadWrite<u32>,
    reserved_0x44: [u8; 0xc],
    maskh_host: ReadWrite<u32>,
    reserved_0x54: [u8; 0xc],
    maskl_vpu: ReadWrite<u32>,
    reserved_0x64: [u8; 0xc],
    maskh_vpu: ReadWrite<u32>,
    reserved_0x74: [u8; 0xc],
    statusl_host: ReadWrite<u32>,
    reserved_0x84: [u8; 0xc],
    statush_host: ReadWrite<u32>,
    reserved_0x94: [u8; 0xc],
    statusl_vpu: ReadWrite<u32>,
    reserved_0xa4: [u8; 0xc],
    statush_vpu: ReadWrite<u32>,
    reserved_0xb4: [u8; 0xc],
}

impl Bcm2712MIP {
    pub const fn new(addr: u64) -> &'static Self {
        unsafe { &*(addr as *const Self) }
    }

    pub fn init(&self) {
        const MASK: u32 = !0;
        const CLEAR: u32 = 0;

        // Unmask Host interrupts
        self.maskl_host.write(CLEAR);
        self.maskh_host.write(CLEAR);
        // Mask VPU interrupts
        self.maskl_vpu.write(MASK);
        self.maskh_vpu.write(MASK);

        // set host edge triggered
        self.cfgl_host.write(MASK);
        self.cfgh_host.write(MASK);
        cpu::dsb_sy();
    }
}
