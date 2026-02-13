use core::ptr::slice_from_raw_parts;

use typestate::ReadWrite;
use typestate::bitregs;

bitregs! {
    pub struct PciCapabilityMsiXConfigurations: u32 {
        pub id@[7:0],
        pub next_ptr@[15:8],
        pub table_size@[26:16],
        reserved@[29:26],
        pub function_mask@[30:30],
        pub msi_x_enable@[31:31],
    }
}

bitregs! {
    pub struct PciCapabilityMsiXTableOffset: u32 {
        pub bir@[2:0],
        pub offset@[31:3],
    }
}

bitregs! {
    pub struct PciCapabilityMsiXPbaOffset: u32 {
        pub bir@[2:0],
        pub offset@[31:3],
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PciCapabilityMsiX {
    pub configurations: ReadWrite<PciCapabilityMsiXConfigurations>,
    pub table_offset: ReadWrite<PciCapabilityMsiXTableOffset>,
    pub pba_offset: ReadWrite<PciCapabilityMsiXPbaOffset>,
}

impl PciCapabilityMsiX {
    pub fn from_array(array: &[u32]) -> Option<&'static Self> {
        let (head3, _) = array.split_first_chunk::<3>()?;
        Some(unsafe { &*(head3.as_ptr() as *const Self) })
    }
}

bitregs! {
    pub struct PciMsiXTableVectorControl: u32 {
        pub mask@[0:0],
        reserved@[31:1] [ignore],
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PciMsiXTable {
    pub message_address_low: ReadWrite<u32>,
    pub message_address_high: ReadWrite<u32>,
    pub message_data: ReadWrite<u32>,
    pub vector_control: ReadWrite<PciMsiXTableVectorControl>,
}

impl PciMsiXTable {
    pub fn from_array(array: &[u32], size: u32) -> Option<&'static [Self]> {
        let (head, _) =
            array.split_at_checked(size as usize * size_of::<PciMsiXTable>() / size_of::<u32>())?;
        Some(unsafe { &*slice_from_raw_parts(head.as_ptr() as *const Self, size as usize) })
    }
}
