use core::mem::size_of;
use typestate::ReadOnly;
use typestate::ReadWrite;
use typestate::bitregs;

bitregs! {
    /// PCI Command Register (offset 0x04, 16-bit).
    /// See OSDev / Linux pci_regs.h for bit meanings.
    pub struct PciCommand: u16 {
        pub io_space@[0:0],
        pub memory_space@[1:1],
        pub bus_master@[2:2],
        pub special_cycles@[3:3],
        pub mem_write_invalidate@[4:4],
        pub vga_palette_snoop@[5:5],
        pub parity_error_response@[6:6],
        pub address_data_stepping@[7:7], // a.k.a. WAIT (obsolete on many systems)
        pub serr_enable@[8:8],
        pub fast_back_to_back@[9:9],
        pub intx_disable@[10:10], // a.k.a. Interrupt Disable
        reserved@[15:11] [res0],
    }
}

bitregs! {
    /// PCI Status Register (offset 0x06, 16-bit).
    /// Many bits are RO, some are RW1C depending on the bit.
    pub struct PciStatus: u16 {
        reserved@[2:0] [res0],
        pub interrupt_status@[3:3],
        pub capabilities_list@[4:4],
        pub mhz66_capable@[5:5],
        pub udf@[6:6], // obsolete (kept for completeness)
        pub fast_back_to_back_capable@[7:7],
        pub master_data_parity_error@[8:8], // RW1C in many implementations
        pub devsel_timing@[10:9] as PciDevselTiming {
            Fast = 0b00,
            Medium = 0b01,
            Slow = 0b10,
            Reserved = 0b11,
        },
        pub signaled_target_abort@[11:11],   // often RW1C
        pub received_target_abort@[12:12],   // often RW1C
        pub received_master_abort@[13:13],   // often RW1C
        pub signaled_system_error@[14:14],   // often RW1C
        pub detected_parity_error@[15:15],   // often RW1C
    }
}

bitregs! {
    /// PCI Header Type register (offset 0x0E, 8-bit).
    pub struct PciHeaderType: u8 {
        pub header_type@[6:0] as PciHeaderKind {
            Standard = 0x0,
            PciToPciBridge = 0x1,
            CardBusBridge = 0x2,
        },
        pub multifunction@[7:7],
    }
}

bitregs! {
    /// PCI BIST register (offset 0x0F, 8-bit).
    pub struct PciBist: u8 {
        pub completion_code@[3:0],
        reserved@[5:4] [res0],
        pub start_bist@[6:6],
        pub bist_capable@[7:7],
    }
}

bitregs! {
    /// PCI-to-PCI Bridge Control (offset 0x3E, 16-bit, Header Type 0x1).
    /// Bits are from linux pci_regs.h; many higher bits are not modeled here.
    pub struct PciBridgeControl: u16 {
        pub parity_enable_secondary@[0:0],
        pub serr_enable_secondary@[1:1],
        pub isa_enable@[2:2],
        pub vga_enable@[3:3],
        reserved@[4:4] [res0],
        pub master_abort_mode@[5:5],
        pub secondary_bus_reset@[6:6],
        pub fast_back_to_back_secondary@[7:7],
        reserved@[15:8] [ignore],
    }
}

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<PCIConfigRegType0>() == 0x40);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<PCIConfigRegType1>() == 0x40);

/// PCI Configuration Header: Type 0x0 (Standard device).
/// Layout follows the conventional 64-byte header.
#[repr(C)]
pub struct PCIConfigRegType0 {
    pub vendor_id: ReadOnly<u16>,       // 0x00
    pub device_id: ReadOnly<u16>,       // 0x02
    pub command: ReadWrite<PciCommand>, // 0x04
    pub status: ReadWrite<PciStatus>,   // 0x06

    pub revision_id: ReadOnly<u8>, // 0x08
    pub prog_if: ReadOnly<u8>,     // 0x09
    pub subclass: ReadOnly<u8>,    // 0x0A
    pub class_code: ReadOnly<u8>,  // 0x0B

    pub cache_line_size: ReadWrite<u8>,       // 0x0C
    pub latency_timer: ReadWrite<u8>,         // 0x0D
    pub header_type: ReadOnly<PciHeaderType>, // 0x0E
    pub bist: ReadWrite<PciBist>,             // 0x0F

    pub bar: [ReadWrite<u32>; 6],       // 0x10..0x27 (BAR0..BAR5)
    pub cardbus_cis_ptr: ReadOnly<u32>, // 0x28

    pub subsystem_vendor_id: ReadOnly<u16>, // 0x2C (low 16)
    pub subsystem_id: ReadOnly<u16>,        // 0x2E (high 16)

    pub expansion_rom_base: ReadWrite<u32>, // 0x30

    pub capabilities_ptr: ReadOnly<u8>, // 0x34 (low 8)
    _reserved0: [u8; 3],                // 0x35..0x37

    _reserved1: u32, // 0x38

    pub interrupt_line: ReadWrite<u8>, // 0x3C
    pub interrupt_pin: ReadOnly<u8>,   // 0x3D
    pub min_grant: ReadOnly<u8>,       // 0x3E
    pub max_latency: ReadOnly<u8>,     // 0x3F
}

/// PCI Configuration Header: Type 0x1 (PCI-to-PCI bridge).
#[repr(C)]
pub struct PCIConfigRegType1 {
    pub vendor_id: ReadOnly<u16>,       // 0x00
    pub device_id: ReadOnly<u16>,       // 0x02
    pub command: ReadWrite<PciCommand>, // 0x04
    pub status: ReadWrite<PciStatus>,   // 0x06

    pub revision_id: ReadOnly<u8>, // 0x08
    pub prog_if: ReadOnly<u8>,     // 0x09
    pub subclass: ReadOnly<u8>,    // 0x0A
    pub class_code: ReadOnly<u8>,  // 0x0B

    pub cache_line_size: ReadWrite<u8>,       // 0x0C
    pub latency_timer: ReadWrite<u8>,         // 0x0D
    pub header_type: ReadOnly<PciHeaderType>, // 0x0E
    pub bist: ReadWrite<PciBist>,             // 0x0F

    pub bar: [ReadWrite<u32>; 2], // 0x10..0x17 (BAR0..BAR1)

    pub primary_bus_number: ReadWrite<u8>,      // 0x18
    pub secondary_bus_number: ReadWrite<u8>,    // 0x19
    pub subordinate_bus_number: ReadWrite<u8>,  // 0x1A
    pub secondary_latency_timer: ReadWrite<u8>, // 0x1B

    pub io_base: ReadWrite<u8>,                 // 0x1C
    pub io_limit: ReadWrite<u8>,                // 0x1D
    pub secondary_status: ReadWrite<PciStatus>, // 0x1E (16-bit)

    pub memory_base: ReadWrite<u16>,  // 0x20
    pub memory_limit: ReadWrite<u16>, // 0x22

    pub prefetchable_memory_base: ReadWrite<u16>, // 0x24
    pub prefetchable_memory_limit: ReadWrite<u16>, // 0x26

    pub prefetchable_base_upper32: ReadWrite<u32>, // 0x28
    pub prefetchable_limit_upper32: ReadWrite<u32>, // 0x2C

    pub io_base_upper16: ReadWrite<u16>,  // 0x30
    pub io_limit_upper16: ReadWrite<u16>, // 0x32

    pub capabilities_ptr: ReadOnly<u8>, // 0x34
    _reserved: [u8; 3],                // 0x35..0x37

    pub expansion_rom_base: ReadWrite<u32>, // 0x38

    pub interrupt_line: ReadWrite<u8>,               // 0x3C
    pub interrupt_pin: ReadOnly<u8>,                 // 0x3D
    pub bridge_control: ReadWrite<PciBridgeControl>, // 0x3E (16-bit)
}
