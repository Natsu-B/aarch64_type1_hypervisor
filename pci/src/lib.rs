#![no_std]

use core::mem::size_of;
use typestate::ReadOnly;
use typestate::ReadWrite;
use typestate::bitregs;

bitregs! {
    /// PCI ID Register (offset 0x00, 32-bit).
    pub struct PciId: u32 {
        pub vendor_id@[15:0],
        pub device_id@[31:16],
    }
}

bitregs! {
    /// Class Code / Revision Register (offset 0x08, 32-bit).
    pub struct PciClassRevision: u32 {
        pub revision_id@[7:0],
        pub prog_if@[15:8],
        pub subclass@[23:16],
        pub class_code@[31:24],
    }
}

bitregs! {
    /// BIST / HeaderType / Latency / CacheLine (offset 0x0C, 32-bit).
    ///
    /// - [7:0]   Cache Line Size
    /// - [15:8]  Latency Timer
    /// - [23:16] Header Type (7-bit) + Multifunction (bit7)
    /// - [31:24] BIST
    pub struct PciBhlc: u32 {
        pub cache_line_size@[7:0],
        pub latency_timer@[15:8],

        pub header_kind@[22:16] as PciHeaderKind {
            Standard = 0x0,
            PciToPciBridge = 0x1,
            CardBusBridge = 0x2,
        },
        pub multifunction@[23:23],

        pub completion_code@[27:24],
        reserved@[29:28] [res0],
        pub start_bist@[30:30],
        pub bist_capable@[31:31],
    }
}

bitregs! {
    /// Subsystem IDs (offset 0x2C, 32-bit) - Type 0 only.
    pub struct PciSubsystemId: u32 {
        pub subsystem_vendor_id@[15:0],
        pub subsystem_id@[31:16],
    }
}

bitregs! {
    /// Capabilities Pointer (offset 0x34, 32-bit).
    pub struct PciCapPtr: u32 {
        pub capabilities_ptr@[7:0],
        reserved@[31:8] [ignore],
    }
}

bitregs! {
    /// Interrupt info (offset 0x3C, 32-bit) - Type 0.
    pub struct PciType0Interrupt: u32 {
        pub interrupt_line@[7:0],
        pub interrupt_pin@[15:8],
        pub min_grant@[23:16],
        pub max_latency@[31:24],
    }
}

bitregs! {
    /// Bus numbers (offset 0x18, 32-bit) - Type 1.
    pub struct PciBusNumbers: u32 {
        pub primary_bus_number@[7:0],
        pub secondary_bus_number@[15:8],
        pub subordinate_bus_number@[23:16],
        pub secondary_latency_timer@[31:24],
    }
}

bitregs! {
    /// Memory base/limit (offset 0x20, 32-bit) - Type 1.
    pub struct PciMemoryBaseLimit: u32 {
        pub memory_base@[15:0],
        pub memory_limit@[31:16],
    }
}

bitregs! {
    /// Prefetchable memory base/limit (offset 0x24, 32-bit) - Type 1.
    pub struct PciPrefMemBaseLimit: u32 {
        pub prefetchable_memory_base@[15:0],
        pub prefetchable_memory_limit@[31:16],
    }
}

bitregs! {
    /// I/O base/limit upper16 (offset 0x30, 32-bit) - Type 1.
    pub struct PciIoUpper16: u32 {
        pub io_base_upper16@[15:0],
        pub io_limit_upper16@[31:16],
    }
}

bitregs! {
    /// Interrupt line/pin + Bridge Control (offset 0x3C, 32-bit) - Type 1.
    pub struct PciType1InterruptBridgeControl: u32 {
        pub interrupt_line@[7:0],
        pub interrupt_pin@[15:8],

        pub parity_enable_secondary@[16:16],
        pub serr_enable_secondary@[17:17],
        pub isa_enable@[18:18],
        pub vga_enable@[19:19],
        reserved@[20:20] [res0],
        pub master_abort_mode@[21:21],
        pub secondary_bus_reset@[22:22],
        pub fast_back_to_back_secondary@[23:23],
        reserved@[31:24] [ignore],
    }
}

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<PCIConfigRegType0>() == 0x40);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<PCIConfigRegType1>() == 0x40);

/// PCI Configuration Header: Type 0x0 (Standard device).
/// Layout is 16x u32 dwords (64 bytes). All accesses are 32-bit.
#[repr(C)]
pub struct PCIConfigRegType0 {
    pub id: ReadOnly<PciId>,                        // 0x00
    cmd_status: ReadWrite<u32>,                     // 0x04
    pub class_revision: ReadOnly<PciClassRevision>, // 0x08
    pub bhlc: ReadWrite<PciBhlc>,                   // 0x0C

    pub bar: [ReadWrite<u32>; 6],       // 0x10..0x27
    pub cardbus_cis_ptr: ReadOnly<u32>, // 0x28

    pub subsystem_id: ReadOnly<PciSubsystemId>, // 0x2C
    pub expansion_rom_base: ReadWrite<u32>,     // 0x30

    pub cap_ptr: ReadOnly<PciCapPtr>, // 0x34
    _reserved: ReadOnly<u32>,         // 0x38

    pub interrupt: ReadWrite<PciType0Interrupt>, // 0x3C
}

/// PCI Configuration Header: Type 0x1 (PCI-to-PCI bridge).
/// Layout is 16x u32 dwords (64 bytes). All accesses are 32-bit.
#[repr(C)]
pub struct PCIConfigRegType1 {
    pub id: ReadOnly<PciId>,                        // 0x00
    cmd_status: ReadWrite<u32>,                     // 0x04
    pub class_revision: ReadOnly<PciClassRevision>, // 0x08
    pub bhlc: ReadWrite<PciBhlc>,                   // 0x0C

    pub bar: [ReadWrite<u32>; 2], // 0x10..0x17

    pub bus_numbers: ReadWrite<PciBusNumbers>, // 0x18
    io_sec_status: ReadWrite<u32>,             // 0x1C

    pub memory_base_limit: ReadWrite<PciMemoryBaseLimit>, // 0x20
    pub pref_mem_base_limit: ReadWrite<PciPrefMemBaseLimit>, // 0x24

    pub prefetchable_base_upper32: ReadWrite<u32>, // 0x28
    pub prefetchable_limit_upper32: ReadWrite<u32>, // 0x2C

    pub io_upper16: ReadWrite<PciIoUpper16>, // 0x30

    pub cap_ptr: ReadOnly<PciCapPtr>,       // 0x34
    pub expansion_rom_base: ReadWrite<u32>, // 0x38

    pub intr_bridge_ctrl: ReadWrite<PciType1InterruptBridgeControl>, // 0x3C
}
