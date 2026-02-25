use core::cell::SyncUnsafeCell;
use core::hint::spin_loop;
use core::mem::MaybeUninit;
use core::mem::offset_of;
use core::mem::size_of;
use core::ops::ControlFlow;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use dtb::DtbParser;
use dtb::WalkError;
use io_api::ethernet::EthernetFrameIo;
use io_api::ethernet::MacAddr;
use typestate::ReadPure;
use typestate::ReadWrite;
use typestate::Readable;
use typestate::Writable;
use typestate::bitregs;

pub const DT_COMPAT_BCM2711_GENET_V5: &str = "brcm,bcm2711-genet-v5";
pub const DT_COMPAT_GENET_V5: &str = "brcm,genet-v5";
pub const DT_COMPAT_BCMGENET_V5: &str = "brcm,bcmgenet-v5";

const GENET_MMIO_MIN_SIZE: usize = 0x6000;

const TOTAL_DESCS: usize = 256;
const RX_DESCS: usize = TOTAL_DESCS;
const TX_DESCS: usize = TOTAL_DESCS;
const DEFAULT_Q: usize = 0x10;

const ENET_MAX_MTU_SIZE: usize = 1536;
const RX_BUF_LENGTH: usize = 2048;
const RX_TOTAL_BUFSIZE: usize = RX_BUF_LENGTH * RX_DESCS;
const RX_BUF_OFFSET: usize = 2;
const TX_BUF_LENGTH: usize = 2048;

const DMA_EN: u32 = 1 << 0;
const DMA_RING_BUF_EN_SHIFT: u32 = 1;
const DMA_BUFLENGTH_SHIFT: u32 = 16;
const DMA_BUFLENGTH_MASK: u32 = 0x0fff;
const DMA_RING_SIZE_SHIFT: u32 = 16;
const DMA_OWN: u32 = 0x8000;
const DMA_EOP: u32 = 0x4000;
const DMA_SOP: u32 = 0x2000;
const DMA_TX_APPEND_CRC: u32 = 0x0040;
const DMA_TX_QTAG_SHIFT: u32 = 7;
const DMA_MAX_BURST_LENGTH: u32 = 0x8;

const DMA_FC_THRESH_HI: u32 = (RX_DESCS as u32) >> 4;
const DMA_FC_THRESH_LO: u32 = 5;
const DMA_FC_THRESH_VALUE: u32 = (DMA_FC_THRESH_LO << 16) | DMA_FC_THRESH_HI;

const MDIO_BUSY_TIMEOUT_ITERS: usize = 200_000;
const PHY_LINK_TIMEOUT_ITERS: usize = 50_000_000;
const TX_DONE_TIMEOUT_ITERS: usize = 200_000;

const PHY_BMCR: u8 = 0;
const PHY_BMSR: u8 = 1;
const PHY_BMCR_ANENABLE: u16 = 1 << 12;
const PHY_BMCR_ANRESTART: u16 = 1 << 9;
const PHY_BMSR_LSTATUS: u16 = 1 << 2;
const PHY_BMSR_ANEGCOMPLETE: u16 = 1 << 5;

const PORT_MODE_EXT_GPHY: u32 = 3;
const UMAC_SPEED_1000: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bcm2711GenetError {
    DtbParseError(&'static str),
    DtbDeviceNotFound,
    InvalidMmioRegion,
    InvalidMacLength(usize),
    UnsupportedPhyMode,
    UnsupportedGenetVersion { major: u8, minor: u8 },
    MdioTimeout,
    MdioReadFail,
    PhyTimeout,
    TxTimeout,
    AlreadyTaken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhyMode {
    Rgmii,
    RgmiiRxid,
    // Best-effort compatibility modes. We only implement the same ID_MODE_DIS behavior
    // as U-Boot for RGMII/RGMII_RXID and do not program any vendor PHY delay registers.
    RgmiiIdBestEffort,
    RgmiiTxidBestEffort,
}

#[repr(C)]
#[derive(Debug)]
struct DmaDesc {
    length_status: ReadWrite<u32>,
    addr_lo: ReadWrite<u32>,
    addr_hi: ReadWrite<u32>,
}

#[repr(C)]
#[derive(Debug)]
struct DmaRingRegs {
    ptr0: ReadWrite<u32>, // +0x00: read/write pointer (RX/TX differs)
    _reserved_0x04: ReadWrite<u32>,
    index_a: ReadWrite<u32>, // +0x08: RX=PROD, TX=CONS
    index_b: ReadWrite<u32>, // +0x0c: RX=CONS, TX=PROD
    ring_buf_size: ReadWrite<u32>,
    start_addr: ReadWrite<u32>,
    _reserved_0x18: ReadWrite<u32>,
    end_addr: ReadWrite<u32>,
    _reserved_0x20: ReadWrite<u32>,
    done_or_thresh: ReadWrite<u32>,
    flow_or_xoff: ReadWrite<u32>,
    ptr1: ReadWrite<u32>,
    _reserved_0x30_0x3f: [ReadWrite<u32>; 4],
}

#[repr(C)]
#[derive(Debug)]
struct DmaCommonRegs {
    ring_cfg: ReadWrite<u32>,
    dma_ctrl: ReadWrite<u32>,
    _reserved_0x08: ReadWrite<u32>,
    scb_burst_size: ReadWrite<u32>,
}

#[repr(C)]
#[derive(Debug)]
struct Registers {
    // GENET_SYS_OFF (0x0000)
    sys_rev_ctrl: ReadPure<u32>,
    sys_port_ctrl: ReadWrite<u32>,
    sys_rbuf_flush_ctrl: ReadWrite<u32>,
    sys_tbuf_flush_ctrl: ReadWrite<u32>,
    _reserved_0x10_0x7f: [u32; 28],

    // GENET_EXT_OFF (0x0080)
    _reserved_0x80_0x8b: [u32; 3],
    ext_rgmii_oob_ctrl: ReadWrite<u32>,

    _reserved_0x90_0x2ff: [u32; 156],

    // GENET_RBUF_OFF (0x0300)
    rbuf_ctrl: ReadWrite<u32>,
    _reserved_0x304_0x3b3: [u32; 44],
    rbuf_tbuf_size_ctrl: ReadWrite<u32>,

    _reserved_0x3b8_0x807: [u32; 274],

    // GENET_UMAC_OFF (0x0800)
    _reserved_0x800_0x807: [u32; 2],
    umac_cmd: ReadWrite<u32>,
    umac_mac0: ReadWrite<u32>,
    umac_mac1: ReadWrite<u32>,
    umac_max_frame_len: ReadWrite<u32>,
    _reserved_0x818_0xb33: [u32; 199],
    umac_tx_flush: ReadWrite<u32>,
    _reserved_0xb38_0xd7f: [u32; 146],
    umac_mib_ctrl: ReadWrite<u32>,
    _reserved_0xd84_0xe13: [u32; 36],
    mdio_cmd: ReadWrite<u32>,

    _reserved_0xe18_0x1fff: [u32; 1146],

    // GENET_RX_OFF (0x2000)
    rx_desc: [DmaDesc; RX_DESCS],

    // GENET_RDMA_REG_OFF (0x2c00)
    rdma_rings: [DmaRingRegs; DEFAULT_Q + 1],
    rdma_common: DmaCommonRegs,

    _reserved_0x3050_0x3fff: [u32; 1004],

    // GENET_TX_OFF (0x4000)
    tx_desc: [DmaDesc; TX_DESCS],

    // GENET_TDMA_REG_OFF (0x4c00)
    tdma_rings: [DmaRingRegs; DEFAULT_Q + 1],
    tdma_common: DmaCommonRegs,
}

const _: () = assert!(size_of::<DmaDesc>() == 0x0c);
const _: () = assert!(size_of::<DmaRingRegs>() == 0x40);
const _: () = assert!(size_of::<DmaCommonRegs>() == 0x10);

const _: () = assert!(offset_of!(Registers, sys_rev_ctrl) == 0x0000);
const _: () = assert!(offset_of!(Registers, sys_port_ctrl) == 0x0004);
const _: () = assert!(offset_of!(Registers, sys_rbuf_flush_ctrl) == 0x0008);
const _: () = assert!(offset_of!(Registers, ext_rgmii_oob_ctrl) == 0x008c);
const _: () = assert!(offset_of!(Registers, rbuf_ctrl) == 0x0300);
const _: () = assert!(offset_of!(Registers, rbuf_tbuf_size_ctrl) == 0x03b4);
const _: () = assert!(offset_of!(Registers, umac_cmd) == 0x0808);
const _: () = assert!(offset_of!(Registers, umac_mac0) == 0x080c);
const _: () = assert!(offset_of!(Registers, umac_mac1) == 0x0810);
const _: () = assert!(offset_of!(Registers, umac_max_frame_len) == 0x0814);
const _: () = assert!(offset_of!(Registers, umac_tx_flush) == 0x0b34);
const _: () = assert!(offset_of!(Registers, umac_mib_ctrl) == 0x0d80);
const _: () = assert!(offset_of!(Registers, mdio_cmd) == 0x0e14);
const _: () = assert!(offset_of!(Registers, rx_desc) == 0x2000);
const _: () = assert!(offset_of!(Registers, rdma_rings) == 0x2c00);
const _: () = assert!(offset_of!(Registers, rdma_common) == 0x3040);
const _: () = assert!(offset_of!(Registers, tx_desc) == 0x4000);
const _: () = assert!(offset_of!(Registers, tdma_rings) == 0x4c00);
const _: () = assert!(offset_of!(Registers, tdma_common) == 0x5040);
const _: () = assert!(size_of::<Registers>() == 0x5050);

bitregs! {
    pub struct SysRevCtrl: u32 {
        reserved@[23:0] [ignore],
        pub major@[27:24],
        pub minor@[31:28],
    }
}

bitregs! {
    pub struct SysPortCtrl: u32 {
        pub port_mode@[2:0],
        reserved@[31:3] [ignore],
    }
}

bitregs! {
    pub struct ExtRgmiiOobCtrl: u32 {
        reserved@[3:0] [ignore],
        pub rgmii_link@[4:4],
        pub oob_disable@[5:5],
        pub rgmii_mode_en@[6:6],
        reserved@[15:7] [ignore],
        pub id_mode_dis@[16:16],
        reserved@[31:17] [ignore],
    }
}

bitregs! {
    pub struct RbufCtrl: u32 {
        reserved@[0:0] [ignore],
        pub align_2b@[1:1],
        reserved@[31:2] [ignore],
    }
}

bitregs! {
    pub struct RbufTbufSizeCtrl: u32 {
        pub value@[31:0],
    }
}

bitregs! {
    pub struct UmacCmd: u32 {
        pub tx_en@[0:0],
        pub rx_en@[1:1],
        pub speed@[3:2],
        reserved@[12:4] [ignore],
        pub sw_reset@[13:13],
        reserved@[14:14] [ignore],
        pub lcl_loop_en@[15:15],
        reserved@[31:16] [ignore],
    }
}

bitregs! {
    pub struct MdioCmd: u32 {
        pub data@[15:0],
        pub reg@[20:16],
        pub phy@[25:21],
        pub op@[27:26] as MdioOp {
            Write = 0b01,
            Read = 0b10,
        },
        pub read_fail@[28:28],
        pub start_busy@[29:29],
        reserved@[31:30] [ignore],
    }
}

#[repr(align(64))]
struct AlignedTxBuffer([u8; TX_BUF_LENGTH]);

#[repr(align(64))]
struct AlignedRxStorage([u8; RX_TOTAL_BUFSIZE]);

struct DtbGenetConfig {
    mmio_base: usize,
    mmio_size: usize,
    mac_addr: MacAddr,
    phy_mode: PhyMode,
    phy_addr: u8,
    interrupts: [u32; 4],
    interrupt_count: usize,
}

/// BCM2711 GENETv5 backend implementing frame-level Ethernet I/O.
///
/// DT assumptions (from Linux `brcm,bcmgenet.yaml` and U-Boot behavior):
/// - `compatible` includes one of:
///   `brcm,bcm2711-genet-v5`, `brcm,genet-v5` (or legacy `brcm,bcmgenet-v5`).
/// - `reg` provides the MMIO frame for the MAC core (we require at least 0x6000 bytes).
/// - MAC address comes from `local-mac-address` or `mac-address` (6 bytes).
/// - `phy-mode` must describe an RGMII mode. This driver supports `rgmii` and
///   `rgmii-rxid` directly; `rgmii-id` and `rgmii-txid` are accepted as best-effort.
/// - `phy-handle` must point to a PHY node with Clause-22 `reg` in range 0..31.
/// - At least two `interrupts` specifiers are expected by binding; we parse and keep
///   decoded IDs for future IRQ support, but the current data path is polling-only.
///
/// Hardware model notes:
/// - GENETv5 exposes TX/RX descriptor rings in MMIO space (not in normal RAM).
/// - We follow U-Boot’s single-queue setup using default queue #16 and assign all
///   256 descriptors to that queue.
/// - RX payload storage itself is in normal RAM (`RXBUF`) and must be cache-maintained.
pub struct Bcm2711GenetV5 {
    regs: &'static Registers,
    mac_addr: MacAddr,
    phy_mode: PhyMode,
    phy_addr: u8,
    interrupts: [u32; 4],
    interrupt_count: usize,
    tx_index: u16,
    rx_index: u16,
    c_index: u16,
    txbuf: AlignedTxBuffer,
}

// SAFETY: Access to the singleton happens through a single mutable reference returned by
// `init_from_dtb`, and caller code keeps ownership discipline over that reference.
unsafe impl Send for Bcm2711GenetV5 {}
// SAFETY: This driver is a process-wide singleton and all mutable operations require `&mut self`,
// so sharing the static storage container does not introduce unsynchronized concurrent mutation.
unsafe impl Sync for Bcm2711GenetV5 {}

// SAFETY: One NIC instance is expected in the bootloader, so singleton ownership is sufficient.
static TAKEN: AtomicBool = AtomicBool::new(false);
// SAFETY: Publishes completion of one-time initialization for `STATE`.
static READY: AtomicBool = AtomicBool::new(false);
// SAFETY: The crate enables `sync_unsafe_cell`; this cell stores the singleton driver instance.
// Access is serialized by the `TAKEN/READY` one-time initialization protocol.
static STATE: SyncUnsafeCell<MaybeUninit<Bcm2711GenetV5>> =
    SyncUnsafeCell::new(MaybeUninit::uninit());
// SAFETY: This storage is dedicated RX DMA memory owned by this NIC backend.
static mut RXBUF: AlignedRxStorage = AlignedRxStorage([0; RX_TOTAL_BUFSIZE]);

impl Bcm2711GenetV5 {
    pub fn init_from_dtb(dtb: &DtbParser) -> Result<&'static mut Self, Bcm2711GenetError> {
        if TAKEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Bcm2711GenetError::AlreadyTaken);
        }

        let result = Self::init_from_dtb_inner(dtb);
        if result.is_err() {
            READY.store(false, Ordering::Release);
            TAKEN.store(false, Ordering::Release);
        }
        result
    }

    fn init_from_dtb_inner(dtb: &DtbParser) -> Result<&'static mut Self, Bcm2711GenetError> {
        let parsed = Self::parse_dtb(dtb)?;
        if parsed.mmio_size < GENET_MMIO_MIN_SIZE || parsed.mmio_base == 0 {
            return Err(Bcm2711GenetError::InvalidMmioRegion);
        }

        // SAFETY: The DT `reg` entry is expected to be an MMIO mapping for GENETv5 and
        // the caller runs in a bootloader environment with a stable mapping for this region.
        let regs = unsafe { &*(parsed.mmio_base as *const Registers) };

        let mut instance = Bcm2711GenetV5 {
            regs,
            mac_addr: parsed.mac_addr,
            phy_mode: parsed.phy_mode,
            phy_addr: parsed.phy_addr,
            interrupts: parsed.interrupts,
            interrupt_count: parsed.interrupt_count,
            tx_index: 0,
            rx_index: 0,
            c_index: 0,
            txbuf: AlignedTxBuffer([0; TX_BUF_LENGTH]),
        };

        instance.init_hw()?;

        // SAFETY: Protected by one-time `TAKEN` acquisition; no other writer can race here.
        unsafe { (*STATE.get()).write(instance) };
        READY.store(true, Ordering::Release);

        // SAFETY: `READY=true` is only published after writing a fully initialized instance.
        let state = unsafe { (&mut *STATE.get()).assume_init_mut() };
        Ok(state)
    }

    fn parse_dtb(dtb: &DtbParser) -> Result<DtbGenetConfig, Bcm2711GenetError> {
        let walk = dtb.for_each_node_view(&mut |node| {
            let matched = node
                .compatible_contains(DT_COMPAT_BCM2711_GENET_V5)
                .map_err(WalkError::Dtb)?
                || node
                    .compatible_contains(DT_COMPAT_GENET_V5)
                    .map_err(WalkError::Dtb)?
                || node
                    .compatible_contains(DT_COMPAT_BCMGENET_V5)
                    .map_err(WalkError::Dtb)?;
            if !matched {
                return Ok(ControlFlow::Continue(()));
            }

            let reg = node
                .reg_iter()
                .map_err(WalkError::Dtb)?
                .next()
                .ok_or(WalkError::User(Bcm2711GenetError::InvalidMmioRegion))?
                .map_err(WalkError::Dtb)?;

            let mac_addr = Self::parse_mac_addr(&node).map_err(WalkError::User)?;
            let phy_mode = Self::parse_phy_mode(&node).map_err(WalkError::User)?;
            let phy_handle = node
                .property_u32_be("phy-handle")
                .map_err(WalkError::Dtb)?
                .ok_or(WalkError::User(Bcm2711GenetError::DtbParseError(
                    "genet: missing phy-handle",
                )))?;

            let phy_addr = match dtb.with_node_view_by_phandle(phy_handle, &mut |phy_node| {
                let reg = phy_node
                    .property_u32_be("reg")?
                    .ok_or("phy-handle node: missing reg")?;
                Ok(reg)
            }) {
                Ok(Some(addr)) => {
                    if addr > 31 {
                        return Err(WalkError::User(Bcm2711GenetError::DtbParseError(
                            "phy-handle node: reg out of range",
                        )));
                    }
                    addr as u8
                }
                Ok(None) => {
                    return Err(WalkError::User(Bcm2711GenetError::DtbParseError(
                        "phy-handle: node not found",
                    )));
                }
                Err(err) => return Err(WalkError::Dtb(err)),
            };

            let mut interrupts = [0u32; 4];
            let mut stored = 0usize;
            let mut total = 0usize;
            let _ = node.for_each_interrupt_specifier(&mut |cells| {
                if total < interrupts.len() {
                    interrupts[total] = Self::decode_interrupt_id(cells);
                    stored += 1;
                }
                total += 1;
                Ok::<ControlFlow<DtbGenetConfig>, WalkError<Bcm2711GenetError>>(
                    ControlFlow::Continue(()),
                )
            })?;

            if total < 2 {
                return Err(WalkError::User(Bcm2711GenetError::DtbParseError(
                    "genet: expected at least two interrupts",
                )));
            }

            Ok(ControlFlow::Break(DtbGenetConfig {
                mmio_base: reg.0,
                mmio_size: reg.1,
                mac_addr,
                phy_mode,
                phy_addr,
                interrupts,
                interrupt_count: stored,
            }))
        });

        match walk {
            Ok(ControlFlow::Break(cfg)) => Ok(cfg),
            Ok(ControlFlow::Continue(())) => Err(Bcm2711GenetError::DtbDeviceNotFound),
            Err(WalkError::Dtb(err)) => Err(Bcm2711GenetError::DtbParseError(err)),
            Err(WalkError::User(err)) => Err(err),
        }
    }

    fn parse_mac_addr(node: &dtb::DtbNodeView<'_, '_>) -> Result<MacAddr, Bcm2711GenetError> {
        let mac = if let Some(bytes) = node
            .property_bytes("local-mac-address")
            .map_err(Bcm2711GenetError::DtbParseError)?
        {
            bytes
        } else if let Some(bytes) = node
            .property_bytes("mac-address")
            .map_err(Bcm2711GenetError::DtbParseError)?
        {
            bytes
        } else {
            return Err(Bcm2711GenetError::DtbParseError(
                "genet: missing local-mac-address/mac-address",
            ));
        };

        if mac.len() != 6 {
            return Err(Bcm2711GenetError::InvalidMacLength(mac.len()));
        }
        Ok(MacAddr([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]))
    }

    fn parse_phy_mode(node: &dtb::DtbNodeView<'_, '_>) -> Result<PhyMode, Bcm2711GenetError> {
        let mode_bytes = node
            .property_bytes("phy-mode")
            .map_err(Bcm2711GenetError::DtbParseError)?
            .ok_or(Bcm2711GenetError::DtbParseError("genet: missing phy-mode"))?;

        let mode = Self::parse_nul_terminated_string(mode_bytes).ok_or(
            Bcm2711GenetError::DtbParseError("genet: invalid phy-mode string"),
        )?;

        match mode {
            "rgmii" => Ok(PhyMode::Rgmii),
            "rgmii-rxid" => Ok(PhyMode::RgmiiRxid),
            "rgmii-id" => Ok(PhyMode::RgmiiIdBestEffort),
            "rgmii-txid" => Ok(PhyMode::RgmiiTxidBestEffort),
            _ => Err(Bcm2711GenetError::UnsupportedPhyMode),
        }
    }

    fn parse_nul_terminated_string(bytes: &[u8]) -> Option<&str> {
        let nul = bytes.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&bytes[..nul]).ok()
    }

    fn decode_interrupt_id(spec: &[u32]) -> u32 {
        if spec.len() >= 2 {
            // For a GIC-style interrupt tuple, [0, N, flags] is SPI(N)+32 and
            // [1, N, flags] is PPI(N)+16. If this is not a GIC tuple, keep first cell.
            return match spec[0] {
                0 => spec[1].saturating_add(32),
                1 => spec[1].saturating_add(16),
                _ => spec[0],
            };
        }
        spec.first().copied().unwrap_or(0)
    }

    fn init_hw(&mut self) -> Result<(), Bcm2711GenetError> {
        let rev = SysRevCtrl::from_bits(self.regs.sys_rev_ctrl.read());
        let major = rev.get(SysRevCtrl::major) as u8;
        let minor = rev.get(SysRevCtrl::minor) as u8;
        if major != 6 {
            return Err(Bcm2711GenetError::UnsupportedGenetVersion { major, minor });
        }

        self.program_phy_interface();

        // Disable MAC, then issue soft reset with local loopback first.
        self.regs.umac_cmd.write(0);
        self.regs.umac_cmd.write(
            UmacCmd::new()
                .set(UmacCmd::sw_reset, 1)
                .set(UmacCmd::lcl_loop_en, 1)
                .bits(),
        );
        Self::short_delay();

        self.umac_reset_sequence();
        self.program_mac_address();

        self.disable_dma_and_flush_tx();
        self.rx_ring_init();
        self.rx_descs_init();
        self.tx_ring_init();
        self.enable_dma();

        self.phy_bringup()?;
        self.adjust_link_and_enable_umac();

        Ok(())
    }

    fn short_delay() {
        for _ in 0..1024 {
            spin_loop();
        }
    }

    fn program_phy_interface(&self) {
        let value = SysPortCtrl::new()
            .set(SysPortCtrl::port_mode, PORT_MODE_EXT_GPHY)
            .bits();
        self.regs.sys_port_ctrl.write(value);
    }

    fn umac_reset_sequence(&self) {
        // U-Boot toggles bit1 in SYS_RBUF_FLUSH_CTRL with short delays around transitions.
        let flush_bit = 1u32 << 1;
        let mut reg = self.regs.sys_rbuf_flush_ctrl.read();
        reg |= flush_bit;
        self.regs.sys_rbuf_flush_ctrl.write(reg);
        Self::short_delay();

        reg &= !flush_bit;
        self.regs.sys_rbuf_flush_ctrl.write(reg);
        Self::short_delay();

        self.regs.sys_rbuf_flush_ctrl.write(0);
        Self::short_delay();

        self.regs.umac_cmd.write(0);
        self.regs.umac_cmd.write(
            UmacCmd::new()
                .set(UmacCmd::sw_reset, 1)
                .set(UmacCmd::lcl_loop_en, 1)
                .bits(),
        );
        Self::short_delay();
        self.regs.umac_cmd.write(0);

        // Reset MIB counters.
        self.regs
            .umac_mib_ctrl
            .write((1 << 0) | (1 << 1) | (1 << 2));
        self.regs.umac_mib_ctrl.write(0);

        self.regs.umac_max_frame_len.write(ENET_MAX_MTU_SIZE as u32);

        let rbuf = RbufCtrl::from_bits(self.regs.rbuf_ctrl.read())
            .set(RbufCtrl::align_2b, 1)
            .bits();
        self.regs.rbuf_ctrl.write(rbuf);

        self.regs.rbuf_tbuf_size_ctrl.write(
            RbufTbufSizeCtrl::new()
                .set(RbufTbufSizeCtrl::value, 1)
                .bits(),
        );
    }

    fn program_mac_address(&self) {
        let addr = self.mac_addr.0;
        let mac0 = ((addr[0] as u32) << 24)
            | ((addr[1] as u32) << 16)
            | ((addr[2] as u32) << 8)
            | (addr[3] as u32);
        let mac1 = ((addr[4] as u32) << 8) | (addr[5] as u32);
        self.regs.umac_mac0.write(mac0);
        self.regs.umac_mac1.write(mac1);
    }

    fn disable_dma_and_flush_tx(&self) {
        self.regs.tdma_common.dma_ctrl.clear_bits(DMA_EN);
        self.regs.rdma_common.dma_ctrl.clear_bits(DMA_EN);

        self.regs.umac_tx_flush.write(1);
        Self::short_delay();
        self.regs.umac_tx_flush.write(0);
    }

    fn enable_dma(&self) {
        let dma_ctrl = (1u32 << (DEFAULT_Q as u32 + DMA_RING_BUF_EN_SHIFT)) | DMA_EN;
        self.regs.tdma_common.dma_ctrl.write(dma_ctrl);
        self.regs.rdma_common.dma_ctrl.set_bits(dma_ctrl);
    }

    fn rdma_ring(&self) -> &DmaRingRegs {
        &self.regs.rdma_rings[DEFAULT_Q]
    }

    fn rx_ring_init(&mut self) {
        self.regs
            .rdma_common
            .scb_burst_size
            .write(DMA_MAX_BURST_LENGTH);

        self.regs.rdma_rings[DEFAULT_Q].start_addr.write(0);
        self.regs.rdma_rings[DEFAULT_Q].ptr1.write(0);
        self.regs.rdma_rings[DEFAULT_Q].ptr0.write(0);
        self.regs.rdma_rings[DEFAULT_Q]
            .end_addr
            .write(((RX_DESCS * size_of::<DmaDesc>()) / 4 - 1) as u32);

        // Hardware cannot initialize RDMA_PROD_INDEX to 0 reliably; align CONS to current PROD.
        self.c_index = (self.regs.rdma_rings[DEFAULT_Q].index_a.read() & 0xffff) as u16;
        self.regs.rdma_rings[DEFAULT_Q]
            .index_b
            .write(self.c_index as u32);
        self.rx_index = self.c_index & 0xff;

        self.regs.rdma_rings[DEFAULT_Q]
            .ring_buf_size
            .write(((RX_DESCS as u32) << DMA_RING_SIZE_SHIFT) | RX_BUF_LENGTH as u32);
        self.regs.rdma_rings[DEFAULT_Q]
            .flow_or_xoff
            .write(DMA_FC_THRESH_VALUE);
        self.regs.rdma_common.ring_cfg.write(1u32 << DEFAULT_Q);
    }

    fn rx_descs_init(&self) {
        let len_stat = ((RX_BUF_LENGTH as u32) << DMA_BUFLENGTH_SHIFT) | DMA_OWN;

        // SAFETY: `RXBUF` is a dedicated static storage region for this singleton NIC driver.
        // We only create a raw pointer (no reference), then hand addresses to descriptors.
        let rxbase = unsafe { core::ptr::addr_of!(RXBUF.0) as *const u8 as usize };

        // The entire RX storage is owned by DMA after descriptor programming. We clean once to
        // push potential dirty CPU lines before NIC writes into these buffers.
        cpu::clean_dcache_range(rxbase as *const u8, RX_TOTAL_BUFSIZE);

        for i in 0..RX_DESCS {
            let desc = &self.regs.rx_desc[i];
            let addr = rxbase + i * RX_BUF_LENGTH;
            desc.addr_lo.write(addr as u32);
            desc.addr_hi.write((addr >> 32) as u32);
            desc.length_status.write(len_stat);
        }
    }

    fn tx_ring_init(&mut self) {
        self.regs
            .tdma_common
            .scb_burst_size
            .write(DMA_MAX_BURST_LENGTH);

        self.regs.tdma_rings[DEFAULT_Q].start_addr.write(0);
        self.regs.tdma_rings[DEFAULT_Q].ptr1.write(0);
        self.regs.tdma_rings[DEFAULT_Q].ptr0.write(0);
        self.regs.tdma_rings[DEFAULT_Q]
            .end_addr
            .write(((TX_DESCS * size_of::<DmaDesc>()) / 4 - 1) as u32);

        // Hardware cannot initialize TDMA_CONS_INDEX to 0 reliably; align PROD to current CONS.
        self.tx_index = (self.regs.tdma_rings[DEFAULT_Q].index_a.read() & 0xffff) as u16;
        self.regs.tdma_rings[DEFAULT_Q]
            .index_b
            .write(self.tx_index as u32);
        self.tx_index &= 0xff;

        self.regs.tdma_rings[DEFAULT_Q].done_or_thresh.write(1);
        self.regs.tdma_rings[DEFAULT_Q].flow_or_xoff.write(0);
        self.regs.tdma_rings[DEFAULT_Q]
            .ring_buf_size
            .write(((TX_DESCS as u32) << DMA_RING_SIZE_SHIFT) | RX_BUF_LENGTH as u32);
        self.regs.tdma_common.ring_cfg.write(1u32 << DEFAULT_Q);
    }

    fn phy_bringup(&self) -> Result<(), Bcm2711GenetError> {
        let bmcr = self.mdio_read(self.phy_addr, PHY_BMCR)?;
        let restart = bmcr | PHY_BMCR_ANENABLE | PHY_BMCR_ANRESTART;
        self.mdio_write(self.phy_addr, PHY_BMCR, restart)?;

        for _ in 0..PHY_LINK_TIMEOUT_ITERS {
            let bmsr = self.mdio_read(self.phy_addr, PHY_BMSR)?;
            if (bmsr & PHY_BMSR_LSTATUS) != 0 && (bmsr & PHY_BMSR_ANEGCOMPLETE) != 0 {
                return Ok(());
            }
            spin_loop();
        }

        Err(Bcm2711GenetError::PhyTimeout)
    }

    fn adjust_link_and_enable_umac(&self) {
        // RGMII OOB control mirrors U-Boot: clear OOB_DISABLE, then force LINK + MODE_EN.
        let mut oob = ExtRgmiiOobCtrl::from_bits(self.regs.ext_rgmii_oob_ctrl.read())
            .set(ExtRgmiiOobCtrl::oob_disable, 0)
            .set(ExtRgmiiOobCtrl::rgmii_link, 1)
            .set(ExtRgmiiOobCtrl::rgmii_mode_en, 1);

        if matches!(self.phy_mode, PhyMode::Rgmii | PhyMode::RgmiiRxid) {
            oob = oob.set(ExtRgmiiOobCtrl::id_mode_dis, 1);
        }
        self.regs.ext_rgmii_oob_ctrl.write(oob.bits());

        // Clause-22 speed resolution is PHY-specific; defaulting to 1000 Mbps after successful
        // autoneg/link to match the RPi4 typical path and keep bring-up deterministic.
        let speed = UMAC_SPEED_1000;
        let cmd = UmacCmd::from_bits(self.regs.umac_cmd.read())
            .set(UmacCmd::speed, speed)
            .set(UmacCmd::tx_en, 1)
            .set(UmacCmd::rx_en, 1)
            .bits();
        self.regs.umac_cmd.write(cmd);
    }

    fn mdio_write(&self, phy: u8, reg: u8, value: u16) -> Result<(), Bcm2711GenetError> {
        let cmd = MdioCmd::new()
            .set_enum(MdioCmd::op, MdioOp::Write)
            .set(MdioCmd::phy, phy as u32)
            .set(MdioCmd::reg, reg as u32)
            .set(MdioCmd::data, value as u32)
            .bits();
        self.regs.mdio_cmd.write(cmd);
        self.regs
            .mdio_cmd
            .set_bits(MdioCmd::new().set(MdioCmd::start_busy, 1).bits());
        self.wait_mdio_done()
    }

    fn mdio_read(&self, phy: u8, reg: u8) -> Result<u16, Bcm2711GenetError> {
        let cmd = MdioCmd::new()
            .set_enum(MdioCmd::op, MdioOp::Read)
            .set(MdioCmd::phy, phy as u32)
            .set(MdioCmd::reg, reg as u32)
            .bits();
        self.regs.mdio_cmd.write(cmd);
        self.regs
            .mdio_cmd
            .set_bits(MdioCmd::new().set(MdioCmd::start_busy, 1).bits());
        self.wait_mdio_done()?;

        let done = MdioCmd::from_bits(self.regs.mdio_cmd.read());
        if done.get(MdioCmd::read_fail) != 0 {
            return Err(Bcm2711GenetError::MdioReadFail);
        }

        Ok(done.get(MdioCmd::data) as u16)
    }

    fn wait_mdio_done(&self) -> Result<(), Bcm2711GenetError> {
        for _ in 0..MDIO_BUSY_TIMEOUT_ITERS {
            if MdioCmd::from_bits(self.regs.mdio_cmd.read()).get(MdioCmd::start_busy) == 0 {
                return Ok(());
            }
            spin_loop();
        }
        Err(Bcm2711GenetError::MdioTimeout)
    }

    fn try_send_frame_result(&mut self, frame: &[u8]) -> Result<(), Bcm2711GenetError> {
        if frame.is_empty() || frame.len() > ENET_MAX_MTU_SIZE || frame.len() > TX_BUF_LENGTH {
            return Err(Bcm2711GenetError::TxTimeout);
        }

        self.txbuf.0[..frame.len()].copy_from_slice(frame);

        // We copy user payload into an internal 64-byte aligned TX scratch buffer so cache clean
        // operations cannot spill into unrelated caller memory.
        let tx_ptr = self.txbuf.0.as_ptr();
        cpu::clean_dcache_range(tx_ptr, frame.len());

        let prod_index = self.regs.tdma_rings[DEFAULT_Q]
            .index_b
            .read()
            .wrapping_add(1);
        let desc = &self.regs.tx_desc[self.tx_index as usize];
        let addr = tx_ptr as usize;

        // Queue tag 0x3f and APPEND_CRC mirror U-Boot. The hardware appends Ethernet FCS when
        // APPEND_CRC is set; frame buffers therefore carry header+payload without trailing FCS.
        let len_stat = ((frame.len() as u32) << DMA_BUFLENGTH_SHIFT)
            | (0x3fu32 << DMA_TX_QTAG_SHIFT)
            | DMA_TX_APPEND_CRC
            | DMA_SOP
            | DMA_EOP;

        desc.addr_lo.write(addr as u32);
        desc.addr_hi.write((addr >> 32) as u32);
        desc.length_status.write(len_stat);

        self.tx_index = (self.tx_index + 1) & 0xff;
        self.regs.tdma_rings[DEFAULT_Q].index_b.write(prod_index);

        let expect = prod_index & 0xffff;
        for _ in 0..TX_DONE_TIMEOUT_ITERS {
            if (self.regs.tdma_rings[DEFAULT_Q].index_a.read() & 0xffff) == expect {
                return Ok(());
            }
            spin_loop();
        }

        Err(Bcm2711GenetError::TxTimeout)
    }

    fn rearm_one_rx_buffer(&mut self) {
        let desc = &self.regs.rx_desc[self.rx_index as usize];
        let addr = ((desc.addr_hi.read() as usize) << 32) | (desc.addr_lo.read() as usize);

        // After CPU consumed an RX buffer, clean it before giving ownership back to DMA.
        cpu::clean_dcache_range(addr as *const u8, RX_BUF_LENGTH);

        self.c_index = self.c_index.wrapping_add(1) & 0xffff;
        self.rdma_ring().index_b.write(self.c_index as u32);
        self.rx_index = (self.rx_index + 1) & 0xff;
    }

    fn try_recv_frame_impl(&mut self, out: &mut [u8]) -> Option<usize> {
        let ring = self.rdma_ring();
        let prod_index = ring.index_a.read() & 0xffff;
        if prod_index == self.c_index as u32 {
            return None;
        }

        let desc = &self.regs.rx_desc[self.rx_index as usize];
        let len_stat = desc.length_status.read();
        let mut length = ((len_stat >> DMA_BUFLENGTH_SHIFT) & DMA_BUFLENGTH_MASK) as usize;
        if length > RX_BUF_LENGTH {
            length = RX_BUF_LENGTH;
        }

        let addr = ((desc.addr_hi.read() as usize) << 32) | (desc.addr_lo.read() as usize);

        // RX buffers are fixed-size, dedicated, and aligned chunks inside `RXBUF`. We invalidate
        // only lines covered by this DMA buffer so we do not discard unrelated dirty cache state.
        cpu::invalidate_dcache_range(addr as *const u8, length);

        // RBUF_ALIGN_2B causes hardware to place payload with a 2-byte offset for IP alignment.
        let payload = length.saturating_sub(RX_BUF_OFFSET);
        let copy_len = payload.min(out.len());
        if copy_len > 0 {
            // SAFETY: Descriptor points into our dedicated RX storage programmed at init.
            let src = unsafe {
                core::slice::from_raw_parts((addr + RX_BUF_OFFSET) as *const u8, copy_len)
            };
            out[..copy_len].copy_from_slice(src);
        }

        self.rearm_one_rx_buffer();
        Some(copy_len)
    }
}

impl EthernetFrameIo for Bcm2711GenetV5 {
    fn max_frame_len(&self) -> usize {
        ENET_MAX_MTU_SIZE
    }

    fn mac_addr(&self) -> MacAddr {
        self.mac_addr
    }

    fn try_recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.try_recv_frame_impl(buf)
    }

    fn try_send_frame(&mut self, frame: &[u8]) -> bool {
        self.try_send_frame_result(frame).is_ok()
    }

    fn on_irq(&mut self) {
        // Polling-only implementation for now. Interrupt IDs are parsed from DT and retained,
        // but IRQ-driven RX/TX completion wiring is future work.
        let _ = (self.interrupt_count, self.interrupts);
    }
}
