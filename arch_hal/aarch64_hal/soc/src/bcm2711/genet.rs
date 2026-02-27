use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt;
use core::fmt::Write as _;
use core::hint::spin_loop;
use core::mem::MaybeUninit;
use core::mem::offset_of;
use core::mem::size_of;
use core::ops::ControlFlow;
use core::sync::atomic::Ordering;
use core::time::Duration;

use dtb::DtbParser;
use dtb::WalkError;
use io_api::ethernet::EthernetFrameIo;
use io_api::ethernet::MacAddr;
use mutex::pod::RawBytePod;
use timer::SystemTimer;
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
const ETH_FCS_LEN: usize = 4;
const TX_BUF_LENGTH: usize = 2048;
const MAX_DMA_WINDOWS: usize = 4;

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

// Real-time deadlines derived from CNTPCT/CNTFRQ keep behavior stable across CPU frequencies.
const MDIO_BUSY_TIMEOUT_US: u64 = 20_000;
const TX_DONE_TIMEOUT_US: u64 = 2_000;
const PHY_STATUS_POLL_INTERVAL_US: u64 = 10_000;
const PHY_STATUS_LOG_INTERVAL_US: u64 = 250_000;
const LOOPBACK_SELFTEST_TIMEOUT_US: u64 = 200_000;
const LOOPBACK_SELFTEST_FRAME_LEN: usize = 128;
const LOOPBACK_SELFTEST_LOG_BYTES: usize = 32;
const LOOPBACK_SELFTEST_ETHERTYPE: u16 = 0x88B5;

const PHY_BMCR: u8 = 0;
const PHY_BMSR: u8 = 1;
const PHY_ADVERTISE: u8 = 4;
const PHY_LPA: u8 = 5;
const PHY_CTRL1000: u8 = 9;
const PHY_STAT1000: u8 = 10;
const PHY_BMCR_ANENABLE: u16 = 1 << 12;
const PHY_BMCR_ANRESTART: u16 = 1 << 9;
const PHY_BMCR_FULLDPLX: u16 = 1 << 8;
const PHY_BMCR_SPEED100: u16 = 1 << 13;
const PHY_BMCR_SPEED1000: u16 = 1 << 6;
const PHY_BMSR_LSTATUS: u16 = 1 << 2;
const PHY_BMSR_ANEGCOMPLETE: u16 = 1 << 5;
const PHY_ADV_10HALF: u16 = 1 << 5;
const PHY_ADV_10FULL: u16 = 1 << 6;
const PHY_ADV_100HALF: u16 = 1 << 7;
const PHY_ADV_100FULL: u16 = 1 << 8;
const PHY_1000_HALF: u16 = 1 << 8;
const PHY_1000_FULL: u16 = 1 << 9;

const PORT_MODE_EXT_GPHY: u32 = 3;
const UMAC_SPEED_10: u32 = 0;
const UMAC_SPEED_100: u32 = 1;
const UMAC_SPEED_1000: u32 = 2;
const BCM2711_DMA_FALLBACK_CPU_BASE: usize = 0x0000_0000;
const BCM2711_DMA_FALLBACK_DMA_BASE: usize = 0xC000_0000;
const BCM2711_DMA_FALLBACK_LEN: usize = 0x4000_0000;

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
    DmaAddressNotCovered,
    El2VaToPaFailed,
    LoopbackSelfTestFailed,
    LoopbackSelfTestTxFailed,
    LoopbackSelfTestRxTimeout,
    LoopbackSelfTestMismatch,
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
        reserved@[5:4] [ignore],
        pub crc_fwd@[6:6],
        reserved@[12:7] [ignore],
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

// Cache maintenance rounds ranges to the runtime D-cache line size derived from CTR_EL0.
// Keep DMA backing storage conservatively aligned so clean/invalidate operations do not spill
// into unrelated memory even on larger cache line configurations.
#[repr(align(256))]
struct AlignedTxBuffer([u8; TX_BUF_LENGTH]);

#[repr(align(256))]
struct AlignedRxStorage([u8; RX_TOTAL_BUFSIZE]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DmaWindow {
    dma_base: usize,
    cpu_base: usize,
    len: usize,
}

impl DmaWindow {
    const fn empty() -> Self {
        Self {
            dma_base: 0,
            cpu_base: 0,
            len: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmaMappingSource {
    DtbRanges { node_name: &'static str },
    DtbRangesEmptyIdentity { node_name: &'static str },
    FallbackBcm2711,
}

enum DmaRangesScanResult {
    NotFound,
    Found {
        windows: [DmaWindow; MAX_DMA_WINDOWS],
        count: usize,
        source: DmaMappingSource,
    },
}

struct DtbGenetConfig {
    mmio_base: usize,
    mmio_size: usize,
    mac_addr: MacAddr,
    phy_mode: PhyMode,
    phy_addr: u8,
    interrupts: [u32; 4],
    interrupt_count: usize,
    dma_windows: [DmaWindow; MAX_DMA_WINDOWS],
    dma_window_count: usize,
    dma_mapping_source: DmaMappingSource,
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
    mmio_base: usize,
    mac_addr: MacAddr,
    phy_mode: PhyMode,
    phy_addr: u8,
    local_loopback: bool,
    interrupts: [u32; 4],
    interrupt_count: usize,
    dma_windows: [DmaWindow; MAX_DMA_WINDOWS],
    dma_window_count: usize,
    dma_mapping_source: DmaMappingSource,
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
static TAKEN: RawBytePod<bool> = unsafe { RawBytePod::new_raw_unchecked(false) };
// SAFETY: Publishes completion of one-time initialization for `STATE`.
static READY: RawBytePod<bool> = unsafe { RawBytePod::new_raw_unchecked(false) };
// SAFETY: One-time debug flag updated atomically to avoid repeated ring index reset logs.
static RX_RING_INDEX_ZERO_LOGGED: RawBytePod<bool> =
    unsafe { RawBytePod::new_raw_unchecked(false) };
// SAFETY: One-time debug flag updated atomically to avoid repeated ring index reset logs.
static TX_RING_INDEX_ZERO_LOGGED: RawBytePod<bool> =
    unsafe { RawBytePod::new_raw_unchecked(false) };
// SAFETY: The crate enables `sync_unsafe_cell`; this cell stores the singleton driver instance.
// Access is serialized by the `TAKEN/READY` one-time initialization protocol.
static STATE: SyncUnsafeCell<MaybeUninit<Bcm2711GenetV5>> =
    SyncUnsafeCell::new(MaybeUninit::uninit());
// SAFETY: This storage is dedicated RX DMA memory owned by this NIC backend.
static mut RXBUF: AlignedRxStorage = AlignedRxStorage([0; RX_TOTAL_BUFSIZE]);

impl Bcm2711GenetV5 {
    pub fn init_from_dtb(
        dtb: &DtbParser,
        link_wait: Option<Duration>,
    ) -> Result<&'static mut Self, Bcm2711GenetError> {
        Self::init_from_dtb_with_mode(dtb, false, link_wait)
    }

    pub fn init_from_dtb_loopback_no_phy(
        dtb: &DtbParser,
    ) -> Result<&'static mut Self, Bcm2711GenetError> {
        Self::init_from_dtb_with_mode(dtb, true, None)
    }

    fn init_from_dtb_with_mode(
        dtb: &DtbParser,
        local_loopback: bool,
        link_wait: Option<Duration>,
    ) -> Result<&'static mut Self, Bcm2711GenetError> {
        if TAKEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Bcm2711GenetError::AlreadyTaken);
        }

        let result = Self::init_from_dtb_inner(dtb, local_loopback, link_wait);
        if result.is_err() {
            READY.store(false, Ordering::Release);
            TAKEN.store(false, Ordering::Release);
        }
        result
    }

    fn init_from_dtb_inner(
        dtb: &DtbParser,
        local_loopback: bool,
        link_wait: Option<Duration>,
    ) -> Result<&'static mut Self, Bcm2711GenetError> {
        let parsed = Self::parse_dtb(dtb)?;
        if parsed.mmio_size < GENET_MMIO_MIN_SIZE || parsed.mmio_base == 0 {
            return Err(Bcm2711GenetError::InvalidMmioRegion);
        }

        // SAFETY: The DT `reg` entry is expected to be an MMIO mapping for GENETv5 and
        // the caller runs in a bootloader environment with a stable mapping for this region.
        let regs = unsafe { &*(parsed.mmio_base as *const Registers) };

        let mut instance = Bcm2711GenetV5 {
            regs,
            mmio_base: parsed.mmio_base,
            mac_addr: parsed.mac_addr,
            phy_mode: parsed.phy_mode,
            phy_addr: parsed.phy_addr,
            local_loopback,
            interrupts: parsed.interrupts,
            interrupt_count: parsed.interrupt_count,
            dma_windows: parsed.dma_windows,
            dma_window_count: parsed.dma_window_count,
            dma_mapping_source: parsed.dma_mapping_source,
            tx_index: 0,
            rx_index: 0,
            c_index: 0,
            txbuf: AlignedTxBuffer([0; TX_BUF_LENGTH]),
        };

        instance.init_hw(link_wait)?;

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

            let (dma_windows, dma_window_count, dma_mapping_source) =
                match Self::parse_dma_windows(&node).map_err(WalkError::User)? {
                    DmaRangesScanResult::Found {
                        windows,
                        count,
                        source,
                    } => (windows, count, source),
                    DmaRangesScanResult::NotFound => {
                        let mut windows = [DmaWindow::empty(); MAX_DMA_WINDOWS];
                        windows[0] = DmaWindow {
                            cpu_base: BCM2711_DMA_FALLBACK_CPU_BASE,
                            dma_base: BCM2711_DMA_FALLBACK_DMA_BASE,
                            len: BCM2711_DMA_FALLBACK_LEN,
                        };
                        debug_uart_log(format_args!(
                            "genet: dma-ranges missing in DTB; using fallback cpu_base=0x{:016x} dma_base=0x{:016x} len=0x{:016x}\n",
                            windows[0].cpu_base,
                            windows[0].dma_base,
                            windows[0].len
                        ));
                        (windows, 1, DmaMappingSource::FallbackBcm2711)
                    }
                };

            Ok(ControlFlow::Break(DtbGenetConfig {
                mmio_base: reg.0,
                mmio_size: reg.1,
                mac_addr,
                phy_mode,
                phy_addr,
                interrupts,
                interrupt_count: stored,
                dma_windows,
                dma_window_count,
                dma_mapping_source,
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

    fn parse_dma_windows(
        node: &dtb::DtbNodeView<'_, '_>,
    ) -> Result<DmaRangesScanResult, Bcm2711GenetError> {
        let mut current = Some(*node);
        while let Some(scan_node) = current {
            let dma_ranges = scan_node
                .property_bytes("dma-ranges")
                .map_err(Bcm2711GenetError::DtbParseError)?;
            let Some(raw_dma_ranges) = dma_ranges else {
                current = scan_node
                    .parent_view()
                    .map_err(Bcm2711GenetError::DtbParseError)?;
                continue;
            };

            if raw_dma_ranges.is_empty() {
                return Ok(DmaRangesScanResult::Found {
                    windows: [DmaWindow::empty(); MAX_DMA_WINDOWS],
                    count: 0,
                    source: DmaMappingSource::DtbRangesEmptyIdentity {
                        node_name: scan_node.name(),
                    },
                });
            }

            let mut windows = [DmaWindow::empty(); MAX_DMA_WINDOWS];
            let mut count = 0usize;
            let mut iter = scan_node
                .dma_ranges_iter()
                .map_err(Bcm2711GenetError::DtbParseError)?
                .ok_or(Bcm2711GenetError::DtbParseError(
                    "genet: dma-ranges present but not iterable",
                ))?;
            for entry in &mut iter {
                let entry = entry.map_err(Bcm2711GenetError::DtbParseError)?;
                if count < MAX_DMA_WINDOWS {
                    windows[count] = DmaWindow {
                        dma_base: entry.child_base,
                        cpu_base: entry.parent_base,
                        len: entry.len,
                    };
                    count += 1;
                }
            }
            return Ok(DmaRangesScanResult::Found {
                windows,
                count,
                source: DmaMappingSource::DtbRanges {
                    node_name: scan_node.name(),
                },
            });
        }

        Ok(DmaRangesScanResult::NotFound)
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

    fn log_dma_mapping_setup(&self) -> Result<(), Bcm2711GenetError> {
        let rx_base_va = Self::rx_base_va();
        let rx_base_pa = Self::rx_base_pa()?;
        let rx_base_dma = self.cpu_to_dma(rx_base_pa, RX_BUF_LENGTH)?;

        let txbuf_va = self.txbuf.0.as_ptr() as usize;
        let txbuf_pa = Self::va_to_pa_el2_read_usize(txbuf_va)?;
        let txbuf_dma = self.cpu_to_dma(txbuf_pa, TX_BUF_LENGTH)?;

        debug_uart_log(format_args!(
            "genet: dma setup mmio_base=0x{:016x} rxbase_va=0x{:016x} rxbase_pa=0x{:016x} rxbase_dma=0x{:016x} txbuf_va=0x{:016x} txbuf_pa=0x{:016x} txbuf_dma=0x{:016x} dma_window_count={}\n",
            self.mmio_base,
            rx_base_va,
            rx_base_pa,
            rx_base_dma,
            txbuf_va,
            txbuf_pa,
            txbuf_dma,
            self.dma_window_count
        ));
        match self.dma_mapping_source {
            DmaMappingSource::DtbRanges { node_name } => {
                debug_uart_log(format_args!(
                    "genet: dma mapping source=DTB dma-ranges @ {}\n",
                    node_name
                ));
            }
            DmaMappingSource::DtbRangesEmptyIdentity { node_name } => {
                debug_uart_log(format_args!(
                    "genet: dma mapping source=DTB dma-ranges empty -> identity @ {}\n",
                    node_name
                ));
            }
            DmaMappingSource::FallbackBcm2711 => {
                debug_uart_log(format_args!(
                    "genet: dma mapping source=fallback bcm2711 dma-ranges\n"
                ));
            }
        }
        for (index, window) in self
            .dma_windows
            .iter()
            .take(self.dma_window_count)
            .enumerate()
        {
            debug_uart_log(format_args!(
                "genet: dma_window[{}] cpu_base=0x{:016x} dma_base=0x{:016x} len=0x{:016x}\n",
                index, window.cpu_base, window.dma_base, window.len
            ));
        }
        Ok(())
    }

    fn rx_base_va() -> usize {
        // SAFETY: `RXBUF` is dedicated static storage for this singleton NIC backend.
        unsafe { core::ptr::addr_of!(RXBUF.0) as *const u8 as usize }
    }

    fn rx_base_pa() -> Result<usize, Bcm2711GenetError> {
        Self::va_to_pa_el2_read_usize(Self::rx_base_va())
    }

    fn va_to_pa_el2_read_usize(va: usize) -> Result<usize, Bcm2711GenetError> {
        let pa = cpu::va_to_pa_el2_read(va as u64).ok_or(Bcm2711GenetError::El2VaToPaFailed)?;
        usize::try_from(pa).map_err(|_| Bcm2711GenetError::El2VaToPaFailed)
    }

    fn rx_slot_va_addr(&self, slot: u16) -> usize {
        Self::rx_base_va() + (slot as usize) * RX_BUF_LENGTH
    }

    fn dma_ctrl_enable_mask() -> u32 {
        (1u32 << (DEFAULT_Q as u32 + DMA_RING_BUF_EN_SHIFT)) | DMA_EN
    }

    fn cpu_to_dma(&self, cpu: usize, len: usize) -> Result<usize, Bcm2711GenetError> {
        if self.dma_window_count == 0 {
            return Ok(cpu);
        }
        let cpu_end = cpu
            .checked_add(len)
            .ok_or(Bcm2711GenetError::DmaAddressNotCovered)?;

        for window in self.dma_windows.iter().take(self.dma_window_count) {
            let Some(window_end) = window.cpu_base.checked_add(window.len) else {
                continue;
            };
            if cpu >= window.cpu_base && cpu_end <= window_end {
                let offset = cpu - window.cpu_base;
                return window
                    .dma_base
                    .checked_add(offset)
                    .ok_or(Bcm2711GenetError::DmaAddressNotCovered);
            }
        }

        Err(Bcm2711GenetError::DmaAddressNotCovered)
    }

    fn init_hw(&mut self, link_wait: Option<Duration>) -> Result<(), Bcm2711GenetError> {
        let result = (|| -> Result<(), Bcm2711GenetError> {
            let rev = SysRevCtrl::from_bits(self.regs.sys_rev_ctrl.read());
            let major = rev.get(SysRevCtrl::major) as u8;
            let minor = rev.get(SysRevCtrl::minor) as u8;
            if major != 6 {
                return Err(Bcm2711GenetError::UnsupportedGenetVersion { major, minor });
            }
            debug_uart_log(format_args!(
                "genet: init rev={}.{} phy_addr={} phy_mode={}\n",
                major,
                minor,
                self.phy_addr,
                phy_mode_name(self.phy_mode)
            ));
            self.log_dma_mapping_setup()?;

            self.program_phy_interface();

            // Disable MAC, then issue soft reset with local loopback first.
            self.regs.umac_cmd.write(0);
            self.regs.umac_cmd.write(
                UmacCmd::new()
                    .set(UmacCmd::sw_reset, 1)
                    .set(UmacCmd::lcl_loop_en, 1)
                    .bits(),
            );
            Self::delay_us(2);

            self.umac_reset_sequence();
            self.program_mac_address();

            self.disable_dma_and_flush_tx();
            self.rx_ring_init();
            self.rx_descs_init()?;
            self.tx_ring_init();
            // SAFETY: `dsb sy` guarantees descriptor stores and cache maintenance complete before
            // setting `DMA_EN`, so RDMA/TDMA cannot fetch stale descriptor data.
            unsafe {
                asm!("dsb sy", options(nostack, preserves_flags));
            }
            self.enable_dma();
            Self::error_sync_barrier();

            if self.local_loopback {
                debug_uart_log(format_args!(
                    "[selftest] genet: skip PHY bringup (local loopback mode)\n"
                ));
            } else {
                match link_wait {
                    Some(timeout) => {
                        debug_uart_log(format_args!(
                            "genet: phy bringup begin timeout={}ms phy_addr={}\n",
                            timeout.as_millis(),
                            self.phy_addr
                        ));
                    }
                    None => {
                        debug_uart_log(format_args!(
                            "genet: phy bringup begin timeout=forever phy_addr={}\n",
                            self.phy_addr
                        ));
                    }
                }
                self.phy_bringup(link_wait)?;
                debug_uart_log(format_args!("genet: phy bringup complete\n"));
            }
            self.adjust_link_and_enable_umac();
            debug_uart_log(format_args!("genet: umac enable complete\n"));
            Ok(())
        })();

        if let Err(err) = result {
            debug_uart_log(format_args!(
                "genet: init failed; quiescing MAC/DMA err={:?}\n",
                err
            ));
            self.stop_hw_quiesce();
            return Err(err);
        }

        Ok(())
    }

    fn delay_us(us: u64) {
        let mut timer = SystemTimer::new();
        timer.init();
        timer.wait(Duration::from_micros(us));
    }

    fn program_phy_interface(&self) {
        let value = SysPortCtrl::new()
            .set(SysPortCtrl::port_mode, PORT_MODE_EXT_GPHY)
            .bits();
        self.regs.sys_port_ctrl.write(value);
    }

    fn umac_reset_sequence(&self) {
        // U-Boot toggles bit1 in SYS_RBUF_FLUSH_CTRL with 10us delays around transitions.
        let flush_bit = 1u32 << 1;
        let mut reg = self.regs.sys_rbuf_flush_ctrl.read();
        reg |= flush_bit;
        self.regs.sys_rbuf_flush_ctrl.write(reg);
        Self::delay_us(10);

        reg &= !flush_bit;
        self.regs.sys_rbuf_flush_ctrl.write(reg);
        Self::delay_us(10);

        self.regs.sys_rbuf_flush_ctrl.write(0);
        Self::delay_us(10);

        self.regs.umac_cmd.write(0);
        self.regs.umac_cmd.write(
            UmacCmd::new()
                .set(UmacCmd::sw_reset, 1)
                .set(UmacCmd::lcl_loop_en, 1)
                .bits(),
        );
        Self::delay_us(2);
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
        let mask = Self::dma_ctrl_enable_mask();
        self.regs.tdma_common.dma_ctrl.clear_bits(mask);
        self.regs.rdma_common.dma_ctrl.clear_bits(mask);
        self.regs.rdma_common.ring_cfg.write(0);
        self.regs.tdma_common.ring_cfg.write(0);
        cpu::dsb_sy();

        self.regs.umac_tx_flush.write(1);
        Self::delay_us(10);
        self.regs.umac_tx_flush.write(0);
    }

    fn enable_dma(&self) {
        let dma_ctrl = Self::dma_ctrl_enable_mask();
        self.regs.tdma_common.dma_ctrl.write(dma_ctrl);
        self.regs.rdma_common.dma_ctrl.set_bits(dma_ctrl);
    }

    fn stop_hw_quiesce(&self) {
        let cmd = UmacCmd::from_bits(self.regs.umac_cmd.read())
            .set(UmacCmd::tx_en, 0)
            .set(UmacCmd::rx_en, 0)
            .bits();
        self.regs.umac_cmd.write(cmd);

        let mask = Self::dma_ctrl_enable_mask();
        self.regs.tdma_common.dma_ctrl.clear_bits(mask);
        self.regs.rdma_common.dma_ctrl.clear_bits(mask);
        self.regs.rdma_common.ring_cfg.write(0);
        self.regs.tdma_common.ring_cfg.write(0);
        cpu::dsb_sy();

        self.regs.umac_tx_flush.write(1);
        Self::delay_us(10);
        self.regs.umac_tx_flush.write(0);
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

        self.c_index = 0;
        self.rx_index = 0;
        self.regs.rdma_rings[DEFAULT_Q].index_a.write(0);
        self.regs.rdma_rings[DEFAULT_Q].index_b.write(0);
        if RX_RING_INDEX_ZERO_LOGGED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            debug_uart_log(format_args!(
                "genet: rdma ring index reset index_a=0x{:08x} index_b=0x{:08x}\n",
                self.regs.rdma_rings[DEFAULT_Q].index_a.read(),
                self.regs.rdma_rings[DEFAULT_Q].index_b.read()
            ));
        }

        self.regs.rdma_rings[DEFAULT_Q]
            .ring_buf_size
            .write(((RX_DESCS as u32) << DMA_RING_SIZE_SHIFT) | RX_BUF_LENGTH as u32);
        self.regs.rdma_rings[DEFAULT_Q]
            .flow_or_xoff
            .write(DMA_FC_THRESH_VALUE);
        self.regs.rdma_common.ring_cfg.write(1u32 << DEFAULT_Q);
    }

    fn rx_descs_init(&self) -> Result<(), Bcm2711GenetError> {
        let len_stat = ((RX_BUF_LENGTH as u32) << DMA_BUFLENGTH_SHIFT) | DMA_OWN;
        let rxbase_va = Self::rx_base_va();
        let rxbase_pa = Self::rx_base_pa()?;

        // The entire RX storage is owned by DMA after descriptor programming. We clean once to
        // push potential dirty CPU lines before NIC writes into these buffers.
        cpu::clean_dcache_range(rxbase_va as *const u8, RX_TOTAL_BUFSIZE);

        for i in 0..RX_DESCS {
            let desc = &self.regs.rx_desc[i];
            let addr_va = rxbase_va + i * RX_BUF_LENGTH;
            let addr_pa = rxbase_pa + i * RX_BUF_LENGTH;
            let addr_dma = self.cpu_to_dma(addr_pa, RX_BUF_LENGTH)?;
            if i == 0 {
                debug_uart_log(format_args!(
                    "genet: rx_desc[0] addr_dma=0x{:016x} addr_pa=0x{:016x} addr_va=0x{:016x} len=0x{:x}\n",
                    addr_dma, addr_pa, addr_va, RX_BUF_LENGTH
                ));
            }
            if (addr_dma >> 32) != 0 {
                debug_uart_log(format_args!(
                    "genet: rx_desc[{}] addr_dma exceeds 32-bit addr_pa=0x{:016x} addr_va=0x{:016x} addr_dma=0x{:016x}\n",
                    i, addr_pa, addr_va, addr_dma
                ));
                return Err(Bcm2711GenetError::DmaAddressNotCovered);
            }
            desc.addr_lo.write(addr_dma as u32);
            desc.addr_hi.write((addr_dma >> 32) as u32);
            desc.length_status.write(len_stat);
            if i < 4 {
                let addr_lo = desc.addr_lo.read();
                let addr_hi = desc.addr_hi.read();
                debug_uart_log(format_args!(
                    "genet: rx_desc[{}] programmed addr_lo=0x{:08x} addr_hi=0x{:08x}\n",
                    i, addr_lo, addr_hi
                ));
            }
        }
        Ok(())
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

        self.tx_index = 0;
        self.regs.tdma_rings[DEFAULT_Q].index_a.write(0);
        self.regs.tdma_rings[DEFAULT_Q].index_b.write(0);
        if TX_RING_INDEX_ZERO_LOGGED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            debug_uart_log(format_args!(
                "genet: tdma ring index reset index_a=0x{:08x} index_b=0x{:08x}\n",
                self.regs.tdma_rings[DEFAULT_Q].index_a.read(),
                self.regs.tdma_rings[DEFAULT_Q].index_b.read()
            ));
        }

        self.regs.tdma_rings[DEFAULT_Q].done_or_thresh.write(1);
        self.regs.tdma_rings[DEFAULT_Q].flow_or_xoff.write(0);
        self.regs.tdma_rings[DEFAULT_Q]
            .ring_buf_size
            .write(((TX_DESCS as u32) << DMA_RING_SIZE_SHIFT) | RX_BUF_LENGTH as u32);
        self.regs.tdma_common.ring_cfg.write(1u32 << DEFAULT_Q);
    }

    fn phy_bringup(&self, link_wait: Option<Duration>) -> Result<(), Bcm2711GenetError> {
        let bmcr = self.mdio_read(self.phy_addr, PHY_BMCR)?;
        let restart = bmcr | PHY_BMCR_ANENABLE | PHY_BMCR_ANRESTART;
        self.mdio_write(self.phy_addr, PHY_BMCR, restart)?;
        debug_uart_log(format_args!(
            "genet: phy bringup start phy={} bmcr=0x{:04x} restart=0x{:04x}\n",
            self.phy_addr, bmcr, restart
        ));

        // Loop-count timeouts vary with core speed. Use a CNTPCT-based deadline so this wait
        // remains a real-time wait independent of frequency/optimization changes.
        let deadline =
            link_wait.map(|timeout| read_cntpct_el0().wrapping_add(ticks_from_duration(timeout)));
        let poll_ticks = ticks_from_us(PHY_STATUS_POLL_INTERVAL_US);
        let log_ticks = ticks_from_us(PHY_STATUS_LOG_INTERVAL_US);
        let mut next_poll = read_cntpct_el0();
        let mut next_log = next_poll.wrapping_add(log_ticks);

        let mut last_bmcr = bmcr;
        let mut last_bmsr = 0u16;
        let mut last_adv = 0u16;
        let mut last_lpa = 0u16;
        let mut last_ctrl1000 = 0u16;
        let mut last_stat1000 = 0u16;

        loop {
            let now = read_cntpct_el0();
            if tick_reached(now, next_poll) {
                last_bmsr = self.mdio_read_bmsr_latched()?;
                if (last_bmsr & PHY_BMSR_LSTATUS) != 0 && (last_bmsr & PHY_BMSR_ANEGCOMPLETE) != 0 {
                    if let Ok(value) = self.mdio_read(self.phy_addr, PHY_BMCR) {
                        last_bmcr = value;
                    }
                    if let Ok(value) = self.mdio_read(self.phy_addr, PHY_ADVERTISE) {
                        last_adv = value;
                    }
                    if let Ok(value) = self.mdio_read(self.phy_addr, PHY_LPA) {
                        last_lpa = value;
                    }
                    if let Ok(value) = self.mdio_read(self.phy_addr, PHY_CTRL1000) {
                        last_ctrl1000 = value;
                    }
                    if let Ok(value) = self.mdio_read(self.phy_addr, PHY_STAT1000) {
                        last_stat1000 = value;
                    }
                    debug_uart_log(format_args!(
                        "genet: phy link up phy={} link=1 aneg=1 bmcr=0x{:04x} bmsr=0x{:04x} adv=0x{:04x} lpa=0x{:04x} c1000=0x{:04x} s1000=0x{:04x}\n",
                        self.phy_addr,
                        last_bmcr,
                        last_bmsr,
                        last_adv,
                        last_lpa,
                        last_ctrl1000,
                        last_stat1000
                    ));
                    return Ok(());
                }
                next_poll = now.wrapping_add(poll_ticks);
            }

            if tick_reached(now, next_log) {
                if let Ok(value) = self.mdio_read_bmsr_latched() {
                    last_bmsr = value;
                }
                if let Ok(value) = self.mdio_read(self.phy_addr, PHY_BMCR) {
                    last_bmcr = value;
                }
                if let Ok(value) = self.mdio_read(self.phy_addr, PHY_ADVERTISE) {
                    last_adv = value;
                }
                if let Ok(value) = self.mdio_read(self.phy_addr, PHY_LPA) {
                    last_lpa = value;
                }
                if let Ok(value) = self.mdio_read(self.phy_addr, PHY_CTRL1000) {
                    last_ctrl1000 = value;
                }
                if let Ok(value) = self.mdio_read(self.phy_addr, PHY_STAT1000) {
                    last_stat1000 = value;
                }

                debug_uart_log(format_args!(
                    "genet: phy wait phy={} link={} aneg={} bmcr=0x{:04x} bmsr=0x{:04x} adv=0x{:04x} lpa=0x{:04x} c1000=0x{:04x} s1000=0x{:04x}\n",
                    self.phy_addr,
                    ((last_bmsr & PHY_BMSR_LSTATUS) != 0) as u8,
                    ((last_bmsr & PHY_BMSR_ANEGCOMPLETE) != 0) as u8,
                    last_bmcr,
                    last_bmsr,
                    last_adv,
                    last_lpa,
                    last_ctrl1000,
                    last_stat1000
                ));
                next_log = now.wrapping_add(log_ticks);
            }

            if let Some(deadline_ticks) = deadline {
                if tick_reached(now, deadline_ticks) {
                    debug_uart_log(format_args!(
                        "genet: phy timeout phy={} link={} aneg={} bmcr=0x{:04x} bmsr=0x{:04x} adv=0x{:04x} lpa=0x{:04x} c1000=0x{:04x} s1000=0x{:04x}\n",
                        self.phy_addr,
                        ((last_bmsr & PHY_BMSR_LSTATUS) != 0) as u8,
                        ((last_bmsr & PHY_BMSR_ANEGCOMPLETE) != 0) as u8,
                        last_bmcr,
                        last_bmsr,
                        last_adv,
                        last_lpa,
                        last_ctrl1000,
                        last_stat1000
                    ));
                    return Err(Bcm2711GenetError::PhyTimeout);
                }
            }
            spin_loop();
        }
    }

    fn resolve_umac_speed_from_phy(&self) -> Option<u32> {
        // Clause-22 provides a mostly-standard way to infer speed. Not all PHYs expose every
        // detail via these registers, so this is intentionally best-effort.
        let bmsr = self.mdio_read_bmsr_latched().ok()?;
        if (bmsr & PHY_BMSR_LSTATUS) == 0 {
            return None;
        }

        let bmcr = self.mdio_read(self.phy_addr, PHY_BMCR).ok()?;
        if (bmcr & PHY_BMCR_ANENABLE) != 0 {
            if (bmsr & PHY_BMSR_ANEGCOMPLETE) == 0 {
                return None;
            }

            // For 1000BASE-T, local advertisement (reg 9) and partner status (reg 10) expose
            // the common capabilities directly; prefer the highest common mode.
            let adv1000 = self.mdio_read(self.phy_addr, PHY_CTRL1000).ok()?;
            let stat1000 = self.mdio_read(self.phy_addr, PHY_STAT1000).ok()?;
            let common1000 = adv1000 & stat1000;
            if (common1000 & PHY_1000_FULL) != 0 {
                return Some(UMAC_SPEED_1000);
            }
            if (common1000 & PHY_1000_HALF) != 0 {
                return Some(UMAC_SPEED_1000);
            }

            // For 10/100, intersect local advertise and partner ability (regs 4/5).
            let advertise = self.mdio_read(self.phy_addr, PHY_ADVERTISE).ok()?;
            let lpa = self.mdio_read(self.phy_addr, PHY_LPA).ok()?;
            let common = advertise & lpa;
            if (common & (PHY_ADV_100FULL | PHY_ADV_100HALF)) != 0 {
                return Some(UMAC_SPEED_100);
            }
            if (common & (PHY_ADV_10FULL | PHY_ADV_10HALF)) != 0 {
                return Some(UMAC_SPEED_10);
            }
            return None;
        }

        // Forced mode path: decode BMCR speed bits. Some PHYs may use vendor extensions for
        // corner cases; returning None keeps caller fallback behavior intact.
        let _is_full_duplex = (bmcr & PHY_BMCR_FULLDPLX) != 0;
        let speed = match (
            (bmcr & PHY_BMCR_SPEED100) != 0,
            (bmcr & PHY_BMCR_SPEED1000) != 0,
        ) {
            (false, false) => UMAC_SPEED_10,
            (true, false) => UMAC_SPEED_100,
            (false, true) => UMAC_SPEED_1000,
            (true, true) => return None,
        };
        Some(speed)
    }

    fn adjust_link_and_enable_umac(&self) {
        // RGMII OOB control mirrors U-Boot: clear OOB_DISABLE, then force LINK + MODE_EN.
        let mut oob = ExtRgmiiOobCtrl::from_bits(self.regs.ext_rgmii_oob_ctrl.read())
            .set(ExtRgmiiOobCtrl::oob_disable, 0)
            .set(ExtRgmiiOobCtrl::rgmii_link, 1)
            .set(ExtRgmiiOobCtrl::rgmii_mode_en, 1);

        if matches!(self.phy_mode, PhyMode::Rgmii | PhyMode::RgmiiRxid) {
            oob = oob.set(ExtRgmiiOobCtrl::id_mode_dis, 1);
        } else {
            oob = oob.set(ExtRgmiiOobCtrl::id_mode_dis, 0);
        }
        self.regs.ext_rgmii_oob_ctrl.write(oob.bits());

        // PHY and MAC speed must match or traffic can fail silently. Resolve speed from Clause-22
        // registers when possible, and fall back to 1000 Mbps to preserve previous behavior.
        let resolved_speed = self.resolve_umac_speed_from_phy();
        let (speed, source) = match resolved_speed {
            Some(value) => (value, "clause22"),
            None => (UMAC_SPEED_1000, "fallback_1000"),
        };
        debug_uart_log(format_args!(
            "genet: umac speed source={} raw={} mbps={}\n",
            source,
            speed,
            umac_speed_mbps(speed)
        ));
        let cmd = UmacCmd::from_bits(self.regs.umac_cmd.read())
            .set(UmacCmd::speed, speed)
            .set(UmacCmd::crc_fwd, 0)
            .set(UmacCmd::sw_reset, 0)
            .set(
                UmacCmd::lcl_loop_en,
                if self.local_loopback { 1 } else { 0 },
            )
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

    fn mdio_read_bmsr_latched(&self) -> Result<u16, Bcm2711GenetError> {
        let bmsr_first = self.mdio_read(self.phy_addr, PHY_BMSR)?;
        let bmsr_second = self.mdio_read(self.phy_addr, PHY_BMSR)?;
        Ok(bmsr_first | bmsr_second)
    }

    fn wait_mdio_done(&self) -> Result<(), Bcm2711GenetError> {
        // Loop-count timeouts are brittle because compiler settings and core frequency change how
        // long one iteration takes. Deadline-based polling keeps timeout behavior predictable.
        let deadline = deadline_ticks_from_now(MDIO_BUSY_TIMEOUT_US);
        loop {
            if MdioCmd::from_bits(self.regs.mdio_cmd.read()).get(MdioCmd::start_busy) == 0 {
                return Ok(());
            }
            if timed_out(deadline) {
                break;
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

        // We copy user payload into an internal cacheline-aligned TX scratch buffer so cache clean
        // operations cannot spill into unrelated caller memory.
        let tx_ptr = self.txbuf.0.as_ptr();
        let txbuf_va = tx_ptr as usize;
        let txbuf_pa = Self::va_to_pa_el2_read_usize(txbuf_va)?;
        cpu::clean_dcache_range(tx_ptr, frame.len());

        let cur = self.regs.tdma_rings[DEFAULT_Q].index_b.read();
        // TDMA producer/consumer indices are effectively 16-bit counters in hardware.
        // Mask on every increment so we never publish 0x1_0000 at wrap boundaries.
        let prod_index = (cur.wrapping_add(1)) & 0xffff;
        let desc = &self.regs.tx_desc[self.tx_index as usize];
        let addr_dma = self.cpu_to_dma(txbuf_pa, frame.len())?;
        if (addr_dma >> 32) != 0 {
            debug_uart_log(format_args!(
                "genet: tx scratch addr_dma exceeds 32-bit addr_pa=0x{:016x} addr_va=0x{:016x} addr_dma=0x{:016x} len={}\n",
                txbuf_pa,
                txbuf_va,
                addr_dma,
                frame.len()
            ));
            return Err(Bcm2711GenetError::DmaAddressNotCovered);
        }

        // Queue tag 0x3f and APPEND_CRC mirror U-Boot. The hardware appends Ethernet FCS when
        // APPEND_CRC is set; frame buffers therefore carry header+payload without trailing FCS.
        let len_stat = ((frame.len() as u32) << DMA_BUFLENGTH_SHIFT)
            | (0x3fu32 << DMA_TX_QTAG_SHIFT)
            | DMA_TX_APPEND_CRC
            | DMA_SOP
            | DMA_EOP;

        desc.addr_lo.write(addr_dma as u32);
        desc.addr_hi.write((addr_dma >> 32) as u32);
        desc.length_status.write(len_stat);

        // SAFETY: `dmb oshst` orders the descriptor MMIO stores above before the TDMA producer
        // index doorbell store below, so the device cannot observe a new producer value before
        // descriptor contents are visible on the interconnect.
        unsafe {
            asm!("dmb oshst", options(nostack, preserves_flags));
        }

        self.tx_index = (self.tx_index + 1) & 0xff;
        self.regs.tdma_rings[DEFAULT_Q].index_b.write(prod_index);

        let expect = (prod_index & 0xffff) as u16;
        let deadline = deadline_ticks_from_now(TX_DONE_TIMEOUT_US);
        // Poll completion using a wrap-safe predicate. Equality only works if no wrap/overshoot
        // happens while we poll; "reached" works both across wrap and when CONS advances further.
        loop {
            let cons = (self.regs.tdma_rings[DEFAULT_Q].index_a.read() & 0xffff) as u16;
            if ring_index_reached(cons, expect) {
                return Ok(());
            }
            if timed_out(deadline) {
                break;
            }
            spin_loop();
        }

        self.recover_after_tx_timeout()?;
        Err(Bcm2711GenetError::TxTimeout)
    }

    fn recover_after_tx_timeout(&mut self) -> Result<(), Bcm2711GenetError> {
        // Best-effort bounded recovery for a wedged TX path. Keep this path free of long MDIO
        // waits so callers do not block for PHY autonegotiation durations on every timeout.
        self.disable_dma_and_flush_tx();
        self.umac_reset_sequence();
        self.program_mac_address();
        self.rx_ring_init();
        self.rx_descs_init()?;
        self.tx_ring_init();
        // SAFETY: Keep the same descriptor/MMIO ordering guarantee as initial bring-up.
        unsafe {
            asm!("dsb sy", options(nostack, preserves_flags));
        }
        self.enable_dma();
        Self::error_sync_barrier();
        self.adjust_link_and_enable_umac();
        Ok(())
    }

    fn rearm_one_rx_buffer(&mut self) {
        let addr_va = self.rx_slot_va_addr(self.rx_index);

        // After CPU consumed an RX buffer, clean it before giving ownership back to DMA.
        cpu::clean_dcache_range(addr_va as *const u8, RX_BUF_LENGTH);

        self.c_index = self.c_index.wrapping_add(1) & 0xffff;
        self.rdma_ring().index_b.write(self.c_index as u32);
        self.rx_index = (self.rx_index + 1) & 0xff;
    }

    fn error_sync_barrier() {
        // SAFETY: `hint #16` is the architectural ESB encoding. On CPUs that implement ESB it
        // synchronizes pending asynchronous SError to this point; on others it behaves as a hint.
        unsafe {
            asm!("hint #16", options(nostack, preserves_flags));
        }
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
        let addr_va = self.rx_slot_va_addr(self.rx_index);

        // RX buffers are fixed-size, dedicated slots inside `RXBUF`. Invalidate the entire slot
        // before reading so stale cache lines from previous, longer packets cannot leak in.
        cpu::invalidate_dcache_range(addr_va as *const u8, RX_BUF_LENGTH);

        // RBUF_ALIGN_2B causes hardware to place payload with a 2-byte offset for IP alignment.
        let mut payload_len = length.saturating_sub(RX_BUF_OFFSET);

        // If CRC forwarding is enabled, the trailing 4-byte FCS is present in the RX buffer.
        // Otherwise, hardware strips FCS and we must not subtract it here.
        let crc_fwd = UmacCmd::from_bits(self.regs.umac_cmd.read()).get(UmacCmd::crc_fwd) != 0;
        if crc_fwd {
            payload_len = payload_len.saturating_sub(ETH_FCS_LEN);
        }
        if payload_len == 0 {
            // Empty/malformed descriptor payload: consume and recycle the descriptor so RX keeps
            // flowing. Returning Some(0) is safe because current callers already drop frame_len=0.
            self.rearm_one_rx_buffer();
            return Some(0);
        }
        if payload_len > out.len() {
            // Never return truncated frames. Callers treat Some(n>0) as a complete Ethernet frame,
            // and partial payloads break higher-layer parsing (e.g. UDP decode). Returning Some(0)
            // explicitly signals "drop this frame" while still consuming the descriptor, so the RX
            // ring does not stall behind an oversized packet.
            self.rearm_one_rx_buffer();
            return Some(0);
        }

        // SAFETY: RX slot addresses are computed from dedicated `RXBUF` storage bounds.
        let src = unsafe {
            core::slice::from_raw_parts((addr_va + RX_BUF_OFFSET) as *const u8, payload_len)
        };
        out[..payload_len].copy_from_slice(src);

        self.rearm_one_rx_buffer();
        Some(payload_len)
    }

    fn loopback_selftest_impl(&mut self) -> Result<(), Bcm2711GenetError> {
        let mut tx = [0u8; LOOPBACK_SELFTEST_FRAME_LEN];
        tx[..6].copy_from_slice(&self.mac_addr.0);
        tx[6..12].copy_from_slice(&self.mac_addr.0);
        tx[12..14].copy_from_slice(&LOOPBACK_SELFTEST_ETHERTYPE.to_be_bytes());
        for (i, byte) in tx[14..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(0x5a);
        }

        debug_uart_log(format_args!(
            "[selftest] genet: send local-loopback frame len={}\n",
            tx.len()
        ));
        if let Err(err) = self.try_send_frame_result(&tx) {
            debug_uart_log(format_args!(
                "[selftest] genet: tx failed during loopback selftest: {:?}\n",
                err
            ));
            return Err(Bcm2711GenetError::LoopbackSelfTestTxFailed);
        }

        let deadline = deadline_ticks_from_now(LOOPBACK_SELFTEST_TIMEOUT_US);
        let mut rx = [0u8; 256];
        loop {
            match self.try_recv_frame_impl(&mut rx) {
                None | Some(0) => {}
                Some(n) => {
                    let expected = tx.len();
                    let expected_with_fcs = expected + ETH_FCS_LEN;
                    if n != expected && n != expected_with_fcs {
                        debug_uart_log(format_args!(
                            "[selftest] genet: unexpected rx length={}, expected {} or {}\n",
                            n, expected, expected_with_fcs
                        ));
                        return Err(Bcm2711GenetError::LoopbackSelfTestMismatch);
                    }
                    if rx[..expected] != tx[..] {
                        debug_uart_log(format_args!(
                            "[selftest] genet: frame mismatch len={} expected={}\n",
                            n, expected
                        ));
                        let inspect = expected.min(LOOPBACK_SELFTEST_LOG_BYTES);
                        for i in 0..inspect {
                            if rx[i] != tx[i] {
                                debug_uart_log(format_args!(
                                    "[selftest] genet: first mismatch byte={} tx={:02x} rx={:02x}\n",
                                    i, tx[i], rx[i]
                                ));
                                break;
                            }
                        }
                        debug_uart_log(format_args!("[selftest] genet: tx[0..{}]=", inspect));
                        for byte in tx.iter().take(inspect) {
                            debug_uart_log(format_args!("{:02x}", byte));
                        }
                        debug_uart_log(format_args!("\n"));
                        debug_uart_log(format_args!("[selftest] genet: rx[0..{}]=", inspect));
                        for byte in rx.iter().take(inspect) {
                            debug_uart_log(format_args!("{:02x}", byte));
                        }
                        debug_uart_log(format_args!("\n"));
                        return Err(Bcm2711GenetError::LoopbackSelfTestMismatch);
                    }
                    if n == expected_with_fcs {
                        debug_uart_log(format_args!(
                            "[selftest] genet: received frame includes trailing 4-byte FCS\n"
                        ));
                    }
                    debug_uart_log(format_args!(
                        "[selftest] genet: local-loopback PASS len={}\n",
                        n
                    ));
                    return Ok(());
                }
            }

            if timed_out(deadline) {
                debug_uart_log(format_args!(
                    "[selftest] genet: timeout waiting for loopback RX frame\n"
                ));
                return Err(Bcm2711GenetError::LoopbackSelfTestRxTimeout);
            }
            spin_loop();
        }
    }

    pub fn local_loopback_selftest(&mut self) -> Result<(), Bcm2711GenetError> {
        if !self.local_loopback {
            debug_uart_log(format_args!(
                "[selftest] genet: local_loopback_selftest requires loopback init mode\n"
            ));
            return Err(Bcm2711GenetError::LoopbackSelfTestFailed);
        }

        self.loopback_selftest_impl()
    }

    pub fn local_loopback_selftest_live(&mut self) -> Result<(), Bcm2711GenetError> {
        let prev_local = self.local_loopback;
        let prev_cmd_bits = self.regs.umac_cmd.read();

        let test_cmd_bits = UmacCmd::from_bits(prev_cmd_bits)
            .set(UmacCmd::sw_reset, 0)
            .set(UmacCmd::lcl_loop_en, 1)
            .set(UmacCmd::tx_en, 1)
            .set(UmacCmd::rx_en, 1)
            .bits();
        self.local_loopback = true;
        self.regs.umac_cmd.write(test_cmd_bits);

        let result = self.loopback_selftest_impl();

        self.regs.umac_cmd.write(prev_cmd_bits);
        self.local_loopback = prev_local;
        result
    }
}

fn ring_index_reached(cons: u16, expect: u16) -> bool {
    // Naive `cons >= expect` fails when the 16-bit index wraps:
    //   expect=0x0000 after wrap, cons=0xffff (still before wrap) would look "greater".
    // In modular arithmetic, `cons` has reached/passed `expect` when `(cons - expect)` is in the
    // forward half-space [0, 0x7fff]. This is equivalent to interpreting the delta as signed i16
    // and checking `>= 0`, but keeps everything in integer arithmetic without casts.
    let delta = cons.wrapping_sub(expect);
    delta < 0x8000
}

struct UartLogBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> UartLogBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.buf[..self.len]).ok()
    }
}

impl<const N: usize> fmt::Write for UartLogBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let avail = self.buf.len().saturating_sub(self.len);
        if avail == 0 {
            return Ok(());
        }
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(avail);
        self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

fn debug_uart_log(args: fmt::Arguments<'_>) {
    let mut line = UartLogBuf::<288>::new();
    let _ = line.write_fmt(args);
    if let Some(s) = line.as_str() {
        print::debug_uart::write(s);
    }
}

fn phy_mode_name(mode: PhyMode) -> &'static str {
    match mode {
        PhyMode::Rgmii => "rgmii",
        PhyMode::RgmiiRxid => "rgmii-rxid",
        PhyMode::RgmiiIdBestEffort => "rgmii-id(best-effort)",
        PhyMode::RgmiiTxidBestEffort => "rgmii-txid(best-effort)",
    }
}

fn umac_speed_mbps(speed: u32) -> u32 {
    match speed {
        UMAC_SPEED_10 => 10,
        UMAC_SPEED_100 => 100,
        UMAC_SPEED_1000 => 1000,
        _ => 0,
    }
}

fn tick_reached(now: u64, target: u64) -> bool {
    now.wrapping_sub(target) < (1u64 << 63)
}

fn read_cntfrq_el0() -> u64 {
    let current_frequency;
    // SAFETY: Accessing CNTFRQ_EL0 requires EL2 in this project, is read-only, and has no side
    // effects. No additional ordering is needed for this static frequency value.
    unsafe {
        asm!(
            "mrs {current_frequency}, CNTFRQ_EL0",
            current_frequency = out(reg) current_frequency
        );
    }
    current_frequency
}

fn read_cntpct_el0() -> u64 {
    cpu::isb();
    let counter;
    // SAFETY: Reading CNTPCT_EL0 requires EL2 in this project and is side-effect free. The ISB
    // above provides ordering so the sampled counter value is not speculatively stale.
    unsafe {
        asm!("mrs {counter}, CNTPCT_EL0", counter = out(reg) counter);
    }
    counter
}

fn ticks_from_us(us: u64) -> u64 {
    let freq = read_cntfrq_el0();
    let ticks = u128::from(us).saturating_mul(u128::from(freq)) / 1_000_000u128;
    ticks.min(u128::from(u64::MAX)) as u64
}

fn ticks_from_duration(duration: Duration) -> u64 {
    let freq = read_cntfrq_el0();
    let ticks = duration.as_nanos().saturating_mul(u128::from(freq)) / 1_000_000_000u128;
    ticks.min(u128::from(u64::MAX)) as u64
}

fn deadline_ticks_from_now(us: u64) -> u64 {
    read_cntpct_el0().wrapping_add(ticks_from_us(us))
}

fn timed_out(deadline: u64) -> bool {
    // Wrap-safe deadline test: once `now` reaches/passes `deadline` in modular u64 space,
    // `(now - deadline)` falls in the forward half-space [0, 2^63).
    tick_reached(read_cntpct_el0(), deadline)
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
