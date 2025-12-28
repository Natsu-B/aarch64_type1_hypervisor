#![cfg_attr(not(test), no_std)]
#![feature(sync_unsafe_cell)]

//! GIC (Generic Interrupt Controller) abstraction for OS (EL1) and hypervisor (EL2) use. (Non-Secure only)
//!
//! This crate provides version-agnostic traits for the common interrupt lifecycle:
//! - per-CPU acknowledge / EOI / priority masking,
//! - global Distributor programming for SPIs,
//! - optional vGIC (virtualization) operations for EL2.
//!
//! Implementations must hide version-specific access paths (GICv2 MMIO vs GICv3 SysReg/MMIO),
//! and must internally apply any required ordering/barrier rules for correctness.

/// GICv2 implementation (MMIO-based Distributor/CPU interface; optional virtualization extensions).
pub mod gicv2;

/// GICv3 implementation (Distributor/Redistributor; CPU interface via system registers; optional ITS/MSI).
pub mod gicv3;

use cpu::CoreAffinity;

/// An MMIO region describing a device register frame.
///
/// `base` is the physical (or already-mapped virtual) base address used for volatile access.
/// `size` is the byte size of the region.
///
/// Implementations typically require:
/// - `base` aligned to the frame granule (commonly 4KiB),
/// - a mapping with *Device* memory attributes (no speculative access, strongly ordered as required),
/// - a region size matching the register block layout used by the backend.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub base: usize,
    pub size: usize,
}

/// Error type used by all GIC traits.
///
/// Backends should prefer returning a specific error over panicking, since these APIs are used in
/// early boot, exception paths, and interrupt context.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum GicError {
    /// Provided MMIO region size does not match the expected register block size.
    InvalidSize,
    /// Provided address is not aligned/valid for the backend (e.g. not page-aligned, unmapped).
    InvalidAddress,
    /// Interrupt ID is outside the supported range or is not valid for the requested operation.
    UnsupportedIntId,
    /// Requested functionality exists architecturally but is not supported by the backend/version.
    UnsupportedFeature,
    /// A `CoreAffinity` cannot be represented/targeted on this GIC backend (e.g. v2 8-CPU mask limit).
    UnsupportedAffinity,
    /// CPU interface number/mask cannot be encoded or decoded (e.g. not in 0..8, or not one-hot).
    InvalidCpuId,
    /// No free CPU slot exists for registering another CPU interface.
    NoFreeCpuSlot,
    /// Route description is not valid for the given `intid` (or cannot be encoded).
    InvalidRoute,
    /// Virtual interrupt description cannot be represented in the backend's list register format.
    InvalidVgicIrq,
    /// Requested state transition is invalid for the current hardware state/configuration.
    InvalidState,
    /// Index is out of range (e.g. LR index >= implemented LR count).
    IndexOutOfRange,
    /// Backend GIC revision is not supported (e.g. GICv2 backend found non-v2 hardware).
    UnsupportedRevision,
    /// Current security state/configuration (Secure vs Non-secure, GIC security settings)
    /// makes the operation architecturally inaccessible (e.g. Secure-only register, NS RAZ/WI).
    InvalidSecurityState,
}

/// Decoded acknowledgement token returned by `acknowledge()`.
///
/// - `raw` is the backend-specific acknowledgement value. Some interfaces require writing the
///   original `raw` value back to an EOI register (e.g. GICv2 GICC_EOIR).
/// - `intid` is the decoded interrupt identifier. Callers must treat spurious IDs as "no interrupt"
///   and must not dispatch handlers for them.
/// - `source` is the optional SGI source. When available, it is exposed as a `CoreAffinity`
///   (e.g. GICv2 IAR includes CPUID bits; GICv3 may provide affinity routing information).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AckedIrq {
    raw: u32,
    ack_kind: AckKind,
    pub intid: u32,
    pub source: Option<CoreAffinity>,
    /// Group determined at acknowledge time (drives EOIR vs AEOIR selection on GICv2).
    pub group: IrqGroup,
}

/// Interrupt group selection.
///
/// Group interpretation depends on security configuration:
/// - On systems with Security Extensions, Group0 is commonly Secure and Group1 is commonly Non-secure.
/// - Some deployments intentionally use only Group1 for both OS and hypervisor-visible interrupts.
///
/// Backends must return `UnsupportedFeature` if the requested group cannot be programmed.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IrqGroup {
    Group0,
    Group1,
}

/// Gic v2 specific acknowledge kind
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum AckKind {
    Iar,
    Aiar,
}

/// Trigger configuration for an interrupt (where configurable).
///
/// For GICv2 SPIs, this typically maps to `GICD_ICFGR` fields:
/// - Level: field = `0b00`
/// - Edge : field = `0b10`
///
/// Backends must return `UnsupportedFeature` if the trigger mode cannot be programmed for `intid`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TriggerMode {
    Level,
    Edge,
}

/// Routing policy for an SPI.
///
/// `Specific` targets a concrete core affinity.
/// `AnyParticipating` requests "1-of-N" routing if the backend supports it (e.g. GICv3 `IROUTER.IRM=1`).
///
/// Backends that cannot support a routing mode (notably GICv2 for true "1-of-N") must return
/// `Err(GicError::UnsupportedFeature)`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SpiRoute {
    /// Route to a specific PE identified by MPIDR-style affinity fields.
    Specific(CoreAffinity),
    /// "1-of-N" routing across participating PEs (if supported by the GIC).
    AnyParticipating,
}

/// Capability snapshot for a per-CPU GIC interface.
///
/// Returned by `GicCpuInterface::init()`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct GicCpuCaps {
    /// Number of implemented priority bits (PRIbits).
    ///
    /// Effective priority levels are `1 << priority_bits` (up to 256 levels).
    /// Backends may determine this by architectural discovery (v3) or safe write/readback probing (v2).
    pub priority_bits: u8,

    /// Whether this backend can toggle Group0 signaling for the current security regime.
    pub supports_group0: bool,
    /// Whether this backend can toggle Group1 signaling for the current security regime.
    pub supports_group1: bool,

    /// Number of implemented minimal binary point size
    ///
    /// The minimum binary point value is IMPLEMENTATION DEFINED
    pub binary_points_min: u8,

    /// Whether the backend can program binary points separately per group (e.g. v3 BPR0/BPR1,
    /// or v2 BPR/ABPR when applicable).
    pub supports_separate_binary_points: bool,

    /// Whether explicit deactivation is meaningful/required (split EOI/deactivate mode).
    pub supports_deactivate: bool,
}

/// EOI behavior selection.
///
/// Some configurations make EOI drop priority *and* deactivate; others require a separate
/// deactivate step to clear the Active state.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EoiMode {
    /// EOI drops priority and deactivates the interrupt (no explicit deactivate required).
    DropAndDeactivate,
    /// EOI drops priority only; caller must use `deactivate()` when appropriate.
    DropOnly,
}

/// Binary point configuration (preemption/subpriority split).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BinaryPoint {
    /// Use a single binary point value for all enabled groups.
    Common(u8),
    /// Program separate binary points per group (if supported).
    Separate { group0: u8, group1: u8 },
}

/// Caller-provided CPU interface configuration.
///
/// Typical flow:
/// 1) `let caps = cpu_if.init()?;`
/// 2) Build `GicCpuConfig` that matches policy and `caps`.
/// 3) `cpu_if.configure(&cfg)?;`
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct GicCpuConfig {
    /// Priority mask (PMR).
    pub priority_mask: u8,

    /// Group enables for the current security regime.
    pub enable_group0: bool,
    pub enable_group1: bool,

    /// Preemption/subpriority split (BPR).
    pub binary_point: BinaryPoint,

    /// EOI/deactivate policy.
    pub eoi_mode: EoiMode,
}

/// Per-CPU interrupt interface (ACK/EOI/PMR).
///
/// This trait represents the CPU-local interface used in the fast path:
/// - priority mask programming,
/// - interrupt acknowledge,
/// - end-of-interrupt (and optional explicit deactivation).
///
/// Implementations must handle required ordering internally:
/// - MMIO-based interfaces may require device ordering and explicit `dsb` sequences.
/// - system-register interfaces may require `isb` after control programming or before acknowledging.
pub trait GicCpuInterface {
    /// Initialize the CPU interface for the current PE and return capability information.
    ///
    /// This should put the interface into a *safe baseline* (typically with signaling disabled
    /// or masked) suitable for early boot, and then report what can be configured.
    ///
    /// Concrete configuration (PMR/BPR/group enables/EOI mode) should be applied via `configure()`.
    fn init(&self) -> Result<GicCpuCaps, GicError>;

    /// Apply caller-provided configuration (PMR/BPR/group enables/EOI mode).
    ///
    /// Backends must validate the request against `GicCpuCaps` and return `UnsupportedFeature`
    /// (or a more specific error) if it cannot be represented.
    fn configure(&self, cfg: &GicCpuConfig) -> Result<(), GicError>;

    /// Set the priority mask (PMR).
    ///
    /// Lower numeric priority values are typically higher priority, but the effective implemented
    /// priority width is version/implementation dependent.
    fn set_priority_mask(&self, pmr: u8) -> Result<(), GicError>;

    /// Acknowledge the highest-priority pending interrupt for this PE.
    ///
    /// Returns `Ok(None)` when no interrupt is available, including spurious IDs.
    /// Callers must treat `None` as "no work" and return from the handler without issuing EOI/DIR.
    fn acknowledge(&self) -> Result<Option<AckedIrq>, GicError>;

    /// Signal end-of-interrupt for an acknowledged interrupt.
    ///
    /// For backends that require it, this uses `ack.raw` (not only `ack.intid`) so that any
    /// embedded metadata (e.g. CPU ID / source bits) is preserved as required by the architecture.
    fn end_of_interrupt(&self, ack: AckedIrq) -> Result<(), GicError>;

    /// Deactivate an interrupt when priority drop and deactivation are split.
    ///
    /// Some configurations use an EOI mode where EOI only drops priority, and a separate "deactivate"
    /// operation is required to clear the active state (e.g. GICv2 `DIR` when configured).
    ///
    /// Implementations that do not require explicit deactivation must return `Ok(())` only if that
    /// is architecturally correct for their configuration (e.g. `EoiMode::DropAndDeactivate`).
    fn deactivate(&self, ack: AckedIrq) -> Result<(), GicError>;
}

/// Operation to apply to the interrupt enable state.
///
/// This is intentionally separated from the rest of the SPI attributes so callers can express
/// "configure-but-do-not-enable" without ambiguity.
///
/// Implementations are permitted to temporarily disable an interrupt while reprogramming its
/// attributes (priority/trigger/route) and then apply the requested final state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EnableOp {
    /// Do not change the enable state.
    Keep,
    /// Ensure the interrupt is enabled after configuration.
    Enable,
    /// Ensure the interrupt is disabled after configuration.
    Disable,
}

/// Global distributor configuration (primarily SPIs).
///
/// This trait models *global* interrupt source configuration that is shared across PEs
/// (in contrast to per-CPU interface operations like acknowledge/EOI).
///
/// # Concurrency
/// Callers must provide appropriate synchronization if the underlying hardware requires it.
/// In many systems, Distributor programming must be serialized across cores.
///
/// # INTID scope
/// This interface is intended for SPIs (Shared Peripheral Interrupts). Implementations must
/// reject unsupported `intid` values (e.g. SGIs/PPIs, spurious IDs, or out-of-range INTIDs)
/// with an error.
pub trait GicDistributor {
    /// Initialize Distributor state to a known baseline.
    ///
    /// Typical responsibilities include:
    /// - disabling forwarding while programming,
    /// - clearing enable/pending/active state for implemented interrupts,
    /// - setting default group/priority/route/trigger where appropriate,
    /// - re-enabling forwarding for the intended interrupt group(s).
    fn init(&self) -> Result<(), GicError>;

    /// Toggle forwarding of a single SPI only (no attribute changes).
    fn set_spi_enable(&self, intid: u32, enable: bool) -> Result<(), GicError>;

    /// Configure a single SPI in the Distributor.
    ///
    /// Implementations may temporarily disable the interrupt while reprogramming attributes.
    /// In particular, changing a programmable `Int_config` field without disabling the interrupt
    /// first is UNPREDICTABLE on GICv2. :contentReference[oaicite:2]{index=2}
    ///
    /// `enable` specifies the *final* enable state:
    /// - `Keep`    : restore the entry state (even if temporarily disabled internally).
    /// - `Enable`  : ensure enabled.
    /// - `Disable` : ensure disabled.
    fn configure_spi(
        &self,
        intid: u32,
        group: IrqGroup,
        priority: u8,
        trigger: TriggerMode,
        route: SpiRoute,
        enable: EnableOp,
    ) -> Result<(), GicError>;
    /// Set or clear the pending state of an interrupt in the Distributor.
    ///
    /// This is primarily intended for:
    /// - bring-up / self-tests (forcing a known SPI to become pending),
    /// - policy code that needs to explicitly clear stale pending state.
    ///
    /// Semantics:
    /// - `pending = true`  : request the interrupt to become pending (typically write-1-to-set).
    /// - `pending = false` : request the interrupt pending state to be cleared (typically write-1-to-clear).
    ///
    /// Notes:
    /// - This API targets SPIs; SGI/PPI pending state can be banked and/or have different rules.
    /// - Setting pending does not guarantee immediate delivery; forwarding, masking, and priority
    ///   rules still apply.
    fn set_pending(&self, intid: u32, pending: bool) -> Result<(), GicError>;
}

/// Target set for an SGI (Software Generated Interrupt).
///
/// Implementations may coalesce or re-encode targets as required by the hardware:
/// - GICv2 encodes targets as an 8-bit CPU target mask (max 8 PEs addressable directly).
/// - GICv3 encodes targets using affinity routing (and may require multiple writes for disjoint clusters).
pub enum SgiTarget<'a> {
    /// Send to the provided set of PEs (by affinity). Empty slice is a no-op.
    Specific(&'a [CoreAffinity]),
    /// Broadcast to all PEs except the current PE (where supported).
    AllButSelf,
    /// Send only to the current PE.
    SelfOnly,
}

/// SGI sender interface.
///
/// `sgi_id` must be in the architecturally defined SGI range (typically 0..16).
/// If a target affinity cannot be encoded by the backend, it must return `UnsupportedAffinity`.
pub trait GicSgi {
    fn send_sgi(&self, sgi_id: u8, target: SgiTarget<'_>) -> Result<(), GicError>;
}

/// Abstract interrupt lifecycle state used for vGIC list registers.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IrqState {
    Inactive,
    Pending,
    Active,
    PendingActive,
}

/// Version-independent virtual interrupt descriptor (vGIC).
///
/// Backends must translate this structure to the underlying list register format:
/// - GICv2 virtual list registers are 32-bit and have tighter ID/field constraints.
/// - GICv3 list registers are 64-bit and support wider ID spaces.
///
/// If the requested values cannot be encoded (e.g. ID too large for GICv2 LR), implementations
/// must return `InvalidVgicIrq`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct VirtualInterrupt {
    /// Virtual interrupt ID presented to the guest.
    pub vintid: u32,
    /// Optional physical interrupt ID for hardware-backed injection.
    pub pintid: Option<u32>,
    /// Virtual priority.
    pub priority: u8,
    /// Virtual interrupt group.
    pub group: IrqGroup,
    /// Virtual interrupt state.
    pub state: IrqState,
    /// Whether this entry represents a hardware-backed interrupt (backend-specific meaning).
    pub hw: bool,
}

/// Version-independent maintenance reasons encoded as a bitset.
///
/// Backends typically map these from:
/// - GICv2 `GICH_MISR` bits, and/or
/// - GICv3 `ICH_MISR_EL2` bits.
///
/// Multiple reasons can be reported simultaneously; callers should treat this as a snapshot.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MaintenanceReasons(pub u32);

impl MaintenanceReasons {
    /// No maintenance reason.
    pub const NONE: Self = Self(0);

    pub const UNDERFLOW: u32 = 1 << 0;
    pub const LR_ENTRY_NOT_PRESENT: u32 = 1 << 1;
    pub const NO_PENDING: u32 = 1 << 2;
    pub const EOI_COUNT_ZERO: u32 = 1 << 3;
    pub const VGRP0_DISABLED: u32 = 1 << 4;
    pub const VGRP1_DISABLED: u32 = 1 << 5;
    pub const VGRP0_ERROR: u32 = 1 << 6;
    pub const VGRP1_ERROR: u32 = 1 << 7;

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn contains(self, bit: u32) -> bool {
        (self.0 & bit) != 0
    }
}

/// vGIC interface (EL2-only).
///
/// This is intentionally separated from the OS-visible traits:
/// - OS code should only depend on `GicCpuInterface`/`GicDistributor`/`GicSgi`.
/// - hypervisor code can additionally depend on `GicVgic`.
///
/// Implementations must provide a `SavedState` that contains all state necessary for vCPU
/// context switching (e.g. list registers, control/VMCR state, and any priority state).
pub trait GicVgic {
    /// Backend-defined saved vGIC state used for vCPU context switching.
    ///
    /// Implementations should keep this as a compact, copy-friendly representation (often arrays
    /// of raw LR values plus a small set of control registers).
    type SavedState;

    /// Initialize virtualization support (enable vGIC interface, configure maintenance IRQ sources, etc.).
    fn vgic_init(&self) -> Result<(), GicError>;

    /// Number of implemented list registers (LRs) used for virtual interrupt injection.
    fn num_list_registers(&self) -> Result<usize, GicError>;

    /// Read a virtual list register entry and decode it into `VirtualInterrupt`.
    fn read_lr(&self, index: usize) -> Result<VirtualInterrupt, GicError>;

    /// Encode `VirtualInterrupt` into a list register entry and write it to the given LR index.
    fn write_lr(&self, index: usize, irq: VirtualInterrupt) -> Result<(), GicError>;

    /// Read and decode maintenance reasons (a snapshot bitset).
    ///
    /// Callers typically use this to drive refill of LRs or error handling on maintenance IRQ.
    fn maintenance_reasons(&self) -> Result<MaintenanceReasons, GicError>;

    /// Save backend-specific vGIC state for a vCPU switch-out.
    fn save_state(&self) -> Result<Self::SavedState, GicError>;

    /// Restore backend-specific vGIC state for a vCPU switch-in.
    fn restore_state(&self, state: &Self::SavedState) -> Result<(), GicError>;
}
