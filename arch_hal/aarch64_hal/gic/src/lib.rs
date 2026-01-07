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

extern crate alloc;

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
    /// The provided VCPU identifier is invalid.
    InvalidVcpuId,
    /// The provided LR index is invalid.
    InvalidLrIndex,
    /// The access size is invalid for the requested operation.
    InvalidAccessSize,
    /// The provided offset is invalid for the requested operation.
    InvalidOffset,
    /// Attempted write to a read-only register.
    ReadOnlyRegister,
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
/// Returned by `GicCpuInterface::init_cpu_interface()`.
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
/// 1) `let caps = cpu_if.init_cpu_interface()?;`
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
    fn init_cpu_interface(&self) -> Result<GicCpuCaps, GicError>;

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
    fn init_distributor(&self) -> Result<(), GicError>;

    /// Toggle forwarding of a single SPI only (no attribute changes).
    fn set_spi_enable(&self, intid: u32, enable: bool) -> Result<(), GicError>;

    /// Configure a single SPI in the Distributor.
    ///
    /// Implementations may temporarily disable the interrupt while reprogramming attributes.
    /// In particular, changing a programmable `Int_config` field without disabling the interrupt
    /// first is UNPREDICTABLE on GICv2.
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
    /// Whether guest deactivation should raise an EOI maintenance interrupt (HW=0 only).
    pub eoi_maintenance: bool,
    /// Virtual priority.
    pub priority: u8,
    /// Virtual interrupt group.
    pub group: IrqGroup,
    /// Virtual interrupt state.
    pub state: IrqState,
    /// Whether this entry represents a hardware-backed interrupt (backend-specific meaning).
    pub hw: bool,
    pub source: Option<VcpuId>,
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
    pub const NONE: Self = Self(0);

    // Bits match GICv2 GICH_MISR and GICv3 ICH_MISR_EL2.
    pub const EOI: u32 = 1 << 0;
    pub const UNDERFLOW: u32 = 1 << 1;
    pub const LR_ENTRY_NOT_PRESENT: u32 = 1 << 2; // LRENP
    pub const NO_PENDING: u32 = 1 << 3; // NP
    pub const VGRP0_ENABLED: u32 = 1 << 4; // VGrp0E
    pub const VGRP0_DISABLED: u32 = 1 << 5; // VGrp0D
    pub const VGRP1_ENABLED: u32 = 1 << 6; // VGrp1E
    pub const VGRP1_DISABLED: u32 = 1 << 7; // VGrp1D

    pub const SUPPORTED: u32 = Self::EOI
        | Self::UNDERFLOW
        | Self::LR_ENTRY_NOT_PRESENT
        | Self::NO_PENDING
        | Self::VGRP0_ENABLED
        | Self::VGRP0_DISABLED
        | Self::VGRP1_ENABLED
        | Self::VGRP1_DISABLED;

    #[inline]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn contains(self, bits: u32) -> bool {
        (self.0 & bits) == bits
    }
}

/// Work requested by vGIC software model after a state update.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VgicWork {
    /// Caller should attempt to refill LRs for affected vCPU(s) when possible.
    pub refill: bool,
    /// Caller should request a "kick" (IPI/resched) for affected vCPU(s) that may be running.
    pub kick: bool,
}

impl VgicWork {
    pub const NONE: Self = Self {
        refill: false,
        kick: false,
    };
    pub const REFILL: Self = Self {
        refill: true,
        kick: false,
    };
    pub const REFILL_KICK: Self = Self {
        refill: true,
        kick: true,
    };
}

/// Guest-visible CPU identity within a VM.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VcpuId(pub u16);

/// Physical interrupt identifier on the host GIC.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PIntId(pub u32);

/// Virtual interrupt identifier as seen by the guest.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VIntId(pub u32);

/// Edge/level semantics for injection bookkeeping (esp. mapped pIRQs).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IrqSense {
    Edge,
    Level,
}

/// Host-side vGIC HW backend (GICv2: GICH_* / GICv3: ICH_*).
///
/// This is *per-PE* hardware state and must be context-switched per vCPU.
pub trait VgicHw {
    /// Backend-defined saved state for a vCPU (LRs + VMCR/APR/etc).
    type SavedState;

    /// Enable/initialize the HW virtualization interface on this PE (EL2).
    fn hw_init(&self) -> Result<(), GicError>;

    /// Enable or disable the virtualization interface for the current vCPU context.
    fn set_enabled(&self, enabled: bool) -> Result<(), GicError>;

    /// Toggle Underflow maintenance interrupt (UIE).
    fn set_underflow_irq(&self, enable: bool) -> Result<(), GicError>;

    /// Implemented LR count on this PE.
    fn num_lrs(&self) -> Result<usize, GicError>;

    /// Bitmap of empty LRs (bit i == 1 => LR[i] is empty).
    fn empty_lr_bitmap(&self) -> Result<u64, GicError>;

    /// Bitmap of LRs that caused an EOI maintenance event (bit i == 1).
    fn eoi_lr_bitmap(&self) -> Result<u64, GicError>;

    /// Read/Write an LR decoded as a version-independent descriptor.
    fn read_lr(&self, index: usize) -> Result<VirtualInterrupt, GicError>;
    fn write_lr(&self, index: usize, irq: VirtualInterrupt) -> Result<(), GicError>;

    /// Read and clear EOICount (LRENP accounting).
    fn take_eoi_count(&self) -> Result<u8, GicError>;

    /// Accessor for APR (active priority register).
    fn read_apr(&self) -> Result<u32, GicError>;
    fn write_apr(&self, value: u32) -> Result<(), GicError>;

    /// Snapshot maintenance reasons (MISR / ICH_MISR_EL2).
    fn maintenance_reasons(&self) -> Result<MaintenanceReasons, GicError>;

    /// Save/restore HW state for vCPU context switching on this PE.
    fn save_state(&self) -> Result<Self::SavedState, GicError>;
    fn restore_state(&self, state: &Self::SavedState) -> Result<(), GicError>;
}

/// Dense vCPU bitmask: bit i => vCPU i.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VcpuMask(pub u16);

impl VcpuMask {
    pub const EMPTY: Self = Self(0);
    pub const fn contains(self, id: VcpuId) -> bool {
        (self.0 & (1u16 << id.0)) != 0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Where an IRQ's state lives (GICv2 banked vs GICv3 redistributor).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VgicIrqScope {
    /// Per-vCPU local IRQ state (SGI/PPI).
    Local(VcpuId),
    /// VM-global IRQ state (SPI).
    Global,
}

/// More precise targeting for update aggregation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VgicTargets {
    One(VcpuId),
    Mask(VcpuMask),
    All,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VgicUpdate {
    None,
    Some {
        targets: VgicTargets,
        work: VgicWork,
    },
}
impl VgicUpdate {
    fn combine(&mut self, other: &VgicUpdate) {
        *self = match (*self, *other) {
            (VgicUpdate::None, u) | (u, VgicUpdate::None) => u,

            (
                VgicUpdate::Some {
                    targets: t1,
                    work: w1,
                },
                VgicUpdate::Some {
                    targets: t2,
                    work: w2,
                },
            ) => {
                let combined_targets = match (t1, t2) {
                    (VgicTargets::All, _) | (_, VgicTargets::All) => VgicTargets::All,

                    (VgicTargets::Mask(m1), VgicTargets::Mask(m2)) => {
                        VgicTargets::Mask(VcpuMask(m1.0 | m2.0))
                    }

                    (VgicTargets::Mask(m), VgicTargets::One(id))
                    | (VgicTargets::One(id), VgicTargets::Mask(m)) => {
                        VgicTargets::Mask(VcpuMask(m.0 | (1u16 << id.0)))
                    }

                    (VgicTargets::One(id1), VgicTargets::One(id2)) if id1 == id2 => {
                        VgicTargets::One(id1)
                    }

                    (VgicTargets::One(id1), VgicTargets::One(id2)) => {
                        VgicTargets::Mask(VcpuMask((1 << id1.0) | (1 << id2.0)))
                    }
                };

                let combined_work = VgicWork {
                    refill: w1.refill || w2.refill,
                    kick: w1.kick || w2.kick,
                };

                VgicUpdate::Some {
                    targets: combined_targets,
                    work: combined_work,
                }
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VSpiRouting {
    Targets(u8),
    Specific(CoreAffinity),
    AnyParticipating,
}

/// VM identity helpers shared by vGIC traits.
pub trait VgicVmInfo {
    type VcpuModel: VgicVcpuModel;

    fn vcpu_count(&self) -> u16;
    fn vcpu(&self, id: VcpuId) -> Result<&Self::VcpuModel, GicError>;
}

/// Guest-visible virtual register file (Distributor/Redistributor) backed by a VM model.
pub trait VgicGuestRegs: VgicVmInfo {
    fn set_dist_enable(
        &mut self,
        enable_grp0: bool,
        enable_grp1: bool,
    ) -> Result<VgicUpdate, GicError>;
    fn dist_enable(&self) -> Result<(bool, bool), GicError>;

    fn set_group(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        group: IrqGroup,
    ) -> Result<VgicUpdate, GicError>;
    fn set_priority(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        priority: u8,
    ) -> Result<VgicUpdate, GicError>;
    fn set_trigger(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        trigger: TriggerMode,
    ) -> Result<VgicUpdate, GicError>;
    fn set_enable(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        enable: bool,
    ) -> Result<VgicUpdate, GicError>;
    fn set_pending(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        pending: bool,
    ) -> Result<VgicUpdate, GicError>;
    fn set_active(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        active: bool,
    ) -> Result<VgicUpdate, GicError>;

    fn read_group_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_group_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError>;

    fn read_enable_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_set_enable_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError>;
    fn write_clear_enable_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError>;

    fn read_pending_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_set_pending_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError>;
    fn write_clear_pending_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError>;

    fn read_active_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_set_active_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError>;
    fn write_clear_active_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError>;

    fn read_priority_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_priority_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError>;
    fn read_trigger_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_trigger_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError>;
    fn read_nsacr_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError>;
    fn write_nsacr_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError>;

    fn set_spi_route(
        &mut self,
        vintid: VIntId,
        targets: VSpiRouting,
    ) -> Result<VgicUpdate, GicError>;
    fn get_spi_route(&self, vintid: VIntId) -> Result<VSpiRouting, GicError>;
}

/// SGI pending source register helpers (CPENDSGIR/SPENDSGIR/SGIR).
pub trait VgicSgiRegs: VgicVmInfo {
    fn read_sgi_pending_sources_word(&self, target: VcpuId, sgi: u8) -> Result<u32, GicError>;
    fn write_set_sgi_pending_sources_word(
        &mut self,
        target: VcpuId,
        sgi: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError>;
    fn write_clear_sgi_pending_sources_word(
        &mut self,
        target: VcpuId,
        sgi: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError>;

    fn write_set_sgi_pending_sources(
        &mut self,
        target: VcpuId,
        sgi: u8,
        sources: VcpuMask,
    ) -> Result<VgicUpdate, GicError> {
        self.write_set_sgi_pending_sources_word(target, sgi, sources.0 as u32)
    }

    fn write_clear_sgi_pending_sources(
        &mut self,
        target: VcpuId,
        sgi: u8,
        sources: VcpuMask,
    ) -> Result<VgicUpdate, GicError> {
        self.write_clear_sgi_pending_sources_word(target, sgi, sources.0 as u32)
    }

    fn inject_sgi(
        &mut self,
        sender: VcpuId,
        targets: VcpuMask,
        sgi: u8,
    ) -> Result<VgicUpdate, GicError> {
        if sender.0 >= 16 {
            return Err(GicError::InvalidVcpuId);
        }
        if targets.is_empty() {
            return Ok(VgicUpdate::None);
        }

        let mut update = VgicUpdate::None;
        for bit in 0..16 {
            if (targets.0 & (1 << bit)) == 0 {
                continue;
            }
            let target = VcpuId(bit);
            let res = self.write_set_sgi_pending_sources_word(target, sgi, 1u32 << sender.0)?;
            update.combine(&res);
        }
        Ok(update)
    }
}

/// Host-side physical IRQ mapping and ingress hooks.
pub trait VgicPirqModel: VgicVmInfo {
    fn map_pirq(
        &mut self,
        pintid: PIntId,
        target: VcpuId,
        vintid: VIntId,
        sense: IrqSense,
        group: IrqGroup,
        priority: u8,
    ) -> Result<VgicUpdate, GicError>;
    fn unmap_pirq(&mut self, pintid: PIntId) -> Result<VgicUpdate, GicError>;
    fn on_physical_irq(&mut self, pintid: PIntId, level: bool) -> Result<VgicUpdate, GicError>;
}

/// VM logical state model marker (version-independent core).
///
/// Implementers should provide:
/// - `VgicGuestRegs` for guest-visible register emulation (groups/enables/pending/priority/routing).
/// - `VgicSgiRegs` for SGI pending-source helpers and SGIR injection.
/// - `VgicPirqModel` for host-side pIRQ mapping and physical interrupt ingress.
pub trait VgicVmModel: VgicGuestRegs + VgicSgiRegs + VgicPirqModel {}

impl<T> VgicVmModel for T where T: VgicGuestRegs + VgicSgiRegs + VgicPirqModel {}

/// Per-vCPU model API: LR refill policy + kick decision.
///
/// This API never touches guest-facing MMIO/sysregs directly.
/// It only decides "what to put into HW LRs" and "whether we must kick a running vCPU".
pub trait VgicVcpuModel {
    /// Refill HW LRs from the software model for this vCPU.
    ///
    /// Returns `true` if the caller should request a "kick" (IPI) because the vCPU
    /// is currently running elsewhere and needs to exit to EL2 for refill.
    fn refill_lrs<H: VgicHw>(&self, hw: &H) -> Result<bool, GicError>;

    /// Handle a maintenance interrupt for this vCPU on this PE.
    ///
    /// Typical actions:
    /// - Read MISR reasons
    /// - Drain completed EOIs / update software state
    /// - Refill LRs on UNDERFLOW
    fn handle_maintenance<H: VgicHw>(
        &self,
        hw: &H,
        on_pirq_eoi: &mut impl FnMut(PIntId),
        on_pirq_deactivate: &mut impl FnMut(PIntId),
        on_pirq_resample: &mut impl FnMut(PIntId),
    ) -> Result<VgicUpdate, GicError>;

    /// Switch in this vCPU's HW state on this PE.
    fn switch_out_sync<H: VgicHw>(&self, hw: &H) -> Result<(), GicError>;
}
