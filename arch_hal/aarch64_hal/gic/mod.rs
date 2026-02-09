use crate::GicError;
use crate::IrqGroup;
use crate::IrqSense;
use crate::IrqState;
use crate::PIntId;
use crate::TriggerMode;
use crate::VIntId;
use crate::VSpiRouting;
use crate::VcpuId;
use crate::VcpuMask;
use crate::VgicGuestRegs;
use crate::VgicIrqScope;
use crate::VgicPirqModel;
use crate::VgicSgiRegs;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::VgicVmInfo;
use crate::VgicWork;
use crate::VirtualInterrupt;
use crate::vm::vcpu::GicVCpuGeneric;
use core::mem::MaybeUninit;

pub(crate) const SGI_COUNT: usize = 16;
mod vcpu;

const LOCAL_INTID_COUNT: usize = 32;

#[derive(Copy, Clone)]
enum BoolField {
    Group,
    Enable,
    Pending,
    Active,
}

#[derive(Copy, Clone)]
pub(crate) struct PirqEntry {
    target: VcpuId,
    vintid: VIntId,
    sense: IrqSense,
    _group: IrqGroup,
    _priority: u8,
}

#[derive(Copy, Clone)]
struct IrqAttrs {
    pending: bool,
    active: bool,
    enable: bool,
    group: IrqGroup,
    priority: u8,
}

struct VcpuArray<const VCPUS: usize, V> {
    len: usize,
    buf: [MaybeUninit<V>; VCPUS],
}

impl<const VCPUS: usize, V: VgicVcpuModel> VcpuArray<VCPUS, V> {
    fn new_with(len: usize, mut make: impl FnMut(VcpuId) -> V) -> Result<Self, GicError> {
        if len > VCPUS {
            return Err(GicError::OutOfResources);
        }
        // SAFETY: `[MaybeUninit<V>; VCPUS]` is uninitialised storage. `len <= VCPUS` is checked
        // above, we write every slot in the initialised prefix exactly once, and `Drop` only
        // touches that prefix so the remaining elements stay uninitialised and never dropped.
        let mut buf: [MaybeUninit<V>; VCPUS] = unsafe { MaybeUninit::uninit().assume_init() };
        for i in 0..len {
            buf[i] = MaybeUninit::new(make(VcpuId(i as u16)));
        }
        Ok(Self { len, buf })
    }

    fn get(&self, idx: usize) -> Option<&V> {
        if idx >= self.len {
            return None;
        }
        // SAFETY: `idx < len` is enforced above so the slot is initialised; returning `&V`
        // maintains aliasing rules because we only hand out shared references here.
        Some(unsafe { self.buf[idx].assume_init_ref() })
    }
}

impl<const VCPUS: usize, V> Drop for VcpuArray<VCPUS, V> {
    fn drop(&mut self) {
        for i in 0..self.len {
            // SAFETY: `len` tracks the initialised prefix; each element in `[0, len)` was
            // written exactly once in `new_with` and is dropped exactly once here.
            unsafe { self.buf[i].assume_init_drop() };
        }
    }
}

/// Virtual Distributor model: per-vCPU private state for INTIDs 0-31 and shared SPI state for 32+.
pub struct GicVmModelGeneric<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel,
> {
    vcpu_count: usize,
    pub(crate) dist_enable: (bool, bool),
    vcpus: VcpuArray<VCPUS, V>,
    pub(crate) group_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    pub(crate) enable_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    pub(crate) pending_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    pub(crate) active_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    pub(crate) priority_local: [[u8; LOCAL_INTID_COUNT]; VCPUS],
    pub(crate) trigger_local: [[TriggerMode; LOCAL_INTID_COUNT]; VCPUS],
    pub(crate) group_global: [bool; GLOBAL_INTIDS],
    pub(crate) enable_global: [bool; GLOBAL_INTIDS],
    pub(crate) pending_global: [bool; GLOBAL_INTIDS],
    pub(crate) active_global: [bool; GLOBAL_INTIDS],
    pub(crate) priority_global: [u8; GLOBAL_INTIDS],
    pub(crate) trigger_global: [TriggerMode; GLOBAL_INTIDS],
    pub(crate) spi_route: [VSpiRouting; GLOBAL_INTIDS],
    pub(crate) sgi_sources: [[u32; 4]; VCPUS],
    pub(crate) pirqs: [Option<PirqEntry>; MAX_INTIDS],
}

pub type GicVmModelFor<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
> = GicVmModelGeneric<
    VCPUS,
    MAX_INTIDS,
    GLOBAL_INTIDS,
    MAX_LRS,
    PENDING_CAP,
    GicVCpuGeneric<VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>,
>;

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
>
    GicVmModelGeneric<
        VCPUS,
        MAX_INTIDS,
        GLOBAL_INTIDS,
        MAX_LRS,
        PENDING_CAP,
        GicVCpuGeneric<VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>,
    >
{
    /// Construct a VM with vCPU ids fixed to `VcpuId(0..vcpu_count-1)`; callers must not assume
    /// alternative vCPU id mappings when using this backend.
    pub fn new(vcpu_count: u16) -> Result<Self, GicError> {
        Self::new_with(vcpu_count, |id| GicVCpuGeneric::with_id(id))
    }
}

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel,
> GicVmModelGeneric<VCPUS, MAX_INTIDS, GLOBAL_INTIDS, MAX_LRS, PENDING_CAP, V>
{
    /// Construct a VM with vCPU ids fixed to `VcpuId(0..vcpu_count-1)`; custom mappings are not
    /// supported because CPUID fields and banked Distributor state rely on contiguous ids.
    pub fn new_with(vcpu_count: u16, make: impl FnMut(VcpuId) -> V) -> Result<Self, GicError> {
        let vcpu_count_usize = vcpu_count as usize;
        if vcpu_count_usize == 0 {
            return Err(GicError::InvalidVcpuId);
        }
        if vcpu_count_usize > VCPUS {
            return Err(GicError::OutOfResources);
        }
        let mut trigger_local = [[TriggerMode::Level; LOCAL_INTID_COUNT]; VCPUS];
        for t in trigger_local.iter_mut().take(vcpu_count_usize) {
            for intid in 0..16 {
                t[intid] = TriggerMode::Edge;
            }
        }
        Ok(Self {
            vcpu_count: vcpu_count_usize,
            dist_enable: (false, false),
            vcpus: VcpuArray::new_with(vcpu_count_usize, make)?,
            group_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            enable_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            pending_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            active_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            priority_local: [[0u8; LOCAL_INTID_COUNT]; VCPUS],
            trigger_local,
            group_global: [false; GLOBAL_INTIDS],
            enable_global: [false; GLOBAL_INTIDS],
            pending_global: [false; GLOBAL_INTIDS],
            active_global: [false; GLOBAL_INTIDS],
            priority_global: [0u8; GLOBAL_INTIDS],
            trigger_global: [TriggerMode::Level; GLOBAL_INTIDS],
            spi_route: [VSpiRouting::Targets(VcpuMask::from_bits(1)); GLOBAL_INTIDS],
            sgi_sources: [[0u32; 4]; VCPUS],
            pirqs: [None; MAX_INTIDS],
        })
    }

    #[inline]
    fn vcpu_index(&self, id: VcpuId) -> Result<usize, GicError> {
        if (id.0 as usize) < self.vcpu_count {
            Ok(id.0 as usize)
        } else {
            Err(GicError::InvalidVcpuId)
        }
    }

    #[inline]
    fn intid_in_range(intid: usize) -> bool {
        intid < MAX_INTIDS
    }

    fn select_bool_slices(&self, field: BoolField) -> (&[[bool; LOCAL_INTID_COUNT]], &[bool]) {
        match field {
            BoolField::Group => (&self.group_local[..self.vcpu_count], &self.group_global),
            BoolField::Enable => (&self.enable_local[..self.vcpu_count], &self.enable_global),
            BoolField::Pending => (&self.pending_local[..self.vcpu_count], &self.pending_global),
            BoolField::Active => (&self.active_local[..self.vcpu_count], &self.active_global),
        }
    }

    fn select_bool_local_mut(&mut self, field: BoolField) -> &mut [[bool; LOCAL_INTID_COUNT]] {
        match field {
            BoolField::Group => &mut self.group_local[..self.vcpu_count],
            BoolField::Enable => &mut self.enable_local[..self.vcpu_count],
            BoolField::Pending => &mut self.pending_local[..self.vcpu_count],
            BoolField::Active => &mut self.active_local[..self.vcpu_count],
        }
    }

    fn select_bool_global_mut(&mut self, field: BoolField) -> &mut [bool] {
        match field {
            BoolField::Group => &mut self.group_global,
            BoolField::Enable => &mut self.enable_global,
            BoolField::Pending => &mut self.pending_global,
            BoolField::Active => &mut self.active_global,
        }
    }

    fn update_for_scope(scope: VgicIrqScope, changed: bool) -> VgicUpdate {
        if !changed {
            return VgicUpdate::None;
        }
        let targets = match scope {
            VgicIrqScope::Local(vcpu) => VgicTargets::One(vcpu),
            VgicIrqScope::Global => VgicTargets::All,
        };
        VgicUpdate::Some {
            targets,
            work: VgicWork::REFILL,
        }
    }

    fn read_bool_word(
        &self,
        scope: VgicIrqScope,
        base: usize,
        field: BoolField,
    ) -> Result<u32, GicError> {
        let mut value = 0u32;
        let (local, global) = self.select_bool_slices(field);
        match scope {
            VgicIrqScope::Local(vcpu) => {
                let idx = self.vcpu_index(vcpu)?;
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    if local[idx][intid] {
                        value |= 1u32 << bit;
                    }
                }
            }
            VgicIrqScope::Global => {
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    if global[intid - LOCAL_INTID_COUNT] {
                        value |= 1u32 << bit;
                    }
                }
            }
        }
        Ok(value)
    }

    fn write_bool_word(
        &mut self,
        scope: VgicIrqScope,
        base: usize,
        bits: u32,
        field: BoolField,
    ) -> Result<bool, GicError> {
        let mut changed = false;
        match scope {
            VgicIrqScope::Local(vcpu) => {
                let idx = self.vcpu_index(vcpu)?;
                let local = self.select_bool_local_mut(field);
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let set = (bits & (1u32 << bit)) != 0;
                    if local[idx][intid] != set {
                        local[idx][intid] = set;
                        changed = true;
                    }
                }
            }
            VgicIrqScope::Global => {
                let global = self.select_bool_global_mut(field);
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let set = (bits & (1u32 << bit)) != 0;
                    let slot = &mut global[intid - LOCAL_INTID_COUNT];
                    if *slot != set {
                        *slot = set;
                        changed = true;
                    }
                }
            }
        }
        Ok(changed)
    }

    fn write_set_bool_word(
        &mut self,
        scope: VgicIrqScope,
        base: usize,
        bits: u32,
        field: BoolField,
    ) -> Result<bool, GicError> {
        Ok(self.write_set_bool_word_mask(scope, base, bits, field)? != 0)
    }

    fn write_clear_bool_word(
        &mut self,
        scope: VgicIrqScope,
        base: usize,
        bits: u32,
        field: BoolField,
    ) -> Result<bool, GicError> {
        Ok(self.write_clear_bool_word_mask(scope, base, bits, field)? != 0)
    }

    fn set_bool(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        val: bool,
        field: BoolField,
    ) -> Result<bool, GicError> {
        let intid = vintid.0 as usize;
        if !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        match scope {
            VgicIrqScope::Local(vcpu) => {
                if intid >= LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let idx = self.vcpu_index(vcpu)?;
                let local = self.select_bool_local_mut(field);
                let slot = &mut local[idx][intid];
                let changed = *slot != val;
                *slot = val;
                Ok(changed)
            }
            VgicIrqScope::Global => {
                if intid < LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let global = self.select_bool_global_mut(field);
                let slot = &mut global[intid - LOCAL_INTID_COUNT];
                let changed = *slot != val;
                *slot = val;
                Ok(changed)
            }
        }
    }

    fn write_set_bool_word_mask(
        &mut self,
        scope: VgicIrqScope,
        base: usize,
        bits: u32,
        field: BoolField,
    ) -> Result<u32, GicError> {
        let mut changed = 0u32;
        match scope {
            VgicIrqScope::Local(vcpu) => {
                let idx = self.vcpu_index(vcpu)?;
                let local = self.select_bool_local_mut(field);
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if (bits & (1u32 << bit)) == 0 {
                        continue;
                    }
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    if !local[idx][intid] {
                        local[idx][intid] = true;
                        changed |= 1u32 << bit;
                    }
                }
            }
            VgicIrqScope::Global => {
                let global = self.select_bool_global_mut(field);
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if (bits & (1u32 << bit)) == 0 {
                        continue;
                    }
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let slot = &mut global[intid - LOCAL_INTID_COUNT];
                    if !*slot {
                        *slot = true;
                        changed |= 1u32 << bit;
                    }
                }
            }
        }
        Ok(changed)
    }

    fn write_clear_bool_word_mask(
        &mut self,
        scope: VgicIrqScope,
        base: usize,
        bits: u32,
        field: BoolField,
    ) -> Result<u32, GicError> {
        let mut changed = 0u32;
        match scope {
            VgicIrqScope::Local(vcpu) => {
                let idx = self.vcpu_index(vcpu)?;
                let local = self.select_bool_local_mut(field);
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if (bits & (1u32 << bit)) == 0 {
                        continue;
                    }
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    if local[idx][intid] {
                        local[idx][intid] = false;
                        changed |= 1u32 << bit;
                    }
                }
            }
            VgicIrqScope::Global => {
                let global = self.select_bool_global_mut(field);
                for bit in 0..32 {
                    let intid = base + bit;
                    if !Self::intid_in_range(intid) {
                        break;
                    }
                    if (bits & (1u32 << bit)) == 0 {
                        continue;
                    }
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let slot = &mut global[intid - LOCAL_INTID_COUNT];
                    if *slot {
                        *slot = false;
                        changed |= 1u32 << bit;
                    }
                }
            }
        }
        Ok(changed)
    }

    fn dist_enabled(&self, group: IrqGroup) -> bool {
        match group {
            IrqGroup::Group0 => self.dist_enable.0,
            IrqGroup::Group1 => self.dist_enable.1,
        }
    }

    fn irq_attrs(&self, scope: VgicIrqScope, vintid: VIntId) -> Result<IrqAttrs, GicError> {
        let intid = vintid.0 as usize;
        if !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        match scope {
            VgicIrqScope::Local(vcpu) => {
                if intid >= LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let idx = self.vcpu_index(vcpu)?;
                Ok(IrqAttrs {
                    pending: self.pending_local[idx][intid],
                    active: self.active_local[idx][intid],
                    enable: self.enable_local[idx][intid],
                    group: if self.group_local[idx][intid] {
                        IrqGroup::Group1
                    } else {
                        IrqGroup::Group0
                    },
                    priority: self.priority_local[idx][intid],
                })
            }
            VgicIrqScope::Global => {
                if intid < LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let idx = intid - LOCAL_INTID_COUNT;
                Ok(IrqAttrs {
                    pending: self.pending_global[idx],
                    active: self.active_global[idx],
                    enable: self.enable_global[idx],
                    group: if self.group_global[idx] {
                        IrqGroup::Group1
                    } else {
                        IrqGroup::Group0
                    },
                    priority: self.priority_global[idx],
                })
            }
        }
    }

    fn targets_for_global_spi(&self, vintid: VIntId) -> Result<VcpuMask, GicError> {
        let intid = vintid.0 as usize;
        if intid < LOCAL_INTID_COUNT || !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        let idx = intid - LOCAL_INTID_COUNT;
        match self.spi_route[idx] {
            VSpiRouting::Targets(mask) => {
                // Drop bits beyond current vCPU count to keep injection deterministic.
                let mut out = VcpuMask::EMPTY;
                for id in mask.iter() {
                    if (id.0 as usize) < self.vcpu_count {
                        // SAFETY: id.0 < vcpu_count <= VCPUS is ensured.
                        let _ = out.set(id);
                    }
                }
                Ok(out)
            }
            VSpiRouting::Specific(_) | VSpiRouting::AnyParticipating => Err(GicError::UnsupportedFeature),
        }
    }

    fn read_priority_word_raw(&self, scope: VgicIrqScope, base: usize) -> Result<u32, GicError> {
        let mut bytes = [0u8; 4];
        for lane in 0..4 {
            let intid = base + lane;
            if !Self::intid_in_range(intid) {
                break;
            }
            bytes[lane] = match scope {
                VgicIrqScope::Local(vcpu) => {
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let idx = self.vcpu_index(vcpu)?;
                    self.priority_local[idx][intid]
                }
                VgicIrqScope::Global => {
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    self.priority_global[intid - LOCAL_INTID_COUNT]
                }
            };
        }
        Ok(u32::from_le_bytes(bytes))
    }

    fn write_priority_word_raw(
        &mut self,
        scope: VgicIrqScope,
        base: usize,
        value: u32,
    ) -> Result<bool, GicError> {
        let mut changed = false;
        for lane in 0..4 {
            let intid = base + lane;
            if !Self::intid_in_range(intid) {
                break;
            }
            let prio = ((value >> (lane * 8)) & 0xff) as u8;
            match scope {
                VgicIrqScope::Local(vcpu) => {
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let idx = self.vcpu_index(vcpu)?;
                    let slot = &mut self.priority_local[idx][intid];
                    if *slot != prio {
                        *slot = prio;
                        changed = true;
                    }
                }
                VgicIrqScope::Global => {
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let slot = &mut self.priority_global[intid - LOCAL_INTID_COUNT];
                    if *slot != prio {
                        *slot = prio;
                        changed = true;
                    }
                }
            }
        }
        Ok(changed)
    }
}

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel,
> VgicVmInfo for GicVmModelGeneric<VCPUS, MAX_INTIDS, GLOBAL_INTIDS, MAX_LRS, PENDING_CAP, V>
{
    type VcpuModel = V;

    fn vcpu_count(&self) -> u16 {
        self.vcpu_count as u16
    }

    fn vcpu(&self, id: VcpuId) -> Result<&Self::VcpuModel, GicError> {
        self.vcpus.get(id.0 as usize).ok_or(GicError::InvalidVcpuId)
    }
}

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel + VgicVcpuQueue,
> GicVmModelGeneric<VCPUS, MAX_INTIDS, GLOBAL_INTIDS, MAX_LRS, PENDING_CAP, V>
{
    fn build_sw_virq(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        source: Option<VcpuId>,
    ) -> Result<VirtualInterrupt, GicError> {
        let attrs = self.irq_attrs(scope, vintid)?;
        let state = if attrs.pending && attrs.active {
            IrqState::PendingActive
        } else if attrs.pending {
            IrqState::Pending
        } else if attrs.active {
            IrqState::Active
        } else {
            IrqState::Inactive
        };
        Ok(VirtualInterrupt::Software {
            vintid: vintid.0,
            eoi_maintenance: false,
            priority: attrs.priority,
            group: attrs.group,
            state,
            source,
        })
    }

    fn build_hw_virq(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        pintid: PIntId,
    ) -> Result<VirtualInterrupt, GicError> {
        let attrs = self.irq_attrs(scope, vintid)?;
        let state = if attrs.pending && attrs.active {
            IrqState::PendingActive
        } else if attrs.pending {
            IrqState::Pending
        } else if attrs.active {
            IrqState::Active
        } else {
            IrqState::Inactive
        };
        Ok(VirtualInterrupt::Hardware {
            vintid: vintid.0,
            pintid: pintid.0,
            priority: attrs.priority,
            group: attrs.group,
            state,
            source: None,
        })
    }

    fn enqueue_to_target(
        &self,
        target: VcpuId,
        virq: VirtualInterrupt,
    ) -> Result<VgicUpdate, GicError> {
        let work = self.vcpu(target)?.enqueue_irq(virq)?;
        Ok(VgicUpdate::Some {
            targets: VgicTargets::One(target),
            work,
        })
    }

    fn cancel_for_scope(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
        source: Option<VcpuId>,
    ) -> Result<VgicUpdate, GicError> {
        let mut update = VgicUpdate::None;
        match scope {
            VgicIrqScope::Local(vcpu) => {
                if vintid.0 < SGI_COUNT as u32 && source.is_none() {
                    let idx = self.vcpu_index(vcpu)?;
                    let sgi = vintid.0 as usize;
                    let word = sgi / 4;
                    let lane = sgi % 4;
                    let lane_mask = (self.sgi_sources[idx][word] >> (lane * 8)) & 0xff;
                    for sender in 0..self.vcpu_count {
                        if (lane_mask & (1 << sender)) == 0 {
                            continue;
                        }
                        self.vcpu(vcpu)?
                            .cancel_irq(vintid, Some(VcpuId(sender as u16)))?;
                    }
                }
                self.vcpu(vcpu)?.cancel_irq(vintid, source)?;
                update.combine(&VgicUpdate::Some {
                    targets: VgicTargets::One(vcpu),
                    work: VgicWork::REFILL,
                });
            }
            VgicIrqScope::Global => {
                let targets = self.targets_for_global_spi(vintid)?;
                for target in targets.iter() {
                    self.vcpu(target)?.cancel_irq(vintid, source)?;
                    update.combine(&VgicUpdate::Some {
                        targets: VgicTargets::One(target),
                        work: VgicWork::REFILL,
                    });
                }
            }
        }
        Ok(update)
    }

    fn maybe_enqueue_irq(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        source: Option<VcpuId>,
    ) -> Result<VgicUpdate, GicError> {
        let attrs = self.irq_attrs(scope, vintid)?;
        if !attrs.pending || !attrs.enable || !self.dist_enabled(attrs.group) {
            return Ok(VgicUpdate::None);
        }

        match scope {
            VgicIrqScope::Local(vcpu) => {
                let irq = self.build_sw_virq(scope, vintid, source)?;
                self.enqueue_to_target(vcpu, irq)
            }
            VgicIrqScope::Global => {
                let targets = self.targets_for_global_spi(vintid)?;
                if targets.is_empty() {
                    return Ok(VgicUpdate::None);
                }
                let mut update = VgicUpdate::None;
                let irq = self.build_sw_virq(scope, vintid, source)?;
                for target in targets.iter() {
                    update.combine(&self.enqueue_to_target(target, irq)?);
                }
                Ok(update)
            }
        }
    }

    fn enqueue_sgi_for_target(
        &mut self,
        target: VcpuId,
        sgi: usize,
    ) -> Result<VgicUpdate, GicError> {
        let idx = self.vcpu_index(target)?;
        let word = sgi / 4;
        let lane = sgi % 4;
        if word >= 4 || sgi >= SGI_COUNT {
            return Err(GicError::UnsupportedIntId);
        }
        let sources = (self.sgi_sources[idx][word] >> (lane * 8)) & 0xff;
        if sources == 0 {
            return self.maybe_enqueue_irq(VgicIrqScope::Local(target), VIntId(sgi as u32), None);
        }

        let mut update = VgicUpdate::None;
        for sender in 0..self.vcpu_count {
            if (sources & (1 << sender)) == 0 {
                continue;
            }
            if sender as usize >= self.vcpu_count {
                return Err(GicError::InvalidVcpuId);
            }
            update.combine(&self.maybe_enqueue_irq(
                VgicIrqScope::Local(target),
                VIntId(sgi as u32),
                Some(VcpuId(sender as u16)),
            )?);
        }
        Ok(update)
    }
}

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel + VgicVcpuQueue,
> VgicGuestRegs for GicVmModelGeneric<VCPUS, MAX_INTIDS, GLOBAL_INTIDS, MAX_LRS, PENDING_CAP, V>
{
    fn set_dist_enable(
        &mut self,
        enable_grp0: bool,
        enable_grp1: bool,
    ) -> Result<VgicUpdate, GicError> {
        let prev = self.dist_enable;
        let changed = prev != (enable_grp0, enable_grp1);
        self.dist_enable = (enable_grp0, enable_grp1);
        let mut update = VgicUpdate::None;

        if (!prev.0 && enable_grp0) || (!prev.1 && enable_grp1) {
            for vcpu_idx in 0..self.vcpu_count {
                let vcpu = VcpuId(vcpu_idx as u16);
                for intid in 0..LOCAL_INTID_COUNT {
                    if intid < SGI_COUNT {
                        continue;
                    }
                    let vintid = VIntId(intid as u32);
                    let attrs = self.irq_attrs(VgicIrqScope::Local(vcpu), vintid)?;
                    let group_enabled = match attrs.group {
                        IrqGroup::Group0 => enable_grp0,
                        IrqGroup::Group1 => enable_grp1,
                    };
                    if attrs.pending && attrs.enable && group_enabled {
                        update.combine(&self.maybe_enqueue_irq(
                            VgicIrqScope::Local(vcpu),
                            vintid,
                            None,
                        )?);
                    }
                }
                // Re-enqueue SGIs when the distributor enables their group.
                for sgi in 0..SGI_COUNT {
                    let attrs = self.irq_attrs(VgicIrqScope::Local(vcpu), VIntId(sgi as u32))?;
                    let group_enabled = match attrs.group {
                        IrqGroup::Group0 => enable_grp0,
                        IrqGroup::Group1 => enable_grp1,
                    };
                    if attrs.pending && attrs.enable && group_enabled {
                        update.combine(&self.enqueue_sgi_for_target(vcpu, sgi)?);
                    }
                }
            }

            for spi_idx in 0..GLOBAL_INTIDS {
                let vintid = VIntId((LOCAL_INTID_COUNT + spi_idx) as u32);
                let attrs = self.irq_attrs(VgicIrqScope::Global, vintid)?;
                let group_enabled = match attrs.group {
                    IrqGroup::Group0 => enable_grp0,
                    IrqGroup::Group1 => enable_grp1,
                };
                if attrs.pending && attrs.enable && group_enabled {
                    update.combine(&self.maybe_enqueue_irq(VgicIrqScope::Global, vintid, None)?);
                }
            }
        }

        update.combine(&Self::update_for_scope(VgicIrqScope::Global, changed));
        Ok(update)
    }

    fn dist_enable(&self) -> Result<(bool, bool), GicError> {
        Ok(self.dist_enable)
    }

    fn set_group(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        group: IrqGroup,
    ) -> Result<VgicUpdate, GicError> {
        let val = matches!(group, IrqGroup::Group1);
        let changed = self.set_bool(scope, vintid, val, BoolField::Group)?;
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_priority(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        let intid = vintid.0 as usize;
        if !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        let changed = match scope {
            VgicIrqScope::Local(vcpu) => {
                if intid >= LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let idx = self.vcpu_index(vcpu)?;
                let slot = &mut self.priority_local[idx][intid];
                let changed = *slot != priority;
                *slot = priority;
                changed
            }
            VgicIrqScope::Global => {
                if intid < LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let slot = &mut self.priority_global[intid - LOCAL_INTID_COUNT];
                let changed = *slot != priority;
                *slot = priority;
                changed
            }
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_trigger(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        trigger: TriggerMode,
    ) -> Result<VgicUpdate, GicError> {
        let intid = vintid.0 as usize;
        if !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        let changed = match scope {
            VgicIrqScope::Local(vcpu) => {
                if intid >= LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let idx = self.vcpu_index(vcpu)?;
                let slot = &mut self.trigger_local[idx][intid];
                let changed = *slot != trigger;
                *slot = trigger;
                changed
            }
            VgicIrqScope::Global => {
                if intid < LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                let slot = &mut self.trigger_global[intid - LOCAL_INTID_COUNT];
                let changed = *slot != trigger;
                *slot = trigger;
                changed
            }
        };
        Ok(Self::update_for_scope(scope, changed))
    }

    fn set_enable(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        enable: bool,
    ) -> Result<VgicUpdate, GicError> {
        let changed = self.set_bool(scope, vintid, enable, BoolField::Enable)?;
        let mut update = VgicUpdate::None;
        let intid = vintid.0 as usize;
        if enable {
            match scope {
                VgicIrqScope::Local(vcpu) if intid < SGI_COUNT => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, intid)?);
                }
                _ => {
                    let attrs = self.irq_attrs(scope, vintid)?;
                    if attrs.pending {
                        update.combine(&self.maybe_enqueue_irq(scope, vintid, None)?);
                    }
                }
            }
        } else {
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }
        update.combine(&Self::update_for_scope(scope, changed));
        Ok(update)
    }

    fn set_pending(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        pending: bool,
    ) -> Result<VgicUpdate, GicError> {
        let changed = self.set_bool(scope, vintid, pending, BoolField::Pending)?;
        let mut update = VgicUpdate::None;
        let intid = vintid.0 as usize;
        if pending {
            match scope {
                VgicIrqScope::Local(vcpu) if intid < SGI_COUNT => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, intid)?);
                }
                _ => update.combine(&self.maybe_enqueue_irq(scope, vintid, None)?),
            }
        } else {
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }
        update.combine(&Self::update_for_scope(scope, changed));
        Ok(update)
    }

    fn set_active(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        active: bool,
    ) -> Result<VgicUpdate, GicError> {
        let changed = self.set_bool(scope, vintid, active, BoolField::Active)?;
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_group_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Group)
    }

    fn write_group_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed = self.write_bool_word(scope, base.0 as usize, value, BoolField::Group)?;
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_enable_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Enable)
    }

    fn write_set_enable_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask =
            self.write_set_bool_word_mask(scope, base.0 as usize, set_bits, BoolField::Enable)?;
        let mut update = VgicUpdate::None;
        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            match scope {
                VgicIrqScope::Local(vcpu) if (base.0 + bit) < SGI_COUNT as u32 => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, (base.0 + bit) as usize)?);
                }
                _ => {
                    let attrs = self.irq_attrs(scope, vintid)?;
                    if attrs.pending {
                        update.combine(&self.maybe_enqueue_irq(scope, vintid, None)?);
                    }
                }
            }
        }
        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn write_clear_enable_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask =
            self.write_clear_bool_word_mask(scope, base.0 as usize, clear_bits, BoolField::Enable)?;
        let mut update = VgicUpdate::None;
        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }
        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn read_pending_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Pending)
    }

    fn write_set_pending_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask =
            self.write_set_bool_word_mask(scope, base.0 as usize, set_bits, BoolField::Pending)?;
        let mut update = VgicUpdate::None;
        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            match scope {
                VgicIrqScope::Local(vcpu) if (base.0 + bit) < SGI_COUNT as u32 => {
                    update.combine(&self.enqueue_sgi_for_target(vcpu, (base.0 + bit) as usize)?);
                }
                _ => update.combine(&self.maybe_enqueue_irq(scope, vintid, None)?),
            }
        }
        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn write_clear_pending_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mask = self.write_clear_bool_word_mask(
            scope,
            base.0 as usize,
            clear_bits,
            BoolField::Pending,
        )?;
        let mut update = VgicUpdate::None;
        for bit in 0..32 {
            if (mask & (1u32 << bit)) == 0 {
                continue;
            }
            let vintid = VIntId(base.0 + bit);
            update.combine(&self.cancel_for_scope(scope, vintid, None)?);
        }
        update.combine(&Self::update_for_scope(scope, mask != 0));
        Ok(update)
    }

    fn read_active_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Active)
    }

    fn write_set_active_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed =
            self.write_set_bool_word(scope, base.0 as usize, set_bits, BoolField::Active)?;
        Ok(Self::update_for_scope(scope, changed))
    }

    fn write_clear_active_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed =
            self.write_clear_bool_word(scope, base.0 as usize, clear_bits, BoolField::Active)?;
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_priority_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        self.read_priority_word_raw(scope, base.0 as usize)
    }

    fn write_priority_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError> {
        let changed = self.write_priority_word_raw(scope, base.0 as usize, value)?;
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_trigger_word(&self, scope: VgicIrqScope, base: VIntId) -> Result<u32, GicError> {
        let mut value = 0u32;
        for bit in 0..16 {
            let intid = base.0 as usize + bit;
            if !Self::intid_in_range(intid) {
                break;
            }
            let is_edge = match scope {
                VgicIrqScope::Local(vcpu) => {
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let idx = self.vcpu_index(vcpu)?;
                    self.trigger_local[idx][intid] == TriggerMode::Edge
                }
                VgicIrqScope::Global => {
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    self.trigger_global[intid - LOCAL_INTID_COUNT] == TriggerMode::Edge
                }
            };
            if is_edge {
                value |= 0b10 << (bit * 2);
            }
        }
        Ok(value)
    }

    fn write_trigger_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<VgicUpdate, GicError> {
        let mut changed = false;
        for bit in 0..16 {
            let intid = base.0 as usize + bit;
            if !Self::intid_in_range(intid) {
                break;
            }
            let field = (value >> (bit * 2)) & 0b11;
            let trigger = if field == 0b10 {
                TriggerMode::Edge
            } else {
                TriggerMode::Level
            };
            match scope {
                VgicIrqScope::Local(vcpu) => {
                    if intid >= LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let idx = self.vcpu_index(vcpu)?;
                    let slot = &mut self.trigger_local[idx][intid];
                    if *slot != trigger {
                        *slot = trigger;
                        changed = true;
                    }
                }
                VgicIrqScope::Global => {
                    if intid < LOCAL_INTID_COUNT {
                        return Err(GicError::UnsupportedIntId);
                    }
                    let slot = &mut self.trigger_global[intid - LOCAL_INTID_COUNT];
                    if *slot != trigger {
                        *slot = trigger;
                        changed = true;
                    }
                }
            }
        }
        Ok(Self::update_for_scope(scope, changed))
    }

    fn read_nsacr_word(&self, _scope: VgicIrqScope, _base: VIntId) -> Result<u32, GicError> {
        Ok(0)
    }

    fn write_nsacr_word(
        &mut self,
        _scope: VgicIrqScope,
        _base: VIntId,
        _value: u32,
    ) -> Result<VgicUpdate, GicError> {
        Ok(VgicUpdate::None)
    }

    fn set_spi_route(
        &mut self,
        vintid: VIntId,
        targets: VSpiRouting,
    ) -> Result<VgicUpdate, GicError> {
        let intid = vintid.0 as usize;
        if intid < LOCAL_INTID_COUNT || !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        let idx = intid - LOCAL_INTID_COUNT;
        match targets {
            VSpiRouting::Targets(mask) => {
                for id in mask.iter() {
                    if (id.0 as usize) >= self.vcpu_count {
                        return Err(GicError::InvalidVcpuId);
                    }
                }
                let entry = VSpiRouting::Targets(mask);
                let changed = self.spi_route[idx] != entry;
                self.spi_route[idx] = entry;
                Ok(Self::update_for_scope(VgicIrqScope::Global, changed))
            }
            VSpiRouting::Specific(_) | VSpiRouting::AnyParticipating => {
                Err(GicError::UnsupportedFeature)
            }
        }
    }

    fn get_spi_route(&self, vintid: VIntId) -> Result<VSpiRouting, GicError> {
        let intid = vintid.0 as usize;
        if intid < LOCAL_INTID_COUNT || !Self::intid_in_range(intid) {
            return Err(GicError::UnsupportedIntId);
        }
        Ok(self.spi_route[intid - LOCAL_INTID_COUNT])
    }
}

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel + VgicVcpuQueue,
> VgicSgiRegs for GicVmModelGeneric<VCPUS, MAX_INTIDS, GLOBAL_INTIDS, MAX_LRS, PENDING_CAP, V>
{
    fn read_sgi_pending_sources_word(&self, target: VcpuId, sgi: u8) -> Result<u32, GicError> {
        let idx = self.vcpu_index(target)?;
        let word = sgi as usize;
        if word >= 4 {
            return Err(GicError::UnsupportedIntId);
        }
        Ok(self.sgi_sources[idx][word])
    }

    fn write_set_sgi_pending_sources_word(
        &mut self,
        target: VcpuId,
        sgi: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError> {
        let idx = self.vcpu_index(target)?;
        let word = sgi as usize;
        if word >= 4 {
            return Err(GicError::UnsupportedIntId);
        }

        let mut update = VgicUpdate::None;
        let mut entry = self.sgi_sources[idx][word];
        let prev = entry;
        let new_bits = sources & !entry;

        for bit in 0..32 {
            if (new_bits & (1u32 << bit)) == 0 {
                continue;
            }
            let lane = bit / 8;
            let sender = bit % 8;
            if sender as usize >= self.vcpu_count || sender >= 8 {
                return Err(GicError::InvalidVcpuId);
            }
            if lane >= 4 {
                return Err(GicError::UnsupportedIntId);
            }
            let sgi_id = word * 4 + lane;
            if sgi_id >= SGI_COUNT {
                return Err(GicError::UnsupportedIntId);
            }
            self.pending_local[idx][sgi_id] = true;
            update.combine(&self.maybe_enqueue_irq(
                VgicIrqScope::Local(target),
                VIntId(sgi_id as u32),
                Some(VcpuId(sender as u16)),
            )?);
        }

        entry |= sources;
        for lane in 0..4 {
            let lane_mask = 0xff << (lane * 8);
            let sgi_id = word * 4 + lane;
            if sgi_id < SGI_COUNT {
                let has_pending = (entry & lane_mask) != 0;
                self.pending_local[idx][sgi_id] = has_pending;
                if !has_pending {
                    update.combine(&self.cancel_for_scope(
                        VgicIrqScope::Local(target),
                        VIntId(sgi_id as u32),
                        None,
                    )?);
                }
            }
        }

        let changed = entry != prev;
        self.sgi_sources[idx][word] = entry;
        update.combine(&Self::update_for_scope(
            VgicIrqScope::Local(target),
            changed,
        ));
        Ok(update)
    }

    fn write_clear_sgi_pending_sources_word(
        &mut self,
        target: VcpuId,
        sgi: u8,
        sources: u32,
    ) -> Result<VgicUpdate, GicError> {
        let idx = self.vcpu_index(target)?;
        let word = sgi as usize;
        if word >= 4 {
            return Err(GicError::UnsupportedIntId);
        }
        let mut entry = self.sgi_sources[idx][word];
        let prev = entry;
        let cleared_bits = prev & sources;

        let mut update = VgicUpdate::None;
        for bit in 0..32 {
            if (cleared_bits & (1u32 << bit)) == 0 {
                continue;
            }
            let lane = bit / 8;
            let sender = bit % 8;
            if sender as usize >= self.vcpu_count || sender >= 8 {
                return Err(GicError::InvalidVcpuId);
            }
            if lane >= 4 {
                return Err(GicError::UnsupportedIntId);
            }
            let sgi_id = word * 4 + lane;
            if sgi_id >= SGI_COUNT {
                return Err(GicError::UnsupportedIntId);
            }
            // cancel queued entry for this (intid, source) pair.
            // cancellation should not depend on current pending bit.
            // pending_local updated below based on remaining sources.
            self.vcpu(target)?
                .cancel_irq(VIntId(sgi_id as u32), Some(VcpuId(sender as u16)))?;
            update.combine(&VgicUpdate::Some {
                targets: VgicTargets::One(target),
                work: VgicWork::REFILL,
            });
        }

        entry &= !sources;
        for lane in 0..4 {
            let lane_mask = 0xff << (lane * 8);
            let sgi_id = word * 4 + lane;
            if sgi_id < SGI_COUNT {
                self.pending_local[idx][sgi_id] = (entry & lane_mask) != 0;
            }
        }

        let changed = entry != prev;
        self.sgi_sources[idx][word] = entry;
        update.combine(&Self::update_for_scope(
            VgicIrqScope::Local(target),
            changed,
        ));
        Ok(update)
    }
}

impl<
    const VCPUS: usize,
    const MAX_INTIDS: usize,
    const GLOBAL_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
    V: VgicVcpuModel + VgicVcpuQueue,
> VgicPirqModel for GicVmModelGeneric<VCPUS, MAX_INTIDS, GLOBAL_INTIDS, MAX_LRS, PENDING_CAP, V>
{
    fn map_pirq(
        &mut self,
        pintid: PIntId,
        target: VcpuId,
        vintid: VIntId,
        sense: IrqSense,
        group: IrqGroup,
        priority: u8,
    ) -> Result<VgicUpdate, GicError> {
        let pintid_idx = pintid.0 as usize;
        if pintid_idx >= MAX_INTIDS {
            return Err(GicError::UnsupportedIntId);
        }
        self.vcpu_index(target)?; // validate target
        let scope = if vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(target)
        } else {
            VgicIrqScope::Global
        };

        let mut update = VgicUpdate::None;
        update.combine(&self.set_group(scope, vintid, group)?);
        update.combine(&self.set_priority(scope, vintid, priority)?);
        update.combine(&self.set_trigger(
            scope,
            vintid,
            match sense {
                IrqSense::Edge => TriggerMode::Edge,
                IrqSense::Level => TriggerMode::Level,
            },
        )?);
        update.combine(&self.set_enable(scope, vintid, true)?);
        if matches!(scope, VgicIrqScope::Global) {
            let route_mask = 1u8 << (target.0 as u8 & 0x7);
            update.combine(&self.set_spi_route(vintid, VSpiRouting::Targets(route_mask))?);
        }

        self.pirqs[pintid_idx] = Some(PirqEntry {
            target,
            vintid,
            sense,
            _group: group,
            _priority: priority,
        });
        Ok(update)
    }

    fn unmap_pirq(&mut self, pintid: PIntId) -> Result<VgicUpdate, GicError> {
        let pintid_idx = pintid.0 as usize;
        if pintid_idx >= self.pirqs.len() {
            return Ok(VgicUpdate::None);
        }
        let Some(entry) = self.pirqs[pintid_idx].take() else {
            return Ok(VgicUpdate::None);
        };
        let scope = if entry.vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(entry.target)
        } else {
            VgicIrqScope::Global
        };
        self.set_enable(scope, entry.vintid, false)
    }

    fn on_physical_irq(&mut self, pintid: PIntId, level: bool) -> Result<VgicUpdate, GicError> {
        let pintid_idx = pintid.0 as usize;
        let Some(entry) = self.pirqs.get(pintid_idx).and_then(|e| e.as_ref()).copied() else {
            return Err(GicError::UnsupportedIntId);
        };
        let scope = if entry.vintid.0 < LOCAL_INTID_COUNT as u32 {
            VgicIrqScope::Local(entry.target)
        } else {
            VgicIrqScope::Global
        };
        let mut update = VgicUpdate::None;
        let set_pending = match entry.sense {
            IrqSense::Edge => level,
            IrqSense::Level => level,
        };
        if set_pending {
            let changed = self.set_bool(scope, entry.vintid, true, BoolField::Pending)?;
            let attrs = self.irq_attrs(scope, entry.vintid)?;
            if attrs.pending && attrs.enable && self.dist_enabled(attrs.group) {
                let irq = self.build_hw_virq(scope, entry.vintid, pintid)?;
                match scope {
                    VgicIrqScope::Local(target) => {
                        update.combine(&self.enqueue_to_target(target, irq)?);
                    }
                    VgicIrqScope::Global => {
                        let targets = self.targets_for_global_spi(entry.vintid)?;
                        for target in targets.iter() {
                            update.combine(&self.enqueue_to_target(target, irq)?);
                        }
                    }
                }
            }
            update.combine(&Self::update_for_scope(scope, changed));
        } else if matches!(entry.sense, IrqSense::Level) {
            let changed = self.set_bool(scope, entry.vintid, false, BoolField::Pending)?;
            update.combine(&self.cancel_for_scope(scope, entry.vintid, None)?);
            update.combine(&Self::update_for_scope(scope, changed));
        }
        Ok(update)
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;
    use core::cell::RefCell;

    const TEST_VCPUS: usize = 4;

    const fn pending_cap_for_vcpus(vcpus: usize) -> usize {
        crate::max_intids_for_vcpus(vcpus)
            .saturating_sub(SGI_COUNT)
            .saturating_add(SGI_COUNT.saturating_mul(vcpus))
    }

    const TEST_MAX_INTIDS: usize = crate::max_intids_for_vcpus(TEST_VCPUS);
    const TEST_GLOBAL_INTIDS: usize = TEST_MAX_INTIDS - LOCAL_INTID_COUNT;
    const TEST_MAX_LRS: usize = crate::VgicVmConfig::<TEST_VCPUS>::MAX_LRS;
    const TEST_PENDING_CAP: usize = pending_cap_for_vcpus(TEST_VCPUS);

    #[derive(Default)]
    struct RecordingVcpu {
        enqueued: RefCell<Vec<VirtualInterrupt>>,
        cancelled: RefCell<Vec<(VIntId, Option<VcpuId>)>>,
    }

    impl RecordingVcpu {
        fn new() -> Self {
            Self {
                enqueued: RefCell::new(Vec::new()),
                cancelled: RefCell::new(Vec::new()),
            }
        }
    }

    impl VgicVcpuModel for RecordingVcpu {
        fn refill_lrs<H: crate::VgicHw>(&self, _hw: &H) -> Result<bool, GicError> {
            Ok(false)
        }

        fn handle_maintenance_collect<H: crate::VgicHw>(
            &self,
            _hw: &H,
        ) -> Result<(VgicUpdate, crate::PirqNotifications), GicError> {
            Ok((VgicUpdate::None, crate::PirqNotifications::new()))
        }

        fn switch_out_sync<H: crate::VgicHw>(&self, _hw: &H) -> Result<(), GicError> {
            Ok(())
        }
    }

    impl VgicVcpuQueue for RecordingVcpu {
        fn enqueue_irq(&self, irq: VirtualInterrupt) -> Result<VgicWork, GicError> {
            self.enqueued.borrow_mut().push(irq);
            Ok(VgicWork::REFILL)
        }

        fn cancel_irq(&self, vintid: VIntId, source: Option<VcpuId>) -> Result<(), GicError> {
            self.cancelled.borrow_mut().push((vintid, source));
            Ok(())
        }
    }

    type RecordingVm = GicVmModelGeneric<
        TEST_VCPUS,
        TEST_MAX_INTIDS,
        TEST_GLOBAL_INTIDS,
        TEST_MAX_LRS,
        TEST_PENDING_CAP,
        RecordingVcpu,
    >;

    fn recording_vm(vcpu_count: u16) -> RecordingVm {
        RecordingVm::new_with(vcpu_count, |id| RecordingVcpu::new(id)).unwrap()
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn vm_model_rejects_invalid_vcpu_counts() {
        assert!(matches!(
            RecordingVm::new_with(0, |id| RecordingVcpu::new(id)),
            Err(GicError::InvalidVcpuId)
        ));
        assert!(matches!(
            RecordingVm::new_with((TEST_VCPUS as u16) + 1, |id| RecordingVcpu::new(id)),
            Err(GicError::OutOfResources)
        ));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pending_and_enabled_irq_is_enqueued() {
        let mut vm = recording_vm(1);
        vm.set_dist_enable(true, true).unwrap();
        vm.set_enable(VgicIrqScope::Local(VcpuId(0)), VIntId(5), true)
            .unwrap();
        let update = vm
            .set_pending(VgicIrqScope::Local(VcpuId(0)), VIntId(5), true)
            .unwrap();
        let vcpu = vm.vcpu(VcpuId(0)).unwrap();
        let enqueued = vcpu.enqueued.borrow();
        assert_eq!(enqueued.len(), 1);
        match enqueued[0] {
            VirtualInterrupt::Software { vintid, state, .. } => {
                assert_eq!(vintid, 5);
                assert_eq!(state, IrqState::Pending);
            }
            _ => panic!("expected software pending virq"),
        }
        assert!(matches!(
            update,
            VgicUpdate::Some {
                targets: VgicTargets::One(VcpuId(0)),
                work
            } if work.refill
        ));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pending_queued_after_enable() {
        let mut vm = recording_vm(1);
        vm.set_dist_enable(true, true).unwrap();
        vm.set_pending(VgicIrqScope::Local(VcpuId(0)), VIntId(7), true)
            .unwrap();
        let vcpu = vm.vcpu(VcpuId(0)).unwrap();
        assert!(vcpu.enqueued.borrow().is_empty());
        vm.set_enable(VgicIrqScope::Local(VcpuId(0)), VIntId(7), true)
            .unwrap();
        assert_eq!(vcpu.enqueued.borrow().len(), 1);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn sgi_sources_enqueue_with_sender() {
        let mut vm = recording_vm(2);
        vm.set_dist_enable(true, true).unwrap();
        vm.set_enable(VgicIrqScope::Local(VcpuId(1)), VIntId(0), true)
            .unwrap();
        vm.write_set_sgi_pending_sources_word(VcpuId(1), 0, 1)
            .unwrap();
        let vcpu = vm.vcpu(VcpuId(1)).unwrap();
        let enqueued = vcpu.enqueued.borrow();
        assert_eq!(enqueued.len(), 1);
        match enqueued[0] {
            VirtualInterrupt::Software { vintid, source, .. } => {
                assert_eq!(vintid, 0);
                assert_eq!(source, Some(VcpuId(0)));
            }
            _ => panic!("expected software SGI"),
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn hardware_irq_enqueues_hw_entry() {
        let mut vm = recording_vm(1);
        vm.set_dist_enable(true, true).unwrap();
        vm.map_pirq(
            PIntId(48),
            VcpuId(0),
            VIntId(40),
            IrqSense::Level,
            IrqGroup::Group1,
            0x20,
        )
        .unwrap();
        vm.on_physical_irq(PIntId(48), true).unwrap();
        let vcpu = vm.vcpu(VcpuId(0)).unwrap();
        let enqueued = vcpu.enqueued.borrow();
        assert_eq!(enqueued.len(), 1);
        match enqueued[0] {
            VirtualInterrupt::Hardware { pintid, .. } => {
                assert_eq!(pintid, 48);
            }
            _ => panic!("expected hardware virq"),
        }
    }
}
