use crate::GicError;
use crate::IrqGroup;
use crate::TriggerMode;
use crate::VIntId;
use crate::VcpuId;
use crate::VgicIrqScope;

pub(crate) const SGI_COUNT: usize = 16;
pub(crate) const LOCAL_INTID_COUNT: usize = 32;

#[derive(Copy, Clone)]
pub(crate) struct IrqAttrs {
    pub(crate) pending: bool,
    pub(crate) active: bool,
    pub(crate) enable: bool,
    pub(crate) group: IrqGroup,
    pub(crate) priority: u8,
}

#[derive(Copy, Clone)]
enum BoolField {
    Group,
    Enable,
    Pending,
    Active,
}

pub(crate) struct IrqState<const VCPUS: usize>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
{
    vcpu_count: usize,
    group_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    enable_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    pending_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    active_local: [[bool; LOCAL_INTID_COUNT]; VCPUS],
    priority_local: [[u8; LOCAL_INTID_COUNT]; VCPUS],
    trigger_local: [[TriggerMode; LOCAL_INTID_COUNT]; VCPUS],

    group_global: [bool; crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT],
    enable_global: [bool; crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT],
    pending_global: [bool; crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT],
    active_global: [bool; crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT],
    priority_global: [u8; crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT],
    trigger_global: [TriggerMode; crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT],
}

impl<const VCPUS: usize> IrqState<VCPUS>
where
    [(); crate::max_intids_for_vcpus(VCPUS)]:,
    [(); crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT]:,
{
    pub(crate) fn new(vcpu_count: usize) -> Self {
        let mut trigger_local = [[TriggerMode::Level; LOCAL_INTID_COUNT]; VCPUS];
        for t in trigger_local.iter_mut().take(vcpu_count) {
            for intid in 0..SGI_COUNT {
                t[intid] = TriggerMode::Edge;
            }
        }

        Self {
            vcpu_count,
            group_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            enable_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            pending_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            active_local: [[false; LOCAL_INTID_COUNT]; VCPUS],
            priority_local: [[0u8; LOCAL_INTID_COUNT]; VCPUS],
            trigger_local,

            group_global: [false; { crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT }],
            enable_global: [false; { crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT }],
            pending_global: [false; { crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT }],
            active_global: [false; { crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT }],
            priority_global: [0u8; { crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT }],
            trigger_global: [TriggerMode::Level; {
                crate::max_intids_for_vcpus(VCPUS) - LOCAL_INTID_COUNT
            }],
        }
    }

    pub(crate) fn vcpu_count(&self) -> usize {
        self.vcpu_count
    }

    pub(crate) fn vcpu_index(&self, id: VcpuId) -> Result<usize, GicError> {
        if (id.0 as usize) < self.vcpu_count {
            Ok(id.0 as usize)
        } else {
            Err(GicError::InvalidVcpuId)
        }
    }

    pub(crate) fn intid_in_range(intid: usize) -> bool {
        intid < crate::max_intids_for_vcpus(VCPUS)
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

    pub(crate) fn irq_attrs(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
    ) -> Result<IrqAttrs, GicError> {
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

    pub(crate) fn trigger(
        &self,
        scope: VgicIrqScope,
        vintid: VIntId,
    ) -> Result<TriggerMode, GicError> {
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
                Ok(self.trigger_local[idx][intid])
            }
            VgicIrqScope::Global => {
                if intid < LOCAL_INTID_COUNT {
                    return Err(GicError::UnsupportedIntId);
                }
                Ok(self.trigger_global[intid - LOCAL_INTID_COUNT])
            }
        }
    }

    pub(crate) fn set_group(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        group: IrqGroup,
    ) -> Result<bool, GicError> {
        let val = matches!(group, IrqGroup::Group1);
        self.set_bool(scope, vintid, val, BoolField::Group)
    }

    pub(crate) fn set_enable(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        enable: bool,
    ) -> Result<bool, GicError> {
        self.set_bool(scope, vintid, enable, BoolField::Enable)
    }

    pub(crate) fn set_pending(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        pending: bool,
    ) -> Result<bool, GicError> {
        self.set_bool(scope, vintid, pending, BoolField::Pending)
    }

    pub(crate) fn set_active(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        active: bool,
    ) -> Result<bool, GicError> {
        self.set_bool(scope, vintid, active, BoolField::Active)
    }

    pub(crate) fn set_priority(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        priority: u8,
    ) -> Result<bool, GicError> {
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
        Ok(changed)
    }

    pub(crate) fn set_trigger(
        &mut self,
        scope: VgicIrqScope,
        vintid: VIntId,
        trigger: TriggerMode,
    ) -> Result<bool, GicError> {
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
        Ok(changed)
    }

    pub(crate) fn read_group_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
    ) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Group)
    }

    pub(crate) fn write_group_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<bool, GicError> {
        self.write_bool_word(scope, base.0 as usize, value, BoolField::Group)
    }

    pub(crate) fn read_enable_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
    ) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Enable)
    }

    pub(crate) fn write_set_enable_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<u32, GicError> {
        self.write_set_bool_word_mask(scope, base.0 as usize, set_bits, BoolField::Enable)
    }

    pub(crate) fn write_clear_enable_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<u32, GicError> {
        self.write_clear_bool_word_mask(scope, base.0 as usize, clear_bits, BoolField::Enable)
    }

    pub(crate) fn read_pending_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
    ) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Pending)
    }

    pub(crate) fn write_set_pending_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<u32, GicError> {
        self.write_set_bool_word_mask(scope, base.0 as usize, set_bits, BoolField::Pending)
    }

    pub(crate) fn write_clear_pending_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<u32, GicError> {
        self.write_clear_bool_word_mask(scope, base.0 as usize, clear_bits, BoolField::Pending)
    }

    pub(crate) fn read_active_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
    ) -> Result<u32, GicError> {
        self.read_bool_word(scope, base.0 as usize, BoolField::Active)
    }

    pub(crate) fn write_set_active_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        set_bits: u32,
    ) -> Result<u32, GicError> {
        self.write_set_bool_word_mask(scope, base.0 as usize, set_bits, BoolField::Active)
    }

    pub(crate) fn write_clear_active_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        clear_bits: u32,
    ) -> Result<u32, GicError> {
        self.write_clear_bool_word_mask(scope, base.0 as usize, clear_bits, BoolField::Active)
    }

    pub(crate) fn read_priority_word_raw(
        &self,
        scope: VgicIrqScope,
        base: usize,
    ) -> Result<u32, GicError> {
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

    pub(crate) fn write_priority_word_raw(
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

    pub(crate) fn read_trigger_word(
        &self,
        scope: VgicIrqScope,
        base: VIntId,
    ) -> Result<u32, GicError> {
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

    pub(crate) fn write_trigger_word(
        &mut self,
        scope: VgicIrqScope,
        base: VIntId,
        value: u32,
    ) -> Result<bool, GicError> {
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
        Ok(changed)
    }
}
