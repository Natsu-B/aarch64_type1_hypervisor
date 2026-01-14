use crate::EoiMode;
use crate::GicError;
use crate::IrqGroup;
use crate::IrqState;
use crate::MaintenanceReasons;
use crate::PIntId;
use crate::PirqNotifications;
use crate::VIntId;
use crate::VcpuId;
use crate::VgicHw;
use crate::VgicTargets;
use crate::VgicUpdate;
use crate::VgicVcpuModel;
use crate::VgicVcpuQueue;
use crate::VgicWork;
use crate::VirtualInterrupt;
use crate::vm::common::LOCAL_INTID_COUNT;
use aarch64_mutex::RawSpinLockIrqSave;
use core::cmp::Ordering;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::Ordering as AtomicOrdering;
use cpu::CoreAffinity;
use mutex::pod::RawAtomicPod;

#[inline(always)]
fn u64_lsb_mask(bits: usize) -> u64 {
    let bits = bits.min(u64::BITS as usize);
    if bits == u64::BITS as usize {
        u64::MAX
    } else {
        // bits < 64 holds here, so the shift is well-defined and won't overflow.
        (1u64 << bits) - 1
    }
}

#[inline(always)]
fn normalize_sw_irq(irq: &mut VirtualInterrupt) {
    if !irq.is_hw() && irq.state() != IrqState::Inactive {
        // Default to EOI maintenance for global interrupts; local SGI/PPI only arm on overflow.
        if irq.vintid() >= LOCAL_INTID_COUNT as u32 {
            irq.set_eoi_maintenance(true);
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct LrKey {
    vintid: VIntId,
    source: Option<VcpuId>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct PendingEntry {
    key: LrKey,
    irq: VirtualInterrupt,
}

/// Ordering for PendingEntry
/// - Higher priority first (lower numeric value)
///
/// This ordering is a deterministic software policy. The architecture does not define a strict
/// tie-break across equal priorities, and some backends quantize priority for HW arbitration.
impl Ord for PendingEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Note: ordering is based on the guest-visible 8-bit priority even though GICv2 LRs store
        // only the upper 5 bits (`priority >> 3`), so lower-bit ties may not match hardware.
        other
            .irq
            .priority()
            .cmp(&self.irq.priority())
            .then_with(|| other.key.vintid.0.cmp(&self.key.vintid.0))
            .then_with(|| {
                let other_src = other.key.source.map(|s| s.0);
                let self_src = self.key.source.map(|s| s.0);
                other_src.cmp(&self_src)
            })
    }
}

impl PartialOrd for PendingEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Capacity accounts for each INTID plus per-SGI source bookkeeping on all vCPUs.
struct FixedSortedArray<T: Copy, const N: usize> {
    len: usize,
    buf: [MaybeUninit<T>; N],
}

impl<T: Copy, const N: usize> FixedSortedArray<T, N> {
    fn new() -> Self {
        // SAFETY: `[MaybeUninit<T>; N]` is backing storage for up to `N` elements. `len` starts
        // at 0 so no uninitialised slot will be dropped or read until we explicitly write it.
        let buf: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        Self { len: 0, buf }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_slice(&self) -> &[T] {
        // SAFETY:
        // - `self.len <= N` is an invariant of `FixedSortedArray`.
        // - The first `self.len` entries of `buf` are initialised to valid `T` values by
        //   insert/remove operations.
        // - `MaybeUninit<T>` has the same layout as `T`, so casting the pointer is valid.
        let ptr = self.buf.as_ptr() as *const T;
        unsafe { core::slice::from_raw_parts(ptr, self.len) }
    }

    fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    fn peek_best(&self) -> Option<&T> {
        if self.len == 0 {
            None
        } else {
            // SAFETY: `len > 0` guarantees the last element is within the initialised prefix and
            // we only produce a shared reference.
            Some(unsafe { self.buf[self.len - 1].assume_init_ref() })
        }
    }

    fn pop_best(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: after decrementing, the old last element still lies in the initialised prefix.
        // `assume_init_read` moves it out to avoid double-drop; the slot is now considered
        // uninitialised until rewritten.
        Some(unsafe { self.buf[self.len].assume_init_read() })
    }

    fn insert_sorted(&mut self, value: T) -> Result<(), GicError>
    where
        T: Ord,
    {
        if self.len == N {
            return Err(GicError::OutOfResources);
        }
        let mut insert_idx = self.len;
        for i in 0..self.len {
            // SAFETY: `i < len` so the slot is initialised; we only read a shared reference for
            // ordering without mutating the element.
            let existing = unsafe { self.buf[i].assume_init_ref() };
            if existing.cmp(&value) == Ordering::Greater {
                insert_idx = i;
                break;
            }
        }
        // SAFETY: `len < N` ensures there is free capacity; we shift the initialised suffix
        // `[insert_idx, len)` one slot to the right to make space. The regions may overlap, which
        // `ptr::copy` handles like `memmove`, and both source and destination lie within the
        // allocated buffer.
        unsafe {
            ptr::copy(
                self.buf.as_ptr().add(insert_idx),
                self.buf.as_mut_ptr().add(insert_idx + 1),
                self.len - insert_idx,
            );
        }
        self.buf[insert_idx] = MaybeUninit::new(value);
        self.len += 1;
        Ok(())
    }

    fn remove_first(&mut self, mut pred: impl FnMut(&T) -> bool) -> bool {
        for i in 0..self.len {
            let matches = {
                // SAFETY: first `len` elements are initialised; we borrow a shared reference to
                // test the predicate without mutating the element.
                let elem = unsafe { self.buf[i].assume_init_ref() };
                pred(elem)
            };
            if matches {
                // SAFETY: `T: Copy`, so shifting elements with `ptr::copy` is sufficient and does
                // not require dropping any value explicitly. This shifts the initialised suffix
                // `[i + 1, len)` down by one slot.
                unsafe {
                    ptr::copy(
                        self.buf.as_ptr().add(i + 1),
                        self.buf.as_mut_ptr().add(i),
                        self.len - i - 1,
                    );
                }
                self.len -= 1;
                return true;
            }
        }
        false
    }
}

struct Inner<
    const MAX_VCPUS: usize,
    const MAX_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
> {
    pending: FixedSortedArray<PendingEntry, PENDING_CAP>,
    in_lr: [Option<LrKey>; MAX_LRS],
    lr_state: [IrqState; MAX_LRS],
    lr_updates: [Option<VirtualInterrupt>; MAX_LRS],
    lr_pintid: [Option<PIntId>; MAX_LRS],
    invalidate_lrs: u64,
    resident: Option<CoreAffinity>,
    sw_empty_lrs: u64,
    overflow_armed: bool,
}

pub struct GicVCpuGeneric<
    const MAX_VCPUS: usize,
    const MAX_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
> {
    id: VcpuId,
    inner: RawSpinLockIrqSave<Inner<MAX_VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>>,
    need_refill: RawAtomicPod<bool>,
}

impl<
    const MAX_VCPUS: usize,
    const MAX_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
> GicVCpuGeneric<MAX_VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>
{
    pub(crate) fn with_id(id: VcpuId) -> Self {
        Self {
            id,
            inner: RawSpinLockIrqSave::new(Inner {
                pending: FixedSortedArray::new(),
                in_lr: [None; MAX_LRS],
                lr_state: [IrqState::Inactive; MAX_LRS],
                lr_updates: [None; MAX_LRS],
                lr_pintid: [None; MAX_LRS],
                invalidate_lrs: 0,
                resident: None,
                sw_empty_lrs: 0,
                overflow_armed: false,
            }),
            need_refill: RawAtomicPod::new(false),
        }
    }

    pub(crate) fn cancel(&self, vintid: VIntId, source: Option<VcpuId>) -> Result<(), GicError> {
        let key = LrKey { vintid, source };
        let mut inner = self.inner.lock_irqsave();
        let mut removed = false;
        while inner.pending.remove_first(|entry| entry.key == key) {
            removed = true;
        }
        if let Some(idx) = inner.in_lr.iter().position(|entry| *entry == Some(key)) {
            if idx < u64::BITS as usize {
                inner.invalidate_lrs |= 1u64 << idx;
            }
            inner.lr_updates[idx] = None;
            removed = true;
        }
        if removed {
            self.need_refill.store(true, AtomicOrdering::Release);
        }
        Ok(())
    }

    pub(crate) fn enqueue(&self, mut irq: VirtualInterrupt) -> Result<VgicWork, GicError> {
        let key = LrKey {
            vintid: VIntId(irq.vintid()),
            source: irq.source(),
        };
        let mut inner = self.inner.lock_irqsave();
        if irq.state() == IrqState::Inactive {
            irq.set_state(IrqState::Pending);
        }
        normalize_sw_irq(&mut irq);
        while inner.pending.remove_first(|entry| entry.key == key) {}
        if let Some(idx) = inner.in_lr.iter().position(|entry| *entry == Some(key)) {
            inner.lr_updates[idx] = Some(irq);
        } else {
            inner.pending.insert_sorted(PendingEntry { key, irq })?;
        }
        self.need_refill.store(true, AtomicOrdering::Release);
        let current = cpu::get_current_core_id();
        // Kick is required if the vCPU is resident on another PE and we have any pending HW-visible work.
        let has_lr_updates = inner.lr_updates.iter().any(Option::is_some);
        let has_work = !inner.pending.is_empty() || inner.invalidate_lrs != 0 || has_lr_updates;
        let kick = inner.resident.is_some_and(|res| res != current) && has_work;
        drop(inner);
        Ok(if kick {
            VgicWork::REFILL_KICK
        } else {
            VgicWork::REFILL
        })
    }

    fn invalidate_lr_entry<H: VgicHw>(
        &self,
        hw: &H,
        idx: usize,
        inner: &mut Inner<MAX_VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>,
    ) -> Result<(), GicError> {
        let invalid = VirtualInterrupt::Software {
            vintid: 0,
            eoi_maintenance: false,
            priority: 0,
            group: IrqGroup::Group0,
            state: IrqState::Inactive,
            source: None,
        };
        // Write first; only clear software bookkeeping after success to avoid SW/HW divergence
        // on error paths.
        hw.write_lr(idx, invalid)?;
        inner.in_lr[idx] = None;
        inner.lr_state[idx] = IrqState::Inactive;
        inner.lr_updates[idx] = None;
        inner.lr_pintid[idx] = None;
        inner.sw_empty_lrs |= 1u64 << idx;
        Ok(())
    }
}

impl<
    const MAX_VCPUS: usize,
    const MAX_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
> VgicVcpuQueue for GicVCpuGeneric<MAX_VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>
{
    fn enqueue_irq(&self, irq: VirtualInterrupt) -> Result<VgicWork, GicError> {
        self.enqueue(irq)
    }

    fn cancel_irq(&self, vintid: VIntId, source: Option<VcpuId>) -> Result<(), GicError> {
        self.cancel(vintid, source)
    }
}

impl<
    const MAX_VCPUS: usize,
    const MAX_INTIDS: usize,
    const MAX_LRS: usize,
    const PENDING_CAP: usize,
> VgicVcpuModel for GicVCpuGeneric<MAX_VCPUS, MAX_INTIDS, MAX_LRS, PENDING_CAP>
{
    fn set_resident(&self, core: CoreAffinity) -> Result<(), GicError> {
        let mut inner = self.inner.lock_irqsave();
        match inner.resident {
            Some(existing) if existing != core => Err(GicError::InvalidState),
            _ => {
                inner.resident = Some(core);
                // Conservatively request a refill when residency changes.
                self.need_refill.store(true, AtomicOrdering::Release);
                Ok(())
            }
        }
    }

    fn clear_resident(&self, core: CoreAffinity) -> Result<(), GicError> {
        let mut inner = self.inner.lock_irqsave();
        match inner.resident {
            None => Ok(()),
            Some(existing) if existing == core => {
                inner.resident = None;
                Ok(())
            }
            Some(_) => Err(GicError::InvalidState),
        }
    }

    fn refill_lrs<H: crate::VgicHw>(&self, hw: &H) -> Result<bool, GicError> {
        if !self.need_refill.load(AtomicOrdering::Acquire) {
            return Ok(false);
        }

        let current = cpu::get_current_core_id();
        let mut inner = self.inner.lock_irqsave();
        let Some(resident) = inner.resident else {
            return Err(GicError::InvalidState);
        };
        if resident != current {
            let has_lr_updates = inner.lr_updates.iter().any(Option::is_some);
            let has_work = !inner.pending.is_empty() || inner.invalidate_lrs != 0 || has_lr_updates;
            return Ok(has_work);
        }

        // Bitmaps are u64; clamp to 64 to avoid overflowing shifts and bogus upper bits.
        let num_lrs = hw.num_lrs()?.min(MAX_LRS).min(u64::BITS as usize);
        let mask = u64_lsb_mask(num_lrs);
        inner.sw_empty_lrs &= mask;
        inner.invalidate_lrs &= mask;
        let invalidate = inner.invalidate_lrs;
        for idx in 0..num_lrs {
            if (invalidate & (1u64 << idx)) != 0 {
                self.invalidate_lr_entry(hw, idx, &mut inner)?;
                inner.invalidate_lrs &= !(1u64 << idx);
            }
        }

        let empty_bits = (hw.empty_lr_bitmap()? | inner.sw_empty_lrs) & mask;
        for idx in 0..num_lrs {
            if (empty_bits & (1u64 << idx)) != 0 {
                inner.in_lr[idx] = None;
                inner.lr_state[idx] = IrqState::Inactive;
                inner.lr_updates[idx] = None;
                inner.lr_pintid[idx] = None;
            }
        }

        for idx in 0..num_lrs {
            let Some(mut update_irq) = inner.lr_updates[idx] else {
                continue;
            };
            let update_key = LrKey {
                vintid: VIntId(update_irq.vintid()),
                source: update_irq.source(),
            };
            if update_irq.state() == IrqState::Inactive {
                update_irq.set_state(IrqState::Pending);
            }
            normalize_sw_irq(&mut update_irq);
            if inner.in_lr[idx] == Some(update_key) {
                hw.write_lr(idx, update_irq)?;
                inner.lr_state[idx] = update_irq.state();
                inner.lr_pintid[idx] = update_irq.pintid().map(PIntId);
                inner.sw_empty_lrs &= !(1u64 << idx);
            } else {
                while inner.pending.remove_first(|entry| entry.key == update_key) {}
                inner.pending.insert_sorted(PendingEntry {
                    key: update_key,
                    irq: update_irq,
                })?;
            }
            inner.lr_updates[idx] = None;
        }

        let mut empty = empty_bits;

        // Fill currently empty LRs.
        for idx in 0..num_lrs {
            if (empty & (1u64 << idx)) == 0 {
                continue;
            }
            let Some(entry) = inner.pending.pop_best() else {
                break;
            };
            let mut irq = entry.irq;
            if irq.state() == IrqState::Inactive {
                irq.set_state(IrqState::Pending);
            }
            normalize_sw_irq(&mut irq);
            // Program the hardware LR before updating software bookkeeping.
            hw.write_lr(idx, irq)?;
            inner.lr_state[idx] = irq.state();
            inner.lr_pintid[idx] = irq.pintid().map(PIntId);
            inner.in_lr[idx] = Some(entry.key);
            inner.lr_updates[idx] = None;
            inner.sw_empty_lrs &= !(1u64 << idx);
            empty &= !(1u64 << idx);
        }
        let eoi_mode = hw.current_eoi_mode()?;
        // Spilling is only ever performed for *pending* software LRs (never Active or HW-backed),
        // which is safe irrespective of the guest EOImode.
        let can_spill = true;

        // If no free LR and still pending work, consider eviction/spill.
        if empty == 0 && !inner.pending.is_empty() && can_spill {
            let best_pending = inner.pending.peek_best().cloned();
            if let Some(best_entry) = best_pending {
                // KVM rule: active or HW-backed entries must never be evicted; only pending SW LRs
                // are candidates for replacement.
                let mut victim_pending: Option<(usize, VirtualInterrupt)> = None;
                for idx in 0..num_lrs {
                    let irq = hw.read_lr(idx)?;
                    let bit = 1u64 << idx;

                    inner.lr_state[idx] = irq.state();
                    inner.lr_pintid[idx] = irq.pintid().map(PIntId);

                    if irq.state() == IrqState::Inactive {
                        inner.in_lr[idx] = None;
                        inner.lr_updates[idx] = None;
                        inner.lr_pintid[idx] = None;
                        inner.sw_empty_lrs |= bit;
                    } else {
                        inner.in_lr[idx] = Some(LrKey {
                            vintid: VIntId(irq.vintid()),
                            source: irq.source(),
                        });
                        inner.sw_empty_lrs &= !bit;
                    }
                    if irq.is_hw() {
                        continue;
                    }
                    // Victim selection uses the guest's 8-bit priority; GICv2 LRs quantise to 5
                    // bits, so ordering for equal upper bits may diverge from hardware tie-breaking.
                    if matches!(irq.state(), IrqState::Pending)
                        && irq.priority() > best_entry.irq.priority()
                    {
                        match &victim_pending {
                            Some((_, v_irq)) if v_irq.priority() >= irq.priority() => {}
                            _ => victim_pending = Some((idx, irq)),
                        }
                    }
                }

                if let Some((idx, victim_irq)) = victim_pending {
                    debug_assert!(matches!(victim_irq.state(), IrqState::Pending));
                    debug_assert!(!victim_irq.is_hw());
                    let _ = inner.pending.pop_best(); // remove best_entry
                    // Return victim to pending queue.
                    let victim_key = LrKey {
                        vintid: VIntId(victim_irq.vintid()),
                        source: victim_irq.source(),
                    };
                    let mut victim_pending_irq = victim_irq;
                    victim_pending_irq.set_state(IrqState::Pending);
                    normalize_sw_irq(&mut victim_pending_irq);
                    inner.pending.insert_sorted(PendingEntry {
                        key: victim_key,
                        irq: victim_pending_irq,
                    })?;
                    // Install best entry into LR.
                    let mut irq = best_entry.irq;
                    if irq.state() == IrqState::Inactive {
                        irq.set_state(IrqState::Pending);
                    }
                    normalize_sw_irq(&mut irq);
                    hw.write_lr(idx, irq)?;
                    inner.lr_state[idx] = irq.state();
                    inner.lr_pintid[idx] = irq.pintid().map(PIntId);
                    inner.in_lr[idx] = Some(best_entry.key);
                    inner.sw_empty_lrs &= !(1u64 << idx);
                }
                // If we could not find a safe pending victim, leave the queue intact. We do not
                // spill active or HW-backed LRs because that would violate EOImode=1 semantics
                // without trapping DIR.
            }
        }

        if inner.resident.map_or(true, |r| r == current) {
            let pending_remaining = !inner.pending.is_empty();
            // Re-read after refill to drive overflow arming/disarming decisions.
            let empties_now = (hw.empty_lr_bitmap()? | inner.sw_empty_lrs) & mask;
            match eoi_mode {
                EoiMode::DropAndDeactivate => {
                    if pending_remaining && empties_now == 0 {
                        // Overflow: no empty LR, pending queue non-empty. Arm EOI-maintenance on
                        // in-flight SW LRs and KEEP it armed until the condition clears.
                        if !inner.overflow_armed {
                            let mut have_sw_inflight = false;
                            let mut have_sw_eoi_armed = false;
                            for idx in 0..num_lrs {
                                if inner.in_lr[idx].is_some() {
                                    let mut irq = hw.read_lr(idx)?;
                                    inner.lr_state[idx] = irq.state();
                                    if !irq.is_hw() && irq.state() != IrqState::Inactive {
                                        have_sw_inflight = true;
                                        if !irq.eoi_maintenance() {
                                            irq.set_eoi_maintenance(true);
                                            hw.write_lr(idx, irq)?;
                                            inner.lr_state[idx] = irq.state();
                                        }
                                        if irq.eoi_maintenance() {
                                            have_sw_eoi_armed = true;
                                        }
                                    }
                                }
                            }
                            inner.overflow_armed = have_sw_inflight && have_sw_eoi_armed;
                        }
                    } else if inner.overflow_armed {
                        // Condition cleared: restore EOI-maintenance to the policy default.
                        for idx in 0..num_lrs {
                            if inner.in_lr[idx].is_some() {
                                let mut irq = hw.read_lr(idx)?;
                                inner.lr_state[idx] = irq.state();
                                if !irq.is_hw() && irq.state() != IrqState::Inactive {
                                    let want_eoi = irq.vintid() >= LOCAL_INTID_COUNT as u32;
                                    if irq.eoi_maintenance() != want_eoi {
                                        irq.set_eoi_maintenance(want_eoi);
                                        hw.write_lr(idx, irq)?;
                                        inner.lr_state[idx] = irq.state();
                                    }
                                }
                            }
                        }
                        inner.overflow_armed = false;
                    }
                }
                EoiMode::DropOnly => {
                    if inner.overflow_armed {
                        for idx in 0..num_lrs {
                            if inner.in_lr[idx].is_some() {
                                let mut irq = hw.read_lr(idx)?;
                                inner.lr_state[idx] = irq.state();
                                if !irq.is_hw() && irq.state() != IrqState::Inactive {
                                    let want_eoi = irq.vintid() >= LOCAL_INTID_COUNT as u32;
                                    if irq.eoi_maintenance() != want_eoi {
                                        irq.set_eoi_maintenance(want_eoi);
                                        hw.write_lr(idx, irq)?;
                                        inner.lr_state[idx] = irq.state();
                                    }
                                }
                            }
                        }
                        inner.overflow_armed = false;
                    }
                }
            }
            hw.set_underflow_irq(pending_remaining)?;
        }
        let has_lr_updates = inner.lr_updates.iter().take(num_lrs).any(Option::is_some);
        let has_remaining_work =
            !inner.pending.is_empty() || inner.invalidate_lrs != 0 || has_lr_updates;
        self.need_refill
            .store(has_remaining_work, AtomicOrdering::Release);
        Ok(false)
    }

    fn handle_maintenance_collect<H: crate::VgicHw>(
        &self,
        hw: &H,
    ) -> Result<(VgicUpdate, PirqNotifications), GicError> {
        let current = cpu::get_current_core_id();

        let reasons = hw.maintenance_reasons()?;
        let eoi_mode = hw.current_eoi_mode()?;

        let mut inner = self.inner.lock_irqsave();
        if inner.resident != Some(current) {
            return Err(GicError::InvalidState);
        }

        let num_lrs = hw.num_lrs()?.min(MAX_LRS).min(u64::BITS as usize);
        let mask = u64_lsb_mask(num_lrs);
        let targets = VgicTargets::One(self.id);

        let mut update = VgicUpdate::None;
        let mut notifications = PirqNotifications::new();

        // LRENP: guest wrote EOIR for a LR that is not present; EOICount is non-zero.
        // Consume and clear EOICount, then request a refill.
        if reasons.contains(MaintenanceReasons::LR_ENTRY_NOT_PRESENT) {
            let _ = hw.take_eoi_count()?;
            self.need_refill.store(true, AtomicOrdering::Release);
            update.combine(&VgicUpdate::Some {
                targets,
                work: VgicWork::REFILL,
            });
        }

        if reasons.contains(MaintenanceReasons::EOI) {
            let eisr = hw.eoi_lr_bitmap()? & mask;
            let empty = hw.empty_lr_bitmap()? & mask;

            let mut any_eoi = false;

            for idx in 0..num_lrs {
                let bit = 1u64 << idx;
                // For both SW and HW entries, ELRSR is the only architecturally reliable way to
                // detect that an LR is no longer resident (especially for HW==1 entries whose
                // pending/active state is tracked in the physical distributor).
                if (empty & bit) != 0 {
                    if inner.in_lr[idx].is_some() {
                        let old = inner.lr_state[idx];
                        if old != IrqState::Inactive {
                            any_eoi = true;
                            if let Some(pintid) = inner.lr_pintid[idx] {
                                notifications.eoi.push(pintid)?;
                                // If the LR disappeared, treat it as fully completed.
                                notifications.deactivate.push(pintid)?;
                            }
                        }

                        inner.in_lr[idx] = None;
                        inner.lr_state[idx] = IrqState::Inactive;
                        inner.lr_updates[idx] = None;
                        inner.lr_pintid[idx] = None;
                        inner.sw_empty_lrs |= bit;
                    }
                    continue;
                }

                let sw_eoi = (eisr & bit) != 0;
                // If we have no software shadow for this LR, only process it when EISR indicates
                // an EOI maintenance event. This makes the handler robust against shadow desync
                // (e.g. migration, ELRSR/EISR quirks) without scanning unrelated LRs.
                if inner.in_lr[idx].is_none() && !sw_eoi {
                    continue;
                }

                let old = inner.lr_state[idx];
                let mut irq = hw.read_lr(idx)?;
                let new = irq.state();

                // EISR is architecturally meaningful only for SW-composed LRs, and may be broken
                // on some implementations. Treat it as a hint and fall back to state transitions.
                let eoi_event = if irq.is_hw() {
                    old != new && old != IrqState::Inactive
                } else {
                    sw_eoi || (old != new && old != IrqState::Inactive)
                };
                if !eoi_event {
                    inner.lr_state[idx] = new;
                    inner.lr_pintid[idx] = irq.pintid().map(PIntId);
                    continue;
                }

                any_eoi = true;

                inner.lr_state[idx] = new;
                inner.lr_pintid[idx] = irq.pintid().map(PIntId);

                if let Some(pintid) = irq.pintid() {
                    notifications.eoi.push(PIntId(pintid))?;
                    match irq.state() {
                        IrqState::Inactive => notifications.deactivate.push(PIntId(pintid))?,
                        IrqState::Pending | IrqState::PendingActive => {
                            notifications.resample.push(PIntId(pintid))?
                        }
                        IrqState::Active => {}
                    }
                }

                let key = LrKey {
                    vintid: VIntId(irq.vintid()),
                    source: irq.source(),
                };

                if irq.is_hw() {
                    match eoi_mode {
                        EoiMode::DropOnly => {
                            // Keep the LR unless the hardware already marked it inactive.
                            if irq.state() == IrqState::Inactive {
                                inner.in_lr[idx] = None;
                                inner.lr_pintid[idx] = None;
                                inner.sw_empty_lrs |= bit;
                            } else {
                                inner.in_lr[idx] = Some(key);
                                inner.sw_empty_lrs &= !bit;
                            }
                        }
                        EoiMode::DropAndDeactivate => {
                            self.invalidate_lr_entry(hw, idx, &mut inner)?;
                        }
                    }
                } else {
                    match eoi_mode {
                        EoiMode::DropOnly => {
                            // Clear EOI-maintenance on SW entries after we've observed the event.
                            if irq.eoi_maintenance() {
                                irq.set_eoi_maintenance(false);
                                hw.write_lr(idx, irq)?;
                                inner.lr_state[idx] = irq.state();
                                inner.lr_pintid[idx] = irq.pintid().map(PIntId);
                            }

                            if irq.state() == IrqState::Inactive {
                                inner.in_lr[idx] = None;
                                inner.lr_pintid[idx] = None;
                                inner.lr_state[idx] = IrqState::Inactive;
                                inner.sw_empty_lrs |= bit;
                            } else {
                                inner.in_lr[idx] = Some(key);
                                inner.sw_empty_lrs &= !bit;
                            }
                        }
                        EoiMode::DropAndDeactivate => {
                            // In drop-and-deactivate mode, keep pending SW entries resident but
                            // invalidate active/inactive ones to free space.
                            if irq.state() == IrqState::Pending {
                                irq.set_eoi_maintenance(false);
                                hw.write_lr(idx, irq)?;
                                inner.lr_state[idx] = irq.state();
                                inner.lr_pintid[idx] = irq.pintid().map(PIntId);
                                inner.in_lr[idx] = Some(key);
                                inner.sw_empty_lrs &= !bit;
                            } else {
                                self.invalidate_lr_entry(hw, idx, &mut inner)?;
                            }
                        }
                    }
                }
            }

            // Clear EISR bits that were latched for this maintenance event. EISR is SW-only;
            // clearing spurious bits is safe and avoids retriggering on broken implementations.
            if eisr != 0 {
                hw.clear_eoi_lr_bitmap(eisr)?;
            }

            // EOICount drives LRENP maintenance interrupts. We do not use it to identify LRs;
            // we only consume it to prevent the same condition from retriggering indefinitely.
            let _ = hw.take_eoi_count()?;

            if any_eoi {
                self.need_refill.store(true, AtomicOrdering::Release);
                update.combine(&VgicUpdate::Some {
                    targets,
                    work: VgicWork::REFILL,
                });
            }
        }

        drop(inner);

        if reasons.0
            & (MaintenanceReasons::NO_PENDING
                | MaintenanceReasons::VGRP0_DISABLED
                | MaintenanceReasons::VGRP1_DISABLED
                | MaintenanceReasons::VGRP0_ENABLED
                | MaintenanceReasons::VGRP1_ENABLED)
            != 0
        {
            self.need_refill.store(true, AtomicOrdering::Release);
            update.combine(&VgicUpdate::Some {
                targets: VgicTargets::One(self.id),
                work: VgicWork::REFILL,
            });
        }

        if reasons.0 & MaintenanceReasons::UNDERFLOW != 0 {
            let kick = self.refill_lrs(hw)?;
            update.combine(&VgicUpdate::Some {
                targets: VgicTargets::One(self.id),
                work: if kick {
                    VgicWork::REFILL_KICK
                } else {
                    VgicWork::REFILL
                },
            });
        }

        // Adjust UIE based on remaining pending work when running on the resident PE.
        let (pending_remaining, resident_now) = {
            let inner = self.inner.lock_irqsave();
            (!inner.pending.is_empty(), inner.resident)
        };
        if resident_now.map_or(true, |r| r == current) {
            hw.set_underflow_irq(pending_remaining)?;
        }

        Ok((update, notifications))
    }

    fn switch_out_sync<H: crate::VgicHw>(&self, hw: &H) -> Result<(), GicError> {
        // Consume EOICount (clearing LRENP) before switching out. This avoids spurious repeated
        // maintenance interrupts if the guest EOI'd an unmapped LR entry.
        let _ = hw.take_eoi_count()?;

        let current = cpu::get_current_core_id();
        let mut inner = self.inner.lock_irqsave();
        if let Some(resident) = inner.resident {
            if resident != current {
                return Err(GicError::InvalidState);
            }
        }
        // ensure no lingering EOI-maintenance arming across context switches.
        let num_lrs = hw.num_lrs()?.min(MAX_LRS);
        for idx in 0..num_lrs {
            let mut irq = hw.read_lr(idx)?;
            inner.lr_state[idx] = irq.state();
            if !irq.is_hw() && irq.eoi_maintenance() {
                irq.set_eoi_maintenance(false);
                hw.write_lr(idx, irq)?;
                inner.lr_state[idx] = irq.state();
            }
        }
        inner.overflow_armed = false;
        inner.resident = None;
        let has_lr_updates = inner.lr_updates.iter().take(num_lrs).any(Option::is_some);
        let has_work = !inner.pending.is_empty() || inner.invalidate_lrs != 0 || has_lr_updates;
        drop(inner);
        self.need_refill.store(has_work, AtomicOrdering::Release);
        hw.set_underflow_irq(false)?;
        hw.set_enabled(false)?;
        Ok(())
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::VgicHw;
    use crate::VgicVcpuModel;
    use core::cell::RefCell;

    const TEST_VCPUS: usize = 4;
    const MAX_LRS: usize = crate::VgicVmConfig::<TEST_VCPUS>::MAX_LRS;
    type TestVcpu = GicVCpuGeneric<
        TEST_VCPUS,
        { crate::max_intids_for_vcpus(TEST_VCPUS) },
        { MAX_LRS },
        { crate::vm::pending_cap_for_vcpus(TEST_VCPUS) },
    >;

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn fixed_sorted_array_signals_overflow() {
        let mut arr: FixedSortedArray<u8, 1> = FixedSortedArray::new();
        arr.insert_sorted(1).unwrap();
        assert!(matches!(
            arr.insert_sorted(2),
            Err(GicError::OutOfResources)
        ));
    }

    fn invalid_irq() -> VirtualInterrupt {
        VirtualInterrupt::Software {
            vintid: 0,
            eoi_maintenance: false,
            priority: 0,
            group: IrqGroup::Group0,
            state: IrqState::Inactive,
            source: None,
        }
    }

    struct CallbackLog<const N: usize> {
        entries: [u32; N],
        len: usize,
    }

    impl<const N: usize> CallbackLog<N> {
        fn new() -> Self {
            Self {
                entries: [0; N],
                len: 0,
            }
        }

        fn push(&mut self, value: u32) {
            if self.len < N {
                self.entries[self.len] = value;
                self.len += 1;
            }
        }

        fn as_slice(&self) -> &[u32] {
            &self.entries[..self.len]
        }
    }

    #[derive(Clone)]
    struct FakeState {
        lrs: [VirtualInterrupt; MAX_LRS],
        elrsr: u64,
        eisr: u64,
        misr: MaintenanceReasons,
        num_lrs: usize,
        hcr_en: bool,
        hcr_uie: bool,
        apr: u32,
        eoi_mode: EoiMode,
    }

    struct FakeHw {
        state: RefCell<FakeState>,
    }

    struct RaceyHw {
        state: RefCell<FakeState>,
    }

    impl FakeHw {
        fn new(num_lrs: usize) -> Self {
            let num_lrs = num_lrs.min(MAX_LRS).min(u64::BITS as usize);
            Self {
                state: RefCell::new(FakeState {
                    lrs: [invalid_irq(); MAX_LRS],
                    elrsr: super::u64_lsb_mask(num_lrs),
                    eisr: 0,
                    misr: MaintenanceReasons::NONE,
                    num_lrs,
                    hcr_en: false,
                    hcr_uie: false,
                    apr: 0,
                    eoi_mode: EoiMode::DropAndDeactivate,
                }),
            }
        }
    }

    impl RaceyHw {
        fn new(num_lrs: usize) -> Self {
            let num_lrs = num_lrs.min(MAX_LRS).min(u64::BITS as usize);
            Self {
                state: RefCell::new(FakeState {
                    lrs: [invalid_irq(); MAX_LRS],
                    elrsr: 0, // start with no empty bits; caller arranges state explicitly.
                    eisr: 0,
                    misr: MaintenanceReasons::NONE,
                    num_lrs,
                    hcr_en: false,
                    hcr_uie: false,
                    apr: 0,
                    eoi_mode: EoiMode::DropAndDeactivate,
                }),
            }
        }
    }

    impl VgicHw for FakeHw {
        type SavedState = ();

        fn hw_init(&self) -> Result<(), GicError> {
            Ok(())
        }

        fn set_enabled(&self, enabled: bool) -> Result<(), GicError> {
            self.state.borrow_mut().hcr_en = enabled;
            Ok(())
        }

        fn set_underflow_irq(&self, enable: bool) -> Result<(), GicError> {
            self.state.borrow_mut().hcr_uie = enable;
            Ok(())
        }

        fn current_eoi_mode(&self) -> Result<EoiMode, GicError> {
            Ok(self.state.borrow().eoi_mode)
        }

        fn num_lrs(&self) -> Result<usize, GicError> {
            Ok(self.state.borrow().num_lrs)
        }

        fn empty_lr_bitmap(&self) -> Result<u64, GicError> {
            Ok(self.state.borrow().elrsr)
        }

        fn eoi_lr_bitmap(&self) -> Result<u64, GicError> {
            Ok(self.state.borrow().eisr)
        }

        fn clear_eoi_lr_bitmap(&self, bitmap: u64) -> Result<(), GicError> {
            let mut st = self.state.borrow_mut();
            st.eisr &= !bitmap;
            Ok(())
        }

        fn take_eoi_count(&self) -> Result<u32, GicError> {
            Ok(0)
        }

        fn read_lr(&self, index: usize) -> Result<VirtualInterrupt, GicError> {
            let state = self.state.borrow();
            if index >= state.num_lrs {
                return Err(GicError::InvalidLrIndex);
            }
            Ok(state.lrs[index])
        }

        fn write_lr(&self, index: usize, irq: VirtualInterrupt) -> Result<(), GicError> {
            let mut state = self.state.borrow_mut();
            if index >= state.num_lrs {
                return Err(GicError::InvalidLrIndex);
            }
            state.lrs[index] = irq;
            if irq.state() == IrqState::Inactive {
                state.elrsr |= 1u64 << index;
            } else {
                state.elrsr &= !(1u64 << index);
            }
            Ok(())
        }

        fn read_apr(&self, index: usize) -> Result<u32, GicError> {
            if index != 0 {
                return Err(GicError::IndexOutOfRange);
            }
            Ok(self.state.borrow().apr)
        }

        fn write_apr(&self, index: usize, value: u32) -> Result<(), GicError> {
            if index != 0 {
                return Err(GicError::IndexOutOfRange);
            }
            self.state.borrow_mut().apr = value;
            Ok(())
        }

        fn maintenance_reasons(&self) -> Result<MaintenanceReasons, GicError> {
            Ok(self.state.borrow().misr)
        }

        fn save_state(&self) -> Result<Self::SavedState, GicError> {
            Ok(())
        }

        fn restore_state(&self, _state: &Self::SavedState) -> Result<(), GicError> {
            Ok(())
        }
    }

    impl FakeHw {
        fn set_eoi_mode(&self, mode: EoiMode) {
            self.state.borrow_mut().eoi_mode = mode;
        }
    }

    impl VgicHw for RaceyHw {
        type SavedState = ();

        fn hw_init(&self) -> Result<(), GicError> {
            Ok(())
        }

        fn set_enabled(&self, enabled: bool) -> Result<(), GicError> {
            self.state.borrow_mut().hcr_en = enabled;
            Ok(())
        }

        fn set_underflow_irq(&self, enable: bool) -> Result<(), GicError> {
            self.state.borrow_mut().hcr_uie = enable;
            Ok(())
        }

        fn current_eoi_mode(&self) -> Result<EoiMode, GicError> {
            Ok(self.state.borrow().eoi_mode)
        }

        fn num_lrs(&self) -> Result<usize, GicError> {
            Ok(self.state.borrow().num_lrs)
        }

        fn empty_lr_bitmap(&self) -> Result<u64, GicError> {
            Ok(self.state.borrow().elrsr)
        }

        fn eoi_lr_bitmap(&self) -> Result<u64, GicError> {
            Ok(self.state.borrow().eisr)
        }

        fn clear_eoi_lr_bitmap(&self, bitmap: u64) -> Result<(), GicError> {
            let mut st = self.state.borrow_mut();
            st.eisr &= !bitmap;
            Ok(())
        }

        fn take_eoi_count(&self) -> Result<u32, GicError> {
            Ok(0)
        }

        fn read_lr(&self, index: usize) -> Result<VirtualInterrupt, GicError> {
            let state = self.state.borrow();
            if index >= state.num_lrs {
                return Err(GicError::InvalidLrIndex);
            }
            Ok(state.lrs[index])
        }

        fn write_lr(&self, index: usize, irq: VirtualInterrupt) -> Result<(), GicError> {
            let mut state = self.state.borrow_mut();
            if index >= state.num_lrs {
                return Err(GicError::InvalidLrIndex);
            }
            state.lrs[index] = irq;
            // Simulate stale ELRSR after invalidation: do not set the empty bit when writing
            // Inactive entries. Keep clearing for non-inactive to model busy LRs.
            if irq.state() != IrqState::Inactive {
                state.elrsr &= !(1u64 << index);
            }
            Ok(())
        }

        fn read_apr(&self, index: usize) -> Result<u32, GicError> {
            if index != 0 {
                return Err(GicError::IndexOutOfRange);
            }
            Ok(self.state.borrow().apr)
        }

        fn write_apr(&self, index: usize, value: u32) -> Result<(), GicError> {
            if index != 0 {
                return Err(GicError::IndexOutOfRange);
            }
            self.state.borrow_mut().apr = value;
            Ok(())
        }

        fn maintenance_reasons(&self) -> Result<MaintenanceReasons, GicError> {
            Ok(self.state.borrow().misr)
        }

        fn save_state(&self) -> Result<Self::SavedState, GicError> {
            Ok(())
        }

        fn restore_state(&self, _state: &Self::SavedState) -> Result<(), GicError> {
            Ok(())
        }
    }

    fn make_irq(vintid: u32, priority: u8, hw: bool, pintid: Option<u32>) -> VirtualInterrupt {
        if hw {
            VirtualInterrupt::Hardware {
                vintid,
                pintid: pintid.unwrap_or(0),
                priority,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            }
        } else {
            VirtualInterrupt::Software {
                vintid,
                eoi_maintenance: false,
                priority,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            }
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn refill_orders_by_priority() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(4);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();

        vcpu.enqueue(make_irq(40, 0x20, false, None)).unwrap();
        vcpu.enqueue(make_irq(50, 0x10, false, None)).unwrap();

        vcpu.refill_lrs(&hw).unwrap();
        let state = hw.state.borrow();
        assert_eq!(state.lrs[0].vintid(), 50);
        assert_eq!(state.lrs[1].vintid(), 40);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn need_refill_clears_when_no_work_remains() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();

        vcpu.enqueue(make_irq(40, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();

        let inner = vcpu.inner.lock_irqsave();
        assert!(inner.pending.is_empty());
        assert_eq!(inner.invalidate_lrs, 0);
        assert!(inner.lr_updates.iter().all(Option::is_none));
        drop(inner);

        assert!(!vcpu.need_refill.load(AtomicOrdering::Acquire));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn software_irq_injection_forces_eoi_maintenance() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();

        vcpu.enqueue(make_irq(48, 0x20, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();

        let lr0 = hw.read_lr(0).unwrap();
        assert!(lr0.eoi_maintenance());
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn remote_resident_requests_kick() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(2);
        vcpu.set_resident(CoreAffinity::new(1, 0, 0, 0)).unwrap();

        let work = vcpu.enqueue(make_irq(60, 0x10, false, None)).unwrap();
        assert!(work.kick);

        let kick = vcpu.refill_lrs(&hw).unwrap();
        assert!(kick);
        let state = hw.state.borrow();
        assert_eq!(state.lrs[0].state(), IrqState::Inactive);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn enqueue_updates_lr_when_key_already_in_lr() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        let key = LrKey {
            vintid: VIntId(40),
            source: None,
        };
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Software {
                vintid: key.vintid.0,
                eoi_maintenance: false,
                priority: 0x20,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
        }
        {
            let mut inner = vcpu.inner.lock_irqsave();
            inner.in_lr[0] = Some(key);
        }

        let updated_irq = VirtualInterrupt::Software {
            vintid: key.vintid.0,
            eoi_maintenance: false,
            priority: 0x10,
            group: IrqGroup::Group1,
            state: IrqState::Inactive,
            source: None,
        };
        vcpu.enqueue(updated_irq).unwrap();
        vcpu.refill_lrs(&hw).unwrap();

        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), key.vintid.0);
        assert_eq!(st.lrs[0].priority(), 0x10);
        assert_eq!(st.lrs[0].state(), IrqState::Pending);
        drop(st);

        let inner = vcpu.inner.lock_irqsave();
        assert!(!inner.pending.iter().any(|entry| entry.key == key));
        assert!(inner.lr_updates[0].is_none());
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn cancel_invalidates_lr_when_key_in_lr() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        let key = LrKey {
            vintid: VIntId(12),
            source: None,
        };
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Software {
                vintid: key.vintid.0,
                eoi_maintenance: false,
                priority: 0x10,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
        }
        {
            let mut inner = vcpu.inner.lock_irqsave();
            inner.in_lr[0] = Some(key);
        }

        vcpu.cancel(key.vintid, key.source).unwrap();
        vcpu.refill_lrs(&hw).unwrap();

        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), 0);
        assert_eq!(st.lrs[0].state(), IrqState::Inactive);
        drop(st);

        let inner = vcpu.inner.lock_irqsave();
        assert!(inner.in_lr[0].is_none());
        assert_eq!(inner.invalidate_lrs, 0);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn stale_lr_update_is_requeued_to_pending() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = RaceyHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        let key = LrKey {
            vintid: VIntId(55),
            source: None,
        };
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = invalid_irq();
            st.elrsr = 0;
        }
        {
            let mut inner = vcpu.inner.lock_irqsave();
            inner.in_lr[0] = None;
            inner.lr_updates[0] = Some(VirtualInterrupt::Software {
                vintid: key.vintid.0,
                eoi_maintenance: false,
                priority: 0x18,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            });
        }

        vcpu.need_refill.store(true, AtomicOrdering::Release);
        vcpu.refill_lrs(&hw).unwrap();

        let inner = vcpu.inner.lock_irqsave();
        assert!(inner.pending.iter().any(|entry| entry.key == key));
        assert!(inner.lr_updates[0].is_none());
        drop(inner);

        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].state(), IrqState::Inactive);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn eoi_maintenance_invalidates_and_calls_callbacks() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(2);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        // NOTE: HW==1 LRs do not participate in EISR (EOI maintenance status only applies to HW==0).
        // Simulate an EOI by a state transition that we have previously observed.
        let key = LrKey {
            vintid: VIntId(45),
            source: None,
        };
        {
            let irq = VirtualInterrupt::Hardware {
                vintid: 45,
                pintid: 33,
                priority: 0x10,
                group: IrqGroup::Group0,
                state: IrqState::Active,
                source: None,
            };
            hw.write_lr(0, irq).unwrap();
            let mut inner = vcpu.inner.lock_irqsave();
            inner.in_lr[0] = Some(key);
            inner.lr_state[0] = IrqState::Active;
            inner.sw_empty_lrs &= !1;
        }
        {
            // EOI observed: Active -> Pending (e.g. level-triggered still pending after EOI).
            let irq = VirtualInterrupt::Hardware {
                vintid: 45,
                pintid: 33,
                priority: 0x10,
                group: IrqGroup::Group0,
                state: IrqState::Pending,
                source: None,
            };
            hw.write_lr(0, irq).unwrap();
            let mut state = hw.state.borrow_mut();
            state.eisr &= !1;
            state.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }

        let mut eoi = CallbackLog::<4>::new();
        let mut deactivate = CallbackLog::<4>::new();
        let mut resample = CallbackLog::<4>::new();
        let update = vcpu
            .handle_maintenance(
                &hw,
                &mut |id| eoi.push(id.0),
                &mut |id| deactivate.push(id.0),
                &mut |id| resample.push(id.0),
            )
            .unwrap();

        assert_eq!(eoi.as_slice(), &[33]);
        assert!(deactivate.as_slice().is_empty());
        assert_eq!(resample.as_slice(), &[33]);
        {
            let state = hw.state.borrow();
            assert_ne!(state.elrsr & 1, 0);
        }

        match update {
            VgicUpdate::Some { work, .. } => {
                assert!(work.refill);
            }
            _ => panic!("expected refill request"),
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn overflow_arms_eoi_and_makes_progress() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(2);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        vcpu.enqueue(make_irq(1, 0x20, false, None)).unwrap();
        vcpu.enqueue(make_irq(2, 0x18, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert!(!st.lrs[0].eoi_maintenance());
            assert!(!st.lrs[1].eoi_maintenance());
        }

        // Force the overflow-arming path:
        // - Make current in-LR entries non-spillable by setting them Active.
        // - Spill logic only considers SW Pending entries as eviction candidates.
        // - With LRs full and pending queue non-empty, refill will arm EOI-maintenance.
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Active);
            st.lrs[1].set_state(IrqState::Active);
            st.elrsr &= !0b11;
        }

        vcpu.enqueue(make_irq(3, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert!(st.lrs[0].eoi_maintenance());
            assert!(st.lrs[1].eoi_maintenance());
        }

        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Inactive);
            st.lrs[0].set_eoi_maintenance(true);
            st.elrsr |= 1;
            st.eisr = 1;
            st.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }
        let update = vcpu.handle_maintenance(&hw, &mut |_id| {}, &mut |_id| {}, &mut |_id| {});
        match update.unwrap() {
            VgicUpdate::Some { work, .. } => assert!(work.refill),
            _ => panic!("expected refill request"),
        }

        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.lrs[0].vintid(), 3);
            assert!(!st.lrs[0].eoi_maintenance());
        }
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn overflow_disarms_when_empty_lr_appears() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(2);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        vcpu.enqueue(make_irq(1, 0x20, false, None)).unwrap();
        vcpu.enqueue(make_irq(2, 0x18, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        vcpu.enqueue(make_irq(3, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert!(st.lrs[0].eoi_maintenance());
            assert!(st.lrs[1].eoi_maintenance());
        }

        // Make one LR empty; disarm should clear EOI maintenance on the remaining entry.
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Inactive);
            st.elrsr |= 1;
        }
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        assert!(!st.lrs[0].eoi_maintenance());
        assert!(!st.lrs[1].eoi_maintenance());
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn overflow_not_armed_when_eoi_mode_drop_only() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        hw.set_eoi_mode(EoiMode::DropOnly);
        vcpu.enqueue(make_irq(1, 0x20, false, None)).unwrap();
        vcpu.enqueue(make_irq(2, 0x18, false, None)).unwrap();

        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert!(!st.lrs[0].eoi_maintenance());
        }
        let inner = vcpu.inner.lock_irqsave();
        assert!(!inner.overflow_armed);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn hw_eoi_triggers_callbacks_and_invalidates() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(2);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        vcpu.enqueue(make_irq(77, 0x20, true, Some(77))).unwrap();
        vcpu.refill_lrs(&hw).unwrap();

        // HW==1 LRs do not participate in EISR. Simulate an EOI by a state transition that we
        // have previously observed as Active -> Inactive.
        {
            let mut irq = hw.read_lr(0).unwrap();
            irq.set_state(IrqState::Active);
            hw.write_lr(0, irq).unwrap();
            let mut inner = vcpu.inner.lock_irqsave();
            inner.lr_state[0] = IrqState::Active;
        }
        {
            let mut irq = hw.read_lr(0).unwrap();
            irq.set_state(IrqState::Inactive);
            hw.write_lr(0, irq).unwrap();
            let mut st = hw.state.borrow_mut();
            st.eisr = 0;
            st.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }

        let mut eoi = CallbackLog::<4>::new();
        vcpu.handle_maintenance(&hw, &mut |id| eoi.push(id.0), &mut |_id| {}, &mut |_id| {})
            .unwrap();
        let st = hw.state.borrow();
        assert_eq!(eoi.as_slice(), &[77]);
        assert_ne!(st.elrsr & 1, 0); // LR marked empty
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn eoi_mode_drop_only_keeps_lr_on_eoi() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        hw.set_eoi_mode(EoiMode::DropOnly);

        // Use a SW interrupt: EOI maintenance for HW==1 does not use EISR.
        let mut irq = make_irq(21, 0x10, false, None);
        irq.set_state(IrqState::Active);
        hw.write_lr(0, irq).unwrap();
        {
            let mut inner = vcpu.inner.lock_irqsave();
            inner.in_lr[0] = Some(LrKey {
                vintid: VIntId(21),
                source: None,
            });
            inner.lr_state[0] = IrqState::Active;
            inner.sw_empty_lrs &= !1;
        }
        {
            let mut st = hw.state.borrow_mut();
            st.eisr = 1;
            st.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }

        let update = vcpu.handle_maintenance(&hw, &mut |_| {}, &mut |_| {}, &mut |_| {});
        assert!(matches!(
            update.unwrap(),
            VgicUpdate::Some { work, .. } if work.refill
        ));
        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].state(), IrqState::Active);
        assert!(!st.lrs[0].eoi_maintenance());
        assert_eq!(st.elrsr & 1, 0);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn eoi_mode_drop_and_deactivate_invalidates_and_preserves_pending() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Software {
                vintid: 3,
                eoi_maintenance: true,
                priority: 0x20,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
            st.eisr = 1;
            st.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }

        vcpu.handle_maintenance(&hw, &mut |_| {}, &mut |_| {}, &mut |_| {})
            .unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.lrs[0].state(), IrqState::Pending);
            assert!(!st.lrs[0].eoi_maintenance());
            assert_eq!(st.elrsr & 1, 0);
        }

        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Active);
            st.lrs[0].set_eoi_maintenance(true);
            st.elrsr &= !1;
            st.eisr = 1;
            st.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }

        vcpu.handle_maintenance(&hw, &mut |_| {}, &mut |_| {}, &mut |_| {})
            .unwrap();
        let st = hw.state.borrow();
        assert_ne!(st.elrsr & 1, 0);
        assert_eq!(st.lrs[0].state(), IrqState::Inactive);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn uie_toggles_with_pending_work() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        vcpu.enqueue(make_irq(20, 0x10, false, None)).unwrap();
        vcpu.enqueue(make_irq(30, 0x18, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        assert!(hw.state.borrow().hcr_uie);
        // Simulate LR becoming empty to allow refill of remaining pending.
        hw.state.borrow_mut().elrsr |= 1;
        vcpu.refill_lrs(&hw).unwrap();
        assert!(!hw.state.borrow().hcr_uie);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn active_or_hw_entries_not_spilled() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Hardware {
                vintid: 40,
                pintid: 55,
                priority: 0x60,
                group: IrqGroup::Group0,
                state: IrqState::Active,
                source: None,
            };
            st.elrsr &= !1;
        }
        vcpu.enqueue(make_irq(50, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.lrs[0].vintid(), 40);
            assert_eq!(st.apr, 0);
        }
        {
            let mut st = hw.state.borrow_mut();
            st.elrsr |= 1;
            st.lrs[0].set_state(IrqState::Inactive);
        }
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), 50);
        assert!(!st.lrs[0].is_hw());
        assert_eq!(st.apr, 0);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn active_entries_stay_resident() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Software {
                vintid: 10,
                eoi_maintenance: false,
                priority: 0x40,
                group: IrqGroup::Group1,
                state: IrqState::Active,
                source: None,
            };
            st.elrsr &= !1;
        }
        vcpu.enqueue(make_irq(50, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.lrs[0].vintid(), 10);
            assert_eq!(st.lrs[0].state(), IrqState::Active);
        }
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Inactive);
            st.elrsr |= 1;
        }
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), 50);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn software_shadow_reuses_lr_when_elrsr_stale() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = RaceyHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.elrsr = 1; // LR0 appears empty initially.
        }
        vcpu.enqueue(make_irq(1, 0x20, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            // Simulate maintenance for LR0 but keep ELRSR stale (0).
            let mut st = hw.state.borrow_mut();
            st.eisr = 1;
            st.misr = MaintenanceReasons(MaintenanceReasons::EOI);
        }
        vcpu.handle_maintenance(&hw, &mut |_| {}, &mut |_| {}, &mut |_| {})
            .unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.elrsr, 0); // hardware still reports not empty
        }
        vcpu.enqueue(make_irq(2, 0x18, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), 2);
        assert_eq!(st.lrs[0].state(), IrqState::Pending);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn pending_sw_can_be_evicted_by_higher_priority() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Software {
                vintid: 5,
                eoi_maintenance: false,
                priority: 0x60,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
        }
        vcpu.enqueue(make_irq(7, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.lrs[0].vintid(), 7);
        }
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Inactive);
            st.elrsr |= 1;
        }
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), 5);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn hw_entries_not_evicted() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Hardware {
                vintid: 15,
                pintid: 48,
                priority: 0x60,
                group: IrqGroup::Group0,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
        }
        vcpu.enqueue(make_irq(9, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        {
            let st = hw.state.borrow();
            assert_eq!(st.lrs[0].vintid(), 15);
            assert!(st.lrs[0].is_hw());
        }
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0].set_state(IrqState::Inactive);
            st.elrsr |= 1;
        }
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        assert_eq!(st.lrs[0].vintid(), 9);
        assert!(!st.lrs[0].is_hw());
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn hw_entries_not_armed_for_overflow() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(2);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Hardware {
                vintid: 15,
                pintid: 48,
                priority: 0x40,
                group: IrqGroup::Group0,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
        }
        vcpu.enqueue(make_irq(20, 0x10, false, None)).unwrap();
        vcpu.refill_lrs(&hw).unwrap();
        let st = hw.state.borrow();
        // HW==1 LRs must never rely on EOI maintenance (EISR is for HW==0 LRs).
        assert!(st.lrs[0].is_hw());
        assert!(!st.lrs[0].eoi_maintenance());

        // NOTE: `make_irq(20, ...)` is PPI (INTID 16-31), i.e. a *local* interrupt.
        // Local SGI/PPI are *not* armed by default; they only arm EOI-maintenance on overflow.
        assert!(!st.lrs[1].is_hw());
        assert!(!st.lrs[1].eoi_maintenance());
        drop(st);

        // This scenario has at least one empty LR while refilling, so overflow arming must not run.
        let inner = vcpu.inner.lock_irqsave();
        assert!(!inner.overflow_armed);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    fn switch_out_clears_overflow_arming() {
        let vcpu = TestVcpu::with_id(VcpuId(0));
        let hw = FakeHw::new(1);
        vcpu.set_resident(cpu::get_current_core_id()).unwrap();
        // Simulate armed overflow on a SW LR.
        {
            let mut st = hw.state.borrow_mut();
            st.lrs[0] = VirtualInterrupt::Software {
                vintid: 3,
                eoi_maintenance: true,
                priority: 0x20,
                group: IrqGroup::Group1,
                state: IrqState::Pending,
                source: None,
            };
            st.elrsr &= !1;
        }
        {
            let mut inner = vcpu.inner.lock_irqsave();
            inner.in_lr[0] = Some(LrKey {
                vintid: VIntId(3),
                source: None,
            });
            inner.overflow_armed = true;
            inner.resident = Some(cpu::get_current_core_id());
        }
        vcpu.switch_out_sync(&hw).unwrap();
        let st = hw.state.borrow();
        assert!(!st.lrs[0].eoi_maintenance());
    }
}
