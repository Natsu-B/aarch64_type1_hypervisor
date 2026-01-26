use crate::vbar::BRK_SLOT_TAG;
use crate::vbar::VBAR_VECTOR_OFFSETS;
use crate::vbar::brk_insn;
use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::cpu;
use arch_hal::cpu::registers::MDSCR_EL1;
use arch_hal::exceptions;
use arch_hal::exceptions::registers::ExceptionClass;
use arch_hal::paging;
use arch_hal::println;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

const PAGE_SIZE: u64 = 0x1000;
const VBAR_ALIGN: u64 = 0x800;
const VBAR_ALIGN_MASK: u64 = VBAR_ALIGN - 1;
const VBAR_PATCH_OFFSETS: [u16; 16] = VBAR_VECTOR_OFFSETS;
const BRK_SLOT_BITS: u16 = 0x000f;

const SPSR_DAIF_D: u64 = 1 << 9;
const SPSR_SS: u64 = 1 << 21;
const SPSR_M_MASK: u64 = 0b1111;
const SPSR_M_EL0T: u64 = 0b0000;
const SPSR_M_EL1T: u64 = 0b0100;
const SPSR_M_EL1H: u64 = 0b0101;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum VbarWatchMode {
    Fgt,
    Poll,
}

impl VbarWatchMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VbarWatchMode::Fgt => "fgt",
            VbarWatchMode::Poll => "poll",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum VbarChangeReason {
    Init,
    Trap,
    Poll,
}

impl VbarChangeReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VbarChangeReason::Init => "init",
            VbarChangeReason::Trap => "trap",
            VbarChangeReason::Poll => "poll",
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct VbarErrorInfo {
    pub(crate) vbar_va: u64,
    pub(crate) reason: &'static str,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct VbarStatusSnapshot {
    pub(crate) enabled: bool,
    pub(crate) mode: VbarWatchMode,
    pub(crate) current_vbar_va: u64,
    pub(crate) current_vbar_ipa: u64,
    pub(crate) pending_repatch: bool,
    pub(crate) last_change_seq: u64,
    pub(crate) last_change_reason: VbarChangeReason,
    pub(crate) last_error: Option<VbarErrorInfo>,
    pub(crate) in_vector_entry_window: bool,
    pub(crate) nested_count: u8,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct VbarTrapSnapshot {
    pub(crate) gprs: [u64; 32],
    pub(crate) esr: u64,
    pub(crate) elr: u64,
    pub(crate) slot_index: u8,
    pub(crate) offset: u16,
    pub(crate) origin_elr_el1: u64,
    pub(crate) origin_spsr_el1: u64,
    pub(crate) origin_esr_el1: u64,
    pub(crate) origin_far_el1: u64,
    pub(crate) origin_sp_el0: u64,
    pub(crate) origin_sp_el1: u64,
    pub(crate) origin_pre_sp: Option<u64>,
    pub(crate) origin_pre_pc: u64,
    pub(crate) nested: bool,
}

#[derive(Copy, Clone, Debug)]
struct StepRestore {
    spsr_d: bool,
    spsr_ss: bool,
    mdscr_ss: bool,
    mdscr_kde: bool,
    mdscr_mde: bool,
}

#[derive(Copy, Clone, Debug)]
struct InternalStep {
    slot: usize,
    restore: StepRestore,
}

struct VbarWatchState {
    enabled: bool,
    mode: VbarWatchMode,
    current_vbar_va: u64,
    current_vbar_ipa: u64,
    current_vbar_ipa_page: u64,
    pending_repatch: bool,
    last_change_seq: u64,
    last_change_reason: VbarChangeReason,
    last_error: Option<VbarErrorInfo>,
    unknown_brk_logged: bool,
    in_vector_entry_window: bool,
    nested_count: u8,
    shadow_insn: [Option<u32>; VBAR_PATCH_OFFSETS.len()],
    is_patched: [bool; VBAR_PATCH_OFFSETS.len()],
    internal_step: Option<InternalStep>,
    last_hit: Option<VbarTrapSnapshot>,
}

impl VbarWatchState {
    const fn new() -> Self {
        Self {
            enabled: false,
            mode: VbarWatchMode::Fgt,
            current_vbar_va: 0,
            current_vbar_ipa: 0,
            current_vbar_ipa_page: 0,
            pending_repatch: false,
            last_change_seq: 0,
            last_change_reason: VbarChangeReason::Init,
            last_error: None,
            unknown_brk_logged: false,
            in_vector_entry_window: false,
            nested_count: 0,
            shadow_insn: [None; VBAR_PATCH_OFFSETS.len()],
            is_patched: [false; VBAR_PATCH_OFFSETS.len()],
            internal_step: None,
            last_hit: None,
        }
    }

    fn clear_patches(&mut self) {
        self.shadow_insn = [None; VBAR_PATCH_OFFSETS.len()];
        self.is_patched = [false; VBAR_PATCH_OFFSETS.len()];
    }
}

static VBAR_STATE: RawSpinLockIrqSave<VbarWatchState> =
    RawSpinLockIrqSave::new(VbarWatchState::new());

const fn pre_exception_sp(spsr_el1: u64, sp_el0: u64, sp_el1: u64) -> Option<u64> {
    match spsr_el1 & SPSR_M_MASK {
        SPSR_M_EL0T => Some(sp_el0),
        SPSR_M_EL1T => Some(sp_el0),
        SPSR_M_EL1H => Some(sp_el1),
        _ => None,
    }
}

pub(crate) fn spsr_el1_mode_label(spsr_el1: u64) -> &'static str {
    match spsr_el1 & SPSR_M_MASK {
        SPSR_M_EL0T => "el0t",
        SPSR_M_EL1T => "el1t",
        SPSR_M_EL1H => "el1h",
        _ => "unknown",
    }
}

pub(crate) fn snapshot_status() -> VbarStatusSnapshot {
    let state = VBAR_STATE.lock_irqsave();
    VbarStatusSnapshot {
        enabled: state.enabled,
        mode: state.mode,
        current_vbar_va: state.current_vbar_va,
        current_vbar_ipa: state.current_vbar_ipa,
        pending_repatch: state.pending_repatch,
        last_change_seq: state.last_change_seq,
        last_change_reason: state.last_change_reason,
        last_error: state.last_error,
        in_vector_entry_window: state.in_vector_entry_window,
        nested_count: state.nested_count,
    }
}

pub(crate) fn last_hit_snapshot() -> Option<VbarTrapSnapshot> {
    let state = VBAR_STATE.lock_irqsave();
    state.last_hit
}

pub(crate) fn clear_last_hit() {
    let mut state = VBAR_STATE.lock_irqsave();
    state.last_hit = None;
}

pub(crate) fn init_vbar_watch() {
    let mut state = VBAR_STATE.lock_irqsave();
    let has_fgt = cpu::has_feat_fgt();
    state.enabled = true;
    state.mode = if has_fgt {
        VbarWatchMode::Fgt
    } else {
        VbarWatchMode::Poll
    };

    if has_fgt {
        cpu::enable_fgt_vbar_el1_write_trap();
    }
    let vbar = cpu::get_vbar_el1();
    if (vbar & VBAR_ALIGN_MASK) != 0 {
        println!("vbar_watch: VBAR_EL1 misaligned: 0x{:X}", vbar);
        record_vbar_error(
            &mut state,
            vbar,
            "vbar_el1_misaligned",
            VbarChangeReason::Init,
        );
        return;
    }
    if let Err(err) = protect_and_patch_vbar_locked(vbar, &mut state) {
        println!("vbar_watch: init failed ({})", err);
        record_vbar_error(&mut state, vbar, err, VbarChangeReason::Init);
        return;
    }

    record_vbar_change(&mut state, VbarChangeReason::Init);
}

pub fn poll_vbar_el1_change() {
    let vbar = cpu::get_vbar_el1();
    let mut state = VBAR_STATE.lock_irqsave();
    if !state.enabled {
        return;
    }
    if state.internal_step.is_some() {
        state.pending_repatch = true;
        return;
    }
    if state.pending_repatch {
        state.pending_repatch = false;
    }
    if vbar == state.current_vbar_va {
        return;
    }
    if (vbar & VBAR_ALIGN_MASK) != 0 {
        record_vbar_error(
            &mut state,
            vbar,
            "vbar_el1_misaligned",
            VbarChangeReason::Poll,
        );
        return;
    }
    match protect_and_patch_vbar_locked(vbar, &mut state) {
        Ok(()) => record_vbar_change(&mut state, VbarChangeReason::Poll),
        Err(err) => record_vbar_error(&mut state, vbar, err, VbarChangeReason::Poll),
    }
}

pub(crate) fn sysreg_trap_handler(
    regs: &mut cpu::Registers,
    info: &exceptions::synchronous_handler::SysRegTrapInfo,
) {
    let iss = info.iss;
    let is_write = iss.direction == exceptions::registers::SysRegDirection::Write;
    let is_vbar = iss.op0 == 3 && iss.op1 == 0 && iss.op2 == 0 && iss.crn == 12 && iss.crm == 0;
    if !is_write || !is_vbar {
        let dir = match iss.direction {
            exceptions::registers::SysRegDirection::Write => "write",
            exceptions::registers::SysRegDirection::Read => "read",
        };
        println!(
            "sysreg trap: unexpected op0={} op1={} op2={} crn={} crm={} rt={} dir={}",
            iss.op0, iss.op1, iss.op2, iss.crn, iss.crm, iss.rt, dir
        );
        panic!("sysreg trap not handled");
    }

    let new_vbar = regs.gpr(iss.rt);
    if (new_vbar & VBAR_ALIGN_MASK) != 0 {
        println!("sysreg trap: VBAR_EL1 misaligned: 0x{:X}", new_vbar);
        panic!("VBAR_EL1 alignment violation");
    }

    cpu::set_vbar_el1(new_vbar);
    {
        let mut state = VBAR_STATE.lock_irqsave();
        if !state.enabled {
            println!("sysreg trap: vbar watch disabled");
            panic!("vbar watch disabled");
        }
        if let Err(err) = protect_and_patch_vbar_locked(new_vbar, &mut state) {
            println!("sysreg trap: protect failed ({})", err);
            panic!("vbar watch failure");
        }
        record_vbar_change(&mut state, VbarChangeReason::Trap);
    }

    cpu::set_elr_el2(cpu::get_elr_el2().wrapping_add(4));
}

pub(crate) fn handle_debug_exception(regs: &mut cpu::Registers, ec: ExceptionClass) -> bool {
    match ec {
        ExceptionClass::BrkInstructionAArch64LowerLevel => handle_vbar_brk(regs),
        ExceptionClass::SoftwareStepLowerLevel => handle_internal_step(),
        _ => false,
    }
}

pub(crate) fn is_vbar_page(ipa: u64) -> bool {
    let state = VBAR_STATE.lock_irqsave();
    state.enabled && state.current_vbar_ipa_page == ipa
}

pub(crate) fn read_vbar_value(ipa: u64, size: usize) -> Option<u64> {
    let mut state = VBAR_STATE.lock_irqsave();
    if !state.enabled || state.current_vbar_ipa_page == 0 {
        return None;
    }
    if (ipa & !(PAGE_SIZE - 1)) != state.current_vbar_ipa_page {
        return None;
    }

    let mut bytes = [0u8; 8];
    for i in 0..size {
        bytes[i] = read_u8_with_shadow(&mut state, ipa + i as u64);
    }
    Some(u64::from_le_bytes(bytes))
}

pub(crate) fn write_vbar_value(ipa: u64, size: usize, value: u64) -> Option<()> {
    let mut state = VBAR_STATE.lock_irqsave();
    if !state.enabled || state.current_vbar_ipa_page == 0 {
        return None;
    }
    if (ipa & !(PAGE_SIZE - 1)) != state.current_vbar_ipa_page {
        return None;
    }

    let bytes = value.to_le_bytes();
    for i in 0..size {
        write_u8_with_shadow(&mut state, ipa + i as u64, bytes[i]);
    }
    Some(())
}

fn record_vbar_change(state: &mut VbarWatchState, reason: VbarChangeReason) {
    state.last_change_seq = state.last_change_seq.saturating_add(1);
    state.last_change_reason = reason;
    state.last_error = None;
    state.pending_repatch = false;
    state.unknown_brk_logged = false;
}

fn record_vbar_error(
    state: &mut VbarWatchState,
    vbar_va: u64,
    reason: &'static str,
    change_reason: VbarChangeReason,
) {
    state.last_error = Some(VbarErrorInfo { vbar_va, reason });
    state.last_change_reason = change_reason;
}

fn protect_and_patch_vbar_locked(
    vbar_el1_va: u64,
    state: &mut VbarWatchState,
) -> Result<(), &'static str> {
    let Some(ipa) = cpu::va_to_ipa_el2_read(vbar_el1_va) else {
        return Err("va_to_ipa_el2_read failed");
    };
    let ipa_page = ipa & !(PAGE_SIZE - 1);
    let base_in_page = ipa & (PAGE_SIZE - 1);
    debug_assert!(base_in_page == 0 || base_in_page == VBAR_ALIGN);
    debug_assert!((base_in_page + 0x780) < PAGE_SIZE);

    if state.current_vbar_ipa == ipa {
        state.current_vbar_va = vbar_el1_va;
        return Ok(());
    }

    if state.current_vbar_ipa != 0 {
        restore_patches(state.current_vbar_ipa, state);
        if state.current_vbar_ipa_page != ipa_page {
            paging::stage2::set_4k_rw(state.current_vbar_ipa_page)
                .map_err(|_| "stage2 rw failed")?;
        }
        state.clear_patches();
        state.internal_step = None;
        state.in_vector_entry_window = false;
    }

    if state.current_vbar_ipa_page != ipa_page {
        paging::stage2::set_4k_exec_only(ipa_page).map_err(|_| "stage2 exec-only failed")?;
    }
    patch_vectors(ipa, state)?;

    state.current_vbar_va = vbar_el1_va;
    state.current_vbar_ipa = ipa;
    state.current_vbar_ipa_page = ipa_page;
    Ok(())
}

fn patch_vectors(ipa_base: u64, state: &mut VbarWatchState) -> Result<(), &'static str> {
    for (slot_idx, offset) in VBAR_PATCH_OFFSETS.iter().enumerate() {
        let offset_u64 = *offset as u64;
        if offset_u64 >= PAGE_SIZE || (offset_u64 & 0x3) != 0 {
            return Err("invalid vector offset");
        }
        let addr = ipa_base + offset_u64;
        let current = read_u32(addr);
        let brk = brk_insn(slot_idx as u16);

        if current != brk {
            if state.shadow_insn[slot_idx].is_none() {
                state.shadow_insn[slot_idx] = Some(current);
            }
            write_u32(addr, brk);
        }

        state.is_patched[slot_idx] = true;
    }
    Ok(())
}

fn restore_patches(ipa_base: u64, state: &mut VbarWatchState) {
    for (slot_idx, offset) in VBAR_PATCH_OFFSETS.iter().enumerate() {
        if !state.is_patched[slot_idx] {
            continue;
        }
        let Some(original) = state.shadow_insn[slot_idx] else {
            continue;
        };
        let addr = ipa_base + *offset as u64;
        write_u32(addr, original);
    }
}

fn handle_vbar_brk(regs: &mut cpu::Registers) -> bool {
    let mut state = VBAR_STATE.lock_irqsave();
    if !state.enabled || state.current_vbar_va == 0 {
        return false;
    }

    let elr = cpu::get_elr_el2();
    let esr = cpu::get_esr_el2();
    let imm16 = (esr & 0xffff) as u16;

    let (slot, offset) = match slot_for_brk(&state, elr, imm16) {
        Some(hit) => hit,
        None => {
            log_unknown_brk(&mut state, elr, imm16);
            return false;
        }
    };

    let Some(original) = state.shadow_insn[slot] else {
        panic!("vbar brk hit without shadow for slot {}", slot);
    };

    let origin_elr_el1 = cpu::get_elr_el1();
    let origin_spsr_el1 = cpu::get_spsr_el1();
    let origin_esr_el1 = cpu::get_esr_el1();
    let origin_far_el1 = cpu::get_far_el1();
    let origin_sp_el0 = cpu::get_sp_el0();
    let origin_sp_el1 = cpu::get_sp_el1();
    let origin_pre_sp = pre_exception_sp(origin_spsr_el1, origin_sp_el0, origin_sp_el1);
    let origin_pre_pc = origin_elr_el1;

    let mut gprs = [0u64; 32];
    gprs.copy_from_slice(regs.gprs());
    let nested = state.in_vector_entry_window;
    if nested {
        state.nested_count = state.nested_count.saturating_add(1);
    } else {
        state.in_vector_entry_window = true;
    }
    state.last_hit = Some(VbarTrapSnapshot {
        gprs,
        esr,
        elr,
        slot_index: slot as u8,
        offset,
        origin_elr_el1,
        origin_spsr_el1,
        origin_esr_el1,
        origin_far_el1,
        origin_sp_el0,
        origin_sp_el1,
        origin_pre_sp,
        origin_pre_pc,
        nested,
    });

    let addr = state.current_vbar_ipa + offset as u64;
    write_u32(addr, original);

    let Some(restore) = enable_internal_single_step() else {
        panic!("failed to enable internal single-step");
    };
    state.internal_step = Some(InternalStep { slot, restore });

    true
}

fn handle_internal_step() -> bool {
    let mut state = VBAR_STATE.lock_irqsave();
    let Some(pending) = state.internal_step.take() else {
        return false;
    };

    disable_internal_single_step(pending.restore);
    state.in_vector_entry_window = false;

    let Some(original) = state.shadow_insn[pending.slot] else {
        panic!("vbar single-step without shadow for slot {}", pending.slot);
    };
    let addr = state.current_vbar_ipa + VBAR_PATCH_OFFSETS[pending.slot] as u64;
    let brk = brk_insn(pending.slot as u16);
    if original != brk {
        write_u32(addr, brk);
    }

    true
}

fn decode_brk_slot(imm16: u16) -> Option<usize> {
    if (imm16 & BRK_SLOT_TAG) == BRK_SLOT_TAG {
        let slot = (imm16 & BRK_SLOT_BITS) as usize;
        if slot < VBAR_PATCH_OFFSETS.len() {
            return Some(slot);
        }
    }
    if imm16 < VBAR_PATCH_OFFSETS.len() as u16 {
        return Some(imm16 as usize);
    }
    None
}

fn elr_in_vbar_range(state: &VbarWatchState, elr: u64) -> bool {
    let base = state.current_vbar_va;
    base != 0 && elr >= base && elr < base + PAGE_SIZE
}

fn log_unknown_brk(state: &mut VbarWatchState, elr: u64, imm16: u16) {
    if state.unknown_brk_logged {
        return;
    }
    if elr_in_vbar_range(state, elr) {
        println!(
            "vbar brk: unexpected imm16=0x{:x} elr_el2=0x{:x}",
            imm16, elr
        );
        state.unknown_brk_logged = true;
    }
}

fn slot_for_brk(state: &VbarWatchState, elr: u64, imm16: u16) -> Option<(usize, u16)> {
    if let Some(slot) = decode_brk_slot(imm16) {
        let offset = VBAR_PATCH_OFFSETS[slot] as u64;
        if state.is_patched[slot] && elr == state.current_vbar_va + offset {
            return Some((slot, VBAR_PATCH_OFFSETS[slot]));
        }
    }

    for (slot, offset) in VBAR_PATCH_OFFSETS.iter().enumerate() {
        if state.is_patched[slot] && elr == state.current_vbar_va + *offset as u64 {
            return Some((slot, *offset));
        }
    }
    None
}

fn read_u8_with_shadow(state: &mut VbarWatchState, addr: u64) -> u8 {
    if let Some((slot, byte_offset)) = slot_for_address(state, addr) {
        let base = state.current_vbar_ipa + VBAR_PATCH_OFFSETS[slot] as u64;
        let word = state.shadow_insn[slot].unwrap_or_else(|| read_u32(base));
        return ((word >> (u32::from(byte_offset) * 8)) & 0xff) as u8;
    }
    read_u8(addr)
}

fn write_u8_with_shadow(state: &mut VbarWatchState, addr: u64, value: u8) {
    if let Some((slot, byte_offset)) = slot_for_address(state, addr) {
        let base = state.current_vbar_ipa + VBAR_PATCH_OFFSETS[slot] as u64;
        let mut word = state.shadow_insn[slot].unwrap_or_else(|| read_u32(base));
        let shift = u32::from(byte_offset) * 8;
        word = (word & !(0xff << shift)) | (u32::from(value) << shift);
        state.shadow_insn[slot] = Some(word);
        return;
    }
    write_u8(addr, value);
}

fn slot_for_address(state: &VbarWatchState, addr: u64) -> Option<(usize, u8)> {
    if addr < state.current_vbar_ipa {
        return None;
    }
    let offset = addr - state.current_vbar_ipa;
    if offset >= PAGE_SIZE {
        return None;
    }
    for (slot, slot_offset) in VBAR_PATCH_OFFSETS.iter().enumerate() {
        let slot_base = *slot_offset as u64;
        if offset >= slot_base && offset < slot_base + 4 {
            return Some((slot, (offset - slot_base) as u8));
        }
    }
    None
}

fn enable_internal_single_step() -> Option<StepRestore> {
    let spsr = cpu::get_spsr_el2();
    let mdscr = cpu::get_mdscr_el1();
    let restore = StepRestore {
        spsr_d: (spsr & SPSR_DAIF_D) != 0,
        spsr_ss: (spsr & SPSR_SS) != 0,
        mdscr_ss: mdscr.get(MDSCR_EL1::ss) != 0,
        mdscr_kde: mdscr.get(MDSCR_EL1::kde) != 0,
        mdscr_mde: mdscr.get(MDSCR_EL1::mde) != 0,
    };

    let new_spsr = (spsr & !SPSR_DAIF_D) | SPSR_SS;
    let new_mdscr = mdscr
        .set(MDSCR_EL1::ss, 1)
        .set(MDSCR_EL1::kde, 1)
        .set(MDSCR_EL1::mde, 1);

    cpu::set_spsr_el2(new_spsr);
    cpu::set_mdscr_el1(new_mdscr);

    let verify_spsr = cpu::get_spsr_el2();
    let verify_mdscr = cpu::get_mdscr_el1();
    let spsr_ok = (verify_spsr & SPSR_DAIF_D) == 0 && (verify_spsr & SPSR_SS) != 0;
    let mdscr_ok = verify_mdscr.get(MDSCR_EL1::ss) != 0
        && verify_mdscr.get(MDSCR_EL1::kde) != 0
        && verify_mdscr.get(MDSCR_EL1::mde) != 0;
    if !(spsr_ok && mdscr_ok) {
        disable_internal_single_step(restore);
        return None;
    }
    Some(restore)
}

fn disable_internal_single_step(restore: StepRestore) {
    let mut spsr = cpu::get_spsr_el2();
    if restore.spsr_d {
        spsr |= SPSR_DAIF_D;
    } else {
        spsr &= !SPSR_DAIF_D;
    }
    if restore.spsr_ss {
        spsr |= SPSR_SS;
    } else {
        spsr &= !SPSR_SS;
    }
    cpu::set_spsr_el2(spsr);

    let mdscr = cpu::get_mdscr_el1()
        .set(MDSCR_EL1::ss, restore.mdscr_ss as u64)
        .set(MDSCR_EL1::kde, restore.mdscr_kde as u64)
        .set(MDSCR_EL1::mde, restore.mdscr_mde as u64);
    cpu::set_mdscr_el1(mdscr);
}

fn read_u8(addr: u64) -> u8 {
    let ptr = addr as *const u8;
    // SAFETY: `ptr` is expected to map guest memory accessible at EL2.
    unsafe { read_volatile(ptr) }
}

fn write_u8(addr: u64, value: u8) {
    let ptr = addr as *mut u8;
    // SAFETY: `ptr` is expected to map guest memory accessible at EL2.
    unsafe {
        write_volatile(ptr, value);
    }
}

fn read_u32(addr: u64) -> u32 {
    let ptr = addr as *const u32;
    // SAFETY: `ptr` is expected to map guest memory accessible at EL2 and be 4-byte aligned.
    unsafe { read_volatile(ptr) }
}

fn write_u32(addr: u64, value: u32) {
    let ptr = addr as *mut u32;
    // SAFETY: `ptr` is expected to map guest memory accessible at EL2 and be 4-byte aligned.
    unsafe {
        write_volatile(ptr, value);
    }
    cpu::sync_icache_pou_for_va_range(ptr as *const u8, core::mem::size_of::<u32>());
}
