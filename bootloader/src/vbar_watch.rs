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

const SPSR_DAIF_D: u64 = 1 << 9;
const SPSR_SS: u64 = 1 << 21;

#[derive(Copy, Clone, Debug)]
struct VbarTrapSnapshot {
    gprs: [u64; 32],
    esr: u64,
    elr: u64,
    slot_index: u8,
    offset: u16,
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
    current_vbar_va: u64,
    current_vbar_ipa: u64,
    current_vbar_ipa_page: u64,
    shadow_insn: [Option<u32>; VBAR_PATCH_OFFSETS.len()],
    is_patched: [bool; VBAR_PATCH_OFFSETS.len()],
    internal_step: Option<InternalStep>,
    last_hit: Option<VbarTrapSnapshot>,
}

impl VbarWatchState {
    const fn new() -> Self {
        Self {
            enabled: false,
            current_vbar_va: 0,
            current_vbar_ipa: 0,
            current_vbar_ipa_page: 0,
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

pub(crate) fn init_vbar_watch() {
    let mut state = VBAR_STATE.lock_irqsave();
    if !cpu::has_feat_fgt() {
        state.enabled = false;
        return;
    }

    cpu::enable_fgt_vbar_el1_write_trap();
    let vbar = cpu::get_vbar_el1();
    if (vbar & VBAR_ALIGN_MASK) != 0 {
        println!("vbar_watch: VBAR_EL1 misaligned: 0x{:X}", vbar);
        state.enabled = false;
        return;
    }
    if let Err(err) = protect_and_patch_vbar_locked(vbar, &mut state) {
        println!("vbar_watch: init failed ({})", err);
        state.enabled = false;
        return;
    }

    state.enabled = true;
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
        None => return false,
    };

    let Some(original) = state.shadow_insn[slot] else {
        panic!("vbar brk hit without shadow for slot {}", slot);
    };

    let mut gprs = [0u64; 32];
    gprs.copy_from_slice(regs.gprs());
    state.last_hit = Some(VbarTrapSnapshot {
        gprs,
        esr,
        elr,
        slot_index: slot as u8,
        offset,
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

fn slot_for_brk(state: &VbarWatchState, elr: u64, imm16: u16) -> Option<(usize, u16)> {
    if imm16 < VBAR_PATCH_OFFSETS.len() as u16 {
        let slot = imm16 as usize;
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
