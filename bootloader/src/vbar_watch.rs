use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::cpu;
use arch_hal::exceptions;
use arch_hal::paging;
use arch_hal::println;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

const PAGE_SIZE: u64 = 0x1000;
const VBAR_ALIGN_MASK: u64 = 0x7ff; // 2 KiB alignment requirement.
const BRK_INSN: u32 = 0xD420_0000;
// Patch "Current EL using SPx" synchronous and SError entries (EL1h common case).
const VBAR_PATCH_OFFSETS: [u64; 2] = [0x200, 0x280];

#[derive(Copy, Clone, Debug)]
struct PatchEntry {
    offset: u64,
    original: u32,
}

struct VbarWatchState {
    enabled: bool,
    current_vbar_el1: u64,
    current_vbar_ipa_page: u64,
    patches: [Option<PatchEntry>; VBAR_PATCH_OFFSETS.len()],
}

impl VbarWatchState {
    const fn new() -> Self {
        Self {
            enabled: false,
            current_vbar_el1: 0,
            current_vbar_ipa_page: 0,
            patches: [None; VBAR_PATCH_OFFSETS.len()],
        }
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

pub(crate) fn is_vbar_page(ipa: u64) -> bool {
    let state = VBAR_STATE.lock_irqsave();
    state.enabled && state.current_vbar_ipa_page == ipa
}

fn protect_and_patch_vbar_locked(
    vbar_el1_va: u64,
    state: &mut VbarWatchState,
) -> Result<(), &'static str> {
    let Some(ipa) = cpu::va_to_ipa_el2_read(vbar_el1_va) else {
        return Err("va_to_ipa_el2_read failed");
    };
    let ipa_page = ipa & !(PAGE_SIZE - 1);

    if state.current_vbar_ipa_page == ipa_page {
        state.current_vbar_el1 = vbar_el1_va;
        return Ok(());
    }

    if state.current_vbar_ipa_page != 0 {
        restore_patches(state.current_vbar_ipa_page, &state.patches);
        paging::stage2::set_4k_rw(state.current_vbar_ipa_page).map_err(|_| "stage2 rw failed")?;
        state.patches = [None; VBAR_PATCH_OFFSETS.len()];
    }

    paging::stage2::set_4k_exec_only(ipa_page).map_err(|_| "stage2 exec-only failed")?;
    patch_vectors(ipa_page, state)?;

    state.current_vbar_el1 = vbar_el1_va;
    state.current_vbar_ipa_page = ipa_page;
    Ok(())
}

fn patch_vectors(ipa_page: u64, state: &mut VbarWatchState) -> Result<(), &'static str> {
    for (slot, offset) in state
        .patches
        .iter_mut()
        .zip(VBAR_PATCH_OFFSETS.iter().copied())
    {
        if offset >= PAGE_SIZE || (offset & 0x3) != 0 {
            return Err("invalid vector offset");
        }
        let addr = ipa_page + offset;
        let ptr = addr as *mut u32;
        // SAFETY: `ptr` points to the guest vector page mapped into EL2; offsets are 4-byte aligned.
        let original = unsafe { read_volatile(ptr) };
        *slot = Some(PatchEntry { offset, original });
        // SAFETY: same as above; we are overwriting one instruction word.
        unsafe {
            write_volatile(ptr, BRK_INSN);
        }
        cpu::clean_dcache_poc(addr as usize, core::mem::size_of::<u32>());
        cpu::invalidate_icache_range(addr as usize, core::mem::size_of::<u32>());
    }
    Ok(())
}

fn restore_patches(ipa_page: u64, patches: &[Option<PatchEntry>; VBAR_PATCH_OFFSETS.len()]) {
    for patch in patches.iter().flatten() {
        let addr = ipa_page + patch.offset;
        let ptr = addr as *mut u32;
        // SAFETY: restoring original instruction words in the guest vector page.
        unsafe {
            write_volatile(ptr, patch.original);
        }
        cpu::clean_dcache_poc(addr as usize, core::mem::size_of::<u32>());
        cpu::invalidate_icache_range(addr as usize, core::mem::size_of::<u32>());
    }
}
