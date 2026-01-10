use core::arch::asm;
use core::num::NonZero;
use core::num::NonZeroU64;
use core::time::Duration;

use cpu;

/// Standard SBSA INTID for the EL2 physical timer interrupt (PPI offset 10 -> INTID 26).
pub const SBSA_EL2_PHYSICAL_TIMER_INTID: u32 = 26; // DT often encodes this as PPI offset 10 (INTID = 16 + 10).

const CNTHP_CTL_ENABLE: u64 = 1 << 0;
const CNTHP_CTL_IMASK: u64 = 1 << 1;
const CNTHP_CTL_ISTATUS: u64 = 1 << 2;

/// EL2 hypervisor physical timer wrapper using the 64-bit comparator (CVAL).
pub struct El2PhysicalTimer {
    counter_frequency: NonZeroU64,
}

impl El2PhysicalTimer {
    /// Read CNTFRQ_EL0 and construct the timer wrapper (panics if zero).
    pub fn new() -> Self {
        let counter_frequency =
            NonZero::new(read_counter_frequency()).expect("CNTFRQ_EL0 must be non-zero");
        Self { counter_frequency }
    }

    /// Return the counter frequency in Hz.
    pub fn counter_frequency_hz(&self) -> NonZeroU64 {
        self.counter_frequency
    }

    /// Sample CNTPCT_EL0 with an ISB beforehand.
    pub fn now(&self) -> u64 {
        read_counter()
    }

    /// Program CNTHP_CVAL_EL2 directly.
    pub fn set_deadline(&self, cval: u64) {
        write_cnthp_cval_el2(cval);
    }

    /// Program a timeout relative to `now()` using CVAL and enable/unmask the timer.
    pub fn set_timeout(&self, duration: Duration) {
        let ticks = duration
            .as_nanos()
            .saturating_mul(u128::from(self.counter_frequency.get()))
            / 1_000_000_000u128;
        let ticks = ticks.min(u128::from(u64::MAX)) as u64;
        let deadline = self.now().saturating_add(ticks);

        self.set_deadline(deadline);
        self.enable();
        self.unmask();
    }

    /// Enable CNTHP.
    pub fn enable(&self) {
        let mut ctl = read_cnthp_ctl_el2();
        ctl |= CNTHP_CTL_ENABLE;
        write_cnthp_ctl_el2(ctl);
    }

    /// Disable CNTHP.
    pub fn disable(&self) {
        let mut ctl = read_cnthp_ctl_el2();
        ctl &= !CNTHP_CTL_ENABLE;
        write_cnthp_ctl_el2(ctl);
    }

    /// Mask CNTHP (IMASK=1).
    pub fn mask(&self) {
        let mut ctl = read_cnthp_ctl_el2();
        ctl |= CNTHP_CTL_IMASK;
        write_cnthp_ctl_el2(ctl);
    }

    /// Unmask CNTHP (IMASK=0).
    pub fn unmask(&self) {
        let mut ctl = read_cnthp_ctl_el2();
        ctl &= !CNTHP_CTL_IMASK;
        write_cnthp_ctl_el2(ctl);
    }

    /// Return true if ISTATUS indicates the timer condition is active.
    pub fn is_firing(&self) -> bool {
        (read_cnthp_ctl_el2() & CNTHP_CTL_ISTATUS) != 0
    }

    /// Re-arm the timer before EOI to clear the level condition and avoid retrigger loops.
    pub fn handle_irq_and_rearm(&self, next: Duration) {
        // Reprogram first so the level condition is cleared before GIC EOI to avoid retrigger loops.
        self.set_timeout(next);
    }

    /// Set CNTVOFF_EL2 to control the virtual counter value seen at EL1/EL0.
    pub fn set_lower_el_virtual_offset(&self, offset: u64) {
        write_cntvoff_el2(offset);
    }

    /// Read CNTVOFF_EL2 (virtual counter offset for lower ELs).
    pub fn lower_el_virtual_offset(&self) -> u64 {
        read_cntvoff_el2()
    }
}

fn read_counter_frequency() -> u64 {
    let current_frequency;
    // SAFETY: Accessing CNTFRQ_EL0 requires executing at EL2 in this project, is read-only, and needs no special ordering.
    unsafe {
        asm!(
            "mrs {current_frequency}, CNTFRQ_EL0",
            current_frequency = out(reg) current_frequency
        );
    }
    current_frequency
}

fn read_counter() -> u64 {
    cpu::isb();
    let counter;
    // SAFETY: Reading CNTPCT_EL0 requires executing at EL2 in this project; the preceding ISB orders the sample and the read has no memory safety impact.
    unsafe {
        asm!("mrs {counter}, CNTPCT_EL0", counter = out(reg) counter);
    }
    counter
}

fn read_cnthp_ctl_el2() -> u64 {
    let ctl;
    // SAFETY: CNTHP_CTL_EL2 is only accessible at EL2, the read is side-effect free, and no extra ordering is required.
    unsafe {
        asm!("mrs {ctl}, CNTHP_CTL_EL2", ctl = out(reg) ctl);
    }
    ctl
}

fn write_cnthp_ctl_el2(val: u64) {
    // SAFETY: Writing CNTHP_CTL_EL2 requires executing at EL2; it only touches timer control bits, and the trailing ISB ensures the new state is observed before continuing.
    unsafe {
        asm!("msr CNTHP_CTL_EL2, {val}", val = in(reg) val);
    }
    cpu::isb();
}

fn write_cnthp_cval_el2(val: u64) {
    // SAFETY: Writing CNTHP_CVAL_EL2 requires executing at EL2; it only programs the comparator, and the trailing ISB makes the new deadline visible before further execution.
    unsafe {
        asm!("msr CNTHP_CVAL_EL2, {val}", val = in(reg) val);
    }
    cpu::isb();
}

fn write_cntvoff_el2(val: u64) {
    // SAFETY: CNTVOFF_EL2 is only writable at EL2; updating it changes the virtual counter view for lower ELs and the trailing ISB makes the new offset visible before continuing.
    unsafe {
        asm!("msr CNTVOFF_EL2, {val}", val = in(reg) val);
    }
    cpu::isb();
}

fn read_cntvoff_el2() -> u64 {
    let offset;
    // SAFETY: CNTVOFF_EL2 is only readable at EL2, reading it has no side effects, and requires no extra ordering.
    unsafe {
        asm!("mrs {offset}, CNTVOFF_EL2", offset = out(reg) offset);
    }
    offset
}
