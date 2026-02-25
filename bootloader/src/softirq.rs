use crate::debug;
use crate::gdb_uart;
use arch_hal::cpu;
use core::sync::atomic::Ordering;
use mutex::pod::RawAtomicPod;

pub const EV_UART_RX: u32 = 1 << 0;
pub const EV_GDB_ATTACH_CHECK: u32 = 1 << 1;
pub const EV_UART_POLL_FALLBACK: u32 = 1 << 2;

const DISPATCH_BUDGET: usize = 8;

static PENDING: RawAtomicPod<u32> = unsafe { RawAtomicPod::new_raw_unchecked(0) };
static ENABLED: RawAtomicPod<u32> = unsafe { RawAtomicPod::new_raw_unchecked(0) };
static IN_SOFTIRQ: RawAtomicPod<bool> = unsafe { RawAtomicPod::new_raw_unchecked(false) };

pub fn enable(mask: u32) {
    ENABLED.fetch_or(mask, Ordering::AcqRel);
}

#[allow(dead_code)]
pub fn disable(mask: u32) {
    ENABLED.fetch_and(!mask, Ordering::AcqRel);
}

pub fn pend_from_irq(mask: u32) {
    let bits = mask & ENABLED.load(Ordering::Acquire);
    if bits != 0 {
        PENDING.fetch_or(bits, Ordering::Release);
    }
}

pub fn pend(mask: u32) {
    let bits = mask & ENABLED.load(Ordering::Acquire);
    if bits != 0 {
        PENDING.fetch_or(bits, Ordering::Release);
    }
}

pub fn take_pending() -> u32 {
    PENDING.swap(0, Ordering::AcqRel)
}

pub fn post_exception(regs: &mut cpu::Registers) {
    if IN_SOFTIRQ.swap(true, Ordering::AcqRel) {
        return;
    }

    let saved_daif = cpu::read_daif();
    cpu::enable_irq();

    for _ in 0..DISPATCH_BUDGET {
        let bits = take_pending();
        if bits == 0 {
            break;
        }

        if bits & (EV_UART_RX | EV_UART_POLL_FALLBACK) != 0 {
            gdb_uart::poll_rx();
        }

        if bits & EV_GDB_ATTACH_CHECK != 0 {
            let reason = gdb_uart::take_attach_reason();
            if reason != 0 && !gdb_uart::is_debug_active() {
                debug::enter_debug_from_irq(regs, reason);
            }
        }
    }

    cpu::irq_restore(saved_daif);
    IN_SOFTIRQ.store(false, Ordering::Release);
}
