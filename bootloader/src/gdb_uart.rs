use arch_hal::aarch64_mutex::RawSpinLockIrqSave;
use arch_hal::pl011::FifoLevel;
use arch_hal::pl011::Pl011Uart;
use byte_stream::ByteStream;
use core::convert::Infallible;

const RX_RING_SIZE: usize = 1024;

pub struct GdbUartStream;

struct RxRing<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
}

impl<const N: usize> RxRing<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            tail: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn push_drop_newest(&mut self, byte: u8) -> bool {
        let next = (self.head + 1) % N;
        if next == self.tail {
            // Drop newest when full to keep the oldest buffered data.
            return false;
        }
        self.buf[self.head] = byte;
        self.head = next;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.buf[self.tail];
        self.tail = (self.tail + 1) % N;
        Some(byte)
    }
}

struct GdbUartState<const N: usize> {
    uart: Pl011Uart,
    rx: RxRing<N>,
}

static GDB_UART_STATE: RawSpinLockIrqSave<Option<GdbUartState<RX_RING_SIZE>>> =
    RawSpinLockIrqSave::new(None);

pub fn init(base: usize, clock_hz: u64, baud: u32) {
    let mut uart = Pl011Uart::new(base, clock_hz);
    uart.init(baud);
    uart.enable_rx_interrupts(FifoLevel::OneQuarter, true);
    let state = GdbUartState {
        uart,
        rx: RxRing::new(),
    };
    let mut guard = GDB_UART_STATE.lock_irqsave();
    *guard = Some(state);
}

pub fn handle_irq() {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return;
    };
    state.uart.handle_rx_irq(&mut |byte| {
        let _ = state.rx.push_drop_newest(byte);
    });
}

fn pop_once() -> Option<u8> {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    guard.as_mut()?.rx.pop()
}

fn try_write_byte(byte: u8) -> bool {
    let mut guard = GDB_UART_STATE.lock_irqsave();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.uart.try_write_byte(byte)
}

impl ByteStream for GdbUartStream {
    type Error = Infallible;

    fn try_read(&self) -> Result<Option<u8>, Self::Error> {
        Ok(pop_once())
    }

    fn try_write(&self, byte: u8) -> Result<bool, Self::Error> {
        Ok(try_write_byte(byte))
    }
}
