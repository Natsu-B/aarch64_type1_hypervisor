#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RspFrameEvent {
    Ignore,
    NeedMore,
    Resync,
    CtrlC,
    FrameComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RspFrameState {
    Idle,
    InFrame,
    Checksum(u8),
}

pub struct RspFrameAssembler {
    state: RspFrameState,
}

impl RspFrameAssembler {
    pub const fn new() -> Self {
        Self {
            state: RspFrameState::Idle,
        }
    }

    pub fn reset(&mut self) {
        self.state = RspFrameState::Idle;
    }

    pub fn push(&mut self, byte: u8) -> RspFrameEvent {
        match self.state {
            RspFrameState::Idle => match byte {
                b'$' => {
                    self.state = RspFrameState::InFrame;
                    RspFrameEvent::NeedMore
                }
                0x03 => {
                    self.state = RspFrameState::Idle;
                    RspFrameEvent::CtrlC
                }
                _ => RspFrameEvent::Ignore,
            },
            RspFrameState::InFrame => match byte {
                b'$' => {
                    self.state = RspFrameState::InFrame;
                    RspFrameEvent::Resync
                }
                b'#' => {
                    self.state = RspFrameState::Checksum(0);
                    RspFrameEvent::NeedMore
                }
                _ => RspFrameEvent::NeedMore,
            },
            RspFrameState::Checksum(count) => {
                if byte == b'$' {
                    self.state = RspFrameState::InFrame;
                    return RspFrameEvent::Resync;
                }
                if count == 0 {
                    self.state = RspFrameState::Checksum(1);
                    RspFrameEvent::NeedMore
                } else {
                    self.state = RspFrameState::Idle;
                    RspFrameEvent::FrameComplete
                }
            }
        }
    }
}

impl Default for RspFrameAssembler {
    fn default() -> Self {
        Self::new()
    }
}
