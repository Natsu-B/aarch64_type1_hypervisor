#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RspFrameEvent {
    Ignore,
    NeedMore,
    Resync,
    CtrlC,
    FrameComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RspFrameByteKind {
    None,
    Payload,
    Checksum,
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
        self.push_with_kind(byte).0
    }

    pub(crate) fn push_with_kind(&mut self, byte: u8) -> (RspFrameEvent, RspFrameByteKind) {
        match self.state {
            RspFrameState::Idle => match byte {
                b'$' => {
                    self.state = RspFrameState::InFrame;
                    (RspFrameEvent::NeedMore, RspFrameByteKind::None)
                }
                0x03 => {
                    self.state = RspFrameState::Idle;
                    (RspFrameEvent::CtrlC, RspFrameByteKind::None)
                }
                _ => (RspFrameEvent::Ignore, RspFrameByteKind::None),
            },
            RspFrameState::InFrame => match byte {
                b'$' => {
                    self.state = RspFrameState::InFrame;
                    (RspFrameEvent::Resync, RspFrameByteKind::None)
                }
                b'#' => {
                    self.state = RspFrameState::Checksum(0);
                    (RspFrameEvent::NeedMore, RspFrameByteKind::None)
                }
                _ => (RspFrameEvent::NeedMore, RspFrameByteKind::Payload),
            },
            RspFrameState::Checksum(count) => {
                if byte == b'$' {
                    self.state = RspFrameState::InFrame;
                    return (RspFrameEvent::Resync, RspFrameByteKind::None);
                }
                if count == 0 {
                    self.state = RspFrameState::Checksum(1);
                    (RspFrameEvent::NeedMore, RspFrameByteKind::Checksum)
                } else {
                    self.state = RspFrameState::Idle;
                    (RspFrameEvent::FrameComplete, RspFrameByteKind::Checksum)
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
