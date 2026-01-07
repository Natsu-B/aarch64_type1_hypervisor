use core::mem::size_of;
use typestate::Readable;
use typestate::Writable;

mod registers;
use registers::GICD_CTLR;
use registers::GicV3Distributor;
use registers::RWP;

pub struct Gicv3Distributor {
    distributor: &'static GicV3Distributor,
}

impl Gicv3Distributor {
    pub fn new(addr: usize, size: usize) -> Result<Self, GicError> {
        if size != size_of::<GicV3Distributor>() {
            return Err(GicError::InvalidSize);
        }
        Ok(Gicv3Distributor {
            distributor: unsafe { &*(addr as *mut GicV3Distributor) },
        })
    }

    fn spin_rwp(&self) {
        while self
            .distributor
            .ctlr
            .read()
            .get_enum::<_, RWP>(GICD_CTLR::rwp)
            .unwrap()
            == RWP::RegisterWriteInProgress
        {
            core::hint::spin_loop();
        }
    }

    pub fn init(&self) {
        self.distributor.ctlr.write(
            GICD_CTLR::new()
                .set(GICD_CTLR::enable_grp0, 0b0)
                .set(GICD_CTLR::enable_grp1, 0b0),
        );
        self.spin_rwp();
        self.distributor
            .ctlr
            .write(GICD_CTLR::new().set(GICD_CTLR::are, 0b1));
        self.spin_rwp();
        self.distributor
            .ctlr
            .set_bits(GICD_CTLR::new().set(GICD_CTLR::enable_grp1, 0b1));
        self.spin_rwp();
        cpu::dsb_ish();
        cpu::isb();
    }

    pub fn set(
        &self,
        int_id: u32,
        priority: u8,
        trigger_mode: GicTriggerMode,
        pending: bool,
        enable: bool,
    ) -> Result<(), GicError> {
        if int_id < 32 {
            return Err(GicError::UnsupportedINTID);
        }
        // set group
        let reg_idx = int_id >> 5; // int_id / u32::BITS
        let reg_offset = int_id & (u32::BITS - 1);
        // non secure group 1
        self.distributor.igroupr[reg_idx as usize].set_bits(1 << reg_offset);
        self.distributor.igrpmodr[reg_idx as usize].clear_bits(1 << reg_offset);

        // set priority
        let reg_idx = int_id >> 2; // int_id / 4
        let reg_offset = (int_id & 0b11) << 3; // (int_id % 4) * 8
        let mask = 0xff << reg_offset;
        let ipriorityr = self.distributor.ipriorityr[reg_idx as usize].read();
        self.distributor.ipriorityr[reg_idx as usize]
            .write((ipriorityr & !mask) | (priority as u32) << reg_offset);

        // set routing (non rooting mode)
        self.distributor.irouter[int_id as usize].write(cpu::get_current_core_id().to_bits());

        // set trigger mode
        let reg_idx = int_id >> 4; // int_id / (u32::BITS / 2)
        let reg_offset = (int_id & (u32::BITS / 2 - 1)) * 2;
        let mask = 0b11 << reg_offset;
        let config = match trigger_mode {
            GicTriggerMode::LevelSensitive => 0b00,
            GicTriggerMode::EdgeTriggered => 0b10,
        };
        let icfgr = self.distributor.icfgr[reg_idx as usize].read();
        self.distributor.icfgr[reg_idx as usize].write((icfgr & !mask) | config << reg_offset);

        // set pending
        let reg_idx = int_id >> 5; // int_id / u32::BITS
        let reg_offset = int_id & (u32::BITS - 1);
        if pending {
            self.distributor.ispendr[reg_idx as usize].write(1 << reg_offset);
        } else {
            self.distributor.icpendr[reg_idx as usize].write(1 << reg_offset);
        }

        // set enable
        if enable {
            self.distributor.isenabler[reg_idx as usize].write(1 << reg_offset);
        } else {
            self.distributor.icenabler[reg_idx as usize].write(1 << reg_offset);
        }
        cpu::dsb_ish();
        cpu::isb();
        Ok(())
    }
}

pub enum GicTriggerMode {
    LevelSensitive,
    EdgeTriggered,
}

pub enum GicError {
    InvalidSize,
    UnsupportedINTID,
}
