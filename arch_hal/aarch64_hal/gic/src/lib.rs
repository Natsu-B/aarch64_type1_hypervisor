#![no_std]

use crate::registers::GICD_CTLR;
use crate::registers::GicV3Distributor;
use crate::registers::RWP;
use core::mem::size_of;
use typestate::Readable;
use typestate::Writable;

mod registers;

pub struct GicDistributor {
    distributer: &'static GicV3Distributor,
}

impl GicDistributor {
    pub fn new(addr: usize, size: usize) -> Result<Self, GicErr> {
        if size != size_of::<GicV3Distributor>() {
            return Err(GicErr::InvalidSize);
        }
        Ok(GicDistributor {
            distributer: unsafe { &*(addr as *mut GicV3Distributor) },
        })
    }

    fn spin_rwp(&self) {
        while self
            .distributer
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
        self.distributer.ctlr.write(
            GICD_CTLR::new()
                .set(GICD_CTLR::enable_grp0, 0b0)
                .set(GICD_CTLR::enable_grp1, 0b0),
        );
        self.spin_rwp();
        self.distributer
            .ctlr
            .write(GICD_CTLR::new().set(GICD_CTLR::are, 0b1));
        self.spin_rwp();
        self.distributer
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
    ) -> Result<(), GicErr> {
        if int_id < 32 {
            return Err(GicErr::UnsupportedINTID);
        }
        // set group
        let reg_idx = int_id >> 5; // int_id / u32::BITS
        let reg_offset = int_id & (u32::BITS - 1);
        // non secure group 1
        self.distributer.igroupr[reg_idx as usize].set_bits(1 << reg_offset);
        self.distributer.igrpmodr[reg_idx as usize].clear_bits(1 << reg_offset);

        // set priority
        let reg_idx = int_id >> 2; // int_id / 4
        let reg_offset = (int_id & 0b11) << 3; // (int_id % 4) * 8
        let mask = 0xff << reg_offset;
        let ipriorityr = self.distributer.ipriorityr[reg_idx as usize].read();
        self.distributer.ipriorityr[reg_idx as usize]
            .write((ipriorityr & !mask) | (priority as u32) << reg_offset);

        // set routing (non rooting mode)
        self.distributer.irouter[int_id as usize].write(todo!() /* cpu affinity */);

        // set trigger mode
        let reg_idx = int_id >> 4; // int_id / (u32::BITS / 2)
        let reg_offset = (int_id & (u32::BITS / 2 - 1)) * 2;
        let mask = 0b11 << reg_offset;
        let config = match trigger_mode {
            GicTriggerMode::LevelSensitive => 0b00,
            GicTriggerMode::EdgeTriggered => 0b10,
        };
        let icfgr = self.distributer.icfgr[reg_idx as usize].read();
        self.distributer.icfgr[reg_idx as usize].write((icfgr & !mask) | config << reg_offset);

        // set pending
        let reg_idx = int_id >> 5; // int_id / u32::BITS
        let reg_offset = int_id & (u32::BITS - 1);
        if pending {
            self.distributer.ispendr[reg_idx as usize].write(1 << reg_offset);
        } else {
            self.distributer.icpendr[reg_idx as usize].write(1 << reg_offset);
        }

        // set enable
        if enable {
            self.distributer.isenabler[reg_idx as usize].write(1 << reg_offset);
        } else {
            self.distributer.icenabler[reg_idx as usize].write(1 << reg_offset);
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

pub enum GicErr {
    InvalidSize,
    UnsupportedINTID,
}
