#![no_std]

pub mod gicv3;

pub use gicv3::GicDistributor;
pub use gicv3::GicErr;
pub use gicv3::GicTriggerMode;
