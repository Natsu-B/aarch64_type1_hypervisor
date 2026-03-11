use crate::bcm2712::Bcm2712Error;
use crate::bcm2712::rp1_interrupt;
use common::PirqHookError;
use common::PirqHookOp;
use core::cell::SyncUnsafeCell;
use core::ptr::slice_from_raw_parts_mut;
use typestate::ReadWrite;

const MIP_SPI_OFFSET: u32 = 128;
const RP1_MSIX_SPI_START: u32 = MIP_SPI_OFFSET + 32;
const RP1_PCIE_CFG_OFFSET: usize = 0x10_8000 + 0x08;
const RP1_PCIE_CFG_LEN: usize = 64;
pub const RP1_UART0_MSIX_INDEX: usize = 25;
pub const RP1_UART0_SPI: u32 = RP1_MSIX_SPI_START + RP1_UART0_MSIX_INDEX as u32;

static RP1_PERIPHERAL_BASE: SyncUnsafeCell<Option<usize>> = SyncUnsafeCell::new(None);

/// # Safety
/// The caller must ensure there is no concurrent access while updating this global state.
/// `Some(base)` must point to a valid, mapped RP1 peripheral MMIO window.
pub(crate) unsafe fn set_rp1_peripheral_base(base: Option<usize>) {
    // SAFETY: Guaranteed by the caller contract above.
    unsafe { *RP1_PERIPHERAL_BASE.get() = base };
}

fn map_bcm2712_error(err: Bcm2712Error) -> PirqHookError {
    match err {
        Bcm2712Error::InvalidWindow
        | Bcm2712Error::InvalidPciHeaderType
        | Bcm2712Error::InvalidSettings => PirqHookError::InvalidInput,
        Bcm2712Error::DtbParseError(_)
        | Bcm2712Error::DtbDeviceNotFound
        | Bcm2712Error::PcieIsNotInitialized
        | Bcm2712Error::UnexpectedDevice(_) => PirqHookError::InvalidState,
    }
}

fn msix_index_from_intid(int_id: u32) -> Result<usize, PirqHookError> {
    let offset = int_id
        .checked_sub(RP1_MSIX_SPI_START)
        .ok_or(PirqHookError::InvalidInput)?;
    let index = usize::try_from(offset).map_err(|_| PirqHookError::InvalidInput)?;
    if index >= RP1_PCIE_CFG_LEN {
        return Err(PirqHookError::InvalidInput);
    }
    Ok(index)
}

fn rp1_msix_iack(int_id: u32) -> Result<(), PirqHookError> {
    let index = msix_index_from_intid(int_id)?;
    // SAFETY: The base is written during RP1 init and then treated as immutable runtime
    // configuration while hooks are active.
    let peripheral_base =
        unsafe { *RP1_PERIPHERAL_BASE.get() }.ok_or(PirqHookError::InvalidState)?;
    let pcie_cfg_base = peripheral_base
        .checked_add(RP1_PCIE_CFG_OFFSET)
        .ok_or(PirqHookError::InvalidState)?;

    // SAFETY: The RP1 peripheral base is captured from DT-backed RP1 init, and `index` has
    // already been bounds-checked against the fixed config-window entry count.
    let pcie_config = unsafe {
        &*slice_from_raw_parts_mut(pcie_cfg_base as *mut ReadWrite<u32>, RP1_PCIE_CFG_LEN)
    };
    pcie_config[index].set_bits(0b0100);
    Ok(())
}

pub fn pirq_hook(int_id: u32, op: PirqHookOp) -> Result<(), PirqHookError> {
    if int_id != RP1_UART0_SPI {
        return Ok(());
    }

    match op {
        PirqHookOp::Enable { enable } => {
            if enable {
                rp1_interrupt::enable_interrupt(int_id)
            } else {
                rp1_interrupt::disable_interrupt(int_id)
            }
            .map_err(map_bcm2712_error)?;
            Ok(())
        }
        PirqHookOp::Eoi => rp1_msix_iack(int_id),
        PirqHookOp::Route { .. } | PirqHookOp::Deactivate | PirqHookOp::Resample => Ok(()),
    }
}
