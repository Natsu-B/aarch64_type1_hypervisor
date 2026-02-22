use crate::IrqSense;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DtGicIrqError {
    UnsupportedCells(usize),
    InvalidType(u32),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DtGicIrq {
    pub intid: u32,
    pub flags: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DtIrqDecodeError {
    UnsupportedCells(usize),
    InvalidType(u32),
    InvalidFlags(u32),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DtIrq {
    pub intid: u32,
    pub sense: IrqSense,
}

/// Decode a GICv2 DT interrupt specifier and keep raw flags.
///
/// Accepts only the 3-cell form `[type, number, flags]`:
/// - `type=0` => SPI, `intid=number+32`
/// - `type=1` => PPI, `intid=number+16`
pub fn decode_gicv2_irq(cells: &[u32]) -> Result<DtGicIrq, DtGicIrqError> {
    if cells.len() != 3 {
        return Err(DtGicIrqError::UnsupportedCells(cells.len()));
    }
    let int_type = cells[0];
    let number = cells[1];
    let flags = cells[2];

    let intid = match int_type {
        0 => number + 32,
        1 => number + 16,
        _ => return Err(DtGicIrqError::InvalidType(int_type)),
    };

    Ok(DtGicIrq { intid, flags })
}

/// Decode a DT interrupt specifier into a physical INTID and edge/level sense.
///
/// For GICv2, the cells are typically:
/// - [type, number, flags]
///   type = 0 (SPI), 1 (PPI)
pub fn decode_dt_irq(cells: &[u32]) -> Result<DtIrq, DtIrqDecodeError> {
    let parsed = decode_gicv2_irq(cells).map_err(|err| match err {
        DtGicIrqError::UnsupportedCells(len) => DtIrqDecodeError::UnsupportedCells(len),
        DtGicIrqError::InvalidType(t) => DtIrqDecodeError::InvalidType(t),
    })?;
    let sense = dt_irq_flags_to_sense(parsed.flags)?;
    Ok(DtIrq {
        intid: parsed.intid,
        sense,
    })
}

pub fn dt_irq_flags_to_sense(flags: u32) -> Result<IrqSense, DtIrqDecodeError> {
    // DT interrupt flags follow Linux IRQ_TYPE_* definitions in the low nibble.
    let trig = flags & 0x0f;
    match trig {
        0x0 => Ok(IrqSense::Level),
        0x1 | 0x2 | 0x3 => Ok(IrqSense::Edge),
        0x4 | 0x8 => Ok(IrqSense::Level),
        _ => Err(DtIrqDecodeError::InvalidFlags(flags)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(not(target_arch = "aarch64"), test)]
    fn decode_gicv2_spi_irq() {
        let irq = decode_gicv2_irq(&[0, 45, 4]).unwrap();
        assert_eq!(irq.intid, 77);
        assert_eq!(irq.flags, 4);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(not(target_arch = "aarch64"), test)]
    fn decode_gicv2_ppi_irq() {
        let irq = decode_gicv2_irq(&[1, 9, 1]).unwrap();
        assert_eq!(irq.intid, 25);
        assert_eq!(irq.flags, 1);
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(not(target_arch = "aarch64"), test)]
    fn decode_gicv2_reject_unsupported_cells() {
        assert_eq!(
            decode_gicv2_irq(&[0, 1]).unwrap_err(),
            DtGicIrqError::UnsupportedCells(2)
        );
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(not(target_arch = "aarch64"), test)]
    fn decode_gicv2_reject_invalid_type() {
        assert_eq!(
            decode_gicv2_irq(&[2, 1, 0]).unwrap_err(),
            DtGicIrqError::InvalidType(2)
        );
    }
}
