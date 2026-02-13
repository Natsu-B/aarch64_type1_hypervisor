use crate::IrqSense;

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

/// Decode a DT interrupt specifier into a physical INTID and edge/level sense.
///
/// For GICv2, the cells are typically:
/// - [type, number, flags]
///   type = 0 (SPI), 1 (PPI)
pub fn decode_dt_irq(cells: &[u32]) -> Result<DtIrq, DtIrqDecodeError> {
    if cells.len() != 3 {
        return Err(DtIrqDecodeError::UnsupportedCells(cells.len()));
    }
    let int_type = cells[0];
    let number = cells[1];
    let flags = cells[2];

    let intid = match int_type {
        0 => number + 32, // SPI IDs start at 32.
        1 => number + 16, // PPI IDs start at 16.
        _ => return Err(DtIrqDecodeError::InvalidType(int_type)),
    };

    let sense = dt_irq_flags_to_sense(flags)?;
    Ok(DtIrq { intid, sense })
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

    #[test]
    fn decode_spi_level_high() {
        let irq = decode_dt_irq(&[0, 25, 4]).unwrap();
        assert_eq!(irq.intid, 32 + 25);
        assert_eq!(irq.sense, IrqSense::Level);
    }

    #[test]
    fn decode_spi_edge_rising() {
        let irq = decode_dt_irq(&[0, 3, 1]).unwrap();
        assert_eq!(irq.intid, 32 + 3);
        assert_eq!(irq.sense, IrqSense::Edge);
    }

    #[test]
    fn decode_ppi_edge_both() {
        let irq = decode_dt_irq(&[1, 7, 3]).unwrap();
        assert_eq!(irq.intid, 16 + 7);
        assert_eq!(irq.sense, IrqSense::Edge);
    }
}
