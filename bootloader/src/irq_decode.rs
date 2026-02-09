#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IrqDecodeError {
    UnsupportedCells(usize),
    InvalidType(u32),
}

/// Decode a DT interrupt specifier into a physical INTID.
///
/// For GICv2, the cells are typically:
/// - [type, number, flags]
///   type = 0 (SPI), 1 (PPI)
pub fn dt_irq_to_pintid(cells: &[u32]) -> Result<u32, IrqDecodeError> {
    if cells.len() != 3 {
        return Err(IrqDecodeError::UnsupportedCells(cells.len()));
    }
    let int_type = cells[0];
    let number = cells[1];
    match int_type {
        0 => Ok(number + 32), // SPI IDs start at 32.
        1 => Ok(number + 16), // PPI IDs start at 16.
        _ => Err(IrqDecodeError::InvalidType(int_type)),
    }
}
