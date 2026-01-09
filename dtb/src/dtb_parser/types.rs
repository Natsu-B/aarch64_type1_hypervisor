use core::mem::size_of;

use typestate::Be;

/// DTB header is present but not validated.
#[derive(Clone, Copy, Debug)]
pub struct Unchecked;

/// DTB header validated (magic/version/alignment).
#[derive(Clone, Copy, Debug)]
pub struct Validated;

#[derive(Clone, Copy)]
pub(crate) struct NodeScope {
    pub(crate) begin: usize,
    pub(crate) end: usize,
}

pub(crate) const TOKEN_SIZE: usize = 4;
pub(crate) const DTB_ALIGN: usize = 4;

pub(crate) fn read_u32_be(bytes: &[u8]) -> Result<u32, &'static str> {
    if bytes.len() != size_of::<u32>() {
        return Err("expected 4 bytes");
    }
    let be = unsafe { &*(bytes.as_ptr() as *const Be<u32>) };
    Ok(be.read())
}

/// Read big-endian N-cells (u32) into usize. Returns (value, consumed_bytes).
pub(crate) fn read_regs_from_bytes(
    bytes: &[u8],
    cells: u32,
) -> Result<(usize, usize), &'static str> {
    let cell_count = usize::try_from(cells).map_err(|_| "regs: cell count overflow")?;
    let needed = cell_count
        .checked_mul(size_of::<u32>())
        .ok_or("regs: size overflow")?;
    if bytes.len() < needed {
        return Err("regs: overrun");
    }

    let mut value = 0usize;
    for chunk in bytes[..needed].chunks_exact(size_of::<u32>()) {
        let word = read_u32_be(chunk)? as usize;
        value = (value << 32) | word;
    }
    Ok((value, needed))
}
