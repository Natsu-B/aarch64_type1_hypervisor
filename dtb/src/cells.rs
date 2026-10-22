//! Big-endian cell encoding helpers shared by the tree builder, patchers, and boot crates.
//!
//! Device-tree integers are stored as sequences of 32-bit big-endian cells. These helpers
//! bounds-check every access and report failures as `&'static str` so callers can propagate
//! them alongside the other DTB editing errors.

/// Reads the big-endian `u32` cell stored at `offset` in `bytes`.
pub fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("dtb: read_be_u32 overflow")?;
    let slice = bytes
        .get(offset..end)
        .ok_or("dtb: read_be_u32 out of bounds")?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Writes `value` as a big-endian `u32` cell at `offset` in `bytes`.
pub fn write_be_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    let end = offset.checked_add(4).ok_or("dtb: write_be_u32 overflow")?;
    let slot = bytes
        .get_mut(offset..end)
        .ok_or("dtb: write_be_u32 out of bounds")?;
    slot.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Writes `value` as `cells` consecutive big-endian `u32` cells starting at `offset`.
///
/// The most significant cell comes first, matching `#address-cells`/`#size-cells` encoding.
/// Cells above the 64 bits carried by `value` are written as zero.
pub fn write_be_u32s(
    bytes: &mut [u8],
    offset: usize,
    cells: usize,
    value: u64,
) -> Result<(), &'static str> {
    for idx in 0..cells {
        let shift = (cells - 1 - idx)
            .checked_mul(32)
            .ok_or("dtb: write_be_u32s shift overflow")?;
        let cell = if shift >= 64 {
            0
        } else {
            ((value >> shift) & 0xffff_ffff) as u32
        };
        let cell_offset = offset
            .checked_add(
                idx.checked_mul(4)
                    .ok_or("dtb: write_be_u32s offset overflow")?,
            )
            .ok_or("dtb: write_be_u32s offset overflow")?;
        write_be_u32(bytes, cell_offset, cell)?;
    }
    Ok(())
}

/// Returns whether the NUL-separated string list `bytes` contains `needle`.
///
/// Empty entries and entries that are not valid UTF-8 never match.
pub fn string_list_contains(bytes: &[u8], needle: &str) -> bool {
    let mut start = 0usize;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| start + i)
            .unwrap_or(bytes.len());
        if end > start
            && let Ok(entry) = core::str::from_utf8(&bytes[start..end])
            && entry == needle
        {
            return true;
        }
        if end == bytes.len() {
            break;
        }
        start = end + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_round_trip() {
        let mut bytes = [0u8; 8];
        write_be_u32(&mut bytes, 4, 0x1234_5678).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(read_be_u32(&bytes, 4).unwrap(), 0x1234_5678);
    }

    #[test]
    fn out_of_bounds_accesses_fail() {
        let mut bytes = [0u8; 6];
        assert!(read_be_u32(&bytes, 3).is_err());
        assert!(write_be_u32(&mut bytes, 3, 0).is_err());
        assert!(read_be_u32(&bytes, usize::MAX).is_err());
    }

    #[test]
    fn write_be_u32s_orders_cells_most_significant_first() {
        let mut bytes = [0xffu8; 12];
        write_be_u32s(&mut bytes, 0, 3, 0x0000_0001_0000_0002).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2]);

        let mut single = [0u8; 4];
        write_be_u32s(&mut single, 0, 1, 0xaaaa_bbbb_cccc_dddd).unwrap();
        assert_eq!(single, [0xcc, 0xcc, 0xdd, 0xdd]);
    }

    #[test]
    fn string_list_matches_whole_entries() {
        let list = b"brcm,bcm2712\0arm,pl011\0";
        assert!(string_list_contains(list, "arm,pl011"));
        assert!(string_list_contains(list, "brcm,bcm2712"));
        assert!(!string_list_contains(list, "arm"));
        assert!(!string_list_contains(list, ""));
        assert!(string_list_contains(b"unterminated", "unterminated"));
    }
}
