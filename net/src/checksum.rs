/// Computes the raw one's-complement sum over a byte slice.
///
/// For odd lengths, the final byte is treated as the high byte of a 16-bit word.
pub fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut idx = 0usize;
    while idx + 1 < data.len() {
        let word = u16::from_be_bytes([data[idx], data[idx + 1]]) as u32;
        sum = sum.wrapping_add(word);
        idx += 2;
    }
    if idx < data.len() {
        let word = u16::from_be_bytes([data[idx], 0]) as u32;
        sum = sum.wrapping_add(word);
    }
    sum
}

/// Folds a 32-bit accumulator into a 16-bit one's-complement sum.
pub fn fold_ones_complement_sum(sum: u32) -> u16 {
    let mut acc = sum;
    while (acc >> 16) != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    acc as u16
}

/// Computes the IPv4 header checksum value to be written into the header field.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    !fold_ones_complement_sum(ones_complement_sum(header))
}

/// Validates an IPv4 header checksum.
///
/// Returns `true` when the folded one's-complement sum equals `0xFFFF`.
pub fn ipv4_header_checksum_is_valid(header: &[u8]) -> bool {
    fold_ones_complement_sum(ones_complement_sum(header)) == 0xFFFF
}
