const BRK_BASE_INSN: u32 = 0xD420_0000;

/// Vector entry offsets within a 2 KiB-aligned VBAR_EL1 table.
pub(crate) const VBAR_VECTOR_OFFSETS: [u16; 16] = [
    0x000, 0x080, 0x100, 0x180, 0x200, 0x280, 0x300, 0x380, 0x400, 0x480, 0x500, 0x580, 0x600,
    0x680, 0x700, 0x780,
];

/// Encode `brk #imm16` (imm16 in bits [20:5]).
pub(crate) const fn brk_insn(imm16: u16) -> u32 {
    BRK_BASE_INSN | ((imm16 as u32) << 5)
}
