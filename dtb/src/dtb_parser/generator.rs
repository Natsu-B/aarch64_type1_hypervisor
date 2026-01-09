use core::iter::once;
use core::mem::size_of;
use core::ptr;

use super::big_endian::FdtProperty;
use super::big_endian::FdtReserveEntry;
use super::parser::DtbParser;

pub struct DtbGenerator<'a> {
    parser: &'a DtbParser,
}

impl<'a> DtbGenerator<'a> {
    pub fn new(parser: &'a DtbParser) -> Self {
        Self { parser }
    }

    pub fn get_required_size(&self, num_mem_reserved: usize) -> (usize, usize) {
        (
            self.parser.dtb_header().total_size() as usize
                + num_mem_reserved * size_of::<FdtReserveEntry>(),
            8,
        )
    }

    pub fn make_dtb(
        &self,
        dtb: &mut [u8],
        reserved_memory: &[(usize, usize)],
        strip_initrd: bool,
    ) -> Result<(), &'static str> {
        if dtb.len() < self.get_required_size(reserved_memory.len()).0 {
            return Err("dtb: buffer too small");
        }

        unsafe {
            ptr::copy(
                self.parser.dtb_header().fdt_base() as *const u8,
                dtb.as_mut_ptr(),
                self.parser.dtb_header().mem_rsvmap_offset(),
            );
        }

        let mut src = self.parser.dtb_header().mem_rsvmap_start();
        let mut dst = dtb.as_ptr() as usize + self.parser.dtb_header().mem_rsvmap_offset();

        while {
            let a = FdtReserveEntry::get_address(src);
            let s = FdtReserveEntry::get_size(src);
            !(a == 0 && s == 0)
        } {
            unsafe {
                ptr::copy(
                    src as *const u8,
                    dst as *mut u8,
                    size_of::<FdtReserveEntry>(),
                )
            };
            src += size_of::<FdtReserveEntry>();
            dst += size_of::<FdtReserveEntry>();
        }

        for (addr, size) in reserved_memory.iter().chain(once(&(0, 0))) {
            let entry = unsafe { &mut *(dst as *mut FdtReserveEntry) };
            entry.write_address(*addr as u64);
            entry.write_size(*size as u64);
            dst += size_of::<FdtReserveEntry>();
        }

        let struct_start = dst;
        unsafe {
            ptr::copy(
                self.parser.dtb_header().struct_start() as *const u8,
                dst as *mut u8,
                self.parser.dtb_header().struct_size(),
            );
        }
        if strip_initrd {
            self.strip_initrd(struct_start, self.parser.dtb_header().struct_size())?;
        }

        let struct_off = struct_start - dtb.as_ptr() as usize;
        dst = (dst + self.parser.dtb_header().struct_size()).next_multiple_of(4);

        unsafe {
            ptr::copy(
                self.parser.dtb_header().strings_start() as *const u8,
                dst as *mut u8,
                self.parser.dtb_header().strings_size(),
            );
        }
        let strings_off = dst - dtb.as_ptr() as usize;

        let hdr = unsafe { &mut *(dtb.as_mut_ptr() as *mut super::big_endian::FtdHeader) };
        hdr.write_struct_offset(struct_off as u32);
        hdr.write_string_offset(strings_off as u32);
        hdr.write_total_size((strings_off + self.parser.dtb_header().strings_size()) as u32);

        Ok(())
    }

    fn strip_initrd(&self, struct_base: usize, struct_size: usize) -> Result<(), &'static str> {
        let mut cursor = struct_base;
        let end = struct_base + struct_size;

        let mut depth: usize = 0;
        let mut in_chosen = false;

        while cursor < end {
            match DtbParser::token_at(cursor) {
                t if t == DtbParser::FDT_NOP => {
                    cursor += DtbParser::TOKEN_SIZE;
                }
                t if t == DtbParser::FDT_BEGIN_NODE => {
                    cursor += DtbParser::TOKEN_SIZE;
                    let (name, name_len) = self.parser.read_cstr_in_range(cursor, end)?;
                    let padded = name_len.next_multiple_of(4);
                    depth += 1;
                    if depth == 2 && name == "chosen" {
                        in_chosen = true;
                    }
                    cursor += padded;
                }
                t if t == DtbParser::FDT_PROP => {
                    let prop_start = cursor;
                    cursor += DtbParser::TOKEN_SIZE;

                    if cursor + size_of::<FdtProperty>() > end {
                        return Err("strip_initrd: prop hdr overrun");
                    }
                    let prop = unsafe { &*(cursor as *const FdtProperty) };
                    cursor += size_of::<FdtProperty>();

                    let name = self
                        .parser
                        .dtb_header()
                        .read_cstr_from_strings(prop.name_offset() as usize)?;
                    let len = prop.len() as usize;
                    let padded = len.next_multiple_of(4);
                    let total = DtbParser::TOKEN_SIZE + size_of::<FdtProperty>() + padded;

                    if in_chosen && (name == "linux,initrd-start" || name == "linux,initrd-end") {
                        let mut p = prop_start;
                        while p < prop_start + total {
                            unsafe {
                                ptr::copy_nonoverlapping(
                                    DtbParser::FDT_NOP.as_ptr(),
                                    p as *mut u8,
                                    DtbParser::TOKEN_SIZE,
                                );
                            }
                            p += DtbParser::TOKEN_SIZE;
                        }
                    }

                    cursor += padded;
                }
                t if t == DtbParser::FDT_END_NODE => {
                    cursor += DtbParser::TOKEN_SIZE;
                    if in_chosen && depth == 2 {
                        in_chosen = false;
                    }
                    depth = depth.saturating_sub(1);
                }
                t if t == DtbParser::FDT_END => break,
                _ => return Err("strip_initrd: unknown token"),
            }
        }

        Ok(())
    }
}
