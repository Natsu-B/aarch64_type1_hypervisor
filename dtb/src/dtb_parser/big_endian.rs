use core::ffi::CStr;
use core::ffi::c_char;
use core::marker::PhantomData;
use core::mem::align_of;
use core::mem::size_of;

use typestate::Be;

use super::types::Unchecked;
use super::types::Validated;
use crate::pr_debug;

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<FdtProperty>() == 8);
const _: () = assert!(size_of::<FdtReserveEntry>() == 16);

const DTB_VERSION: u32 = 17;
const DTB_HEADER_MAGIC: u32 = 0xd00d_feed;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FtdHeader {
    magic: Be<u32>,
    total_size: Be<u32>,
    off_dt_struct: Be<u32>,
    off_dt_strings: Be<u32>,
    off_mem_rsvmap: Be<u32>,
    version: Be<u32>,
    last_comp_version: Be<u32>,
    boot_cpuid_phys: Be<u32>,
    size_dt_strings: Be<u32>,
    size_dt_struct: Be<u32>,
}

impl FtdHeader {
    pub fn magic(&self) -> u32 {
        self.magic.read()
    }

    pub fn total_size(&self) -> u32 {
        self.total_size.read()
    }

    pub fn struct_offset(&self) -> u32 {
        self.off_dt_struct.read()
    }

    pub fn strings_offset(&self) -> u32 {
        self.off_dt_strings.read()
    }

    pub fn mem_rsvmap_offset(&self) -> u32 {
        self.off_mem_rsvmap.read()
    }

    pub fn version(&self) -> u32 {
        self.version.read()
    }

    pub fn last_comp_version(&self) -> u32 {
        self.last_comp_version.read()
    }

    pub fn boot_cpuid_phys(&self) -> u32 {
        self.boot_cpuid_phys.read()
    }

    pub fn strings_size(&self) -> u32 {
        self.size_dt_strings.read()
    }

    pub fn struct_size(&self) -> u32 {
        self.size_dt_struct.read()
    }

    pub fn write_string_offset(&mut self, offset: u32) {
        self.off_dt_strings.write(offset);
    }

    pub fn write_struct_offset(&mut self, offset: u32) {
        self.off_dt_struct.write(offset);
    }

    pub fn write_total_size(&mut self, size: u32) {
        self.total_size.write(size);
    }
}

#[repr(C)]
pub struct FdtProperty {
    property_len: Be<u32>,
    name_offset: Be<u32>,
}

impl FdtProperty {
    pub fn len(&self) -> u32 {
        self.property_len.read()
    }

    pub fn name_offset(&self) -> u32 {
        self.name_offset.read()
    }

    pub fn get_property_len(&self) -> u32 {
        self.len()
    }

    pub fn get_name_offset(&self) -> u32 {
        self.name_offset()
    }
}

#[repr(C)]
pub struct FdtReserveEntry {
    address: Be<u64>,
    size: Be<u64>,
}

impl FdtReserveEntry {
    pub fn address(&self) -> u64 {
        self.address.read()
    }

    pub fn size(&self) -> u64 {
        self.size.read()
    }

    pub fn get_address(ptr: usize) -> u64 {
        unsafe { &*(ptr as *const Self) }.address()
    }

    pub fn get_size(ptr: usize) -> u64 {
        unsafe { &*(ptr as *const Self) }.size()
    }

    pub fn write_address(&mut self, addr: u64) {
        self.address.write(addr);
    }

    pub fn write_size(&mut self, size: u64) {
        self.size.write(size);
    }
}

pub struct Dtb<State> {
    fdt_base: usize,
    header: FtdHeader,
    _state: PhantomData<State>,
}

impl Dtb<Unchecked> {
    pub fn new_unchecked(address: usize) -> Result<Self, &'static str> {
        if address % core::mem::align_of::<FtdHeader>() != 0 {
            return Err("dtb: unaligned fdt address");
        }
        let header = unsafe { *(address as *const FtdHeader) };
        Ok(Self {
            fdt_base: address,
            header,
            _state: PhantomData,
        })
    }

    pub fn validate(self) -> Result<Dtb<Validated>, &'static str> {
        if self.header.magic() != DTB_HEADER_MAGIC {
            return Err("dtb: invalid magic");
        }
        pr_debug!("dtb last_comp_version: {}", self.header.last_comp_version());
        if self.header.last_comp_version() > DTB_VERSION {
            return Err("dtb: incompatible version");
        }
        if self.header.struct_offset() as usize % align_of::<FdtProperty>() != 0 {
            return Err("dtb: unaligned struct offset");
        }
        if self.header.strings_offset() as usize % align_of::<u32>() != 0 {
            return Err("dtb: unaligned strings offset");
        }
        if self.header.mem_rsvmap_offset() as usize % align_of::<FdtReserveEntry>() != 0 {
            return Err("dtb: unaligned memreserve offset");
        }
        Ok(Dtb {
            fdt_base: self.fdt_base,
            header: self.header,
            _state: PhantomData,
        })
    }
}

impl Dtb<Validated> {
    pub fn new(address: usize) -> Result<Self, &'static str> {
        Dtb::<Unchecked>::new_unchecked(address)?.validate()
    }
}

impl<State> Dtb<State> {
    pub fn fdt_base(&self) -> usize {
        self.fdt_base
    }

    pub fn total_size(&self) -> u32 {
        self.header.total_size()
    }

    pub fn struct_offset(&self) -> usize {
        self.header.struct_offset() as usize
    }

    pub fn strings_offset(&self) -> usize {
        self.header.strings_offset() as usize
    }

    pub fn mem_rsvmap_offset(&self) -> usize {
        self.header.mem_rsvmap_offset() as usize
    }

    pub fn struct_size(&self) -> usize {
        self.header.struct_size() as usize
    }

    pub fn strings_size(&self) -> usize {
        self.header.strings_size() as usize
    }

    pub fn struct_start(&self) -> usize {
        self.fdt_base + self.struct_offset()
    }

    pub fn struct_end(&self) -> usize {
        self.struct_start() + self.struct_size()
    }

    pub fn strings_start(&self) -> usize {
        self.fdt_base + self.strings_offset()
    }

    pub fn strings_end(&self) -> usize {
        self.strings_start() + self.strings_size()
    }

    pub fn mem_rsvmap_start(&self) -> usize {
        self.fdt_base + self.mem_rsvmap_offset()
    }

    pub fn read_cstr_from_strings(&self, name_offset: usize) -> Result<&'static str, &'static str> {
        let addr = self
            .strings_start()
            .checked_add(name_offset)
            .ok_or("strings: overflow")?;
        let s = unsafe { CStr::from_ptr(addr as *const c_char) };
        s.to_str().map_err(|_| "strings: invalid utf8")
    }

    pub fn read_u32_be(ptr: usize) -> u32 {
        unsafe { &*(ptr as *const Be<u32>) }.read()
    }

    pub fn read_regs(ptr: usize, cells: u32) -> Result<(usize, usize), &'static str> {
        let mut value = 0usize;
        let mut consumed = 0usize;
        for _ in 0..cells {
            value <<= 32;
            value += Self::read_u32_be(ptr + consumed) as usize;
            consumed = consumed
                .checked_add(size_of::<u32>())
                .ok_or("regs: overflow")?;
        }
        Ok((value, consumed))
    }

    pub fn get_fdt_address(&self) -> usize {
        self.fdt_base()
    }

    pub fn get_memory_reservation_offset(&self) -> usize {
        self.mem_rsvmap_offset()
    }

    pub fn get_total_size(&self) -> u32 {
        self.total_size()
    }

    pub fn get_version(&self) -> u32 {
        self.header.version()
    }

    pub fn get_last_comp_version(&self) -> u32 {
        self.header.last_comp_version()
    }

    pub fn get_boot_cpuid_phys(&self) -> u32 {
        self.header.boot_cpuid_phys()
    }

    pub fn get_struct_start_address(&self) -> usize {
        self.struct_start()
    }

    pub fn get_struct_end_address(&self) -> usize {
        self.struct_end()
    }

    pub fn get_struct_size(&self) -> usize {
        self.struct_size()
    }

    pub fn get_string_start_address(&self) -> usize {
        self.strings_start()
    }

    pub fn get_string_end_address(&self) -> usize {
        self.strings_end()
    }

    pub fn get_string_size(&self) -> usize {
        self.strings_size()
    }

    pub fn get_memory_reservation_start_address(&self) -> usize {
        self.mem_rsvmap_start()
    }

    pub fn read_char_str(address: usize) -> Result<&'static str, &'static str> {
        let s = unsafe { CStr::from_ptr(address as *const c_char) };
        s.to_str().map_err(|_| "strings: invalid utf8")
    }
}
