OUTPUT_FORMAT(elf64-aarch64)
ENTRY(_start)

PHDRS
{
    headers PT_PHDR PHDRS;
    text PT_LOAD FILEHDR PHDRS;
    rodata PT_LOAD;
    data PT_LOAD;
}

_ALIGN_SIZE = 0x1000;
_RAM_BASE   = 0x40400000;

SECTIONS {
  . = _RAM_BASE;
  __ram_start = _RAM_BASE;
  _PROGRAM_START = .;
  . = . + SIZEOF_HEADERS;

  .el1_text : ALIGN(_ALIGN_SIZE) {
    __el1_region_start = .;
    __el1_text_start = .;
    KEEP(*(.text.el1_exceptions .text.el1_exceptions.*))
    KEEP(*(.text.el1 .text.el1.*))
    __el1_text_end = .;
  }

  .el1_rodata : ALIGN(_ALIGN_SIZE) {
    __el1_rodata_start = .;
    KEEP(*(.rodata.el1_exceptions .rodata.el1_exceptions.*))
    KEEP(*(.rodata.el1 .rodata.el1.*))
    __el1_rodata_end = .;
  }

  __el1_region_end = .;

  .text : ALIGN(_ALIGN_SIZE) {
    __text_start = .;
    *(.text .text.*)
    __text_end = .;
  }

  .data : ALIGN(_ALIGN_SIZE) {
    __data_start = .;
    *(.data .data.*)
    __data_end = .;
  }

  .rodata : ALIGN(_ALIGN_SIZE) {
    __rodata_start = .;
    *(.rodata .rodata.*)
    __rodata_end = .;
  }

  .bss : ALIGN(_ALIGN_SIZE) {
    __bss_start = .;
    _BSS_START = .;
    *(.bss .bss.*)
    _BSS_END = .;
    __bss_end = .;
  }

  .got : ALIGN(_ALIGN_SIZE) {
    *(.got .got.*)
  }
  _PROGRAM_END = .;

  _STACK_BOTTOM = _PROGRAM_END;
  __stack_start = _STACK_BOTTOM;
  . = 0x80000000;
  _STACK_TOP = .;
  __stack_end = _STACK_TOP;
  __ram_end = __stack_end;

  ASSERT(_PROGRAM_START < _PROGRAM_END, "PROGRAM range invalid")
  ASSERT(_BSS_START <= _BSS_END, "BSS range invalid")
  ASSERT(_PROGRAM_END <= _STACK_BOTTOM, "PROGRAM overlaps STACK")
  ASSERT(_STACK_BOTTOM + 0x10000 <= _STACK_TOP, "STACK shortage")
  ASSERT((_STACK_TOP & 0xF) == 0, "STACK_TOP not 16-byte aligned")
  ASSERT(__text_start >= __ram_start && __text_end <= __ram_end, "text out of RAM")
  ASSERT(__rodata_start >= __ram_start && __rodata_end <= __ram_end, "rodata out of RAM")
  ASSERT(__data_start >= __ram_start && __data_end <= __ram_end, "data out of RAM")
  ASSERT(__bss_start >= __ram_start && __bss_end <= __ram_end, "bss out of RAM")
  ASSERT(__bss_end <= __stack_start, "bss overlaps stack")
  ASSERT(__stack_end <= __ram_end, "stack out of RAM")
  ASSERT((__stack_start & 0xF) == 0, "stack not 16-byte aligned")
  ASSERT((__stack_end & 0xF) == 0, "stack not 16-byte aligned")
}
