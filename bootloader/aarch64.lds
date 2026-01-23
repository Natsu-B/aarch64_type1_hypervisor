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
  _PROGRAM_START = .;
  . = . + SIZEOF_HEADERS;

  .text : ALIGN(_ALIGN_SIZE) {
    *(.text .text.*)
  }

  .data : ALIGN(_ALIGN_SIZE) {
    *(.data .data.*)
  }

  .rodata : ALIGN(_ALIGN_SIZE) {
    *(.rodata .rodata.*)
  }

  .bss : ALIGN(_ALIGN_SIZE) {
    _BSS_START = .;
    *(.bss .bss.*)
    _BSS_END = .;
  }

  .got : ALIGN(_ALIGN_SIZE) {
    *(.got .got.*)
  }
  _PROGRAM_END = .;

  _STACK_BOTTOM = _PROGRAM_END;
  . = 0x50000000;
  _STACK_TOP = .;

  ASSERT(_PROGRAM_START < _PROGRAM_END, "PROGRAM range invalid")
  ASSERT(_BSS_START <= _BSS_END, "BSS range invalid")
  ASSERT(_PROGRAM_END <= _STACK_BOTTOM, "PROGRAM overlaps STACK")
  ASSERT((_STACK_TOP & 0xF) == 0, "STACK_TOP not 16-byte aligned")
}
