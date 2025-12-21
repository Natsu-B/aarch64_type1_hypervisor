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
_IMAGE_BASE = 0x40400000;
_STACK_SIZE = 0x20000;

SECTIONS
{
  . = _IMAGE_BASE;
  __image_start = .;
  . += SIZEOF_HEADERS;

  .text : ALIGN(_ALIGN_SIZE) {
    *(.text .text.*)
  }

  .data : ALIGN(_ALIGN_SIZE) {
    *(.data .data.*)
  }

  .rodata : ALIGN(_ALIGN_SIZE) {
    *(.rodata .rodata.*)
  }

  .bss (NOLOAD) : ALIGN(_ALIGN_SIZE) {
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    __bss_end = .;
  } :data

  .stack (NOLOAD) : ALIGN(_ALIGN_SIZE) {
    __stack_bottom = .;
    . = . + _STACK_SIZE;
    __stack_top = .;
  } :data

  . = ALIGN(_ALIGN_SIZE);
  __image_end = .;
}
