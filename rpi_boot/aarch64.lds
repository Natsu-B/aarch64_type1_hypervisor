OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS {
  text    PT_LOAD FLAGS(0x5);  /* RX */
  rodata  PT_LOAD FLAGS(0x4);  /* R */
  data    PT_LOAD FLAGS(0x6);  /* RW */
  payload PT_LOAD FLAGS(0x4);  /* R  */
}

SECTIONS
{
    . = 0x200000;
    _PROGRAM_START = .;

    .text ALIGN(8) : {
        *(.text.boot)
        *(.text*)
    } :text

    .rodata ALIGN(8) : {
        *(.rodata*)
    } : rodata

    .data ALIGN(8) : {
        *(.data*)
    } :data

    .bss ALIGN(8) : {
        _BSS_START = .;
        *(.bss*)
        . = ALIGN(8);
        _BSS_END = .;
    } :data

    . = . + 0x10000;

    _STACK_TOP = .;

    .img ALIGN(0x2 * 0x1000 * 0x1000) : {
        __linux_image_start = .;
        KEEP(*(.img*))
        . = ALIGN(0x1000);
        __linux_image_end = .;
    } :payload

    _PROGRAM_END = .;
}
