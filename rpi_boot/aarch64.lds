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
    . = 0x80000;
    _PROGRAM_START = .;

    .text.boot : {
        *(.text.boot*)
    } : text

    .text ALIGN(8) : {
        *(.text*)
    } :text

    .rodata ALIGN(64) : {
        __el2_tls_start = .;
        KEEP(*(.el2_tls .el2_tls.*))
        __el2_tls_end = .;
        __el2_tls_size = __el2_tls_end - __el2_tls_start;
        *(.rodata*)
    } : rodata

    .data ALIGN(8) : {
        *(.data*)
    } :data

    .bss ALIGN(8) : {
        _BSS_START = .;
        *(.bss*)
        . = ALIGN(64);
        __el2_tls_bsp_start = .;
        . = . + __el2_tls_size;
        __el2_tls_bsp_end = .;
        . = ALIGN(8);
        _BSS_END = .;
    } :data

    . = . + 0x10000;

    _STACK_TOP = .;
    _PROGRAM_END = .;
    . = 0x300000;
    _LINUX_IMAGE = .;
}
