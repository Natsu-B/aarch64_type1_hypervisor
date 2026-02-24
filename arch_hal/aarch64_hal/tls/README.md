# EL2 TLS linker requirements

The `tls` crate places per-CPU variables in the `.el2_tls` section. Linker scripts must:

- define `__el2_tls_start` and `__el2_tls_end`,
- `KEEP(*(.el2_tls .el2_tls.*))` so the template is not garbage-collected,
- keep the TLS region within `.rodata` and aligned to at least 64 bytes.

In-tree scripts already containing this stanza:

- `bootloader/aarch64.lds`
- `rpi_boot/aarch64.lds`
- `test.lds`

When adding a new target/linker script, copy the same block ahead of the general `.rodata*` entries.
