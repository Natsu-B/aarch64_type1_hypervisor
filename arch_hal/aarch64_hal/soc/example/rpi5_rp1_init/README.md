# Raspberry Pi 5 RP1 init validation example

Build:

```sh
cargo check --manifest-path arch_hal/aarch64_hal/soc/example/rpi5_rp1_init/Cargo.toml --target aarch64-unknown-none-softfloat
```

The example emits its validation log through AArch64 semihosting when launched through OpenOCD. This avoids relying on the unavailable UART10 channel during debug-probe validation. It validates the firmware-provided RP1 PCIe setup, resolves RP1 BAR mappings, verifies the inbound PCIe DMA window, and writes a PL011 message through RP1 UART0 at BAR offset `0x30000`.

Expected minimum debug UART log:

```text
[rpi5-rp1-init] start
init rp1...
PCIE: ...
[rpi5-rp1-init] RP1 peripheral BAR ...
[rpi5-rp1-init] DMA window ...
[rpi5-rp1-init] DMA PREFLIGHT PASS
[rpi5-rp1-init] UART DMA SKIP: missing verified RP1 DMA controller registers, DREQ IDs, and channel completion status
[rpi5-rp1-init] semihosting still alive
[rpi5-rp1-init] PASS
```

Expected additional RP1 UART0 log when the firmware or boot configuration routes UART0 pins:

```text
[rpi5-rp1-init] RP1 UART0 TX PASS
```

UART DMA is intentionally skipped. This repository does not yet contain verified RP1 DMA controller base offsets, channel register layout, UART DREQ IDs, FIFO DMA semantics, or completion status definitions.

No real-hardware log is recorded in this source tree. Run the example on the connected board and retain the captured UART log outside the repository if it includes board-specific data.

The board firmware must leave the BCM2712-to-RP1 PCIe link up (the current project convention is `pciex4_reset = 0`). If the semihost log reports `PcieIsNotInitialized`, the example stops before RP1 UART0 access and DMA preflight; this is a firmware setup failure, not a DMA PASS.

For OpenOCD validation, enable semihosting before loading the ELF:

```gdb
monitor arm semihosting enable
```
