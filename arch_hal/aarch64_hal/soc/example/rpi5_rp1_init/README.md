# Raspberry Pi 5 RP1 init validation example

Build:

```sh
cargo check --manifest-path arch_hal/aarch64_hal/soc/example/rpi5_rp1_init/Cargo.toml --target aarch64-unknown-none-softfloat
```

The example emits its validation log through AArch64 semihosting when launched through OpenOCD. This avoids relying on the unavailable UART10 channel during debug-probe validation. It validates the RP1 PCIe setup, BAR mappings, and inbound PCIe DMA window before any UART DMA transaction.

## Full-RC low PCI BAR layout

The BCM2712 full-RC path follows the RP1/Linux low PCI layout:

```text
BAR1 RP1 peripherals : PCI 0x00000000
BAR2 shared SRAM     : PCI 0x00400000
BAR0 MSI-X/table     : PCI 0x00800000
RC outbound          : CPU/AXI 0x1f00000000 -> PCI 0x00000000
```

BAR sizes are still probed and validated before assignment. `BAR1 = 0` is
intentional in this RP1 full-init layout; it is not treated as unassigned. A
read of `0xffffffff` from UART0, DMAC, or GEM through BAR1 means the aperture
is not reachable. The example dumps PCIe/AER state and blocks UART DMA in that
case.

## UART0 DMA DTB discovery

For UART0 DMA discovery, the boot partition `config.txt` must contain:

```text
dtparam=uart0=on
dtparam=uart0_dma=on
```

The Raspberry Pi firmware [overlays README](https://github.com/raspberrypi/firmware/blob/master/boot/overlays/README)
defines `uart0_dma` as enabling DMA usage on UART0 for BCM2712; it is off by default.
The test must use the firmware-generated DTB from that boot, not an unmodified
base DTB. The example logs the UART0 node path, compatible string, `reg`,
`dmas`, and `dma-names`, then obtains TX/RX request IDs from the DTB specifiers.
Linux's known values (`RX=0x19`, `TX=0x1a`) are diagnostic comparisons only.
`dtparam=uart0_dma=on` provides DTB DMA specifiers; it does not establish PCIe
BAR/MMIO reachability. UART DMA is attempted only after BAR1 smoke, bridge,
MSI-X, and DMA-preflight gates pass.

Expected minimum debug UART log:

```text
[rpi5-rp1-init] start
init rp1...
PCIE: ...
[rpi5-rp1-init] RP1 peripheral BAR ...
[rpi5-rp1-init] DMA window ...
[rpi5-rp1-init] DMA PREFLIGHT PASS
[rpi5-rp1-init] BAR1 MMIO smoke PASS
[rpi5-rp1-init] semihosting still alive
[rpi5-rp1-init] PASS
```

Expected additional RP1 UART0 log when the firmware or boot configuration routes UART0 pins:

```text
[rpi5-rp1-init] RP1 UART0 TX PASS
```

If BAR1 smoke fails, the example prints `UART DMA: BLOCKED, BAR1 MMIO aperture
is not reachable` and does not touch UART DMA registers.

No real-hardware log is recorded in this source tree. Run the example on the connected board and retain the captured UART log outside the repository if it includes board-specific data.

The board firmware must leave the BCM2712-to-RP1 PCIe link up (the current project convention is `pciex4_reset = 0`). If the semihost log reports `PcieIsNotInitialized`, the example stops before RP1 UART0 access and DMA preflight; this is a firmware setup failure, not a DMA PASS.

For OpenOCD validation, enable semihosting before loading the ELF:

```gdb
monitor arm semihosting enable
```
