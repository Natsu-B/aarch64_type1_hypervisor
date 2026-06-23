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

The RP1 controller uses the Synopsys AXI DMAC CFG2 channel layout (`dma-targets
= 64`). The TX test places the DTB TX request in CFG2 `dst_per` and translates
UART0 DR from its CPU BAR alias to the RP1 local DMA address
`0xc040030000`. A successful DMA completion is distinct from observing bytes
on external UART pins; capture those separately when validating physical UART
wiring.

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

## RP1 GEM wire-level TX validation

The Ethernet part of this example has two distinct success levels:

* `[rp1-gem] TX broadcast PASS` is local RP1 GEM TX descriptor/MAC-side success.
* A matching host `tcpdump` frame is wire-level TX success. ELF load and the local marker alone
  do not prove that a frame left the CM5 and reached the host NIC.

Before launching this validator, bring up the directly connected host interface and start a capture
in a separate terminal:

```sh
sudo ip link set enp2s0 up
sudo tcpdump -i enp2s0 -e -n -XX 'ether proto 0x88b5'
```

Use the delayed CM5 `force-boot` and OpenOCD procedure from `$HOME/README.md`. Do not attach
direct `gdb-multiarch` until OpenOCD has logged `SWD DPIDR 0x2ba01477`, detected
`bcm2712.cpu0`, reported its port-3333 listener, and `ss` confirms `:3333` is listening. Enable
semihosting before `load` and `continue` when required.

For the latest validated configuration, the host capture included:

```text
2c:cf:67:c2:9a:58 > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x88b5), length 60
```

Its payload was repeated `0xa5` bytes. The source MAC must match the example's
`[rp1-gem] using MAC ...` marker. The target must also report BAR1 smoke and DMA preflight PASS,
a PHY ID, `link up Mbps1000 full duplex`, `[rp1-gem] TX broadcast PASS`, and the final
`BAR/DMA/Ethernet validation PASS` marker. This proves GEM DMA TX, MAC TX, PHY link, cable, and
host-NIC reception only; it does not claim RX descriptor, ARP/IP, interrupt, guest, or sustained
traffic support.

## RP1 GEM RX validation

TX validation does not establish that RP1 GEM can receive a host frame. The RX stage runs after
the broadcast TX test and emits an RX-ready marker containing the exact destination MAC. Send the
following deterministic unicast test frame only after that marker appears:

```text
destination: MAC printed by [rp1-gem] RX test ready
source:      02:48:4f:53:54:01
EtherType:   0x88b5
payload:     RP1-GEM-RX-TEST
length:      60 bytes excluding FCS
```

The local, standard-library-only sender is outside this repository:

```sh
sudo /opt/rpi-cm5-hack/scripts/send-rp1-gem-rx.py \
  --interface enp2s0 \
  --destination <MAC-from-RX-ready-marker> \
  --log-dir /opt/rpi-cm5-hack/logs/<timestamp>-rp1-gem-rx
```

The validator polls `Rp1Gem::try_recv_frame()` at one millisecond intervals for at most 30 seconds.
It requires the complete 60-byte unicast frame, checks both MAC addresses, EtherType, and the
payload marker, and fails on descriptor errors or oversized frames. Reflected broadcast traffic
from the preceding TX test is explicitly rejected as a test frame and recorded, while the bounded
wait continues for the required host unicast.

RX success requires both markers:

```text
[rp1-gem] RX test frame PASS
[rpi5-rp1-init] Ethernet RX validation PASS
```

A full polling Ethernet smoke requires the prior TX markers and these RX markers. The validated
CM5 run received the unicast `02:48:4f:53:54:01 > 2c:cf:67:c2:9a:58`, EtherType `0x88b5`, length
60, with payload `RP1-GEM-RX-TEST`. It establishes host TX through the cable/PHY/MAC/DMA RX
descriptor path into `try_recv_frame()`; it does not claim ARP/IP, interrupt-driven networking,
Linux guest integration, or sustained bidirectional traffic.
