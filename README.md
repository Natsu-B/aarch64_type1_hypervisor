# aarch64_type1_hypervisor

[![CI](https://github.com/Natsu-B/aarch64_type1_hypervisor/actions/workflows/check.yml/badge.svg)](https://github.com/Natsu-B/aarch64_type1_hypervisor/actions/workflows/check.yml)
[![Pages](https://github.com/Natsu-B/aarch64_type1_hypervisor/actions/workflows/publish-branches.yml/badge.svg)](https://natsu-b.github.io/aarch64_type1_hypervisor/)

A Rust `no_std` AArch64 Type-1 (thin) hypervisor + bootloader that is launched by U-Boot (`bootelf`) and boots a single Linux guest.
This project is WIP and targets QEMU `virt` and Raspberry Pi 5.

## Repository commands

This workspace provides cargo aliases:

```sh
cargo xbuild  # build (copies artifacts into ./bin)
cargo xrun    # run on QEMU (build + run.sh)
cargo xtest   # run all tests (std + UEFI/QEMU + U-Boot/QEMU)
```

## Toolchain

* Rust nightly (see `rust-toolchain.toml`)
* `rust-src` component is required (build uses `-Z build-std`)
* Target: `aarch64-unknown-none-softfloat`

## Quick start: QEMU `virt` (U-Boot + virtio-blk)

### 0) Prerequisites (host)

Typical required tools:

* `qemu-system-aarch64`, `dtc`
* `sudo`, `sfdisk`, `losetup`, `mkfs.vfat`, `mount`, `dd` (used by `run.sh`)

### 1) Build U-Boot + boot script

```sh
./u-boot/init.sh
```

This generates:

* `./bin/u-boot.bin`
* `./bin/boot.scr`

### 2) Build guest Linux artifacts via Docker (Buildroot)

Add `./create_linux_bin.sh` (Docker-based helper) and run:

```sh
chmod +x ./create_linux_bin.sh
./create_linux_bin.sh           # default Buildroot version
# or
./create_linux_bin.sh 2025.05   # explicit version
```

Outputs:

* `./bin/Image`  (Linux kernel Image)
* `./bin/DISK0`  (rootfs image, copied from Buildroot `rootfs.ext2`)

### 3) Generate a DTB with bootargs

```sh
./setup.sh
```

This dumps QEMU’s DTB and writes a modified DTB:

* `./bin/qemu_mod.dtb`

### 4) Run the hypervisor

```sh
cargo xrun
```

What happens:

* `cargo xrun` builds the `elf-hypervisor` package and copies `elf-hypervisor.elf` into `./bin/`
* `run.sh` creates `./bin/disk.img` with:
  * p1: FAT32 (contains `elf-hypervisor.elf`, `u-boot.bin`, `boot.scr`, `Image`, `qemu.dtb`)
  * p2: raw rootfs written from `./bin/DISK0`
* QEMU is launched with GICv3 enabled and GDB stub on `tcp::1234`

### Debug (GDB)

QEMU is started with:

```sh
-gdb tcp::1234   # add "-S" in run.sh if you want to stop at reset
```

## Raspberry Pi 5

```sh
cargo xrun rpi5
```

This builds `rpi_boot.elf` and converts it to `kernel_2712.img` using `rust-objcopy`.
Copy the resulting `kernel_2712.img` to your Pi boot media as appropriate.

For local development with the repository toolchain, use the Nix shell explicitly if `cargo`
is not already on `PATH`:

```sh
/nix/var/nix/profiles/default/bin/nix develop --accept-flake-config --command cargo xrun rpi5
```

The generated Pi 5 firmware image is:

```sh
bin/kernel_2712.img
```

Copy that file to the Pi 5 boot partition as `kernel_2712.img`, then power-cycle or reset the
board so the firmware starts it from reset. This is the preferred execution path for `rpi_boot`;
loading `bin/rpi_boot.elf` over OpenOCD after Linux or another EL2 payload is already running can
leave the MMU/cache state enabled and jump back into the existing high virtual address space.

To start the local OpenOCD server for inspection:

```sh
./run.sh
```

This opens the OpenOCD command port on `4444` and CPU GDB ports starting at `3333`. If OpenOCD
reports stale debug state or secondary-core `DSCR_DTR_RX_FULL` errors, stop OpenOCD and do a real
board reset before retrying. The helper below toggles USB hub power for the default hub location:

```sh
./reboot.sh 3
```

If your Pi is connected through a different controllable hub, override the hub location:

```sh
LOCATION=1-1 ./reboot.sh 5
```

Use `sudo uhubctl` to list controllable hubs and connected debug/UART adapters. Note that toggling
the hub containing only the debug probe resets the probe, not necessarily the Pi board itself; for a
clean boot test, reset or power-cycle the Pi 5 power input or boot media path.

## CM5 RP1 GEM wire-level TX validation

The `rpi5_rp1_init` example validates the RP1 Cadence GEM transmit path. ELF load success is
not Ethernet validation success, and `[rp1-gem] TX broadcast PASS` alone establishes only local
GEM descriptor/MAC-side completion. A wire-level TX PASS requires both the target-side markers
and receipt of the generated frame by the directly connected host NIC.

Run the capture from the repository root. `enp2s0` is the interface used by the latest validated
CM5 setup; choose the interface that is physically cabled to the CM5 on another host setup.

1. Bring up the host interface:

   ```sh
   sudo ip link set enp2s0 up
   ```

2. Start the capture before booting the validator. Run it in a separate terminal or background it
   so it remains active while the target runs:

   ```sh
   sudo timeout 180s tcpdump -i enp2s0 -e -n -XX 'ether proto 0x88b5' > host-tcpdump.log 2>&1
   ```

3. Follow the delayed `force-boot` procedure in `$HOME/README.md`, then start OpenOCD only after
   that delay has elapsed.

4. Do not start GDB until all of the following are true:

   * OpenOCD logged `SWD DPIDR 0x2ba01477`.
   * OpenOCD detected `bcm2712.cpu0`.
   * OpenOCD logged `Listening on port 3333 for gdb connections`.
   * `ss` shows `:3333` in `LISTEN` state.

5. Load the `rpi5_rp1_init` ELF with direct `gdb-multiarch`, rather than a loader helper. Enable
   semihosting before `load` and `continue` when required:

   ```gdb
   target remote :3333
   monitor arm semihosting enable
   load
   continue
   ```

The required target-side evidence is:

```text
[rpi5-rp1-init] BAR1 MMIO smoke PASS
[rpi5-rp1-init] DMA PREFLIGHT PASS
[rp1-gem] PHY addr ... id ...
[rp1-gem] link up Mbps1000 full duplex
[rp1-gem] TX broadcast PASS
[rpi5-rp1-init] BAR/DMA/Ethernet validation PASS
```

The host capture must show a frame whose source is the MAC logged by the validator, whose
destination is `ff:ff:ff:ff:ff:ff`, whose EtherType is `0x88b5`, whose length is 60, and whose
payload contains repeated `0xa5` bytes. Only the combination of this capture and the target-side
markers is a wire-level TX PASS. It validates the GEM DMA descriptor path, MAC transmit path,
PHY link, Ethernet cable, and host NIC receive path. It does not validate RP1 GEM RX descriptors,
ARP/IP, interrupt-driven networking, Linux guest integration, or sustained bidirectional traffic.

Latest validated example (logs are deliberately retained outside this repository):

```text
Host interface: enp2s0
Source MAC: 2c:cf:67:c2:9a:58
Destination MAC: ff:ff:ff:ff:ff:ff
EtherType: 0x88b5
Length: 60
Link: 1000 Mbps full duplex
Result: Host wire RX PASS
Log directory: /opt/rpi-cm5-hack/logs/20260623-135901-rp1-gem-wire-rx/
```

## Raspberry Pi 5 UART0 Input

RP1 UART0 input is handled by the RP1 pIRQ hook as a level MSI-X source. The `rpi_boot`
exception handler reports generic passthrough-MMIO completion and IRQ resample points, while the
RP1 hook owns the source-specific PL011 status/completion checks and MSI-X IACK/reissue.

## Testing

```sh
cargo xtest
cargo xtest --help  # show filtering options and arg forwarding
cargo xtest -p gdb_remote -t uefi_packet_size  # filter xtest.txt by package and test name (UEFI/U-Boot)
```

The test plan is defined in `xtest.txt`:

* `std` unit tests for selected crates
* UEFI/QEMU tests for:
  * virtio-blk
  * FAT32(sudo required)
  * `gdb_remote` handshake

* U-Boot/QEMU tests for:
  * paging stage-1 / stage-2 translation
  * gic v2

## Workspace layout

* `bootloader` (`elf-hypervisor`): QEMU path entry; sets up EL2 and boots Linux at EL1
* `rpi_boot`: Raspberry Pi 5 entry
* `arch_hal`: AArch64 HAL (paging, exceptions, PL011, PSCI, timer, GIC)
* `dtb`, `elf`: parsers/helpers used by boot paths
* `file` + `virtio`: virtio-blk and FAT32 helper stack
* `gdb_remote`: `no_std` IRQ-driven GDB RSP engine
* `allocator`, `mutex`, `typestate`, `intrusive_linked_list`: low-level runtime building blocks
