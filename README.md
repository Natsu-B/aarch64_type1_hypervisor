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

## Testing

```sh
cargo xtest
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
