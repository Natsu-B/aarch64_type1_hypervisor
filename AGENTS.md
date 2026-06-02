# Repository Guidelines

## Project Structure & Module Organization

This is a Rust `no_std` workspace for an AArch64 type-1 hypervisor targeting QEMU `virt` and Raspberry Pi boards. Root crates are listed in `Cargo.toml`. Main boot paths live in `bootloader/` (`elf-hypervisor` for QEMU/U-Boot) and `rpi_boot/` (Raspberry Pi entry). Hardware and platform support is split into `arch_hal/`, `pci/`, `virtio/`, `dtb/`, and `elf/`. Runtime utilities live in `allocator/`, `mutex/`, `typestate/`, and `intrusive_linked_list/`. Tests are usually in per-crate `tests/` directories; integration assets and scripts include `u-boot/`, `run.sh`, `create_linux_bin.sh`, and `xtest.txt`.

## Build, Test, and Development Commands

Use the cargo aliases from `.cargo/config.toml`:

```sh
cargo xbuild          # build and copy artifacts into ./bin
cargo xrun            # build, prepare disk image, and run QEMU
cargo xrun rpi5       # build Raspberry Pi 5 kernel_2712.img
cargo xbuild rpi4     # build Raspberry Pi 4 target
cargo xtest           # run std, UEFI/QEMU, and U-Boot/QEMU tests
cargo xtest --help    # show xtest filters and forwarding options
```

For CI-equivalent local runs, prefer `nix develop --accept-flake-config --command <cmd>`. Initialize firmware before boot tests: `git submodule update --init --recursive && (cd u-boot && ./init.sh)`.

For Raspberry Pi 5 hardware runs, `cargo xrun rpi5` only builds `bin/kernel_2712.img`; copy that image to the Pi boot partition and boot it from firmware reset. If `cargo` is not on `PATH`, use `/nix/var/nix/profiles/default/bin/nix develop --accept-flake-config --command cargo xrun rpi5`. The repository root `run.sh` is the QEMU runner and should not be repurposed for hardware. Pi 5 hardware helpers live under `scripts/rpi5-hw/`:

```sh
scripts/rpi5-hw/reboot-usb-hub.sh 10   # optional USB hub power cycle; LOCATION=<hub> overrides
scripts/rpi5-hw/openocd.sh             # starts OpenOCD, CPU0 GDB on :3333
scripts/rpi5-hw/load-gdb.sh            # loads bin/rpi_boot.elf and continues
scripts/rpi5-hw/serial-login-test.sh   # waits for ttyAMA0 login and tests UART0 input
```

Avoid treating OpenOCD ELF injection as the normal boot path: loading `bin/rpi_boot.elf` after Linux or another EL2 payload is already running can leave MMU/cache state enabled and jump back into the existing high virtual address space. For reset troubleshooting, `scripts/rpi5-hw/reboot-usb-hub.sh 10` toggles the default USB hub power and `LOCATION=<hub>` can target another controllable hub; verify hub topology with `sudo uhubctl`. Toggling a hub that contains only the debug probe resets the probe, not necessarily the Pi board, so use a real Pi power-cycle/reset for clean boot tests.

## Coding Style & Naming Conventions

The workspace uses Rust nightly with `rust-src` and target `aarch64-unknown-none-softfloat` from `rust-toolchain.toml`. Format with `cargo fmt --all`; CI checks `cargo fmt --all -- --check`. `rustfmt.toml` sets `imports_granularity = "Item"`. Workspace lints warn on `clippy::pedantic`, `missing_docs`, and missing crate-level docs, so document public APIs and important private items. Keep crate, module, and file names in `snake_case`.

## Testing Guidelines

Tests are driven by `xtask` and `xtest.txt`. Place Rust integration tests under each crate’s `tests/` directory, as in `gdb_remote/tests/` and `net/tests/`. Use descriptive test names that match filterable behavior, for example `uefi_packet_size` or `net_udp_ipv4`. Run targeted tests with `cargo xtest -p gdb_remote -t uefi_packet_size` when iterating, then run `cargo xtest` before submitting.

## TODO: Raspberry Pi 5 UART0 Input

Linux console and input must stay on RP1 UART0 (`ttyAMA0`). Hypervisor-only output uses RP1 UART1.
The current working fix keeps UART0 input alive by explicitly rearming the RP1 UART0 MSI-X source
from the `rpi_boot` MMIO/IRQ path. Treat this as hardware-integration debt, not as the final model.

Observed history:

* The `rpi_boot-rp1-uart0-irq-loop` tag proved that physical UART0 input works on this board when
  the Linux image placement is adjusted to the current linker layout.
* Pi 5 `uart0-pi5` leaves GPIO14/15 function select bits as `0x04`; using `0x10` breaks UART0.
* When input stalls, PL011 RX/MIS can be asserted while the host GIC has no pending SPI 185.
  Manually writing the RP1 MSI-X IACK entry for source 25 makes SPI 185 pending and input proceeds.
* Moving only the IACK calls into the existing pIRQ `Eoi`/`Resample` hook path was tested and did
  not restore UART0 login input.
* Polling/resampling all RP1 passthrough MSI-X sources, or all enabled sources, from the generic IRQ
  path caused boot regressions and systemd stalls.
* A better fix should identify the RP1 interrupt-source pending/armed state and model source
  reissue in the RP1 pIRQ hook or generic pIRQ layer, without open-coded UART0 MMIO checks in
  `rpi_boot/src/handler.rs`.

## Commit & Pull Request Guidelines

Recent history uses Conventional Commit-style subjects such as `fix(rpi_boot): deduplicate rootwait bootarg` and `fix(virtio-blk): allow guest address zero buffers`. Keep subjects imperative, scoped, and specific. Pull requests should describe the affected boot path or crate, list tested commands, note hardware/QEMU coverage, and call out firmware, DTB, or disk-image assumptions.

## Security & Configuration Tips

Some scripts use `sudo`, loop devices, mounting, and generated files in `bin/`. Review shell changes carefully, keep generated artifacts out of source changes unless intentionally updating fixtures, and avoid committing machine-specific paths or boot media contents.
