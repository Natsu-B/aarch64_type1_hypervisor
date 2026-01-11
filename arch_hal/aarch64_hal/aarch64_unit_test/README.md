# aarch64_unit_test

`aarch64_unit_test` is a tiny `no_std` unit-test harness for AArch64 bare-metal,
intended to be executed under **U-Boot + QEMU**.

This repository’s `cargo xtest` (`cargo xtask test`) supports a test-plan entry kind
called **`uboot-unit`**, which runs **library unit tests** (`cargo test --lib`) for
`aarch64-unknown-none-softfloat` using a custom runner script.

---

## What is `uboot-unit` in this repository?

A `uboot-unit` test is:

- Built by `cargo test --target aarch64-unknown-none-softfloat --lib`
- Linked with a repository-provided link script (`test.lds`) passed via `RUSTFLAGS`
- Executed by setting:
  - `CARGO_TARGET_AARCH64_UNKNOWN_NONE_SOFTFLOAT_RUNNER=<runner-script>`
- The runner launches `qemu-system-aarch64` with **U-Boot** as `-bios`,
  and U-Boot loads and runs the test ELF via `bootelf`.

The test result is reported by **QEMU semihosting exit**:
- success: exit code `0`
- failure: exit code `1`

---

## Using this crate from your package (required implementation)

### 1) Add dev-dependency

In your package’s `Cargo.toml`:

```toml
[dev-dependencies]
aarch64_unit_test = { path = "../aarch64_unit_test" } # adjust path for your crate location
````

If your tests print logs, add `print` as needed (optional for users; the harness itself uses it).

### 2) Enable `custom_test_frameworks` only for `test && aarch64`

In your crate root (`src/lib.rs`):

```rust
#![no_std]

// Enable custom test frameworks only for AArch64 bare-metal test builds.
#![cfg_attr(all(test, target_arch = "aarch64"), feature(custom_test_frameworks))]
#![cfg_attr(all(test, target_arch = "aarch64"), test_runner(aarch64_unit_test::test_runner))]
#![cfg_attr(all(test, target_arch = "aarch64"), reexport_test_harness_main = "test_main")]

// Provide a runnable entrypoint for U-Boot/QEMU.
#[cfg(all(test, target_arch = "aarch64"))]
aarch64_unit_test::uboot_unit_test_harness!(aarch64_unit_test::init_default_uart);

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    #[test_case]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
```

Notes:

* The harness macro defines `_start`, sets up SP from `__stack_top`, clears `.bss`,
  calls `test_main()`, then exits via semihosting.
* If you need board-specific UART init, pass your own init function instead of
  `aarch64_unit_test::init_default_uart`.

### 3) Linker script requirements

The link script used for `uboot-unit` must export these symbols:

* `__stack_top`
* `__bss_start`
* `__bss_end`

`uboot_unit_test_harness!` depends on them.

---

## Runner script requirements (for `uboot-unit`)

A `uboot-unit` runner script must:

1. Accept the test ELF path as argv[1]
2. Prepare a FAT directory containing:

   * `elf-hypervisor.elf` (the test ELF)
   * `u-boot.bin` and `boot.scr` (copied from `./bin/`)
   * optional `qemu.dtb` if required by your setup
3. Launch `qemu-system-aarch64` with:

   * `-bios u-boot.bin`
   * `-drive file=fat:rw:<fat-dir>,...`
   * `-semihosting-config enable=on,target=native`
4. Return QEMU’s exit code (0/1 expected)

You can model your script after existing `uboot` test scripts, e.g.
`arch_hal/aarch64_hal/gic/scripts/run_gicv2_pending_test.sh` or
`arch_hal/aarch64_hal/paging/scripts/run_stage_paging_test.sh`.

---

## Registering the test in `xtest.txt`

Add a line:

```text
uboot-unit <package> <runner-script> [extra cargo args...]
```

Example:

```text
uboot-unit gic arch_hal/aarch64_hal/gic/scripts/run_gicv2_pending_test.sh
```

Choose / create a runner script whose QEMU machine config matches your test needs
(e.g. `gic-version=2` vs `gic-version=3`).

---

## Building U-Boot artifacts required by runner scripts

Runner scripts expect these files under repository `./bin/`:

* `bin/u-boot.bin`
* `bin/boot.scr`

Build them via:

```sh
$ nix-develop
$ ./u-boot/init.sh
```

This builds U-Boot and generates `boot.scr` from `u-boot/boot.txt`.

---

## Debugging

* Many runner scripts support `XTASK_QEMU_GDB_SOCKET` to enable QEMU `-gdb unix:...`.
* UART output:

  * default UART base: `0x0900_0000`
  * default UART clock: `48_000_000 Hz`
  * baud: `115200`

If your environment differs, provide a custom init function and pass it to
`uboot_unit_test_harness!(...)`.
