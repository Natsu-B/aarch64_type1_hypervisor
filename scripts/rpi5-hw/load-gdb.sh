#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

ELF="${ELF:-bin/rpi_boot.elf}"
GDB_PORT="${GDB_PORT:-3333}"
GDB_BIN="${GDB_BIN:-gdb}"

exec "${GDB_BIN}" -q "${ELF}" \
  -ex "target remote :${GDB_PORT}" \
  -ex "load" \
  -ex "continue"
