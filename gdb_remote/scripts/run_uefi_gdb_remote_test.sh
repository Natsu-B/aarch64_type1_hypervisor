#!/bin/sh
set -eu
export LC_ALL=C

PATH_TO_ELF="${1:-}"

if [ -z "$PATH_TO_ELF" ]; then
    echo "usage: $0 <path-to-uefi-test-elf>"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
BIN_DIR="$SCRIPT_DIR/../bin/EFI/BOOT"

rm -rf "$SCRIPT_DIR/../bin/EFI"
mkdir -p "$BIN_DIR"
cp "$PATH_TO_ELF" "$BIN_DIR/BOOTAA64.EFI"

FIRMWARE="$REPO_ROOT/test/RELEASEAARCH64_QEMU_EFI.fd"
if [ ! -f "$FIRMWARE" ]; then
    echo "Missing UEFI firmware: $FIRMWARE" >&2
    exit 1
fi

QEMU_BIN=${QEMU_BIN:-qemu-system-aarch64}
GDB_BIN=${GDB_BIN:-gdb}
UART_PORT=${UART_PORT:-12355}

QEMU_LOG="$SCRIPT_DIR/../bin/qemu_uefi_gdb_remote_${UART_PORT}.log"
rm -f "$QEMU_LOG"

# If xtask provided a QEMU gdbstub socket path, enable it for timeout debugging.
# Trim leading/trailing whitespace to avoid creating a socket named " " (space).
SOCK_RAW="${XTASK_QEMU_GDB_SOCKET:-}"
SOCK_TRIMMED="$(printf '%s' "$SOCK_RAW" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

set -- "$QEMU_BIN" \
  -M virt,gic-version=3,secure=off,virtualization=on \
  -global virtio-mmio.force-legacy=off \
  -cpu cortex-a53 -smp 4 -m 1G \
  -bios "$FIRMWARE" \
  -nographic \
  -semihosting-config enable=on,target=native \
  -no-reboot -no-shutdown \
  -serial null \
  -serial "tcp:127.0.0.1:${UART_PORT},server,nowait" \
  -drive "file=fat:rw:$SCRIPT_DIR/../bin,format=raw,if=none,media=disk,id=disk" \
  -device virtio-blk-device,drive=disk,bus=virtio-mmio-bus.0

if [ -n "$SOCK_TRIMMED" ]; then
    rm -f "$SOCK_TRIMMED"
    set -- "$@" -gdb "unix:${SOCK_TRIMMED},server,nowait"
fi

"$@" 2>"$QEMU_LOG" &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
}
trap cleanup EXIT

# Fail fast if QEMU died immediately (prevents long GDB connect timeouts).
sleep 1
if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "QEMU failed to start. Log:" >&2
    sed -n '1,200p' "$QEMU_LOG" >&2
    exit 1
fi

# Give firmware time to finish early init (UART0 console is routed to null anyway).
sleep 3

# Generate a temporary GDB script bound to the chosen port.
TMP_GDB_SCRIPT=$(mktemp "${SCRIPT_DIR}/../bin/gdb_remote_test.XXXXXX.gdb")
cat > "$TMP_GDB_SCRIPT" <<EOF
set architecture aarch64
set confirm off
set pagination off
set remotetimeout 20
set debug remote 1
target remote 127.0.0.1:${UART_PORT}
monitor exit 0
quit 0
EOF

"$GDB_BIN" --batch -x "$TMP_GDB_SCRIPT"
STATUS=$?

rm -f "$TMP_GDB_SCRIPT"

exit $STATUS
