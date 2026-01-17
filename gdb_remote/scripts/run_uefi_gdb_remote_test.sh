#!/bin/sh

PATH_TO_ELF="$1"

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

QEMU_BIN=${QEMU_BIN:-qemu-system-aarch64}
GDB_BIN=${GDB_BIN:-gdb}
UART_PORT=${UART_PORT:-12355}

# If xtask provided a QEMU gdbstub socket path, enable it for timeout debugging.
if [ -n "${XTASK_QEMU_GDB_SOCKET:-}" ]; then
    rm -f "${XTASK_QEMU_GDB_SOCKET}"
fi
"$QEMU_BIN" \
  -M virt,gic-version=3,secure=off,virtualization=on \
  -global virtio-mmio.force-legacy=off \
  -cpu cortex-a53 -smp 4 -m 1G \
  -bios "$REPO_ROOT/test/RELEASEAARCH64_QEMU_EFI.fd" \
  -nographic \
  -semihosting-config enable=on,target=native \
  -no-reboot -no-shutdown \
  ${XTASK_QEMU_GDB_SOCKET:+-gdb unix:${XTASK_QEMU_GDB_SOCKET},server,nowait} \
  -serial tcp:127.0.0.1:${UART_PORT},server,nowait \
  -drive file=fat:rw:"$SCRIPT_DIR/../bin",format=raw,if=none,media=disk,id=disk \
  -device virtio-blk-device,drive=disk,bus=virtio-mmio-bus.0 &

QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null
}
trap cleanup EXIT

# Give firmware time to finish early banner noise before GDB connects.
sleep 6

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
