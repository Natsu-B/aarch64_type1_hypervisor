#!/bin/sh
set -e

PATH_TO_ELF="$1"

if [ -z "$PATH_TO_ELF" ]; then
    echo "usage: $0 <path-to-test-elf>"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../../.." && pwd)
FAT_DIR="$SCRIPT_DIR/../bin"
BIN="$REPO_ROOT/bin"

rm -rf "$FAT_DIR"
mkdir -p "$FAT_DIR"

cp "$PATH_TO_ELF" "$FAT_DIR/elf-hypervisor.elf"
cp "$BIN/boot.scr" "$FAT_DIR/boot.scr"
cp "$BIN/u-boot.bin" "$FAT_DIR/u-boot.bin"
if [ -f "$BIN/qemu.dtb" ]; then
    cp "$BIN/qemu.dtb" "$FAT_DIR/qemu.dtb"
fi

QEMU_GDB_ARGS=""
if [ -n "$XTASK_QEMU_GDB_SOCKET" ]; then
    rm -f "$XTASK_QEMU_GDB_SOCKET"
    QEMU_GDB_ARGS="-gdb unix:path=$XTASK_QEMU_GDB_SOCKET,server=on,wait=off"
fi

set +e
qemu-system-aarch64 \
  -M virt,gic-version=3,secure=off,virtualization=on \
  -global virtio-mmio.force-legacy=off \
  -smp 4 \
  -bios "$FAT_DIR/u-boot.bin" \
  -cpu cortex-a55 -m 4G \
  -nographic -no-reboot \
  -semihosting-config enable=on,target=native \
  -drive file=fat:rw:"$FAT_DIR",format=raw,if=none,media=disk,id=disk \
  -device virtio-blk-device,drive=disk,bus=virtio-mmio-bus.0 \
  $QEMU_GDB_ARGS
RETCODE=$?
set -e

if [ $RETCODE -eq 0 ]; then
    exit 0
elif [ $RETCODE -eq 1 ]; then
    printf "\nFailed\n"
    exit 1
else
    printf "\nUnexpected QEMU exit code: %s\n" "$RETCODE"
    exit "$RETCODE"
fi
