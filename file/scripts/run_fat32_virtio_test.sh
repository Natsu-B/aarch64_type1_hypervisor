#!/bin/sh

set -e

PATH_TO_ELF="$1"

# get absolute path
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

DISK_IMG="$SCRIPT_DIR/../bin/fat32_virtio.img"

# Layout follows https://github.com/PG-MANA/MiniVisor/blob/main/tools/create_disk.sh:
# a 2000 MiB disk with one FAT32 (LBA) partition starting at sector 2048.
SECTOR_SIZE=512
DISK_SECTORS=4096000
PART_START=2048
PART_SECTORS=$((DISK_SECTORS - PART_START))

# mtools addresses the partition through an `image@@byte_offset` path, which
# needs neither root nor loop devices and works on both Linux and macOS.
PART="$DISK_IMG@@$((PART_START * SECTOR_SIZE))"
export MTOOLS_SKIP_CHECK=1

for tool in mformat mmd mcopy mtype mdir; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FAIL: $tool not found; run inside \`nix develop\` (mtools)" >&2
        exit 1
    fi
done

# Print a 32-bit value as little-endian raw bytes.
le32() {
    for s in 0 8 16 24; do
        # shellcheck disable=SC2059
        printf "\\$(printf '%03o' $((($1 >> s) & 255)))"
    done
}

# Rebuild the image on every run so a previous (possibly failed) run can never
# leave stale files behind. The sparse file costs no real disk space up front.
mkdir -p "$SCRIPT_DIR/../bin"
rm -f "$DISK_IMG"
dd if=/dev/zero of="$DISK_IMG" bs=$SECTOR_SIZE count=0 seek=$DISK_SECTORS 2>/dev/null

# MBR partition entry 1: inactive, CHS fields unused (LBA only), type 0x0C
# (FAT32 LBA), followed by the 0x55AA boot signature at the end of sector 0.
{
    printf '\000\376\377\377\014\376\377\377'
    le32 $PART_START
    le32 $PART_SECTORS
} | dd of="$DISK_IMG" bs=1 seek=446 conv=notrunc 2>/dev/null
printf '\125\252' | dd of="$DISK_IMG" bs=1 seek=510 conv=notrunc 2>/dev/null

mformat -i "$PART" -F -T $PART_SECTORS -H $PART_START -h 64 -s 32 ::
mmd -i "$PART" ::EFI ::EFI/BOOT
mcopy -i "$PART" "${PATH_TO_ELF}" ::EFI/BOOT/BOOTAA64.EFI
mcopy -i "$PART" "$SCRIPT_DIR/hello.txt" ::
mcopy -i "$PART" "$SCRIPT_DIR/very_long_long_example_text.TXT" ::

QEMU_GDB_ARGS=""
if [ -n "$XTASK_QEMU_GDB_SOCKET" ]; then
    rm -f "$XTASK_QEMU_GDB_SOCKET"
    QEMU_GDB_ARGS="-gdb unix:path=$XTASK_QEMU_GDB_SOCKET,server=on,wait=off"
fi

# QEMU's exit status is the test verdict, so stop aborting on failure here.
set +e

qemu-system-aarch64 \
  -M virt,gic-version=3,secure=off,virtualization=on \
  -global virtio-mmio.force-legacy=off \
  -cpu cortex-a53 -smp 4 -m 4G \
  -bios $SCRIPT_DIR/../../test/RELEASEAARCH64_QEMU_EFI.fd \
  -nographic \
  -semihosting-config enable=on,target=native \
  -no-reboot -no-shutdown \
  -drive file=$DISK_IMG,format=raw,if=none,media=disk,id=disk \
  -device virtio-blk-device,bus=virtio-mmio-bus.0,drive=disk \
  $QEMU_GDB_ARGS

RETCODE=$?

if [ $RETCODE -eq 0 ]; then
    # Inspect the disk image again to check the created file
    if ! mdir -i "$PART" ::testdir >/dev/null 2>&1; then
        echo "FAIL: testdir not found"
        exit 1
    fi
    if ! mdir -i "$PART" ::testdir/testfile.txt >/dev/null 2>&1; then
        echo "FAIL: testfile.txt not found"
        exit 1
    fi
    if [ "$(mtype -i "$PART" ::testdir/testfile.txt)" != "test content" ]; then
        echo "FAIL: testfile.txt content mismatch"
        exit 1
    fi
    echo "Host check: PASS"
    exit 0
elif [ $RETCODE -eq 1 ]; then
    printf "\nFailed\n"
    exit 1
fi
