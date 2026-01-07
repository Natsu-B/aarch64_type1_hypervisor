#!/bin/sh
set -eu

# Build Buildroot artifacts (Image + rootfs.ext2) in Docker and export to ./bin
# Output files:
#   - ./bin/Image
#   - ./bin/DISK0   (Buildroot output/images/rootfs.ext2)

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BIN="$SCRIPT_DIR/bin"
CACHE_DIR="$SCRIPT_DIR/.cache/buildroot"
DL_DIR="$CACHE_DIR/dl"

VERSION="${1:-2025.05}"

mkdir -p "$BIN" "$DL_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker not found in PATH" >&2
  exit 1
fi

BUILDER_IMAGE="aarch64-hv-buildroot-builder:ubuntu24.04"

# Build builder image once (contains host packages needed to build Buildroot)
if ! docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
  docker build -t "$BUILDER_IMAGE" - <<'EOF'
FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bash bc binutils build-essential bzip2 cpio diffutils file gawk gcc g++ gzip make patch perl \
    rsync sed tar unzip wget curl git xz-utils ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
EOF
fi

# Run Buildroot build in container, export artifacts via bind mount.
# BR2_DL_DIR is set to a host-mounted cache to speed up subsequent builds. :contentReference[oaicite:2]{index=2}
docker run --rm \
  -e VERSION="$VERSION" \
  -e FORCE_UNSAFE_CONFIGURE=1 \
  -e BR2_DL_DIR=/dl \
  -v "$DL_DIR:/dl:rw" \
  -v "$BIN:/out:rw" \
  "$BUILDER_IMAGE" \
  bash -lc '
    set -euo pipefail

    BUILDROOT_DIR=/tmp/buildroot
    rm -rf "$BUILDROOT_DIR"
    mkdir -p "$BUILDROOT_DIR"
    cd "$BUILDROOT_DIR"

    curl -fsSL "https://buildroot.org/downloads/buildroot-${VERSION}.tar.xz" | tar -xJf -
    cd "buildroot-${VERSION}"

    make qemu_aarch64_virt_defconfig

    # Do not build host-qemu inside Buildroot; repo uses external qemu-system-aarch64 (run.sh).
    sed -i -e "s/BR2_PACKAGE_HOST_QEMU=y/BR2_PACKAGE_HOST_QEMU=n/" .config

    make -j"$(nproc)"

    cp -f output/images/Image /out/Image
    cp -f output/images/rootfs.ext2 /out/DISK0

    ls -lh /out/Image /out/DISK0
  '

echo "OK: exported:"
echo "  $BIN/Image"
echo "  $BIN/DISK0"
