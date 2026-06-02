#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

exec openocd -f interface/cmsis-dap.cfg -f scripts/rpi5-hw/openocd-rpi5.cfg
