#!/usr/bin/env bash
set -euo pipefail

LOCATION="${LOCATION:-2}"
WAIT_SECONDS="${1:-10}"

echo "USB hub location ${LOCATION}: power off"
sudo uhubctl -l "${LOCATION}" -a off

echo "Waiting ${WAIT_SECONDS} seconds..."
sleep "${WAIT_SECONDS}"

echo "USB hub location ${LOCATION}: power on"
sudo uhubctl -l "${LOCATION}" -a on

echo "Done."
