#!/usr/bin/env bash
set -euo pipefail

UART0="${UART0:-/dev/serial/by-id/usb-FTDI_FT230X_Basic_UART_DK0FJLXC-if00-port0}"
LOG="${LOG:-/tmp/rpi5-uart0.log}"
USER_NAME="${USER_NAME:-pi}"
PASSWORD="${PASSWORD:-raspberry}"
TIMEOUT="${TIMEOUT:-260}"

stty -F "${UART0}" 115200 raw -echo -echoe -echok -echoctl -echoke -ixon -ixoff -icrnl -inlcr -opost -crtscts

: > "${LOG}"
setsid sh -c "while true; do cat '${UART0}'; sleep 0.2; done" >> "${LOG}" 2>/tmp/rpi5-uart0.err &
LOGGER_PID=$!
trap 'kill "${LOGGER_PID}" 2>/dev/null || true' EXIT

echo "Waiting for raspberrypi login on ${UART0}..."
for _ in $(seq 1 "${TIMEOUT}"); do
  if grep -a "raspberrypi login:" "${LOG}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! grep -a "raspberrypi login:" "${LOG}" >/dev/null 2>&1; then
  echo "LOGIN_TIMEOUT"
  tail -n 120 "${LOG}"
  exit 1
fi

printf '%s\r' "${USER_NAME}" > "${UART0}"
sleep 2
printf '%s\r' "${PASSWORD}" > "${UART0}"
sleep 6
printf 'echo UART0_INPUT_OK; tty; id; uname -a\r' > "${UART0}"
sleep 8
printf 'echo LONG_UART0_INPUT_0123456789abcdefghijklmnopqrstuvwxyz_0123456789abcdefghijklmnopqrstuvwxyz_0123456789abcdefghijklmnopqrstuvwxyz_END; echo UART0_STILL_OK\r' > "${UART0}"
sleep 8

if ! grep -a "UART0_INPUT_OK" "${LOG}" >/dev/null || ! grep -a "UART0_STILL_OK" "${LOG}" >/dev/null; then
  echo "UART0_INPUT_FAILED"
  tail -n 120 "${LOG}"
  exit 1
fi

tail -n 80 "${LOG}"
echo "UART0 login/input test passed."
