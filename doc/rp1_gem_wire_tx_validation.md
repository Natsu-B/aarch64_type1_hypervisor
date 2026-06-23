# RP1 GEM wire-level TX validation

This document is the sanitized PR validation note for the RP1 Cadence GEM work. Raw UART,
OpenOCD, GDB, and packet-capture logs remain outside the repository.

## CM5 result

Wire-level CM5 RP1 GEM TX validation passed.

* Host interface: `enp2s0`
* OpenOCD readiness: gated on `SWD DPIDR 0x2ba01477`, `bcm2712.cpu0`, the port-3333 listener,
  and `ss` confirmation that `:3333` is listening
* ELF loading: direct `gdb-multiarch`, after readiness; semihosting enabled before `load` and
  `continue`
* PHY link: 1000 Mbps full duplex
* Target marker: `[rp1-gem] TX broadcast PASS`
* Validator MAC: `2c:cf:67:c2:9a:58`
* Host capture: one matching broadcast frame
  * `2c:cf:67:c2:9a:58 > ff:ff:ff:ff:ff:ff`
  * EtherType `0x88b5`
  * length 60
  * payload repeated `0xa5`
* The host-frame source MAC matched `[rp1-gem] using MAC 2c:cf:67:c2:9a:58`.
* External artifacts: `/opt/rpi-cm5-hack/logs/20260623-135901-rp1-gem-wire-rx/`

This validates the GEM DMA descriptor path, MAC transmit path, PHY link, Ethernet cable, and host
PC NIC receive path. It does not claim GEM RX descriptor operation, ARP/IP, interrupt-driven
networking, Linux guest integration, or sustained bidirectional traffic.

## Review criterion

`[rp1-gem] TX broadcast PASS` is local descriptor/MAC-side success only. A wire-level TX PASS
requires that marker and a host capture with the validator MAC as source, broadcast destination,
EtherType `0x88b5`, length 60, and repeated `0xa5` payload bytes. ELF load success alone is not
Ethernet validation success.
