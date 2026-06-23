# RP1 GEM CM5 RX validation

This is the sanitized record for host-to-CM5 RP1 GEM RX validation. Raw OpenOCD, GDB, UART, and
packet-capture artifacts remain outside the repository.

## Result

CM5/RP1 GEM polling RX passed after the existing wire-level TX validation.

* Host interface: `enp2s0`
* OpenOCD readiness: `SWD DPIDR 0x2ba01477`, `bcm2712.cpu0`, the OpenOCD GDB listener, and
  `ss` confirmation of `:3333` listening before direct `gdb-multiarch` attachment
* Target destination MAC: `2c:cf:67:c2:9a:58`
* Host source MAC: `02:48:4f:53:54:01`
* EtherType: `0x88b5`
* Frame length: 60 bytes excluding FCS
* Payload marker: `RP1-GEM-RX-TEST`
* Sender burst: five frames at 100 ms spacing
* Hardware log directory: `/opt/rpi-cm5-hack/logs/20260623-145308-rp1-gem-rx/`

The target emitted:

```text
[rp1-gem] RX test frame PASS
[rpi5-rp1-init] Ethernet RX validation PASS
```

Host capture showed the corresponding unicast frame:

```text
02:48:4f:53:54:01 > 2c:cf:67:c2:9a:58, ethertype Unknown (0x88b5), length 60
... 88b5 5250 312d 4745 4d2d 5258 2d54 4553 54 ...
```

The preceding TX broadcast was reflected into RX and logged as a wrong-destination frame. It was
not accepted as RX success; the bounded polling stage continued until the required host unicast
arrived.

## Scope of evidence

Together with the TX record in `rp1_gem_wire_tx_validation.md`, this proves polling
`EthernetFrameIo` smoke in both directions:

* CM5 RP1 GEM DMA TX descriptor to host NIC RX
* host NIC TX through cable/PHY/MAC into CM5 RP1 GEM DMA RX descriptors and `try_recv_frame()`

It does not claim ARP/IP, interrupt-driven networking, Linux guest integration, or sustained
bidirectional traffic.
