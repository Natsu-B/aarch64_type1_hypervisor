# RP1 GEM network smoke

This is a hardware-only RP1 PCIe/GEM validation example. It initializes RP1 in
`Auto` mode, initializes `Rp1Gem`, sends a broadcast ARP request to the static
server configuration in `src/main.rs`, and logs the matching ARP reply. When
`TFTP_FILENAME` is `Some`, it also sends an octet-mode TFTP RRQ and logs the
first matching UDP/TFTP response. The example always calls `Rp1Gem::quiesce`
before its terminal idle loop.

Build it with:

```sh
cargo check --manifest-path arch_hal/aarch64_hal/soc/example/rpi5_rp1_net_smoke/Cargo.toml --target aarch64-unknown-none-softfloat
```

It is deliberately not in `xtest.txt`: it requires the connected CM5/RP1,
direct host Ethernet, a configured server address, and semihosting enabled in
OpenOCD/GDB (`monitor arm semihosting enable`). Capture host traffic with:

```sh
sudo tcpdump -i <cm5-ethernet-iface> -e -n 'arp or udp port 69 or udp portrange 1024-65535'
```
