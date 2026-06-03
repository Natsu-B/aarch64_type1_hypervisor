aarch64_type1_hypervisorのgitリポジトリである
このデバイスにはRaspberry Pi 5とSWD Debug Probe(ttyACM0)、UART変換(ttyUSB0/1)が接続されていて、Raspberry Pi 5のDebug PortにDebug Probeが、uart 0/1にttyUSB0/1が接続されている
reboot.shを実行するとすべてのUSBの電源をoff/onすることができ、Raspberry Pi 5のrebootに利用できる
Debug Probeへの接続はOpenOCDを用いる。repository rootのrun.shはQEMU用なので、Raspberry Pi 5実機ではscripts/rpi5-hw/openocd.shを使う。これでCPU0のGDB portは3333になる。
実機での基本手順:

1. /nix/var/nix/profiles/default/bin/nix develop --accept-flake-config --command cargo xrun rpi5
2. scripts/rpi5-hw/reboot-usb-hub.sh 10
3. scripts/rpi5-hw/openocd.sh
4. 別端末で scripts/rpi5-hw/load-gdb.sh
5. UART0入力確認は scripts/rpi5-hw/serial-login-test.sh

この端末ではUART0は /dev/serial/by-id/usb-FTDI_FT230X_Basic_UART_DK0FJLXC-if00-port0 -> ttyUSB1、UART1は /dev/serial/by-id/usb-FTDI_FT230X_Basic_UART_DK0GKNKN-if00-port0 -> ttyUSB0、Debug Probe UARTはttyACM0。

Raspberry Pi 5 UART0入力

現在の実機で動くコードは、Linux console/inputをUART0のttyAMA0に残し、EL2ログをUART1へ移したうえで、RP1 UART0 MSI-X source 25をRP1 pIRQ hook側でlevel sourceとしてreissueしている。rpi_boot handlerは汎用のpassthrough-MMIO完了とIRQ resampleだけを通知し、UART0固有のPL011状態確認はbcm2712のpirq_hook側に閉じている。

これまでの確認事項:

* rpi_boot-rp1-uart0-irq-loop tagではUART0入力が実際に成功した。linux imageの位置を現在のlinker script相当に合わせれば動く。
* Pi 5のuart0-pi5 overlayではGPIO14/15のfunction selectorは0x04が正しく、0x10にするとUART0が壊れる。
* 入力が詰まる状態ではPL011のRX/MISはassertされるが、host GICのSPI 185 pendingが立たない。RP1 MSI-X IACK source 25を書き込むとpendingが立ち、入力が進む。
* pIRQ hookのEoi/Resample/ConfigureだけへIACKを移す案は、ログイン入力を復旧できなかった。
* RP1 passthrough MSI-X source全体、またはenabled source全体をIRQ handlerからresampleする案は、systemd boot stallを起こした。
* 現在の修正では、PL011 MISをrpi_boot handlerで直接見ず、RP1 pIRQ hook側でsource reissueを表現している。
