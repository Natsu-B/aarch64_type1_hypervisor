# HyprProbe ドキュメント（gdb branch）

![hyprprobe logo](./image/hyprprobe_logo.png)

このディレクトリは、AArch64 向けのデバッグ支援環境 **HyprProbe** のドキュメントをまとめたものです。
HyprProbe は GDB Remote Serial Protocol と連携し、低レイヤーデバッグで「壊れる前/後に検知する」ための機能（例外可視化、memfault、VBAR 監視、semihosting 等）を提供します。

## セットアップ / 起動

以下の手順で起動できます。

```sh
git clone https://github.com/Natsu-B/aarch64_type1_hypervisor
cd aarch64_hypervisor

git submodule update --init --recursive

cd u-boot/
nix develop
./init.sh

cd ..
nix develop
cargo xrun
```

これにより、HyprProbeがqumu上で起動します。
この状態で、gdb上にて`target remote :3333`で接続することができます。

以降は通常のGDBと同様に操作可能です。

HyprProbeは2025年度SecHack365での成果物です。