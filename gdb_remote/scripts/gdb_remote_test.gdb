set debug remote 1
set remotelogfile /tmp/gdb-remote.log
set architecture aarch64
set confirm off
set pagination off
set remotetimeout 20
target remote 127.0.0.1:1234
monitor exit 0
quit 0
