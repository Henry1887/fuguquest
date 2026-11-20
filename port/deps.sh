#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs llvm unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_1.3.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
chmod +x /root/Tools/payload-dumper-go/payload-dumper-go

mkdir -p /work/build/deps
cd /work/build/deps
unzip -o /work/QPro_50849480091200340.zip payload.bin >/dev/null
/root/Tools/payload-dumper-go/payload-dumper-go -p system_ext,vendor -o . payload.bin

for inner in /bin/trackingfidelityservice /lib64/libhzos_trackinghost.meta.so /lib64/libhzos_trackingclient_internal.meta.so /lib64/libhzos_trackingclient.meta.so; do
  out="/work/build/deps/$(basename $inner)"
  if debugfs -R "dump $inner $out" system_ext.img 2>/dev/null; then
    echo "### $inner"
    llvm-readelf -d "$out" 2>/dev/null | grep NEEDED
  fi
done

for inner in /lib64/vendor.oculus.hardware.sensors@1.0.so /lib64/vendor.oculus.hardware.graphics.composer@1.1.so /lib64/libcdsprpc.so /lib64/libgraloc.qti.so; do
  out="/work/build/deps/$(basename $inner)"
  if debugfs -R "dump $inner $out" vendor.img 2>/dev/null; then
    echo "### $inner"
    llvm-readelf -d "$out" 2>/dev/null | grep NEEDED
  fi
done
