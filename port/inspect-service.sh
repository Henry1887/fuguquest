#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs llvm unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_1.3.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
chmod +x /root/Tools/payload-dumper-go/payload-dumper-go

mkdir -p /work/build/svc
cd /work/build/svc
unzip -o /work/QPro_50849480091200340.zip payload.bin >/dev/null
/root/Tools/payload-dumper-go/payload-dumper-go -p system_ext -o . payload.bin

debugfs -R "dump /bin/trackingservice /work/build/svc/trackingservice" system_ext.img 2>/dev/null || true
ls -l /work/build/svc/trackingservice

echo "=== NEEDED ==="
llvm-readelf -d /work/build/svc/trackingservice | grep NEEDED
