#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_1.3.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
chmod +x /root/Tools/payload-dumper-go/payload-dumper-go

mkdir -p /work/build/im
cd /work/build/im
unzip -o /work/QPro_50849480091200340.zip payload.bin >/dev/null
/root/Tools/payload-dumper-go/payload-dumper-go -p vendor -o . payload.bin

echo "=== init.insmod.sh ==="
debugfs -R "cat /bin/init.insmod.sh" vendor.img 2>/dev/null
