#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_2.1.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
chmod +x /root/Tools/payload-dumper-go/payload-dumper-go

mkdir -p /work/build/list
cd /work/build/list
unzip -o /work/QPro_50849480091200340.zip payload.bin >/dev/null
/root/Tools/payload-dumper-go/payload-dumper-go -p vendor -o . payload.bin

echo "=== vendor /lib/modules ==="
debugfs -R "ls -l /lib/modules" vendor.img 2>/dev/null || true

echo "=== vendor /etc/init.insmod.cfg ==="
debugfs -R "cat /etc/init.insmod.cfg" vendor.img 2>/dev/null | head -80 || true
