#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs llvm unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_1.3.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
chmod +x /root/Tools/payload-dumper-go/payload-dumper-go

mkdir -p /work/build/gaps
cd /work/build/gaps
unzip -o /work/QPro_50849480091200340.zip payload.bin >/dev/null
/root/Tools/payload-dumper-go/payload-dumper-go -p system_ext,system,vendor -o . payload.bin

for lib in libtrackingengines.so libtrackingserviceservers.so libvrsensors-hidlwrapper.so libvrsensors-utils.so libtrackingvendorutils.so libtrackinginjection-service.so libhzos_trackinghost.meta.so libhzos_trackingclient_internal.meta.so libhzos_trackingclient.meta.so libperfettoutils.so libjsoncpp.so vendor.oculus.hardware.sensors@1.0.so vendor.oculus.hardware.graphics.composer@1.1.so; do
  debugfs -R "dump /lib64/$lib /work/build/gaps/$lib" system_ext.img 2>/dev/null || true
done

for lib in libutils.so libcutils.so libui.so libbase.so liblog.so; do
  debugfs -R "dump /lib64/$lib /work/build/gaps/$lib" system.img 2>/dev/null || true
done

python3 -m venv /opt/v
/opt/v/bin/pip install -q -r /work/requirements-port.txt
export PATH="/opt/v/bin:$PATH"

cd /work
for f in /work/build/gaps/*.so; do
  /opt/v/bin/python -c "
import sys
sys.path.insert(0, '/work')
from port import find_gap
import os
f = '$f'
try:
    o, s = find_gap(f)
    print('%-58s %6d' % (os.path.basename(f), s))
except Exception as e:
    print('%-58s %s' % (os.path.basename(f), 'ERR'))
"
done
