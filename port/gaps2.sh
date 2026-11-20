#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq e2fsprogs unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_1.3.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
chmod +x /root/Tools/payload-dumper-go/payload-dumper-go

rm -rf /work/build/gaps
mkdir -p /work/build/gaps
cd /work/build/gaps
unzip -o /work/QPro_50849480091200340.zip payload.bin >/dev/null
/root/Tools/payload-dumper-go/payload-dumper-go -p system_ext,system,vendor -o . payload.bin

for lib in libtrackingengines.so libtrackingserviceservers.so libvrsensors-hidlwrapper.so libvrsensors-utils.so libtrackingvendorutils.so libtrackinginjection-service.so libhzos_trackinghost.meta.so libhzos_trackingclient_internal.meta.so libhzos_trackingclient.meta.so libperfettoutils.so libjsoncpp.so libui.so libutils.so libcutils.so libbase.so; do
  debugfs -R "dump /lib64/$lib /work/build/gaps/$lib" system_ext.img 2>/dev/null || true
done

python3 - <<'PY'
import os, struct
d = '/work/build/gaps'
for n in sorted(os.listdir(d)):
    if not n.endswith('.so'): continue
    p = os.path.join(d, n)
    try:
        b = open(p, 'rb').read()
        if b[:4] != b'\x7fELF': continue
        e_phoff, = struct.unpack_from('<Q', b, 0x20)
        phentsz, phnum = struct.unpack_from('<HH', b, 0x36)
        best = 0
        for i in range(phnum):
            o = e_phoff + i * phentsz
            p_type, p_flags = struct.unpack_from('<II', b, o)
            p_off, = struct.unpack_from('<Q', b, o + 8)
            p_filesz, = struct.unpack_from('<Q', b, o + 32)
            if p_type != 1 or not (p_flags & 1): continue
            seg = b[p_off:p_off + p_filesz]
            run = 0
            for c in seg:
                if c == 0:
                    run += 1
                    if run > best: best = run
                else:
                    run = 0
        print('%-58s %6d' % (n, best))
    except Exception as e:
        print('%-58s ERR' % n)
PY
