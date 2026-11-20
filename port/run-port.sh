#!/bin/bash
set -e

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip python3-venv e2fsprogs llvm unzip curl

mkdir -p /root/Tools/payload-dumper-go
tar -xzf /work/port/tools/payload-dumper-go_1.3.0_linux_amd64.tar.gz -C /root/Tools/payload-dumper-go
find /root/Tools/payload-dumper-go -type f -name "payload-dumper-go" -exec chmod +x {} \;
ls -l /root/Tools/payload-dumper-go

python3 -m venv /opt/v
/opt/v/bin/pip install -q -r /work/requirements-port.txt
export PATH="/opt/v/bin:$PATH"

cd /work
/opt/v/bin/python port.py --zip QPro_50849480091200340.zip --merged --carrier rdbg --inject-lib libgralloc.qti.so --enforcing-off 1 --cred-off auto
