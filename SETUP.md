# Setup — external dependencies (Linux & Windows)

The scripts are pure Python and OS-independent, but they shell out to a few external tools. Install
the ones for what you'll run, then point `toolconf.py` (or env vars) at them.

| Tool | Needed by | `toolconf.py` / env var | Notes |
|------|-----------|-------------------------|-------|
| **Python 3.8+** | everything | — | run scripts with `python` / `python3` |
| **pycryptodome** | `orchestrate.py` | — (pip) | provides `Crypto.Cipher.AES` (keystream) |
| **adb** (platform-tools) | `orchestrate.py`, `port.py --device` | on PATH | Google platform-tools |
| **LLVM/clang** (`clang`, `llvm-objcopy`, `llvm-readelf`, `llvm-nm`) | `orchestrate.py`, `build_credmod.py`, `port.py` | `AOSP_CLANG_BIN` (the `bin/` dir) | ≥ v14; AOSP clang **or** stock LLVM — only assembles AArch64 asm |
| **payload-dumper-go** | `port.py` | `PAYLOAD_DUMPER` (full path to the binary) | extracts OTA partitions |
| **debugfs** (e2fsprogs) | `port.py` | `DEBUGFS` (default: `debugfs` on PATH) | reads files out of ext4 partition images |
| **vmlinux-to-elf** | `port.py` | `VMLINUX_TO_ELF` (default: `vmlinux-to-elf` on PATH) | boot.img → vmlinux with symbols |
| Android **NDK** | *only* rebuilding `e2e.dex`/native (optional) | `NDK_BIN` | `e2e.dex` is prebuilt & committed — skip unless changing the Java |

**Minimum to run the exploit** (`orchestrate.py`): Python + pycryptodome + adb + LLVM/clang.
**To add a new firmware target** (`port.py`): also payload-dumper-go + debugfs + vmlinux-to-elf.

---

## Linux

```bash
# Python libs
python3 -m pip install --user pycryptodome vmlinux-to-elf

# distro packages
#  Fedora:
sudo dnf install android-tools clang llvm e2fsprogs
#  Debian/Ubuntu:
sudo apt install adb clang llvm e2fsprogs

# payload-dumper-go — grab the linux_amd64 release binary
#  https://github.com/ssut/payload-dumper-go/releases
tar xf payload-dumper-go_*_linux_amd64.tar.gz -C ~/Tools/
```

Then set the paths (once, e.g. in `~/.bashrc`) — or edit the defaults at the top of `toolconf.py`:
```bash
export AOSP_CLANG_BIN=/usr/bin                 # dir holding clang, llvm-objcopy, llvm-readelf, llvm-nm
export PAYLOAD_DUMPER=$HOME/Tools/payload-dumper-go
# DEBUGFS / VMLINUX_TO_ELF default to PATH names, so nothing to set if installed above
```
> `AOSP_CLANG_BIN` is the directory that *contains* the `clang`/`llvm-*` binaries. On Fedora/Debian
> that's `/usr/bin`. If you use the AOSP prebuilt instead, point it at
> `.../clang-r450784e/bin`.

---

## Windows

Install (PowerShell; `winget` or manual downloads):
```powershell
winget install Python.Python.3.12
winget install LLVM.LLVM                        # -> C:\Program Files\LLVM\bin (clang.exe, llvm-*.exe)
python -m pip install pycryptodome vmlinux-to-elf
```
- **adb**: download *SDK Platform-Tools for Windows* from
  https://developer.android.com/tools/releases/platform-tools , unzip (e.g. `C:\platform-tools`),
  and add that folder to your **PATH**.
- **payload-dumper-go**: download the `windows_amd64` release .exe from
  https://github.com/ssut/payload-dumper-go/releases and save it (e.g.
  `C:\Tools\payload-dumper-go.exe`).
- **debugfs**: not native to Windows. Easiest is to **run `port.py` under WSL** (Ubuntu:
  `sudo apt install e2fsprogs`) — everything else works either way. If you must stay in native
  Windows, install an e2fsprogs port (Cygwin `e2fsprogs`, or Ext2Fsd/“e2fsprogs for Windows” builds)
  and point `DEBUGFS` at its `debugfs.exe`.

Then set the paths (PowerShell; use `[Environment]::SetEnvironmentVariable(...,'User')` to persist) —
or edit `toolconf.py`:
```powershell
$env:AOSP_CLANG_BIN = "C:\Program Files\LLVM\bin"
$env:PAYLOAD_DUMPER = "C:\Tools\payload-dumper-go.exe"
$env:DEBUGFS        = "C:\cygwin64\bin\debugfs.exe"   # only if not using WSL
```
> `toolconf.py` auto-appends `.exe` to the clang/llvm tool names on Windows, so
> `AOSP_CLANG_BIN` just needs to be the `bin` directory.

> **Recommended split:** run **`orchestrate.py` natively on Windows** (needs only Python +
> pycryptodome + adb + LLVM — all easy on Windows), and do the occasional **`port.py` under WSL**
> (where debugfs/vmlinux-to-elf/payload-dumper are trivial). Targets are just JSON + a few small
> files, so build them once (either OS) and commit them.

---

## Verify

```bash
python - <<'PY'
import shutil, os, importlib.util, subprocess
import sys; sys.path.insert(0, ".")
import toolconf as t
def ok(label, path, run=None):
    found = os.path.isfile(path) or shutil.which(path)
    print(f"  {'OK ' if found else 'MISSING'} {label}: {path}")
print("Crypto (pycryptodome):", "OK" if importlib.util.find_spec("Crypto") else "MISSING  (pip install pycryptodome)")
print("adb:", "OK" if shutil.which("adb") else "MISSING")
for lbl, p in [("clang", t.CLANG), ("llvm-objcopy", t.OBJCOPY), ("llvm-readelf", t.READELF),
               ("llvm-nm", t.NM), ("payload-dumper-go", t.PDG), ("debugfs", t.DEBUGFS),
               ("vmlinux-to-elf", t.VMLINUX_TO_ELF)]:
    ok(lbl, p)
PY
```
Anything `MISSING` → install it or fix its path in `toolconf.py` / the matching env var. `debugfs`,
`payload-dumper-go`, and `vmlinux-to-elf` are only needed for `port.py` (adding targets), not for
running the exploit.
