# Setup — dependencies (Linux & Windows)

There are two separate jobs with very different requirements:

| Job | Needs | Notes |
|-----|-------|-------|
| **Run the exploit** (`fuguquest`) | **Rust toolchain** (to build once) + **adb** | No clang, no LLVM, no Python, no pip. The binary is self-contained. |
| **Add a new firmware target** (`port.py`) | **Python 3.8+** + adb + extraction tools | payload-dumper-go, debugfs, vmlinux-to-elf, llvm-readelf/nm |

If someone hands you a ready `targets/<name>.json` (+ its `targets/<name>/` binaries), you only need
the first row: build the binary and run it.

---

## Run the exploit

### 1. Rust toolchain (build the binary — once)
- **Linux:** `curl https://sh.rustup.rs -sSf | sh` (or distro `rust`/`cargo` package), then
  `cd rust && cargo build --release`.
- **Windows:** install **rustup** from https://rustup.rs (pick the MSVC or GNU toolchain), then
  `cd rust` and `cargo build --release` → `rust\target\release\fuguquest.exe`.

The crate has **zero dependencies**, so `cargo build` works fully offline. Output:
`rust/target/release/fuguquest`. Copy it anywhere; it embeds `e2e.dex` and the post-ex assets.

Optional fully-static / cross builds:
```
rustup target add x86_64-unknown-linux-musl   && cargo build --release --target x86_64-unknown-linux-musl
rustup target add x86_64-pc-windows-gnu        && cargo build --release --target x86_64-pc-windows-gnu
```

### 2. adb (platform-tools)
- **Linux:** `sudo dnf install android-tools` (Fedora) / `sudo apt install adb` (Debian/Ubuntu).
- **Windows:** download *SDK Platform-Tools* from
  https://developer.android.com/tools/releases/platform-tools , unzip, add the folder to **PATH**.

That's it — `fuguquest -t targets/<name>.json --adb-root` needs nothing else.

---

## Add a new firmware target (`port.py`)

Only needed to build a new `targets/*.json` from an OTA zip. `port.py` is Python and shells out to a
few tools; point `toolconf.py` (or env vars) at them.

| Tool | env var (`toolconf.py`) | Install |
|------|-------------------------|---------|
| **Python 3.8+** | — | run with `python3 port.py …` |
| **payload-dumper-go** | `PAYLOAD_DUMPER` (full path) | release binary from https://github.com/ssut/payload-dumper-go/releases |
| **debugfs** (e2fsprogs) | `DEBUGFS` (default: on PATH) | `dnf/apt install e2fsprogs` (Windows: use WSL) |
| **vmlinux-to-elf** | `VMLINUX_TO_ELF` (default: on PATH) | `pip install -r requirements-port.txt` |
| **llvm-readelf / llvm-nm** | `READELF` / `NM` | `dnf/apt install llvm` (Windows: `winget install LLVM.LLVM`) |

```bash
# Linux
sudo dnf install android-tools llvm e2fsprogs        # or: apt install adb llvm e2fsprogs
python3 -m pip install --user -r requirements-port.txt
# payload-dumper-go: unpack the linux_amd64 release into ~/Tools/
export PAYLOAD_DUMPER=$HOME/Tools/payload-dumper-go   # DEBUGFS/VMLINUX_TO_ELF default to PATH names
```

On Windows the cleanest path for `port.py` is **WSL** (debugfs/vmlinux-to-elf/payload-dumper are
trivial there). Targets are just JSON + a few small files, so build them once (either OS) and commit
them — then any machine only needs the run-side (Rust + adb).

---

## Verify

Run side:
```
cargo --version && adb version | head -1
cd rust && cargo build --release && ./target/release/fuguquest --help
```

Port side (optional):
```
python3 - <<'PY'
import shutil, os, sys; sys.path.insert(0, ".")
import toolconf as t
def ok(label, path): print(f"  {'OK ' if os.path.isfile(path) or shutil.which(path) else 'MISSING'} {label}: {path}")
print("adb:", "OK" if shutil.which("adb") else "MISSING")
for lbl, p in [("payload-dumper-go", t.PDG), ("debugfs", t.DEBUGFS), ("vmlinux-to-elf", t.VMLINUX_TO_ELF),
               ("llvm-readelf", t.READELF), ("llvm-nm", t.NM)]:
    ok(lbl, p)
PY
```
