# DirtyFrag-LPE — unprivileged SELinux Enforcing→Permissive + root (Quest 3 / 3S / Pro / 2)

A single self-contained binary that runs the full zero-root chain: an unprivileged (`uid 2000` shell
/ any app) Dirty-Frag page-cache poison → unsigned kernel module load → `selinux_state.enforcing = 0`
→ optional root (cred-patch) → optional Magisk.

The runtime is a **single OS-independent Rust binary with no external dependencies** — no clang, no
LLVM, no Python, no pip. It assembles the AArch64 carrier/cred/stub payloads itself, parses/rewrites
the carrier ELF itself, computes the Dirty-Frag AES-GCM keystream itself, and embeds `e2e.dex` + the
post-ex assets. The only thing it shells out to is **`adb`**.

> Adding a *new firmware target* still uses `port.py` (Python) — see **[PORTING.md](PORTING.md)** and
> **[SETUP.md](SETUP.md)**. That's the only part that needs Python + the extraction tools.

## Build

```
cd rust && cargo build --release          # -> rust/target/release/fuguquest  (or .exe on Windows)
```
Zero crates, so it builds offline. For a portable static Linux binary:
`rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl`.
Cross-compile for Windows with `x86_64-pc-windows-gnu`.

## Run

```
fuguquest -t targets/<name>.json [-d SERIAL] [--settle N] [--verify-root]
          [--no-restore | --leave-disabled | --postex | --adb-root]
```

**One binary, all devices.** The target JSON's `kernel.merged` flag picks the flow — no rebuild:
- **Quest 3 / 3S (non-merged, 5.10)** — two-carrier flow (`llcc_perfmon` enforcing carrier +
  `usbip-vudc` cred carrier). Validated on-device (adb-root ~10 s).
- **Quest 3S / Quest Pro / Quest 2 (merged)** — one carrier does enforcing=0 + cred-patch together;
  Q3S uses a `.text`-splice carrier. See below.

### `--adb-root` — root adb shells without Magisk
Cred-patches the running **adbd** to `uid 0 + all caps + kernel SELinux context` and leaves SELinux
**Permissive**, so every **new** `adb shell` is full root — no Magisk, no Zygisk. Needs
`kernel.cred_security_off` in the target.
```
fuguquest -t targets/<name>.json --adb-root
# then open a NEW shell:   adb shell   ->   id   # uid=0, context u:r:kernel:s0
```
Transient (RAM-only): a reboot fully clears it. Existing shells stay uid 2000; only shells forked
after the patch are root.

### Merged flow (Quest Pro 4.19 / Quest 2 / Quest 3S)
The merged carrier does everything in one module load: `build_credmod` diff-patches the carrier into
`enforcing=0 + status-page-sync + cred-patch`, loaded **once** → Permissive **and** root together.
The carrier is `vendor_file`/`vendor_dlkm` (shell can't read it under Enforcing) so it's poisoned by
an `init_array` ctor injected into a `same_process_hal_file` lib mapped by `trackingservice`
(`libgralloc.qti` on QPro, `libcdsprpc` on Q3S). QPro's cfg is shell-readable under Enforcing (1-file
ctor); Q3S's isn't (2-file ctor). Quest Pro's `bl __platform_driver_register` routes through a PLT
veneer, so the anchor is an **R_AARCH64_ABS64** slot the loader fills with the real address
(veneer-proof); Q3S's `llcc_perfmon` has a 52 B `.init.text` so the patch goes in `.text` with
`module->init` repointed (`.text`-splice).
```
fuguquest -t targets/QPro_51483620027600340.json --postex     # -> Permissive + uid 0 + Magisk
fuguquest -t targets/q3s_<build>.json --adb-root
```

### Post-exploitation (`--postex`) — unprivileged → uid 0 → Magisk
After reaching Permissive, roots a shell and sets up Magisk, **no per-kernel compilation**:
1. host builds a **diff-patched cred carrier** in-process and pushes it to `/data/local/tmp/uv.ko`
   (its init reads `&__platform_driver_register` from an ABS64 anchor and cred-patches a waiting
   shell to uid 0 + all caps; anchor-relative `find_vpid`/`pid_task`/`selinux_state` deltas from JSON);
2. shell poisons the cfg (permissive ⇒ DAC read) → `insmod|/data/local/tmp/uv.ko`;
3. `ctl.start insmod_sh` loads uv.ko → the waiting shell becomes **uid 0** (polled to confirm);
4. that root shell runs `postex/postex.sh`: drop_caches → rmmod carriers →
   `singularity_magisk.sh` (Singularity Magisk fork, embedded) → `setenforce 1`.

Two things that make it work: the carrier also calls `selinux_status_update_setenforce(&state,0)` so
userspace `/sys/fs/selinux/status` goes permissive (magiskpolicy applies), and the payload is a
Quest-tuned Singularity fork (`SL_RESTART_ZYGOTE=0`, no zygote restart).

### Cleanup modes (after Permissive is reached)
- **default** — `setenforce 1; rmmod; reboot` → device clean (Enforcing).
- **`--leave-disabled`** — revert the code-injection poisons (shell, no reboot), keep Permissive.
- **`--adb-root`** — cred-patch adbd, keep Permissive, no Magisk (transient, reboot clears).
- **`--postex`** — root via insmod_sh cred carrier → Singularity Magisk → setenforce 1.
- **`--no-restore`** — leave everything poisoned & permissive (debugging).

`--settle N` (default 3) waits for the ctor's carrier/cfg poison after the trackingservice restart.

## Chain (all steps as uid-2000 shell, no su)
1. **stage** attacker-keyed AES-GCM ESP SA via IpSecService (`q3.Stager`)
2. **poison the inject lib** (`libeva`/`libgralloc.qti`/`libcdsprpc`): redirect `init_array[0]` → a
   1/2-file poison stub planted in the lib's code gap
3. **poison `libandroid_servers.so::dump`** → a `ctl.restart trackingservice` stub
4. **`dumpsys input`** → system_server restarts trackingservice → the injected ctor runs in
   `hal_tracking_default` and page-cache-poisons the carrier `.ko` (+ `init.insmod.cfg`)
5. **`setprop ctl.start insmod_sh`** → init `finit_module`s the poisoned carrier → unsigned module
   loads → `enforcing = 0` (merged carrier also cred-patches to uid 0)

Key optimization: **diff-injection** — the carrier is the *real* module with an in-place init patch
(enforcing carrier decodes its own `bl` anchor; cred/merged carrier uses a loader-filled ABS64 anchor
— veneer-proof), so only tens of bytes need poisoning and the whole IV table fits the lib's gap.

## Files
- `rust/`            — the orchestrator + all host logic (one binary, no deps, no clang). Builds
  everything the old `orchestrate.py`/`build_credmod.py`/`elfutil.py` did, in-process:
  - `src/asm.rs` — two-pass AArch64 assembler (replaces the clang assemble step)
  - `src/aes.rs` — AES-128 keystream (Dirty-Frag)
  - `src/elf.rs` — ELF64 reader/mutator (carrier splice + reloc rewrite)
  - `src/emit.rs` — carrier init patch, cred-patch, inject stub, libandroid stub, build_carrier/cfg
  - `src/credmod.rs` — merged/cred carrier builder (`.init.text` + `.text`-splice modes)
  - `src/orchestrate.rs` — the full pipeline (both flows, all cleanup modes)
  - `src/adb.rs` — adb wrapper + background Stager / WaitShell
  - embeds `e2e.dex` + `postex/*` via `include_bytes!`
- `port.py`          — (Python) gather a new firmware's values → draft `targets/<name>.json`;
  `--merged`/`--cfg-ctor` emit the merged / Q3S shapes
- `toolconf.py`      — external tool paths for `port.py` (readelf/nm/debugfs/vmlinux-to-elf/payload-dumper)
- `SETUP.md`         — dependency install (run = Rust+adb; port = Python+tools) for Linux & Windows
- `PORTING.md`       — how to add a new firmware (both device families)
- `requirements-port.txt` — Python extras for `port.py` only (vmlinux-to-elf)
- `targets/*.json`   — per-firmware constants/offsets/paths (named after the OTA zip)
- `targets/<name>/`  — that firmware's gathered binaries (carrier `.ko`, cfg, cred carrier on Q3)
- `asm/*.S.tmpl`     — reference asm the Rust emitters mirror (no longer used at runtime)
- `java/Stager.java`, `java/Writer.java` → `e2e.dex` — firmware-independent Dirty-Frag primitives
- `postex/…`         — the root payload (embedded in the binary)

## Adding a new firmware
```
python3 port.py --zip q3_<build>.zip          # OTA-only; name defaults to the zip basename
fuguquest -t targets/q3_<build>.json
```
See **[PORTING.md](PORTING.md)**. `port.py` extracts the carrier/cfg/vmlinux, computes the
anchor-relative deltas, and derives the inject-lib/libandroid offsets. No code changes to run it.

> Authorized bug-bounty research only. `--no-restore` leaves the device permissive; the default
> restores (setenforce 1; rmmod; reboot).
