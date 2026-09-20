# DirtyFrag-LPE — unprivileged SELinux Enforcing→Permissive + root (Quest 3 & Quest Pro)

Single orchestrator that runs the full zero-root chain: an unprivileged (`uid 2000` shell / any
app) Dirty-Frag page-cache poison → unsigned kernel module load → `selinux_state.enforcing = 0`.

```
python3 orchestrate.py --target targets/<name>.json [--device SERIAL] [--settle N] [--verify-root]
                       [--no-restore | --leave-disabled | --postex]
```

**One file, both devices.** The target JSON's `kernel.merged` flag picks the flow — no code changes:
- **Quest 3** (5.10) — two-carrier flow. Validated on **5234532** (unit B, ~18 s) and **5243367**
  (unit A, locked retail, ~20 s).
- **Quest Pro** (4.19) — merged single-carrier flow (`targets/questpro-5148362.json`); see
  [Quest Pro](#quest-pro-merged-single-carrier) below.

### Quest Pro (merged single-carrier)
Quest Pro's 4.19 kernel differs (`selinux_state.enforcing @ +1`, `task_struct.cred @ 0x7e8`) and,
critically, its **only** not-loaded module with a big-enough init is `rdbg` (680 B) — `llcc_perfmon`
is already loaded, and the small USB-net modules (≤168 B init) can't hold the 196 B cred-patch. So a
single carrier does everything: `build_credmod` diff-patches `rdbg` into
`enforcing=0 + status-page-sync + cred-patch(waiting-shell pid)`, and it is loaded **once** →
Permissive **and** root together. Because `rdbg` is `vendor_file` (shell can't read it under
Enforcing) it's poisoned by a **1-file** `init_array` ctor injected into `libgralloc.qti.so` (a
`same_process_hal_file` lib mapped by `trackingservice`, 3.7 KB code gap); the cfg *is* shell-readable
under Enforcing here, so shell poisons it directly. All values (deltas, offsets) verified statically
from the firmware + BTF. Run:

```
python3 orchestrate.py -t targets/questpro-5148362.json --postex        # -> Permissive + uid 0 + Magisk
```

> Status: on-device run #1 confirmed the chain executes end-to-end — rdbg loaded and our patched
> `init_module` ran (panic log). It panicked because 4.19 routes the module's
> `bl __platform_driver_register` through a **PLT veneer**, so decoding the bl gave the veneer, not
> the symbol. Fixed: the anchor is now an **R_AARCH64_ABS64** slot the loader fills with the real
> address (no CALL26/veneer). Remaining on-device unknowns: `module.sig_enforce` off (rdbg loaded, so
> likely off), and Magisk setup. Dirty-Frag itself is **confirmed on 4.19**.

### Post-exploitation (`--postex`) — unprivileged → uid 0 root → Magisk
After reaching Permissive, roots a shell and sets up Magisk, **no per-kernel compilation**:
1. shell writes a **diff-patched cred carrier** (`usbip-vudc.ko`, not-loaded, 408 B init) to
   `/data/local/tmp/uv.ko` — its init reads `&__platform_driver_register` from an ABS64 anchor and
   cred-patches a waiting shell's `task->cred` to uid 0 + all caps (anchor-relative `find_vpid`/
   `pid_task`/`selinux_state`, per-kernel deltas from the target JSON);
2. shell poisons the cfg (permissive ⇒ DAC read) to `insmod|/data/local/tmp/uv.ko`;
3. `ctl.start insmod_sh` loads uv.ko → the waiting shell becomes **uid 0** (polled to confirm);
4. that root shell runs `postex/postex.sh`: drop_caches → rmmod both carriers →
   `singularity_magisk.sh` (Singularity Magisk v30.7 fork, from `postex/assets/`) → `setenforce 1`.

```
python3 orchestrate.py -t targets/<name>.json --postex [--skip-magisk]
```
**Proven on locked retail A (~40 s):** a fresh unprivileged `adb shell` → `su -c id` = **uid 0,
`u:r:magisk:s0`, under SELinux Enforcing**. Magisk (Singularity v30.7 fork) daemon + manager live.

Two things that made it work:
- **SELinux status-page sync** — the carrier flips `enforcing=0` by a direct memory write, which
  updates the kernel AVC but *not* the `/sys/fs/selinux/status` page userspace reads, so init kept
  enforcing (setprop/ctl.stop/magiskpolicy denied). The usbip carrier now also calls
  `selinux_status_update_setenforce(&selinux_state,0)` (anchor-relative) → userspace truly
  permissive → magiskpolicy applies → after the final `setenforce 1`, headless `su` works under
  enforcing.
- **Payload = `singularity_magisk.sh`** (Quest-tuned v30.7 fork, `SL_RESTART_ZYGOTE=0`) instead of
  the AVD `live_setup.sh`: no zygote restart (the AVD script's `stop`/`start` was ~181 s of the old
  219 s total) and no `memfd_file` magiskpolicy error. Zygisk isn't injected into already-running
  procs (set `SL_RESTART_ZYGOTE=1` for that), but `su` works.

Both carriers are still **diff-patched existing modules** (llcc_perfmon = enforcing; usbip-vudc =
cred-patch + status-page sync), so a new kernel needs only the JSON deltas — no compilation.

### Cleanup modes (what happens after Permissive is reached)
- **default** — `setenforce 1; rmmod; reboot` → device fully clean (Enforcing). Needs root only on a
  rooted validation unit; on a locked unit the reboot alone restores.
- **`--leave-disabled`** — reverts the *code-injection* poisons (libeva ctor + libandroid dump) via
  shell, **no reboot, SELinux stays Permissive**. For handing off to a post-exploitation script.
  Residue left (benign, cleared later once root): the carrier/cfg page-cache poison + the loaded
  `llcc_perfmon`. (`--postex` does this whole hand-off automatically; use `--leave-disabled` only to
  drive post-ex by hand.)
- **`--no-restore`** — leave everything poisoned & permissive (debugging).

`--settle N` (default 8) is how long to wait for the ctor's carrier/cfg poison to finish after the
trackingservice restart, before firing `insmod_sh`. Do not lower it — re-triggering would revert
the poison.

## Chain (all steps as uid-2000 shell, no su)
1. **stage** attacker-keyed AES-GCM ESP SA via IpSecService (`q3.Stager`)
2. **poison `libeva.so`**: redirect `init_array[0]` (RELR slot) → a 2-file poison stub planted in
   libeva's ~1.8 KB code gap
3. **poison `libandroid_servers.so::dump`** → a `ctl.restart trackingservice` stub
4. **`dumpsys input`** → system_server restarts trackingservice → the libeva ctor runs in
   `hal_tracking_default` and page-cache-poisons the carrier `.ko` (48-byte enforcing=0 patch) +
   `init.insmod.cfg` (adds an `insmod` line)
5. **`setprop ctl.start insmod_sh`** → `init-insmod-sh` finit_modules the poisoned carrier →
   kernel loads the unsigned module → `enforcing = 0`

Key optimization: **diff-injection** — the target module is the *real* carrier with a 52-byte
in-place init patch (the enforcing carrier decodes its own `bl` anchor; the cred/merged carrier uses
an ABS64 anchor the loader fills — veneer-proof — see `cred_patch.S.tmpl`),
so only ~48 bytes need poisoning and the whole IV table fits libeva's existing gap (no 78 KB table).

## Files
- `orchestrate.py`   — the whole pipeline (build + stage + poison + trigger + verify + post-ex/cleanup);
  dispatches two-carrier (`run`) vs merged (`run_merged`) on `kernel.merged`
- `toolconf.py`      — ONE place for all external tool paths (clang/objcopy/readelf/nm, NDK,
  payload-dumper, debugfs, vmlinux-to-elf); env vars override. Imported by the scripts below.
- `port.py`          — gather a new firmware's values → draft `targets/<name>.json` (+ binaries);
  `--merged` emits the single-carrier shape (Quest Pro)
- `build_credmod.py` — diff-patch the cred carrier (usbip-vudc on Q3, rdbg on QPro); takes
  `enf_off`/`cred_off` so one template covers 5.10 and 4.19
- `PORTING.md`       — how to add a new firmware (automated + manual, both device families)
- `targets/*.json`   — per-firmware constants/offsets/paths (quest3-5234532, quest3-5243367,
  questpro-5148362)
- `targets/<name>/`   — that firmware's gathered binaries: carrier `.ko` (llcc_perfmon on Q3, rdbg
  on QPro), `init.insmod.cfg` (+ `usbip-vudc.ko` on Q3)
- `asm/` — `patch_init.S` (llcc enforcing patch, embedded in orchestrate.py), the injection ctor
  stub (generated in-code by `build_inject_stub`, N-file / dynamic tables), `libas_restart.S.tmpl`
  (system_server restart stub), `cred_patch.S.tmpl` (cred-patch + status-page sync; `@ENF_OFF@`/
  `@CRED_OFF@` substituted per target)
- `java/Stager.java`, `java/Writer.java` → `e2e.dex` — firmware-independent Dirty-Frag primitives
- `postex/postex.sh` + `postex/assets/{singularity_magisk.sh, singularity-Magisk.apk}` — the root payload

## Adding a new firmware
One command (see `PORTING.md` for details + the manual equivalent):

```
python3 port.py --zip q3_<build>.zip --name quest3-<short> --device <SERIAL>
python3 orchestrate.py -t targets/quest3-<short>.json
```

`port.py` extracts the carrier/cfg/vmlinux from the exact-build zip, computes DELTA, and derives
libeva/libandroid offsets from the device's own libs. No code changes — the orchestrator auto-derives
the carrier ELF layout and repoints its relocations. Only `vermagic` + `delta_selinux_from_anchor`
have differed between builds so far (userspace libs unchanged).

> Authorized bug-bounty research only. `--no-restore` leaves the device permissive; the default
> restores (setenforce 1; rmmod; reboot).
