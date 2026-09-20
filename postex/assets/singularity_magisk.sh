#!/system/bin/sh
# desc: Singularity Magisk fork (v30.7) via tmpfs, no boot patch
# Payload: install + activate the Singularity Magisk fork (Magisk v30.7 with a
# Meta-Quest Zygisk fix) on an already-LPE'd, already-booted Quest, WITHOUT
# patching the boot image.

set -u

R=${IONSTACK_PAYLOAD_RESULT:-/dev/null}
# run.sh resolves and pushes the APK (preferring a signed local copy, else
# downloading the release ON THE HOST) and exports IONSTACK_APK. The download
# cannot happen here: this device has no curl. If IONSTACK_APK is missing the
# APK simply was not staged -- there is nothing this script can do to fetch it.
APK=${IONSTACK_APK:-/data/local/tmp/singularity-Magisk.apk}
DATABIN=/data/adb/magisk
SECURE_DIR=/data/adb
MAGISKTMP=/debug_ramdisk
INTLROOT="$MAGISKTMP/.magisk"
PKG=com.singularity.magisk
ARCH_DIR=lib/arm64-v8a

# Latest versionName/Code for SL Magisk
LATEST_VERSION_CODE=30700
LATEST_VERSION_NAME=d5cca8b2
WORK=/data/local/tmp/.sl_magisk_extract

# live_setup.sh stops zygote around the setup so Zygisk is present from the
# moment every app process is forked. On a headset that restarts the whole VR
# shell for ~30s, so it is opt-in here rather than the default.
# DEVIATION: default 0. Set SL_RESTART_ZYGOTE=1 for the full live_setup.sh flow.
RESTART_ZYGOTE=${SL_RESTART_ZYGOTE:-0}

log()  { echo "[sl-magisk] $*"; }
res()  { echo "$*" >> "$R"; }
die()  { res "sl_magisk=fail stage=$1 reason=$2"; log "FAIL ($1): $2"; exit 1; }

# --- 1. prerequisites --------------------------------------------------------
[ "$(id -u 2>/dev/null)" = 0 ] || die prereq not_root

enf=$(cat /sys/fs/selinux/enforce 2>/dev/null || echo "?")
if [ "$enf" != 0 ]; then
  log "WARNING: SELinux enforce=$enf (expected 0); daemon context work may be denied"
  res "sl_magisk_selinux=$enf"
fi

# run.sh is the only thing that stages the APK (this device has no curl).
[ -f "$APK" ] || die apk "not found at $APK -- run.sh stages it. Put singularity-Magisk.apk in the repo root, or let run.sh download it, then re-run."
log "using apk: $APK ($(wc -c < "$APK" 2>/dev/null) bytes)"
res "sl_magisk_apk=$APK"

command -v unzip >/dev/null 2>&1 || die tools "no unzip on device (need it to extract magisk binaries)"

mount | grep -q ' /data ' 2>/dev/null || grep -q ' /data ' /proc/mounts 2>/dev/null \
  || die prereq "/data not mounted"

# --- 2. idempotency: already active? -----------------------------------------
if [ -e "$INTLROOT" ] && pgrep -x magiskd >/dev/null 2>&1; then
  ver=$("$MAGISKTMP/magisk64" -c 2>/dev/null || echo "?")
  log "already active (magiskd running, magisk tmpfs present); ver=$ver"
  res "sl_magisk=already_active ver=$ver"
  exit 0
fi

# --- 3. extract magisk binaries from the APK into DATABIN --------------------
# The daemon (bootstages.rs setup_magisk_env) hard-requires DATABIN/busybox or
# it aborts post-fs-data into safe mode, so busybox is NOT optional.
rm -rf "$WORK"; mkdir -p "$WORK" || die extract "cannot mkdir $WORK"
mkdir -p "$DATABIN" || die extract "cannot mkdir $DATABIN"

extract() { # <zip entry> <dest name> <required 0|1>
  if unzip -o -j "$APK" "$1" -d "$WORK" >/dev/null 2>&1 && [ -f "$WORK/$(basename "$1")" ]; then
    cp -f "$WORK/$(basename "$1")" "$DATABIN/$2" && chmod 755 "$DATABIN/$2"
    log "extracted $2"
  elif [ "$3" = 1 ]; then
    die extract "missing required entry $1 in apk"
  else
    log "skip optional $2 (no $1)"
  fi
}

extract "$ARCH_DIR/libmagisk.so"       magisk64     1
extract "$ARCH_DIR/libmagiskboot.so"   magiskboot   1
extract "$ARCH_DIR/libmagiskinit.so"   magiskinit   1
extract "$ARCH_DIR/libmagiskpolicy.so" magiskpolicy 1
extract "$ARCH_DIR/libbusybox.so"      busybox      1
extract "lib/armeabi-v7a/libmagisk.so" magisk32     0   # for 32-bit su clients
extract "assets/stub.apk"              stub.apk     0
chmod 644 "$DATABIN/stub.apk" 2>/dev/null

# live_setup.sh:129 -- module installers source these from MAGISKBIN.
unzip -oj "$APK" 'assets/*.sh' -d "$DATABIN" >/dev/null 2>&1 \
  && log "extracted assets/*.sh into $DATABIN" \
  || log "WARNING: no assets/*.sh in apk; module installers may fail"

# live_setup.sh:130-132
mkdir -p "$SECURE_DIR/modules" "$SECURE_DIR/post-fs-data.d" "$SECURE_DIR/service.d" 2>/dev/null
res "sl_magisk_databin=ok"

# --- 4. install the manager app ----------------------------------------------
# DEVIATION FROM OUR OLD ORDER, MATCHING live_setup.sh:54 -- the app goes in
# BEFORE the boot stages. post_fs_data() -> preserve_stub_apk() and
# boot_complete() -> ensure_manager() both look for the manager; installing
# afterwards meant the first manager check ran against a package that was not
# there yet.
# Install (or replace) the manager, handling the ONE failure that otherwise
# self-destructs: a signature conflict. If a manager built with a DIFFERENT
# signing key is already installed, `pm install -r` fails
# (INSTALL_FAILED_UPDATE_INCOMPATIBLE / signatures do not match), the old
# manager stays, and then the stub.apk we stage below (from THIS apk) carries a
# cert that does not match it -> preserve_stub_apk()/check_orig() flags a
# mismatch and uninstalls the app a few hundred ms after it opens. The GitHub
# release is CN=Android Debug while a hand-signed build is a release key, so
# swapping between them trips exactly this. On a signature conflict, uninstall
# the stale manager and install cleanly so the manager and the staged stub.apk
# share one key.
install_manager() {
  pm install -r -g "$APK" >/data/local/tmp/sl_pm_out 2>&1 && return 0
  if grep -qiE "INSTALL_FAILED_UPDATE_INCOMPATIBLE|signature|INSTALL_FAILED_SHARED_USER_INCOMPATIBLE" /data/local/tmp/sl_pm_out; then
    log "manager already installed with a DIFFERENT signing key; removing it so"
    log "  the new one and its stub.apk share a cert (avoids the self-uninstall)"
    pm uninstall "$PKG" >/dev/null 2>&1
    pm install -r -g "$APK" >/data/local/tmp/sl_pm_out 2>&1 && return 0
  fi
  return 1
}

# Version gate: only touch the manager app if it is missing or outdated.
dp_out=$(dumpsys package "$PKG" 2>/dev/null)
cur_vcode=$(printf '%s\n' "$dp_out" | grep -m1 -oE 'versionCode=[0-9]+' | cut -d= -f2)
cur_vcode=${cur_vcode:-0}
cur_vname=$(printf '%s\n' "$dp_out" | grep -m1 -oE 'versionName=[^ ]+' | cut -d= -f2)
cur_vname=${cur_vname:-}

if pm path "$PKG" >/dev/null 2>&1 \
    && [ "$cur_vcode" -ge "$LATEST_VERSION_CODE" ] 2>/dev/null \
    && [ "$cur_vname" = "$LATEST_VERSION_NAME" ]; then
  log "manager already up to date (installed vcode=$cur_vcode vname=$cur_vname, latest vcode=$LATEST_VERSION_CODE vname=$LATEST_VERSION_NAME); skipping install"
  res "sl_magisk_pm=up_to_date vcode=$cur_vcode vname=$cur_vname"
else
  if pm path "$PKG" >/dev/null 2>&1; then
    log "manager outdated (installed vcode=$cur_vcode vname=$cur_vname, latest vcode=$LATEST_VERSION_CODE vname=$LATEST_VERSION_NAME); updating in place"
  else
    log "manager not installed ($PKG); installing"
  fi
  if install_manager; then
    log "installed manager $PKG"
    res "sl_magisk_pm=ok"
  else
    log "WARNING: pm install failed: $(tail -c 200 /data/local/tmp/sl_pm_out 2>/dev/null)"
    res "sl_magisk_pm=fail msg=\"$(tail -c 120 /data/local/tmp/sl_pm_out 2>/dev/null | tr '\n' ' ')\""
  fi
fi

# --- 5. stand up the magisk tmpfs at /debug_ramdisk --------------------------
# get_magisk_tmp() accepts ONLY /debug_ramdisk or /sbin, and live_setup.sh picks
# /debug_ramdisk on "Android Q+ without sbin" (its line 122-124), which is us.
#
# DEVIATION: live_setup.sh:77-79 force-unmounts /debug_ramdisk. We refuse
# instead. That is an emulator script; here, mounting a tmpfs over a NON-empty
# /debug_ramdisk hides live content for every process on the device.
dr_mounted=0; grep -q ' /debug_ramdisk ' /proc/mounts 2>/dev/null && dr_mounted=1
dr_entries=$(ls -A "$MAGISKTMP" 2>/dev/null | tr '\n' ' ')
log "/debug_ramdisk: mounted=$dr_mounted entries=[$dr_entries]"
res "sl_magisk_debug_ramdisk=\"mounted=$dr_mounted entries=[$dr_entries]\""

case "$dr_entries" in
  ""|".magisk "|".magisk") : ;;
  *) die tmpfs "/debug_ramdisk is non-empty ([$dr_entries]); refusing to mount over live content" ;;
esac

if [ ! -e "$MAGISKTMP" ]; then
  die tmpfs "/debug_ramdisk does not exist and / is read-only; cannot create mountpoint"
fi

if [ ! -w "$MAGISKTMP" ] || [ "$dr_mounted" = 0 ]; then
  if mount -t tmpfs -o mode=0755 magisk "$MAGISKTMP" 2>/data/local/tmp/sl_mnt_err; then
    log "mounted tmpfs at $MAGISKTMP"
  else
    die tmpfs "mount tmpfs at $MAGISKTMP failed: $(cat /data/local/tmp/sl_mnt_err 2>/dev/null)"
  fi
fi

# live_setup.sh:134-138 -- these four go on the tmpfs, not just in DATABIN.
# stub.apk is the one that used to be missing: preserve_stub_apk()
# (package.rs:444) reads $MAGISKTMP/stub.apk to populate `trusted_cert`, and
# post_fs_data() calls it first thing (bootstages.rs:113). magiskinit normally
# stages it in initramfs. Without it trusted_cert stays EMPTY, every manager
# check mismatches in check_orig() (package.rs:301) and calls uninstall_pkg() --
# the app deletes itself a few hundred ms after you open it, logged as
# "pkg: APK signature mismatch" in /cache/magisk.log. `check-signature` is on by
# default in release builds (native/src/core/Cargo.toml:11). preserve_stub_apk()
# then REMOVES the file, so this must be redone every boot.
for f in magisk64 magisk32 magiskpolicy stub.apk; do
  [ -f "$DATABIN/$f" ] || { log "skip $f (not extracted)"; continue; }
  cp -af "$DATABIN/$f" "$MAGISKTMP/$f" || die tmpfs "cannot place $f on tmpfs"
done
chmod 755 "$MAGISKTMP/magisk64" 2>/dev/null
chmod 644 "$MAGISKTMP/stub.apk" 2>/dev/null
ln -sf magisk64 "$MAGISKTMP/magisk" 2>/dev/null
MAGISK="$MAGISKTMP/magisk64"

# live_setup.sh:143-145 -- applet symlinks. `su` is the one apps invoke.
ln -sf ./magisk64    "$MAGISKTMP/su"        2>/dev/null
ln -sf ./magisk64    "$MAGISKTMP/resetprop" 2>/dev/null
ln -sf ./magiskpolicy "$MAGISKTMP/supolicy" 2>/dev/null

# live_setup.sh:147-151. worker is its own PRIVATE tmpfs -- it is the workdir
# module mounts are staged in, and it must not propagate to other namespaces.
mkdir -p "$INTLROOT/device" "$INTLROOT/worker" || die tmpfs "cannot create $INTLROOT layout"
if ! grep -q " $INTLROOT/worker " /proc/mounts 2>/dev/null; then
  mount -t tmpfs -o mode=0755 magisk "$INTLROOT/worker" 2>/dev/null \
    && log "mounted worker tmpfs" || log "WARNING: worker tmpfs mount failed"
fi
mount --make-private "$INTLROOT/worker" 2>/dev/null || log "WARNING: make-private on worker failed"
# The daemon only reads RECOVERYMODE from this; write it fresh so nothing stale
# is inherited. live_setup.sh just touches it.
{ echo "KEEPVERITY=true"; echo "KEEPFORCEENCRYPT=true"; echo "RECOVERYMODE=false"; } > "$INTLROOT/config"

export MAGISKTMP
# live_setup.sh:154 -- finds/creates the preinit device used for sepolicy rules.
MAKEDEV=1 "$MAGISK" --preinit-device >/data/local/tmp/sl_preinit_out 2>&1 \
  && log "preinit-device: $(cat /data/local/tmp/sl_preinit_out 2>/dev/null)" \
  || log "WARNING: --preinit-device failed: $(head -c 160 /data/local/tmp/sl_preinit_out 2>/dev/null)"
res "sl_magisk_tmpfs=ok"

# --- 6. SELinux: install the magisk domain into the LIVE policy --------------
# live_setup.sh:156-169. This is what creates the `magisk` SELinux domain that
# MagiskSU needs to hand root to other apps. Without it, su for apps only works
# while SELinux is permissive -- which is the state our exploit happens to leave
# behind, but leaning on that is not the same as Magisk working.
RULESCMD=""
rule="$INTLROOT/preinit/sepolicy.rule"
[ -f "$rule" ] && RULESCMD="--apply $rule"
if [ -d /sys/fs/selinux ]; then
  if [ -f /vendor/etc/selinux/precompiled_sepolicy ]; then
    "$DATABIN/magiskpolicy" --load /vendor/etc/selinux/precompiled_sepolicy --live --magisk $RULESCMD \
      >/data/local/tmp/sl_pol_out 2>&1
  elif [ -f /sepolicy ]; then
    "$DATABIN/magiskpolicy" --load /sepolicy --live --magisk $RULESCMD >/data/local/tmp/sl_pol_out 2>&1
  else
    "$DATABIN/magiskpolicy" --live --magisk $RULESCMD >/data/local/tmp/sl_pol_out 2>&1
  fi
  if [ $? = 0 ]; then
    log "magiskpolicy --live --magisk applied"
    res "sl_magisk_sepolicy=ok"
  else
    log "WARNING: magiskpolicy failed: $(head -c 200 /data/local/tmp/sl_pol_out 2>/dev/null)"
    res "sl_magisk_sepolicy=fail"
  fi
fi

# --- 7. drive the boot stages ------------------------------------------------
# live_setup.sh:74-82,171-177. Stopping zygote first is what makes Zygisk apply
# to every app process; without it Zygisk cannot touch anything already running.
# `start` is trapped so a failure or a payload timeout cannot leave the headset
# with no framework. (A SIGKILL would still skip the trap -- if this payload is
# enabled, give it room via IONSTACK_PAYLOAD_TIMEOUT.)
if [ "$RESTART_ZYGOTE" = 1 ]; then
  log "stopping framework (SL_RESTART_ZYGOTE=1)"
  trap 'start 2>/dev/null; trap - EXIT INT TERM' EXIT INT TERM
  "$MAGISK" --stop 2>/dev/null
  stop
  setprop sys.boot_completed 0
  res "sl_magisk_zygote_restart=1"
else
  log "NOT restarting the framework; Zygisk will not inject already-running procs"
  log "  (set SL_RESTART_ZYGOTE=1 for the full live_setup.sh behaviour)"
  res "sl_magisk_zygote_restart=0"
fi

log "post-fs-data ..."
"$MAGISK" --post-fs-data 2>/data/local/tmp/sl_pfd_err
if ! pgrep -x magiskd >/dev/null 2>&1; then
  die daemon "magiskd not running after --post-fs-data: $(head -c 200 /data/local/tmp/sl_pfd_err 2>/dev/null)"
fi
ver=$("$MAGISK" -c 2>/dev/null || echo "?")
log "magiskd up; ver=$ver"
res "sl_magisk_daemon=up ver=$ver"

if [ "$RESTART_ZYGOTE" = 1 ]; then
  log "starting framework"
  start
  trap - EXIT INT TERM
fi

log "service ..."
"$MAGISK" --service 2>/dev/null || log "WARNING: --service returned nonzero"
# live_setup.sh:176 -- let zygote come up before boot-complete resets its props.
sleep 2
log "boot-complete ..."
"$MAGISK" --boot-complete 2>/dev/null || log "WARNING: --boot-complete returned nonzero"

# --- 8. summary --------------------------------------------------------------
mods=$(ls -1 "$SECURE_DIR/modules" 2>/dev/null | wc -l 2>/dev/null || echo 0)
mgr=$(pm path "$PKG" >/dev/null 2>&1 && echo installed || echo MISSING)
log "done. daemon=up ver=$ver modules=$mods manager=$mgr"
[ "$RESTART_ZYGOTE" = 1 ] || log "NOTE: Zygisk not active for already-running procs (SL_RESTART_ZYGOTE=0)"
res "sl_magisk=ok ver=$ver modules=$mods manager=$mgr"
rm -rf "$WORK"
exit 0
