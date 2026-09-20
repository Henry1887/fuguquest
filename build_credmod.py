#!/usr/bin/env python3
# build_credmod.py <carrier.ko> <out.ko> <dsel> <dfv> <dpt> <pid> <dssuse> [enf_off] [cred_off]
# Diff-patch a NOT-loaded carrier's init_module into an enforcing=0 + status-sync + cred-patch payload.
# deltas are (symbol - __platform_driver_register) from the target vmlinux (signed, 32-bit range).
# enf_off/cred_off default to Q3 5.10 (0 / 0x778); pass 1 / 0x7e8 for Quest Pro 4.19. One template,
# both devices — the caller (orchestrate.py) reads them from the target JSON.
import struct, subprocess, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
TC = os.environ.get("AOSP_CLANG_BIN", "/home/henry/Tools/aosp-clang/clang-r450784e/bin")
CLANG, OBJCOPY, READELF = (os.path.join(TC, x) for x in ("clang", "llvm-objcopy", "llvm-readelf"))
R_AARCH64_CALL26 = 0x11b

def _int(x): return int(x, 16) if isinstance(x, str) and x.lower().startswith("0x") else int(x)

# <carrier> <out> <dsel> <dfv> <dpt> <pid> <dssuse> [enf_off] [cred_off] [dtext] [detext]
carrier, out = sys.argv[1], sys.argv[2]
dsel, dfv, dpt, pid, dssuse = (_int(x) for x in sys.argv[3:8])
enf_off  = _int(sys.argv[8]) if len(sys.argv) > 8 else 0        # selinux_state.enforcing byte offset
cred_off = _int(sys.argv[9]) if len(sys.argv) > 9 else 0x778    # task_struct->cred
# optional kernel-text bounds (anchor-relative). If given, the module bails cleanly (ret, no writes)
# unless the decoded pdr lands in [_text,_etext) — turns a bad/veneer anchor decode into a no-op
# instead of a kernel panic. Q3 targets omit these (proven direct-bl decode); QPro passes them.
dtext = _int(sys.argv[10]) if len(sys.argv) > 10 else None   # _text - anchor (lower bound)
guarded = dtext is not None

# Lower-bound guard only (compact — fits the inject-lib gap): bail (ret 0, no writes) unless
# pdr >= _text. On arm64 the module region sits BELOW _text, so a PLT-veneer decode lands < _text
# and is rejected -> a bad anchor decode becomes a clean no-op instead of a kernel panic.
GUARD = """    // guard: bail unless pdr >= _text (rejects a below-_text PLT veneer / bad decode)
    movz w9, #0                  // [G0] DTEXT_lo
    movk w9, #0, lsl #16         // [G1] DTEXT_hi
    add  x9, x19, w9, sxtw
    cmp  x19, x9
    b.lo done"""

# --- assemble the template (substitute per-target struct offsets) ---
tmpl = open(os.path.join(HERE, "asm", "cred_patch.S.tmpl")).read()
src = tmpl.replace("@ENF_OFF@", str(enf_off)).replace("@CRED_OFF@", hex(cred_off)) \
          .replace("@GUARD@", GUARD if guarded else "")
s = "/tmp/cred_patch.S"; o = "/tmp/cred_patch.o"; b = "/tmp/cred_patch.bin"
open(s, "w").write(src)
subprocess.run([CLANG, "-target", "aarch64-linux-gnu", "-c", s, "-o", o], check=True, capture_output=True)
subprocess.run([OBJCOPY, "-O", "binary", "--only-section=.patch", o, b], check=True)
patch = bytearray(open(b, "rb").read())
anchor_off = None
for l in subprocess.run([READELF, "-s", o], capture_output=True, text=True).stdout.splitlines():
    f = l.split()
    if len(f) >= 8 and f[7] == "anchor": anchor_off = int(f[1], 16)
assert anchor_off is not None, "anchor label not found"

# --- patch the 8 movz/movk (w-reg) immediates in program order ---
def set_imm16(word, imm):  # keep opcode+Rd+hw, set imm16 (bits 20:5)
    return (word & ~(0xffff << 5)) | ((imm & 0xffff) << 5)
mov_offsets = []
for off in range(0, len(patch), 4):
    w = struct.unpack_from("<I", patch, off)[0]
    if (w & 0xff800000) in (0x52800000, 0x72800000):  # movz/movk, sf=0 (w-reg)
        mov_offsets.append(off)
# program order: [guard: DTEXT] then DSEL, DSSUSE, DFV, DPT, PID
def lohi(v): return [v & 0xffff, (v >> 16) & 0xffff]
vals = (lohi(dtext) if guarded else []) + \
       lohi(dsel) + lohi(dssuse) + lohi(dfv) + lohi(dpt) + lohi(pid)
want_n = 12 if guarded else 10
assert len(mov_offsets) == want_n, f"expected {want_n} movz/movk-w, got {len(mov_offsets)}"
for off, imm in zip(mov_offsets, vals):
    struct.pack_into("<I", patch, off, set_imm16(struct.unpack_from("<I", patch, off)[0], imm))

# --- ELF splice into carrier .init.text + fix relocations ---
d = bytearray(open(carrier, "rb").read())
e_shoff, = struct.unpack_from("<Q", d, 0x28)
shentsz, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
secs = []
for i in range(shnum):
    so = e_shoff + i * shentsz
    nm, = struct.unpack_from("<I", d, so)
    sh_type, = struct.unpack_from("<I", d, so + 4)
    sh_off, sh_size = struct.unpack_from("<QQ", d, so + 24)
    sh_link, sh_info = struct.unpack_from("<II", d, so + 40)
    sh_entsz, = struct.unpack_from("<Q", d, so + 56)
    secs.append(dict(nm=nm, type=sh_type, off=sh_off, size=sh_size, link=sh_link, info=sh_info, entsz=sh_entsz))
strtab_off = secs[shstrndx]["off"]
def sname(nm):
    e = d.index(b"\0", strtab_off + nm); return d[strtab_off + nm:e].decode()
byname = {sname(s["nm"]): s for s in secs}
it = byname[".init.text"]; rela = byname[".rela.init.text"]
assert it["size"] >= len(patch), f".init.text {it['size']} < patch {len(patch)}"
d[it["off"]:it["off"] + len(patch)] = patch
# symtab/strtab for symbol names of relocations
symtab = secs[rela["link"]]; sym_strtab = secs[symtab["link"]]["off"]
def symname(idx):
    so = symtab["off"] + idx * 24
    nm, = struct.unpack_from("<I", d, so)
    e = d.index(b"\0", sym_strtab + nm); return d[sym_strtab + nm:e].decode()
n = rela["size"] // 24; repointed = 0
for i in range(n):
    e = rela["off"] + i * 24
    r_off, r_info = struct.unpack_from("<QQ", d, e)
    typ = r_info & 0xffffffff; sym = r_info >> 32
    if typ == R_AARCH64_CALL26 and symname(sym) == "__platform_driver_register" and repointed == 0:
        struct.pack_into("<Q", d, e, anchor_off); repointed += 1        # anchor -> our slot
    elif r_off < len(patch):
        struct.pack_into("<Q", d, e + 8, 0)                             # -> R_AARCH64_NONE
assert repointed == 1, "did not find __platform_driver_register CALL26 anchor"
open(out, "wb").write(d)
diffs = sum(1 for i in range(len(d)) if d[i] != bytearray(open(carrier, "rb").read())[i])
print(f"{out}: patch {len(patch)}B, anchor@0x{anchor_off:x}, {diffs} diff bytes, pid={pid} "
      f"dsel={dsel:#x} dfv={dfv&0xffffffff:#x} dpt={dpt&0xffffffff:#x}")
