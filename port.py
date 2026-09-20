#!/usr/bin/env python3
# port.py — gather everything needed for a new firmware target and emit targets/<name>.json.
#
#   python3 port.py --zip q3_<build>.zip --name quest3-<short> [--device SERIAL]
#                   [--anchor __platform_driver_register]
#
# Needs: payload-dumper-go, debugfs, vmlinux-to-elf, llvm-readelf/nm, and (for lib offsets) either
# a connected device of that build OR the vendor/system partitions in the zip. Carrier .ko + cfg +
# DELTA come from the EXACT-build firmware; libeva/libandroid offsets from the device's own libs.
import argparse, json, os, re, struct, subprocess, sys, tempfile, shutil, atexit
HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = "/home/henry/Tools/aosp-clang/clang-r450784e/bin"
READELF, NM = os.path.join(TOOLS, "llvm-readelf"), os.path.join(TOOLS, "llvm-nm")
PDG = os.environ.get("PAYLOAD_DUMPER", "/home/henry/Tools/payload-dumper-go_1.3.0_linux_amd64/payload-dumper-go")
R_AARCH64_CALL26 = 0x11b

def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout
def die(m): print("ERROR:", m); sys.exit(1)

def dump_partitions(zippath, workdir, parts):
    sh(f"cd {workdir} && unzip -o {zippath} payload.bin >/dev/null 2>&1")
    subprocess.run([PDG, "-p", ",".join(parts), "-o", workdir,
                    os.path.join(workdir, "payload.bin")], capture_output=True)

def debugfs_dump(img, inner, outp):
    subprocess.run(["debugfs", "-R", f"dump {inner} {outp}", img], capture_output=True)
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

def lib_from_device_or_zip(name, dev, workdir, part_img, inner):
    local = os.path.join(workdir, name)
    if dev:
        with open(local, "wb") as f:
            f.write(subprocess.run(["adb", "-s", dev, "shell", f"cat {inner_dev(name)}"],
                                   capture_output=True).stdout)
        if os.path.getsize(local) > 1000: return local
    debugfs_dump(part_img, inner, local)
    return local if os.path.exists(local) else None

def inner_dev(name):
    return {"libeva.so": "/vendor/lib64/libeva.so",
            "libandroid_servers.so": "/system/lib64/libandroid_servers.so"}[name]

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
    a = ap.parse_args()
    a.zip = os.path.abspath(a.zip)   # dump_partitions cd's into workdir; zip path must be absolute
    tdir = os.path.join(HERE, "targets", a.name); os.makedirs(tdir, exist_ok=True)
    scratch = os.path.join(HERE, "build"); os.makedirs(scratch, exist_ok=True)   # on disk, not tmpfs
    wd = tempfile.mkdtemp(prefix="port_", dir=scratch)
    atexit.register(lambda: shutil.rmtree(wd, ignore_errors=True))               # 1.4GB payload etc.
    print(f"[*] work dir {wd} (auto-removed on exit)")

    print("[*] dumping boot, vendor, vendor_dlkm ...")
    dump_partitions(a.zip, wd, ["boot", "vendor", "vendor_dlkm"])

    print("[*] extracting carrier + cfg ...")
    ko = os.path.join(tdir, "llcc_perfmon.ko")
    if not debugfs_dump(os.path.join(wd, "vendor_dlkm.img"), "/lib/modules/llcc_perfmon.ko", ko):
        die("carrier llcc_perfmon.ko not found in vendor_dlkm")
    cfg = os.path.join(tdir, "init.insmod.cfg")
    if not debugfs_dump(os.path.join(wd, "vendor.img"), "/etc/init.insmod.cfg", cfg):
        die("init.insmod.cfg not found in vendor")
    # cred carrier: a NOT-loaded module with a big enough .init.text + a __platform_driver_register
    # anchor. usbip-vudc (408B init, dep usbip-core which is loaded) works on both Quest builds.
    credko = os.path.join(tdir, "usbip-vudc.ko")
    if not debugfs_dump(os.path.join(wd, "vendor_dlkm.img"), "/lib/modules/usbip-vudc.ko", credko):
        die("cred carrier usbip-vudc.ko not found in vendor_dlkm")
    vermagic = re.search(r"vermagic=(\S+)", sh(f"strings -a {ko}")).group(1)
    anchor = carrier_anchor_symbol(ko) or a.anchor
    # build_credmod repoints the __platform_driver_register CALL26 in the cred carrier's init.
    cred_relas = sh(f"{READELF} -r {credko}")
    cred_ok = "__platform_driver_register" in cred_relas.split("rela.init.text", 1)[-1].split("Relocation section", 1)[0]
    if not cred_ok:
        print("[!] cred carrier init has no __platform_driver_register CALL26 — build_credmod will "
              "fail; pick another not-loaded cred carrier with a bigger init + that anchor")
    print(f"    carrier vermagic={vermagic}  anchor={anchor}  cred_anchor_ok={cred_ok}")

    print("[*] vmlinux-to-elf (deltas: selinux_state, find_vpid, pid_task, ssuse) ...")
    vm = os.path.join(wd, "vmlinux.elf")
    subprocess.run(["vmlinux-to-elf", os.path.join(wd, "boot.img"), vm], capture_output=True)
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

    print("[*] libeva / libandroid offsets ...")
    libeva = lib_from_device_or_zip("libeva.so", a.device, wd, os.path.join(wd, "vendor_dlkm.img"),
                                    "/lib64/libeva.so")
    libas = lib_from_device_or_zip("libandroid_servers.so", a.device, wd, os.path.join(wd, "vendor.img"),
                                   "/lib64/libandroid_servers.so")
    if not libeva or os.path.getsize(libeva) < 1000: die("could not obtain libeva (connect --device)")
    if not libas or os.path.getsize(libas) < 1000: die("could not obtain libandroid_servers (connect --device)")
    ia_off, ctor = init_array_and_ctor(libeva)
    gap_off, gap_sz = find_gap(libeva)
    dump_off, dump_sz = dump_sym(libas, "NativeInputManager4dumpE")

    build = subprocess.run(["adb", "-s", a.device, "shell", "getprop", "ro.build.version.incremental"],
                           capture_output=True, text=True).stdout.strip() if a.device else "UNKNOWN-set-me"
    tgt = {
        "name": a.name,
        "description": f"Quest 3 build {build}, kernel {vermagic}",
        "device": {"build_incremental": build, "vermagic": vermagic},
        "dirtyfrag": {"sa_spi": "0xdeadbe10", "writer_spi": "0xdeadbe11", "keymat_base": "0x41"},
        "kernel": {"anchor_symbol": anchor, "enforcing_off": 0,
                   "delta_selinux_from_anchor": d32("selinux_state"),
                   "delta_findvpid_from_anchor": d32("find_vpid"),
                   "delta_pidtask_from_anchor": d32("pid_task"),
                   "delta_ssuse_from_anchor": d32("selinux_status_update_setenforce")},
        "carrier": {"device_path": "/vendor/lib/modules/llcc_perfmon.ko",
                    "local_ko": f"{a.name}/llcc_perfmon.ko", "anchor_reloc_off": "0x14"},
        "cred_carrier": {"device_path": "/vendor/lib/modules/usbip-vudc.ko",
                         "local_ko": f"{a.name}/usbip-vudc.ko",
                         "note": "not-loaded, dep usbip-core loaded; 408B init; anchor __platform_driver_register"},
        "libeva": {"device_path": "/vendor/lib64/libeva.so", "init_array_off": hex(ia_off),
                   "orig_ctor_off": hex(ctor), "stub_gap_off": hex(gap_off), "stub_gap_size": gap_sz},
        "libandroid_servers": {"device_path": "/system/lib64/libandroid_servers.so",
                               "dump_off": hex(dump_off), "dump_size": dump_sz},
        "cfg": {"device_path": "/vendor/etc/init.insmod.cfg", "local_cfg": f"{a.name}/init.insmod.cfg",
                "inject_off": "0x21", "inject_len": 54},
        "services": {"tracking": "trackingservice", "insmod_sh": "insmod_sh"},
        "property_socket": "/dev/socket/property_service",
    }
    outp = os.path.join(HERE, "targets", a.name + ".json")
    json.dump(tgt, open(outp, "w"), indent=2)
    print(f"\n[+] wrote {outp}")
    print(f"[+] assets in targets/{a.name}/")
    print("[!] VERIFY before use: cfg.inject_off/inject_len span whole cfg lines >17B before EOF;")
    print("    stub_gap is unused code (a zero run); libeva/libandroid offsets came from",
          "the device" if a.device else "the zip (pass --device for exact)")

if __name__ == "__main__":
    main()
