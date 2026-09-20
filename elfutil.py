#!/usr/bin/env python3
# elfutil.py — tiny pure-Python ELF64 reader so the RUN path (orchestrate.py / build_credmod.py)
# needs ONLY clang (the assembler), not llvm-objcopy or llvm-readelf. Some LLVM installs (e.g. the
# WinGet LLVM.LLVM package) ship clang but omit the llvm-* binutils, which used to break the build.
import struct

def obj_section_and_syms(path, secname):
    """Return (bytes of section `secname`, {symbol_name: st_value}) for a relocatable ELF64 .o.
    Replaces `llvm-objcopy -O binary --only-section=secname` + `llvm-readelf -s`. st_value is the
    section-relative offset of each defined symbol in `secname` (what the assemble step needs)."""
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 2:
        raise ValueError(f"{path}: not an ELF64 file")
    e_shoff, = struct.unpack_from("<Q", d, 0x28)
    shentsz, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
    secs = []
    for i in range(shnum):
        o = e_shoff + i * shentsz
        nm, typ = struct.unpack_from("<II", d, o)
        off, size = struct.unpack_from("<QQ", d, o + 0x18)
        link, = struct.unpack_from("<I", d, o + 0x28)
        entsz, = struct.unpack_from("<Q", d, o + 0x38)
        secs.append(dict(name=nm, type=typ, off=off, size=size, link=link, entsz=entsz))
    shstr = secs[shstrndx]["off"]
    def sname(nm):
        e = d.index(b"\0", shstr + nm); return d[shstr + nm:e].decode()
    named = {sname(s["name"]): (i, s) for i, s in enumerate(secs)}
    if secname not in named:
        raise ValueError(f"{path}: section {secname} not found")
    sec_idx, sec = named[secname]
    raw = d[sec["off"]:sec["off"] + sec["size"]]
    syms = {}
    for s in secs:
        if s["type"] != 2:  # SHT_SYMTAB
            continue
        strtab = secs[s["link"]]["off"]
        n = s["size"] // 24
        for k in range(n):
            e = s["off"] + k * 24
            st_name, = struct.unpack_from("<I", d, e)
            st_shndx, = struct.unpack_from("<H", d, e + 6)
            st_value, = struct.unpack_from("<Q", d, e + 8)
            if st_shndx != sec_idx or st_name == 0:
                continue
            end = d.index(b"\0", strtab + st_name)
            syms[d[strtab + st_name:end].decode()] = st_value
    return bytearray(raw), syms
