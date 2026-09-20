#!/usr/bin/env python3
# toolconf.py — ONE place for every external tool location used by the DirtyFrag-LPE scripts.
# Change a path here (or set the matching env var) and orchestrate.py / build_credmod.py / port.py
# all pick it up. Env vars win over the defaults below, so you can override without editing the file:
#
#   AOSP_CLANG_BIN   dir holding clang + llvm-objcopy/readelf/nm   (kernel-module .S/.ko builds)
#   NDK_BIN          NDK llvm prebuilt bin dir                     (native/e2e.dex rebuilds)
#   PAYLOAD_DUMPER   payload-dumper-go binary                      (port.py partition extract)
#   DEBUGFS          debugfs binary                                (port.py ext image extract)
#   VMLINUX_TO_ELF   vmlinux-to-elf binary                         (port.py kernel symbols)
import os, shutil

# --- toolchain bin directories -------------------------------------------------------------------
# AOSP clang (aarch64-linux-gnu): builds the carrier .ko diff patches + injection/cred asm.
CLANG_BIN = os.environ.get("AOSP_CLANG_BIN", "/home/henry/Tools/aosp-clang/clang-r450784e/bin")
# Android NDK llvm prebuilt bin (aarch64-linux-android*-clang): native PoCs / rebuilding e2e.dex tools.
NDK_BIN   = os.environ.get("NDK_BIN",
    "/home/henry/Tools/android-sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin")

# --- resolver: prefer the configured bin dir, else fall back to the tool on PATH ------------------
# So it "just works" if clang/llvm are installed and on PATH (e.g. `winget install LLVM.LLVM`) even
# when AOSP_CLANG_BIN still points at the default. `.exe` is added on Windows. If nothing is found,
# the configured path is returned so the eventual error names the expected location.
def _tool(bindir, name):
    exe = name + ".exe" if os.name == "nt" else name
    cand = os.path.join(bindir, exe)
    if os.path.isfile(cand): return cand
    return shutil.which(name) or shutil.which(exe) or cand

def _bin(envvar, default, name):   # standalone binary: env path -> configured -> PATH -> name
    p = os.environ.get(envvar, default)
    if os.path.isfile(p): return p
    return shutil.which(p) or shutil.which(name) or p

# --- individual tools (the ones the scripts actually invoke) --------------------------------------
CLANG     = _tool(CLANG_BIN, "clang")
OBJCOPY   = _tool(CLANG_BIN, "llvm-objcopy")
READELF   = _tool(CLANG_BIN, "llvm-readelf")
NM        = _tool(CLANG_BIN, "llvm-nm")
NDK_CLANG = _tool(NDK_BIN, "aarch64-linux-android30-clang")

# --- standalone binaries (env path, else PATH) ---------------------------------------------------
PDG            = _bin("PAYLOAD_DUMPER", "/home/henry/Tools/payload-dumper-go_1.3.0_linux_amd64/payload-dumper-go", "payload-dumper-go")
DEBUGFS        = _bin("DEBUGFS", "debugfs", "debugfs")
VMLINUX_TO_ELF = _bin("VMLINUX_TO_ELF", "vmlinux-to-elf", "vmlinux-to-elf")
