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
import os

# --- toolchain bin directories -------------------------------------------------------------------
# AOSP clang (aarch64-linux-gnu): builds the carrier .ko diff patches + injection/cred asm.
CLANG_BIN = os.environ.get("AOSP_CLANG_BIN", "/home/henry/Tools/aosp-clang/clang-r450784e/bin")
# Android NDK llvm prebuilt bin (aarch64-linux-android*-clang): native PoCs / rebuilding e2e.dex tools.
NDK_BIN   = os.environ.get("NDK_BIN",
    "/home/henry/Tools/android-sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin")

# --- individual tools (derived from the bin dirs; the four the scripts actually invoke) -----------
def _tool(bindir, name):
    p = os.path.join(bindir, name)
    return p + ".exe" if os.name == "nt" and not p.lower().endswith(".exe") else p   # Windows: clang.exe etc.
CLANG     = _tool(CLANG_BIN, "clang")
OBJCOPY   = _tool(CLANG_BIN, "llvm-objcopy")
READELF   = _tool(CLANG_BIN, "llvm-readelf")
NM        = _tool(CLANG_BIN, "llvm-nm")
NDK_CLANG = _tool(NDK_BIN, "aarch64-linux-android30-clang")

# --- standalone binaries (PATH name by default; override with an absolute path via env) -----------
PDG            = os.environ.get("PAYLOAD_DUMPER",
    "/home/henry/Tools/payload-dumper-go_1.3.0_linux_amd64/payload-dumper-go")
DEBUGFS        = os.environ.get("DEBUGFS", "debugfs")
VMLINUX_TO_ELF = os.environ.get("VMLINUX_TO_ELF", "vmlinux-to-elf")
