package com.research.fuguapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/** User taps the app -> runs the no-adb chain on a background thread; result to logcat (tag FUGUAPP)
 *  and files/result. (VR shell suppresses adb `am start`, but a user-initiated launch runs onCreate.) */
public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        new Thread(new Worker(this)).start();
    }
    static class Worker implements Runnable {
        final Activity a; Worker(Activity a) { this.a = a; }
        public void run() {
            String res = Chain.run(a.getApplicationContext());
            Log.i("FUGUAPP", "RESULT " + res);
            try { java.io.RandomAccessFile r = new java.io.RandomAccessFile(new java.io.File(a.getFilesDir(), "result"), "rw");
                  r.setLength(0); r.write(res.getBytes()); r.close(); } catch (Throwable ignore) {}
        }
    }
}
