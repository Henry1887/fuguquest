package com.research.fuguapp;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

/** Headless test entry (app is debuggable): am instrument -w com.research.fuguapp/.Inst
 *  Runs the chain in the app's process (untrusted_app) and returns the result on stdout. */
public class Inst extends Instrumentation {
    @Override public void onCreate(Bundle a) { super.onCreate(a); start(); }
    @Override public void onStart() {
        String res;
        try { res = Chain.run(getTargetContext()); }
        catch (Throwable t) { res = "ERR " + t; }
        Bundle b = new Bundle(); b.putString("res", res);
        finish(Activity.RESULT_OK, b);
    }
}
