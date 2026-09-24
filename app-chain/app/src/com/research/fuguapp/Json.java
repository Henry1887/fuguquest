package com.research.fuguapp;

/**
 * Minimal 2-level accessor over the flat target JSON (same shape the primary chain's run.sh reads).
 * Not a general parser — just s(top,key) / sOr / has for "top": { "key": "value-or-number" }.
 */
public class Json {
    final String t;
    Json(String s) { t = s; }
    public static Json parse(String s) { return new Json(s); }

    public String s(String top, String key) {
        String v = get(top, key);
        if (v == null) throw new RuntimeException("missing " + top + "." + key);
        return v;
    }
    public String sOr(String top, String key, String def) { String v = get(top, key); return v == null ? def : v; }
    public boolean has(String top) { return t.indexOf("\"" + top + "\"") >= 0; }

    // scan for "top": { ... "key": <value> ... } (value = string or bare number/bool up to , or })
    String get(String top, String key) {
        int ti = t.indexOf("\"" + top + "\"");
        if (ti < 0) return null;
        int brace = t.indexOf('{', ti);
        if (brace < 0) return null;
        int end = matchBrace(t, brace);
        String block = t.substring(brace, end < 0 ? t.length() : end);
        int ki = block.indexOf("\"" + key + "\"");
        if (ki < 0) return null;
        int colon = block.indexOf(':', ki);
        if (colon < 0) return null;
        int p = colon + 1;
        while (p < block.length() && (block.charAt(p) == ' ' || block.charAt(p) == '\t')) p++;
        if (p >= block.length()) return null;
        if (block.charAt(p) == '"') {
            int q = block.indexOf('"', p + 1);
            return block.substring(p + 1, q);
        }
        int q = p;
        while (q < block.length() && ",}\n\r ".indexOf(block.charAt(q)) < 0) q++;
        return block.substring(p, q).trim();
    }
    static int matchBrace(String s, int open) {
        int depth = 0;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return i + 1; }
        }
        return -1;
    }
}
