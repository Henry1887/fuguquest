// Self-contained AES-128 (FIPS-197) for the Dirty-Frag keystream. Matches the pure-Python fallback
// in the old orchestrate.py (and pycryptodome). Only the first keystream byte is ever needed.
#![allow(dead_code)]

const SBOX: [u8; 256] = {
    // computed at compile time from the standard AES S-box hex
    let hex = *b"637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0\
b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275\
09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf\
d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2\
cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb\
e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08\
ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e\
e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";
    let mut s = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let hi = from_hex(hex[i * 2]);
        let lo = from_hex(hex[i * 2 + 1]);
        s[i] = (hi << 4) | lo;
        i += 1;
    }
    s
};

const fn from_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn xt(a: u8) -> u8 { if a & 0x80 != 0 { (((a as u16) << 1) as u8) ^ 0x1b } else { a << 1 } }

pub struct Aes128 { rk: [[u8; 4]; 44] }

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 { w[i] = [key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]; }
        for i in 4..44 {
            let mut t = w[i-1];
            if i % 4 == 0 {
                t = [t[1], t[2], t[3], t[0]];
                for b in t.iter_mut() { *b = SBOX[*b as usize]; }
                t[0] ^= RCON[i/4 - 1];
            }
            for j in 0..4 { w[i][j] = w[i-4][j] ^ t[j]; }
        }
        Aes128 { rk: w }
    }

    /// Encrypt one 16-byte block (ECB).
    pub fn encrypt(&self, blk: &[u8; 16]) -> [u8; 16] {
        // state as columns: s[c][j]
        let mut s = [[0u8; 4]; 4];
        for c in 0..4 { for j in 0..4 { s[c][j] = blk[c*4 + j]; } }
        for c in 0..4 { for j in 0..4 { s[c][j] ^= self.rk[c][j]; } }
        for rnd in 1..10 {
            s = self.round(s, rnd, false);
        }
        s = self.round(s, 10, true);
        let mut out = [0u8; 16];
        for c in 0..4 { for j in 0..4 { out[c*4 + j] = s[c][j]; } }
        out
    }

    fn round(&self, s: [[u8; 4]; 4], rnd: usize, last: bool) -> [[u8; 4]; 4] {
        // SubBytes
        let mut s2 = [[0u8; 4]; 4];
        for c in 0..4 { for j in 0..4 { s2[c][j] = SBOX[s[c][j] as usize]; } }
        // ShiftRows: rows[j] = [s2[c][j] for c], rotated left by j
        let mut rows = [[0u8; 4]; 4];
        for j in 0..4 { for c in 0..4 { rows[j][c] = s2[c][j]; } }
        for j in 0..4 { rows[j].rotate_left(j); }
        // cols[c][j] = rows[j][c]
        let mut cols = [[0u8; 4]; 4];
        for c in 0..4 { for j in 0..4 { cols[c][j] = rows[j][c]; } }
        let mut out = [[0u8; 4]; 4];
        if !last {
            for c in 0..4 {
                let a = cols[c];
                out[c][0] = xt(a[0]) ^ xt(a[1]) ^ a[1] ^ a[2] ^ a[3];
                out[c][1] = a[0] ^ xt(a[1]) ^ xt(a[2]) ^ a[2] ^ a[3];
                out[c][2] = a[0] ^ a[1] ^ xt(a[2]) ^ xt(a[3]) ^ a[3];
                out[c][3] = xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xt(a[3]);
            }
        } else {
            out = cols;
        }
        let base = rnd * 4;
        for c in 0..4 { for j in 0..4 { out[c][j] ^= self.rk[base + c][j]; } }
        out
    }
}

/// keystream0_fn(keymat_base): returns a closure iv(8B) -> first keystream byte, matching
/// Stager/Writer rfc4106(gcm(aes)) counter block SALT|IV|0x00000002.
pub fn keystream0(keymat_base: u8) -> impl Fn(&[u8; 8]) -> u8 {
    let mut keymat = [0u8; 20];
    for i in 0..20 { keymat[i] = keymat_base.wrapping_add(i as u8); }
    let mut key = [0u8; 16];
    key.copy_from_slice(&keymat[0..16]);
    let salt = [keymat[16], keymat[17], keymat[18], keymat[19]];
    let aes = Aes128::new(&key);
    move |iv: &[u8; 8]| {
        let mut blk = [0u8; 16];
        blk[0..4].copy_from_slice(&salt);
        blk[4..12].copy_from_slice(iv);
        blk[12..16].copy_from_slice(&[0, 0, 0, 2]);
        aes.encrypt(&blk)[0]
    }
}
