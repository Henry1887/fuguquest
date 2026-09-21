// Minimal two-pass AArch64 assembler — emits the exact instruction set used by the DirtyFrag
// carrier init patch, cred-patch, init_array inject stub and the libandroid_servers restart stub,
// with labels + adr/b/bl/b.ne/cbz fixups. Replaces the clang assemble step (no external toolchain).
// Every emitter is validated byte-for-byte against the previous clang output (see `validate`).
#![allow(dead_code)]
use std::collections::HashMap;

#[derive(Clone)]
enum Fixup {
    Adr { at: usize, label: String },   // ADR Xd, label  (+/-1MB, imm21)
    B { at: usize, label: String },     // B label        (imm26)
    Bl { at: usize, label: String },    // BL label       (imm26)
    Bcond { at: usize, label: String }, // B.cond label   (imm19)
    Cbz { at: usize, label: String },   // CBZ Xt, label  (imm19)
}

pub struct Asm {
    pub code: Vec<u8>,
    labels: HashMap<String, usize>,
    fixups: Vec<Fixup>,
}

fn w(v: u32) -> [u8; 4] { v.to_le_bytes() }

impl Asm {
    pub fn new() -> Self { Asm { code: Vec::new(), labels: HashMap::new(), fixups: Vec::new() } }
    fn emit(&mut self, word: u32) { self.code.extend_from_slice(&w(word)); }
    fn here(&self) -> usize { self.code.len() }

    pub fn label(&mut self, name: &str) { self.labels.insert(name.to_string(), self.here()); }
    pub fn label_off(&self, name: &str) -> usize { self.labels[name] }

    // ---- data directives ----
    pub fn byte(&mut self, b: u8) { self.code.push(b); }
    pub fn bytes(&mut self, b: &[u8]) { self.code.extend_from_slice(b); }
    pub fn word(&mut self, v: u32) { self.code.extend_from_slice(&w(v)); }
    pub fn quad(&mut self, v: u64) { self.code.extend_from_slice(&v.to_le_bytes()); }
    pub fn asciz(&mut self, s: &str) { self.code.extend_from_slice(s.as_bytes()); self.code.push(0); }
    pub fn space(&mut self, n: usize) { self.code.extend(std::iter::repeat(0u8).take(n)); }
    /// Align like clang in an exec (.text/"ax") section: fill 4-byte-aligned gaps with NOP words,
    /// then zero the sub-word remainder.
    pub fn balign(&mut self, a: usize) {
        let mut pad = (a - self.here() % a) % a;
        while pad >= 4 && self.here() % 4 == 0 { self.emit(0xD503201F); pad -= 4; } // nop
        while pad > 0 { self.code.push(0); pad -= 1; }
    }

    // ---- fixed encodings ----
    pub fn bti_c(&mut self) { self.emit(0xD503245F); }
    pub fn paciasp(&mut self) { self.emit(0xD503233F); }
    pub fn autiasp(&mut self) { self.emit(0xD50323BF); }
    pub fn svc0(&mut self) { self.emit(0xD4000001); }
    pub fn ret(&mut self) { self.emit(0xD65F03C0); }
    pub fn ret_reg(&mut self, rn: u32) { self.emit(0xD65F0000 | (rn << 5)); }
    pub fn blr(&mut self, rn: u32) { self.emit(0xD63F0000 | (rn << 5)); }

    // ---- moves ----
    pub fn movz_w(&mut self, rd: u32, imm: u16, hw: u32) { self.emit(0x52800000 | (hw << 21) | ((imm as u32) << 5) | rd); }
    pub fn movk_w(&mut self, rd: u32, imm: u16, hw: u32) { self.emit(0x72800000 | (hw << 21) | ((imm as u32) << 5) | rd); }
    pub fn movz_x(&mut self, rd: u32, imm: u16, hw: u32) { self.emit(0xD2800000 | (hw << 21) | ((imm as u32) << 5) | rd); }
    pub fn movk_x(&mut self, rd: u32, imm: u16, hw: u32) { self.emit(0xF2800000 | (hw << 21) | ((imm as u32) << 5) | rd); }
    pub fn movn_x(&mut self, rd: u32, imm: u16, hw: u32) { self.emit(0x92800000 | (hw << 21) | ((imm as u32) << 5) | rd); }
    /// mov Xd, #imm (small non-negative -> movz; -1..=-65536 -> movn)
    pub fn mov_x_imm(&mut self, rd: u32, val: i64) {
        if val >= 0 && val <= 0xffff { self.movz_x(rd, val as u16, 0); }
        else if val < 0 && val >= -0x10000 { self.movn_x(rd, (!val) as u16, 0); }
        else { panic!("mov_x_imm out of simple range: {}", val); }
    }
    pub fn mov_w_imm(&mut self, rd: u32, val: u16) { self.movz_w(rd, val, 0); }
    /// mov Xd, Xn  (orr Xd, xzr, Xn)
    pub fn mov_x(&mut self, rd: u32, rn: u32) { self.emit(0xAA0003E0 | (rn << 16) | rd); }
    /// mov Wd, wzr  (orr Wd, wzr, wzr)
    pub fn mov_w_wzr(&mut self, rd: u32) { self.emit(0x2A1F03E0 | rd); }
    /// mov Xd, xzr
    pub fn mov_x_xzr(&mut self, rd: u32) { self.emit(0xAA1F03E0 | rd); }
    /// orr Wd, wzr, #1
    pub fn orr_w_1(&mut self, rd: u32) { self.emit(0x320003E0 | rd); }

    // ---- arithmetic (imm12) ----
    pub fn add_imm(&mut self, rd: u32, rn: u32, imm: u32) { self.emit(0x91000000 | (imm << 10) | (rn << 5) | rd); }
    pub fn sub_imm(&mut self, rd: u32, rn: u32, imm: u32) { self.emit(0xD1000000 | (imm << 10) | (rn << 5) | rd); }
    pub fn subs_w_imm(&mut self, rd: u32, rn: u32, imm: u32) { self.emit(0x71000000 | (imm << 10) | (rn << 5) | rd); }
    /// mov Xd, sp  (add Xd, sp, #0); sp=31
    pub fn mov_x_sp(&mut self, rd: u32) { self.add_imm(rd, 31, 0); }
    /// mov x29, sp
    pub fn mov_fp_sp(&mut self) { self.add_imm(29, 31, 0); }
    /// add Xd, Xn, Wm, sxtw
    pub fn add_x_w_sxtw(&mut self, rd: u32, rn: u32, rm: u32) { self.emit(0x8B20C000 | (rm << 16) | (rn << 5) | rd); }

    // ---- loads/stores (imm) ----
    pub fn ldr_x(&mut self, rt: u32, rn: u32, off: u32) { self.emit(0xF9400000 | ((off / 8) << 10) | (rn << 5) | rt); }
    pub fn ldr_w(&mut self, rt: u32, rn: u32, off: u32) { self.emit(0xB9400000 | ((off / 4) << 10) | (rn << 5) | rt); }
    pub fn str_x(&mut self, rt: u32, rn: u32, off: u32) { self.emit(0xF9000000 | ((off / 8) << 10) | (rn << 5) | rt); }
    pub fn str_w(&mut self, rt: u32, rn: u32, off: u32) { self.emit(0xB9000000 | ((off / 4) << 10) | (rn << 5) | rt); }
    /// ldur Xt,[Xn,#simm9]
    pub fn ldur_x(&mut self, rt: u32, rn: u32, off: i32) { self.emit(0xF8400000 | (((off as u32) & 0x1ff) << 12) | (rn << 5) | rt); }
    /// strb Wt,[Xn,#imm12]
    pub fn strb(&mut self, rt: u32, rn: u32, off: u32) { self.emit(0x39000000 | (off << 10) | (rn << 5) | rt); }

    // ---- pair loads/stores (64-bit signed offset, imm7 scaled by 8) ----
    fn imm7(off: i32, scale: i32) -> u32 { (((off / scale) as u32) & 0x7f) << 15 }
    pub fn stp_x(&mut self, rt: u32, rt2: u32, rn: u32, off: i32) { self.emit(0xA9000000 | Self::imm7(off, 8) | (rt2 << 10) | (rn << 5) | rt); }
    pub fn ldp_x(&mut self, rt: u32, rt2: u32, rn: u32, off: i32) { self.emit(0xA9400000 | Self::imm7(off, 8) | (rt2 << 10) | (rn << 5) | rt); }
    pub fn stp_x_preidx(&mut self, rt: u32, rt2: u32, rn: u32, off: i32) { self.emit(0xA9800000 | Self::imm7(off, 8) | (rt2 << 10) | (rn << 5) | rt); }
    pub fn ldp_x_postidx(&mut self, rt: u32, rt2: u32, rn: u32, off: i32) { self.emit(0xA8C00000 | Self::imm7(off, 8) | (rt2 << 10) | (rn << 5) | rt); }
    /// stp Wt,Wt2,[Xn,#imm7*4]
    pub fn stp_w(&mut self, rt: u32, rt2: u32, rn: u32, off: i32) { self.emit(0x29000000 | Self::imm7(off, 4) | (rt2 << 10) | (rn << 5) | rt); }

    // ---- pc-relative (recorded, resolved in finish()) ----
    pub fn adr(&mut self, rd: u32, label: &str) { self.fixups.push(Fixup::Adr { at: self.here(), label: label.into() }); self.emit(0x10000000 | rd); }
    pub fn b(&mut self, label: &str) { self.fixups.push(Fixup::B { at: self.here(), label: label.into() }); self.emit(0x14000000); }
    pub fn bl(&mut self, label: &str) { self.fixups.push(Fixup::Bl { at: self.here(), label: label.into() }); self.emit(0x94000000); }
    pub fn bne(&mut self, label: &str) { self.fixups.push(Fixup::Bcond { at: self.here(), label: label.into() }); self.emit(0x54000001); }
    pub fn cbz_x(&mut self, rt: u32, label: &str) { self.fixups.push(Fixup::Cbz { at: self.here(), label: label.into() }); self.emit(0xB4000000 | rt); }

    /// Resolve all fixups; returns (bytes, labels).
    pub fn finish(mut self) -> (Vec<u8>, HashMap<String, usize>) {
        for f in &self.fixups {
            match f {
                Fixup::Adr { at, label } => {
                    let target = self.labels[label] as i64;
                    let imm = target - *at as i64;               // ADR: byte delta from the ADR itself
                    let imm = (imm as i32) & 0x1fffff;
                    let base = u32::from_le_bytes([self.code[*at], self.code[*at+1], self.code[*at+2], self.code[*at+3]]);
                    let word = base | (((imm as u32) & 3) << 29) | ((((imm as u32) >> 2) & 0x7ffff) << 5);
                    self.code[*at..*at+4].copy_from_slice(&w(word));
                }
                Fixup::B { at, label } | Fixup::Bl { at, label } => {
                    let target = self.labels[label] as i64;
                    let imm26 = (((target - *at as i64) >> 2) as u32) & 0x03ffffff;
                    let base = u32::from_le_bytes([self.code[*at], self.code[*at+1], self.code[*at+2], self.code[*at+3]]);
                    self.code[*at..*at+4].copy_from_slice(&w(base | imm26));
                }
                Fixup::Bcond { at, label } | Fixup::Cbz { at, label } => {
                    let target = self.labels[label] as i64;
                    let imm19 = (((target - *at as i64) >> 2) as u32) & 0x7ffff;
                    let base = u32::from_le_bytes([self.code[*at], self.code[*at+1], self.code[*at+2], self.code[*at+3]]);
                    self.code[*at..*at+4].copy_from_slice(&w(base | (imm19 << 5)));
                }
            }
        }
        (self.code, self.labels)
    }
}
