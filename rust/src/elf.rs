// ELF64 relocatable (.ko) reader/mutator — section table, symbol table, name lookup. Enough for the
// carrier diff-injection and cred-patch splice (both .init.text and .text-splice modes). Pure Rust,
// replaces the Python struct-unpack logic in build_carrier / build_credmod / elfutil.
#![allow(dead_code)]
use std::collections::HashMap;

pub const R_AARCH64_NONE: u32 = 0;
pub const R_AARCH64_ABS64: u32 = 0x101;
pub const R_AARCH64_CALL26: u32 = 0x11b;

#[derive(Clone)]
pub struct Section {
    pub name: String,
    pub typ: u32,
    pub off: usize,
    pub size: usize,
    pub link: u32,
    pub info: u32,
    pub entsz: usize,
}

pub struct Elf {
    pub data: Vec<u8>,
    pub secs: Vec<Section>,
    pub byname: HashMap<String, usize>,
}

fn u16(d: &[u8], o: usize) -> u16 { u16::from_le_bytes([d[o], d[o+1]]) }
fn u32(d: &[u8], o: usize) -> u32 { u32::from_le_bytes([d[o], d[o+1], d[o+2], d[o+3]]) }
fn u64(d: &[u8], o: usize) -> u64 { u64::from_le_bytes(d[o..o+8].try_into().unwrap()) }

impl Elf {
    pub fn parse(data: Vec<u8>) -> Result<Elf, String> {
        if &data[0..4] != b"\x7fELF" || data[4] != 2 { return Err("not ELF64".into()); }
        let e_shoff = u64(&data, 0x28) as usize;
        let shentsz = u16(&data, 0x3a) as usize;
        let shnum = u16(&data, 0x3c) as usize;
        let shstrndx = u16(&data, 0x3e) as usize;
        // first pass: raw section records (name is an offset into shstrtab)
        let mut raw = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let so = e_shoff + i * shentsz;
            let name_off = u32(&data, so) as usize;
            let typ = u32(&data, so + 4);
            let off = u64(&data, so + 24) as usize;
            let size = u64(&data, so + 32) as usize;
            let link = u32(&data, so + 40);
            let info = u32(&data, so + 44);
            let entsz = u64(&data, so + 56) as usize;
            raw.push((name_off, typ, off, size, link, info, entsz));
        }
        let strtab_off = raw[shstrndx].2;
        let sname = |name_off: usize| -> String {
            let mut e = strtab_off + name_off;
            while data[e] != 0 { e += 1; }
            String::from_utf8_lossy(&data[strtab_off + name_off..e]).into_owned()
        };
        let mut secs = Vec::with_capacity(shnum);
        let mut byname = HashMap::new();
        for (i, r) in raw.iter().enumerate() {
            let nm = sname(r.0);
            byname.insert(nm.clone(), i);
            secs.push(Section { name: nm, typ: r.1, off: r.2, size: r.3, link: r.4, info: r.5, entsz: r.6 });
        }
        Ok(Elf { data, secs, byname })
    }

    pub fn sec(&self, name: &str) -> Option<&Section> { self.byname.get(name).map(|&i| &self.secs[i]) }
    pub fn sec_idx(&self, name: &str) -> Option<usize> { self.byname.get(name).copied() }

    fn symtab(&self) -> &Section { self.secs.iter().find(|s| s.typ == 2).expect("no symtab") }

    pub fn symname(&self, idx: usize) -> String {
        let st = self.symtab();
        let strtab = self.secs[st.link as usize].off;
        let so = st.off + idx * 24;
        let nm = u32(&self.data, so) as usize;
        let mut e = strtab + nm;
        while self.data[e] != 0 { e += 1; }
        String::from_utf8_lossy(&self.data[strtab + nm..e]).into_owned()
    }
    pub fn nsyms(&self) -> usize { self.symtab().size / 24 }
    pub fn sym_value(&self, idx: usize) -> u64 { u64(&self.data, self.symtab().off + idx * 24 + 8) }
    pub fn sym_info(&self, idx: usize) -> u8 { self.data[self.symtab().off + idx * 24 + 4] }
    pub fn sym_shndx(&self, idx: usize) -> u16 { u16(&self.data, self.symtab().off + idx * 24 + 6) }

    pub fn find_sym(&self, name: &str) -> Option<usize> {
        (0..self.nsyms()).find(|&i| self.symname(i) == name)
    }
    /// index of the STT_SECTION symbol for section `sec_idx`
    pub fn section_symbol(&self, sec_idx: usize) -> Option<usize> {
        (0..self.nsyms()).find(|&i| (self.sym_info(i) & 0xf) == 3 && self.sym_shndx(i) as usize == sec_idx)
    }

    // ---- raw poke helpers ----
    pub fn wr_u32(&mut self, off: usize, v: u32) { self.data[off..off+4].copy_from_slice(&v.to_le_bytes()); }
    pub fn wr_u64(&mut self, off: usize, v: u64) { self.data[off..off+8].copy_from_slice(&v.to_le_bytes()); }
    pub fn wr_i64(&mut self, off: usize, v: i64) { self.data[off..off+8].copy_from_slice(&v.to_le_bytes()); }
    pub fn rd_u32(&self, off: usize) -> u32 { u32(&self.data, off) }
    pub fn rd_u64(&self, off: usize) -> u64 { u64(&self.data, off) }
    pub fn splice(&mut self, off: usize, bytes: &[u8]) { self.data[off..off+bytes.len()].copy_from_slice(bytes); }
}
