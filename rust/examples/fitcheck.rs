// Offline stub-fit check for a MERGED target: build the credmod carrier, then the inject stub, and
// report whether it fits the chosen inject-lib's exec gap — without a device. Handy when porting an
// old build whose libs have small exec gaps (the merged stub is ~diffs*12 + ~344 B fixed).
//   cargo run --example fitcheck -- <rdbg.ko> <gap_size> <dsel> <dfv> <dpt> <dssuse> <cred_off>
// Defaults are q2_50837850062000150 + libcdsprpc's gap.
#[path = "../src/asm.rs"] mod asm;
#[path = "../src/aes.rs"] mod aes;
#[path = "../src/elf.rs"] mod elf;
#[path = "../src/emit.rs"] mod emit;
#[path = "../src/credmod.rs"] mod credmod;

fn sx32(v: u64) -> i64 { (v as u32 as i32) as i64 }
fn arg(i: usize, d: u64) -> u64 { std::env::args().nth(i).map(|s| {
    let s = s.trim_start_matches("0x"); u64::from_str_radix(s, 16).unwrap_or(d) }).unwrap_or(d) }

fn main() {
    let ko = std::env::args().nth(1).unwrap_or("../targets/q2_50837850062000150/rdbg.ko".into());
    let orig = std::fs::read(&ko).expect("read carrier");
    let gap_size = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3328usize);
    let (dsel, dfv, dpt, dssuse) = (sx32(arg(3, 0x109672c)), sx32(arg(4, 0xffa047cc)),
                                    sx32(arg(5, 0xffa049c0)), sx32(arg(6, 0xffd631ec)));
    let cred_off = arg(7, 0x7e0) as u32;

    let (patched, msg) = credmod::build_credmod(orig.clone(), dsel, dfv, dpt, 0, dssuse, 1, cred_off, Some(0x78))
        .expect("build_credmod");
    let ndiff = (0..patched.len()).filter(|&i| orig[i] != patched[i]).count();
    println!("credmod: {}\ncarrier {} B, patched differs in {} bytes", msg, orig.len(), ndiff);

    let files = vec![("/vendor/lib/modules/rdbg.ko".to_string(), orig.clone(), patched)];
    // gap_off/orig_ctor/init_array_off don't affect the size check; use the JSON's libcdsprpc values.
    match emit::build_inject_stub(0xdeadbe10, 0x41, 9999, 0x15300, gap_size, 0x3b8f8, 0x3d180, &files) {
        Ok((raw, _s, c)) => println!("MERGED inject stub: {} B (gap {}, {} free) diffs={:?} => FITS",
                                     raw.len(), gap_size, gap_size as isize - raw.len() as isize, c),
        Err(e) => println!("MERGED inject stub: {}", e),
    }

    // ---- split flow: Phase-A enforcing-only carrier (should be small enough to fit) ----
    let (enf, emsg) = credmod::build_credmod_ex(orig.clone(), dsel, dfv, dpt, 0, dssuse, 1, cred_off, None, true)
        .expect("build_credmod_ex enforcing-only");
    let nd = (0..enf.len()).filter(|&i| orig[i] != enf[i]).count();
    println!("PHASE-A enforcing-only: {}\n  differs in {} bytes", emsg, nd);
    let files2 = vec![("/vendor/lib/modules/rdbg.ko".to_string(), orig.clone(), enf)];
    match emit::build_inject_stub(0xdeadbe10, 0x41, 9999, 0x15300, gap_size, 0x3b8f8, 0x3d180, &files2) {
        Ok((raw, _s, c)) => println!("PHASE-A inject stub: {} B (gap {}, {} free) diffs={:?} => FITS",
                                     raw.len(), gap_size, gap_size as isize - raw.len() as isize, c),
        Err(e) => { eprintln!("PHASE-A inject stub: {}", e); std::process::exit(1); }
    }
    // ---- Phase-B renamed cred carrier (loaded shell-direct under Permissive; no gap limit) ----
    let (credb, _m) = credmod::build_credmod(orig.clone(), dsel, dfv, dpt, 12345, dssuse, 1, cred_off, None)
        .expect("build_credmod phase-B");
    let renamed = credmod::rename_module(credb, "rdbgcp").expect("rename_module");
    let has = renamed.windows(7).any(|w| w == b"rdbgcp\0");
    println!("PHASE-B cred carrier renamed to 'rdbgcp' ({} B, name-in-image={}) — coexists with loaded 'rdbg'",
             renamed.len(), has);
}
