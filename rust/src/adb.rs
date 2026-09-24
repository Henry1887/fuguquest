// Command runner + background Stager / WaitShell. Two modes:
//   remote (default): shell out to the `adb` binary  (host/PC -> device)
//   local  (--local): run commands directly with `sh -c`  (binary runs ON the device, in the shell
//                     domain via an adb-wireless self-connect) — lets one `adb shell fugu --local ...`
//                     drive the whole chain with no per-command adb round-trips.
#![allow(dead_code)]
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Adb { pub serial: String, pub local: bool }

impl Adb {
    pub fn new(serial: &str) -> Adb { Adb { serial: serial.to_string(), local: false } }
    pub fn new_local() -> Adb { Adb { serial: "local".into(), local: true } }

    fn base(&self) -> Command {
        let mut c = Command::new("adb");
        c.arg("-s").arg(&self.serial);
        c
    }
    fn out(&self, args: &[&str]) -> String {
        let o = self.base().args(args).output();
        match o { Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(), Err(_) => String::new() }
    }
    /// run a shell command, return stdout trimmed. local: `sh -c cmd`; remote: `adb shell cmd`.
    pub fn sh(&self, cmd: &str) -> String {
        if self.local {
            let o = Command::new("sh").arg("-c").arg(cmd).output();
            match o { Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(), Err(_) => String::new() }
        } else { self.out(&["shell", cmd]) }
    }
    pub fn su(&self, cmd: &str) -> String { self.sh(&format!("su -c \"{}\"", cmd)) }
    pub fn getprop(&self, p: &str) -> String { self.sh(&format!("getprop {}", p)) }
    pub fn alive(&self) -> bool { if self.local { true } else { self.out(&["get-state"]) == "device" } }

    /// stage a local file to a device path. local: filesystem copy (+ preserve exec via later chmod).
    pub fn push(&self, local: &str, remote: &str) -> bool {
        if self.local {
            if local == remote { return true; }
            std::fs::copy(local, remote).is_ok()
        } else {
            self.base().args(["push", local, remote]).stdout(Stdio::null()).stderr(Stdio::null())
                .status().map(|s| s.success()).unwrap_or(false)
        }
    }
    pub fn reboot(&self) { if self.local { let _ = self.sh("reboot"); } else { let _ = self.base().arg("reboot").status(); } }
    pub fn wait_for_device(&self) { if !self.local { let _ = self.base().arg("wait-for-device").status(); } }

    /// dd if=path bs=1 skip=off count=n | base64  -> decoded bytes  (routes through sh -> mode-aware)
    pub fn read_region(&self, path: &str, off: u64, n: usize) -> Vec<u8> {
        let cmd = format!("dd if={} bs=1 skip={} count={} 2>/dev/null | base64", path, off, n);
        b64decode(&self.sh(&cmd))
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

// spawn a shell command as a background child (remote via adb, or local via sh -c)
fn spawn_shell(local: bool, serial: &str, cmd: &str) -> Option<Child> {
    if local {
        Command::new("sh").arg("-c").arg(cmd).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()
    } else {
        Command::new("adb").args(["-s", serial, "shell", cmd]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()
    }
}

// ---- background Dirty-Frag SA stager ----
pub struct Stager { serial: String, local: bool, child: Option<Child>, started: bool, pub port: Option<u16> }
impl Stager {
    pub fn new(serial: &str, local: bool) -> Stager { Stager { serial: serial.to_string(), local, child: None, started: false, port: None } }
    pub fn start(&mut self) -> Option<u16> {
        let mut child = spawn_shell(self.local, &self.serial,
            "cd /data/local/tmp && CLASSPATH=e2e.dex exec app_process / q3.Stager 1800")?;
        self.started = true;
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
        // ART's app_process forks a VM worker that survives killing the launcher and would keep the
        // adb-shell pty open (hanging `adb shell fugu --local`); pkill it by name to guarantee release.
        if self.local && self.started {
            let _ = Command::new("sh").arg("-c").arg("pkill -f q3.Stager").status();
            self.started = false;
        }
    }
}
impl Drop for Stager { fn drop(&mut self) { self.stop(); } }

// ---- waiting shell (cred-patched to root, then runs postex.sh) ----
pub struct WaitShell { serial: String, local: bool, child: Option<Child>, pub pid: Option<i64>, skip: String, mods: String }
impl WaitShell {
    pub fn new(serial: &str, local: bool, skip_magisk: bool, carrier_mods: &str) -> WaitShell {
        WaitShell { serial: serial.to_string(), local, child: None, pid: None,
                    skip: if skip_magisk { "1" } else { "0" }.to_string(), mods: carrier_mods.to_string() }
    }
    fn sh1(&self, cmd: &str) -> String {
        if self.local { Command::new("sh").arg("-c").arg(cmd).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default() }
        else { Command::new("adb").args(["-s", &self.serial, "shell", cmd]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default() }
    }
    pub fn start(&mut self) -> Option<i64> {
        let _ = self.sh1("rm -f /data/local/tmp/pepid /data/local/tmp/pego /data/local/tmp/postex_done");
        let cmd = format!(
            "echo $$ > /data/local/tmp/pepid; while [ ! -f /data/local/tmp/pego ]; do sleep 0.2; done; \
             SKIP_MAGISK={} CARRIER_MODS='{}' sh /data/local/tmp/postex.sh", self.skip, self.mods);
        let child = spawn_shell(self.local, &self.serial, &cmd)?;
        self.child = Some(child);
        for _ in 0..50 {
            let pid = self.sh1("cat /data/local/tmp/pepid 2>/dev/null");
            if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                self.pid = pid.parse().ok();
                return self.pid;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }
    pub fn release(&self) { let _ = self.sh1("touch /data/local/tmp/pego"); }
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
        if v == 255 { continue; }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 { bits -= 8; out.push((buf >> bits) as u8); }
    }
    out
}
