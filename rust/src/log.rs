// Colored, timestamped logging matching the Python orchestrator's banner/step/ok/... helpers.
#![allow(dead_code)]
use std::io::IsTerminal;
use std::sync::OnceLock;
use std::time::Instant;

static T0: OnceLock<Instant> = OnceLock::new();
static COLOR: OnceLock<bool> = OnceLock::new();

fn t0() -> Instant { *T0.get_or_init(Instant::now) }
fn color() -> bool { *COLOR.get_or_init(|| std::io::stdout().is_terminal()) }

pub fn init() { let _ = t0(); let _ = color(); }

fn c(code: &str) -> &str { if color() { code } else { "" } }
fn ts() -> String {
    let s = t0().elapsed().as_secs_f64();
    format!("{}[{:6.1}s]{}", c("\x1b[90m"), s, c("\x1b[0m"))
}

pub fn banner(txt: &str) {
    let line = "═".repeat(txt.chars().count() + 2);
    println!("\n{}{}╔{}╗\n║ {} ║\n╚{}╝{}", c("\x1b[36m"), c("\x1b[1m"), line, txt, line, c("\x1b[0m"));
}
pub fn step(t: &str) { println!("{} {}{}▸{} {}{}{}", ts(), c("\x1b[34m"), c("\x1b[1m"), c("\x1b[0m"), c("\x1b[1m"), t, c("\x1b[0m")); }
pub fn ok(t: &str)   { println!("{} {}  ✓ {}{}", ts(), c("\x1b[32m"), t, c("\x1b[0m")); }
pub fn info(t: &str) { println!("{} {}    {}{}", ts(), c("\x1b[90m"), t, c("\x1b[0m")); }
pub fn warn(t: &str) { println!("{} {}  ! {}{}", ts(), c("\x1b[33m"), t, c("\x1b[0m")); }
pub fn err(t: &str)  { println!("{} {}{}  ✗ {}{}", ts(), c("\x1b[31m"), c("\x1b[1m"), t, c("\x1b[0m")); }
pub fn win(t: &str)  { println!("{} {}{}  ★ {}{}", ts(), c("\x1b[32m"), c("\x1b[1m"), t, c("\x1b[0m")); }

pub fn die(t: &str) -> ! { err(t); std::process::exit(1); }
