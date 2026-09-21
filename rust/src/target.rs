// Typed accessors over a parsed target JSON.
#![allow(dead_code)]
use crate::json::{Json, hx};
use crate::log::die;

pub struct Target {
    pub j: Json,
    pub dir: std::path::PathBuf, // targets/ directory (for local_ko / local_cfg)
}

impl Target {
    pub fn load(path: &str) -> Target {
        let txt = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {}: {}", path, e)));
        let j = Json::parse(&txt).unwrap_or_else(|e| die(&format!("parse {}: {}", path, e)));
        // targets/ dir = parent of the json file
        let dir = std::path::Path::new(path).parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
        Target { j, dir }
    }
    fn node(&self, p: &[&str]) -> Option<&Json> {
        let mut cur = &self.j;
        for k in p { cur = cur.get(k)?; }
        Some(cur)
    }
    pub fn opt(&self, p: &[&str]) -> Option<&Json> { self.node(p) }
    pub fn s(&self, p: &[&str]) -> String {
        self.node(p).and_then(|n| n.as_str()).unwrap_or_else(|| die(&format!("missing string {:?}", p))).to_string()
    }
    pub fn s_opt(&self, p: &[&str]) -> Option<String> { self.node(p).and_then(|n| n.as_str()).map(|s| s.to_string()) }
    pub fn hx(&self, p: &[&str]) -> i64 {
        self.node(p).and_then(hx).unwrap_or_else(|| die(&format!("missing int {:?}", p)))
    }
    pub fn hx_or(&self, p: &[&str], d: i64) -> i64 { self.node(p).and_then(hx).unwrap_or(d) }
    pub fn hx_opt(&self, p: &[&str]) -> Option<i64> { self.node(p).and_then(hx) }
    pub fn bool_or(&self, p: &[&str], d: bool) -> bool { self.node(p).and_then(|n| n.as_bool()).unwrap_or(d) }
    pub fn has(&self, p: &[&str]) -> bool { self.node(p).is_some() }
    pub fn merged(&self) -> bool { self.bool_or(&["kernel", "merged"], false) }

    /// generic inject lib key: "inject_lib" (QPro/Q3S) or "libeva" (Q3)
    pub fn inj_key(&self) -> &'static str { if self.has(&["inject_lib"]) { "inject_lib" } else { "libeva" } }

    pub fn local_path(&self, p: &[&str]) -> std::path::PathBuf { self.dir.join(self.s(p)) }
}
