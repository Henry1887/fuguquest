// Embedded runtime assets (so the tool is a single self-contained binary). e2e.dex is required for
// every run; the postex/* assets are only used by --postex (Magisk). Materialized into the work dir.
use std::path::{Path, PathBuf};

pub const E2E_DEX: &[u8] = include_bytes!("../../e2e.dex");
pub const POSTEX_SH: &[u8] = include_bytes!("../../postex/postex.sh");
pub const SINGULARITY_SH: &[u8] = include_bytes!("../../postex/assets/singularity_magisk.sh");
pub const SINGULARITY_APK: &[u8] = include_bytes!("../../postex/assets/singularity-Magisk.apk");

/// Write an embedded asset into `dir`, return its path.
pub fn write_to(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap_or_else(|e| crate::log::die(&format!("write {}: {}", p.display(), e)));
    p
}
