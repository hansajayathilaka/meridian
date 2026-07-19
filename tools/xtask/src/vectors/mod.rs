//! `xtask -- vectors`: regenerate every conformance fixture under `test-vectors/`.
//!
//! Each fixture set gets its own module. All of them write deterministically (fixed seeds, no
//! wall-clock/RNG input) so re-running the generator is a no-op against a clean checkout — that
//! self-consistency is itself asserted by CI (`git diff --exit-code test-vectors/`).

mod envelope;
mod identity;
mod ratchet;
mod safety_numbers;
mod x3dh;

use std::path::{Path, PathBuf};

/// `<repo-root>/test-vectors/<name>`. `CARGO_MANIFEST_DIR` = `<root>/tools/xtask`.
pub(crate) fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("xtask lives at <root>/tools/xtask")
        .join("test-vectors")
        .join(name)
}

/// Serialize `value` as pretty JSON with a trailing newline and write it to `path`.
pub(crate) fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    json.push('\n');
    std::fs::write(path, json).map_err(|e| format!("writing {}: {e}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

pub fn generate() -> Result<(), String> {
    identity::generate_identity()?;
    x3dh::generate_x3dh()?;
    ratchet::generate_ratchet()?;
    envelope::generate_envelope()?;
    safety_numbers::generate_safety_numbers()?;
    Ok(())
}
