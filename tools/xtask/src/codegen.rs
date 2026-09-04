//! `xtask codegen`'s wasm-bindgen half (task 12.10): runs `wasm-pack build` on `meridian-wasm`
//! and emits its JS glue + `.d.ts` into `bindings/typescript/` (stack.md §3's checked-in
//! generated-code convention) — the piece a browser UI (`clients/web`, not yet landed) would
//! import without needing the Rust toolchain at all.
//!
//! The UniFFI half (Kotlin/Swift, T12) stays `TODO: confirm` — no mobile-consuming task has landed
//! in this workspace yet, so there is nothing to wire it to.
//!
//! Deliberately NOT wired up here: a CI "drift" job re-running this and diffing `bindings/` (the
//! full checked-in-codegen contract `stack.md` §3 describes). That is a workspace-wide codegen
//! policy spanning every future binding target (wasm, and later UniFFI), not something this task's
//! own scope (a `meridian-wasm` scaffold + smoke build) owns — see this task's own CI step
//! (`.github/workflows/ci.yml`'s `wasm-build` job), which runs `wasm-pack build` directly rather
//! than through this command, precisely so it doesn't need this command's own error handling
//! around a possibly-missing `wasm-pack` binary.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run() -> Result<(), String> {
    let repo_root = repo_root()?;
    let wasm_crate = repo_root.join("apps/wasm");
    // `bindings/typescript/generated/`, not `bindings/typescript/` directly: the root
    // `.gitignore`'s existing `/bindings/**/generated` pattern already reserves any `generated/`
    // subdirectory under `bindings/` for build output (as opposed to hand-maintained wrapper code
    // living directly under `bindings/typescript/`), so this reuses that convention rather than
    // introducing a new one. Not checked in by this task (no `clients/web` consumer exists yet to
    // review the output against) — see this file's module doc.
    let out_dir = repo_root.join("bindings/typescript/generated");

    println!("xtask codegen: wasm-bindgen (meridian-wasm -> bindings/typescript/generated)");
    let status = Command::new("wasm-pack")
        .arg("build")
        .arg(&wasm_crate)
        .arg("--release")
        .arg("--target")
        .arg("web")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--out-name")
        .arg("meridian_wasm")
        .status()
        .map_err(|e| {
            format!(
                "failed to run `wasm-pack` (is it installed? https://rustwasm.github.io/wasm-pack/installer/): {e}"
            )
        })?;

    if !status.success() {
        return Err(format!("wasm-pack build exited with {status}"));
    }

    println!("xtask codegen: UniFFI (Kotlin/Swift) — TODO: confirm, no T12 consumer landed yet");
    Ok(())
}

fn repo_root() -> Result<PathBuf, String> {
    // `cargo run -p xtask` always sets CARGO_MANIFEST_DIR to this crate's own directory
    // (tools/xtask); the workspace root is two levels up.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "CARGO_MANIFEST_DIR not set".to_string())?;
    let root = Path::new(&manifest_dir)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("could not find workspace root above {manifest_dir}"))?;
    Ok(root.to_path_buf())
}
