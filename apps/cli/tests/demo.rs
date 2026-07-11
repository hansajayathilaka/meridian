//! End-to-end acceptance test for the `meridian id` demo script
//! (docs/architecture/features/01-identity-keystore-core.md "Working output").
//!
//! Drives the real binary with a scratch `MERIDIAN_HOME` and a scripted passphrase
//! (`MERIDIAN_PASSPHRASE`), covering: new → show → sign → verify → parse (valid & corrupt), plus
//! the "keyfile is never plaintext" and "tampered message fails closed" checks.

use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

struct Env {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .output()
            .expect("failed to run meridian binary")
    }

    fn work_path(&self, name: &str) -> std::path::PathBuf {
        self.work.path().join(name)
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn full_demo_flow() {
    let env = Env::new();

    // $ meridian id new --store file --out alice.key
    let out = env.run(&[
        "id",
        "new",
        "--store",
        "file",
        "--out",
        "alice.key",
        "--hint",
        "chat.example",
    ]);
    assert!(
        out.status.success(),
        "new failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let created = stdout(&out);
    assert!(
        created.starts_with("Created mrd1:"),
        "unexpected: {created}"
    );
    assert!(created.trim_end().ends_with("@chat.example"));

    // The keyfile exists and is an age container — never the raw seed in plaintext.
    let keyfile = env.work_path("alice.key");
    let key_bytes = std::fs::read(&keyfile).unwrap();
    assert!(
        key_bytes.starts_with(b"age-encryption.org/v1"),
        "keyfile must be age-encrypted, not plaintext"
    );

    // $ meridian id show
    let out = env.run(&["id", "show"]);
    assert!(out.status.success());
    let id = stdout(&out).trim().to_string();
    assert!(id.starts_with("mrd1:") && id.ends_with("@chat.example"));

    // $ meridian id show --qr  (renders a QR; just assert it produced block output + the id)
    let out = env.run(&["id", "show", "--qr"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains('█'), "expected a rendered QR code");

    // $ echo "hello" > m.txt && meridian id sign m.txt > m.sig
    std::fs::write(env.work_path("m.txt"), b"hello\n").unwrap();
    let out = env.run(&["id", "sign", "m.txt"]);
    assert!(
        out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sig_hex = stdout(&out).trim().to_string();
    assert_eq!(sig_hex.len(), 128, "signature should be 64 bytes hex");
    std::fs::write(env.work_path("m.sig"), &sig_hex).unwrap();

    // $ meridian id verify m.txt m.sig <id>   → OK
    let out = env.run(&["id", "verify", "m.txt", "m.sig", &id]);
    assert!(out.status.success(), "verify should succeed");
    assert_eq!(stdout(&out).trim(), "OK");

    // Tampered message → verification fails closed (non-zero exit).
    std::fs::write(env.work_path("m.txt"), b"goodbye\n").unwrap();
    let out = env.run(&["id", "verify", "m.txt", "m.sig", &id]);
    assert!(
        !out.status.success(),
        "tampered message must fail verification"
    );

    // $ meridian id parse <id>  → key + hint
    let out = env.run(&["id", "parse", &id]);
    assert!(out.status.success());
    let parsed = stdout(&out);
    assert!(parsed.contains("hint: chat.example"));
    assert!(parsed.contains("key:  "));
}

#[test]
fn parse_rejects_corrupt_checksum() {
    let env = Env::new();
    env.run(&["id", "new", "--store", "file", "--out", "alice.key"]);
    let id = stdout(&env.run(&["id", "show"])).trim().to_string();

    // Corrupt one character in the middle of the key part (a real checksum failure).
    let at = id.find('@').unwrap();
    let key_start = "mrd1:".len();
    let mut chars: Vec<char> = id.chars().collect();
    let mid = (key_start + at) / 2;
    chars[mid] = if chars[mid] == 'a' { 'b' } else { 'a' };
    let corrupt: String = chars.into_iter().collect();

    let out = env.run(&["id", "parse", &corrupt]);
    assert!(!out.status.success(), "corrupt ID must be rejected");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("checksum mismatch"), "unexpected error: {err}");
}

#[test]
fn export_import_roundtrip() {
    let env = Env::new();
    env.run(&["id", "new", "--store", "file", "--out", "alice.key"]);
    let id = stdout(&env.run(&["id", "show"])).trim().to_string();

    // Export to a portable keyfile.
    let portable = env.work_path("portable.mrk");
    let out = env.run(&["id", "export", "--out", portable.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(Path::new(&portable).exists());

    // Import into a *fresh* home; the reconstructed ID must match.
    let fresh = Env::new();
    let out = fresh.run(&[
        "id",
        "import",
        portable.to_str().unwrap(),
        "--store",
        "file",
        "--out",
        "imported.key",
    ]);
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let imported_id = stdout(&fresh.run(&["id", "show"])).trim().to_string();
    assert_eq!(id, imported_id, "export/import must preserve the identity");
}
