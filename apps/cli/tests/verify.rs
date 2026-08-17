//! `meridian verify <id> --scan-file <path>` (task 4.5): CLI round trip proving the headless
//! compare flow actually reaches [`meridian_core::trust::TrustStore::mark_verified`]. Builds a QR
//! image encoding the safety number for a known pair of accounts (via
//! `meridian_core::identity::render_luma`, the same primitive `verify.rs` uses to decode), feeds
//! it back in through `--scan-file`, and asserts the contact ends up `Verified`. Also covers the
//! mismatch (must NOT verify) and unknown-contact (clear error, matching `contact.rs`'s
//! `unknown_contact_message` pattern) cases from the task's scope.
//!
//! The interactive display+confirm path (no `--scan-file`) isn't exercised here since these tests
//! run with stdin closed (never a TTY, same convention as `contact_mgmt.rs`) — `--scan-file` is
//! the fully headless/scriptable path this file proves end to end.

use std::path::Path;
use std::process::{Command, Stdio};

use meridian_core::crypto::safety_number;
use meridian_core::identity::{parse_id, render_luma};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Create a fresh file-store account under `home`/`work`, with the given routing hint, and return
/// its full `mrd1:…@hint` ID. Mirrors `contact_mgmt.rs`'s helper of the same shape.
fn new_account(home: &Path, work: &Path, hint: &str) -> String {
    let out = Command::new(BIN)
        .args([
            "id", "new", "--store", "file", "--out", "id.key", "--hint", hint,
        ])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run meridian id new");
    assert!(
        out.status.success(),
        "id new failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(BIN)
        .args(["id", "show"])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run meridian id show");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `meridian contact add <id>`, asserting success — the contact must already be known before
/// `verify` can call `mark_verified` on it.
fn contact_add(home: &Path, work: &Path, id: &str) {
    let out = Command::new(BIN)
        .args(["contact", "add", id])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run meridian contact add");
    assert!(
        out.status.success(),
        "contact add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `meridian contact list --json`'s raw stdout, for asserting on `"state":"…"`.
fn contact_list_json(home: &Path, work: &Path) -> String {
    let out = Command::new(BIN)
        .args(["contact", "list", "--json"])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run meridian contact list");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// `meridian verify <args...>`, with stdin closed (never a TTY).
fn verify(home: &Path, work: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(BIN)
        .arg("verify")
        .args(args)
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("run meridian verify {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The real safety number between two ids, computed independently of the CLI (the same way
/// `verify.rs` computes it internally) — the value this test's QR fixtures encode.
fn expected_number(self_id: &str, peer_id: &str) -> String {
    let me = parse_id(self_id).expect("parse self id");
    let peer = parse_id(peer_id).expect("parse peer id");
    safety_number(me.pubkey(), peer.pubkey())
}

#[test]
fn scan_file_match_marks_contact_verified() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let self_id = new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path(), "bob.example");

    contact_add(home.path(), work.path(), &peer_id);
    let listed = contact_list_json(home.path(), work.path());
    assert!(
        listed.contains("\"state\":\"pinned\""),
        "must start out pinned (TOFU), not verified: {listed}"
    );

    let number = expected_number(&self_id, &peer_id);
    let qr_dir = tempfile::tempdir().unwrap();
    let qr_path = qr_dir.path().join("safety.png");
    render_luma(&number)
        .expect("render safety number as a QR bitmap")
        .save(&qr_path)
        .expect("write QR fixture to disk");

    let (ok, stdout, stderr) = verify(
        home.path(),
        work.path(),
        &[&peer_id, "--scan-file", qr_path.to_str().unwrap()],
    );
    assert!(ok, "verify --scan-file (match) failed: {stderr}");
    assert!(stdout.contains("MATCH"), "{stdout}");
    assert!(stdout.contains("VERIFIED"), "{stdout}");

    let listed = contact_list_json(home.path(), work.path());
    assert!(
        listed.contains("\"state\":\"verified\""),
        "contact must be Verified after a matching scan: {listed}"
    );
}

#[test]
fn scan_file_mismatch_does_not_verify() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path(), "carol.example");

    contact_add(home.path(), work.path(), &peer_id);

    // A QR encoding an obviously-wrong number (not the real safety number for this pair).
    let qr_dir = tempfile::tempdir().unwrap();
    let qr_path = qr_dir.path().join("wrong.png");
    let wrong_number = "0".repeat(60);
    render_luma(&wrong_number)
        .expect("render wrong number as a QR bitmap")
        .save(&qr_path)
        .expect("write QR fixture to disk");

    let (ok, stdout, stderr) = verify(
        home.path(),
        work.path(),
        &[&peer_id, "--scan-file", qr_path.to_str().unwrap()],
    );
    assert!(!ok, "a mismatched safety number must not report success");
    assert!(stdout.contains("MISMATCH"), "{stdout}");
    assert!(
        stderr.contains("NOT verified"),
        "error should be explicit about the failed verification: {stderr}"
    );

    let listed = contact_list_json(home.path(), work.path());
    assert!(
        listed.contains("\"state\":\"pinned\""),
        "a mismatch must never advance trust state: {listed}"
    );
}

#[test]
fn scan_file_match_for_unknown_contact_is_a_clean_error() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let self_id = new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    // Deliberately never `contact add`ed.
    let peer_id = new_account(peer_home.path(), peer_work.path(), "dave.example");

    let number = expected_number(&self_id, &peer_id);
    let qr_dir = tempfile::tempdir().unwrap();
    let qr_path = qr_dir.path().join("safety.png");
    render_luma(&number)
        .expect("render safety number as a QR bitmap")
        .save(&qr_path)
        .expect("write QR fixture to disk");

    let (ok, stdout, stderr) = verify(
        home.path(),
        work.path(),
        &[&peer_id, "--scan-file", qr_path.to_str().unwrap()],
    );
    assert!(!ok, "an unknown contact must never end up verified");
    assert!(
        stdout.contains("MATCH"),
        "the numbers themselves still matched: {stdout}"
    );
    assert!(
        stderr.contains("contact add"),
        "error should point at `meridian contact add`: {stderr}"
    );

    // A matching scan for a peer that was never `contact add`ed must have zero persisted side
    // effect -- no contact record created at all, not just "not verified". `contact list --json`
    // prints nothing (no "(no contacts)" placeholder -- that's the non-JSON path only) when the
    // store is empty, so empty stdout here is the correct "nothing was ever added" signal.
    let listed = contact_list_json(home.path(), work.path());
    assert!(
        listed.trim().is_empty(),
        "an unknown-contact verify attempt must not create any contact record: {listed}"
    );
}
