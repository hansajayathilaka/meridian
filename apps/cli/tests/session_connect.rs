//! `meridian session connect` fail-closed guards that hold regardless of the `webrtc` cargo
//! feature (1.24) — mirrors `session_demo.rs`'s precedent from 1.22 for exactly this shape of
//! test (`session_demo_rejects_webrtc_transport_without_the_feature`).

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

fn new_account(home: &std::path::Path, work: &std::path::Path) -> String {
    let out = Command::new(BIN)
        .args([
            "id",
            "new",
            "--store",
            "file",
            "--out",
            "id.key",
            "--hint",
            "localhost",
        ])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
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
        .output()
        .expect("run meridian id show");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn session_connect_rejects_loopback_transport() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path());
    // A second, real (never-run) account — these tests never reach the network, but the peer id
    // must still parse as a genuine mrd1 ID (base32 + CRC32C checksum), not a hand-crafted string.
    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path());

    let out = Command::new(BIN)
        .args([
            "session",
            "connect",
            &peer_id,
            "--server",
            "ws://127.0.0.1:1",
            "--transport",
            "loopback",
        ])
        .current_dir(work.path())
        .env("MERIDIAN_HOME", home.path())
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .output()
        .expect("run meridian session connect --transport loopback");
    assert!(
        !out.status.success(),
        "expected non-zero exit for --transport loopback"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("LoopbackTransport's fabric is in-process only"),
        "stderr should explain why loopback is rejected: {stderr}"
    );
}

// Only meaningful on a plain build: with the `webrtc` feature compiled in, `--transport webrtc`
// is expected to proceed (see `session_connect_webrtc.rs`), so this guard can't hold there.
#[cfg(not(feature = "webrtc"))]
#[test]
fn session_connect_rejects_webrtc_transport_without_the_feature() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path());
    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path());

    let out = Command::new(BIN)
        .args([
            "session",
            "connect",
            &peer_id,
            "--server",
            "ws://127.0.0.1:1",
            "--transport",
            "webrtc",
        ])
        .current_dir(work.path())
        .env("MERIDIAN_HOME", home.path())
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .output()
        .expect("run meridian session connect --transport webrtc");
    assert!(
        !out.status.success(),
        "expected non-zero exit for --transport webrtc on a non-feature build"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("built without the `webrtc` feature"),
        "stderr should explain the feature is missing: {stderr}"
    );
}
