//! T04/T05 acceptance over the **real** transport backend (1.22, F11 wire prerequisite): `cargo
//! nextest run -p meridian-cli --features webrtc`.
//!
//! Mirrors `session_demo.rs`'s loopback-based coverage, but drives `--transport webrtc` — real
//! ICE/SCTP/DTLS on localhost, exercised through the compiled binary rather than an in-process
//! `cargo test` inside `apps/core` (1.15 already proved the backend itself works that way; this
//! proves the CLI can select it). Also proves the fail-closed validation guard: `--transport webrtc`
//! rejects a non-default `--nat`/`--policy` rather than silently ignoring them or hanging trying to
//! reach the demo's fabricated (loopback-only) TURN host.

#![cfg(feature = "webrtc")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

#[test]
fn session_demo_webrtc_shows_server_down_continuity() {
    let out = Command::new(BIN)
        .args(["session", "demo", "--transport", "webrtc"])
        .output()
        .expect("run meridian session demo --transport webrtc");
    assert!(
        out.status.success(),
        "session demo --transport webrtc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    // The fingerprint was verified and the session came up direct, over a real DTLS handshake.
    assert!(
        text.contains("DTLS fp verified"),
        "missing fp-verified line: {text}"
    );
    // The rendezvous was stopped and chat still flowed both ways over the real data channel.
    assert!(
        text.contains("rendezvous stopped"),
        "missing server-down line: {text}"
    );
    assert!(
        text.contains("[alice → bob] hello over p2p"),
        "alice→bob missing: {text}"
    );
    assert!(
        text.contains("[bob → alice] hi back"),
        "bob→alice missing: {text}"
    );
    // The `session info` line proves the real backend, not the loopback simulation, was used.
    assert!(
        text.contains("transport=webrtc-datachannel"),
        "missing/wrong transport line (expected webrtc-datachannel): {text}"
    );
    assert!(text.contains("mrd.ctrl/1"), "ctrl stream missing: {text}");
    assert!(text.contains("mrd.chat/1"), "chat stream missing: {text}");
}

#[test]
fn session_demo_webrtc_json_mode() {
    let out = Command::new(BIN)
        .args(["session", "demo", "--transport", "webrtc", "--json"])
        .output()
        .expect("run meridian session demo --transport webrtc --json");
    assert!(
        out.status.success(),
        "session demo --transport webrtc --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"established\":true"),
        "unexpected json: {text}"
    );
    assert!(
        text.contains("\"server_dropped\":true"),
        "unexpected json: {text}"
    );
}

#[test]
fn session_demo_webrtc_rejects_nat_simulation() {
    // There is no NAT simulation for a real transport — the flag must be rejected, not ignored.
    let out = Command::new(BIN)
        .args([
            "session",
            "demo",
            "--transport",
            "webrtc",
            "--nat",
            "symmetric",
        ])
        .output()
        .expect("run meridian session demo --transport webrtc --nat symmetric");
    assert!(
        !out.status.success(),
        "expected non-zero exit for --transport webrtc --nat symmetric"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NAT simulation") || stderr.contains("nat"),
        "stderr should explain why --nat is rejected under --transport webrtc: {stderr}"
    );
}

#[test]
fn session_demo_webrtc_rejects_relay_only_policy() {
    // The demo's TURN servers are fabricated for LoopbackTransport's simulation; a real
    // WebRtcTransport would actually try to reach the fake `turn-a` host. Must fail closed.
    let out = Command::new(BIN)
        .args([
            "session",
            "demo",
            "--transport",
            "webrtc",
            "--policy",
            "relay-only",
        ])
        .output()
        .expect("run meridian session demo --transport webrtc --policy relay-only");
    assert!(
        !out.status.success(),
        "expected non-zero exit for --transport webrtc --policy relay-only"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TURN") || stderr.contains("policy"),
        "stderr should explain why --policy relay-only is rejected under --transport webrtc: {stderr}"
    );
}
