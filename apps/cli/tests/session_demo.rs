//! T04 acceptance: the `meridian session demo` subcommand establishes a direct P2P session, drops
//! the rendezvous, and shows chat continuing over the data channel — the headline demo from
//! docs/architecture/features/04-p2p-session-substrate.md "Working output".

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

#[test]
fn session_demo_shows_server_down_continuity() {
    let out = Command::new(BIN)
        .args(["session", "demo"])
        .output()
        .expect("run meridian session demo");
    assert!(
        out.status.success(),
        "session demo failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    // The fingerprint was verified and the session came up direct.
    assert!(
        text.contains("DTLS fp verified"),
        "missing fp-verified line: {text}"
    );
    // The rendezvous was stopped and chat still flowed both ways.
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
    // The `session info` line lists both streams over the loopback transport.
    assert!(
        text.contains("transport=loopback"),
        "missing transport line: {text}"
    );
    assert!(text.contains("mrd.ctrl/1"), "ctrl stream missing: {text}");
    assert!(text.contains("mrd.chat/1"), "chat stream missing: {text}");
}

#[test]
fn session_demo_json_mode() {
    let out = Command::new(BIN)
        .args(["session", "demo", "--json"])
        .output()
        .expect("run meridian session demo --json");
    assert!(out.status.success());
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
