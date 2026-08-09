//! Task 2.15 acceptance (the `session_connect.rs`/`RendezvousRelay` half): cross-org **P2P
//! signaling** — not just cross-org chat — only works because `session_connect.rs`'s
//! `RendezvousRelay::new(&mut client, Some(peer_hint.clone()))` call site actually threads the
//! peer's `@domain` hint onto every `route`/`route_with_hint` call the signaling handshake makes.
//!
//! Before this task, `apps/core/src/signal_relay.rs`'s `RendezvousRelay::send` hardcoded
//! `hint: None`, and `apps/cli/src/session_connect.rs:189` constructed the relay with `None`
//! regardless of the peer's parsed `@domain`. `route_with_hint` and the server's federated routing
//! (task 2.8) already worked correctly — the only thing missing was a live caller that ever passed
//! `Some(hint)` through *this* path (`apps/cli/tests/federation_route_hint.rs` closed the same gap
//! for `chat.rs`'s `route_tolerant`, but nothing exercised `session connect`).
//!
//! ## Why this needs *bidirectional* federation (unlike `federation_route_hint.rs`)
//! `chat.rs`'s cross-org test could get away with a one-way federation link (org-a dials org-b)
//! because it used a raw `SignalingClient` for Bob and never needed a message to travel back
//! through org-b to org-a. `session connect`'s WebRTC handshake is a genuine two-way exchange:
//! the initiator sends an SDP **offer** through its own home server, and the responder sends an
//! SDP **answer** back through *its* home server (`session::dial_established`/
//! `answer_established`, both calling `relay.send`). Since this test runs **two real `meridian
//! session connect` child processes**, each on its own org's server, `RendezvousRelay::new`'s
//! `Some(peer_hint)` fix is exercised on *both* legs — and a single mutation reverting
//! `session_connect.rs:189` back to `None` breaks *both* legs identically (the same source line
//! backs both the initiator's and the responder's relay), so either leg failing already fails this
//! test.
//!
//! ## Non-vacuity (mutation-test reasoning)
//! Alice's account lives only at org-a; Bob's only at org-b — neither ever connects to the other's
//! home server. `RendezvousRelay::send`'s `route_with_hint` maps a same-server "peer not found"
//! outcome to `RouteOk { delivered: false }` (`Ok(false)`, not a wire error), which
//! `map_route_result` turns into a **hard, immediate** `SessionError::Relay(pretty much
//! "peer is not currently connected")` (unlike `chat.rs`'s tolerant offline-delivery — there is no
//! mailbox for the offer/answer exchange, see `signal_relay.rs`'s module docs). So:
//! - With the fix reverted, whichever side dials first gets an immediate, loud process failure
//!   (`dial: peer is not currently connected to the rendezvous` / `answer: ...`) rather than a
//!   hang — a regression here is a *fast*, visible break, not a silent one.
//! - With the fix in place, both `to_hint`s reach the wire, both orgs federate the route, and a
//!   real two-process WebRTC session establishes end to end (bounded by this test's own bounded
//!   process-wait, same safety net `session_connect_webrtc.rs` already uses).

#![cfg(feature = "webrtc")]

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod support;
use support::{drain, Client};

/// Bound for waiting on a child `session connect` process to exit. Must stay strictly greater
/// than `meridian_core::session::ANSWER_TIMEOUT` (30s) — see `session_connect_webrtc.rs`'s
/// identical constant for why a harness deadline equal to that internal timeout is a
/// zero-margin race that a loaded CI runner can lose.
const PROCESS_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

// -- CLI driver (mirrors apps/cli/tests/session_connect_webrtc.rs) ---------------------------------
//
// `session connect`'s spawn/wait shape (JSON-streamed subprocess, bounded wait) is specific to
// this file — `support::Client` only provides `spawn_chat` (used by `federation_route_hint.rs`),
// so this file layers its own `spawn_connect`/`ConnectProc` on top of the shared `Client`/`drain`.

/// Spawn `session connect <peer_id> --server <server> --transport webrtc --json` as a real child
/// process, talking only to `client`'s own home server (`server`) — the peer id's `@domain` is the
/// only thing that ever names the other org.
fn spawn_connect(client: &Client, server: &str, peer_id: &str) -> ConnectProc {
    let mut child = Command::new(support::BIN)
        .args([
            "session",
            "connect",
            peer_id,
            "--server",
            server,
            "--transport",
            "webrtc",
            "--json",
        ])
        .current_dir(client.work.path())
        .env("MERIDIAN_HOME", client.home.path())
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn session connect");
    let out = drain(child.stdout.take().unwrap());
    let err = drain(child.stderr.take().unwrap());
    ConnectProc { child, out, err }
}

/// A running `session connect` subprocess with its stdout/stderr accumulated by reader threads.
struct ConnectProc {
    child: Child,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl ConnectProc {
    /// Wait for the process to exit (bounded), returning `(success, stdout, stderr)`. Bounded so a
    /// regression (the responder's `recv_sdp` blocking forever on an offer that a hint-less route
    /// can never deliver) fails this test loudly instead of hanging the suite.
    fn wait(mut self, timeout: Duration) -> (bool, String, String) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return (
                    status.success(),
                    self.out.lock().unwrap().clone(),
                    self.err.lock().unwrap().clone(),
                );
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return (
                    false,
                    self.out.lock().unwrap().clone(),
                    format!(
                        "{}\n[test] timed out waiting for process to exit",
                        self.err.lock().unwrap()
                    ),
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

// -- The test ---------------------------------------------------------------------------------

#[test]
fn two_processes_on_two_federated_orgs_establish_a_real_p2p_session() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pair = rt.block_on(support::boot_federated_pair_bidirectional());
    let (a_c2s_url, b_c2s_url) = (pair.a_c2s_url.clone(), pair.b_c2s_url.clone());

    // Alice: a real account on org-a. Bob: a real account on org-b. Neither ever connects to the
    // other's home server — the routing invariant this test is built around: each side's
    // `session connect` only ever dials its OWN home server, and the peer id's `@domain` (parsed
    // from `mrd1:...@org-b.test` / `mrd1:...@org-a.test`) is the only thing that can make the
    // handshake cross the federation boundary.
    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key", "org-a.test");
    bob.new_account("bob.key", "org-b.test");
    let alice_id = alice.id();
    let bob_id = bob.id();

    // Both sides must be live at the same time (no mailbox for the offer/answer exchange), so
    // spawn both concurrently and wait for both, mirroring `session_connect_webrtc.rs`.
    let a = spawn_connect(&alice, &a_c2s_url, &bob_id);
    let b = spawn_connect(&bob, &b_c2s_url, &alice_id);

    let (a_ok, a_out, a_err) = a.wait(PROCESS_WAIT_TIMEOUT);
    let (b_ok, b_out, b_err) = b.wait(PROCESS_WAIT_TIMEOUT);

    // The wire-level, non-vacuity-proving assertion: without `session_connect.rs`'s hint fix,
    // whichever side dials first gets an immediate hard failure the moment its home server can't
    // find the peer locally (`RendezvousRelay::send` never treats a not-connected peer as
    // retryable) — so a regression here shows up as `a_ok`/`b_ok` being false, not a hang.
    assert!(
        a_ok,
        "alice's session connect failed — with the hint fix reverted this fails immediately \
         (\"peer is not currently connected to the rendezvous\"), since bob's account never \
         registers with org-a at all.\nstdout: {a_out}\nstderr: {a_err}"
    );
    assert!(
        b_ok,
        "bob's session connect failed — same reasoning as alice's, in the other direction (bob's \
         answer must cross back from org-b to org-a).\nstdout: {b_out}\nstderr: {b_err}"
    );

    let combined = format!("{a_out}\n{b_out}");

    // The real WebRtcTransport backend was used, and a real P2P session actually came up on both
    // sides — this can only happen if BOTH the offer (org-a -> org-b) and the answer (org-b ->
    // org-a) were successfully federated using the peer's threaded hint.
    assert!(
        combined.contains("\"transport\":\"webrtc-datachannel\""),
        "expected a \"transport\":\"webrtc-datachannel\" field in combined output: {combined}"
    );
    assert!(
        a_out.contains("\"event\":\"p2p_connect\"") && a_out.contains("\"established\":true"),
        "alice did not report an established cross-org session: {a_out}"
    );
    assert!(
        b_out.contains("\"event\":\"p2p_connect\"") && b_out.contains("\"established\":true"),
        "bob did not report an established cross-org session: {b_out}"
    );
    // One side dialed, the other answered (role decided by key order, no race) — both directions
    // of the federation link were genuinely exercised regardless of which side drew which role.
    let roles = format!(
        "{}{}",
        a_out.contains("\"role\":\"initiator\""),
        b_out.contains("\"role\":\"initiator\"")
    );
    assert!(
        roles == "truefalse" || roles == "falsetrue",
        "expected exactly one initiator: alice_out={a_out} bob_out={b_out}"
    );
}
