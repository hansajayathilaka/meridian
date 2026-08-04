//! Real-process acceptance test for `meridian session connect` (1.24, F11 wire prerequisite):
//! `cargo nextest run -p meridian-cli --features webrtc`.
//!
//! Unlike `session_demo_webrtc.rs` (one process simulating both sides of a P2P session
//! in-process), this spawns **two separate `meridian` child processes** against a real
//! `meridian-rendezvous` instance started by the test on localhost, each running `session connect
//! <other-peer-id> --server <url> --transport webrtc` concurrently. This is what proves the
//! `SignalRelay`-over-`SignalingClient` adapter actually lets two OS processes rendezvous and dial
//! a real P2P session — `session demo`'s in-process `LoopbackTransport`/`MemRelay` simulation can
//! never exercise that path.

#![cfg(feature = "webrtc")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Bound for waiting on a child `session connect` process to exit. Must stay strictly greater
/// than `meridian_core::session::ANSWER_TIMEOUT` (30s): that internal timeout is what's supposed
/// to fire and let the process exit cleanly on a genuinely stuck dial, so a test-harness deadline
/// equal to it is a race with zero margin — under any scheduling slowness (a loaded CI runner) the
/// harness's own hard kill can fire at/before the internal timeout, turning a clean
/// `AnswerTimeout` exit into this file's own "timed out waiting for process to exit" instead.
///
/// 90s (task 2.16, was 60s): with the real fix
/// (`ICE_DISCONNECTED_TIMEOUT`/`ICE_FAILED_TIMEOUT` in `apps/transport/src/webrtc_backend.rs`, see
/// that constant's doc) landed, `two_processes_establish_a_real_p2p_session_when_a_turn_grant_is_minted`
/// below establishes directly on the first attempt — no 1.29 relay-fallback retry needed — in
/// ~20–25s measured locally, repeatedly. 90s keeps a comfortable multiple of that for a
/// slower/loaded CI runner without resurrecting the ~70–90s two-attempt worst case task 2.16 found
/// (and fixed) `two_processes_establish_a_real_p2p_session_when_a_turn_grant_is_minted`'s own doc
/// comment walks through that finding in full.
const PROCESS_WAIT_TIMEOUT: Duration = Duration::from_secs(90);

fn spawn_server_with_config(config: Config) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let store = std::sync::Arc::new(MemoryStore::new());
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    format!("ws://{}", rx.recv().unwrap())
}

fn spawn_server() -> String {
    spawn_server_with_config(Config::default())
}

/// A real `[turn]` secret configured (mirrors `apps/rendezvous/tests/rendezvous.rs`'s
/// `config_with_turn`) — `request_turn_credentials` mints a real HMAC grant without needing a live
/// coturn (minting is pure HMAC computation server-side; nothing validates the grant against a
/// running relay), so this proves the CLI's successful-grant path end to end.
///
/// The endpoint is deliberately an **IP literal** (an RFC 5737 `TEST-NET-2` address, guaranteed
/// non-routable and never home to a real listener) rather than a hostname (task 2.16). A hostname
/// here (`turn.localhost` originally) makes `webrtc-ice`'s relay-candidate gathering resolve it via
/// `tokio::net::lookup_host`, whose latency depends on the local resolver/egress path — this
/// sandbox's proxied egress happens to fail that particular query in milliseconds (not
/// representative), while some real resolvers (e.g. systemd-resolved, common on GitHub Actions'
/// Ubuntu runners) synthesize an instant RFC 6761 loopback answer for any `*.localhost` name
/// instead of querying the network at all — either way, DNS timing is an environment-dependent
/// variable this test has no business depending on. An IP literal removes it entirely: it parses
/// directly as a `SocketAddr` (`tokio::net::addr`'s `ToSocketAddrs for str` impl has a synchronous
/// fast path for exactly this — confirmed against the vendored `tokio` 1.52.3 source), so no DNS
/// lookup happens, deterministically, in this sandbox, in CI, or anywhere else.
fn spawn_server_with_turn() -> String {
    let mut config = Config::default();
    config.turn = meridian_rendezvous::config::Turn {
        secret: "shared-secret-abc".into(),
        realm: "localhost".into(),
        urls: vec![
            "turn:198.51.100.1:3478?transport=udp".into(),
            "turn:198.51.100.1:3478?transport=tcp".into(),
            "turns:198.51.100.1:443?transport=tcp".into(),
        ],
        ttl_secs: 120,
    };
    spawn_server_with_config(config)
}

struct Client {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Client {
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
            .expect("run meridian")
    }

    fn new_account(&self, keyfile: &str) {
        let out = self.run(&[
            "id",
            "new",
            "--store",
            "file",
            "--out",
            keyfile,
            "--hint",
            "localhost",
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }

    fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Spawn `session connect <peer_id> --server <server> --transport webrtc --json` as a real
    /// child process (not run to completion here — the caller waits for both sides concurrently).
    fn spawn_connect(&self, server: &str, peer_id: &str) -> ConnectProc {
        let mut child = Command::new(BIN)
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
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn session connect");
        let out = drain(child.stdout.take().unwrap());
        let err = drain(child.stderr.take().unwrap());
        ConnectProc { child, out, err }
    }
}

/// A running `session connect` subprocess with its stdout/stderr accumulated by reader threads.
struct ConnectProc {
    child: Child,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl ConnectProc {
    /// Wait for the process to exit (bounded), returning `(success, stdout, stderr)`.
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

/// Spawn a thread draining a child stream into a shared string buffer.
fn drain<R: std::io::Read + Send + 'static>(stream: R) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let sink = buf.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => sink.lock().unwrap().push_str(&line),
            }
        }
    });
    buf
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn refuses_to_connect_when_the_configured_policy_for_the_peer_is_not_direct_and_turn_is_unavailable(
) {
    // A real rendezvous is now up (task 1.25's TURN wiring), but with `Config::default()`'s empty
    // `[turn].secret` — the same "dev/air-gapped, no relay configured" shape as
    // `turn_unavailable_when_no_relay_configured` in `apps/rendezvous/tests/rendezvous.rs`. Under
    // `direct` this would degrade to a host/srflx-only attempt, but the whole point of `relay-only`
    // is relay availability, so `session connect` must still fail closed rather than silently
    // connecting without one — that would hand host/srflx candidates to the peer with no warning.
    let server = spawn_server();

    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let bob_id = bob.id();

    let set = alice.run(&[
        "config",
        "set",
        "policy",
        "relay-only",
        "--contact",
        &bob_id,
    ]);
    assert!(set.status.success(), "config set: {}", stderr(&set));

    let out = alice.run(&[
        "session",
        "connect",
        &bob_id,
        "--server",
        &server,
        "--transport",
        "webrtc",
    ]);
    assert!(
        !out.status.success(),
        "expected session connect to refuse a non-direct policy with no TURN relay configured"
    );
    let err = stderr(&out);
    assert!(
        err.contains("turn_unavailable") && err.contains("relay"),
        "stderr should explain the TURN-unavailable policy refusal: {err}"
    );
}

#[test]
fn two_processes_establish_a_real_p2p_session_over_the_rendezvous() {
    let server = spawn_server();

    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let alice_id = alice.id();
    let bob_id = bob.id();

    // Both sides must be live on the rendezvous at the same time (there is no mailbox for the
    // offer/answer exchange — see `signal_relay.rs`'s module docs), so spawn both concurrently and
    // wait for both, rather than running them one after another.
    let a = alice.spawn_connect(&server, &bob_id);
    let b = bob.spawn_connect(&server, &alice_id);

    let (a_ok, a_out, a_err) = a.wait(PROCESS_WAIT_TIMEOUT);
    let (b_ok, b_out, b_err) = b.wait(PROCESS_WAIT_TIMEOUT);

    assert!(
        a_ok,
        "alice's session connect failed.\nstdout: {a_out}\nstderr: {a_err}"
    );
    assert!(
        b_ok,
        "bob's session connect failed.\nstdout: {b_out}\nstderr: {b_err}"
    );

    let combined = format!("{a_out}\n{b_out}");

    // The real WebRtcTransport backend was used, not a simulation. Both sides run with
    // `--json`, so the headline event's `"transport":"..."` field is what actually gets
    // printed (the plain-text `transport=...` `Display` line only appears without `--json`).
    assert!(
        combined.contains("\"transport\":\"webrtc-datachannel\""),
        "expected a \"transport\":\"webrtc-datachannel\" field in combined output: {combined}"
    );
    // Both sides established the session ("p2p_connect" is the --json headline event).
    assert!(
        a_out.contains("\"event\":\"p2p_connect\"") && a_out.contains("\"established\":true"),
        "alice did not report an established session: {a_out}"
    );
    assert!(
        b_out.contains("\"event\":\"p2p_connect\"") && b_out.contains("\"established\":true"),
        "bob did not report an established session: {b_out}"
    );
    // One side dialed, the other answered (role decided by key order, no race).
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

#[test]
// This test first ran in CI when `cargo test -p meridian-cli --features webrtc` was wired into
// the pipeline (task 2.15's fix for a coverage gap); it immediately hung well past a 60s bound
// (PR #45, runs 30807298073 and 30808339815) despite passing reliably in local/interactive
// sandboxes. Root cause (task 2.16 — reproduced directly, repeatedly, with wall-clock timestamps,
// not guessed at): the original placeholder TURN endpoint was a hostname (`turn.localhost`), whose
// DNS resolution happened to fail in ~60ms in this sandbox's restricted/proxied egress — too fast
// to ever exercise the real failure path below. Switching to an IP literal (this file's
// `spawn_server_with_turn`, still practically unreachable — no coturn is listening) removes that
// environment-dependent DNS-timing variable, and reproduces a real, previously-undiscovered defect
// every time: `apps/transport/src/webrtc_backend.rs`'s `ICE_DISCONNECTED_TIMEOUT`+`ICE_FAILED_TIMEOUT`
// (tuned to 2s+4s by 1.29) is tight enough that the ICE agent can declare a Checking phase `Failed`
// before a **perfectly valid host candidate pair** (both `session connect` processes on the same
// machine) gets validated, whenever other configured ICE servers (STUN reflexive probes, a TURN
// Allocate) are concurrently gathering against a server that never answers — timestamped runs
// showed the Checking→Failed transition landing at almost exactly 6.0s (= `disconnected_timeout` +
// `failed_timeout`) every time, with the real pair still sitting there unvalidated. That failure
// then triggers 1.29's relay-only retry, which is doomed too (the TURN grant is genuinely dead),
// burning a second full round of the same bounded waits before finally erroring — every individual
// timeout fires correctly (`GATHER_TIMEOUT`/`WAIT_TIMEOUT`/`ANSWER_TIMEOUT`/`OFFER_TIMEOUT` are all
// real, bounded, and do return), but two full doomed attempts summed to ~70–90s, comfortably past
// both the 30s and 60s external bounds this test previously tried, which is what actually produced
// the "hung" symptom (a legitimately bounded but much-larger-than-assumed worst case, not a true
// infinite hang). Fixed at the root: `ICE_DISCONNECTED_TIMEOUT`/`ICE_FAILED_TIMEOUT` widened to
// 3s+9s (12s total, still comfortably inside `WAIT_TIMEOUT`'s 15s — see that constant's own doc in
// `apps/transport/src/webrtc_backend.rs` for the full reasoning and its distinction from 1.29's own,
// different non-convergence finding) — with that, this test now establishes directly on the first
// attempt, no relay-fallback retry needed, in ~20–25s measured locally, repeatedly. The test's own
// endpoint is also now an IP literal regardless of DNS behavior (see `spawn_server_with_turn`), and
// `apps/cli/src/main.rs` now tears its per-command runtime down with a bounded `shutdown_timeout`
// rather than relying on `Runtime::Drop` (which otherwise waits indefinitely for any orphaned
// `spawn_blocking` DNS-resolution thread) — both real, defense-in-depth improvements, even though
// the ICE-timeout fix above turned out to be the dominant cause. See
// docs/tasks/phase-2/2.16-turn-grant-ci-hang.md for the full writeup.
fn two_processes_establish_a_real_p2p_session_when_a_turn_grant_is_minted() {
    // A real `[turn]` secret is configured on the rendezvous (unlike `spawn_server`'s default),
    // so `request_turn_credentials` succeeds and `session connect` threads a real (if practically
    // unreachable — no coturn is actually running) `IceServer` into the ICE config under the
    // default `direct` policy. This proves the successful-grant → `IceServer` conversion doesn't
    // break the existing localhost happy path: host candidates still win even with a TURN server
    // offered alongside them.
    let server = spawn_server_with_turn();

    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let alice_id = alice.id();
    let bob_id = bob.id();

    let a = alice.spawn_connect(&server, &bob_id);
    let b = bob.spawn_connect(&server, &alice_id);

    let (a_ok, a_out, a_err) = a.wait(PROCESS_WAIT_TIMEOUT);
    let (b_ok, b_out, b_err) = b.wait(PROCESS_WAIT_TIMEOUT);

    assert!(
        a_ok,
        "alice's session connect failed.\nstdout: {a_out}\nstderr: {a_err}"
    );
    assert!(
        b_ok,
        "bob's session connect failed.\nstdout: {b_out}\nstderr: {b_err}"
    );
    assert!(
        a_out.contains("\"event\":\"p2p_connect\"") && a_out.contains("\"established\":true"),
        "alice did not report an established session: {a_out}"
    );
    assert!(
        b_out.contains("\"event\":\"p2p_connect\"") && b_out.contains("\"established\":true"),
        "bob did not report an established session: {b_out}"
    );
}
