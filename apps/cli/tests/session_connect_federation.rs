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

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::{serve, AppState, MemoryStore};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

// -- PKI test harness (mirrors apps/cli/tests/federation_route_hint.rs /
//    apps/rendezvous/tests/federation_route.rs) -------------------------------------------------

struct TestCa {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(common_name: &str) -> TestCa {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let key = KeyPair::generate().expect("generate CA key");
    let cert = params.self_signed(&key).expect("self-sign CA cert");
    TestCa { cert, key }
}

fn make_leaf(domain: &str, ca: &TestCa) -> (rcgen::Certificate, KeyPair) {
    let mut params =
        CertificateParams::new(vec![domain.to_string()]).expect("SAN must be a valid DNS name");
    params.distinguished_name.push(DnType::CommonName, domain);
    let key = KeyPair::generate().expect("generate leaf key");
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("sign leaf cert");
    (cert, key)
}

fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

struct Identity {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    ca_bundle_path: std::path::PathBuf,
}

fn mint_identity(dir: &Path, tag: &str, domain: &str, ca: &TestCa) -> Identity {
    let (leaf_cert, leaf_key) = make_leaf(domain, ca);
    Identity {
        cert_path: write(dir, &format!("{tag}.crt.pem"), &leaf_cert.pem()),
        key_path: write(dir, &format!("{tag}.key.pem"), &leaf_key.serialize_pem()),
        ca_bundle_path: write(dir, &format!("{tag}.ca.pem"), &ca.cert.pem()),
    }
}

// -- Server harness -------------------------------------------------------------------------------

fn base_config(domain: &str) -> Config {
    Config {
        server: Server {
            domain: domain.to_string(),
            bind: "127.0.0.1:0".to_string(),
            ..Server::default()
        },
        limits: Limits::default(),
        turn: Turn::default(),
        federation: Federation::default(),
    }
}

async fn spawn_c2s(state: Arc<AppState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(state, listener).await;
    });
    format!("ws://{addr}")
}

async fn spawn_federation(state: Arc<AppState>) -> SocketAddr {
    let listener = bind_federation(&state).await.expect("bind s2s listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_federation(listener, state).await;
    });
    addr
}

/// Bind an ephemeral loopback listener purely to learn a free port, then release it immediately.
/// Needed because (unlike the one-way harness in `federation_route_hint.rs`) **both** orgs here
/// dial **each other**, so each side's `federation_map.toml` must name the other's s2s address
/// before either `AppState` exists — and `StaticMap` is loaded once, at `AppState::new` time
/// (`apps/rendezvous/src/state.rs`), not re-read later. Picking two real, currently-free loopback
/// ports up front (then handing the same fixed addresses to `federation.bind` below) breaks that
/// chicken-and-egg cycle at the cost of the usual tiny (and in practice negligible, single-host
/// test) TOCTOU port-reuse window.
async fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> std::path::PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// Build one org's federation config, bound at a pre-chosen fixed address and dialing out to
/// whichever `partners` are named — unlike `federation_route_hint.rs`'s asymmetric
/// `org_a_federation`/`org_b_federation` (only A ever dials), both orgs in this test use this same
/// helper: both accept inbound AND dial out, since `session connect`'s SDP offer/answer exchange
/// needs to cross the federation boundary in both directions.
fn federation_config(
    dir: &Path,
    ca: &TestCa,
    tag: &str,
    domain: &str,
    bind_addr: SocketAddr,
    partners: &[(&str, SocketAddr, &str)],
) -> Federation {
    let id = mint_identity(dir, tag, domain, ca);
    let map_path = write_federation_map(dir, partners);
    Federation {
        enabled: true,
        bind: bind_addr.to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        fed_fetch_per_origin_per_min: 300,
        fed_route_per_origin_per_min: 600,
        fed_per_origin_account_per_min: 30,
        ..Federation::default()
    }
}

/// Stands up org-a and org-b, each federating to the other (mutual dial), returning both c2s URLs.
async fn stand_up_two_orgs_bidirectional(dir: &Path, ca: &TestCa) -> (String, String) {
    let a_fed_addr = free_loopback_addr().await;
    let b_fed_addr = free_loopback_addr().await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = federation_config(
        dir,
        ca,
        "a",
        "org-a.test",
        a_fed_addr,
        &[("org-b.test", b_fed_addr, "org-b.test")],
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_fed_bound = spawn_federation(a_state.clone()).await;
    assert_eq!(
        a_fed_bound, a_fed_addr,
        "org-a's s2s listener must bind the pre-chosen address"
    );
    let a_c2s_url = spawn_c2s(a_state).await;

    let mut b_config = base_config("org-b.test");
    b_config.federation = federation_config(
        dir,
        ca,
        "b",
        "org-b.test",
        b_fed_addr,
        &[("org-a.test", a_fed_addr, "org-a.test")],
    );
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_bound = spawn_federation(b_state.clone()).await;
    assert_eq!(
        b_fed_bound, b_fed_addr,
        "org-b's s2s listener must bind the pre-chosen address"
    );
    let b_c2s_url = spawn_c2s(b_state).await;

    (a_c2s_url, b_c2s_url)
}

// -- CLI driver (mirrors apps/cli/tests/session_connect_webrtc.rs) ---------------------------------

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

    /// Each account's own `--hint` names its OWN home org (never the peer's) — exactly like
    /// `federation_route_hint.rs`'s `new_account`, and unlike `session_connect_webrtc.rs`'s
    /// single-server test (which hardcodes `"localhost"` for both sides since there is only one
    /// server there).
    fn new_account(&self, keyfile: &str, own_domain_hint: &str) {
        let out = self.run(&[
            "id",
            "new",
            "--store",
            "file",
            "--out",
            keyfile,
            "--hint",
            own_domain_hint,
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }

    fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Spawn `session connect <peer_id> --server <server> --transport webrtc --json` as a real
    /// child process, talking only to this client's own home server (`server`) — the peer id's
    /// `@domain` is the only thing that ever names the other org.
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

// -- The test ---------------------------------------------------------------------------------

#[test]
fn two_processes_on_two_federated_orgs_establish_a_real_p2p_session() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (a_c2s_url, b_c2s_url) = rt.block_on(stand_up_two_orgs_bidirectional(dir.path(), &ca));

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
    let a = alice.spawn_connect(&a_c2s_url, &bob_id);
    let b = bob.spawn_connect(&b_c2s_url, &alice_id);

    let (a_ok, a_out, a_err) = a.wait(Duration::from_secs(30));
    let (b_ok, b_out, b_err) = b.wait(Duration::from_secs(30));

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
