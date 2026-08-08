//! Task 2.15 acceptance: cross-org **routing** (not just bundle fetch) is hint-aware end to end,
//! driven through a real, live CLI path.
//!
//! Before this task, `apps/core/src/signal_relay.rs`'s `RendezvousRelay::send` and
//! `apps/cli/src/chat.rs`'s `route_tolerant` both hardcoded `hint: None` on every routed call.
//! `SignalingClient::route_with_hint` (`apps/signaling/src/client.rs`) already threaded a `Some`
//! hint correctly onto the wire (`RouteBody.to_hint`) and the server already federated on it
//! (task 2.8) — but the only caller anywhere in the tree that ever passed `Some(hint)` was a
//! server-side test (`apps/rendezvous/tests/federation_route.rs`) driving `SignalingClient`
//! directly. This test closes exactly that gap: it drives the real `meridian chat` binary as a
//! subprocess (mirrors `apps/cli/tests/chat_demo.rs`), across two real, federated
//! `meridian-rendezvous` instances over a real s2s mTLS link (mirrors
//! `apps/rendezvous/tests/federation_route.rs`'s harness), and asserts the message actually
//! arrives at a peer whose account has *never* connected to the sender's own server — the only way
//! that can happen is if the CLI's routed call carried `to_hint: Some("org-b.test")` all the way
//! to the wire and the server federated on it.
//!
//! **Why this is non-vacuous (mutation-test reasoning):** without the fix, `route_with_hint`'s
//! `to_hint` is `None`, which `ws::handle_route` treats as a same-server route
//! (`docs/api/wire-protocol.md` §2; see that function's own "routing invariant" comment). Since
//! Bob's account only ever registers with org-b's registry, a hint-less route from org-a's server
//! can never find him locally — `deliver_one` returns `Some(false)` (not an error: `route_ok
//! {delivered:false}`), so Alice's `chat` process would print `"delivered":false` and Bob's own
//! `next_deliver()` would simply hang forever waiting for a message that structurally cannot
//! arrive. This test bounds that wait (`BOB_DELIVER_TIMEOUT`) so a regression fails loudly instead
//! of hanging the suite, and additionally asserts on the wire-level fact (`delivered:true` in
//! Alice's own JSON output) rather than only on Bob's receipt.
//!
//! Bob is a raw in-test `SignalingClient` (never a full `meridian chat` process): he only needs to
//! publish a bundle and observe one `Deliver` frame, and this sidesteps needing org-b to *also*
//! federate back to org-a just to carry an auto-acknowledgement receipt (`chat.rs`'s
//! `deliver_content` sends one on every inbound text) — a real two-way CLI-to-CLI chat is already
//! covered same-server by `chat_demo.rs`; this test's whole point is the cross-org **routing** hop
//! specifically, which a single A→B delivery proves.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meridian_core::identity::{generate_account, parse_id, MemorySecretStore};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::{serve, AppState, MemoryStore};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Generous but bounded: a genuine "the hint never reached the wire" regression must hang forever
/// (Bob can never receive locally), so this needs to be long enough to rule out ordinary CI
/// slowness while still turning "impossible to deliver" into a loud, fast test failure rather than
/// wedging the whole suite.
const BOB_DELIVER_TIMEOUT: Duration = Duration::from_secs(20);

// -- PKI test harness (mirrors apps/rendezvous/tests/federation_route.rs /
//    apps/cli/tests/federation_errors.rs) --------------------------------------------------------

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

// -- Server harness (mirrors federation_route.rs) -------------------------------------------------

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

fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> std::path::PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// A (Alice's home server) dials out to B: its own federation identity, a `federation_map.toml`
/// pointing `org-b.test` at B's already-bound s2s address, `enabled = true`, static discovery.
/// Only A ever needs to dial in this test (Bob is a raw client, never routes anything back).
fn org_a_federation(dir: &Path, ca: &TestCa, a_domain: &str, b_fed_addr: SocketAddr) -> Federation {
    let id = mint_identity(dir, "a", a_domain, ca);
    let map_path = write_federation_map(dir, &[("org-b.test", b_fed_addr, "org-b.test")]);
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        // A's own OUTBOUND admission policy (task 3.1, review finding F1) — `open`, since this
        // test is about A successfully routing to B, not about A refusing to dial out at all.
        // `Federation::default()`'s fail-closed `Closed` would otherwise make A deny before ever
        // reaching B.
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    }
}

/// B (Bob's home server): accepts inbound federation, `open` policy, never dials out.
fn org_b_federation(dir: &Path, ca: &TestCa, b_domain: &str) -> Federation {
    let id = mint_identity(dir, "b", b_domain, ca);
    let empty_map = write(dir, "b-federation_map.toml", "");
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: empty_map.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        fed_fetch_per_origin_per_min: 300,
        fed_route_per_origin_per_min: 600,
        fed_per_origin_account_per_min: 30,
        ..Federation::default()
    }
}

/// Stands up org-a (dials out, hosts Alice's real CLI process) + org-b (accepts inbound, hosts
/// Bob's raw in-test client), returning both c2s URLs.
async fn stand_up_two_orgs(dir: &Path, ca: &TestCa) -> (String, String) {
    let mut b_config = base_config("org-b.test");
    b_config.federation = org_b_federation(dir, ca, "org-b.test");
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;
    let b_c2s_url = spawn_c2s(b_state).await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(dir, ca, "org-a.test", b_fed_addr);
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    (a_c2s_url, b_c2s_url)
}

// -- CLI driver (mirrors apps/cli/tests/chat_demo.rs) ---------------------------------------------

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
    fn new_account(&self, keyfile: &str, hint: &str) {
        let out = self.run(&[
            "id", "new", "--store", "file", "--out", keyfile, "--hint", hint,
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }
    fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
    fn spawn_chat(&self, server: &str, peer_id: &str) -> ChatProc {
        let mut child = Command::new(BIN)
            .args(["chat", peer_id, "--server", server, "--json"])
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn chat");
        let stdin = child.stdin.take().unwrap();
        let out = drain(child.stdout.take().unwrap());
        let err = drain(child.stderr.take().unwrap());
        ChatProc {
            child,
            stdin: Some(stdin),
            out,
            err,
        }
    }
}

struct ChatProc {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl ChatProc {
    fn send(&mut self, line: &str) {
        use std::io::Write;
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = writeln!(stdin, "{line}");
            let _ = stdin.flush();
        }
    }
    fn out(&self) -> String {
        self.out.lock().unwrap().clone()
    }
    fn err(&self) -> String {
        self.err.lock().unwrap().clone()
    }
    fn finish(mut self) -> (String, String) {
        self.stdin.take(); // drop stdin -> EOF -> clean exit
        let _ = self.child.wait();
        (self.out(), self.err())
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

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    cond()
}

// -- The test ---------------------------------------------------------------------------------

#[test]
fn cross_org_chat_route_reaches_a_peer_who_never_connected_to_the_sender_home_server() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (a_c2s_url, b_c2s_url) = rt.block_on(stand_up_two_orgs(dir.path(), &ca));

    // Alice: a real account on org-a, driven through the real `meridian` binary.
    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");
    let alice_id = alice.id();
    let alice_ik = *parse_id(&alice_id).unwrap().pubkey();

    // Bob: a raw in-test `SignalingClient` on org-b — never a `meridian chat` process, and never
    // connects anywhere but org-b's own c2s socket (the routing invariant this test is built
    // around: the CLI must never dial `org-b.test` directly, only its own home server org-a must
    // federate there on Bob's behalf).
    //
    // Roles in `chat.rs` are decided deterministically by key order (the lexicographically
    // smaller identity key initiates X3DH) so Alice's already-fixed key needs a Bob whose key
    // sorts *after* it — generate candidates until one does, so this test is never flaky by
    // depending on which side happens to initiate.
    let bob_store = MemorySecretStore::new();
    let bob_account = loop {
        let candidate = generate_account(&bob_store, "org-b.test").unwrap();
        if candidate.public_key().as_bytes().as_slice() >= alice_ik.as_slice() {
            break candidate;
        }
    };
    let bob_ik = *bob_account.public_key().as_bytes();
    let bob_id = bob_account.to_id_string();

    let mut bob_client = rt
        .block_on(SignalingClient::connect(
            &b_c2s_url,
            &bob_store,
            bob_account.handle(),
            bob_ik,
            None,
            1,
        ))
        .expect("bob connects to org-b");
    let _bundle = rt
        .block_on(bob_client.publish_bundle(&bob_store, bob_account.handle(), DEFAULT_OTK_COUNT))
        .expect("bob publishes a bundle so alice's fetch-across-orgs succeeds");

    // Alice's `meridian chat` process only ever talks to org-a's own server (`a_c2s_url`); the
    // peer id (`bob_id`, `mrd1:...@org-b.test`) is the only thing that ever names org-b.
    let mut a = alice.spawn_chat(&a_c2s_url, &bob_id);
    std::thread::sleep(Duration::from_millis(500)); // let alice connect + publish + fetch + X3DH

    let sent = wait_until(Duration::from_secs(15), || {
        a.send("hello across orgs");
        std::thread::sleep(Duration::from_millis(400));
        a.out().contains("\"event\":\"sent\"")
    });
    assert!(
        sent,
        "alice never even reported a 'sent' event.\nstdout: {}\nstderr: {}",
        a.out(),
        a.err()
    );

    // The wire-level assertion: alice's own JSON output says the route delivered — this can only
    // be true if `RouteBody.to_hint` reached the server and org-a federated to org-b, since Bob's
    // account has never registered with org-a's registry at all.
    assert!(
        a.out().contains("\"delivered\":true"),
        "alice's route to bob must report delivered:true — a hint-less route can never find a \
         peer who only ever registered at a DIFFERENT org's server.\nstdout: {}\nstderr: {}",
        a.out(),
        a.err()
    );

    // The receiving-side assertion: Bob's own live connection to org-b actually received the
    // envelope, `from` set to Alice's real key — not merely that alice's client believes it sent
    // something.
    let deliver = rt
        .block_on(async {
            tokio::time::timeout(BOB_DELIVER_TIMEOUT, bob_client.next_deliver()).await
        })
        .unwrap_or_else(|_| {
            panic!(
                "bob never received anything within {BOB_DELIVER_TIMEOUT:?} — the cross-org \
                 route never reached the wire (a regression here means to_hint stopped being \
                 threaded through). alice stdout: {}\nalice stderr: {}",
                a.out(),
                a.err()
            )
        })
        .expect("bob's connection to org-b must not error while awaiting delivery");
    assert_eq!(
        deliver.from, alice_ik,
        "the envelope bob received must be attributed to alice's real key, relayed verbatim \
         across the federation boundary"
    );
    assert!(
        !deliver.blob.as_bytes().is_empty(),
        "the delivered envelope must carry alice's sealed chat blob"
    );

    let (a_out, a_err) = a.finish();
    assert!(
        a_out.contains("\"delivered\":true"),
        "final check after teardown: {a_out} / {a_err}"
    );
}
