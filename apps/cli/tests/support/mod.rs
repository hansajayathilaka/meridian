//! Shared test harness: PKI (test CA + leaf certs), rendezvous server-boot helpers, and the
//! `meridian` CLI subprocess driver used by the cross-org federation integration tests in this
//! crate.
//!
//! Task 3.4 / review finding F18: this used to be ~40 lines of near-identical `make_ca`/
//! `make_leaf`/`mint_identity`/`write`/`base_config`/`spawn_c2s`/`spawn_federation`/`Client`/
//! `ChatProc`/`drain`/`wait_until` boilerplate, copy-pasted into `federation_errors.rs`,
//! `federation_route_hint.rs`, `session_connect_federation.rs`, and `two_orgs_walkthrough.rs`
//! independently. One copy here instead.
//!
//! **Must be `support/mod.rs`, not a bare `support.rs`**: Cargo treats a bare `tests/support.rs`
//! as its own top-level integration-test binary; `tests/support/mod.rs`, brought in via `mod
//! support;` from each real test file, is a plain module instead.
//!
//! Dev-dependency only (`tempfile`, `rcgen`, `meridian-rendezvous` — all already this crate's own
//! `[dev-dependencies]`) — nothing here is linked into the production `meridian` binary. Not every
//! test file in this crate uses every helper below: each integration-test file compiles this
//! module fresh as its own private `mod`, so per-file unused warnings would otherwise fire for
//! whichever helpers that particular file doesn't happen to call — hence the blanket allow.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::{serve, AppState};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const BIN: &str = env!("CARGO_BIN_EXE_meridian");

// -- PKI test harness ---------------------------------------------------------------------------

/// A minted CA: its self-signed `rcgen::Certificate` (used as the `signed_by` issuer) and key.
pub struct TestCa {
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
}

impl TestCa {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "Meridian Test Federation CA");
        let key = KeyPair::generate().expect("generate CA key");
        let cert = params.self_signed(&key).expect("self-sign CA cert");
        TestCa { cert, key }
    }

    /// Mint a leaf cert for `domain` (used as both the SAN dNSName and the CN), signed by this CA,
    /// writing cert/key/CA-bundle PEMs under `dir`. `domain` also serves as the filename tag, plus
    /// `tag` to disambiguate when more than one identity shares a domain string in the same dir
    /// (bidirectional harnesses mint "a"/"b"-tagged identities for "org-a.test"/"org-b.test").
    pub fn issue(&self, dir: &Path, tag: &str, domain: &str) -> Identity {
        let mut params =
            CertificateParams::new(vec![domain.to_string()]).expect("SAN must be a valid DNS name");
        params.distinguished_name.push(DnType::CommonName, domain);
        let key = KeyPair::generate().expect("generate leaf key");
        let leaf_cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("sign leaf cert");
        Identity {
            cert_path: write(dir, &format!("{tag}.crt.pem"), &leaf_cert.pem()),
            key_path: write(dir, &format!("{tag}.key.pem"), &key.serialize_pem()),
            ca_bundle_path: write(dir, &format!("{tag}.ca.pem"), &self.cert.pem()),
        }
    }
}

pub fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// A minted identity's cert+key PEM files, written under some `dir`, plus the CA bundle PEM it was
/// signed under (also written under `dir`).
pub struct Identity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_bundle_path: PathBuf,
}

impl Identity {
    pub fn cert_path_str(&self) -> &str {
        self.cert_path.to_str().unwrap()
    }
    pub fn key_path_str(&self) -> &str {
        self.key_path.to_str().unwrap()
    }
    pub fn ca_bundle_path_str(&self) -> &str {
        self.ca_bundle_path.to_str().unwrap()
    }
}

// -- rendezvous server-boot harness --------------------------------------------------------------

pub fn base_config(domain: &str) -> Config {
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

/// Spawn `state`'s c2s WS listener and return its `ws://` URL.
pub async fn spawn_c2s(state: Arc<AppState>) -> String {
    spawn_c2s_handle(state).await.0
}

/// Same as [`spawn_c2s`], also returning the listener task's [`JoinHandle`] — needed by tests that
/// must later kill the server outright (abort the task), not merely stop using it.
pub async fn spawn_c2s_handle(state: Arc<AppState>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = serve(state, listener).await;
    });
    (format!("ws://{addr}"), handle)
}

/// Bind `state`'s s2s federation listener and start serving it. Returns the bound address.
pub async fn spawn_federation(state: Arc<AppState>) -> SocketAddr {
    spawn_federation_handle(state).await.0
}

/// Same as [`spawn_federation`], also returning the listener task's [`JoinHandle`].
pub async fn spawn_federation_handle(state: Arc<AppState>) -> (SocketAddr, JoinHandle<()>) {
    let listener = bind_federation(&state).await.expect("bind s2s listener");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        run_federation(listener, state).await;
    });
    (addr, handle)
}

/// Bind an ephemeral loopback listener purely to learn a free port, then release it immediately —
/// needed by bidirectional harnesses, where both orgs' `federation_map.toml` must name the OTHER's
/// s2s address before either `AppState` exists (`StaticMap` is loaded once, at `AppState::new`
/// time, not re-read later).
pub async fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Build a `federation_map.toml` (private-CA mode, task 2.5's schema): one `[[partner]]` entry per
/// `(domain, endpoint, pinned_identity)` tuple.
pub fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// Build one org's federation config, bound at a pre-chosen fixed address and dialing out to
/// whichever `partners` are named — the bidirectional-harness shape (`session_connect_federation.rs`
/// / `two_orgs_walkthrough.rs`), where both orgs accept inbound AND dial out.
pub fn federation_config(
    dir: &Path,
    ca: &TestCa,
    tag: &str,
    domain: &str,
    bind_addr: SocketAddr,
    partners: &[(&str, SocketAddr, &str)],
) -> Federation {
    let id = ca.issue(dir, tag, domain);
    let map_path = write_federation_map(dir, partners);
    Federation {
        enabled: true,
        bind: bind_addr.to_string(),
        cert_path: id.cert_path_str().to_string(),
        key_path: id.key_path_str().to_string(),
        ca_bundle_path: id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        fed_fetch_per_origin_per_min: 300,
        fed_route_per_origin_per_min: 600,
        fed_per_origin_account_per_min: 30,
        ..Federation::default()
    }
}

/// Everything needed to tear a stood-up bidirectional two-org rig down, or leave it running (used
/// by the continuity-style tests that prove a P2P data channel survives after both are aborted).
pub struct BidirectionalPair {
    pub dir: tempfile::TempDir,
    pub ca: TestCa,
    pub a_c2s_url: String,
    pub b_c2s_url: String,
    pub handles: Vec<JoinHandle<()>>,
}

impl BidirectionalPair {
    /// Kill BOTH rendezvous servers: abort every listener task (c2s + federation, both orgs).
    /// `JoinHandle::abort` cancels the task at its next await point — the listening sockets are
    /// dropped when the aborted tasks unwind, so no new connection can be accepted and no
    /// in-flight `accept().await` completes either.
    pub fn kill_both_servers(self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

/// Stand up org-a and org-b, each federating to the other (mutual dial) at fixed domains
/// `"org-a.test"`/`"org-b.test"`, returning both c2s URLs and abortable listener handles.
pub async fn boot_federated_pair_bidirectional() -> BidirectionalPair {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let a_fed_addr = free_loopback_addr().await;
    let b_fed_addr = free_loopback_addr().await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = federation_config(
        dir.path(),
        &ca,
        "a",
        "org-a.test",
        a_fed_addr,
        &[("org-b.test", b_fed_addr, "org-b.test")],
    );
    let a_store = Arc::new(meridian_rendezvous::MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let (a_fed_bound, a_fed_handle) = spawn_federation_handle(a_state.clone()).await;
    assert_eq!(
        a_fed_bound, a_fed_addr,
        "org-a's s2s listener must bind the pre-chosen address"
    );
    let (a_c2s_url, a_c2s_handle) = spawn_c2s_handle(a_state).await;

    let mut b_config = base_config("org-b.test");
    b_config.federation = federation_config(
        dir.path(),
        &ca,
        "b",
        "org-b.test",
        b_fed_addr,
        &[("org-a.test", a_fed_addr, "org-a.test")],
    );
    let b_store = Arc::new(meridian_rendezvous::MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let (b_fed_bound, b_fed_handle) = spawn_federation_handle(b_state.clone()).await;
    assert_eq!(
        b_fed_bound, b_fed_addr,
        "org-b's s2s listener must bind the pre-chosen address"
    );
    let (b_c2s_url, b_c2s_handle) = spawn_c2s_handle(b_state).await;

    BidirectionalPair {
        dir,
        ca,
        a_c2s_url,
        b_c2s_url,
        handles: vec![a_fed_handle, a_c2s_handle, b_fed_handle, b_c2s_handle],
    }
}

// -- CLI driver -----------------------------------------------------------------------------------

/// A `meridian` CLI identity: its own isolated `MERIDIAN_HOME` + working directory.
pub struct Client {
    pub home: tempfile::TempDir,
    pub work: tempfile::TempDir,
}

impl Client {
    pub fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        }
    }

    pub fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .output()
            .expect("run meridian")
    }

    /// Run `meridian <args>` to completion, but **bounded**: a real hang fails the test loudly
    /// instead of wedging the whole suite. `Command::output()` alone has no timeout at all, which
    /// would make "no hang" unfalsifiable.
    pub fn run_bounded(&self, args: &[&str], timeout: Duration) -> Output {
        let mut child = Command::new(BIN)
            .args(args)
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn meridian binary");
        let start = Instant::now();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_status) => return child.wait_with_output().expect("collect output"),
                None => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!(
                            "meridian {args:?} did not exit within {timeout:?} — treated as a hang"
                        );
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    pub fn new_account(&self, keyfile: &str, hint: &str) {
        let out = self.run(&[
            "id", "new", "--store", "file", "--out", keyfile, "--hint", hint,
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }

    pub fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Spawn `meridian chat <peer_id> --server <server> --json` as a real child process, with its
    /// stdin piped (for scripted input) and stdout/stderr accumulated by background reader
    /// threads.
    pub fn spawn_chat(&self, server: &str, peer_id: &str) -> ChatProc {
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

/// A running `meridian chat` subprocess with its stdout/stderr accumulated by reader threads.
pub struct ChatProc {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl ChatProc {
    pub fn send(&mut self, line: &str) {
        use std::io::Write;
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = writeln!(stdin, "{line}");
            let _ = stdin.flush();
        }
    }
    pub fn out(&self) -> String {
        self.out.lock().unwrap().clone()
    }
    pub fn err(&self) -> String {
        self.err.lock().unwrap().clone()
    }
    pub fn finish(mut self) -> (String, String) {
        self.stdin.take(); // drop stdin -> EOF -> clean exit
        let _ = self.child.wait();
        (self.out(), self.err())
    }
}

pub fn drain<R: std::io::Read + Send + 'static>(stream: R) -> Arc<Mutex<String>> {
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

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    cond()
}
