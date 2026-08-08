//! Task 2.9 acceptance: client-side federation error taxonomy.
//!
//! Drives two real, in-process `meridian-rendezvous` servers ("A" = alice's home server, "B" =
//! bob's) connected over a real s2s mTLS link (task 2.4, mirrors
//! `apps/rendezvous/tests/federation_fetch.rs`'s PKI/harness), then runs the real `meridian` CLI
//! binary as a subprocess (mirrors `apps/cli/tests/rendezvous_demo.rs`) fetching a cross-org
//! bundle through it — end to end, exactly the path a user drives.
//!
//! Two scenarios, matching the task's acceptance criteria:
//! - a `closed`-policy org B → `meridian fetch-bundle` exits clean and non-zero, naming the cause
//!   (`federation denied`), and does so **quickly** — never a hang.
//! - the stale-hint case (B has no record of the target — indistinguishable, from this one wire
//!   response, from "never registered" and "re-registered at a different org", task 2.9's own risk
//!   note) → the output says **"unreachable at hint"**.
//!
//! Both assertions additionally grep the full output (stdout + stderr) for the canonical
//! security-warning/verification vocabulary (`docs/security/verification-ux.md`) and assert its
//! **absence** — the reachability-vs-security distinction this task exists to keep, checked as
//! code rather than merely claimed in a doc comment.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::{serve, AppState, MemoryStore};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Generous enough for two real in-process servers + one real s2s round trip on a loaded CI box,
/// while still being a real, enforced bound: a genuine hang (the failure mode this task exists to
/// close off) would sit at "forever", not "a few seconds late" — this catches that distinction
/// without being so tight it flakes on a slow machine.
const NO_HANG_TIMEOUT: Duration = Duration::from_secs(20);

// -- PKI test harness (mirrors apps/rendezvous/tests/federation_fetch.rs) -----------------------

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

// -- Server harness (mirrors apps/rendezvous/tests/federation_fetch.rs) --------------------------

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

/// Spawn `domain`'s c2s WS listener and return its `ws://` URL.
async fn spawn_c2s(state: Arc<AppState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(state, listener).await;
    });
    format!("ws://{addr}")
}

/// Bind `domain`'s s2s federation listener and start serving it. Returns the bound address.
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

/// A's federation config: dials out to B, pinning to B's own domain (a straightforward,
/// non-adversarial private-CA setup — the pinned-identity mismatch attack is 2.7's job, not this
/// task's).
fn org_a_federation(
    dir: &Path,
    ca: &TestCa,
    a_domain: &str,
    b_domain: &str,
    b_fed_addr: SocketAddr,
) -> Federation {
    let id = mint_identity(dir, "a", a_domain, ca);
    let map_path = write_federation_map(dir, &[(b_domain, b_fed_addr, b_domain)]);
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        // A's own OUTBOUND admission policy (task 3.1, review finding F1) — always `open` here:
        // both scenarios in this file are about B's response (closed-policy denial or a stale
        // hint), never about A refusing to dial out in the first place. `Federation::default()`'s
        // fail-closed `Closed` would otherwise make A deny before ever reaching B, which is a
        // different, untested code path in this file.
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    }
}

/// B's federation config: never dials out in these tests, but still needs a syntactically valid
/// (partner-less) map, per `AppState::new`'s fail-loud-at-boot federation runtime.
fn org_b_federation(
    dir: &Path,
    ca: &TestCa,
    b_domain: &str,
    policy: FederationPolicyMode,
) -> Federation {
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
        policy,
        ..Federation::default()
    }
}

/// Stand up org-a (dialing out) + org-b (the federation target), returning A's c2s URL — the only
/// endpoint the CLI ever talks to (the routing invariant).
async fn stand_up_two_orgs(dir: &Path, ca: &TestCa, b_policy: FederationPolicyMode) -> String {
    let mut b_config = base_config("org-b.test");
    b_config.federation = org_b_federation(dir, ca, "org-b.test", b_policy);
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state).await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(dir, ca, "org-a.test", "org-b.test", b_fed_addr);
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    spawn_c2s(a_state).await
}

// -- CLI driver (mirrors apps/cli/tests/rendezvous_demo.rs) --------------------------------------

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

    /// Run `meridian <args>` to completion, but **bounded**: a real hang (the exact failure mode
    /// this task exists to close off) fails the test loudly instead of wedging the whole suite.
    /// `Command::output()` alone has no timeout at all, which would make "no hang" unfalsifiable.
    fn run_bounded(&self, args: &[&str], timeout: Duration) -> Output {
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
                            "meridian {args:?} did not exit within {timeout:?} — treated as a \
                             hang, exactly the failure mode task 2.9 exists to close off"
                        );
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_bounded(args, NO_HANG_TIMEOUT)
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
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The canonical security/verification vocabulary this task's whole point is to keep OUT of a
/// reachability failure's copy (docs/security/verification-ux.md; `BundleVerification`'s own
/// wording in `apps/signaling/src/error.rs`). Checked as a real, explicit assertion rather than
/// merely asserted in prose — this is the "no security warning" property from the task file.
const SECURITY_COPY_MARKERS: &[&str] = &[
    "FATAL",
    "signature does not match",
    "safety number",
    "intercept",
    "verify the new safety number",
    "key change",
    "substitut",
];

fn assert_no_security_copy(combined: &str) {
    let lower = combined.to_ascii_lowercase();
    for marker in SECURITY_COPY_MARKERS {
        assert!(
            !lower.contains(&marker.to_ascii_lowercase()),
            "a reachability/policy failure must NEVER emit security-warning copy — found \
             {marker:?} in output:\n{combined}"
        );
    }
}

// -- Scenario 1: closed-policy org -> clean, non-zero, no hang, named cause ----------------------

#[test]
fn closed_policy_org_produces_a_clean_non_zero_exit_never_a_hang() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let a_c2s_url = rt.block_on(stand_up_two_orgs(
        dir.path(),
        &ca,
        FederationPolicyMode::Closed,
    ));

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");

    // Bob's identity never needs to exist at B for this scenario — B's `closed` policy rejects on
    // policy alone, before any target lookup (mirrors
    // `federation_fetch.rs::closed_policy_at_b_is_reported_as_fed_denied`).
    let bob = Client::new();
    bob.new_account("bob.key", "org-b.test");
    let bob_id = bob.id();

    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &a_c2s_url]);

    // Clean, non-zero exit — never a panic/crash, never a hang (enforced above by `run_bounded`).
    assert!(
        !out.status.success(),
        "a closed-policy org must fail the fetch, non-zero exit; stdout={}",
        stdout(&out)
    );
    assert!(
        out.status.code().is_some(),
        "the process must exit cleanly (a defined exit code), not be killed/signalled"
    );

    let combined = format!("{}{}", stdout(&out), stderr(&out));
    // A named, diagnosable cause — not a bare "error" with no context.
    assert!(
        combined.to_ascii_lowercase().contains("denied") && combined.contains("org-b.test"),
        "expected a named federation-denied cause mentioning org-b.test, got: {combined}"
    );
    assert_no_security_copy(&combined);
}

// -- Scenario 2: stale hint -> "unreachable at hint", never a security warning -------------------

#[test]
fn stale_hint_reports_unreachable_at_hint_never_a_security_warning() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let rt = tokio::runtime::Runtime::new().unwrap();
    // B is Open — the point here is that B genuinely has no record of the target, exactly the
    // stale-hint acceptance scenario (Bob re-registered at org-c, so org-b either never had him or
    // no longer does — indistinguishable from this one wire response, task 2.9's own risk note).
    let a_c2s_url = rt.block_on(stand_up_two_orgs(
        dir.path(),
        &ca,
        FederationPolicyMode::Open,
    ));

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");

    // A syntactically valid id hinting at org-b.test that never published anything there.
    let ghost = Client::new();
    ghost.new_account("ghost.key", "org-b.test");
    let ghost_id = ghost.id();

    let out = alice.run(&["fetch-bundle", &ghost_id, "--server", &a_c2s_url]);

    assert!(
        !out.status.success(),
        "a stale/unknown hint must fail the fetch, non-zero exit; stdout={}",
        stdout(&out)
    );
    assert!(
        out.status.code().is_some(),
        "the process must exit cleanly (a defined exit code), not be killed/signalled"
    );

    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        combined.contains("unreachable at hint"),
        "expected the literal phrase 'unreachable at hint', got: {combined}"
    );
    assert!(
        combined.contains("org-b.test"),
        "expected the hint domain to be named, got: {combined}"
    );
    assert_no_security_copy(&combined);
}
