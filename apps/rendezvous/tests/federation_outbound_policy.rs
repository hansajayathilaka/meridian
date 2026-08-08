//! Task 3.1 acceptance (review finding F1, blocking): server A's outbound dial-out path
//! (`federation::outbound::dial_foreign`) must consult A's OWN admission policy
//! (`state.federation.policy.admit(hint_domain)`) **before** any discovery/DNS lookup or TCP
//! dial — closing the client-driven SSRF / internal-port-probe oracle where a `closed`/
//! `allowlist` server would otherwise resolve and dial an arbitrary client-named domain on a
//! client's say-so alone.
//!
//! Each test maps to one of the task file's required cases:
//! - `closed` policy at A + outbound `Fetch{hint}` → `fed_denied` (never even reaches B)
//! - `closed` policy at A + outbound `Route{to_hint}` → `fed_denied`
//! - `allowlist` policy at A: a non-member hint is denied; the allowlisted member is admitted
//!   (proceeds past the policy check — proven by a DISTINCT error code, `fed_unreachable`, from a
//!   deliberately dead dial target, never `fed_denied`)
//! - **the load-bearing test**: zero DNS lookup and zero TCP connect on denial — a real
//!   `TcpListener` is bound at the would-be dial endpoint and proven to never receive an `accept`,
//!   and a call-counting [`Discovery`] stand-in is proven to receive zero `resolve` calls,
//!   through the exact same `Discovery` trait seam `federation::outbound` itself consults.
//!
//! ## Harness
//! Reuses this crate's established two-real-server-over-real-mTLS pattern
//! (`federation_fetch.rs`/`federation_route.rs`/`federation_abuse.rs`, code-reviewer-accepted
//! per-file duplication rather than a shared `tests/support` module) for the wire-level
//! (`fed_denied`) cases, plus a direct call into `federation::outbound` (both are `pub`) for the
//! zero-I/O proof, which needs to install a call-counting [`Discovery`] into a running
//! [`AppState`] — something only reachable by constructing the state directly, not through the
//! config-driven [`AppState::new`] alone.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use meridian_identity::{generate_account, KeyHandle, MemorySecretStore};
use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::federation::outbound::{
    fetch_foreign_bundle, route_foreign, FetchForeignError, RouteForeignError,
};
use meridian_rendezvous::federation::{Discovery, DiscoveryError, Endpoint};
use meridian_rendezvous::{serve, AppState, MemoryStore};
use meridian_signaling::{SignalError, SignalingClient};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;

// -- PKI test harness (mirrors federation_fetch.rs / federation_route.rs / federation_abuse.rs) --

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

// -- Server harness ----------------------------------------------------------------------------

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

struct Acct {
    store: MemorySecretStore,
    pubkey: [u8; 32],
    handle: KeyHandle,
}

fn new_acct(hint: &str) -> Acct {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, hint).unwrap();
    Acct {
        pubkey: *account.public_key().as_bytes(),
        handle: account.handle().clone(),
        store,
    }
}

impl Acct {
    async fn connect(&self, url: &str) -> Result<SignalingClient, SignalError> {
        SignalingClient::connect(url, &self.store, &self.handle, self.pubkey, None, 1).await
    }
}

/// Build a `federation_map.toml` (private-CA mode, task 2.5's schema) pointing `domain` at `addr`.
fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> std::path::PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// Build A's [`Federation`] config: `enabled = true`, `discovery = "static"`, a map entry pointing
/// `b_domain` at `b_fed_addr`, and A's own admission `policy` — the axis this task adds
/// enforcement for, so every test here sets it explicitly rather than relying on
/// [`Federation::default`]'s fail-closed `Closed`.
fn org_a_federation(
    dir: &Path,
    ca: &TestCa,
    a_domain: &str,
    b_domain: &str,
    b_fed_addr: SocketAddr,
    policy: FederationPolicyMode,
    allowlist: Vec<String>,
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
        policy,
        allowlist,
        ..Federation::default()
    }
}

/// B's own federation identity — B's policy is always `open`; every test in this file exercises
/// A's OWN outbound admission decision, never B's inbound one (that's `federation_fetch.rs`'s/
/// `federation_route.rs`'s `closed_policy_at_b_is_reported_as_fed_denied`, already-correct and out
/// of this task's scope). Several tests below expect the request to be refused by A before it ever
/// reaches B at all — a B that would happily admit anything makes that refusal unambiguously A's.
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

/// Stand up B (accepting, `open`) + A (dialing out, with the given outbound `policy`), returning
/// A's c2s URL — the common setup for the wire-level (`fed_denied`) cases below.
async fn stand_up(
    policy: FederationPolicyMode,
    allowlist: Vec<String>,
) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let b_config_federation = org_b_federation(dir.path(), &ca, "org-b.test");
    let mut b_config = base_config("org-b.test");
    b_config.federation = b_config_federation;
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state).await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        b_fed_addr,
        policy,
        allowlist,
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    (a_c2s_url, dir)
}

// -- 1: closed policy at A + outbound Fetch{hint} -> fed_denied ---------------------------------

#[tokio::test]
async fn closed_policy_at_a_denies_outbound_fetch() {
    let (a_c2s_url, _dir) = stand_up(FederationPolicyMode::Closed, Vec::new()).await;

    let alice = new_acct("org-a.test");
    let target = [0x42u8; 32]; // irrelevant — A refuses to even dial, on policy alone
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedDenied, got {other:?}"),
    }
}

// -- 2: closed policy at A + outbound Route{to_hint} -> fed_denied ------------------------------

#[tokio::test]
async fn closed_policy_at_a_denies_outbound_route() {
    let (a_c2s_url, _dir) = stand_up(FederationPolicyMode::Closed, Vec::new()).await;

    let alice = new_acct("org-a.test");
    let target = [0x43u8; 32];
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .route_with_hint(target, Some("org-b.test".to_string()), b"hi bob".to_vec())
        .await
        .unwrap_err();
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedDenied, got {other:?}"),
    }
}

// -- 3: allowlist policy at A: non-member denied, member admitted -------------------------------

#[tokio::test]
async fn allowlist_policy_at_a_denies_a_non_member_domain() {
    // A's allowlist names some OTHER domain, never "org-b.test" — the fetch must be denied before
    // ever reaching B, exactly as under `closed`.
    let (a_c2s_url, _dir) = stand_up(
        FederationPolicyMode::Allowlist,
        vec!["not-org-b.test".to_string()],
    )
    .await;

    let alice = new_acct("org-a.test");
    let target = [0x44u8; 32];
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedDenied, got {other:?}"),
    }
}

/// The allowlisted member is ADMITTED — i.e. proceeds past the policy choke point. Proven by a
/// deliberately dead dial target: `org-b.test` is on A's allowlist but the map entry points at a
/// `SocketAddr` nothing is listening on (bound, then immediately dropped), so a request that
/// cleared the policy check but then genuinely failed to dial comes back `fed_unreachable` — a
/// DIFFERENT client-visible code from `fed_denied`. If admission were wrongly still rejecting this
/// domain, the outcome would be `fed_denied` instead; getting `fed_unreachable` is the proof the
/// policy check let it through.
#[tokio::test]
async fn allowlist_policy_at_a_admits_the_listed_domain_and_proceeds_past_the_policy_check() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        dead_addr,
        FederationPolicyMode::Allowlist,
        vec!["org-b.test".to_string()],
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let target = [0x45u8; 32];
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::FedUnreachable { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!(
            "expected FedUnreachable (proving the allowlist admitted this domain and the dial \
             attempt itself is what failed, against the deliberately dead address), got {other:?}"
        ),
    }
}

// -- 4: the load-bearing test — zero DNS lookup and zero TCP connect on denial ------------------

/// A [`Discovery`] stand-in that counts every `resolve` call and, if ever actually called, hands
/// back a real endpoint pointing at this test's own `TcpListener` — so if the policy choke point
/// were ever bypassed, this test would not just observe a nonzero call count but a REAL accepted
/// TCP connection at the listener below, the strongest available proof this is not a vacuous count.
struct CountingDiscovery {
    calls: Arc<AtomicUsize>,
    endpoint: Endpoint,
}

#[async_trait]
impl Discovery for CountingDiscovery {
    async fn resolve(&self, _domain: &str) -> Result<Vec<Endpoint>, DiscoveryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![self.endpoint.clone()])
    }
}

/// Installs `discovery` into a freshly-built (not yet cloned/spawned) [`AppState`], via
/// `Arc::get_mut` — the only way to reach `FederationRuntime::discovery` with a test-controlled
/// [`Discovery`] impl, since [`AppState::new`] always builds a config-driven one internally. Must
/// be called before the returned `Arc` is cloned anywhere (no live listener spawned on it yet).
fn install_discovery(state: &mut Arc<AppState>, discovery: Arc<dyn Discovery>) {
    Arc::get_mut(state)
        .expect("AppState must still be uniquely owned (not yet cloned/spawned)")
        .federation
        .discovery = Some(discovery);
}

#[tokio::test]
async fn closed_policy_denial_makes_zero_dns_lookups_and_zero_tcp_connects() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    // A real listener at the address `CountingDiscovery` would resolve "org-b.test" to, so a
    // dial-attempt regression is provable at the TCP layer, not just via the call counter.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted_writer = accepted.clone();
    tokio::spawn(async move {
        // If `dial_foreign` ever regresses and actually connects here, this resolves and flips the
        // flag; if the policy check correctly short-circuits before any dial, this task just waits
        // forever (harmlessly dropped at process exit) and the flag stays false.
        if listener.accept().await.is_ok() {
            accepted_writer.store(true, Ordering::SeqCst);
        }
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let counting_discovery = Arc::new(CountingDiscovery {
        calls: calls.clone(),
        endpoint: Endpoint {
            host: listener_addr.ip().to_string(),
            port: listener_addr.port(),
            priority: 0,
            weight: 0,
            pinned_identity: None,
            policy: None,
        },
    });

    let id = mint_identity(dir.path(), "a", "org-a.test", &ca);
    let mut a_config = base_config("org-a.test");
    a_config.federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        // `StaticMap::load` would fail-closed on this nonexistent path — irrelevant here, since
        // `install_discovery` below replaces the config-driven discovery entirely before it is
        // ever consulted (the policy check aborts before that point is even reached).
        map_path: dir.path().join("unused.toml").to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Closed,
        ..Federation::default()
    };
    std::fs::write(dir.path().join("unused.toml"), "").unwrap();
    let a_store = Arc::new(MemoryStore::new());
    let mut a_state = AppState::new(a_config, a_store);
    install_discovery(&mut a_state, counting_discovery);

    let target = [0x46u8; 32];
    let fetch_err = fetch_foreign_bundle(&a_state, "org-b.test", target)
        .await
        .expect_err("closed policy must deny the fetch");
    assert!(
        matches!(fetch_err, FetchForeignError::Denied),
        "expected FetchForeignError::Denied, got {fetch_err:?}"
    );

    let route_err = route_foreign(&a_state, "org-b.test", target, [0x47u8; 32], b"hi".to_vec())
        .await
        .expect_err("closed policy must deny the route");
    assert!(
        matches!(route_err, RouteForeignError::Denied),
        "expected RouteForeignError::Denied, got {route_err:?}"
    );

    // Give any wrongly-fired background dial attempt a generous window to show up before we check.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the policy choke point must reject before `Discovery::resolve` is ever called — a \
         nonzero count here means dial_foreign performed a DNS-shaped lookup for a domain its own \
         policy had already refused, exactly the oracle this task closes"
    );
    assert!(
        !accepted.load(Ordering::SeqCst),
        "the policy choke point must reject before any TCP dial — the listener at the would-be \
         endpoint must never see an accepted connection when policy denies the domain"
    );
}

/// Regression (code-review finding on this task): federation simply being switched off
/// (`Federation::default()` — `enabled: false`, `discovery: None`, `policy: Closed`) must report
/// `NotConfigured`/`fed_unreachable` on BOTH outbound entry points, not `Denied`/`fed_denied` on
/// one and `NotConfigured` on the other. `dial_foreign` checks `discovery.is_none()` before the
/// policy choke point precisely so `fetch_foreign_bundle` (which has no guard of its own) agrees
/// with `route_foreign` (which has its own early `discovery.is_none()` guard ahead of
/// `dial_foreign`) about which error wins when there is no policy decision to report at all — a
/// server that hasn't turned federation on has made no domain-specific admission decision.
#[tokio::test]
async fn disabled_federation_is_not_configured_not_denied_on_either_path() {
    let a_config = base_config("org-a.test");
    assert!(
        !a_config.federation.enabled,
        "sanity: default federation is disabled"
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);

    let target = [0x48u8; 32];
    let fetch_err = fetch_foreign_bundle(&a_state, "org-b.test", target)
        .await
        .expect_err("disabled federation must refuse the fetch");
    assert!(
        matches!(fetch_err, FetchForeignError::NotConfigured),
        "expected FetchForeignError::NotConfigured, got {fetch_err:?}"
    );

    let route_err = route_foreign(&a_state, "org-b.test", target, [0x49u8; 32], b"hi".to_vec())
        .await
        .expect_err("disabled federation must refuse the route");
    assert!(
        matches!(route_err, RouteForeignError::NotConfigured),
        "expected RouteForeignError::NotConfigured, got {route_err:?}"
    );
}
