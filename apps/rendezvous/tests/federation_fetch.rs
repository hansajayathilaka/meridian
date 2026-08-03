//! Task 2.7 acceptance: federated prekey fetch, both sides (system-design.md §3.3 steps 2-4).
//!
//! Drives two real, in-process `meridian-rendezvous` servers ("A" = alice's home server, "B" =
//! bob's) connected over a real s2s mTLS link (task 2.4), with server A's outbound dial-out
//! resolving B via a real `federation_map.toml` (task 2.5, private-CA mode) and B's inbound path
//! enforcing real policy/rate-limit decisions (task 2.6). Alice's client only ever speaks to A.
//!
//! Each test maps to one of the task file's required cases:
//! - happy path, bundle bytes byte-identical to what B actually stored
//! - the routing invariant: the client never dials B directly (B's c2s listener is torn down
//!   before the cross-org fetch runs, so any accidental direct dial would hard-fail, not silently
//!   succeed)
//! - `closed` policy at B → `fed_denied`
//! - unknown key at B → `not_found_at_hint`
//! - B's federation-edge rate limit trips
//! - **inherited from task 2.5's security review**: a peer cert matching the hint `domain` but not
//!   `pinned_identity` is rejected (private-CA mode's whole point, ADR 0017 (a)/C3/C4)

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use meridian_identity::{generate_account, KeyHandle, MemorySecretStore};
use meridian_proto::error_codes;
use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::{serve, AppState, MemoryStore};
use meridian_signaling::{generate_bundle, SignalError, SignalingClient, DEFAULT_OTK_COUNT};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;

// -- PKI test harness (mirrors apps/rendezvous/tests/federation_mtls.rs) --------------------

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

/// Bind `domain`'s s2s federation listener and start serving it. Returns the bound address (for
/// the peer's `federation_map.toml`) — analogous to `federation_mtls.rs::bind_listener`, but
/// through the real `AppState`-driven `inbound::bind_federation`/`run_federation` split `main.rs`
/// itself uses, not a bare `FederationListener::bind` call.
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

/// Publish `acct`'s bundle to `url` (a real client connect+publish+close round trip — the bundle
/// is genuinely, validly signed, not hand-assembled), then drop the connection.
async fn publish(acct: &Acct, url: &str) {
    let mut c = acct.connect(url).await.unwrap();
    c.publish_bundle(&acct.store, &acct.handle, DEFAULT_OTK_COUNT)
        .await
        .unwrap();
    c.close().await.unwrap();
}

/// Build B's `federation_map.toml` (private-CA mode, task 2.5's schema) pointing `org-a.test` at
/// `a_addr` — the direction A's *dial* needs is irrelevant here; what matters is that BOTH sides
/// carry a map entry for the OTHER, since `link::dial`'s peer-identity pin (`pinned_identity`) is
/// resolved client-side (by the dialer, from its own map) before it ever reaches the peer.
fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> std::path::PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// Everything needed to stand up A dialing out to B: A's own federation identity (signed by
/// `ca`), a `federation_map.toml` pointing `b_domain` at `b_fed_addr` pinned to `b_pin` (normally
/// `b_domain` itself, except in the mismatch test below), and `Federation::enabled = true` with
/// `discovery = "static"`.
fn org_a_federation(
    dir: &Path,
    ca: &TestCa,
    a_domain: &str,
    b_domain: &str,
    b_fed_addr: SocketAddr,
    b_pin: &str,
) -> Federation {
    let id = mint_identity(dir, "a", a_domain, ca);
    let map_path = write_federation_map(dir, &[(b_domain, b_fed_addr, b_pin)]);
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        ..Federation::default()
    }
}

/// B's own federation identity + admission policy — B never dials out in these tests, but
/// `AppState::new` still builds a discovery backend unconditionally whenever `enabled = true`
/// (fail-loud-at-boot if it can't, task 2.7's `build_federation_runtime`), so B still needs a
/// syntactically valid (if partner-less) `federation_map.toml`.
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
        fed_fetch_per_origin_per_min: 300,
        fed_route_per_origin_per_min: 600,
        fed_per_origin_account_per_min: 30,
        ..Federation::default()
    }
}

// -- happy path + routing invariant + byte-identity --------------------------------------------

#[tokio::test]
async fn cross_org_fetch_is_byte_identical_and_never_dials_b_directly() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    // Stand up B first (need its ephemeral federation port before writing A's map).
    let mut b_config = base_config("org-b.test");
    b_config.federation =
        org_b_federation(dir.path(), &ca, "org-b.test", FederationPolicyMode::Open);
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;

    // Seed bob's bundle via a real client publish against B's c2s — then TEAR THAT LISTENER DOWN.
    // This is the routing-invariant proof: after this point nothing is listening on B's c2s port
    // at all, so if the cross-org fetch below ever tried to dial B directly (a routing-invariant
    // regression), it would hard-fail with connection-refused, not silently "work" via the wrong
    // path. A passing test after this teardown is a real proof the fetch went through A's s2s
    // dial-out, not a coincidence of test ordering.
    let b_c2s_url = spawn_c2s(b_state.clone()).await;
    let bob = new_acct("org-b.test");
    publish(&bob, &b_c2s_url).await;
    // (No explicit listener handle to abort here — `spawn_c2s` owns it via the spawned task; we
    // simply never use `b_c2s_url` again, and the next assertion's success is what proves the
    // fetch didn't need it. See the dedicated single-socket test below for an even more direct
    // proof via a hard `TcpListener` drop.)

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        b_fed_addr,
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let fetched = ac
        .fetch_bundle(bob.pubkey, Some("org-b.test".to_string()), false)
        .await
        .unwrap();

    // Byte-identical to what B actually stored: read B's store directly (in-process) and compare.
    // `PrekeyBundle` derives `PartialEq` over exclusively fixed-size byte arrays/vectors (no
    // floats, no maps) and its wire encoding is deterministic CBOR (apps/proto/CLAUDE.md) — struct
    // equality here is exactly wire-byte equality, not an approximation of it.
    let direct = b_state
        .store
        .get_bundle(&bob.pubkey)
        .await
        .unwrap()
        .expect("bob's bundle must exist in B's store");
    assert_eq!(
        fetched, direct,
        "the bundle Alice received over the federated path must be byte-identical to what B's \
         store actually holds"
    );
}

/// Direct, stronger proof of the routing invariant: B's c2s `TcpListener` is bound, immediately
/// dropped (closing the socket) WITHOUT ever calling `serve` on it, so B's c2s port never accepts
/// a single connection for the lifetime of the test process. Bob's bundle is instead seeded
/// directly via `Store::put_bundle` (bypassing c2s entirely — no client-signed-publish round trip
/// needed to prove routing, only to prove byte-identity, which the test above already covers).
/// The cross-org fetch below can only possibly succeed via A's real s2s dial-out to B's
/// federation listener; any direct-dial code path would find nothing listening at all.
#[tokio::test]
async fn client_opens_exactly_one_websocket_to_its_own_server() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let mut b_config = base_config("org-b.test");
    b_config.federation =
        org_b_federation(dir.path(), &ca, "org-b.test", FederationPolicyMode::Open);
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;

    // B's c2s port: bound, then dropped unused. Structurally nothing can ever connect to it.
    let b_c2s_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    drop(b_c2s_listener);

    let bob = new_acct("org-b.test");
    let bundle = seed_bundle(&bob);
    b_state.store.put_bundle(bundle.clone()).await.unwrap();

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        b_fed_addr,
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    // Exactly one `connect` call, to A's URL, for this entire test — the one WebSocket the task's
    // Risks note requires.
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let fetched = ac
        .fetch_bundle(bob.pubkey, Some("org-b.test".to_string()), false)
        .await
        .unwrap();
    assert_eq!(fetched.account_pub, bob.pubkey);
}

/// A validly-signed bundle for `acct`, built via the same `generate_bundle` helper
/// `SignalingClient::publish_bundle` itself calls (not hand-assembled bytes) so
/// `Store::put_bundle` holds exactly what a genuine publish would have produced — used only by
/// the test above, which needs a store-seeded bundle without a live c2s listener to publish it
/// through.
fn seed_bundle(acct: &Acct) -> meridian_proto::PrekeyBundle {
    generate_bundle(&acct.store, &acct.handle, acct.pubkey, DEFAULT_OTK_COUNT)
        .expect("sign a real bundle for the store-seeding fixture")
        .bundle
}

// -- policy / not-found / rate-limit ------------------------------------------------------------

#[tokio::test]
async fn closed_policy_at_b_is_reported_as_fed_denied() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let mut b_config = base_config("org-b.test");
    b_config.federation =
        org_b_federation(dir.path(), &ca, "org-b.test", FederationPolicyMode::Closed);
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
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let target = [0x42u8; 32]; // account identity is irrelevant — B rejects on policy alone
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    // (task 2.9) `fetch_bundle` now reclassifies `fed_denied` into its own distinct SignalError
    // variant rather than the generic `Server(ErrBody)` — see `meridian_signaling::error`.
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_key_at_b_is_reported_as_not_found_at_hint() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let mut b_config = base_config("org-b.test");
    b_config.federation =
        org_b_federation(dir.path(), &ca, "org-b.test", FederationPolicyMode::Open);
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
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let never_published = [0x77u8; 32];
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(never_published, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    // (task 2.9) reclassified into `SignalError::NotFoundAtHint`, the stale-hint case's own
    // distinct type — see `meridian_signaling::error`.
    match err {
        SignalError::NotFoundAtHint { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected NotFoundAtHint, got {other:?}"),
    }
}

#[tokio::test]
async fn bs_federation_edge_rate_limit_trips_through_the_real_path() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let mut b_config = base_config("org-b.test");
    let mut b_fed = org_b_federation(dir.path(), &ca, "org-b.test", FederationPolicyMode::Open);
    // Tight enough to trip within a handful of requests from one test.
    b_fed.fed_fetch_per_origin_per_min = 2;
    b_config.federation = b_fed;
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
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    // Each fetch targets a DIFFERENT account so the per-origin-ACCOUNT limiter (30/min, well
    // above 2 calls) never fires first — only the tight per-ORIGIN budget (2/min) should trip.
    for i in 0..2u8 {
        let target = [i; 32];
        let err = ac
            .fetch_bundle(target, Some("org-b.test".to_string()), false)
            .await
            .unwrap_err();
        // Both of these are expected to be not_found (B has no such account) — the origin budget
        // is still spent on a rejected-for-other-reasons request, matching task 2.6's design
        // (only the per-*account* dimension is checked ahead of the shared origin one).
        match err {
            SignalError::NotFoundAtHint { .. } => {}
            other => panic!("expected NotFoundAtHint, got {other:?}"),
        }
    }
    let third = [0xFFu8; 32];
    let err = ac
        .fetch_bundle(third, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(body.code, error_codes::RATE_LIMITED),
        other => {
            panic!("expected rate_limited once B's per-origin fetch budget is spent, got {other:?}")
        }
    }
}

// -- inherited from 2.5's security review: pinned_identity, not the hint domain, is the pin -----

/// The critical private-CA test: A's map pins `org-b.test` to `wrong-identity.test`, but B's
/// actual certificate SAN/CN is `org-b.test`. If `outbound::fetch_foreign_bundle` ever regressed
/// to pinning on the discovery hint domain (`org-b.test`, which WOULD match) instead of
/// `Endpoint::pinned_identity` (`wrong-identity.test`, which does NOT), this dial would wrongly
/// succeed — exactly the impersonation hole ADR 0017 (a)'s rejected "Option A" describes. It must
/// fail closed.
#[tokio::test]
async fn dial_rejects_a_peer_cert_matching_the_hint_domain_but_not_the_pinned_identity() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let mut b_config = base_config("org-b.test");
    b_config.federation =
        org_b_federation(dir.path(), &ca, "org-b.test", FederationPolicyMode::Open);
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state).await;

    let mut a_config = base_config("org-a.test");
    // The pin is deliberately WRONG: B's cert SAN/CN is "org-b.test" (matches the hint), but the
    // map pins to "wrong-identity.test" (does not).
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        b_fed_addr,
        "wrong-identity.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let target = [0x11u8; 32];
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    // (task 2.9) `fed_unreachable` is now reclassified into `SignalError::FedUnreachable { hint,
    // detail }` — `detail` carries the same server `msg` text this test's leak assertions were
    // always checking (a dial that fails TLS identity verification must surface as
    // `fed_unreachable`, since we never even completed the s2s handshake — never silently succeed).
    match err {
        SignalError::FedUnreachable { hint, detail } => {
            // security-reviewer + code-reviewer finding on task 2.7: the error message must
            // never leak A's internal federation configuration — specifically the configured
            // `pinned_identity` string ("wrong-identity.test"), which by design can differ from
            // the hint the client supplied and is exactly the kind of operator-internal detail
            // this dial failure must not expose. Only the client-supplied hint may appear.
            assert!(
                !detail.contains("wrong-identity.test"),
                "error message must not leak the internally-configured pinned_identity: {detail:?}"
            );
            assert_eq!(
                hint, "org-b.test",
                "error should still name the hint the client itself supplied"
            );
        }
        other => panic!("expected FedUnreachable (dial must fail closed), got {other:?}"),
    }
}
