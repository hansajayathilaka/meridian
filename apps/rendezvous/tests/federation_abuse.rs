//! Task 2.12 — the phase-2 exit gate: Feature 06's cross-org abuse acceptance criteria, turned
//! into executable, CI-wired tests (docs/architecture/features/06-cross-org-federation.md's
//! "Acceptance criteria" + "Abuse tests" deliverable).
//!
//! Reuses the real two-real-server-over-real-mTLS harness `federation_fetch.rs`/
//! `federation_route.rs` (tasks 2.7/2.8) already established — this crate's existing duplication
//! convention (code-reviewer-accepted on 2.7) rather than factoring out a shared `tests/support`
//! module. Each test maps to one Feature-06 acceptance criterion not already pinned elsewhere in
//! this crate's test suite:
//! - **rate-limit enforcement** on the *route* dimension (task 2.6/2.8) — `federation_fetch.rs`
//!   already covers the *fetch* dimension; this file closes the route-side gap.
//! - **allowlist rejection specifically** (not just `closed`, which `federation_fetch.rs`/
//!   `federation_route.rs` already cover) — a non-allowlisted origin under `policy = "allowlist"`.
//! - **oversized-envelope rejection**, restated here so the full abuse suite is discoverable from
//!   one file (federation_route.rs owns the detailed pre-dial/defense-in-depth split; this is the
//!   acceptance-level restatement the task file calls for).
//! - **the A2×2 cross-org malicious-server bundle-substitution test**: Org B's server lies about
//!   the requested identity's prekey bundle over the federated fetch path (the new
//!   `test-tamper-hook` extension, task 2.12 deliverable 1) — Alice's client (via Org A) must
//!   abort via its own `verify_bundle` check, exactly as the single-hop version already does
//!   (`apps/rendezvous/tests/rendezvous.rs::tampered_bundle_is_rejected`), pinned to
//!   `SignalError::BundleVerification` specifically (never a generic catch-all), mirroring how
//!   1.28/1.32 pin outcomes to a specific variant on a specific side.
//! - **F17 structural inertness** of the new federated tamper hook: without the
//!   `test-tamper-hook` cargo feature, even `allow_test_tamper = true` at B must leave the
//!   federated fetch reply byte-identical to what B's store actually holds — see this file's CI
//!   note below on why that assertion needs its own package-scoped, default-features CI step.
//!
//! ## The 1.28/1.32 resolver-2 trap, applied to federation
//! Exactly as `apps/rendezvous/tests/rendezvous.rs` documents: resolver-2 feature unification turns
//! `test-tamper-hook` ON workspace-wide whenever a dev target (e.g. `apps/cli`, whose
//! dev-dependency on `meridian-rendezvous` pins the feature) is built — so a `#[cfg(not(feature =
//! "test-tamper-hook"))]` guard in THIS file would be silently compiled out under `cargo test
//! --workspace`, and the only invocation under which it (and the feature-ON cell next to it)
//! genuinely execute is the existing package-scoped CI steps (`cargo test -p meridian-rendezvous`
//! / `cargo test -p meridian-rendezvous --features test-tamper-hook`) — both already exist (task
//! 1.28/1.32) and, being package-scoped with no `--test` filter, automatically pick up this new
//! test binary with no CI edit required. See `.github/workflows/ci.yml`'s "Tamper-hook" steps.

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
use meridian_signaling::{SignalError, SignalingClient};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;

// -- PKI test harness (mirrors federation_fetch.rs / federation_route.rs / federation_mtls.rs) ---

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

fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> std::path::PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// A dials out to B: A's own federation identity, a `federation_map.toml` pointing `b_domain` at
/// `b_fed_addr` pinned to `b_domain` itself, `Federation::enabled = true`, `discovery = "static"`.
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
        // (task 3.1) `Federation::default`'s `policy` is `Closed` — the fail-closed default. This
        // file's tests exercise B's abuse-handling behavior (rate limits/allowlist/tamper), not
        // A's own outbound admission decision (dedicated coverage: `federation_outbound_policy.rs`),
        // so A itself must be willing to dial `b_domain` at all for any of them to reach B.
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    }
}

/// B's own federation identity + admission policy/limits — B never dials out in these tests.
#[allow(clippy::too_many_arguments)]
fn org_b_federation(
    dir: &Path,
    ca: &TestCa,
    b_domain: &str,
    policy: FederationPolicyMode,
    allowlist: Vec<String>,
    fed_fetch_per_origin_per_min: u32,
    fed_route_per_origin_per_min: u32,
    fed_per_origin_account_per_min: u32,
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
        allowlist,
        fed_fetch_per_origin_per_min,
        fed_route_per_origin_per_min,
        fed_per_origin_account_per_min,
        ..Federation::default()
    }
}

/// Stand up A (dialing out) + B (accepting), returning both `AppState`s and both c2s URLs.
struct Rig {
    // Only read directly by the tamper-hook cell below (`#[cfg(feature = "test-tamper-hook")]`),
    // to reach into B's store and prove the substitution left the store itself untouched.
    #[cfg_attr(not(feature = "test-tamper-hook"), allow(dead_code))]
    b_state: Arc<AppState>,
    a_c2s_url: String,
    b_c2s_url: String,
    _dir: tempfile::TempDir,
}

#[allow(clippy::too_many_arguments)]
async fn stand_up(
    b_policy: FederationPolicyMode,
    b_allowlist: Vec<String>,
    fed_fetch_per_origin_per_min: u32,
    fed_route_per_origin_per_min: u32,
    fed_per_origin_account_per_min: u32,
    arm_b_test_tamper: bool,
) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");

    let mut b_config = base_config("org-b.test");
    b_config.federation = org_b_federation(
        dir.path(),
        &ca,
        "org-b.test",
        b_policy,
        b_allowlist,
        fed_fetch_per_origin_per_min,
        fed_route_per_origin_per_min,
        fed_per_origin_account_per_min,
    );
    b_config.server.allow_test_tamper = arm_b_test_tamper;
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;
    let b_c2s_url = spawn_c2s(b_state.clone()).await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(dir.path(), &ca, "org-a.test", "org-b.test", b_fed_addr);
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    Rig {
        b_state,
        a_c2s_url,
        b_c2s_url,
        _dir: dir,
    }
}

// -- rate-limit enforcement: the ROUTE dimension (2.6/2.8) --------------------------------------
//
// `federation_fetch.rs::bs_federation_edge_rate_limit_trips_through_the_real_path` already proves
// this for FETCH. Nothing in this crate's existing suite drives the identical property for ROUTE
// through the real wire path — this closes that gap, which is exactly what Feature 06's "abuse
// tests: rate-limit enforcement" criterion asks for.

#[tokio::test]
async fn bs_federation_route_rate_limit_trips_through_the_real_path() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 2, 30, false).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();

    // The per-origin-ACCOUNT limiter keys on the SENDER's account (`req.from` — Alice, constant
    // across all three calls here, per `apps/rendezvous/src/federation/inbound.rs`), never the
    // route's target, so varying the target below doesn't affect which limiter trips — it's set
    // high enough (30/min) relative to the tight per-ORIGIN route budget (2/min) that the origin
    // budget trips first regardless. None of these targets are connected at B, so each
    // individually would be `not_connected`; what this test proves is that the THIRD one is
    // `rate_limited` instead, i.e. the origin budget (not the account budget, and not a
    // coincidental not-connected error) is what trips.
    for i in 0..2u8 {
        let target = [i; 32];
        let err = ac
            .route_with_hint(target, Some("org-b.test".to_string()), b"hi".to_vec())
            .await
            .unwrap_err();
        match err {
            SignalError::Server(body) => assert_eq!(body.code, error_codes::NOT_CONNECTED),
            other => panic!("expected not_connected (target simply isn't online), got {other:?}"),
        }
    }
    let third = [0xFFu8; 32];
    let err = ac
        .route_with_hint(third, Some("org-b.test".to_string()), b"hi".to_vec())
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(
            body.code,
            error_codes::RATE_LIMITED,
            "once B's per-origin ROUTE budget (2/min) is spent, a third distinct-target route \
             must be rejected as rate_limited, not not_connected"
        ),
        other => panic!("expected rate_limited, got {other:?}"),
    }
}

// -- allowlist rejection, specifically (not just `closed`) --------------------------------------
//
// `federation_fetch.rs`/`federation_route.rs` already cover `policy = "closed"`. Feature 06's
// acceptance criterion separately names "a closed-policy org rejects inbound federation" but the
// abuse-test deliverable also names "allowlist rejection" as its own criterion — a domain that is
// simply NOT on the allowlist (as opposed to policy being closed outright) must fail the same way.

#[tokio::test]
async fn allowlist_policy_rejects_a_non_allowlisted_origin_as_fed_denied() {
    // B's allowlist deliberately does NOT include "org-a.test" — some other domain instead, so
    // this is a genuine allowlist MISS, not an empty (vacuously-rejects-everything) allowlist.
    let rig = stand_up(
        FederationPolicyMode::Allowlist,
        vec!["org-c.test".to_string()],
        300,
        600,
        30,
        false,
    )
    .await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let target = [0x22u8; 32]; // identity is irrelevant — B rejects on policy alone
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!(
            "a domain absent from B's allowlist must be rejected exactly like `closed` (a clean, \
             client-visible fed_denied) — got {other:?}"
        ),
    }
}

#[tokio::test]
async fn allowlist_policy_admits_the_listed_origin() {
    // The control: the SAME allowlist policy, with "org-a.test" actually present, must NOT reject
    // — proving the cell above is measuring the allowlist-miss specifically, not "allowlist mode
    // rejects everything unconditionally."
    let rig = stand_up(
        FederationPolicyMode::Allowlist,
        vec!["org-a.test".to_string()],
        300,
        600,
        30,
        false,
    )
    .await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let target = [0x22u8; 32];
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    // Not present at B, but NOT a policy rejection: proves the allowlisted domain was admitted and
    // the request reached the store lookup.
    match err {
        SignalError::NotFoundAtHint { .. } => {}
        other => panic!(
            "an allowlisted origin must be admitted past the policy check (rejected only for \
             lacking the target, not for policy) — got {other:?}"
        ),
    }
}

// -- oversized-envelope rejection (acceptance-level restatement) ---------------------------------
//
// `federation_route.rs` owns the detailed pre-dial/defense-in-depth split; this is the
// acceptance-level cell Feature 06's own "abuse tests" deliverable names directly, kept here so
// the whole abuse suite is discoverable from one file.

#[tokio::test]
async fn oversized_envelope_is_rejected_cross_org() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, false).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let oversized = vec![0x41u8; 2 * 1024 * 1024]; // 2 MiB, well over MAX_FRAME_LEN (1 MiB)
    let target = [0x33u8; 32];
    let err = ac
        .route_with_hint(target, Some("org-b.test".to_string()), oversized)
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(body.code, error_codes::BAD_REQUEST),
        other => panic!("expected bad_request for an oversized cross-org envelope, got {other:?}"),
    }
}

// -- A2×2: cross-org malicious-server bundle substitution (task 2.12 deliverable 1) -------------
//
// Org B's server lies to Org A about the requested identity's prekey bundle over the FEDERATED
// fetch path — the cross-org analogue of `rendezvous.rs::tampered_bundle_is_rejected`. Alice's
// client (talking only to Org A) must abort via its OWN `verify_bundle` check
// (`meridian-signaling::bundle::verify_bundle`, applied identically to a local or federated
// fetch reply — see `SignalingClient::fetch_bundle`'s doc comment) even though B actively tried to
// substitute. Pinned to `SignalError::BundleVerification` specifically, never a generic
// `unwrap_err()`/catch-all, mirroring 1.28/1.32's "pin the specific variant on the specific side"
// discipline.

#[cfg(feature = "test-tamper-hook")]
#[tokio::test]
async fn cross_org_malicious_server_bundle_substitution_is_rejected_by_the_client() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, true).await;

    // Bob's REAL bundle is published at B — the tamper hook substitutes a DIFFERENT bundle in the
    // fed_fetch_bundle reply, so this test also proves the substitution is B lying about a real,
    // existing identity, not merely reporting "not found" under a different guise.
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();
    bc.publish_bundle(
        &bob.store,
        &bob.handle,
        meridian_signaling::DEFAULT_OTK_COUNT,
    )
    .await
    .unwrap();

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(bob.pubkey, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::BundleVerification(_) => {}
        other => panic!(
            "a bundle substituted by a malicious FOREIGN server must be rejected by the client's \
             OWN verify_bundle check with SignalError::BundleVerification specifically — anything \
             else (including a bare unwrap_err on some other variant) does not prove the client-side \
             trust anchor actually fired. Got: {other:?}"
        ),
    }

    // Non-vacuity / direct proof the substitution actually happened, not merely that SOME error
    // fired: read B's own store directly and confirm the (real, untampered) bundle held there is
    // for Bob's real key — the client's rejection above is therefore of a bundle that differs from
    // what the client asked for, not of a store miss.
    let direct = rig
        .b_state
        .store
        .get_bundle(&bob.pubkey)
        .await
        .unwrap()
        .expect("bob's real bundle must exist in B's own store, untouched by the hook");
    assert_eq!(
        direct.account_pub, bob.pubkey,
        "B's own store must still hold the REAL bundle under bob's real key — only the wire reply \
         to A was substituted, proving this is a lying-server attack, not data corruption at rest"
    );
}

/// **F17 structural inertness.** Without the `test-tamper-hook` cargo feature, the substitution
/// code in `federation::inbound::handle_fed_fetch` does not exist at all — so even
/// `allow_test_tamper = true` at B must leave the federated reply byte-identical to what B's own
/// store holds. This is the federated counterpart to
/// `rendezvous.rs::tamper_flag_is_inert_without_feature`.
///
/// NOTE ON CI (see this file's module doc): this guard only runs under
/// `cargo test -p meridian-rendezvous` (default features) — `cargo test --workspace` compiles it
/// out entirely via resolver-2 unification (apps/cli's dev-dependency pins the feature on
/// workspace-wide). That CI step already exists (task 1.28/1.32) and needs no change to pick up
/// this new test binary.
#[cfg(not(feature = "test-tamper-hook"))]
#[tokio::test]
async fn fed_fetch_tamper_flag_is_inert_without_feature() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, true).await;

    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();
    bc.publish_bundle(
        &bob.store,
        &bob.handle,
        meridian_signaling::DEFAULT_OTK_COUNT,
    )
    .await
    .unwrap();

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    // Even with `allow_test_tamper = true` "enabled" at the config layer, the hook doesn't exist
    // in this build at all — the real bundle must come back and pass verification.
    let fetched = ac
        .fetch_bundle(bob.pubkey, Some("org-b.test".to_string()), false)
        .await
        .expect("without the cargo feature, the federated fetch must return bob's REAL bundle");
    assert_eq!(fetched.account_pub, bob.pubkey);
}
