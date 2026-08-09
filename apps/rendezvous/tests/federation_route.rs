//! Task 2.8 acceptance: federated envelope routing + per-request reachability (system-design.md
//! §3.3 step 5, §3.4).
//!
//! Same two-real-server-over-real-mTLS harness as `federation_fetch.rs` (task 2.7) — cert-minting,
//! `spawn_c2s`/`spawn_federation`, `org_a_federation`/`org_b_federation` config builders — copied
//! and adapted per-file (the existing `federation_mtls.rs`/`federation_fetch.rs` duplication
//! convention this crate already established; code-reviewer flagged this as acceptable on 2.7, not
//! something to fix here).
//!
//! Each test maps to one of the task file's required cases:
//! - byte-identical envelope A→B delivery, asserted on the exact bytes Bob's OWN live connection
//!   received (`SignalingClient::next_deliver`'s real WebSocket read), never a re-encode
//! - oversized envelope rejected pre-dial on A (never reaches a dial at all — proven by pointing
//!   the hint at an address nothing is listening on and still getting `bad_request`, not
//!   `fed_unreachable`), and B's defense-in-depth check exercised directly (unreachable through
//!   the wire in-process, since `link::read_frame`'s own cap already rejects an oversized frame
//!   before it's ever decoded — see `inbound::handle_fed_route`'s doc comment)
//! - `closed` policy at B → `fed_denied`
//! - reachability collapses "target never existed at B" and "target existed, now disconnected"
//!   into the identical `not_connected` code and message — no existence oracle
//! - reachability is never logged or persisted (source-level grep, mirrors task 2.6's
//!   `policy_module_introduces_no_unhashed_identifier_logging`)

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use meridian_proto::{error_codes, fed_error_codes, FedRoute, OpaqueBlob};
use meridian_rendezvous::config::{DiscoveryMode, Federation, FederationPolicyMode};
use meridian_rendezvous::federation::inbound::handle_fed_route;
use meridian_rendezvous::federation::{FederationLimits, FederationPolicy};
use meridian_rendezvous::state::Registry;
use meridian_rendezvous::{AppState, MemoryStore};
use meridian_signaling::SignalError;
use tokio::net::TcpListener;

mod support;
use support::{
    base_config, boot_federated_pair, new_acct, spawn_c2s, write_federation_map, FederatedPairOpts,
    TestCa,
};

/// A dials out to B: A's own federation identity, a `federation_map.toml` pointing `b_domain` at
/// `b_fed_addr` pinned to `b_pin`, `Federation::enabled = true`, `discovery = "static"`.
fn org_a_federation(
    dir: &Path,
    ca: &TestCa,
    a_domain: &str,
    b_domain: &str,
    b_fed_addr: SocketAddr,
    b_pin: &str,
) -> Federation {
    let id = ca.issue(dir, a_domain);
    let map_path = write_federation_map(dir, &[(b_domain, b_fed_addr, b_pin)]);
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path_str().to_string(),
        key_path: id.key_path_str().to_string(),
        ca_bundle_path: id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        // (task 3.1) `Federation::default`'s `policy` is `Closed` — the fail-closed default. This
        // module's tests are exercising B's behavior (discovery/dial/policy/rate-limit outcomes AT
        // B), not A's own outbound admission decision (that axis has its own dedicated coverage in
        // `tests/federation_outbound_policy.rs`), so A itself must be willing to dial `b_domain` at
        // all for any of them to reach B in the first place.
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    }
}

/// Stand up A (dialing out) + B (accepting) with B's policy `open` by default, returning both
/// `AppState`s and A's c2s URL — the common setup shared by most of these tests.
struct Rig {
    b_state: Arc<AppState>,
    a_c2s_url: String,
    b_c2s_url: String,
    _dir: tempfile::TempDir,
}

async fn stand_up(policy: FederationPolicyMode) -> Rig {
    let pair = boot_federated_pair(FederatedPairOpts {
        b_policy: policy,
        ..Default::default()
    })
    .await;
    Rig {
        b_state: pair.b_state,
        a_c2s_url: pair.a_c2s_url,
        b_c2s_url: pair
            .b_c2s_url
            .expect("boot_federated_pair spawns B's c2s by default"),
        _dir: pair.dir,
    }
}

// -- byte-identical delivery ---------------------------------------------------------------------

/// The core transport-independence assertion, now covering the s2s hop: Bob's connection to B
/// receives the EXACT bytes Alice handed to `route_with_hint` on A. `bc.next_deliver()` performs a
/// real read off Bob's own live WebSocket (`SignalingClient::recv_frame` → the underlying
/// `tokio-tungstenite` stream) and decodes exactly what arrived; `msg.blob.as_bytes()` is compared
/// directly against the original `Vec<u8>` Alice sent — never a re-encode-and-compare of a value
/// this test already holds.
#[tokio::test]
async fn federated_route_delivers_byte_identical_envelope() {
    let rig = stand_up(FederationPolicyMode::Open).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();

    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    let payload = b"the quick brown fox jumps over the lazy dog, byte for byte".to_vec();
    let delivered = ac
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), payload.clone())
        .await
        .unwrap();
    assert!(
        delivered,
        "route to a connected federated peer must deliver"
    );

    let msg = bc.next_deliver().await.unwrap();
    assert_eq!(
        msg.from, alice.pubkey,
        "Deliver.from must be Alice's key, relayed verbatim across the federation boundary"
    );
    assert_eq!(
        msg.blob.as_bytes(),
        payload.as_slice(),
        "the bytes Bob's own connection actually received must be byte-identical to what Alice \
         sent — this is the transport-independence invariant, now proven across the s2s hop"
    );
}

// -- oversized rejection --------------------------------------------------------------------------

/// A's pre-dial check (architect decision #1) rejects an oversized envelope before ever dialing
/// B. Proven, not merely asserted: the federation map points `org-b.test` at a `SocketAddr`
/// nothing is listening on (bound then immediately dropped), so any actual dial attempt would
/// fail with `fed_unreachable` — a `bad_request` here instead is only possible if A's own
/// pre-dial size check fired first, before any connection was even attempted.
#[tokio::test]
async fn oversized_envelope_is_rejected_before_any_dial() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    // An address nothing is listening on: bind an ephemeral port, then drop the listener.
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
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    // 2 MiB of raw envelope bytes: comfortably over `link::MAX_FRAME_LEN` (1 MiB) regardless of
    // CBOR/frame overhead.
    let oversized = vec![0x41u8; 2 * 1024 * 1024];
    let target = [0x55u8; 32];
    let err = ac
        .route_with_hint(target, Some("org-b.test".to_string()), oversized)
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(
            body.code,
            error_codes::BAD_REQUEST,
            "an oversized envelope must be rejected before any dial is attempted — a dial to \
             this test's deliberately-dead address would surface as fed_unreachable, not \
             bad_request, if the size check ran too late"
        ),
        other => panic!("expected bad_request, got {other:?}"),
    }
}

/// `handle_fed_route`'s own defense-in-depth oversized check (architect decision #1), exercised
/// directly. Unreachable via the normal wire path in this same process: a frame that actually
/// crossed the wire already passed `link::read_frame`'s own `MAX_FRAME_LEN` cap before it was ever
/// decoded into a `FedRoute` at all (see that function's doc comment) — this is B's belt-and-
/// suspenders check for a non-compliant peer, tested the only way it CAN be triggered: calling the
/// handler directly with a hand-built, oversized `FedRoute`.
#[tokio::test]
async fn bs_defense_in_depth_oversized_check_rejects_directly() {
    let registry = Registry::default();
    let policy = FederationPolicy::Open;
    let limits = FederationLimits::new(300, 600, 30);
    let req = FedRoute {
        to: [0x11u8; 32],
        from: [0x22u8; 32],
        envelope: OpaqueBlob::new(vec![0x41u8; 2 * 1024 * 1024]),
    };
    let err = handle_fed_route(&registry, &policy, &limits, "org-a.test", &req)
        .await
        .expect_err("an oversized FedRoute body must be rejected");
    assert_eq!(err.code, fed_error_codes::BAD_REQUEST);
    // The oversized recipient must never have reached the registry (defense-in-depth means the
    // check runs BEFORE delivery, not merely in addition to it).
    assert!(!registry.is_connected(&req.to));
}

// -- closed policy at B ----------------------------------------------------------------------------

#[tokio::test]
async fn closed_policy_at_b_is_reported_as_fed_denied() {
    let rig = stand_up(FederationPolicyMode::Closed).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let target = [0x66u8; 32]; // account identity is irrelevant — B rejects on policy alone
    let err = ac
        .route_with_hint(target, Some("org-b.test".to_string()), b"hi bob".to_vec())
        .await
        .unwrap_err();
    // (task 2.9) `route_with_hint` now reclassifies `fed_denied` into its own distinct
    // `SignalError` variant rather than the generic `Server(ErrBody)` — see
    // `meridian_signaling::error`.
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedDenied, got {other:?}"),
    }
}

// -- reachability: no existence oracle -------------------------------------------------------------

/// The core anti-enumeration assertion (architect decision #3): "target never existed at B" and
/// "target existed at B, now disconnected" must be indistinguishable to Alice — same code, same
/// message. If they diverged even slightly, org A could enumerate which keys have EVER registered
/// at org B, not just which are online right now.
#[tokio::test]
async fn reachability_collapses_unknown_and_known_offline_targets() {
    let rig = stand_up(FederationPolicyMode::Open).await;
    let alice = new_acct("org-a.test");

    // Case 1: a target that never existed at B at all.
    let never_registered = [0x77u8; 32];
    let mut ac1 = alice.connect(&rig.a_c2s_url).await.unwrap();
    let err_unknown = ac1
        .route_with_hint(
            never_registered,
            Some("org-b.test".to_string()),
            b"hello".to_vec(),
        )
        .await
        .unwrap_err();

    // Case 2: a target that DID connect to B, then disconnected — a real, known, now-offline
    // account, not merely an unregistered key.
    let bob = new_acct("org-b.test");
    let bc = bob.connect(&rig.b_c2s_url).await.unwrap();
    bc.close().await.unwrap();
    // Wait for B's own registry to observe the disconnect (async teardown in `ws::handle_socket`).
    for _ in 0..200 {
        if !rig.b_state.registry.is_connected(&bob.pubkey) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        !rig.b_state.registry.is_connected(&bob.pubkey),
        "bob must have fully disconnected from B before this test continues"
    );

    let mut ac2 = alice.connect(&rig.a_c2s_url).await.unwrap();
    let err_known_offline = ac2
        .route_with_hint(
            bob.pubkey,
            Some("org-b.test".to_string()),
            b"hello".to_vec(),
        )
        .await
        .unwrap_err();

    let (code_unknown, msg_unknown) = match err_unknown {
        SignalError::Server(body) => (body.code, body.msg),
        other => panic!("expected a structured server error, got {other:?}"),
    };
    let (code_known_offline, msg_known_offline) = match err_known_offline {
        SignalError::Server(body) => (body.code, body.msg),
        other => panic!("expected a structured server error, got {other:?}"),
    };

    assert_eq!(code_unknown, error_codes::NOT_CONNECTED);
    assert_eq!(
        code_unknown, code_known_offline,
        "an unknown target and a known-but-offline target must produce the IDENTICAL \
         client-visible code — anything else is a fresh existence oracle"
    );
    assert_eq!(
        msg_unknown, msg_known_offline,
        "the message text must also be identical, not just the code"
    );
}

// -- reachability is never logged or persisted -------------------------------------------------

/// Mirrors task 2.6's `policy_module_introduces_no_unhashed_identifier_logging`: scoped to
/// `handle_fed_reachability`'s own function body (not the whole file, which legitimately logs
/// elsewhere, e.g. `run_federation`'s accept-error line) so this is a precise claim about the
/// reachability path specifically, not a blanket ban on this file ever logging anything.
#[test]
fn reachability_path_introduces_no_logging_or_persistence() {
    let src = include_str!("../src/federation/inbound.rs");
    let start = src
        .find("pub async fn handle_fed_reachability")
        .expect("handle_fed_reachability must exist in inbound.rs");
    // The next `pub async fn` after it is the following item (`serve_link`) — bound the search to
    // exactly this function's body.
    let after = &src[start..];
    let end = after[1..]
        .find("\npub async fn ")
        .map(|i| i + 1)
        .unwrap_or(after.len());
    let body = &after[..end];

    let logging_macros = [
        "trace!",
        "debug!",
        "info!",
        "warn!",
        "error!",
        "println!",
        "eprintln!",
        "print!",
        "eprint!",
        "panic!",
        "dbg!",
    ];
    for (lineno, line) in body.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for m in logging_macros {
            assert!(
                !line.contains(m),
                "handle_fed_reachability:{}: found a logging macro ({m}) — the reachability path \
                 must add no logging at all: {line}",
                lineno + 1,
            );
        }
    }

    // Nothing store/persistence-shaped is referenced either: the function takes no `&dyn Store`
    // parameter at all (structurally cannot write to a store), confirmed here at the source level
    // too so a future signature change that added one would be caught by this same test.
    assert!(
        !body.contains("Store"),
        "handle_fed_reachability must never take or touch a Store — reachability is an in-memory \
         Registry lookup only, never persisted"
    );
}
