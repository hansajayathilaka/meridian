//! Task 2.8 acceptance: federated envelope routing + per-request reachability (system-design.md
//! §3.3 step 5, §3.4).
//!
//! Same two-real-server-over-real-mTLS harness as `federation_fetch.rs` (task 2.7): cert-minting,
//! `spawn_c2s`/`spawn_federation`, and `stand_up`/`boot_federated_pair` (this crate's shared
//! `tests/support/mod.rs`, task 3.4/F18 — the per-file `make_ca`/`mint_identity`/server-boot
//! duplication this comment used to describe was extracted there). This file keeps a local
//! `org_a_federation` for the one config knob (A's `Federation`) `boot_federated_pair`'s options
//! don't parameterize; B's side goes through `boot_federated_pair` directly.
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use meridian_proto::{
    error_codes, fed_error_codes, FedErr, FedFrame, FedOp, FedReachable, FedRoute, OpaqueBlob,
};
use meridian_rendezvous::config::{DiscoveryMode, Federation, FederationPolicyMode, Mailbox};
use meridian_rendezvous::federation::inbound::{handle_fed_route, FedRouteDeps};
use meridian_rendezvous::federation::outbound::ROUTE_REPLY_GRACE;
use meridian_rendezvous::federation::FederationTimeouts;
use meridian_rendezvous::federation::{dial, Discovery, DiscoveryError, Endpoint};
use meridian_rendezvous::federation::{FederationLimits, FederationListener, FederationPolicy};
use meridian_rendezvous::metrics::Metrics;
use meridian_rendezvous::state::Registry;
use meridian_rendezvous::{AppState, MemoryStore, Store};
use meridian_signaling::SignalError;
use tokio::net::{TcpListener, TcpStream};

mod support;
use support::{
    base_config, boot_federated_pair, install_discovery, new_acct, spawn_c2s, spawn_federation,
    write_federation_map, FederatedPairOpts, TestCa,
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
    let limits = FederationLimits::new(300, 600, 30, 300);
    let req = FedRoute {
        to: [0x11u8; 32],
        from: [0x22u8; 32],
        envelope: OpaqueBlob::new(vec![0x41u8; 2 * 1024 * 1024]),
    };
    let metrics = Metrics::new();
    let store = MemoryStore::new();
    let mailbox = Mailbox::default();
    let err = handle_fed_route(
        &registry,
        &policy,
        &limits,
        FedRouteDeps {
            metrics: &metrics,
            store: &store,
            mailbox: &mailbox,
        },
        &["org-a.test".to_string()],
        "org-a.test",
        &req,
    )
    .await
    .expect_err("an oversized FedRoute body must be rejected");
    assert_eq!(err.code, fed_error_codes::BAD_REQUEST);
    // The oversized recipient must never have reached the registry (defense-in-depth means the
    // check runs BEFORE delivery, not merely in addition to it).
    assert!(!registry.is_connected(&req.to));
}

// -- task 8.6: federated mailbox enqueue on an offline recipient -----------------------------------
//
// Genuinely exercising this branch through the real A-to-B wire path (`route_with_hint`) is not
// possible deterministically: `route_foreign`'s own `reachable_foreign` pre-check (architect
// decision #3) already gates the *entire* target-liveness axis ahead of ever sending the actual
// `FedRoute` — a recipient that never connected to B is `not_connected` at A before B's
// `handle_fed_route` runs at all, and a recipient that stays connected through both the pre-check
// and the delivery attempt is simply "delivered," never reaching the offline branch either. The
// only way to reach this branch for real is the narrow pre-check/delivery disconnect race this
// task's own doc comment describes — not something a fast, non-flaky test can construct. So, same
// reasoning and the same directness as `bs_defense_in_depth_oversized_check_rejects_directly`
// above: call `handle_fed_route` directly with a hand-built `FedRoute` naming a recipient that was
// never registered in `Registry` at all.

/// Offline + `ttl_days > 0` + under quota: `handle_fed_route` enqueues into B's own store and
/// returns `Ok(())` — the pre-8.6 return value is unchanged, but it's no longer a lie: before this
/// task `Ok(())` meant "silently dropped," now it means "durably queued." `Ok(())` is what makes
/// `handle_federated_route` (`ws.rs`) reply `RouteOk{delivered:true, queued:false}` to A's own
/// sender unconditionally (that mapping itself is pre-existing and untouched by this task — proven
/// live, with delivery instead of queuing, by `federated_route_delivers_byte_identical_envelope`
/// above) — this is the accepted, documented optimistic-success residual (phase-8 architect
/// consult point 2): A's sender never learns whether B delivered live or queued.
#[tokio::test]
async fn federated_route_to_offline_recipient_enqueues_and_still_reports_ok() {
    let registry = Registry::default();
    let policy = FederationPolicy::Open;
    let limits = FederationLimits::new(300, 600, 30, 300);
    let store = MemoryStore::new();
    let mailbox = Mailbox::default(); // ttl_days=14, quota_mb=50 — plenty of room
    let bob = [0x33u8; 32];
    let payload = b"queued while bob was offline".to_vec();
    let req = FedRoute {
        to: bob,
        from: [0x22u8; 32],
        envelope: OpaqueBlob::new(payload.clone()),
    };

    let result = handle_fed_route(
        &registry,
        &policy,
        &limits,
        FedRouteDeps {
            metrics: &Metrics::new(),
            store: &store,
            mailbox: &mailbox,
        },
        &["org-a.test".to_string()],
        "org-a.test",
        &req,
    )
    .await;
    assert!(
        result.is_ok(),
        "offline + mailbox enabled + under quota must still report Ok(()), matching \
         fire-and-forget-on-success — got {result:?}"
    );

    let rows = store.mailbox_list_for_recipient(&bob).await.unwrap();
    assert_eq!(rows.len(), 1, "the envelope must actually be durable now");
    assert_eq!(rows[0].blob, payload);
}

/// Offline + would exceed `quota_mb`: `handle_fed_route` returns `Err(FedErr{code:mailbox_full})`
/// — a legitimate, deliberate exception to fire-and-forget-on-success (federation-protocol-v1.md
/// §2 already says failure is reported only via `FedErr`), never a silent drop and never a
/// `RouteOk`-shaped anything (there is no `FedRouteOk`). `ws::federated_route_error_reply` then
/// maps `fed_error_codes::MAILBOX_FULL` through to the identical `error_codes::MAILBOX_FULL` the
/// local (same-server) route path already produces (task 8.5) — same client-visible code for the
/// same condition, regardless of which side of a federation boundary it happened on.
#[tokio::test]
async fn federated_route_to_offline_recipient_over_quota_is_rejected() {
    let registry = Registry::default();
    let policy = FederationPolicy::Open;
    let limits = FederationLimits::new(300, 600, 30, 300);
    let store = MemoryStore::new();
    let mailbox = Mailbox {
        ttl_days: 14,
        quota_mb: 0, // any non-empty enqueue immediately exceeds a zero quota
        ..Mailbox::default()
    };
    let bob = [0x44u8; 32];
    let req = FedRoute {
        to: bob,
        from: [0x22u8; 32],
        envelope: OpaqueBlob::new(b"this will not fit".to_vec()),
    };

    let err = handle_fed_route(
        &registry,
        &policy,
        &limits,
        FedRouteDeps {
            metrics: &Metrics::new(),
            store: &store,
            mailbox: &mailbox,
        },
        &["org-a.test".to_string()],
        "org-a.test",
        &req,
    )
    .await
    .expect_err("over-quota enqueue must be a genuine FedErr, never Ok(())");
    assert_eq!(err.code, fed_error_codes::MAILBOX_FULL);

    assert_eq!(
        store.mailbox_size_bytes_for_recipient(&bob).await.unwrap(),
        0,
        "a quota-rejected federated route must not create a row"
    );
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

// -- task 3.7: one link per routed message (F10) + SRV failover (N2) ----------------------------

/// Wrap `target` behind a raw byte-forwarding TCP proxy: every accepted connection at the returned
/// address is immediately paired with a fresh outbound connection to `target`, and the two streams
/// are spliced together verbatim (`tokio::io::copy_bidirectional`). TLS still terminates at the
/// REAL peer behind `target` — this proxy never touches a single mTLS byte, so it changes nothing
/// about certificate validation or the s2s protocol above it. What it buys: an exact, external,
/// syscall-level count of how many raw TCP connections crossed it — independent of anything
/// `route_foreign`/`dial_foreign` themselves report, so a regression back to "one dial for the
/// pre-check, a second for the real route" is provable from OUTSIDE the code under test, not merely
/// inferred from its own internal call count.
async fn spawn_counting_tcp_proxy(target: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            let (mut inbound, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (addr, accepts)
}

/// Stand up B for real (accepting, real federation listener) and A dialing out THROUGH a counting
/// proxy in front of B's real federation address, rather than at that address directly — so every
/// raw TCP connection A opens toward B, whatever the s2s layer above it does, is independently
/// countable at [`ProxiedRig::proxy_accepts`].
struct ProxiedRig {
    /// A's own state — needed for the dialing-side `federation_link_up` steady-state assertion
    /// (see `n_routed_messages_show_n_single_link_opens_not_flapping`'s doc comment for why the
    /// dialing side, not B's accept side, is what's asserted on).
    a_state: Arc<AppState>,
    a_c2s_url: String,
    b_c2s_url: String,
    proxy_accepts: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn stand_up_through_proxy() -> ProxiedRig {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let b_id = ca.issue(dir.path(), "org-b.test");
    let b_empty_map = write_federation_map(dir.path(), &[]);
    let b_federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: b_id.cert_path_str().to_string(),
        key_path: b_id.key_path_str().to_string(),
        ca_bundle_path: b_id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: b_empty_map.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    };
    let mut b_config = base_config("org-b.test");
    b_config.federation = b_federation;
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;
    let b_c2s_url = spawn_c2s(b_state.clone()).await;

    let (proxy_addr, proxy_accepts) = spawn_counting_tcp_proxy(b_fed_addr).await;

    // A's federation_map points "org-b.test" at the PROXY address, still pinned to B's real
    // domain — the proxy is a pure byte-forwarder, so this changes nothing about which certificate
    // A ends up validating (still B's own, presented across the proxied connection).
    let a_federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        proxy_addr,
        "org-b.test",
    );
    let mut a_config = base_config("org-a.test");
    a_config.federation = a_federation;
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state.clone()).await;

    ProxiedRig {
        a_state,
        a_c2s_url,
        b_c2s_url,
        proxy_accepts,
        _dir: dir,
    }
}

/// Deliverable 1 (task 3.7): one routed message must open exactly ONE TCP connection to the
/// foreign server. Before this task, `route_foreign` dialed twice — once for its internal
/// `reachable_foreign` liveness pre-check, once more for the actual `FedRoute` — each a fully
/// independent TCP+TLS connection to the same peer; this would show up here as 2, not 1.
#[tokio::test]
async fn one_routed_message_opens_exactly_one_tcp_connection() {
    let rig = stand_up_through_proxy().await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    let delivered = ac
        .route_with_hint(
            bob.pubkey,
            Some("org-b.test".to_string()),
            b"one message, one link".to_vec(),
        )
        .await
        .unwrap();
    assert!(delivered, "bob is connected; the route must deliver");
    bc.next_deliver().await.unwrap();

    assert_eq!(
        rig.proxy_accepts.load(Ordering::SeqCst),
        1,
        "one routed message must open exactly ONE TCP connection to B, counted at the proxy \
         (not inferred from route_foreign's own internal call count) — 2 here would mean the old \
         pre-check-dials-separately-from-the-real-dial behavior regressed"
    );
}

/// Deliverable 3 (task 3.7): sending N routed messages in sequence must open exactly N TCP
/// connections — not 2N — and A's OWN `federation_link_up` gauge (the dialing side — `route_foreign`
/// runs on A, and its `fed_link` is dialed with `state.metrics`, i.e. A's `Arc<Metrics>`, per
/// `dial_foreign`) must return to its steady-state 0 immediately after each message completes,
/// never accumulating or "flapping" an extra link-open per message. `route_foreign`'s `fed_link` is
/// a plain local variable, dropped synchronously (ordinary Rust drop-glue, no extra network round
/// trip needed) before that call returns to its own caller — so a caller observing A's gauge right
/// after one `route_with_hint` resolves should always see 0. (B's OWN accept-side gauge is
/// deliberately NOT asserted here: B only notices the connection closed on ITS NEXT read, an
/// inherently racy, separately-scheduled event relative to when A's client-visible call returns —
/// asserting on it would make this test flaky for a reason that has nothing to do with the
/// property under test.) A regression to "two independent dials per message" would still
/// eventually return to 0 on A's side too (both links get dropped, just later and twice as often),
/// so the *count*-based proof below is the load-bearing one; the gauge check is corroborating, not
/// the sole proof.
#[tokio::test]
async fn n_routed_messages_show_n_single_link_opens_not_flapping() {
    let rig = stand_up_through_proxy().await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    const N: usize = 4;
    for i in 0..N {
        let delivered = ac
            .route_with_hint(
                bob.pubkey,
                Some("org-b.test".to_string()),
                format!("message {i}").into_bytes(),
            )
            .await
            .unwrap_or_else(|e| panic!("message {i} of {N} must deliver: {e:?}"));
        assert!(delivered);
        bc.next_deliver().await.unwrap();

        assert_eq!(
            rig.a_state.metrics.federation_links_up(),
            0,
            "message {i}: A's own federation_link_up gauge must be back at its steady-state 0 \
             immediately after this one message's route_foreign call returns — the link it dialed \
             is dropped inside route_foreign itself (ordinary Rust drop-glue, no extra network \
             round trip) before returning, so nothing here should ever observe an elevated or \
             still-climbing count between messages"
        );
    }

    assert_eq!(
        rig.proxy_accepts.load(Ordering::SeqCst),
        N,
        "{N} sequential routed messages must open exactly {N} TCP connections total — not {}, \
         which is what the old two-dials-per-message behavior would have produced",
        N * 2
    );
}

/// A [`Discovery`] stand-in returning two fixed [`Endpoint`]s, in the SRV-shaped order
/// [`SrvDiscovery`](meridian_rendezvous::federation::SrvDiscovery) would already have sorted them
/// into (priority ascending) — this test drives `dial_foreign`'s SRV-failover loop directly,
/// without needing a real DNS resolver or SRV records.
struct TwoEndpointDiscovery {
    first: Endpoint,
    second: Endpoint,
}

#[async_trait]
impl Discovery for TwoEndpointDiscovery {
    async fn resolve(&self, _domain: &str) -> Result<Vec<Endpoint>, DiscoveryError> {
        Ok(vec![self.first.clone(), self.second.clone()])
    }
}

/// Deliverable 2 (task 3.7, N2): a first candidate endpoint that refuses the TCP connection
/// outright must not fail the whole dial — `dial_foreign` falls through to the second candidate
/// and, since it's a real reachable peer, the route still delivers. Both endpoints are SRV-shaped
/// (`pinned_identity: None`): the domain pin for each is computed fresh from THAT candidate (falls
/// back to the hint domain, "org-b.test") — never reused from the first, failed candidate — so this
/// also proves the failover path still validates the SECOND candidate's certificate against the
/// correct intended domain, not a relaxed or skipped check.
#[tokio::test]
async fn a_refusing_first_endpoint_falls_through_to_a_working_second() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    // B, for real: accepting real federation connections.
    let b_id = ca.issue(dir.path(), "org-b.test");
    let b_empty_map = write_federation_map(dir.path(), &[]);
    let b_federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: b_id.cert_path_str().to_string(),
        key_path: b_id.key_path_str().to_string(),
        ca_bundle_path: b_id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: b_empty_map.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    };
    let mut b_config = base_config("org-b.test");
    b_config.federation = b_federation;
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;
    let b_c2s_url = spawn_c2s(b_state).await;

    // The "first" candidate: bound, then immediately dropped, so any connection attempt is
    // refused (a fast RST) rather than hanging on a timeout.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let a_id = ca.issue(dir.path(), "org-a.test");
    // Unused once `install_discovery` below replaces A's discovery outright — only needs to parse
    // cleanly at `AppState::new` time (same pattern as
    // `federation_outbound_policy.rs::closed_policy_denial_makes_zero_dns_lookups_and_zero_tcp_connects`).
    let a_unused_map = write_federation_map(dir.path(), &[]);
    let a_federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: a_id.cert_path_str().to_string(),
        key_path: a_id.key_path_str().to_string(),
        ca_bundle_path: a_id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: a_unused_map.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    };
    let mut a_config = base_config("org-a.test");
    a_config.federation = a_federation;
    let a_store = Arc::new(MemoryStore::new());
    let mut a_state = AppState::new(a_config, a_store);
    install_discovery(
        &mut a_state,
        Arc::new(TwoEndpointDiscovery {
            first: Endpoint {
                host: dead_addr.ip().to_string(),
                port: dead_addr.port(),
                priority: 0,
                weight: 0,
                pinned_identity: None,
            },
            second: Endpoint {
                host: b_fed_addr.ip().to_string(),
                port: b_fed_addr.port(),
                priority: 1,
                weight: 0,
                pinned_identity: None,
            },
        }),
    );
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&b_c2s_url).await.unwrap();

    let delivered = ac
        .route_with_hint(
            bob.pubkey,
            Some("org-b.test".to_string()),
            b"failover works".to_vec(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "a routed message must still succeed via the SECOND candidate endpoint once the \
                 first refuses the connection outright: {e:?}"
            )
        });
    assert!(delivered);
    let msg = bc.next_deliver().await.unwrap();
    assert_eq!(msg.blob.as_bytes(), b"failover works");
}

// -- task 3.8: federated deliveries count in envelopes_routed_total (F8 + N4) -------------------

/// Minimal local mirror of `rendezvous.rs`'s own `http_get` — not shared through `tests/support`
/// because it's the only file besides `rendezvous.rs` that needs a raw `/metrics` scrape (both
/// `handle_fed_route`'s c2s router and the plain local one expose `/metrics` on the SAME axum
/// router, task 2.8's federated-route tests just never previously had a reason to hit it).
async fn http_get(host: &str, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = TcpStream::connect(host).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

/// Read the current value of one **unlabeled** Prometheus sample line (`<name> <value>`, e.g.
/// `meridian_envelopes_routed_total 3`) out of a rendered `/metrics` body. Panics if the family
/// isn't rendered at all, or if it turns up carrying a label block (`name{...}`) — this metric must
/// never grow one (see this section's second test).
fn metric_value(body: &str, name: &str) -> i64 {
    let rendered_body = body.split_once("\r\n\r\n").map_or(body, |(_, b)| b);
    for line in rendered_body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            let rest = rest.trim();
            assert!(
                !rest.starts_with('{'),
                "{name} must never be exported with a label block (found: {line})"
            );
            return rest
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse metric value from line: {line}"));
        }
    }
    panic!("metric family {name} not found in body:\n{body}");
}

/// Task 3.8 (F8): a federated delivery — the inbound `fed_route` path, `handle_fed_route` — must
/// increment `meridian_envelopes_routed_total` exactly once per successfully-delivered message,
/// mirroring `ws::deliver_one`'s identical accounting for the local (same-server) path. Before this
/// task's fix, `handle_fed_route` discarded `Registry::send_to`'s return value outright and never
/// touched the metric at all, so every federated delivery — the entire point of Phase 2 — was
/// invisible to ops dashboards reading this counter. Two sequential deliveries (not just one) prove
/// this is a genuine per-delivery increment, not a one-shot fixup that only fires once.
#[tokio::test]
async fn federated_delivery_increments_envelopes_routed_total_exactly_once_per_message() {
    let rig = stand_up(FederationPolicyMode::Open).await;
    let host = rig
        .b_c2s_url
        .strip_prefix("ws://")
        .expect("spawn_c2s always returns a ws:// URL")
        .to_string();

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    let before = metric_value(
        &http_get(&host, "/metrics").await,
        "meridian_envelopes_routed_total",
    );

    let delivered = ac
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"one".to_vec())
        .await
        .unwrap();
    assert!(delivered, "bob is connected; the route must deliver");
    bc.next_deliver().await.unwrap();

    let after_one = metric_value(
        &http_get(&host, "/metrics").await,
        "meridian_envelopes_routed_total",
    );
    assert_eq!(
        after_one,
        before + 1,
        "one federated delivery must increment the counter by exactly one"
    );

    let delivered2 = ac
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"two".to_vec())
        .await
        .unwrap();
    assert!(
        delivered2,
        "bob is still connected; the second route must deliver too"
    );
    bc.next_deliver().await.unwrap();

    let after_two = metric_value(
        &http_get(&host, "/metrics").await,
        "meridian_envelopes_routed_total",
    );
    assert_eq!(
        after_two,
        before + 2,
        "a second federated delivery must increment the counter by exactly one more — proving \
         this is a real per-delivery increment, not a one-shot fixup"
    );
}

/// Task 3.8 (Scope's hard "Out" constraint): a federated delivery must introduce no new metric
/// name and no new label — in particular, no `peer_domain`/per-partner label, which would
/// materialize the cross-org contact graph this server talks to (anonymity-and-retention.md
/// must-never #2; 2.4 already settled the identical question the same way for
/// `meridian_federation_link_up`). Mirrors `rendezvous.rs`'s own
/// `metrics_endpoint_exposes_allowlisted_names` allowlist-diff pattern (exhaustiveness: every
/// family actually rendered must be on `tools/metrics-allowlist.txt`), scraped from a real HTTP GET
/// after a real federated delivery — not merely inferred from source code.
#[tokio::test]
async fn federated_delivery_introduces_no_new_metric_name_or_label() {
    let rig = stand_up(FederationPolicyMode::Open).await;
    let host = rig
        .b_c2s_url
        .strip_prefix("ws://")
        .expect("spawn_c2s always returns a ws:// URL")
        .to_string();

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    let delivered = ac
        .route_with_hint(
            bob.pubkey,
            Some("org-b.test".to_string()),
            b"metrics-allowlist check".to_vec(),
        )
        .await
        .unwrap();
    assert!(delivered);
    bc.next_deliver().await.unwrap();

    let body = http_get(&host, "/metrics").await;

    let allowlist_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/metrics-allowlist.txt"
    );
    let allowlist_text =
        std::fs::read_to_string(allowlist_path).expect("read tools/metrics-allowlist.txt");
    let allowlist: std::collections::HashSet<String> = allowlist_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();

    let rendered_body = body
        .split_once("\r\n\r\n")
        .map_or(body.as_str(), |(_, b)| b);
    let mut rendered = std::collections::HashSet::new();
    let mut saw_labeled_envelopes_routed = false;
    for line in rendered_body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name_and_labels = line.split_whitespace().next().unwrap_or("");
        if name_and_labels.starts_with("meridian_envelopes_routed_total{") {
            saw_labeled_envelopes_routed = true;
        }
        let name = name_and_labels.split('{').next().unwrap_or(name_and_labels);
        rendered.insert(name.to_string());
    }

    assert!(
        !saw_labeled_envelopes_routed,
        "meridian_envelopes_routed_total must never carry a label (e.g. peer_domain) — that would \
         materialize the cross-org contact graph"
    );

    let leaked: Vec<&String> = rendered.difference(&allowlist).collect();
    assert!(
        leaked.is_empty(),
        "metric families rendered but not in tools/metrics-allowlist.txt: {leaked:?}\nfull body:\n{body}"
    );
    assert!(
        rendered.contains("meridian_envelopes_routed_total"),
        "the counter this task fixes must actually be rendered"
    );
}

// -- task 3.20: ROUTE_REPLY_GRACE — measure, then pin the residual ------------------------------

/// Measures the real `FedRoute` reply-RTT distribution this task's `ROUTE_REPLY_GRACE` tightening
/// is grounded on, over the SAME two-real-server-over-real-mTLS harness every other test in this
/// file uses (`FederationListener`/`link::dial`, i.e. exactly what `route_foreign` itself drives —
/// never a mock of the wire protocol).
///
/// **What this measures, precisely:** the span from finishing the write of a `FedRoute` frame to
/// finishing the read of B's `FedErr` reply — the exact interval `ROUTE_REPLY_GRACE` bounds inside
/// `route_foreign` (see that constant's doc comment). B's federation policy is `Closed`, so every
/// `FedRoute` this test sends is rejected by `handle_fed_route`'s very first check
/// (`policy.admit_any`) before it ever reaches the rate limiter or the registry — a real,
/// in-process-cheap `FedErr{policy_denied}`, i.e. the SAME "processing cost ~0, wire RTT is what
/// dominates" case the residual's own risk note describes. One link is dialed once and reused for
/// all `N` requests (not re-dialed per request): `ROUTE_REPLY_GRACE` only ever bounds the
/// post-dial reply wait, never the dial itself, so re-paying dial/TLS cost per sample would measure
/// the wrong span.
///
/// **`#[ignore]`:** this is a measurement bench, not a correctness assertion — run manually with
/// `cargo test --release -p meridian-rendezvous --test federation_route -- --ignored --nocapture
/// measure_route_reply_rtt_distribution` and read the printed distribution off stdout. Left in the
/// tree (rather than deleted after one manual run) so the measurement can be re-taken if the system
/// under test changes again, exactly as task 3.20's own Risk note anticipates ("measuring before
/// [3.3/3.7] land would measure the wrong system" — the inverse is also true: a future change to
/// the outbound path invalidates this number too, and this is how to retake it).
#[tokio::test]
#[ignore = "manual measurement bench (task 3.20) — not a correctness assertion; run with --ignored --nocapture"]
async fn measure_route_reply_rtt_distribution() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let b_id = ca.issue(dir.path(), "org-b.test");
    let b_empty_map = write_federation_map(dir.path(), &[]);
    let b_federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: b_id.cert_path_str().to_string(),
        key_path: b_id.key_path_str().to_string(),
        ca_bundle_path: b_id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: b_empty_map.to_str().unwrap().to_string(),
        // Closed: `handle_fed_route` rejects on its very first, purely in-process check, so the
        // reply is genuinely cheap to produce — isolating wire RTT as the dominant cost, exactly
        // the scenario `ROUTE_REPLY_GRACE`'s residual is about.
        policy: FederationPolicyMode::Closed,
        ..Federation::default()
    };
    let mut b_config = base_config("org-b.test");
    b_config.federation = b_federation;
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state).await;

    let a_id = ca.issue(dir.path(), "org-a.test");
    let client_tls = a_id.client_tls();
    let mut link = dial(
        b_fed_addr,
        "org-b.test",
        client_tls,
        "org-a.test",
        None,
        FederationTimeouts::default(),
    )
    .await
    .expect("real mTLS dial to B must succeed");

    const N: usize = 200;
    let mut samples: Vec<Duration> = Vec::with_capacity(N);
    for i in 0..N {
        let req = FedRoute {
            to: [0x11u8; 32],
            from: [0x22u8; 32],
            envelope: OpaqueBlob::new(format!("rtt sample {i}").into_bytes()),
        };
        let out = FedFrame::new(FedOp::Route, i as u64, &req).unwrap();
        let start = std::time::Instant::now();
        link.send_frame(&out).await.expect("send FedRoute");
        let reply = link.recv_frame().await.expect("recv reply");
        samples.push(start.elapsed());
        assert_eq!(
            reply.op,
            FedOp::Err,
            "B's Closed policy must reject every request with FedErr, sample {i}"
        );
    }

    samples.sort();
    let min = samples[0];
    let max = samples[N - 1];
    let p50 = samples[N / 2];
    let p95 = samples[N * 95 / 100];
    let p99 = samples[N * 99 / 100];
    let sum: Duration = samples.iter().sum();
    let mean = sum / N as u32;
    println!(
        "ROUTE_REPLY_GRACE reply-RTT measurement (task 3.20): N={N} min={min:?} p50={p50:?} \
         mean={mean:?} p95={p95:?} p99={p99:?} max={max:?}"
    );
}

/// A synthetic stand-in for B that speaks the real wire protocol (`FederationListener`/
/// `FederationLink` — the same types `route_foreign`/`handle_fed_route` themselves use, not a mock
/// of the protocol) but delays its `FedRoute` → `FedErr` reply by `delay` — simulating exactly the
/// "B genuinely answered, but the reply crossed the wire late (congestion/loss)" scenario
/// `ROUTE_REPLY_GRACE`'s doc comment describes, without needing a delay hook wired into production
/// `handle_fed_route`/`serve_link` (out of this task's file-scope: only `outbound.rs`,
/// `federation_route.rs`, and `federation-protocol-v1.md` are touched by task 3.20). Confirms
/// `FedReachability` immediately with `connected: true` (so `route_foreign`'s own pre-check passes
/// and it proceeds to send the real `FedRoute`, exactly as it would against a live, reachable B),
/// then, on the `FedRoute` itself, sleeps `delay` before replying `FedErr` — both handled over the
/// ONE link `dial_foreign` establishes, matching task 3.7's single-link-per-message shape.
async fn spawn_delayed_fed_err_responder(
    dir: &Path,
    ca: &TestCa,
    domain: &str,
    delay: Duration,
) -> SocketAddr {
    let id = ca.issue(dir, domain);
    let listener = FederationListener::bind("127.0.0.1:0", &id.paths(), domain, None)
        .await
        .expect("bind synthetic delayed-B listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut link, _peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        loop {
            let frame = match link.recv_frame().await {
                Ok(f) => f,
                Err(_) => return,
            };
            match frame.op {
                FedOp::Reachability => {
                    let reply = FedReachable { connected: true };
                    if let Ok(out) = FedFrame::new(FedOp::Reachable, frame.id, &reply) {
                        let _ = link.send_frame(&out).await;
                    }
                }
                FedOp::Route => {
                    tokio::time::sleep(delay).await;
                    let err = FedErr {
                        code: fed_error_codes::POLICY_DENIED.to_string(),
                        msg: "synthetic delayed rejection (task 3.20 ROUTE_REPLY_GRACE boundary \
                              test)"
                            .to_string(),
                    };
                    if let Ok(out) = FedFrame::new(FedOp::Err, frame.id, &err) {
                        let _ = link.send_frame(&out).await;
                    }
                    return;
                }
                _ => return,
            }
        }
    });
    addr
}

/// The boundary test the task's own Risks note names as missing: a `FedErr` reply that is genuine
/// (B really did reject) but crosses the wire slower than `ROUTE_REPLY_GRACE` is STILL reported to
/// the client as a successful delivery — `route_foreign`'s reply wait has already elapsed and
/// returned `Ok(())` by the time it arrives, and the late frame is simply never read.
///
/// This is the residual task 3.20 measures and tightens the WINDOW on, but — per the task's own
/// Scope "Out" boundary — does **not** structurally close: closing it outright needs
/// `federation-protocol-v1.md`'s "do not add a `FedRouteOk`" decision reopened via an ADR (the
/// architect reviewer's call, not something to do unilaterally here). `delay` is set to
/// `ROUTE_REPLY_GRACE + 100ms`: comfortably past the tightened window (itself sized off this task's
/// own measured p99 — see `measure_route_reply_rtt_distribution`), proving the residual is real at
/// the NEW value, not merely a leftover artifact of the old 500ms guess.
#[tokio::test]
async fn fed_err_delayed_past_route_reply_grace_is_still_reported_as_false_success() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let delay = ROUTE_REPLY_GRACE + Duration::from_millis(100);
    let b_addr = spawn_delayed_fed_err_responder(dir.path(), &ca, "org-b.test", delay).await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        b_addr,
        "org-b.test",
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&a_c2s_url).await.unwrap();
    let target = [0x99u8; 32];

    let delivered = ac
        .route_with_hint(
            target,
            Some("org-b.test".to_string()),
            b"late fed_err".to_vec(),
        )
        .await
        .expect(
            "ROUTE_REPLY_GRACE's residual (task 3.20, still open by design — see this test's own \
             doc comment): a FedErr arriving after the window must not surface as a client-visible \
             error at all, since route_foreign has already returned Ok(()) by the time it arrives",
        );
    assert!(
        delivered,
        "a genuine FedErr delayed past ROUTE_REPLY_GRACE is STILL reported as a false-positive \
         delivery confirmation at the NEW, tightened value — this is the documented residual task \
         3.20 measures and narrows the window on, not one it closes outright (that needs \
         federation-protocol-v1.md's 'no FedRouteOk' decision reopened via an ADR, out of this \
         task's scope)"
    );
}
