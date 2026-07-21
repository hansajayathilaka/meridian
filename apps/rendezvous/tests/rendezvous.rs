//! Integration tests for the T02 rendezvous MVP, driving a real in-process server with the real
//! `meridian-signaling` client. Each test maps to an acceptance criterion in
//! docs/architecture/features/02-rendezvous-mvp.md.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use meridian_identity::{generate_account, sign, KeyHandle, MemorySecretStore};
use meridian_proto::{error_codes, Auth, Challenge, ErrBody, Frame, Op};
use meridian_rendezvous::config::Admission;
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};
use meridian_signaling::{SignalError, SignalingClient, DEFAULT_OTK_COUNT};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

// -- harness -----------------------------------------------------------------

async fn spawn(config: Config) -> String {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(config, store);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(state, listener).await;
    });
    format!("ws://{addr}")
}

fn config_open() -> Config {
    Config::default() // domain "localhost", open admission, tamper off
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

/// Register + publish a bundle, then drop the connection (bundle persists server-side).
async fn register(acct: &Acct, url: &str) {
    let mut c = acct.connect(url).await.unwrap();
    c.publish_bundle(&acct.store, &acct.handle, DEFAULT_OTK_COUNT)
        .await
        .unwrap();
    c.close().await.unwrap();
}

// -- acceptance: happy path --------------------------------------------------

#[tokio::test]
async fn register_publish_and_fetch_verifies() {
    let url = spawn(config_open()).await;
    let alice = new_acct("localhost");
    let bob = new_acct("localhost");

    register(&bob, &url).await;

    let mut ac = alice.connect(&url).await.unwrap();
    let bundle = ac.fetch_bundle(bob.pubkey, false).await.unwrap();
    assert_eq!(bundle.account_pub, bob.pubkey);
    assert_eq!(bundle.otk_count(), DEFAULT_OTK_COUNT);
}

// -- acceptance: tampered bundle fails closed --------------------------------
//
// Requires the `test-tamper-hook` cargo feature (F17) — the actual substitution logic is compiled
// out entirely without it (the server would just return the untampered bundle and this assertion
// would fail), so this test only compiles/runs when the feature is enabled:
// `cargo test -p meridian-rendezvous --features test-tamper-hook`.

#[cfg(feature = "test-tamper-hook")]
#[tokio::test]
async fn tampered_bundle_is_rejected() {
    let mut config = config_open();
    config.server.allow_test_tamper = true;
    let url = spawn(config).await;

    let alice = new_acct("localhost");
    let bob = new_acct("localhost");
    register(&bob, &url).await;

    let mut ac = alice.connect(&url).await.unwrap();
    let err = ac.fetch_bundle(bob.pubkey, true).await.unwrap_err();
    assert!(
        matches!(err, SignalError::BundleVerification(_)),
        "expected hard verification failure, got {err:?}"
    );
}

// F17: without the `test-tamper-hook` feature the substitution code is compiled out entirely, so
// even a config with `allow_test_tamper = true` and a client-sent `tamper` flag must be inert —
// the server returns the real, untampered bundle. This is the structural counterpart to
// `tampered_bundle_is_rejected` above (which only compiles/runs *with* the feature).
#[cfg(not(feature = "test-tamper-hook"))]
#[tokio::test]
async fn tamper_flag_is_inert_without_feature() {
    let mut config = config_open();
    config.server.allow_test_tamper = true; // even "enabled" at the config layer...
    let url = spawn(config).await;

    let alice = new_acct("localhost");
    let bob = new_acct("localhost");
    register(&bob, &url).await;

    let mut ac = alice.connect(&url).await.unwrap();
    // ...requesting tamper=true still gets bob's real bundle back — the hook doesn't exist in
    // this build at all.
    let bundle = ac.fetch_bundle(bob.pubkey, true).await.unwrap();
    assert_eq!(bundle.account_pub, bob.pubkey);
}

// -- acceptance: exact-key-only (anti-enumeration) ---------------------------

#[tokio::test]
async fn fetch_is_exact_key_only() {
    let url = spawn(config_open()).await;
    let alice = new_acct("localhost");
    let bob = new_acct("localhost");
    register(&bob, &url).await;

    let mut ac = alice.connect(&url).await.unwrap();

    // A one-byte-off key is a different principal — no fuzzy/prefix match exists.
    let mut near_miss = bob.pubkey;
    near_miss[0] ^= 0x01;
    let err = ac.fetch_bundle(near_miss, false).await.unwrap_err();
    match err {
        SignalError::Server(ErrBody { code, .. }) => assert_eq!(code, error_codes::NOT_FOUND),
        other => panic!("expected not_found, got {other:?}"),
    }
}

// -- acceptance (T05): ephemeral, distinct-per-request TURN credentials -------

fn config_with_turn() -> Config {
    let mut config = config_open();
    config.turn = meridian_rendezvous::config::Turn {
        secret: "shared-secret-abc".into(),
        realm: "localhost".into(),
        urls: vec![
            "turn:turn.localhost:3478?transport=udp".into(),
            "turn:turn.localhost:3478?transport=tcp".into(),
            "turns:turn.localhost:443?transport=tcp".into(),
        ],
        ttl_secs: 120,
    };
    config
}

#[tokio::test]
async fn turn_credentials_are_minted_and_verify_under_the_secret() {
    let url = spawn(config_with_turn()).await;
    let alice = new_acct("localhost");
    let mut c = alice.connect(&url).await.unwrap();

    let grant = c.request_turn_credentials().await.unwrap();
    // The ladder is UDP → TCP → TLS-443, and the realm is echoed.
    assert!(grant.urls[0].contains("transport=udp"));
    assert!(grant.urls.last().unwrap().contains(":443"));
    assert_eq!(grant.realm, "localhost");
    assert_eq!(grant.ttl_secs, 120);
    // coturn recomputes exactly this HMAC over the username to accept the allocation.
    assert_eq!(
        grant.credential,
        meridian_rendezvous::turn::sign_username("shared-secret-abc", &grant.username)
    );
    // The username embeds a future expiry (TTL enforcement without server-side state).
    let expiry = meridian_rendezvous::turn::username_expiry(&grant.username).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expiry > now, "credential must expire in the future");
}

#[tokio::test]
async fn each_turn_request_mints_a_distinct_credential() {
    let url = spawn(config_with_turn()).await;
    let alice = new_acct("localhost");
    let mut c = alice.connect(&url).await.unwrap();

    let a = c.request_turn_credentials().await.unwrap();
    let b = c.request_turn_credentials().await.unwrap();
    // Distinct per-request nonces ⇒ distinct usernames+credentials (feature-05 acceptance). This
    // proves distinctness, NOT single-use enforcement: a single captured credential is still valid
    // to mint allocations until its own embedded expiry, bounded only by coturn's `user-quota`
    // (infra/coturn/turnserver.conf), not rejected outright. True reuse-rejection at the wire level
    // is proven separately (task 1.23, split from what was originally 1.16).
    assert_ne!(a.username, b.username);
    assert_ne!(a.credential, b.credential);
}

#[tokio::test]
async fn turn_unavailable_when_no_relay_configured() {
    // A dev/air-gapped-no-relay server (empty secret) refuses minting; the client falls back to the
    // host/STUN ladder.
    let url = spawn(config_open()).await;
    let alice = new_acct("localhost");
    let mut c = alice.connect(&url).await.unwrap();

    let err = c.request_turn_credentials().await.unwrap_err();
    match err {
        SignalError::Server(ErrBody { code, .. }) => {
            assert_eq!(code, error_codes::TURN_UNAVAILABLE)
        }
        other => panic!("expected turn_unavailable, got {other:?}"),
    }
}

// -- acceptance: auth rejects replayed challenges -----------------------------

#[tokio::test]
async fn replayed_auth_is_rejected() {
    let url = spawn(config_open()).await;
    let acct = new_acct("localhost");

    // Connection 1: capture a valid Auth frame (signed over nonce_1 ‖ domain).
    let (mut s1, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let ch1: Challenge = recv_frame(&mut s1).await.decode().unwrap();
    let auth1 = signed_auth(&acct, &ch1);
    let auth_frame = Frame::new(Op::Auth, 1, &auth1).unwrap();
    send_frame(&mut s1, &auth_frame).await;
    assert_eq!(recv_frame(&mut s1).await.op, Op::AuthOk);

    // Connection 2: replay the exact captured Auth against a fresh challenge (nonce_2 ≠ nonce_1).
    let (mut s2, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let _ch2: Challenge = recv_frame(&mut s2).await.decode().unwrap();
    send_frame(&mut s2, &auth_frame).await;
    let reply = recv_frame(&mut s2).await;
    assert_eq!(reply.op, Op::Err);
    assert_eq!(
        reply.decode::<ErrBody>().unwrap().code,
        error_codes::AUTH_FAILED
    );
}

// -- acceptance: opaque routing between connected peers -----------------------

#[tokio::test]
async fn routes_opaque_envelope_between_connected_peers() {
    let url = spawn(config_open()).await;
    let alice = new_acct("localhost");
    let bob = new_acct("localhost");

    let mut bc = bob.connect(&url).await.unwrap();
    let mut ac = alice.connect(&url).await.unwrap();

    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let delivered = ac.route(bob.pubkey, payload.clone()).await.unwrap();
    assert!(delivered);

    let msg = bc.next_deliver().await.unwrap();
    assert_eq!(msg.from, alice.pubkey);
    assert_eq!(msg.blob.as_bytes(), payload.as_slice());
}

#[tokio::test]
async fn route_to_offline_peer_errors() {
    let url = spawn(config_open()).await;
    let alice = new_acct("localhost");
    let bob = new_acct("localhost"); // never connects

    let mut ac = alice.connect(&url).await.unwrap();
    let err = ac.route(bob.pubkey, vec![1, 2, 3]).await.unwrap_err();
    match err {
        SignalError::Server(ErrBody { code, .. }) => assert_eq!(code, error_codes::NOT_CONNECTED),
        other => panic!("expected not_connected, got {other:?}"),
    }
}

// -- admission ---------------------------------------------------------------

#[tokio::test]
async fn invite_admission_gates_registration() {
    let mut config = config_open();
    config.server.admission = Admission::Invite;
    config.server.invite_tokens = vec!["golden-ticket".into()];
    let url = spawn(config).await;

    let acct = new_acct("localhost");
    // No invite → denied.
    let err = acct
        .connect(&url)
        .await
        .err()
        .expect("expected admission denial");
    assert!(
        matches!(err, SignalError::Server(_)),
        "expected admission denial, got {err:?}"
    );

    // With the right token → admitted.
    let ok = SignalingClient::connect(
        &url,
        &acct.store,
        &acct.handle,
        acct.pubkey,
        Some("golden-ticket".into()),
        1,
    )
    .await;
    assert!(ok.is_ok(), "valid invite should be admitted");
}

// -- metrics endpoint (allowlisted names only) -------------------------------

#[tokio::test]
async fn metrics_endpoint_exposes_allowlisted_names() {
    let url = spawn(config_open()).await;
    let bob = new_acct("localhost");
    register(&bob, &url).await;

    let host = url.strip_prefix("ws://").unwrap().to_string();
    let body = http_get(&host, "/metrics").await;
    assert!(body.contains("meridian_connections_active"));
    assert!(body.contains("meridian_envelopes_routed_total"));
    assert!(body.contains("meridian_prekey_pool_depth"));
    // The pool depth reflects Bob's published one-time prekeys.
    assert!(body.contains(&format!("meridian_prekey_pool_depth {DEFAULT_OTK_COUNT}")));

    let health = http_get(&host, "/healthz").await;
    assert!(health.contains("ok"));

    // Exhaustiveness: every family actually rendered in the body must be on the allowlist —
    // closing the vacuous-lint gap (F14) where a new, non-allowlisted metric family (e.g. a
    // contact-graph counter) would otherwise pass CI silently. (Note: the allowlist also reserves
    // names for metrics not yet implemented — e.g. mailbox/federation/TURN-allocation gauges — so
    // this is a one-way subset check, not a bijection.)
    let allowlist = load_metrics_allowlist();
    let rendered = rendered_metric_families(&body);
    let leaked: Vec<&String> = rendered.difference(&allowlist).collect();
    assert!(
        leaked.is_empty(),
        "metric families rendered but not in tools/metrics-allowlist.txt: {leaked:?}\nfull body:\n{body}"
    );

    // Existing behavior: the families the server does implement today are actually rendered.
    let currently_implemented: std::collections::HashSet<String> = [
        "meridian_connections_active",
        "meridian_envelopes_routed_total",
        "meridian_prekey_pool_depth",
        "meridian_turn_credentials_minted_total",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let missing: Vec<&String> = currently_implemented.difference(&rendered).collect();
    assert!(
        missing.is_empty(),
        "expected metric families never rendered: {missing:?}\nfull body:\n{body}"
    );
}

/// Parse `tools/metrics-allowlist.txt` into the set of allowed metric family names, skipping
/// blank lines and `#`-prefixed comments.
fn load_metrics_allowlist() -> std::collections::HashSet<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/metrics-allowlist.txt"
    );
    let text = std::fs::read_to_string(path).expect("read tools/metrics-allowlist.txt");
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Extract the set of metric **family** names actually present as sample lines in a rendered
/// Prometheus text-exposition body. `raw` is the full HTTP response (headers + body) as returned
/// by [`http_get`]; only the body past the blank-line separator is parsed. Skips `# HELP` /
/// `# TYPE` comment lines, strips label sets (`{...}`), and folds histogram/summary suffixes
/// (`_bucket`, `_sum`, `_count`) back onto their base family so multi-line families don't
/// false-positive as extra families.
fn rendered_metric_families(raw: &str) -> std::collections::HashSet<String> {
    let body = raw.split_once("\r\n\r\n").map_or(raw, |(_, body)| body);
    let mut families = std::collections::HashSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Sample line: "<name>{labels} value" or "<name> value".
        let name_and_labels = line.split_whitespace().next().unwrap_or("");
        let name = name_and_labels.split('{').next().unwrap_or(name_and_labels);
        let family = name
            .strip_suffix("_bucket")
            .or_else(|| name.strip_suffix("_sum"))
            .or_else(|| name.strip_suffix("_count"))
            .unwrap_or(name);
        families.insert(family.to_string());
    }
    families
}

// -- rate limiting -----------------------------------------------------------

#[tokio::test]
async fn fetch_rate_limit_trips() {
    let mut config = config_open();
    config.limits.fetch_per_account_per_min = 3;
    let url = spawn(config).await;

    let alice = new_acct("localhost");
    let bob = new_acct("localhost");
    register(&bob, &url).await;

    let mut ac = alice.connect(&url).await.unwrap();
    for _ in 0..3 {
        ac.fetch_bundle(bob.pubkey, false).await.unwrap();
    }
    // The 4th fetch this window is refused.
    let err = ac.fetch_bundle(bob.pubkey, false).await.unwrap_err();
    match err {
        SignalError::Server(ErrBody { code, .. }) => assert_eq!(code, error_codes::RATE_LIMITED),
        other => panic!("expected rate_limited, got {other:?}"),
    }
}

// -- capacity ----------------------------------------------------------------

/// Concurrency smoke: the async server holds many simultaneous connections on one runtime (no
/// thread-per-connection). This runs a modest count in CI; the 5k-on-2-vCPU acceptance target is a
/// perf-box run (`cargo test --release -- --ignored capacity`). See the T02 acceptance criteria.
#[tokio::test]
async fn holds_many_concurrent_connections() {
    const N: usize = 250;
    let mut config = config_open();
    config.limits.auth_per_ip_per_min = 1_000_000; // all conns share 127.0.0.1 in this test
    let url = spawn(config).await;

    let mut accts = Vec::with_capacity(N);
    for _ in 0..N {
        accts.push(new_acct("localhost"));
    }
    // Connect all concurrently and hold the sessions open.
    let mut clients = Vec::with_capacity(N);
    for acct in &accts {
        clients.push(acct.connect(&url).await.unwrap());
    }

    let host = url.strip_prefix("ws://").unwrap().to_string();
    let body = http_get(&host, "/metrics").await;
    assert!(
        body.contains(&format!("meridian_connections_active {N}")),
        "expected {N} active connections; got:\n{body}"
    );
    drop(clients);
}

// -- low-level frame helpers -------------------------------------------------

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn recv_frame(ws: &mut Ws) -> Frame {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => return Frame::from_bytes(&b).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected ws message: {other:?}"),
        }
    }
}

async fn send_frame(ws: &mut Ws, frame: &Frame) {
    ws.send(Message::Binary(frame.to_bytes().unwrap()))
        .await
        .unwrap();
}

fn signed_auth(acct: &Acct, challenge: &Challenge) -> Auth {
    let mut to_sign = challenge.nonce.to_vec();
    to_sign.extend_from_slice(challenge.server_domain.as_bytes());
    let sig = sign(&acct.store, &acct.handle, &to_sign).unwrap();
    Auth {
        account_pub: acct.pubkey,
        sig: *sig.as_bytes(),
        invite: None,
        max_bundle_v: 1,
    }
}

/// Minimal HTTP/1.1 GET for hitting `/metrics` and `/healthz` without an HTTP client dep.
async fn http_get(host: &str, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}
