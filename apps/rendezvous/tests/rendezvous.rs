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
