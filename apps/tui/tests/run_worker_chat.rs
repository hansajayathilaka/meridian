//! `meridian_tui::worker` — task 4.33's own test target
//! (`cargo nextest run -p meridian-tui --test run_worker_chat`).
//!
//! Dispatches `SendMessage`/`PersistHistory` effects directly against `meridian_tui::worker::dispatch`
//! (no live screen stack, no channel plumbing — same shape as `tests/run_worker_account.rs`/
//! `tests/run_worker_contacts.rs`) against a real, in-process `meridian-rendezvous` server and a real
//! second identity playing the peer, so "delivered" vs. "offline" and "first send establishes a
//! session" are proven against the genuine wire path, not simulated.
//!
//! ## Why `OsSecretStore` + `install_mock_keystore` for "us"
//! Same reasoning as `tests/run_worker_contacts.rs`'s own module doc: `SendMessageRequest`/
//! `PersistHistoryRequest` carry no `StoreChoice`/passphrase (see those requests' own doc comments in
//! `crate::app`), so `worker.rs::open_account_store` only actually resolves for an OS-keystore-backed
//! account today — a file-backed one fails closed (see
//! `send_message_for_a_file_backed_account_fails_closed_with_an_actionable_message` below).
//!
//! ## Why the peer is a plain `MemorySecretStore` identity, not another on-disk account
//! The peer never needs `account.json`/the OS keystore in these tests — it is driven directly through
//! `meridian_core::signaling::SignalingClient`/`meridian_core::identity` exactly like
//! `apps/cli/tests/chat_demo.rs`'s own two-client harness, just from one process instead of two
//! subprocesses. Nothing here exercises the peer's own *receive* path (task 4.35, out of scope) — the
//! peer only ever needs to publish a real, signature-valid bundle and (for the "delivered" case) stay
//! connected long enough for the server to report a live route.
//!
//! ## Proving "first send fetches, a later send does not"
//! [`BundleFetchCountingStore`] wraps a real [`MemoryStore`] to count `get_bundle` calls (the only
//! server-side op `SignalingClient::fetch_bundle` ever drives) — a falsifiable proof that establishing
//! a session on the first `SendMessage` dispatch, then sending a second message on the same
//! conversation, fetches the peer's bundle exactly once, never twice.
//!
//! ## Proving `SendGate` is never consulted
//! `send_succeeds_even_though_trust_bin_marks_the_peer_blocked` seeds a real, sealed `trust.bin`
//! marking the peer [`TrustState::Blocked`] before dispatching `SendMessage` — and asserts the send
//! still completes. `worker.rs::run_send_message` has no `TrustStore` in scope at all to have checked
//! in the first place; this test is the falsifiable version of that structural fact, mirroring this
//! task's own binding constraint (`crate::screens::chat`'s `dispatch_gated_send` is the *only* place
//! that ever decides whether to dispatch `Effect::SendMessage` — the worker must never re-derive or
//! second-guess that decision).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::identity::{
    generate_account, install_mock_keystore, AccountId, FileSecretStore, KeyHandle,
    MemorySecretStore, OsSecretStore,
};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_core::trust::TrustStore;
use meridian_proto::PrekeyBundle;
use meridian_rendezvous::{serve, AppState, Config, MemoryStore, Store};

use meridian_tui::app::{
    Effect, PersistHistoryEffect, PersistHistoryRequest, SendMessageEffect, SendMessageRequest,
    WorkerEvent,
};
use meridian_tui::store::history::{self, Direction as MsgDirection, HistoryEntry, MessageState};
use meridian_tui::worker::{dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors
// `apps/tui/tests/run_worker_contacts.rs`'s own `EnvGuard` exactly.
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// See `run_worker_contacts.rs`'s identical constant for why this warmup has to happen exactly once,
/// before any test's own dispatch reaches `worker.rs::init_os_keystore`.
static KEYRING_WARMUP: std::sync::Once = std::sync::Once::new();

struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    prev_home: Option<String>,
}

impl EnvGuard {
    fn set(dir: &Path) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var("MERIDIAN_HOME").ok();
        // SAFETY: serialized by ENV_LOCK, the only place in this test binary touching this var.
        unsafe {
            std::env::set_var("MERIDIAN_HOME", dir);
        }
        KEYRING_WARMUP.call_once(|| {
            let _ = keyring::Entry::new("meridian-tui-chat-test-warmup", "warmup");
        });
        install_mock_keystore();
        Self {
            _lock: lock,
            prev_home,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: see `EnvGuard::set`.
        unsafe {
            match &self.prev_home {
                Some(v) => std::env::set_var("MERIDIAN_HOME", v),
                None => std::env::remove_var("MERIDIAN_HOME"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-process rendezvous server, counting `get_bundle` calls (fetch_bundle's only server-side op).
// ---------------------------------------------------------------------------

struct BundleFetchCountingStore {
    inner: MemoryStore,
    get_bundle_calls: AtomicUsize,
}

impl BundleFetchCountingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            get_bundle_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Store for BundleFetchCountingStore {
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> Result<(), meridian_rendezvous::store::StoreError> {
        self.inner
            .register_account(account_pub, admission, max_bundle_v)
            .await
    }

    async fn put_bundle(
        &self,
        bundle: PrekeyBundle,
    ) -> Result<(), meridian_rendezvous::store::StoreError> {
        self.inner.put_bundle(bundle).await
    }

    async fn get_bundle(
        &self,
        target: &[u8; 32],
    ) -> Result<Option<PrekeyBundle>, meridian_rendezvous::store::StoreError> {
        self.get_bundle_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_bundle(target).await
    }

    async fn total_otks(&self) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner.total_otks().await
    }

    // (task 8.8) Forwarded to `self.inner`, exactly like every other method above — without
    // these, the trait's own default impls (`StoreError::Backend("... not implemented")`, added
    // task 8.1) apply instead, and `handle_route`'s offline-recipient path (task 8.5) genuinely
    // calls `mailbox_enqueue_with_quota` against `Config::default()`'s non-zero `ttl_days` in
    // `spawn_server` below — a route to an offline peer would hard-fail with `bad_request "store
    // failed"` rather than exercising the real mailbox-queuing behavior this test's own peer-
    // offline scenario is supposed to go through.
    async fn mailbox_enqueue(
        &self,
        recipient_pub: [u8; 32],
        blob: Vec<u8>,
        arrived_at: u64,
        expires_at: u64,
    ) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner
            .mailbox_enqueue(recipient_pub, blob, arrived_at, expires_at)
            .await
    }

    async fn mailbox_list_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
    ) -> Result<Vec<meridian_rendezvous::store::MailboxEntry>, meridian_rendezvous::store::StoreError>
    {
        self.inner.mailbox_list_for_recipient(recipient_pub).await
    }

    async fn mailbox_delete_by_ids(
        &self,
        recipient_pub: &[u8; 32],
        ids: &[u64],
    ) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner.mailbox_delete_by_ids(recipient_pub, ids).await
    }

    async fn mailbox_purge_expired(
        &self,
        now: u64,
    ) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner.mailbox_purge_expired(now).await
    }

    async fn mailbox_size_bytes_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
    ) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner
            .mailbox_size_bytes_for_recipient(recipient_pub)
            .await
    }
}

/// Starts the real rendezvous server on a background OS thread with its own runtime, bound to an
/// ephemeral port — mirrors `tests/run_worker_account.rs::spawn_server` exactly.
fn spawn_server() -> (String, Arc<BundleFetchCountingStore>) {
    let store = Arc::new(BundleFetchCountingStore::new());
    let store_for_server = Arc::clone(&store);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let config = Config::default();
            let state = AppState::new(config, store_for_server);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    let addr = rx.recv().unwrap();
    (format!("ws://{addr}"), store)
}

// ---------------------------------------------------------------------------
// Account fixtures
// ---------------------------------------------------------------------------

const SERVICE: &str = "meridian-tui-chat-test";

/// Mints a real OS-keystore-backed "us" account (against the mock keystore [`EnvGuard::set`] already
/// installed) and saves its real `account.json` — the exact shape `worker.rs::open_account_store`
/// re-derives its `SecretStore`/`KeyHandle` from on every dispatch.
fn setup_us_account() -> (KeyHandle, [u8; 32]) {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "self.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    (account.handle().clone(), *account.public_key().as_bytes())
}

/// Generates a fresh, independent peer identity whose pubkey sorts strictly larger (`larger = true`)
/// or strictly smaller (`larger = false`) than `us_pub` — i.e. whether "us" is the crypto initiator
/// per `apps/cli/src/chat.rs::run`'s own `account_pub.as_slice() <= peer_ik.as_slice()` role decision,
/// which `worker.rs::run_send_message` mirrors exactly. Regenerates until the ordering holds (Ed25519
/// pubkeys are effectively uniform 32-byte strings, so this converges in a handful of attempts).
fn generate_peer_with_ordering(us_pub: &[u8; 32], larger: bool) -> (MemorySecretStore, AccountId) {
    for _ in 0..1000 {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, "localhost").expect("peer generate_account");
        let peer_pub = *account.public_key().as_bytes();
        let ok = if larger {
            peer_pub.as_slice() > us_pub.as_slice()
        } else {
            peer_pub.as_slice() < us_pub.as_slice()
        };
        if ok {
            return (store, account);
        }
    }
    panic!("could not generate a peer key with the required ordering after 1000 attempts");
}

/// Connects as `account` and publishes a real, signature-valid bundle to `server` — mirrors
/// `apps/cli/src/chat.rs::run`'s own publish step. Returns the live, still-connected client so the
/// caller decides whether to keep it open (peer "online") or close it (peer "offline").
async fn publish_peer_bundle(
    server: &str,
    store: &MemorySecretStore,
    account: &AccountId,
) -> SignalingClient {
    let mut client = SignalingClient::connect(
        server,
        store,
        account.handle(),
        *account.public_key().as_bytes(),
        None,
        1,
    )
    .await
    .expect("peer connect");
    client
        .publish_bundle(store, account.handle(), DEFAULT_OTK_COUNT)
        .await
        .expect("peer publish_bundle");
    client
}

/// Writes `$MERIDIAN_HOME/tui/config.toml` naming `server` — `worker.rs::resolve_server`'s only
/// source for the rendezvous URL a `SendMessage` dispatch connects to (see that function's own doc
/// comment for why `SendMessageRequest` itself carries no server field).
fn write_server_config(home: &Path, server: &str) {
    let path = home.join("tui").join("config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).expect("create tui config dir");
    std::fs::write(&path, format!("[account]\nserver = \"{server}\"\n"))
        .expect("write config.toml");
}

async fn dispatch_effect(effect: Effect) -> WorkerEvent {
    let mut session = OnboardingSession::default();
    dispatch(effect, &mut session).await
}

fn send_request(peer_pubkey: [u8; 32], peer_hint: &str, body: &str) -> Effect {
    Effect::SendMessage(SendMessageEffect {
        request: SendMessageRequest {
            peer_pubkey,
            peer_hint: peer_hint.to_string(),
            body: body.to_string(),
        },
        outcome: None,
    })
}

// ---------------------------------------------------------------------------
// First-send session establishment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn first_send_establishes_a_session_by_fetching_the_peers_bundle_then_sends() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let (_us_handle, us_pub) = setup_us_account();
    // "us" must be the crypto initiator for this test — the responder side never fetches a bundle
    // itself (see `generate_peer_with_ordering`'s own doc comment).
    let (peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();
    let _peer_client = publish_peer_bundle(&server, &peer_store, &peer_account).await;

    assert_eq!(
        store.get_bundle_calls.load(Ordering::SeqCst),
        0,
        "no bundle fetch should have happened yet"
    );

    let outcome =
        dispatch_effect(send_request(peer_pub, peer_account.hint(), "hello from us")).await;
    let sent = match outcome {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => sent,
        other => panic!("expected a completed SendMessage, got {other:?}"),
    };
    assert!(sent.delivered, "peer was online — must report delivered");
    assert!(!sent.mid.is_empty());
    assert_eq!(sent.mid.len(), 32, "mid is 128 bits, hex-encoded");

    assert_eq!(
        store.get_bundle_calls.load(Ordering::SeqCst),
        1,
        "first send must fetch the peer's bundle exactly once"
    );

    // The session is now real and persisted: reloading `sessions.bin` off disk (through the same
    // OS-keystore path the worker itself used to seal it) shows it.
    let os = OsSecretStore::new(SERVICE);
    let handle = KeyHandle::from_label(&AccountDescriptor::load().expect("account.json").label);
    let bytes = std::fs::read(account::sessions_path().unwrap()).expect("sessions.bin exists");
    let chat = meridian_core::chat::ChatState::open_at_rest(&os, &handle, &bytes)
        .expect("open sessions.bin");
    assert!(chat.has_session(&peer_pub));
}

#[tokio::test]
async fn subsequent_send_on_an_already_established_session_does_not_refetch_the_bundle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let (_us_handle, us_pub) = setup_us_account();
    let (peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();
    let _peer_client = publish_peer_bundle(&server, &peer_store, &peer_account).await;

    match dispatch_effect(send_request(peer_pub, peer_account.hint(), "first message")).await {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => assert!(sent.delivered),
        other => panic!("expected the first send to complete, got {other:?}"),
    }
    assert_eq!(store.get_bundle_calls.load(Ordering::SeqCst), 1);

    match dispatch_effect(send_request(
        peer_pub,
        peer_account.hint(),
        "second message",
    ))
    .await
    {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => assert!(sent.delivered),
        other => panic!("expected the second send to complete, got {other:?}"),
    }
    assert_eq!(
        store.get_bundle_calls.load(Ordering::SeqCst),
        1,
        "a send on an already-established session must never refetch the peer's bundle"
    );
}

// ---------------------------------------------------------------------------
// Delivered vs. offline-peer outcomes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_to_an_online_peer_reports_delivered_true() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, _store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let (_us_handle, us_pub) = setup_us_account();
    let (peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();
    // Kept alive (not closed) for the whole test — the peer stays "online".
    let _peer_client = publish_peer_bundle(&server, &peer_store, &peer_account).await;

    match dispatch_effect(send_request(peer_pub, peer_account.hint(), "hi")).await {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => assert!(sent.delivered, "peer connection is still open"),
        other => panic!("expected a completed SendMessage, got {other:?}"),
    }
}

/// `delivered == false` for an offline peer, still a `WorkerEvent::Completed` (never a
/// `WorkerEvent::Failed`): the send itself succeeded, the peer just was not reachable to receive it
/// live. `write_server_config`'s server runs `Config::default()`'s non-zero `mailbox.ttl_days` (task
/// 8.15: this test's own send genuinely takes the T07 mailbox-enqueue path, not the pre-T07
/// `not_connected` drop — see `BundleFetchCountingStore`'s own doc comment on its mailbox-method
/// forwarding, a few lines up in this file), so the real, current outcome here is
/// `{delivered:false, queued:true}`, asserted below.
#[tokio::test]
async fn send_to_an_offline_peer_completes_with_delivered_false_and_queued_true() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, _store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let (_us_handle, us_pub) = setup_us_account();
    let (peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();
    let peer_client = publish_peer_bundle(&server, &peer_store, &peer_account).await;
    // The peer goes offline before we ever try to reach them.
    peer_client.close().await.expect("close peer connection");

    match dispatch_effect(send_request(peer_pub, peer_account.hint(), "hi")).await {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => {
            assert!(
                !sent.delivered,
                "peer connection was closed before the send"
            );
            assert!(
                sent.queued,
                "the default (non-zero ttl_days) mailbox must have durably queued this send \
                 rather than dropping it — got {sent:?}"
            );
        }
        other => panic!(
            "an offline peer must still be a Completed outcome (delivered: false), got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// SendGate is never consulted by the worker
// ---------------------------------------------------------------------------

/// Seeds a real, sealed `trust.bin` marking the peer [`meridian_core::trust::TrustState::Blocked`]
/// and dispatches `SendMessage` against them anyway — this must still succeed, proving
/// `worker.rs::run_send_message` has no `TrustStore`/`SendGate` check of its own. See this module's
/// own doc comment ("Proving `SendGate` is never consulted") for the full reasoning: in the real
/// system this exact request would never be dispatched (`crate::screens::chat::dispatch_gated_send`
/// is the only call site, and it would have refused), but *this* test proves the worker-side half of
/// that invariant directly rather than only inspecting the screen.
#[tokio::test]
async fn send_succeeds_even_though_trust_bin_marks_the_peer_blocked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, _store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let (us_handle, us_pub) = setup_us_account();
    let (peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();
    let _peer_client = publish_peer_bundle(&server, &peer_store, &peer_account).await;

    // Seal a real trust.bin recording the peer as user-blocked — a real `SendGate::Blocked` case
    // (`TrustStore::can_send` checks `Contact::user_blocked` first and unconditionally).
    let os = OsSecretStore::new(SERVICE);
    let mut trust = TrustStore::default();
    trust.observe(peer_pub, peer_account.hint(), 1_760_000_000);
    trust
        .set_user_blocked(&peer_pub, true)
        .expect("block the freshly observed contact");
    assert!(matches!(
        trust.can_send(&peer_pub),
        meridian_core::trust::SendGate::Blocked(_)
    ));
    let sealed = trust.seal_at_rest(&os, &us_handle).expect("seal trust.bin");
    std::fs::write(account::trust_path().unwrap(), sealed).expect("write trust.bin");

    match dispatch_effect(send_request(peer_pub, peer_account.hint(), "still sends")).await {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => assert!(sent.delivered),
        other => panic!(
            "the worker must never consult SendGate itself — expected a completed send \
             regardless of trust.bin's Blocked state, got {other:?}"
        ),
    }
}

/// The *hard* failure mode, distinct from the *soft* one above: the configured server itself is
/// unreachable (connection refused), not merely "reachable but this peer isn't connected right
/// now". `ws://127.0.0.1:1` mirrors `apps/cli/tests/session_connect.rs`'s own use of that exact
/// address — port 1 is unassigned/privileged, so nothing is ever listening there and the OS
/// refuses the connection immediately (no timeout to wait out, unlike a black-holed address).
/// `SignalingClient::connect` itself must fail here, surfacing as `WorkerEvent::Failed` with a
/// message that names the real gap (a connection failure) — distinguishable both from the
/// no-server-configured wording (`send_without_a_configured_server_...`) and from the offline-peer
/// wording (`send_to_an_offline_peer_...`, which is a `Completed`, not a `Failed`, outcome at all).
#[tokio::test]
async fn send_with_an_unreachable_server_fails_closed_with_a_connection_failure_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    write_server_config(tmp.path(), "ws://127.0.0.1:1");

    let (_us_handle, us_pub) = setup_us_account();
    let (_peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();

    match dispatch_effect(send_request(peer_pub, peer_account.hint(), "hi")).await {
        WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                message.contains("connecting to"),
                "message should name a connection failure, distinct from the \
                 no-server-configured and offline-peer wordings, got: {message}"
            );
            assert!(
                !message.contains("no rendezvous server configured"),
                "must not be confused with the no-server-configured message: {message}"
            );
        }
        other => panic!("expected a failed SendMessage (unreachable server), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Adversarial: no session and not the initiator, no server configured, file-backed account
// ---------------------------------------------------------------------------

/// A non-initiator (peer key sorts smaller than ours) with no existing session has nothing to
/// establish itself — `worker.rs::run_send_message` never fetches/initiates on that side, mirroring
/// `apps/cli/src/chat.rs::run`'s own `initiator && !has_session` guard exactly. `seal_outbound` then
/// fails closed with `ChatError::NoSession` rather than silently buffering (this worker has no
/// receive path — task 4.35 — to eventually flush a buffer against).
#[tokio::test]
async fn send_as_the_non_initiator_with_no_session_fails_closed_never_implying_store_and_forward() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let (_us_handle, us_pub) = setup_us_account();
    // Peer sorts *smaller* than us — so "us" is the responder, never the initiator.
    let (_peer_store, peer_account) = generate_peer_with_ordering(&us_pub, false);
    let peer_pub = *peer_account.public_key().as_bytes();
    // Deliberately never published — a responder-side send must not even try to fetch one.

    match dispatch_effect(send_request(
        peer_pub,
        peer_account.hint(),
        "no session yet",
    ))
    .await
    {
        WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                !message.contains("delivered later") && !message.contains("come online"),
                "must never imply store-and-forward: {message}"
            );
        }
        other => panic!("expected a failed SendMessage (no session), got {other:?}"),
    }
    assert_eq!(
        store.get_bundle_calls.load(Ordering::SeqCst),
        0,
        "a non-initiator with no session must never attempt a bundle fetch"
    );
}

#[tokio::test]
async fn send_without_a_configured_server_fails_closed_with_an_actionable_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    // No config.toml written at all — `resolve_server` has nothing to read.
    let (_us_handle, us_pub) = setup_us_account();
    let (_peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();

    match dispatch_effect(send_request(peer_pub, peer_account.hint(), "hi")).await {
        WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                message.contains("no rendezvous server configured"),
                "message should name the real gap, got: {message}"
            );
        }
        other => panic!("expected a failed SendMessage (no server configured), got {other:?}"),
    }
}

#[tokio::test]
async fn send_message_for_a_file_backed_account_fails_closed_with_an_actionable_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, _store) = spawn_server();
    write_server_config(tmp.path(), &server);

    let keyfile: PathBuf = tmp.path().join("account.key");
    let fs = FileSecretStore::new(&keyfile, "correct horse battery staple");
    let account = generate_account(&fs, "self.example").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");
    let peer_pub = [0x22u8; 32];

    match dispatch_effect(send_request(peer_pub, "localhost", "hi")).await {
        WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                message.contains("passphrase-protected"),
                "message should name the real gap, got: {message}"
            );
        }
        other => panic!("expected a failed SendMessage, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// PersistHistory
// ---------------------------------------------------------------------------

#[tokio::test]
async fn persist_history_appends_a_real_sealed_transcript_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_us_account();
    let peer_pub = [0x33u8; 32];

    let entry = HistoryEntry {
        v: history::CURRENT_VERSION,
        mid: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        dir: MsgDirection::Out,
        ts: 1_760_000_000,
        stream: "mrd.chat/1".to_string(),
        body: "pushed the branch".to_string(),
        state: MessageState::Delivered,
    };
    let effect = Effect::PersistHistory(PersistHistoryEffect {
        request: PersistHistoryRequest {
            peer_pubkey: peer_pub,
            entry: entry.clone(),
        },
        outcome: None,
    });

    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::PersistHistory(PersistHistoryEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected a completed PersistHistory, got {other:?}"),
    }

    let os = OsSecretStore::new(SERVICE);
    let handle = KeyHandle::from_label(&AccountDescriptor::load().expect("account.json").label);
    let entries = history::load_or_default(&hex::encode(peer_pub), &os, &handle)
        .expect("load history/<peer>.jsonl");
    assert_eq!(entries, vec![entry]);
}
