//! `meridian_tui::worker::run_inbound_loop` — task 4.35's own test target
//! (`cargo nextest run -p meridian-tui --test inbound_delivery`).
//!
//! Mirrors `apps/cli`'s own chat integration test setup (`apps/cli/tests/chat_demo.rs`) and this
//! crate's own `tests/run_worker_chat.rs`: a real, in-process `meridian-rendezvous` server, a real
//! OS-keystore-backed "us" account (against the mock keystore `EnvGuard::set` installs), and a real
//! second identity playing the peer, driven directly through `meridian_core::chat::ChatState`/
//! `meridian_core::signaling::SignalingClient` — never simulated.
//!
//! Covers this task's four named deliverables:
//! 1. [`message_request_surfaces_via_ctrl_r_when_requests_screen_is_not_open`] — (a).
//! 2. [`inbound_text_message_while_chat_open_appends_live_and_persists`] +
//!    [`a_racing_outbound_persist_history_dedups_against_a_same_mid_inbound_message`] — (b).
//! 3. [`malformed_inbound_envelope_is_dropped_and_the_loop_keeps_running`] — (c).
//! 4. [`auto_ack_still_replies_even_though_trust_bin_marks_the_sender_blocked`] — (d), the
//!    falsifiable version of "the auto-ack path is never gated by `SendGate`", mirroring
//!    `run_worker_chat.rs`'s own `send_succeeds_even_though_trust_bin_marks_the_peer_blocked`.
//!
//! Plus a review-driven regression:
//! 5. [`reply_to_a_message_request_accepted_contact_with_a_blank_hint_routes_locally`] — the
//!    identical empty-hint-misroutes-as-federation bug (d)'s auto-ack fix closed, found the second
//!    time on the ordinary outbound `Effect::SendMessage`/`route_tolerant` path
//!    (`worker::sanitize_routing_hint` now centralizes the fix across every routing-hint call site).
//!
//! And, closing a review-flagged coverage gap:
//! 6. [`reconnect_with_backoff_escalates_then_recovers_and_resumes_forwarding_inbound`] — the
//!    reconnect-with-backoff logic itself (attempt counting, clamping, `AppEvent::ConnectionStatus`
//!    emission, and resumed forwarding after a real reconnect), previously exercised only by
//!    `statusbar.rs`'s pure rendering-primitive test, never by `run_inbound_loop` itself.
//!
//! And, task 5.1's own review-fix coverage (the actual deliverable of that task — see its own file,
//! `docs/tasks/phase-5/5.1-persist-reconcile-delivery-receipts.md`): `App::handle_inbound`'s
//! `InboundEvent::Receipt` arm used to reconcile the `Sent` → `Delivered` transition only when the
//! exact matching `Screen::Chat` happened to be `self.screens.last_mut()`, and never persisted the
//! transition at all (so a restart reverted it back to `Sent`).
//! 7. [`receipt_reconciles_into_a_chat_screen_that_is_not_topmost`] — the routing-bug half: a receipt
//!    for a `Screen::Chat` buried under another screen on the stack must still reconcile, exactly
//!    like [`crate::app::App::apply_accepted_request`]/`apply_added_contact` already do for their own
//!    inbound events.
//! 8. [`receipt_delivered_state_survives_a_restart_via_load_history`] — the persistence half: the
//!    resulting `Delivered` state must survive a real `Effect::PersistReceipt` round trip and still
//!    read back `Delivered` (not `Sent`) via a fresh `Effect::LoadHistory`-equivalent read, simulating
//!    a restart.
//!
//! And, closing two review/test-engineer-flagged coverage gaps left open by the two tests above:
//! 9. [`receipt_for_a_peer_with_no_chat_screen_open_still_persists`] — `PersistReceiptRequest`'s own
//!    doc comment claims "a receipt for a peer with no `Screen::Chat` currently open must still
//!    update `history.jsonl`"; unlike deliverable 7 (a `Screen::Chat` buried under another screen),
//!    this drives the zero-matching-screens case — no `Screen::Chat` pushed at all — and confirms
//!    `Effect::PersistReceipt` still comes back and still lands `Delivered` on disk.
//! 10. [`mark_delivered_for_an_unknown_mid_is_a_no_op_on_disk`] — the disk-level counterpart to
//!     `tests/screens_chat.rs::apply_receipt_for_an_unknown_mid_is_a_no_op` (the in-memory half):
//!     `store::history::mark_delivered_at`'s documented no-op-if-absent contract (`Ok(())`, no write
//!     at all) for a receipt whose `ack.mid` never matches any `Out` entry on disk, proven by a
//!     byte-for-byte-unchanged sealed file, not just an unchanged decoded `Vec<HistoryEntry>`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use meridian_core::account::AccountDescriptor;
use meridian_core::chat::{ChatState as CoreChatState, DESYNC_RECOVERY_THRESHOLD};
use meridian_core::envelope::{ChatContent, MessageEnvelope};
use meridian_core::identity::{
    generate_account, install_mock_keystore, AccountId, KeyHandle, MemorySecretStore, OsSecretStore,
};
use meridian_core::signaling::SignalingClient;
use meridian_core::trust::{TrustState, TrustStore};
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

use meridian_tui::app::{
    AcceptRequestEffect, AcceptRequestRequest, App, AppEvent, Effect, InboundEvent, Screen,
    SendMessageEffect, SendMessageRequest, SetUserBlockedEffect, SetUserBlockedRequest,
};
use meridian_tui::screens::chat::{self, ChatState as TuiChatState};
use meridian_tui::screens::requests::RequestsState;
use meridian_tui::store::history::{Direction as MsgDirection, HistoryEntry, MessageState};
use meridian_tui::worker::{dispatch, run_inbound_loop, OnboardingSession};

use ratatui::backend::TestBackend;
use ratatui::Terminal;

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors
// `tests/run_worker_chat.rs`'s own `EnvGuard` exactly.
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());
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
            let _ = keyring::Entry::new("meridian-tui-inbound-test-warmup", "warmup");
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
// In-process rendezvous server
// ---------------------------------------------------------------------------

fn spawn_server() -> String {
    let store = std::sync::Arc::new(MemoryStore::new());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let config = Config::default();
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    let addr = rx.recv().unwrap();
    format!("ws://{addr}")
}

// ---------------------------------------------------------------------------
// A killable, restartable-on-the-same-address in-process rendezvous server — used only by the
// reconnect-with-backoff test below (deliverable 6); every other test in this file uses the
// simpler, forever-running `spawn_server()` above.
// ---------------------------------------------------------------------------

/// Handle to a server spawned by [`try_spawn_server_at`]. `kill()` signals the server's dedicated
/// OS thread to stop and drop its whole Tokio runtime — closing the listener *and* every accepted
/// connection's socket (a real, unplanned-outage-style disconnect from a connected client's point
/// of view, not a clean WS close) — so a later [`try_spawn_server_at`] call can rebind the identical
/// address.
struct KillableServer {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl KillableServer {
    async fn kill(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // A brief grace period for the server's OS thread to actually finish dropping its runtime
        // (closing the listening socket) before a caller tries to rebind the same address — an
        // `.await`, not a blocking sleep, so it never stalls this test's own async executor (in
        // particular, the `run_inbound_loop` task under test, spawned onto the same runtime, keeps
        // making progress the whole time).
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Spawns a real, in-process `meridian-rendezvous` server on `bind_addr` (a fresh, empty
/// `MemoryStore` every time — never carried over from a prior server on the same address), exactly
/// like [`spawn_server`] except bindable to a caller-chosen fixed address and returning a
/// [`KillableServer`] instead of running forever. Reports a bind failure back through the result
/// rather than panicking inside the spawned thread, so [`spawn_server_restart`] can retry.
fn try_spawn_server_at(bind_addr: SocketAddr) -> Result<(String, KillableServer), String> {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<Result<SocketAddr, String>>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let store = std::sync::Arc::new(MemoryStore::new());
            let config = Config::default();
            let state = AppState::new(config, store);
            match tokio::net::TcpListener::bind(bind_addr).await {
                Ok(listener) => {
                    let actual = listener.local_addr().unwrap();
                    let _ = addr_tx.send(Ok(actual));
                    tokio::select! {
                        _ = serve(state, listener) => {}
                        _ = shutdown_rx => {}
                    }
                }
                Err(e) => {
                    let _ = addr_tx.send(Err(e.to_string()));
                }
            }
        });
        // `rt` drops here, at thread exit, forcibly ending every task it was still driving —
        // including any live WebSocket connection — and closing their sockets.
    });
    let actual = addr_rx
        .recv()
        .map_err(|_| "server thread hung up before reporting a bind result".to_string())??;
    Ok((
        format!("ws://{actual}"),
        KillableServer {
            addr: actual,
            shutdown: Some(shutdown_tx),
        },
    ))
}

fn spawn_server_at(addr: Option<SocketAddr>) -> (String, KillableServer) {
    let bind_addr = addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    try_spawn_server_at(bind_addr)
        .expect("bind must succeed for a fresh ephemeral/explicit address")
}

/// Rebinds `addr` for a fresh server, retrying briefly: a just-killed listener's port is not
/// guaranteed to be immediately available for a new bind on every platform/kernel, even though
/// [`KillableServer::kill`] already waits out the common case.
async fn spawn_server_restart(addr: SocketAddr) -> (String, KillableServer) {
    for attempt in 1..=20u32 {
        match try_spawn_server_at(addr) {
            Ok(pair) => return pair,
            Err(e) if attempt < 20 => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = e;
            }
            Err(e) => panic!("could not rebind {addr} after {attempt} attempts: {e}"),
        }
    }
    unreachable!("loop above always either returns or panics")
}

// ---------------------------------------------------------------------------
// Account fixtures
// ---------------------------------------------------------------------------

const SERVICE: &str = "meridian-tui-inbound-test";

/// Mints a real OS-keystore-backed "us" account (against the mock keystore) and saves its real
/// `account.json` — the exact shape `worker::inbound_handoff`/`open_account_store` re-derive their
/// `SecretStore`/`KeyHandle` from.
fn setup_us_account() -> (KeyHandle, [u8; 32]) {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "self.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    (account.handle().clone(), *account.public_key().as_bytes())
}

/// Publishes a real, signature-valid bundle for "us" — so a peer can X3DH-initiate toward it — and
/// persists the matching prekey *secrets* into a real, sealed `sessions.bin`, so a later inbound
/// X3DH message actually has a matching vault entry to open against. Mirrors
/// `apps/cli/src/chat.rs::run`'s own publish step (`publish_bundle` immediately followed by
/// `state.vault.set_bundle(...)` and a `save_state`) exactly — `worker::run_inbound_loop` itself does
/// not publish a bundle at all (out of this task's scope — see that function's own module doc), so a
/// live test has to do the equivalent of onboarding's own `Effect::PublishBundle` step (which
/// likewise never threads the secrets into a `ChatState`/`sessions.bin` — see `worker::
/// handle_publish_bundle`'s own scope) itself, once, before the persistent loop can receive anything.
async fn publish_own_bundle(server: &str, handle: &KeyHandle, account_pub: [u8; 32]) {
    let os = OsSecretStore::new(SERVICE);
    let mut client = SignalingClient::connect(server, &os, handle, account_pub, None, 1)
        .await
        .expect("us connect to publish");
    let generated = client
        .publish_bundle(&os, handle, 8)
        .await
        .expect("us publish_bundle");
    let _ = client.close().await;

    let otks: Vec<([u8; 32], [u8; 32])> = generated
        .bundle
        .otks
        .iter()
        .zip(generated.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    let mut chat = CoreChatState::default();
    chat.vault.set_bundle(
        generated.bundle.spk,
        *generated.spk_secret,
        otks,
        1_760_000_000,
    );
    let sealed = chat.seal_at_rest(&os, handle).expect("seal sessions.bin");
    let path = meridian_core::account::sessions_path().expect("sessions_path");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create sessions.bin parent dir");
    }
    std::fs::write(&path, sealed).expect("write sessions.bin");
}

/// A fresh, independent peer identity — ordering relative to "us" does not matter here: the peer is
/// always the one reaching out (fetching "us"'s bundle and X3DH-initiating), never the other way
/// around, unlike `tests/run_worker_chat.rs`'s own outbound-focused fixtures.
fn generate_peer() -> (MemorySecretStore, AccountId) {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "peer.example").expect("peer generate_account");
    (store, account)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Drains `rx` until an [`AppEvent::Inbound`] arrives (skipping any interleaved
/// [`AppEvent::ConnectionStatus`] pushes — the loop always emits `Connected` right after connecting),
/// or the overall `timeout` elapses. `None` on timeout/closed channel, never a panic — callers decide
/// what "nothing arrived" should mean for their own test.
async fn recv_inbound(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    timeout: Duration,
) -> Option<InboundEvent> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(AppEvent::Inbound(event))) => return Some(*event),
            Ok(Some(AppEvent::ConnectionStatus(_))) => continue,
            Ok(Some(_)) | Ok(None) | Err(_) => return None,
        }
    }
}

/// Drains `rx` until the next [`AppEvent::ConnectionStatus`] arrives (skipping any interleaved
/// [`AppEvent::Inbound`] pushes), or `timeout` elapses. `None` on timeout/closed channel.
async fn recv_status(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    timeout: Duration,
) -> Option<meridian_tui::statusbar::ConnectionState> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(AppEvent::ConnectionStatus(state))) => return Some(state),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

/// Drains `rx`, skipping every [`AppEvent::ConnectionStatus::Reconnecting`]/[`AppEvent::Inbound`]
/// push, until a [`ConnectionState::Connected`] status arrives or `timeout` elapses.
async fn recv_connected(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    timeout: Duration,
) -> bool {
    use meridian_tui::statusbar::ConnectionState;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(AppEvent::ConnectionStatus(ConnectionState::Connected))) => return true,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return false,
        }
    }
}

fn spawn_inbound_loop(
    handle: KeyHandle,
    account_pub: [u8; 32],
    server: &str,
) -> tokio::sync::mpsc::UnboundedReceiver<AppEvent> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let os: std::sync::Arc<dyn meridian_core::identity::SecretStore> =
        std::sync::Arc::new(OsSecretStore::new(SERVICE));
    tokio::spawn(run_inbound_loop(
        os,
        handle,
        account_pub,
        server.to_string(),
        vec![50, 100],
        tx,
    ));
    rx
}

async fn dispatch_effect(effect: Effect) -> meridian_tui::app::WorkerEvent {
    let mut session = OnboardingSession::default();
    dispatch(effect, &mut session).await
}

/// Writes `$MERIDIAN_HOME/tui/config.toml` naming `server` — `worker::resolve_server`'s only source
/// for the rendezvous URL an outbound `Effect::SendMessage` dispatch connects to. Mirrors
/// `tests/run_worker_chat.rs::write_server_config` exactly (this file otherwise never dispatches an
/// outbound send, so it never needed this helper before).
fn write_server_config(home: &Path, server: &str) {
    let path = home.join("tui").join("config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).expect("create tui config dir");
    std::fs::write(&path, format!("[account]\nserver = \"{server}\"\n"))
        .expect("write config.toml");
}

/// Peer-side: fetch "us"'s bundle, X3DH-initiate, seal `body` as `ChatContent::Text`, and route it —
/// the peer's own first-contact send, mirroring `apps/cli/src/chat.rs::run`'s initiator path.
async fn peer_send_first_contact(
    server: &str,
    peer_store: &MemorySecretStore,
    peer_account: &AccountId,
    us_pub: [u8; 32],
    body: &str,
) -> (CoreChatState, SignalingClient, [u8; 16]) {
    let mut client = SignalingClient::connect(
        server,
        peer_store,
        peer_account.handle(),
        *peer_account.public_key().as_bytes(),
        None,
        1,
    )
    .await
    .expect("peer connect");
    let bundle = client
        .fetch_bundle(us_pub, None, false)
        .await
        .expect("peer fetch us bundle");
    let mut chat = CoreChatState::default();
    chat.start_initiator_session(
        peer_store,
        peer_account.handle(),
        peer_account.public_key().as_bytes(),
        &us_pub,
        &bundle.spk,
        bundle.otks.first().copied(),
    )
    .expect("peer start_initiator_session");
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("random id");
    let blob = chat
        .seal_outbound(
            peer_store,
            peer_account.handle(),
            peer_account.public_key().as_bytes(),
            &us_pub,
            &ChatContent::Text {
                id,
                body: body.to_string(),
            },
        )
        .expect("peer seal_outbound first contact");
    client
        .route_with_hint(us_pub, None, blob)
        .await
        .expect("peer route first contact");
    (chat, client, id)
}

/// Peer-side, on an already-established session: seal and route another `ChatContent::Text`.
async fn peer_send_text(
    peer_store: &MemorySecretStore,
    peer_account: &AccountId,
    us_pub: [u8; 32],
    chat: &mut CoreChatState,
    client: &mut SignalingClient,
    body: &str,
) -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("random id");
    let blob = chat
        .seal_outbound(
            peer_store,
            peer_account.handle(),
            peer_account.public_key().as_bytes(),
            &us_pub,
            &ChatContent::Text {
                id,
                body: body.to_string(),
            },
        )
        .expect("peer seal_outbound");
    client
        .route_with_hint(us_pub, None, blob)
        .await
        .expect("peer route");
    id
}

/// Full setup for tests that need an already-*accepted* conversation (not just a queued request):
/// peer sends the opening message request, "us" runs the real accept effect, returns everything a
/// follow-up `peer_send_text` needs.
async fn establish_accepted_conversation(
    server: &str,
    handle: &KeyHandle,
    us_pub: [u8; 32],
) -> (
    tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    MemorySecretStore,
    AccountId,
    CoreChatState,
    SignalingClient,
) {
    let rx = spawn_inbound_loop(handle.clone(), us_pub, server);
    let (peer_store, peer_account) = generate_peer();
    let peer_pub = *peer_account.public_key().as_bytes();

    let (peer_chat, peer_client, _first_id) =
        peer_send_first_contact(server, &peer_store, &peer_account, us_pub, "hi, it's me").await;

    let mut rx = rx;
    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("message request must arrive");
    assert!(matches!(
        event,
        InboundEvent::MessageRequest(ref e) if e.sender_ik == peer_pub
    ));

    let outcome = dispatch_effect(Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: peer_pub,
        },
        outcome: None,
    }))
    .await;
    assert!(
        matches!(
            outcome,
            meridian_tui::app::WorkerEvent::Completed(Effect::AcceptRequest(_))
        ),
        "accept must succeed: {outcome:?}"
    );

    (rx, peer_store, peer_account, peer_chat, peer_client)
}

fn key(
    code: crossterm::event::KeyCode,
    modifiers: crossterm::event::KeyModifiers,
) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, modifiers)
}

// ---------------------------------------------------------------------------
// (a) message request surfaces on next Ctrl-R when Screen::Requests isn't open
// ---------------------------------------------------------------------------

#[tokio::test]
async fn message_request_surfaces_via_ctrl_r_when_requests_screen_is_not_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let mut rx = spawn_inbound_loop(handle, us_pub, &server);

    let (peer_store, peer_account) = generate_peer();
    let peer_pub = *peer_account.public_key().as_bytes();
    let _peer = peer_send_first_contact(
        &server,
        &peer_store,
        &peer_account,
        us_pub,
        "hello from peer",
    )
    .await;

    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("a message request must arrive over the persistent connection");
    let entry = match event {
        InboundEvent::MessageRequest(entry) => entry,
        other => panic!("expected InboundEvent::MessageRequest, got {other:?}"),
    };
    assert_eq!(entry.sender_ik, peer_pub);
    assert!(!entry.safety_number.is_empty());

    // Route it into a real, otherwise-idle App — Screen::Requests is not open (App starts on
    // Onboarding).
    let mut app = App::new();
    assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::MessageRequest(
        entry.clone(),
    ))));
    assert!(effects.is_empty(), "a queued request dispatches no effect");
    assert_eq!(app.pending_inbound_request_count(), 1);

    // Ctrl-R surfaces it.
    app.update(AppEvent::Key(key(
        crossterm::event::KeyCode::Char('r'),
        crossterm::event::KeyModifiers::CONTROL,
    )));
    match app.current_screen() {
        Screen::Requests(state) => {
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.entries[0].sender_ik, peer_pub);
        }
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
    assert_eq!(
        app.pending_inbound_request_count(),
        0,
        "draining into Screen::Requests must clear the pending buffer"
    );
}

// ---------------------------------------------------------------------------
// (b) inbound chat message while Screen::Chat is open appends live, persists, and dedups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inbound_text_message_while_chat_open_appends_live_and_persists() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let (mut rx, peer_store, peer_account, mut peer_chat, mut peer_client) =
        establish_accepted_conversation(&server, &handle, us_pub).await;
    let peer_pub = *peer_account.public_key().as_bytes();

    peer_send_text(
        &peer_store,
        &peer_account,
        us_pub,
        &mut peer_chat,
        &mut peer_client,
        "second message, now on an accepted session",
    )
    .await;

    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("the follow-up text message must arrive");
    let (event_peer, entry) = match event {
        InboundEvent::Message { peer_pubkey, entry } => (peer_pubkey, entry),
        other => panic!("expected InboundEvent::Message, got {other:?}"),
    };
    assert_eq!(event_peer, peer_pub);
    assert_eq!(entry.body, "second message, now on an accepted session");
    assert_eq!(entry.dir, MsgDirection::In);
    assert_eq!(entry.state, MessageState::Received);

    // Route it into a real App with Screen::Chat open for this exact peer.
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(TuiChatState::new(
        peer_pub,
        peer_account.hint().to_string(),
        TrustStore::default(),
        Vec::new(),
        0,
    ))));
    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: peer_pub,
        entry: entry.clone(),
    })));

    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(state.entries.len(), 1, "message must append live");
            assert_eq!(state.entries[0].body, entry.body);
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
    let persist = effects
        .iter()
        .find_map(|e| match e {
            Effect::PersistHistory(p) => Some(p.clone()),
            _ => None,
        })
        .expect("a live-appended inbound message must dispatch Effect::PersistHistory");
    assert_eq!(persist.request.peer_pubkey, peer_pub);
    assert_eq!(persist.request.entry.mid, entry.mid);

    // Actually persist it (mirrors the real worker round trip) and confirm it survives on disk.
    let outcome = dispatch_effect(Effect::PersistHistory(persist)).await;
    assert!(matches!(
        outcome,
        meridian_tui::app::WorkerEvent::Completed(Effect::PersistHistory(_))
    ));
    let peer_pub_hex = hex::encode(peer_pub);
    let os = OsSecretStore::new(SERVICE);
    let saved = meridian_tui::store::history::load_or_default(&peer_pub_hex, &os, &handle)
        .expect("load history");
    // Task 4.49: `establish_accepted_conversation`'s own `Effect::AcceptRequest` now also persists
    // the peer's first-contact intro ("hi, it's me") into this same `history.jsonl` — a real,
    // separate write this test's own fixture triggers, not something this test drives itself. So
    // this second, live-appended message lands as entry index 1, not 0; `saved.len()` is 2, not 1.
    assert_eq!(
        saved.len(),
        2,
        "expected the accepted intro plus this second message"
    );
    assert_eq!(saved[0].dir, MsgDirection::In);
    assert_eq!(saved[0].body, "hi, it's me");
    assert_eq!(saved[1].mid, entry.mid);
    assert_eq!(saved[1].body, entry.body);
}

/// Deliverable (b)'s own dedup requirement: an inbound message racing a *already-applied* outbound
/// `PersistHistory` (or an earlier inbound apply) that happens to share the same `mid` must not be
/// double-appended and must not dispatch a second `Effect::PersistHistory` — proves
/// `crate::screens::chat::insert_deduped` (reused unchanged by `handle_inbound_message`) is genuinely
/// keyed only on `mid`, not on direction, exactly as this crate's own module doc always promised.
#[tokio::test]
async fn a_racing_outbound_persist_history_dedups_against_a_same_mid_inbound_message() {
    let peer_pub = [7u8; 32];
    let racing_mid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

    // Simulate an already-applied racing outbound send: the exact same `mid` is already present in
    // `entries` (e.g. `complete_send` already inserted it moments earlier, on the same event loop
    // tick — plausible if a locally-sent echo or a retried delivery ever produced the same id).
    let existing = HistoryEntry {
        v: meridian_tui::store::history::CURRENT_VERSION,
        mid: racing_mid.clone(),
        dir: MsgDirection::Out,
        ts: 1_760_000_000,
        stream: "mrd.chat/1".to_string(),
        body: "already here".to_string(),
        state: MessageState::Delivered,
    };
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(TuiChatState::new(
        peer_pub,
        "peer.example".to_string(),
        TrustStore::default(),
        vec![existing.clone()],
        0,
    ))));

    let racing_inbound = HistoryEntry {
        v: meridian_tui::store::history::CURRENT_VERSION,
        mid: racing_mid.clone(),
        dir: MsgDirection::In,
        ts: 1_760_000_001,
        stream: "mrd.chat/1".to_string(),
        body: "a same-mid inbound race".to_string(),
        state: MessageState::Received,
    };
    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: peer_pub,
        entry: racing_inbound,
    })));

    assert!(
        effects.is_empty(),
        "a duplicate mid must never dispatch a second Effect::PersistHistory"
    );
    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(state.entries.len(), 1, "no duplicate row");
            assert_eq!(
                state.entries[0], existing,
                "the original entry is untouched"
            );
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// (c) a malformed/adversarial inbound envelope is dropped, never crashes the loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_inbound_envelope_is_dropped_and_the_loop_keeps_running() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let (mut rx, peer_store, peer_account, mut peer_chat, mut peer_client) =
        establish_accepted_conversation(&server, &handle, us_pub).await;

    // Adversarial: route a completely malformed blob, never routed through `seal_outbound` at all —
    // not even valid envelope framing, let alone a valid signature.
    peer_client
        .route_with_hint(
            us_pub,
            None,
            b"not a real envelope at all -- adversarial garbage".to_vec(),
        )
        .await
        .expect("route the malformed blob (server accepts any opaque bytes)");

    // Nothing should surface from this one — the loop drops it silently (logged, not forwarded).
    let nothing = recv_inbound(&mut rx, Duration::from_millis(600)).await;
    assert!(
        nothing.is_none(),
        "a malformed envelope must never surface as an InboundEvent, got {nothing:?}"
    );

    // The loop must still be alive and correctly processing further, legitimate input.
    peer_send_text(
        &peer_store,
        &peer_account,
        us_pub,
        &mut peer_chat,
        &mut peer_client,
        "still here after the garbage",
    )
    .await;
    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("a legitimate message after the malformed one must still arrive");
    match event {
        InboundEvent::Message { entry, .. } => {
            assert_eq!(entry.body, "still here after the garbage");
        }
        other => panic!("expected InboundEvent::Message, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// (d) auto-ack is never gated by SendGate
// ---------------------------------------------------------------------------

/// Falsifiable version of "the auto-ack path is unreachable from any gated send call site" — mirrors
/// `tests/run_worker_chat.rs::send_succeeds_even_though_trust_bin_marks_the_peer_blocked`'s exact
/// pattern, one direction earlier: seeds a real, sealed `trust.bin` marking the sender **locally
/// blocked** before the peer sends, and asserts the auto-ack still goes out and the message still
/// surfaces. `worker::process_inbound_delivery` has no `TrustStore` handle in scope at all to have
/// gated the ack with in the first place (it only ever reads `trust.bin`, read-only, to resolve a
/// federation routing hint) — this is the structural fact this test makes falsifiable.
#[tokio::test]
async fn auto_ack_still_replies_even_though_trust_bin_marks_the_sender_blocked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let (mut rx, peer_store, peer_account, mut peer_chat, mut peer_client) =
        establish_accepted_conversation(&server, &handle, us_pub).await;
    let peer_pub = *peer_account.public_key().as_bytes();

    // Lock the sender out via a real SetUserBlocked effect — the exact same write path
    // `Screen::ContactDetail`'s block action would dispatch.
    let outcome = dispatch_effect(Effect::SetUserBlocked(SetUserBlockedEffect {
        request: SetUserBlockedRequest {
            pubkey: peer_pub,
            blocked: true,
        },
        outcome: None,
    }))
    .await;
    assert!(matches!(
        outcome,
        meridian_tui::app::WorkerEvent::Completed(Effect::SetUserBlocked(_))
    ));

    let id = peer_send_text(
        &peer_store,
        &peer_account,
        us_pub,
        &mut peer_chat,
        &mut peer_client,
        "can you still hear me?",
    )
    .await;

    // The message still surfaces to the app — receiving is never gated by SendGate.
    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("the message must still be delivered to the app despite the local block");
    assert!(matches!(event, InboundEvent::Message { .. }));

    // And the auto-ack receipt still arrives back at the peer, addressed to the acknowledged id.
    let deliver = tokio::time::timeout(Duration::from_secs(10), peer_client.next_deliver())
        .await
        .expect("timed out waiting for the auto-ack receipt")
        .expect("next_deliver for the receipt");
    let content = peer_chat
        .open_inbound(
            &peer_store,
            peer_account.handle(),
            peer_account.public_key().as_bytes(),
            &deliver.from,
            deliver.blob.as_bytes(),
        )
        .expect("the auto-ack receipt must open cleanly");
    match content {
        ChatContent::Receipt { ack } => assert_eq!(ack, id),
        other => panic!("expected a Receipt acknowledging {id:?}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Regression: an outbound reply to a message-request-accepted contact (blank hint) must route as
// local delivery, never misroute as a federation attempt against domain "".
// ---------------------------------------------------------------------------

/// This task's own named demo scenario is "peer sends a message request -> we accept -> both sides
/// chat." The reply half of that ("both sides chat") sends outbound through
/// `worker::run_send_message`'s `route_tolerant`, fed directly from `SendMessageRequest.peer_hint`
/// (`apps/tui/src/screens/chat.rs::dispatch_gated_send` sets this unconditionally from
/// `state.peer_hint`, with no emptiness check of its own). A contact accepted via
/// `Effect::AcceptRequest` is TOFU-pinned with a **blank** hint (`run_accept_request`'s own
/// documented "`MessageRequest` carries no advisory hint" contract) — exactly the identical latent
/// bug this task's own auto-ack path had (see
/// `auto_ack_still_replies_even_though_trust_bin_marks_the_sender_blocked`'s own doc comment above),
/// just on the ordinary outbound send path instead. Before `worker::sanitize_routing_hint` was
/// applied at `route_tolerant`'s own call site, a blank hint was
/// forwarded verbatim as `Some(String::new())`, which `meridian-rendezvous`'s `handle_route` treats
/// as *any* non-matching hint being a foreign-domain federation attempt rather than local delivery —
/// silently misrouting every reply to a message-request-originated contact in a real deployment.
#[tokio::test]
async fn reply_to_a_message_request_accepted_contact_with_a_blank_hint_routes_locally() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;
    write_server_config(tmp.path(), &server);

    let (_rx, _peer_store, peer_account, _peer_chat, mut peer_client) =
        establish_accepted_conversation(&server, &handle, us_pub).await;
    let peer_pub = *peer_account.public_key().as_bytes();

    // "us" replies with the exact blank hint `dispatch_gated_send` actually produces for a contact
    // accepted this way — never a non-empty hint like every `send_request` call site in
    // `tests/run_worker_chat.rs`.
    let outcome = dispatch_effect(Effect::SendMessage(SendMessageEffect {
        request: SendMessageRequest {
            peer_pubkey: peer_pub,
            peer_hint: String::new(),
            body: "welcome, now both sides chat".to_string(),
        },
        outcome: None,
    }))
    .await;
    let sent = match outcome {
        meridian_tui::app::WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => sent,
        other => panic!("expected a completed SendMessage, got {other:?}"),
    };
    assert!(
        sent.delivered,
        "the peer is connected right now: a blank hint must route as local delivery, not a \
         federation attempt against domain \"\" (which would report delivered: false or fail \
         closed outright)"
    );

    let deliver = tokio::time::timeout(Duration::from_secs(10), peer_client.next_deliver())
        .await
        .expect("timed out waiting for the reply to arrive at the peer")
        .expect("next_deliver for the reply");
    assert_eq!(deliver.from, us_pub);
}

// ---------------------------------------------------------------------------
// (test-engineer follow-up) reconnect-with-backoff: attempt counting, clamping,
// `AppEvent::ConnectionStatus` emission, and resumed inbound forwarding after a real reconnect.
// ---------------------------------------------------------------------------

/// `worker::run_inbound_loop`'s reconnect-with-backoff logic previously had no functional test —
/// the only test touching `ConnectionState::Reconnecting` was `statusbar.rs`'s own pure rendering
/// test, which never touches `run_inbound_loop` at all. This drives the real loop against a real,
/// in-process server: connect, observe `Connected`, kill the server connection outright (drop the
/// listener's whole Tokio runtime, not a clean WS close), observe escalating-then-clamped
/// `Reconnecting { attempt, max }` statuses with `backoff_ms: vec![50, 100]` (`max == 2`), restart a
/// fresh server bound to the *identical* address, observe `Connected` again, then confirm the loop
/// still correctly forwards a subsequently delivered message.
///
/// **What this covers vs. what's still open** (see this task's own file's Status section for the
/// authoritative version of this note): this is as close to "kill and restart on the same address"
/// as this harness supports — the killed server's whole OS thread/Tokio runtime is dropped (a real
/// severed-TCP-connection outage, not a graceful shutdown), and the replacement server rebinds the
/// exact same `SocketAddr` (with a short retry loop for the rare case the port isn't immediately
/// free again) rather than a different one, since `run_inbound_loop` is handed one fixed server URL
/// for its whole call and has no way to be redirected mid-flight. Not covered: OS-level partial
/// failures short of a full connection drop (e.g. a half-open TCP connection that never sends a
/// FIN/RST), and backoff timing precision beyond "escalates, then clamps at `max`" — this test
/// asserts ordering/values, not wall-clock delay accuracy.
#[tokio::test]
async fn reconnect_with_backoff_escalates_then_recovers_and_resumes_forwarding_inbound() {
    use meridian_tui::statusbar::ConnectionState;

    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, first_server) = spawn_server_at(None);
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let mut rx = spawn_inbound_loop(handle.clone(), us_pub, &server);

    // Initial connect succeeds.
    let initial = recv_status(&mut rx, Duration::from_secs(5))
        .await
        .expect("an initial ConnectionStatus must arrive");
    assert_eq!(initial, ConnectionState::Connected);

    // Sever the connection outright — a real outage, not a clean close.
    let addr = first_server.addr;
    first_server.kill().await;

    // Escalating attempts, then clamped at `max` (backoff has 2 steps here).
    let s1 = recv_status(&mut rx, Duration::from_secs(5))
        .await
        .expect("first Reconnecting status must arrive");
    assert_eq!(s1, ConnectionState::Reconnecting { attempt: 1, max: 2 });

    let s2 = recv_status(&mut rx, Duration::from_secs(5))
        .await
        .expect("second Reconnecting status must arrive");
    assert_eq!(s2, ConnectionState::Reconnecting { attempt: 2, max: 2 });

    let s3 = recv_status(&mut rx, Duration::from_secs(5))
        .await
        .expect("a third Reconnecting status must arrive, proving the loop never gives up");
    assert_eq!(
        s3,
        ConnectionState::Reconnecting { attempt: 2, max: 2 },
        "attempt must clamp at max rather than growing past it"
    );

    // Restart a fresh server on the identical address and confirm the loop actually reconnects.
    let (restarted, _second_server) = spawn_server_restart(addr).await;
    assert_eq!(
        restarted, server,
        "must rebind the identical address the loop is retrying"
    );
    publish_own_bundle(&restarted, &handle, us_pub).await;

    assert!(
        recv_connected(&mut rx, Duration::from_secs(10)).await,
        "the loop must reconnect and report Connected once the server is back"
    );

    // And it still correctly forwards a subsequently delivered message.
    let (peer_store, peer_account) = generate_peer();
    let peer_pub = *peer_account.public_key().as_bytes();
    let _peer = peer_send_first_contact(
        &restarted,
        &peer_store,
        &peer_account,
        us_pub,
        "hello after reconnect",
    )
    .await;

    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("a message request must still arrive over the reconnected loop");
    match event {
        InboundEvent::MessageRequest(entry) => assert_eq!(entry.sender_ik, peer_pub),
        other => panic!("expected InboundEvent::MessageRequest, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// (task 4.51) spawn_blocking concurrency proof: a slow `SecretStore` must not freeze this
// current-thread runtime's other tasks while `run_inbound_loop` signs its handshake.
// ---------------------------------------------------------------------------

/// Wraps any [`meridian_core::identity::SecretStore`] and adds a fixed, real
/// (`std::thread::sleep`, not `tokio::time::sleep` — this must actually occupy a thread, mirroring
/// `FileSecretStore::decrypt_seed`'s own real synchronous scrypt cost) delay to every
/// `use_key`/`derive_key` call — a controllable stand-in for a passphrase-wrapped keyfile's
/// age/scrypt unwrap, without needing a real one (this task's own Status section separately
/// measures the real `FileSecretStore` cost directly).
struct SlowStore {
    inner: OsSecretStore,
    delay: Duration,
}

impl SlowStore {
    fn new(inner: OsSecretStore, delay: Duration) -> Self {
        Self { inner, delay }
    }
}

impl meridian_core::identity::SecretStore for SlowStore {
    fn store(
        &self,
        label: &str,
        secret: &[u8],
    ) -> Result<KeyHandle, meridian_core::identity::StoreError> {
        self.inner.store(label, secret)
    }

    fn use_key(
        &self,
        h: &KeyHandle,
        op: meridian_core::identity::SignOrDh,
        input: &[u8],
    ) -> Result<Vec<u8>, meridian_core::identity::StoreError> {
        std::thread::sleep(self.delay);
        self.inner.use_key(h, op, input)
    }

    fn nonextractable(&self) -> bool {
        self.inner.nonextractable()
    }

    fn derive_key(
        &self,
        h: &KeyHandle,
        info: &[u8],
    ) -> Result<[u8; 32], meridian_core::identity::StoreError> {
        std::thread::sleep(self.delay);
        self.inner.derive_key(h, info)
    }
}

/// **Falsifiable concurrency proof (task 4.51 Deliverable 6).** Before this task,
/// `run_inbound_loop` called `SignalingClient::connect`'s handshake `sign()` directly on its own
/// task — under `apps/cli/src/main.rs`'s real `current_thread` runtime (this test uses the same
/// flavor: `#[tokio::test]`'s default), that synchronous call would occupy the *only* OS thread the
/// whole runtime has, so a concurrently spawned lightweight task could make **no** progress at all
/// for the call's whole duration. After this task, the same signing call runs inside
/// `tokio::task::spawn_blocking` (`SignalingClient::connect_owned`/`handshake_owned`) —
/// `spawn_blocking` hands the work to Tokio's separate blocking-thread pool, freeing this runtime's
/// own thread to keep polling other tasks. This test proves that concretely: with a [`SlowStore`]
/// sleeping for 300ms on every `use_key` call, a concurrently spawned "heartbeat" task ticking every
/// 10ms must accumulate several ticks *during* `run_inbound_loop`'s own connect+handshake — not zero,
/// and not only after it completes. Reverting the fix (calling `sign()` synchronously again) makes
/// this test fail with an observed tick count of 0 or 1 — falsified, not vacuous.
#[tokio::test]
async fn run_inbound_loops_handshake_never_freezes_a_concurrently_scheduled_task() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let slow = SlowStore::new(OsSecretStore::new(SERVICE), Duration::from_millis(300));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_inbound_loop(
        std::sync::Arc::new(slow),
        handle,
        us_pub,
        server,
        vec![50, 100],
        tx,
    ));

    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticks_writer = ticks.clone();
    let heartbeat = tokio::spawn(async move {
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ticks_writer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    // Wait for the loop to actually connect (which, even fixed, still takes at least the ~300ms
    // the slow store's one handshake `use_key` call sleeps for).
    let connected = recv_connected(&mut rx, Duration::from_secs(5)).await;
    assert!(
        connected,
        "the loop must still reach Connected, just not synchronously"
    );

    let observed = ticks.load(std::sync::atomic::Ordering::SeqCst);
    heartbeat.abort();
    assert!(
        observed >= 8,
        "expected the concurrently-scheduled heartbeat task to have ticked at least ~8 times \
         (out of up to 30 possible in the ~300ms slow-store window) while run_inbound_loop's own \
         handshake sign() was in flight — observed {observed}. A near-zero count here is exactly \
         what an un-`spawn_blocking`'d synchronous sign() call would produce on this \
         `current_thread` runtime: this is the falsifiable regression this task's fix must prevent."
    );
}

/// The same falsifiable shape as
/// [`run_inbound_loops_handshake_never_freezes_a_concurrently_scheduled_task`], targeting
/// `process_inbound_delivery`'s own blocking crypto (`load_chat`'s `derive_key`, `open_inbound`'s
/// X3DH `use_key`, `save_chat`'s `derive_key` — three [`SlowStore`] calls, not one) instead of the
/// handshake — the exact defect this task exists to fix: a genuine first-contact envelope's decrypt
/// work must not freeze the runtime a concurrently-scheduled task depends on.
#[tokio::test]
async fn process_inbound_deliverys_crypto_never_freezes_a_concurrently_scheduled_task() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let slow = SlowStore::new(OsSecretStore::new(SERVICE), Duration::from_millis(200));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_inbound_loop(
        std::sync::Arc::new(slow),
        handle,
        us_pub,
        server.clone(),
        vec![50, 100],
        tx,
    ));
    assert!(
        recv_connected(&mut rx, Duration::from_secs(5)).await,
        "loop must connect before the peer can deliver anything"
    );

    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticks_writer = ticks.clone();
    let heartbeat = tokio::spawn(async move {
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ticks_writer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let (peer_store, peer_account) = generate_peer();
    let _peer = peer_send_first_contact(
        &server,
        &peer_store,
        &peer_account,
        us_pub,
        "task-4.51 concurrency probe",
    )
    .await;

    let event = recv_inbound(&mut rx, Duration::from_secs(5))
        .await
        .expect("the first-contact request must still arrive with a slow store");
    assert!(matches!(event, InboundEvent::MessageRequest(_)));

    let observed = ticks.load(std::sync::atomic::Ordering::SeqCst);
    heartbeat.abort();
    assert!(
        observed >= 20,
        "expected the concurrently-scheduled heartbeat task to have ticked at least ~20 times \
         (out of up to 60 possible across the ~600ms three-call slow-store window: load_chat + \
         open_inbound + save_chat) while process_inbound_delivery's own blocking crypto was in \
         flight — observed {observed}. A near-zero count here is what running that crypto \
         synchronously on this `current_thread` runtime would produce."
    );
}

// ---------------------------------------------------------------------------
// (task 5.1) Review fix: `InboundEvent::Receipt` reconciliation + persistence
// ---------------------------------------------------------------------------
//
// Neither test below needs the real network/inbound-loop plumbing the rest of this file drives —
// mirrors `a_racing_outbound_persist_history_dedups_against_a_same_mid_inbound_message`'s own
// lighter-weight shape: a real `App`, fed a real, hand-constructed `AppEvent::Inbound(InboundEvent::
// Receipt { .. })` directly, exactly as `App::update` would receive it off the worker→App channel in
// production (`worker::process_inbound_delivery` builds the identical `InboundEvent::Receipt` shape
// from a real auto-ack — see deliverable (d) above for that half already being covered).

/// Renders `state` at 80x24 through the same `chat::render` entry point the real TUI draws with, and
/// returns the plain-text buffer contents — mirrors `tests/screens_chat.rs::render_chat_to_text`
/// exactly (not imported from there since integration test binaries in this crate are each their own
/// compilation unit with no shared `tests/common` module today).
fn render_chat_to_text(state: &TuiChatState) -> String {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| chat::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

fn out_entry(mid: &str, body: &str, state: MessageState) -> HistoryEntry {
    HistoryEntry {
        v: meridian_tui::store::history::CURRENT_VERSION,
        mid: mid.to_string(),
        dir: MsgDirection::Out,
        ts: 1_760_000_000,
        stream: "mrd.chat/1".to_string(),
        body: body.to_string(),
        state,
    }
}

/// **Deliverable 7 — the routing-bug fix.** Opens `Screen::Chat` for a peer with an already-`Sent`
/// outbound entry, navigates away (`Ctrl-R`'s own real effect: pushing `Screen::Requests` on top,
/// exactly like `message_request_surfaces_via_ctrl_r_when_requests_screen_is_not_open` above drives),
/// dispatches a real `AppEvent::Inbound(InboundEvent::Receipt { .. })` while `Screen::Chat` is
/// **not** topmost, then navigates back (`Esc`'s own real effect: popping `Screen::Requests` back
/// off) and asserts the double-tick `Delivered` marker actually renders.
///
/// Before this task's fix, `App::handle_inbound`'s `InboundEvent::Receipt` arm only ever checked
/// `self.screens.last_mut()`; with `Screen::Requests` on top, the receipt would have been silently
/// dropped and this test would still observe `MessageState::Sent` (a single tick) after navigating
/// back — falsifying the fix if it regresses.
#[test]
fn receipt_reconciles_into_a_chat_screen_that_is_not_topmost() {
    let peer_pub = [42u8; 32];
    let mid = "cccccccccccccccccccccccccccccc".to_string();

    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(TuiChatState::new(
        peer_pub,
        "peer.example".to_string(),
        TrustStore::default(),
        vec![out_entry(&mid, "hi", MessageState::Sent)],
        0,
    ))));

    // Navigate away: Screen::Chat is no longer `self.screens.last_mut()`.
    app.push_screen(Screen::Requests(Box::new(RequestsState::new(Vec::new()))));
    assert!(matches!(app.current_screen(), Screen::Requests(_)));

    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Receipt {
        peer_pubkey: peer_pub,
        ack: mid.clone(),
    })));

    // Deliverable 8's own precondition: persistence is dispatched unconditionally, regardless of
    // what's currently on top of the stack — checked in isolation by the next test, just asserted
    // present here too so this test alone would already catch a regression that drops it.
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::PersistReceipt(p) if p.request.peer_pubkey == peer_pub && p.request.ack == mid)),
        "a receipt must dispatch Effect::PersistReceipt even when Screen::Chat isn't topmost, got {effects:?}"
    );

    // Navigate back.
    app.pop_screen();
    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(
                state.entries[0].state,
                MessageState::Delivered,
                "the Sent row must have transitioned to Delivered even though Screen::Chat was not \
                 topmost when the receipt arrived"
            );
            let text = render_chat_to_text(state);
            assert!(
                text.contains("✓✓") || text.contains("vv"),
                "expected the double-tick Delivered marker to render, got:\n{text}"
            );
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// **Deliverable 8 — the persistence fix.** Drives the exact `Effect::PersistReceipt` a real
/// `InboundEvent::Receipt` dispatches through a real worker round trip
/// (`meridian_tui::worker::dispatch`), then reloads the peer's `history.jsonl` from scratch — the
/// same reader `Effect::LoadHistory`'s own execution uses — and confirms the reloaded entry still
/// reads `Delivered`, not `Sent`. Before this task's fix there was no persistence effect at all: a
/// freshly reloaded transcript would always show `Sent`, silently reverting whatever the live
/// in-memory transition had shown a moment before, exactly the restart-durability gap this task's own
/// file names.
#[tokio::test]
async fn receipt_delivered_state_survives_a_restart_via_load_history() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (handle, _us_pub) = setup_us_account();

    let peer_pub = [43u8; 32];
    let peer_pub_hex = hex::encode(peer_pub);
    let mid = "dddddddddddddddddddddddddddddd".to_string();

    // Seed history.jsonl with an already-persisted Sent entry — mirrors what a real
    // Effect::PersistHistory (complete_send's own dispatch) would already have written before any
    // receipt could plausibly arrive.
    let os = OsSecretStore::new(SERVICE);
    meridian_tui::store::history::append(
        &peer_pub_hex,
        &out_entry(&mid, "hi", MessageState::Sent),
        &os,
        &handle,
    )
    .expect("seed a Sent entry into history.jsonl");

    // Drive the App exactly as production does: a real App with Screen::Chat open, a real
    // AppEvent::Inbound(InboundEvent::Receipt) dispatch, and the real Effect::PersistReceipt it
    // returns, executed through the real worker.
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(TuiChatState::new(
        peer_pub,
        "peer.example".to_string(),
        TrustStore::default(),
        vec![out_entry(&mid, "hi", MessageState::Sent)],
        0,
    ))));
    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Receipt {
        peer_pubkey: peer_pub,
        ack: mid.clone(),
    })));
    let persist = effects
        .into_iter()
        .find_map(|e| match e {
            Effect::PersistReceipt(p) => Some(p),
            _ => None,
        })
        .expect("a receipt must dispatch Effect::PersistReceipt");

    let outcome = dispatch_effect(Effect::PersistReceipt(persist)).await;
    assert!(
        matches!(
            outcome,
            meridian_tui::app::WorkerEvent::Completed(Effect::PersistReceipt(_))
        ),
        "expected the real worker to complete Effect::PersistReceipt, got {outcome:?}"
    );

    // Simulate a restart: reload straight off disk with a fresh reader, exactly like
    // Effect::LoadHistory's own execution (worker::run_load_history) does.
    let reloaded = meridian_tui::store::history::load_or_default(&peer_pub_hex, &os, &handle)
        .expect("load history after the simulated restart");
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].mid, mid);
    assert_eq!(
        reloaded[0].state,
        MessageState::Delivered,
        "the Delivered transition must survive a restart, not revert to Sent"
    );
}

/// **Deliverable 9 — the zero-matching-screens case.** Unlike
/// [`receipt_reconciles_into_a_chat_screen_that_is_not_topmost`] (a `Screen::Chat` buried under
/// another screen), this drives a receipt against an `App` with **no** `Screen::Chat` anywhere on the
/// stack at all (the freshly constructed default: `Screen::Onboarding`) — the case
/// [`meridian_tui::app::PersistReceiptRequest`]'s own doc comment names directly: "a receipt for a
/// peer with no `Screen::Chat` currently open must still update `history.jsonl`". Confirms
/// `Effect::PersistReceipt` still comes back (nothing to reconcile in memory, but persistence is
/// unconditional) and, following [`receipt_delivered_state_survives_a_restart_via_load_history`]'s own
/// pattern, that a real `worker::dispatch` round trip actually lands `Delivered` in `history.jsonl`.
#[tokio::test]
async fn receipt_for_a_peer_with_no_chat_screen_open_still_persists() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (handle, _us_pub) = setup_us_account();

    let peer_pub = [44u8; 32];
    let peer_pub_hex = hex::encode(peer_pub);
    let mid = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();

    // Seed history.jsonl with an already-persisted Sent entry, exactly like
    // `receipt_delivered_state_survives_a_restart_via_load_history` does.
    let os = OsSecretStore::new(SERVICE);
    meridian_tui::store::history::append(
        &peer_pub_hex,
        &out_entry(&mid, "hi", MessageState::Sent),
        &os,
        &handle,
    )
    .expect("seed a Sent entry into history.jsonl");

    // No Screen::Chat anywhere on the stack — App::new()'s own default (Screen::Onboarding), not
    // even pushed over with Screen::Requests/Screen::Main like the not-topmost test does.
    let mut app = App::new();
    assert!(matches!(app.current_screen(), Screen::Onboarding(_)));

    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Receipt {
        peer_pubkey: peer_pub,
        ack: mid.clone(),
    })));
    let persist = effects
        .into_iter()
        .find_map(|e| match e {
            Effect::PersistReceipt(p) => Some(p),
            _ => None,
        })
        .expect(
            "a receipt must dispatch Effect::PersistReceipt even with zero Screen::Chat instances \
             on the stack",
        );
    assert_eq!(persist.request.peer_pubkey, peer_pub);
    assert_eq!(persist.request.ack, mid);

    let outcome = dispatch_effect(Effect::PersistReceipt(persist)).await;
    assert!(
        matches!(
            outcome,
            meridian_tui::app::WorkerEvent::Completed(Effect::PersistReceipt(_))
        ),
        "expected the real worker to complete Effect::PersistReceipt, got {outcome:?}"
    );

    let reloaded = meridian_tui::store::history::load_or_default(&peer_pub_hex, &os, &handle)
        .expect("load history after the round trip");
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].mid, mid);
    assert_eq!(
        reloaded[0].state,
        MessageState::Delivered,
        "history.jsonl must reflect Delivered even though no Screen::Chat was ever open for this peer"
    );
}

/// **Deliverable 10 — the disk-level unknown-`mid` no-op.** The in-memory equivalent
/// (`tests/screens_chat.rs::apply_receipt_for_an_unknown_mid_is_a_no_op`) already covers
/// `chat::apply_receipt` leaving a state's `entries` untouched; this covers
/// `store::history::mark_delivered_at`'s own documented disk-level contract — "a no-op (`Ok(())`, no
/// write at all)" — for a real `Effect::PersistReceipt` round trip whose `ack` never matches any `Out`
/// entry on disk. Compares the sealed file's raw bytes before and after, not just the decoded
/// `Vec<HistoryEntry>`: since [`meridian_tui::store::history::mark_delivered_at`] documents skipping
/// the reseal-and-rewrite entirely (not merely reproducing an equivalent ciphertext) when no matching
/// row is found, the file on disk must be byte-for-byte identical, nonce and all.
#[tokio::test]
async fn mark_delivered_for_an_unknown_mid_is_a_no_op_on_disk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (handle, _us_pub) = setup_us_account();

    let peer_pub = [45u8; 32];
    let peer_pub_hex = hex::encode(peer_pub);
    let persisted_mid = "ffffffffffffffffffffffffffffff".to_string();
    let unknown_mid = "11111111111111111111111111111111".to_string();

    let os = OsSecretStore::new(SERVICE);
    meridian_tui::store::history::append(
        &peer_pub_hex,
        &out_entry(&persisted_mid, "hi", MessageState::Sent),
        &os,
        &handle,
    )
    .expect("seed a Sent entry into history.jsonl");

    let path = meridian_tui::store::history_path(&peer_pub_hex).expect("history_path");
    let before = std::fs::read(&path).expect("read sealed history.jsonl before the receipt");

    // Drive the exact real path: an App with a Screen::Chat open for this peer (so the in-memory
    // half is exercised too, mirroring `apply_receipt_for_an_unknown_mid_is_a_no_op`'s own
    // "state.entries[0].state stays Sent" assertion), a real InboundEvent::Receipt whose `ack` was
    // never persisted, and the real Effect::PersistReceipt it dispatches, run through the real
    // worker.
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(TuiChatState::new(
        peer_pub,
        "peer.example".to_string(),
        TrustStore::default(),
        vec![out_entry(&persisted_mid, "hi", MessageState::Sent)],
        0,
    ))));
    let effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Receipt {
        peer_pubkey: peer_pub,
        ack: unknown_mid.clone(),
    })));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries[0].state,
            MessageState::Sent,
            "an unknown mid must not flip the unrelated persisted entry's in-memory state"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
    let persist = effects
        .into_iter()
        .find_map(|e| match e {
            Effect::PersistReceipt(p) => Some(p),
            _ => None,
        })
        .expect("a receipt must dispatch Effect::PersistReceipt even for an unknown mid");
    assert_eq!(persist.request.ack, unknown_mid);

    let outcome = dispatch_effect(Effect::PersistReceipt(persist)).await;
    assert!(
        matches!(
            outcome,
            meridian_tui::app::WorkerEvent::Completed(Effect::PersistReceipt(_))
        ),
        "expected the real worker to complete Effect::PersistReceipt, got {outcome:?}"
    );

    let after = std::fs::read(&path).expect("read sealed history.jsonl after the receipt");
    assert_eq!(
        before, after,
        "an unknown-mid receipt must not touch history.jsonl on disk at all, not even reseal an \
         equivalent document"
    );

    let reloaded = meridian_tui::store::history::load_or_default(&peer_pub_hex, &os, &handle)
        .expect("load history after the no-op");
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].mid, persisted_mid);
    assert_eq!(
        reloaded[0].state,
        MessageState::Sent,
        "the unrelated persisted entry must remain Sent, never flipped by an unknown-mid receipt"
    );
}

// ---------------------------------------------------------------------------
// Task 5.5 (review finding F5): receive-side desync recovery wired into `run_inbound_loop` —
// mirrors `apps/cli/src/chat.rs::maybe_attempt_recovery`'s gate discipline. This section proves the
// half of the property that is honestly reachable over a real network: repeated `Desync` against a
// contact already `Blocked` by an unresolved key change never bypasses `TrustStore::can_send`'s
// early gate to attempt an automatic re-handshake, and never mutates `trust.bin` at all — exactly
// mirroring `apps/core/tests/desync_recovery.rs`'s own `attempt_recovery`-level proof, now shown
// through the real `run_inbound_loop` this crate actually runs.
//
// The complementary half — that a genuine key *substitution* surfaced by a fresh bundle is detected
// and blocked (`TrustState::PinnedKeyChanged`/`Blocked`, `SendGate::Warn`/`Blocked`) — is proven at
// the `meridian-core` level in `apps/core/tests/session.rs`'s
// `recover_from_desync_warns_and_blocks_a_key_substitution_against_a_pinned_established_session`/
// `..._hard_blocks_..._verified_...`: `meridian_signaling::verify_bundle` pins a real
// `SignalingClient::fetch_bundle` response to the *exact requested* key, so a genuine on-the-wire
// substitution against an already-known peer fails closed at that fetch — structurally before this
// crate's own `attempt_worker_recovery` ever reaches `meridian_core::desync::attempt_recovery` at
// all (see that function's own doc comment) — making the substitution-detection half untestable
// honestly at this network-integration layer, and squarely `apps/core/tests/session.rs`'s job
// instead.
// ---------------------------------------------------------------------------

/// The real, sealed `trust.bin` for `handle`, as it stands on disk — mirrors [`setup_us_account`]'s
/// sibling helpers (`publish_own_bundle`'s own `sessions.bin` read/write) and
/// `tests/run_worker_trust.rs`'s own `write_trust`/(implicit) read pattern.
fn read_trust(handle: &KeyHandle) -> TrustStore {
    let os = OsSecretStore::new(SERVICE);
    let path = meridian_core::account::trust_path().expect("trust_path");
    let bytes = std::fs::read(&path).expect("read trust.bin");
    TrustStore::open_at_rest(&os, handle, &bytes).expect("open trust.bin")
}

/// Mirrors `tests/run_worker_trust.rs::write_trust` exactly.
fn write_trust(handle: &KeyHandle, trust: &TrustStore) {
    let os = OsSecretStore::new(SERVICE);
    let path = meridian_core::account::trust_path().expect("trust_path");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create trust.bin parent dir");
    }
    let sealed = trust.seal_at_rest(&os, handle).expect("seal trust.bin");
    std::fs::write(&path, sealed).expect("write trust.bin");
}

/// Corrupts an authentic envelope's ratchet header (a byte inside `enc_header`, past the 2-byte
/// length prefix) and re-signs it under the real sender's identity key — mirrors
/// `apps/core/tests/desync_recovery.rs::mangle_and_resign` exactly: authentic (passes signature
/// verification) but undecryptable (`ChatError::Desync`), never a forged sender.
fn mangle_and_resign(
    peer_store: &MemorySecretStore,
    peer_account: &AccountId,
    blob: &[u8],
) -> Vec<u8> {
    let mut env = MessageEnvelope::from_blob(blob).expect("decode envelope");
    env.ct[2] ^= 0xFF;
    let sig =
        meridian_core::identity::sign(peer_store, peer_account.handle(), &env.signing_bytes())
            .expect("resign");
    env.sig = *sig.as_bytes();
    env.to_blob().expect("encode envelope")
}

/// The flagship proof for this task's TUI-side wiring: a contact already `TrustState::Blocked` from
/// a prior, unresolved key-change incident — mirrors `apps/core/tests/desync_recovery.rs`'s own
/// `stand_in_prior_key` pattern for constructing a real, already-blocked contact record keyed
/// exactly at the peer this conversation is already talking to — gets repeated, authentic-but-
/// undecryptable envelopes from that exact peer. Before task 5.5, `run_inbound_loop` had **no**
/// desync-recovery wiring at all (this file's own module doc, pre-task-5.5 revision, said so
/// explicitly); now it does, and this proves the wiring never bypasses the early
/// `TrustStore::can_send` gate just because a repeated desync legitimately crossed the recovery
/// threshold — mirroring `apps/cli/src/chat.rs::maybe_attempt_recovery`'s identical ordering.
#[tokio::test]
async fn repeated_desync_against_an_already_blocked_contact_never_bypasses_can_send() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let (mut rx, peer_store, peer_account, mut peer_chat, mut peer_client) =
        establish_accepted_conversation(&server, &handle, us_pub).await;
    let peer_pub = *peer_account.public_key().as_bytes();

    let pinned = read_trust(&handle);
    assert_eq!(
        pinned.trust_state(&peer_pub),
        TrustState::Pinned,
        "sanity: accepting a message request TOFU-pins the sender"
    );

    // Overwrite trust.bin: the peer is already `Blocked` from an unrelated, earlier key-change
    // incident (`stand_in_prior_key` -> `peer_pub`), simulating a real deployment where a key
    // change was detected and never resolved *before* this scenario's own repeated desync begins.
    let mut blocked = TrustStore::default();
    let stand_in_prior_key = [0xCDu8; 32];
    blocked.observe(stand_in_prior_key, "peer.example", 1_700_000_000);
    blocked
        .mark_verified(&stand_in_prior_key)
        .expect("known contact");
    blocked
        .observe_key_change(&stand_in_prior_key, peer_pub, "peer.example", 1_700_000_001)
        .expect("known contact, distinct new key");
    assert_eq!(blocked.trust_state(&peer_pub), TrustState::Blocked);
    write_trust(&handle, &blocked);
    let before_bytes = std::fs::read(meridian_core::account::trust_path().unwrap())
        .expect("read trust.bin after seeding Blocked");

    // Drive DESYNC_RECOVERY_THRESHOLD consecutive, authentic-but-undecryptable envelopes from the
    // real peer over the real rendezvous relay.
    for i in 0..DESYNC_RECOVERY_THRESHOLD {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("random id");
        let blob = peer_chat
            .seal_outbound(
                &peer_store,
                peer_account.handle(),
                peer_account.public_key().as_bytes(),
                &us_pub,
                &ChatContent::Text {
                    id,
                    body: format!("noise {i}"),
                },
            )
            .expect("peer seal_outbound");
        let mangled = mangle_and_resign(&peer_store, &peer_account, &blob);
        peer_client
            .route_with_hint(us_pub, None, mangled)
            .await
            .expect("route a mangled envelope");
    }

    // None of the mangled envelopes ever surfaces as an InboundEvent — each is dropped as Desync,
    // exactly like any other rejection.
    assert!(
        recv_inbound(&mut rx, Duration::from_millis(500))
            .await
            .is_none(),
        "a mangled/undecryptable envelope must never surface as an InboundEvent"
    );

    // A genuine, well-formed follow-up sent AFTER the burst — the ordered-delivery synchronization
    // point this test uses to know every prior mangled envelope (including the threshold-crossing
    // one) has already been fully processed: WS delivery is ordered and `run_inbound_loop`
    // processes strictly sequentially (one `process_inbound_delivery` call fully completes,
    // including its own `sessions.bin`/`trust.bin` I/O, before the next `next_deliver()` is even
    // polled), so this event's arrival is a hard barrier, not a fixed sleep.
    let sync_id = peer_send_text(
        &peer_store,
        &peer_account,
        us_pub,
        &mut peer_chat,
        &mut peer_client,
        "still here after the burst",
    )
    .await;
    let event = recv_inbound(&mut rx, Duration::from_secs(10))
        .await
        .expect("the genuine follow-up must still be delivered — the gated refusal wedged nothing");
    match event {
        InboundEvent::Message { entry, .. } => assert_eq!(entry.mid, hex::encode(sync_id)),
        other => panic!("expected InboundEvent::Message, got {other:?}"),
    }

    // The real assertion this test exists for, now safe to check: `trust.bin` is byte-identical to
    // what this test itself seeded — the early `can_send` gate refused the automatic re-handshake
    // outright once the threshold was crossed, never reaching a network fetch or
    // `meridian_core::desync::attempt_recovery`, and never mutating trust state as a side effect of
    // even considering one.
    let after_bytes = std::fs::read(meridian_core::account::trust_path().unwrap())
        .expect("read trust.bin after the burst");
    assert_eq!(
        before_bytes, after_bytes,
        "trust.bin must be byte-identical: a gated peer's repeated desync must never touch trust \
         state at all, not even a resealed-but-equivalent document"
    );
    let trust_after = read_trust(&handle);
    assert_eq!(trust_after.trust_state(&peer_pub), TrustState::Blocked);
}

// -------------------------------------------------------------------------------------------------
// The deadlock regression (task 5.5 review finding, blocking): the scenario the test above
// deliberately does NOT cover, because it never reaches `worker::attempt_worker_recovery` at all —
// the peer there is already `Blocked`, so the early `TrustStore::can_send` gate refuses before any
// network I/O. This test drives the exact opposite, ordinary/non-gated case (Pinned, `SendGate::Ok`)
// so `attempt_worker_recovery` is actually reached and actually completes — the code path where
// `process_inbound_delivery` used to hold `chat_state_lock` across `attempt_worker_recovery`'s own
// (re-)acquisition of that same, non-reentrant lock, wedging this worker's every future
// `chat_state_lock`-guarded effect (`SendMessage`/`AcceptRequest`/`RejectRequest`, and every future
// inbound delivery) forever. Reproduced and verified against the pre-fix code per this task's own
// Status section: reverting the `drop(_chat_guard)` this task added to `process_inbound_delivery`
// makes this test hang/time out; restoring it makes this test pass.
// -------------------------------------------------------------------------------------------------

/// Mirrors [`publish_own_bundle`] exactly, but for the *peer* side of this file's tests, and also
/// populates the peer's own [`CoreChatState::vault`] with the matching private material (spk/otk
/// secrets) — every other test in this file only ever has the peer *send*, never *receive*, so no
/// prior helper needed this. This test's peer must be able to decode a genuine inbound X3DH open
/// from "us" (exactly what a successful [`worker::attempt_worker_recovery`] produces on "us"'s side:
/// a fresh [`meridian_core::chat::ChatState::replace_session_as_initiator`] re-handshake), which
/// requires the peer to actually hold the private counterpart to whatever bundle "us" fetched —
/// `attempt_worker_recovery`'s own network fetch (`worker::fetch_with_retry`) also requires a real
/// bundle to exist on the server at all, which this publish step (not just the vault populate) is
/// what provides.
async fn publish_peer_bundle(
    server: &str,
    peer_store: &MemorySecretStore,
    peer_account: &AccountId,
    peer_chat: &mut CoreChatState,
) {
    let peer_pub = *peer_account.public_key().as_bytes();
    let mut client =
        SignalingClient::connect(server, peer_store, peer_account.handle(), peer_pub, None, 1)
            .await
            .expect("peer connect to republish a bundle");
    let generated = client
        .publish_bundle(peer_store, peer_account.handle(), 8)
        .await
        .expect("peer publish_bundle");
    let _ = client.close().await;

    let otks: Vec<([u8; 32], [u8; 32])> = generated
        .bundle
        .otks
        .iter()
        .zip(generated.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    peer_chat.vault.set_bundle(
        generated.bundle.spk,
        *generated.spk_secret,
        otks,
        1_760_000_000,
    );
}

#[tokio::test]
async fn repeated_desync_against_an_ordinary_pinned_contact_reaches_recovery_and_never_deadlocks_the_worker(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    write_server_config(tmp.path(), &server);
    let (handle, us_pub) = setup_us_account();
    publish_own_bundle(&server, &handle, us_pub).await;

    let (mut rx, peer_store, peer_account, mut peer_chat, mut peer_client) =
        establish_accepted_conversation(&server, &handle, us_pub).await;
    let peer_pub = *peer_account.public_key().as_bytes();

    let pinned = read_trust(&handle);
    assert_eq!(
        pinned.trust_state(&peer_pub),
        TrustState::Pinned,
        "sanity: an ordinary, non-gated contact — the exact case that reaches \
         attempt_worker_recovery, unlike this file's already-Blocked test above"
    );

    // Unlike the already-Blocked scenario, this scenario needs `attempt_worker_recovery`'s own
    // network fetch to actually succeed: the peer must have genuinely (re)published a real,
    // fetchable bundle, with the matching private material resident locally so the peer can also
    // decode "us"'s subsequent fresh re-initiation.
    publish_peer_bundle(&server, &peer_store, &peer_account, &mut peer_chat).await;

    // Drive DESYNC_RECOVERY_THRESHOLD consecutive, authentic-but-undecryptable envelopes from the
    // real peer over the real rendezvous relay — identical to this file's already-Blocked test,
    // except this peer is never gated, so the threshold-crossing envelope's own `SendGate::Ok` read
    // actually reaches `attempt_worker_recovery` (the exact call this task's deadlock lived in).
    for i in 0..DESYNC_RECOVERY_THRESHOLD {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("random id");
        let blob = peer_chat
            .seal_outbound(
                &peer_store,
                peer_account.handle(),
                peer_account.public_key().as_bytes(),
                &us_pub,
                &ChatContent::Text {
                    id,
                    body: format!("noise {i}"),
                },
            )
            .expect("peer seal_outbound");
        let mangled = mangle_and_resign(&peer_store, &peer_account, &blob);
        peer_client
            .route_with_hint(us_pub, None, mangled)
            .await
            .expect("route a mangled envelope");
    }

    // None of the mangled envelopes ever surfaces as an InboundEvent — each is dropped as Desync,
    // exactly like any other rejection, whether or not recovery ends up firing on the last one.
    assert!(
        recv_inbound(&mut rx, Duration::from_millis(500))
            .await
            .is_none(),
        "a mangled/undecryptable envelope must never surface as an InboundEvent"
    );

    // THE DEADLOCK-REGRESSION ASSERTION. Pre-fix, `process_inbound_delivery` (running inside
    // `run_inbound_loop`'s own spawned task) is, right now, permanently blocked inside
    // `attempt_worker_recovery`'s own `chat_state_lock().lock().await` — which can never succeed,
    // because the *same* task is the one still holding that lock's only guard, one stack frame up.
    // `chat_state_lock` is a single process-wide singleton also guarding `run_send_message`
    // (`worker::run_send_message`'s own `let _chat_guard = chat_state_lock().lock().await;`), so
    // dispatching an ordinary `Effect::SendMessage` right now would, pre-fix, hang forever too —
    // exactly the "no more messages can be sent" DoS this task's own Status section names. Bounded
    // by `tokio::time::timeout` so this test fails loudly (a timeout panic) rather than hanging the
    // whole test binary if the fix ever regresses.
    let send_outcome = tokio::time::timeout(
        Duration::from_secs(20),
        dispatch_effect(Effect::SendMessage(SendMessageEffect {
            request: SendMessageRequest {
                peer_pubkey: peer_pub,
                // Blank, not `"peer.example"`: mirrors
                // `reply_to_a_message_request_accepted_contact_with_a_blank_hint_routes_locally`'s
                // own comment — this is the exact hint `dispatch_gated_send` actually produces for a
                // contact accepted via a message request, this test's own setup path
                // (`establish_accepted_conversation`).
                peer_hint: String::new(),
                body: "still alive after the burst".to_string(),
            },
            outcome: None,
        })),
    )
    .await
    .expect(
        "process_inbound_delivery must never deadlock the whole worker: a repeated desync against \
         an ordinary (non-gated) contact that crosses DESYNC_RECOVERY_THRESHOLD, reaching \
         attempt_worker_recovery, must not wedge chat_state_lock forever — the very next \
         SendMessage dispatch must still complete",
    );
    let sent = match send_outcome {
        meridian_tui::app::WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => sent,
        other => {
            panic!("expected a completed SendMessage after the recovery attempt, got {other:?}")
        }
    };
    assert!(!sent.mid.is_empty());

    // Not just "some Result came back" — the conversation is genuinely live and responsive: the
    // peer actually receives this fresh message and can decode it. This proves the lock-discipline
    // half this test exists for: SendMessage genuinely completes after attempt_worker_recovery runs,
    // rather than the whole worker staying wedged. It does NOT independently prove attempt_worker_
    // recovery's own fetch/recover/persist logic ran correctly — the mangled-ciphertext desync this
    // test drives never actually breaks "us"'s own sending chain toward the peer (Double Ratchet
    // keeps independent send/receive chains), so this same assertion would still pass even if
    // attempt_worker_recovery's body were replaced with a no-op (confirmed by mutation testing during
    // this task's review). Recovery-outcome correctness for the shared core logic is covered
    // separately and genuinely by apps/core/tests/session.rs's
    // recover_from_desync_actually_recovers_against_the_genuine_peer_with_a_clean_can_send, which
    // does assert on the real RecoveryOutcome::Recovered return value.
    let deliver = tokio::time::timeout(Duration::from_secs(10), peer_client.next_deliver())
        .await
        .expect("the peer must receive the recovered message within a bounded time")
        .expect("next_deliver for the recovered message");
    let content = peer_chat
        .open_inbound(
            &peer_store,
            peer_account.handle(),
            &peer_pub,
            &deliver.from,
            deliver.blob.as_bytes(),
        )
        .expect("the peer must accept us's fresh re-initiation despite holding a stale session");
    match content {
        ChatContent::Text { body, .. } => assert_eq!(body, "still alive after the burst"),
        other => panic!("expected the recovered Text message, got {other:?}"),
    }
}
