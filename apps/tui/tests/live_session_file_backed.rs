//! Task 4.40's own new test target (`cargo nextest run -p meridian-tui --test
//! live_session_file_backed`) — closing task 4.38's Defect B: `worker.rs::open_account_store`'s
//! `StoreKind::File` branch used to fail closed unconditionally, so a file-backed account reached a
//! genuine, connected `Screen::Main` and then failed on its very first contacts/trust/send action.
//!
//! ## Why this file exists, distinct from `run_worker_contacts.rs`/`run_worker_trust.rs`/
//! `run_worker_chat.rs`
//! Every one of those files' own module docs names the same reason for testing exclusively against
//! `OsSecretStore` + `install_mock_keystore`: before this task, `open_account_store` only ever
//! resolved for an OS-keystore-backed account — a file-backed one failed closed by construction (see
//! each file's own `..._fails_closed_with_an_actionable_message` test, all three of which this task
//! deliberately leaves passing unmodified: a dispatch against a **fresh** `OnboardingSession` that
//! never saw a successful `Unlock` must still fail closed today, exactly as before — see this task's
//! own `docs/tasks/phase-4/4.40-file-backed-live-session-store.md` Scope section). This file is the
//! first in this crate's test suite to drive a **file-backed** account through a real
//! `Effect::Unlock` and then reuse the **same** `OnboardingSession` (never a fresh one per dispatch,
//! unlike every `dispatch_effect` helper in the three files above) across the twelve
//! contacts/trust/chat handlers this task rewired — proving the cache `handle_unlock` populates is
//! actually what makes each of them succeed, with no second passphrase prompt anywhere in the path
//! (structurally true here: none of `AddContactRequest`/`SetPetnameRequest`/`AcceptRequestRequest`/
//! `SendMessageRequest`/`PersistHistoryRequest` carries a passphrase field at all — see each one's own
//! doc comment in `crate::app` — so if any of these dispatches succeeds post-`Unlock` for a
//! file-backed account at all, no second prompt could possibly have happened).
//!
//! ## Building a genuine pending `MessageRequest` (for `accept_request_...` below)
//! Mirrors `run_worker_trust.rs`'s own `receive_first_contact`/`Alice` fixture exactly (same real
//! X3DH handshake: `generate_bundle` -> `start_initiator_session` -> `seal_outbound` ->
//! `open_inbound`), just against `bob`'s real `FileSecretStore` instead of an `OsSecretStore` — no
//! mock keystore needed anywhere in this file at all.
//!
//! ## The negative "no second scrypt/age-decrypt" call-counting test
//! Lives in `apps/tui/src/worker.rs`'s own `#[cfg(test)] mod tests`, not here — it needs private
//! access to `OnboardingSession::set_live_store`/`live_store` to inject an instrumented `SecretStore`
//! double directly (bypassing a real `Effect::Unlock` round trip, which always constructs its own
//! real `FileSecretStore`). See that module's own
//! `open_account_store_reuses_the_cached_file_backed_store_never_rebuilding_it` test.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::chat::ChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, AccountId, FileSecretStore, MemorySecretStore};
use meridian_core::signaling::{generate_bundle, SignalingClient, DEFAULT_OTK_COUNT};
use meridian_core::trust::TrustStore;
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

use meridian_tui::app::{
    AcceptRequestEffect, AcceptRequestRequest, AddContactEffect, AddContactRequest, Effect,
    PersistHistoryEffect, PersistHistoryRequest, SendMessageEffect, SendMessageRequest,
    SessionOutcome, SetPetnameEffect, SetPetnameRequest, UnlockEffect, UnlockRequest, WorkerEvent,
};
use meridian_tui::store::history::{self, Direction as MsgDirection, HistoryEntry, MessageState};
use meridian_tui::worker::{dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` environment guard — mirrors every other `run_worker_*.rs` file's own
// `EnvGuard` exactly, minus the OS-keystore warmup/`install_mock_keystore` machinery none of those
// other files' `EnvGuard`s need for a purely file-backed account.
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

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

const PASSPHRASE: &str = "correct horse battery staple";

/// Mints a real, file-backed account and saves its real `account.json` — the exact shape
/// `Effect::Unlock` (and, through it, `worker.rs::open_account_store`'s `StoreKind::File` branch)
/// needs.
fn setup_file_backed_account(dir: &Path) -> (PathBuf, AccountId) {
    let keyfile = dir.join("account.key");
    let fs = FileSecretStore::new(&keyfile, PASSPHRASE);
    let account = generate_account(&fs, "self.example").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");
    (keyfile, account)
}

/// Dispatches a real `Effect::Unlock` against `session` — the one and only place in this file that
/// populates `session`'s file-backed live-store cache (mirrors `handle_unlock`'s own single-writer
/// contract). Every test below dispatches its later effects against this exact same `session`, never
/// a fresh one, since a fresh `OnboardingSession` would have nothing cached and would fail closed
/// exactly like `..._fails_closed_with_an_actionable_message` in the other `run_worker_*.rs` files.
async fn unlock(session: &mut OnboardingSession, keyfile: PathBuf) {
    let effect = Effect::Unlock(Box::new(UnlockEffect {
        request: UnlockRequest {
            keyfile,
            passphrase: PASSPHRASE.to_string(),
        },
        outcome: SessionOutcome::empty(),
    }));
    match dispatch(effect, session).await {
        WorkerEvent::Completed(Effect::Unlock(_)) => {}
        other => panic!("expected a completed Unlock, got {other:?}"),
    }
}

fn read_trust(keyfile: &Path, account: &AccountId) -> TrustStore {
    let fs = FileSecretStore::new(keyfile, PASSPHRASE);
    let bytes = std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");
    TrustStore::open_at_rest(&fs, account.handle(), &bytes).expect("open trust.bin")
}

fn read_chat(keyfile: &Path, account: &AccountId) -> ChatState {
    let fs = FileSecretStore::new(keyfile, PASSPHRASE);
    let bytes = std::fs::read(account::sessions_path().unwrap()).expect("sessions.bin exists");
    ChatState::open_at_rest(&fs, account.handle(), &bytes).expect("open sessions.bin")
}

fn write_chat(keyfile: &Path, account: &AccountId, chat: &ChatState) {
    let fs = FileSecretStore::new(keyfile, PASSPHRASE);
    let path = account::sessions_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sealed = chat
        .seal_at_rest(&fs, account.handle())
        .expect("seal sessions.bin");
    std::fs::write(&path, sealed).expect("write sessions.bin");
}

fn peer_id() -> (String, [u8; 32], String) {
    let peer_store = MemorySecretStore::new();
    let peer = generate_account(&peer_store, "peer.example").expect("peer generate_account");
    let id = peer.to_id_string();
    let parsed = meridian_core::identity::parse_id(&id).expect("parse_id");
    (id, *parsed.pubkey(), parsed.hint().to_string())
}

// ---------------------------------------------------------------------------
// AddContact / SetPetname / PersistHistory — no network needed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_backed_session_supports_add_contact_set_petname_and_persist_history_post_unlock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (keyfile, account) = setup_file_backed_account(tmp.path());

    let mut session = OnboardingSession::default();
    unlock(&mut session, keyfile.clone()).await;

    // --- AddContact -------------------------------------------------------------------------
    let (id, pubkey, hint) = peer_id();
    let add_effect = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: id.clone(),
            pubkey,
            hint: hint.clone(),
            petname: None,
        },
        outcome: None,
    });
    match dispatch(add_effect, &mut session).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(added),
            ..
        })) => assert_eq!(added.pubkey, pubkey),
        other => panic!(
            "expected AddContact to complete for a file-backed session post-Unlock, got {other:?}"
        ),
    }
    let trust_after_add = read_trust(&keyfile, &account);
    assert!(trust_after_add.contact(&pubkey).is_some());

    // --- SetPetname ---------------------------------------------------------------------------
    let petname_effect = Effect::SetPetname(SetPetnameEffect {
        request: SetPetnameRequest {
            pubkey,
            petname: Some("bff".to_string()),
        },
        outcome: None,
    });
    match dispatch(petname_effect, &mut session).await {
        WorkerEvent::Completed(Effect::SetPetname(SetPetnameEffect {
            outcome: Some(()), ..
        })) => {}
        other => panic!(
            "expected SetPetname to complete for a file-backed session post-Unlock, got {other:?}"
        ),
    }
    let trust_after_petname = read_trust(&keyfile, &account);
    assert_eq!(
        trust_after_petname.contact(&pubkey).unwrap().petname,
        Some("bff".to_string())
    );

    // --- PersistHistory -------------------------------------------------------------------------
    let entry = HistoryEntry {
        v: history::CURRENT_VERSION,
        mid: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        dir: MsgDirection::Out,
        ts: 1_760_000_000,
        stream: "mrd.chat/1".to_string(),
        body: "pushed the branch".to_string(),
        state: MessageState::Delivered,
    };
    let history_effect = Effect::PersistHistory(PersistHistoryEffect {
        request: PersistHistoryRequest {
            peer_pubkey: pubkey,
            entry: entry.clone(),
        },
        outcome: None,
    });
    match dispatch(history_effect, &mut session).await {
        WorkerEvent::Completed(Effect::PersistHistory(PersistHistoryEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!(
            "expected PersistHistory to complete for a file-backed session post-Unlock, got \
             {other:?}"
        ),
    }
    let fs = FileSecretStore::new(&keyfile, PASSPHRASE);
    let entries = history::load_or_default(&hex::encode(pubkey), &fs, account.handle())
        .expect("load history/<peer>.jsonl");
    assert_eq!(entries, vec![entry]);
}

// ---------------------------------------------------------------------------
// AcceptRequest — a genuine, gated first-contact request, delivered and TOFU-pinned.
// ---------------------------------------------------------------------------

struct Alice {
    store: MemorySecretStore,
    account: AccountId,
}

impl Alice {
    fn new() -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, "alice.example").expect("generate_account");
        Self { store, account }
    }

    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }

    fn opening_envelope(&self, bob_ik: &[u8; 32], spk: &[u8; 32], opk: [u8; 32]) -> Vec<u8> {
        let ik = self.ik();
        let mut alice_chat = ChatState::default();
        alice_chat
            .start_initiator_session(
                &self.store,
                self.account.handle(),
                &ik,
                bob_ik,
                spk,
                Some(opk),
            )
            .expect("start_initiator_session");
        alice_chat
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                bob_ik,
                &ChatContent::Text {
                    id: [1u8; 16],
                    body: "hi bob, it's alice".into(),
                },
            )
            .expect("seal_outbound")
    }
}

/// Mirrors `run_worker_trust.rs::receive_first_contact` exactly, against `bob`'s real
/// `FileSecretStore` instead of an `OsSecretStore`.
fn receive_first_contact(keyfile: &Path, bob: &AccountId, bob_chat: &mut ChatState) -> Alice {
    let fs = FileSecretStore::new(keyfile, PASSPHRASE);
    let bob_ik = *bob.public_key().as_bytes();
    let gen = generate_bundle(&fs, bob.handle(), bob_ik, 5).expect("generate_bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = gen
        .bundle
        .otks
        .iter()
        .zip(gen.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob_chat
        .vault
        .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, 1_760_000_000);

    let alice = Alice::new();
    let alice_ik = alice.ik();
    let blob = alice.opening_envelope(&bob_ik, &gen.bundle.spk, gen.bundle.otks[0]);

    let outcome = bob_chat.open_inbound(&fs, bob.handle(), &bob_ik, &alice_ik, &blob);
    assert!(
        matches!(outcome, Err(meridian_core::chat::ChatError::MessageRequest)),
        "fixture setup sanity: a first-contact envelope must land in the request queue, got \
         {outcome:?}"
    );
    alice
}

#[tokio::test]
async fn file_backed_session_supports_accept_request_post_unlock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (keyfile, bob) = setup_file_backed_account(tmp.path());

    let mut session = OnboardingSession::default();
    unlock(&mut session, keyfile.clone()).await;

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&keyfile, &bob, &mut bob_chat);
    let alice_ik = alice.ik();
    write_chat(&keyfile, &bob, &bob_chat);

    let effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    match dispatch(effect, &mut session).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!(
            "expected AcceptRequest to complete for a file-backed session post-Unlock, got \
             {other:?}"
        ),
    }

    let chat_after = read_chat(&keyfile, &bob);
    assert!(chat_after.pending_request(&alice_ik).is_none());
    assert!(chat_after.has_session(&alice_ik));

    let trust_after = read_trust(&keyfile, &bob);
    let contact = trust_after
        .contact(&alice_ik)
        .expect("accept must TOFU-pin the sender");
    assert_eq!(contact.hint, "");
}

// ---------------------------------------------------------------------------
// SendMessage — a real, in-process rendezvous server + a real peer.
// ---------------------------------------------------------------------------

/// Starts the real rendezvous server on a background OS thread with its own runtime, bound to an
/// ephemeral port — mirrors `run_worker_chat.rs::spawn_server` exactly (minus its own
/// `get_bundle`-counting instrumentation, not needed here).
fn spawn_server() -> String {
    let store = Arc::new(MemoryStore::new());
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

fn write_server_config(home: &Path, server: &str) {
    let path = home.join("tui").join("config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).expect("create tui config dir");
    std::fs::write(&path, format!("[account]\nserver = \"{server}\"\n"))
        .expect("write config.toml");
}

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

#[tokio::test]
async fn file_backed_session_supports_send_message_post_unlock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (keyfile, us_account) = setup_file_backed_account(tmp.path());
    let us_pub = *us_account.public_key().as_bytes();
    let server = spawn_server();
    write_server_config(tmp.path(), &server);

    let mut session = OnboardingSession::default();
    unlock(&mut session, keyfile.clone()).await;

    // "us" must be the crypto initiator — see `generate_peer_with_ordering`'s own doc comment in
    // `run_worker_chat.rs`, mirrored here.
    let (peer_store, peer_account) = generate_peer_with_ordering(&us_pub, true);
    let peer_pub = *peer_account.public_key().as_bytes();
    let _peer_client = publish_peer_bundle(&server, &peer_store, &peer_account).await;

    let send_effect = Effect::SendMessage(SendMessageEffect {
        request: SendMessageRequest {
            peer_pubkey: peer_pub,
            peer_hint: peer_account.hint().to_string(),
            body: "hello from a file-backed live session".to_string(),
        },
        outcome: None,
    });
    match dispatch(send_effect, &mut session).await {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            outcome: Some(sent),
            ..
        })) => {
            assert!(sent.delivered, "peer was online — must report delivered");
        }
        other => panic!(
            "expected SendMessage to complete for a file-backed session post-Unlock, got {other:?}"
        ),
    }

    let chat_after = read_chat(&keyfile, &us_account);
    assert!(chat_after.has_session(&peer_pub));
}
