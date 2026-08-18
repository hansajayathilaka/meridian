//! `meridian_tui::worker::republish_bundle`/`inbound_handoff` — task 4.39's own test target
//! (`cargo nextest run -p meridian-tui --test republish_bundle`).
//!
//! Task 4.38 found no code path in `meridian-tui` ever republished a prekey bundle with its secret
//! scalars persisted into `sessions.bin`'s `PrekeyVault` — every genuine first-contact message hit
//! `ChatError::UnknownPrekey` and was silently dropped. Task 4.39 closes this via
//! [`meridian_tui::worker::republish_bundle`], wired into `apps/tui/src/lib.rs::run_worker`'s
//! `inbound_handoff` branch. This file covers that new function's own two named deliverables,
//! mirroring 4.30-4.35's own per-task test-file pattern (`tests/run_worker_account.rs`/
//! `tests/inbound_delivery.rs`) rather than re-deriving a new one:
//!
//! 1. [`republished_secrets_are_resolvable_by_chat_state_open_inbound`] — the actual defect-closing
//!    property: a bundle `republish_bundle` publishes carries secrets a peer's real
//!    `meridian_core::chat::ChatState::open_inbound` can decrypt against, not just "no error was
//!    returned from `republish_bundle` itself".
//! 2. [`republish_only_fires_once_per_session_via_the_inbound_started_guard`] — replays
//!    `crate::run_worker`'s own `inbound_started`-guarded call site (see that function's own doc
//!    comment in `apps/tui/src/lib.rs`) against a real sequence of dispatched effects, proving a
//!    later, unrelated effect dispatch (an ordinary `PublishBundle`, and even a *second*
//!    `LoadSession` success) never re-triggers a second republish.
//! 3. [`inbound_handoff_also_produces_a_working_handoff_for_a_file_backed_account`] — the
//!    "both account types are covered by construction" claim this task's own file makes about
//!    `inbound_handoff`, checked directly for the file-backed branch too (never re-deriving one
//!    `SecretStore`/`KeyHandle` shape for `Os` and a different one for `File`).
//!
//! ## Why (1) and (2) use an OS-keystore (mocked) account, not a file-backed one
//! `republish_bundle` mirrors `apps/cli/src/chat.rs::run`'s own `publish_bundle(store, handle,
//! DEFAULT_OTK_COUNT)` call exactly (`DEFAULT_OTK_COUNT` = 100 — see that function's own doc
//! comment) — `1 + otk_count` = 101 real signatures. Driving that against `handoff.store` for a
//! **file-backed** account (a raw, un-cached `FileSecretStore` — `worker::inbound_handoff`'s own
//! `Effect::Unlock` branch builds one fresh per handoff, never the bulk-signing-optimized
//! `MemorySecretStore` `worker::open_store_for_bulk_signing` uses for onboarding's own
//! `PublishBundle`) re-runs a full scrypt KDF unwrap on **every single signature** — genuinely,
//! reproducibly, multiple minutes for one republish (confirmed while writing this test: a real
//! `#[test]` run against a file-backed account here took over 90 seconds and climbing before being
//! killed). This is a real finding, documented in this task's own Status section as a follow-up, not
//! swept under the rug — but it is a **performance** defect (`worker::inbound_handoff`'s file-backed
//! branch was built for `run_inbound_loop`'s own cheap one-signature-per-delivery use, never for a
//! 101-signature bulk publish), not a correctness one, and any fix touches exactly the "extending
//! in-memory key residency" security-posture question `docs/tasks/phase-4/README.md` already
//! reserves for task 4.40's own load-bearing architect + security-reviewer consult — not something
//! to invent unilaterally here. So (1)/(2) below use the same sanctioned, headless-CI-safe
//! `install_mock_keystore()` OS-keystore mock `tests/inbound_delivery.rs`/`tests/live_session_e2e.rs`
//! already use (fast: no KDF per signature), and (3) proves `inbound_handoff`'s file-backed branch
//! still produces a structurally correct handoff without ever calling the expensive
//! `republish_bundle` against it.

use std::future::Future;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use meridian_core::account::{self, AccountDescriptor, StoreKind};
use meridian_core::chat::ChatState as CoreChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    generate_account, install_mock_keystore, FileSecretStore, MemorySecretStore,
};
use meridian_core::signaling::SignalingClient;
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

use meridian_tui::app::{
    Effect, GenerateAccountEffect, GenerateAccountRequest, GeneratedAccount, LoadSessionEffect,
    LoadSessionRequest, PublishBundleEffect, PublishBundleRequest, RegisterRequest, SessionOutcome,
    StoreChoice, UnlockEffect, UnlockRequest, WorkerEvent,
};
use meridian_tui::worker::{dispatch, inbound_handoff, republish_bundle, OnboardingSession};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors `tests/inbound_delivery.rs`'s own
// `EnvGuard` exactly.
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
            let _ = keyring::Entry::new("meridian-tui-republish-test-warmup", "warmup");
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
// In-process rendezvous server — mirrors `tests/run_worker_account.rs::spawn_server` exactly.
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

/// Runs a future to completion on a fresh current-thread runtime — mirrors
/// `tests/run_worker_account.rs::block_on` exactly.
fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime")
        .block_on(fut)
}

/// Mints a real, mock-OS-keystore-backed account through the actual `GenerateAccount` -> `Register`
/// dispatch sequence — never hand-rolled — so `account.json`'s `server` field is populated exactly
/// the way `worker::resolve_server`/`worker::inbound_handoff` require it to be (see
/// `handle_register`'s own `persist_registered_server` call). Mirrors
/// `tests/live_session_e2e.rs::run_peer`'s own onboarding prefix.
async fn onboard_os_account(
    server: &str,
    session: &mut OnboardingSession,
    hint: &str,
) -> GeneratedAccount {
    let generate_effect = Effect::GenerateAccount(GenerateAccountEffect {
        request: GenerateAccountRequest {
            store: StoreChoice::Os,
            hint: hint.to_string(),
        },
        outcome: None,
    });
    let generated = match dispatch(generate_effect, session).await {
        WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            outcome: Some(generated),
            ..
        })) => generated,
        other => panic!("expected a completed GenerateAccount, got {other:?}"),
    };

    let register_effect = Effect::Register(RegisterRequest {
        server: server.to_string(),
        invite: None,
        store: StoreChoice::Os,
        label: generated.label.clone(),
        account_pub: generated.account_pub,
    });
    match dispatch(register_effect, session).await {
        WorkerEvent::Completed(Effect::Register(_)) => {}
        other => panic!("expected a completed Register, got {other:?}"),
    }
    generated
}

fn load_session_effect() -> Effect {
    Effect::LoadSession(LoadSessionEffect {
        request: LoadSessionRequest,
        outcome: None,
    })
}

// ---------------------------------------------------------------------------
// (1) republished secrets are actually resolvable by ChatState::open_inbound
// ---------------------------------------------------------------------------

#[test]
fn republished_secrets_are_resolvable_by_chat_state_open_inbound() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();

    let mut session = OnboardingSession::default();
    let (generated, handoff) = block_on(async {
        let generated = onboard_os_account(&server, &mut session, "self-org.test").await;

        let outcome = dispatch(load_session_effect(), &mut session).await;
        assert!(
            matches!(outcome, WorkerEvent::Completed(Effect::LoadSession(_))),
            "expected a completed LoadSession, got {outcome:?}"
        );
        let handoff = inbound_handoff(&outcome)
            .expect("a successful OS-keystore LoadSession must produce an inbound handoff");
        (generated, handoff)
    });

    // The function under test: connect, publish, and persist the matching secrets into
    // sessions.bin's PrekeyVault.
    block_on(republish_bundle(
        handoff.store.as_ref(),
        &handoff.handle,
        handoff.account_pub,
        &handoff.server,
    ))
    .expect("republish_bundle must succeed against a real, freshly-registered account");

    // A completely independent peer identity fetches "us"'s freshly-republished bundle from the
    // server and X3DH-initiates against it — mirrors `apps/cli/src/chat.rs::fetch_with_retry` +
    // `start_initiator_session`'s own sequence exactly.
    let peer_store = MemorySecretStore::new();
    let peer_account =
        generate_account(&peer_store, "peer.example").expect("peer generate_account");
    let peer_pub = *peer_account.public_key().as_bytes();
    let blob = block_on(async {
        let mut client = SignalingClient::connect(
            &server,
            &peer_store,
            peer_account.handle(),
            peer_pub,
            None,
            1,
        )
        .await
        .expect("peer connect");
        let bundle = client
            .fetch_bundle(generated.account_pub, None, false)
            .await
            .expect("peer fetch us bundle");
        let mut chat = CoreChatState::default();
        chat.start_initiator_session(
            &peer_store,
            peer_account.handle(),
            &peer_pub,
            &generated.account_pub,
            &bundle.spk,
            bundle.otks.first().copied(),
        )
        .expect("peer start_initiator_session");
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("random id");
        let blob = chat
            .seal_outbound(
                &peer_store,
                peer_account.handle(),
                &peer_pub,
                &generated.account_pub,
                &ChatContent::Text {
                    id,
                    body: "first contact".to_string(),
                },
            )
            .expect("peer seal_outbound");
        let _ = client.close().await;
        blob
    });

    // Load "us"'s real, on-disk sessions.bin — exactly what `republish_bundle` just wrote — and
    // prove `ChatState::open_inbound` actually resolves the peer's opening envelope against it: the
    // falsifiable version of "the republished bundle's secrets are vault-persisted", not just
    // "republish_bundle itself returned Ok".
    let path = account::sessions_path().expect("sessions_path");
    let sealed = std::fs::read(&path).expect("sessions.bin must exist after republish_bundle");
    let mut us_chat = CoreChatState::open_at_rest(handoff.store.as_ref(), &handoff.handle, &sealed)
        .expect("open sessions.bin");
    // A first envelope from a sender `us_chat` has never seen before is gated into a
    // `ChatError::MessageRequest` (task 2.10, §3.5) rather than delivered directly — but per that
    // error variant's own doc comment, "[b]y the time a `MessageRequest` exists, the crypto
    // underneath it is *done*: the envelope's signature verified, X3DH ran... and a live `Session`
    // is already installed". So `Err(ChatError::MessageRequest)` here is the *expected*, successful-
    // decryption outcome for first contact — mirrors `apps/cli/src/chat.rs::handle_inbound`'s own
    // `Err(ChatError::MessageRequest)` arm exactly. The actual defect this task closes would surface
    // as `Err(ChatError::UnknownPrekey)` instead (decryption never even starts — no matching vault
    // secret) — that is the one outcome this assertion must rule out.
    match us_chat.open_inbound(
        handoff.store.as_ref(),
        &handoff.handle,
        &generated.account_pub,
        &peer_pub,
        &blob,
    ) {
        Ok(ChatContent::Text { body, .. }) => assert_eq!(body, "first contact"),
        Ok(other) => panic!("expected ChatContent::Text, got {other:?}"),
        Err(meridian_core::chat::ChatError::MessageRequest) => {
            let req = us_chat
                .pending_request(&peer_pub)
                .expect("open_inbound just inserted this request");
            match &req.intro {
                ChatContent::Text { body, .. } => assert_eq!(body, "first contact"),
                other => panic!("expected a Text intro, got {other:?}"),
            }
        }
        Err(e) => panic!(
            "the peer's first-contact envelope must open cleanly against the republished, \
             vault-persisted bundle — got {e:?} instead (ChatError::UnknownPrekey here would mean \
             task 4.38's Defect A is still open)"
        ),
    }
}

// ---------------------------------------------------------------------------
// (2) republish fires exactly once per session, never re-triggered by a later, unrelated dispatch
// ---------------------------------------------------------------------------

/// Replays `apps/tui/src/lib.rs::run_worker`'s own `inbound_started`-guarded call site exactly (see
/// that function's own doc comment): a fresh `bool` flag, checked before every `inbound_handoff`
/// peek, set the first time a handoff is produced. `inbound_handoff` itself has no memory of its
/// own (see its own doc comment) — a **second** `LoadSession` success later in the same sequence
/// would, on `inbound_handoff` alone, still produce a second `Some`. This test proves the *guard*
/// around it — the actual thing `crate::run_worker` relies on — is what keeps the real
/// `republish_bundle` call to exactly one per session, and that an ordinary unrelated effect
/// (`PublishBundle`) never even reaches the `Some` branch to begin with.
#[test]
fn republish_only_fires_once_per_session_via_the_inbound_started_guard() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();

    let mut session = OnboardingSession::default();
    let mut inbound_started = false;
    let mut republish_calls = 0usize;

    block_on(async {
        let generated = onboard_os_account(&server, &mut session, "self-org.test").await;

        // The real session-start event.
        let load_outcome = dispatch(load_session_effect(), &mut session).await;

        // A later, unrelated effect — an ordinary re-publish a user might trigger manually from a
        // still-open onboarding-style screen.
        let publish_outcome = dispatch(
            Effect::PublishBundle(PublishBundleEffect {
                request: PublishBundleRequest {
                    server: server.clone(),
                    store: StoreChoice::Os,
                    label: generated.label.clone(),
                    account_pub: generated.account_pub,
                    otk_count: 5,
                },
                outcome: None,
            }),
            &mut session,
        )
        .await;

        // A repeated LoadSession later in the same session — on `inbound_handoff` alone this still
        // reads `Some`; only the guard below (mirroring `run_worker`'s own `inbound_started`) must
        // suppress a second republish.
        let second_load_outcome = dispatch(load_session_effect(), &mut session).await;

        for outcome in [&load_outcome, &publish_outcome, &second_load_outcome] {
            if !inbound_started {
                if let Some(handoff) = inbound_handoff(outcome) {
                    inbound_started = true;
                    republish_bundle(
                        handoff.store.as_ref(),
                        &handoff.handle,
                        handoff.account_pub,
                        &handoff.server,
                    )
                    .await
                    .expect("republish_bundle must succeed");
                    republish_calls += 1;
                }
            }
        }

        // Sanity: the middle, unrelated `PublishBundle` dispatch on its own never produces a
        // handoff at all — the guard above isn't doing the only work here.
        assert!(
            inbound_handoff(&publish_outcome).is_none(),
            "inbound_handoff must never produce a handoff for an unrelated PublishBundle outcome"
        );
    });

    assert_eq!(
        republish_calls, 1,
        "republish_bundle must fire exactly once per session, never re-triggered by a later, \
         unrelated effect dispatch (PublishBundle) or a repeated LoadSession success"
    );
}

// ---------------------------------------------------------------------------
// (3) inbound_handoff also produces a working handoff for a file-backed account (never republishes
//     against it here — see the module doc's "Why (1) and (2) use an OS-keystore account" section)
// ---------------------------------------------------------------------------

/// Proves `worker::inbound_handoff`'s `Effect::Unlock` branch independently derives a structurally
/// correct [`meridian_tui::worker::InboundHandoff`] for a file-backed account too — the "both account
/// types are covered by construction" claim this task's own file makes, checked directly rather than
/// only asserted for the OS-keystore branch above. Deliberately does **not** call the real,
/// expensive `republish_bundle` against it — see the module doc's own explanation.
#[test]
fn inbound_handoff_also_produces_a_working_handoff_for_a_file_backed_account() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("account.key");
    let passphrase = "correct horse battery staple";
    let fs = FileSecretStore::new(&keyfile, passphrase);
    let account = generate_account(&fs, "self-org.test").expect("generate_account");
    let mut descriptor = AccountDescriptor::new_file(&account, &keyfile);
    // `inbound_handoff`/`worker::resolve_server` need a server on the descriptor (or a
    // `config.toml` override) — mirrors what a real `Effect::Register` dispatch would have
    // persisted; hand-set here since this test never dispatches `Register` at all (no need for a
    // live server for a structural-only check).
    descriptor.server = Some("ws://127.0.0.1:1".to_string());
    descriptor.save().expect("save account.json");
    assert_eq!(descriptor.store, StoreKind::File);

    let mut session = OnboardingSession::default();
    let outcome = block_on(dispatch(
        Effect::Unlock(Box::new(UnlockEffect {
            request: UnlockRequest {
                keyfile: keyfile.clone(),
                passphrase: passphrase.to_string(),
            },
            outcome: SessionOutcome::empty(),
        })),
        &mut session,
    ));
    assert!(
        matches!(outcome, WorkerEvent::Completed(Effect::Unlock(_))),
        "expected a completed Unlock, got {outcome:?}"
    );

    let handoff = inbound_handoff(&outcome)
        .expect("a successful file-backed Unlock must produce an inbound handoff too");
    assert_eq!(handoff.account_pub, *account.public_key().as_bytes());
    assert_eq!(handoff.server, "ws://127.0.0.1:1");
    // `worker::inbound_handoff` (like every other handler in `worker.rs`) rebuilds the `KeyHandle`
    // from `account.json`'s own `descriptor.label` (the hex-encoded pubkey — see
    // `AccountDescriptor::new_file`), never from `account.handle()` — `FileSecretStore::store`'s own
    // returned handle instead carries the *keyfile path* as its label (`file.rs::store`'s own `Ok`
    // arm), a different value entirely. Comparing against that would be comparing the wrong thing.
    assert_eq!(
        handoff.handle.label(),
        hex::encode(account.public_key().as_bytes())
    );
}
