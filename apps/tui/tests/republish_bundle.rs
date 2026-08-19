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
//! 4. [`republish_bundle_fails_cleanly_without_panicking_on_an_unreachable_server`] — the
//!    log-only-and-still-listen failure UX `crate::run_worker`'s own doc comment commits to (a failed
//!    republish must never block `run_inbound_loop` from starting): proves `republish_bundle` itself
//!    returns a plain `Err(String)` — never panics, never blocks — when the connect step fails, which
//!    is the one property `run_worker`'s `if let Err(e) = ... { eprintln!(...) }` (no early return)
//!    actually depends on.
//!
//! Task 4.43 adds three more, all about the **file-backed** path this file originally could not
//! exercise at all (see the section below):
//!
//! 5. [`file_backed_republish_completes_and_its_secrets_open_a_peers_first_envelope`] — (1)'s
//!    property, for a file-backed account, through a real `republish_bundle` that actually runs.
//! 6. [`the_whole_file_backed_republish_costs_no_further_seed_unwrap_after_inbound_handoffs_single_one`]
//!    — the derivation-count property, phrased falsifiably (see that test's own doc comment).
//! 7. [`run_worker_drops_the_bulk_signing_store_before_spawning_the_inbound_loop`] — the residency
//!    bound task 4.43's security rationale rests on.
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
//!
//! ### Update (task 4.43): that defect is fixed, and (5)-(7) below now exercise the file-backed path
//! The paragraph above is left as 4.39's own historical record; it no longer describes the current
//! state. `worker::inbound_handoff` now also builds an unwrap-**once**
//! `meridian_core::identity::MemorySecretStore` (`InboundHandoff::bulk_signing_store`), which
//! `apps/tui/src/lib.rs::run_worker` hands to `republish_bundle` and drops before spawning
//! `run_inbound_loop`. `InboundHandoff::store` — what `run_inbound_loop` itself keeps — is
//! deliberately unchanged. A file-backed republish therefore costs **one** age/scrypt unwrap for the
//! whole 101-signature burst instead of 101 of them: measured on this machine, a completed
//! `Effect::Unlock` reached `run_inbound_loop`'s spawn in **194.50 s before / 1.92 s after**, and a
//! real PTY-driven `meridian tui` reached `Screen::Main` in **211.5 s before / 3.6 s after** (task
//! 4.43's own Status section records the methodology). Tests (5)-(7) below are the coverage that
//! became possible — and mandatory — once that was true.

use std::future::Future;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use meridian_core::account::{self, AccountDescriptor, StoreKind};
use meridian_core::chat::ChatState as CoreChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    generate_account, install_mock_keystore, FileSecretStore, KeyHandle, MemorySecretStore,
    SecretStore, SignOrDh, StoreError,
};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
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

// ---------------------------------------------------------------------------
// (4) a failed republish returns a clean Err, never panics — the property `run_worker`'s
//     log-only-and-still-listen wiring (no early return around the call) actually depends on.
// ---------------------------------------------------------------------------

/// `run_worker` (`apps/tui/src/lib.rs`) wraps its `republish_bundle` call in
/// `if let Err(e) = ... { eprintln!(...) }` with no early return, so `run_inbound_loop` always spawns
/// regardless of outcome — that wiring is a structural fact of `lib.rs`, not something an integration
/// test against a private function can re-exercise. What *is* this crate's own responsibility to
/// prove is the property that wiring relies on: `republish_bundle` itself fails cleanly (a plain
/// `Err(String)`, no panic) rather than hanging or aborting when its first step — connecting — fails.
#[test]
fn republish_bundle_fails_cleanly_without_panicking_on_an_unreachable_server() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());

    let mut session = OnboardingSession::default();
    let (generated, handoff) = block_on(async {
        // No real server is spawned here — `onboard_os_account` needs one to register against, so
        // reuse the same real server as the other tests, then hand `republish_bundle` a deliberately
        // unreachable address instead (mirrors test 3's own `"ws://127.0.0.1:1"` unreachable-address
        // trick) rather than tearing the server down mid-test.
        let server = spawn_server();
        let generated = onboard_os_account(&server, &mut session, "self-org.test").await;
        let outcome = dispatch(load_session_effect(), &mut session).await;
        let handoff = inbound_handoff(&outcome)
            .expect("a successful OS-keystore LoadSession must produce an inbound handoff");
        (generated, handoff)
    });
    let _ = generated;

    let result = block_on(republish_bundle(
        handoff.store.as_ref(),
        &handoff.handle,
        handoff.account_pub,
        "ws://127.0.0.1:1",
    ));

    match result {
        Err(e) => assert!(
            e.contains("connecting to"),
            "expected a connect-stage error message, got {e:?}"
        ),
        Ok(()) => panic!("republish_bundle must not succeed against an unreachable server"),
    }
}

// ---------------------------------------------------------------------------
// Task 4.43 shared fixtures for the file-backed path
// ---------------------------------------------------------------------------

/// Mints a real, **file-backed** account through the actual `GenerateAccount` -> `Register` dispatch
/// sequence — the file-store twin of [`onboard_os_account`] above, never hand-rolled, so
/// `account.json` gets its `store: StoreKind::File`, its `keyfile`, and (via `handle_register`'s own
/// `persist_registered_server`) its `server` field exactly the way `worker::resolve_server`/
/// `worker::inbound_handoff` require. Returns the account plus the keyfile path
/// `worker::default_keyfile_path` chose for it (`$MERIDIAN_HOME/account.key`), which is also what
/// `Effect::Unlock`'s own request has to carry.
async fn onboard_file_account(
    server: &str,
    session: &mut OnboardingSession,
    passphrase: &str,
    hint: &str,
) -> (GeneratedAccount, std::path::PathBuf) {
    let store = StoreChoice::File {
        passphrase: passphrase.to_string(),
    };
    let generate_effect = Effect::GenerateAccount(GenerateAccountEffect {
        request: GenerateAccountRequest {
            store: store.clone(),
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
        store,
        label: generated.label.clone(),
        account_pub: generated.account_pub,
    });
    match dispatch(register_effect, session).await {
        WorkerEvent::Completed(Effect::Register(_)) => {}
        other => panic!("expected a completed Register, got {other:?}"),
    }

    let keyfile = account::config_dir()
        .expect("config_dir")
        .join("account.key");
    assert!(
        keyfile.exists(),
        "onboarding must have written the age/scrypt keyfile at {}",
        keyfile.display()
    );
    (generated, keyfile)
}

/// Dispatches the real `Effect::Unlock` for a file-backed account and peeks the resulting
/// `WorkerEvent` exactly as `apps/tui/src/lib.rs::run_worker` does — returning the
/// `worker::InboundHandoff` that call site would have gone on to use.
async fn unlock_and_hand_off(
    keyfile: &Path,
    passphrase: &str,
    session: &mut OnboardingSession,
) -> meridian_tui::worker::InboundHandoff {
    let outcome = dispatch(
        Effect::Unlock(Box::new(UnlockEffect {
            request: UnlockRequest {
                keyfile: keyfile.to_path_buf(),
                passphrase: passphrase.to_string(),
            },
            outcome: SessionOutcome::empty(),
        })),
        session,
    )
    .await;
    assert!(
        matches!(outcome, WorkerEvent::Completed(Effect::Unlock(_))),
        "expected a completed Unlock, got {outcome:?}"
    );
    inbound_handoff(&outcome).expect("a successful file-backed Unlock must produce a handoff")
}

/// A fresh, unrelated peer identity that fetches `our_pub`'s currently-published bundle from
/// `server`, X3DH-initiates against it, and seals one first-contact `Text` — mirrors
/// `apps/cli/src/chat.rs::fetch_with_retry` + `start_initiator_session` exactly, and is the same
/// sequence test (1) above performs inline (left inline there on purpose: 4.39's own tests are not
/// rewritten by this task). Returns the peer's pubkey and the sealed blob.
async fn peer_first_contact_envelope(
    server: &str,
    our_pub: [u8; 32],
    body: &str,
) -> ([u8; 32], Vec<u8>) {
    let peer_store = MemorySecretStore::new();
    let peer_account =
        generate_account(&peer_store, "peer.example").expect("peer generate_account");
    let peer_pub = *peer_account.public_key().as_bytes();
    let mut client = SignalingClient::connect(
        server,
        &peer_store,
        peer_account.handle(),
        peer_pub,
        None,
        1,
    )
    .await
    .expect("peer connect");
    let bundle = client
        .fetch_bundle(our_pub, None, false)
        .await
        .expect("peer fetch our bundle");
    let mut chat = CoreChatState::default();
    chat.start_initiator_session(
        &peer_store,
        peer_account.handle(),
        &peer_pub,
        &our_pub,
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
            &our_pub,
            &ChatContent::Text {
                id,
                body: body.to_string(),
            },
        )
        .expect("peer seal_outbound");
    let _ = client.close().await;
    (peer_pub, blob)
}

// ---------------------------------------------------------------------------
// (5) a FILE-BACKED republish that actually completes, and whose secrets a peer's first envelope
//     really resolves against — the test task 4.39 could not write (its own file-backed coverage
//     deliberately stopped short of calling `republish_bundle` at all, because doing so took > 90 s
//     and climbing against the raw `FileSecretStore`)
// ---------------------------------------------------------------------------

/// Task 4.43's headline property, and the one that proves the store swap is *only* a performance
/// change: the bundle a file-backed session republishes through
/// `InboundHandoff::bulk_signing_store` carries secrets that
/// `meridian_core::chat::ChatState::open_inbound` genuinely resolves a peer's first-contact envelope
/// against — the same assertion test (1) makes for an OS-keystore account, now for the account type
/// that could not be tested at all before.
///
/// Deliberately re-opens the resealed `sessions.bin` with **`handoff.store`** (the raw
/// `FileSecretStore` `run_inbound_loop` keeps), not with the `MemorySecretStore` that wrote it: both
/// derive from the same Ed25519 seed through the same `derive_key_from_seed(seed, info)`, so this is
/// the falsifiable version of the plan-time correctness check that the resealed document stays
/// readable by every other handler's `FileSecretStore` path — no migration, no compatibility risk.
#[test]
fn file_backed_republish_completes_and_its_secrets_open_a_peers_first_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let passphrase = "correct horse battery staple";

    let mut session = OnboardingSession::default();
    let (generated, keyfile) = block_on(onboard_file_account(
        &server,
        &mut session,
        passphrase,
        "self-org.test",
    ));
    let descriptor = AccountDescriptor::load().expect("account.json");
    assert_eq!(
        descriptor.store,
        StoreKind::File,
        "this test is meaningless unless the account really is file-backed"
    );

    let handoff = block_on(unlock_and_hand_off(&keyfile, passphrase, &mut session));

    // The function under test, wired exactly as `run_worker` wires it (task 4.43): the
    // bulk-signing store, never `handoff.store`.
    block_on(republish_bundle(
        handoff.bulk_signing_store.as_ref(),
        &handoff.handle,
        handoff.account_pub,
        &handoff.server,
    ))
    .expect(
        "a file-backed republish_bundle must succeed against a real, freshly-registered account",
    );

    let (peer_pub, blob) = block_on(peer_first_contact_envelope(
        &server,
        generated.account_pub,
        "first contact, file-backed",
    ));

    let path = account::sessions_path().expect("sessions_path");
    let sealed = std::fs::read(&path).expect("sessions.bin must exist after republish_bundle");
    let mut us_chat = CoreChatState::open_at_rest(handoff.store.as_ref(), &handoff.handle, &sealed)
        .expect("the FileSecretStore path must still open the sessions.bin the MemorySecretStore resealed");
    // `Err(ChatError::MessageRequest)` is the *expected* first-contact outcome — see test (1)'s own
    // explanation of why (the crypto underneath it is already done). `ChatError::UnknownPrekey` is
    // the one outcome that would mean the republished secrets never reached the vault.
    match us_chat.open_inbound(
        handoff.store.as_ref(),
        &handoff.handle,
        &generated.account_pub,
        &peer_pub,
        &blob,
    ) {
        Ok(ChatContent::Text { body, .. }) => assert_eq!(body, "first contact, file-backed"),
        Ok(other) => panic!("expected ChatContent::Text, got {other:?}"),
        Err(meridian_core::chat::ChatError::MessageRequest) => {
            let req = us_chat
                .pending_request(&peer_pub)
                .expect("open_inbound just inserted this request");
            match &req.intro {
                ChatContent::Text { body, .. } => assert_eq!(body, "first contact, file-backed"),
                other => panic!("expected a Text intro, got {other:?}"),
            }
        }
        Err(e) => panic!(
            "a file-backed account's republished, vault-persisted bundle must open the peer's \
             first-contact envelope — got {e:?} (ChatError::UnknownPrekey here would mean the \
             bulk-signing store wrote secrets the FileSecretStore path cannot see)"
        ),
    }
}

// ---------------------------------------------------------------------------
// (6) the whole republish costs no further seed unwrap beyond the single one inbound_handoff
//     already performed
// ---------------------------------------------------------------------------

/// Counts the [`SecretStore`] operations a republish actually performs, delegating each to the real
/// store — in the spirit of task 4.40's own `CountingStore`, and with the same care that task's
/// review-outcome correction demanded about *what* the count proves.
struct CountingStore {
    inner: Box<dyn SecretStore>,
    signs: std::sync::atomic::AtomicUsize,
    derives: std::sync::atomic::AtomicUsize,
}

impl CountingStore {
    fn new(inner: Box<dyn SecretStore>) -> Self {
        Self {
            inner,
            signs: std::sync::atomic::AtomicUsize::new(0),
            derives: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn signs(&self) -> usize {
        self.signs.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn derives(&self) -> usize {
        self.derives.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SecretStore for CountingStore {
    fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle, StoreError> {
        self.inner.store(label, secret)
    }
    fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.use_key(h, op, input)
    }
    fn nonextractable(&self) -> bool {
        self.inner.nonextractable()
    }
    fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32], StoreError> {
        self.derives
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.derive_key(h, info)
    }
}

/// The exact number of `derive_key` calls a republish's at-rest work performs **for this test's
/// scenario**, asserted as an equality like `signs()` rather than as a floor.
///
/// `republish_bundle`'s at-rest work is `load_chat` then `save_chat`. `save_chat`'s `seal_at_rest`
/// always derives once. `load_chat` derives only when `sessions.bin` already exists — on a
/// just-onboarded account it takes its `ErrorKind::NotFound` arm and returns
/// `CoreChatState::default()` without touching the store. The test below onboards fresh and asserts
/// that precondition explicitly before counting, so this number is pinned by a stated fact rather
/// than by luck: **1**. (A returning session, whose `sessions.bin` exists, would derive twice.)
const EXPECTED_AT_REST_DERIVES: usize = 1;

/// **The derivation-count deliverable, phrased the way task 4.40's own review correction requires.**
///
/// `FileSecretStore::use_key`/`derive_key` each call `decrypt_seed()` — a full age/scrypt unwrap,
/// starting with `fs::read(keyfile)` — on *every single call*, and no cache anywhere changes that.
/// So the property worth asserting is not a vague "the cache prevents scrypt" but: **one
/// `export_seed` / one expensive-store construction covers the entire republish.**
///
/// Made falsifiable by removing the keyfile from disk *after* `inbound_handoff` built the handoff and
/// *before* `republish_bundle` runs. From that moment, any `decrypt_seed` — i.e. any seed unwrap at
/// all — is impossible: it would fail at `fs::read` with `StoreError::NotFound`. The republish
/// nevertheless completes, with 100+ counted signing operations plus its at-rest `derive_key`, every
/// one of them served by the single unwrap `inbound_handoff` performed when it constructed the
/// `MemorySecretStore`. The control assertion pins the other half: the same handoff's
/// `store` — the raw `FileSecretStore` `run_inbound_loop` keeps, unchanged by this task — cannot
/// perform even *one* operation under the same conditions, which is exactly what makes the
/// pre-4.43 wiring's 101 unwraps visible here.
#[test]
fn the_whole_file_backed_republish_costs_no_further_seed_unwrap_after_inbound_handoffs_single_one()
{
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let passphrase = "correct horse battery staple";

    let mut session = OnboardingSession::default();
    let (_generated, keyfile) = block_on(onboard_file_account(
        &server,
        &mut session,
        passphrase,
        "self-org.test",
    ));
    let handoff = block_on(unlock_and_hand_off(&keyfile, passphrase, &mut session));

    // Everything the republish is allowed to rely on has already been unwrapped, once, by
    // `inbound_handoff`. Take the keyfile away: no further scrypt unwrap can possibly succeed.
    let stashed = tmp.path().join("account.key.stashed");
    std::fs::rename(&keyfile, &stashed).expect("stash the keyfile");
    assert!(!keyfile.exists());

    // Control: the store `run_inbound_loop` keeps really does re-read the keyfile per operation —
    // it cannot sign even once now. (Task 4.39's wiring handed *this* store to `republish_bundle`,
    // which is why it paid 101 unwraps and took ~190 s.)
    assert!(
        handoff
            .store
            .use_key(&handoff.handle, SignOrDh::Sign, b"probe")
            .is_err(),
        "InboundHandoff::store must still be the per-call-unwrapping FileSecretStore (it holds no \
         raw seed of its own) — if this ever succeeds with the keyfile gone, the residency bound \
         this task's security rationale depends on has quietly changed"
    );

    // Pins `EXPECTED_AT_REST_DERIVES` to a stated fact rather than to luck: with no `sessions.bin`
    // on disk yet, `load_chat` takes its `NotFound` arm (no `derive_key`) and `save_chat`'s
    // `seal_at_rest` is the single at-rest derive of the whole republish.
    assert!(
        !account::sessions_path().expect("sessions_path").exists(),
        "this account was just onboarded — nothing should have written sessions.bin before the \
         republish, or the derive count asserted below is measuring a different sequence"
    );

    let counting = CountingStore::new(handoff.bulk_signing_store);
    block_on(republish_bundle(
        &counting,
        &handoff.handle,
        handoff.account_pub,
        &handoff.server,
    ))
    .expect(
        "the whole republish must complete from the single seed unwrap inbound_handoff already \
         performed — with the keyfile gone, any second unwrap would have failed",
    );

    // 1 connect-time auth signature + 1 SPK + DEFAULT_OTK_COUNT OTKs.
    let expected_signs = 2 + DEFAULT_OTK_COUNT;
    assert_eq!(
        counting.signs(),
        expected_signs,
        "expected {expected_signs} signing ops (1 connect auth + 1 SPK + {DEFAULT_OTK_COUNT} OTKs) \
         through the one already-unwrapped store"
    );
    // An exact count, not a floor, for the same reason `signs()` above is exact — see
    // `EXPECTED_AT_REST_DERIVES` for why this scenario's number is 1 rather than 2.
    assert_eq!(
        counting.derives(),
        EXPECTED_AT_REST_DERIVES,
        "save_chat's at-rest sealing must also have gone through the same single unwrap — \
         exactly {EXPECTED_AT_REST_DERIVES} derive_key call for a just-onboarded account, whose \
         load_chat finds no sessions.bin to open (see EXPECTED_AT_REST_DERIVES)"
    );

    std::fs::rename(&stashed, &keyfile).expect("restore the keyfile");
}

// ---------------------------------------------------------------------------
// Source-text fixtures for the two structural assertions below — tests (7) and (8)
// ---------------------------------------------------------------------------

/// `apps/tui/src/lib.rs`'s `run_worker` body **only**, comments stripped.
///
/// Bounding the search to the one function under assertion is the point: searching the whole file
/// would let a future helper that happens to contain any of the needles below make the source-order
/// assertions vacuously true instead of failing loudly. Mirrors how the rendezvous suite's own
/// `include_str!` tests bound theirs (`apps/rendezvous/tests/federation_route.rs:336`,
/// `federation_timeouts.rs:252` both slice from a named `fn` to the next item).
///
/// `include_str!` bakes the on-disk source in at **compile** time, so a rebuild that races an edit
/// to `lib.rs` can make these two tests fail spuriously — rebuild cleanly before believing a
/// surprising failure here.
fn run_worker_source() -> String {
    const LIB_RS: &str = include_str!("../src/lib.rs");
    let start = LIB_RS
        .find("async fn run_worker(")
        .expect("apps/tui/src/lib.rs must still define `async fn run_worker`");
    let body = &LIB_RS[start..];
    // A top-level item's closing brace is the first `}` at column 0 — guaranteed by `cargo fmt`,
    // which this crate enforces.
    let end = body
        .find("\n}\n")
        .expect("`run_worker` must have a closing brace at column 0");
    strip_comments(&body[..end])
}

/// Removes both whole-line and trailing `//` comments, so no comment — a doc comment, or a
/// `// drop(bulk_signing_store);` tacked onto the end of a code line — can ever satisfy a search.
/// Lines containing a string literal are left whole rather than risking a cut inside one (a
/// `"ws://…"` URL is `//`-shaped); none of the needles searched for here live in a string literal.
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                return "";
            }
            match line.find("//") {
                Some(idx) if !line.contains('"') => &line[..idx],
                _ => line,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Byte offset of `needle` in `code`, asserting it occurs **exactly once**. A second occurrence
/// would silently pick the first and turn the source-order assertions into a coincidence.
fn find_exactly_once(code: &str, needle: &str) -> usize {
    let hits = code.matches(needle).count();
    assert_eq!(
        hits, 1,
        "`{needle}` must occur exactly once in `run_worker`'s body — {hits} occurrences would make \
         this file's source-order assertions vacuous rather than falsifiable"
    );
    code.find(needle).expect("just counted exactly one")
}

// ---------------------------------------------------------------------------
// (7) the bulk-signing store is dropped before run_inbound_loop is spawned
// ---------------------------------------------------------------------------

/// **The residency bound task 4.43's security rationale rests on.**
///
/// The rationale is: holding one raw seed for the ~2 s a republish takes is strictly *less* exposure
/// than the 101 `Zeroizing<Vec<u8>>` materializations of that same seed the old path performed across
/// ~190 s. That only holds if the `MemorySecretStore` really is released at republish completion
/// rather than living for the process's life — i.e. if `run_worker` drops it **before**
/// `tokio::spawn(run_inbound_loop(..))`, and never hands it to that loop.
///
/// This is a structural fact of `apps/tui/src/lib.rs` that an integration test cannot re-execute:
/// `run_worker` is private, takes live channels, and spawns a forever-loop. So it is asserted
/// directly against that file's own source text — sliced to `run_worker`'s **own body** and with
/// comments stripped, so neither a doc comment nor some unrelated helper elsewhere in `lib.rs` can
/// satisfy (or silently vacuate) it. The in-repo precedent for that technique is the rendezvous
/// suite's own `include_str!` assertions, which bound their search to one function the same way:
/// `apps/rendezvous/tests/federation_policy.rs:335`, `apps/rendezvous/tests/federation_route.rs:336`,
/// `apps/rendezvous/tests/federation_timeouts.rs:252`. It is explicitly *not* test (4) above — that
/// test met the same private-`run_worker` wall and deliberately **declined** source-text assertion,
/// proving instead the runtime property (`republish_bundle` returns a plain `Err`, never panics)
/// that `run_worker`'s log-only wiring depends on.
///
/// Falsifiable in the four ways that matter: deleting the `drop`, reordering it after the spawn,
/// handing the bulk store to `run_inbound_loop`, or handing `republish_bundle`
/// `store.as_ref()` instead of `bulk_signing_store.as_ref()` each fail this test. That last one is
/// the regression nothing else in this file catches — tests (5), (6) and (8) all call
/// `republish_bundle` directly, so a `run_worker` that quietly went back to `store.as_ref()` would
/// still compile, still satisfy every ordering assertion here, and still leave the whole suite green
/// while restoring the ~190 s freeze. The complementary *runtime* half of the same property lives in
/// test (6): the store that `run_inbound_loop` does keep provably holds no raw seed at all.
#[test]
fn run_worker_drops_the_bulk_signing_store_before_spawning_the_inbound_loop() {
    let code = run_worker_source();

    let republish = find_exactly_once(&code, "worker::republish_bundle(");
    let dropped = find_exactly_once(&code, "drop(bulk_signing_store);");
    let spawn = find_exactly_once(&code, "tokio::spawn(worker::run_inbound_loop(");

    assert!(
        republish < dropped,
        "the bulk-signing store must be dropped *after* the republish that needs it"
    );
    assert!(
        dropped < spawn,
        "the bulk-signing store must be dropped *before* run_inbound_loop is spawned — otherwise \
         the raw account seed stays resident for the whole process's life, which is a materially \
         different security decision than the one task 4.43 was cleared for"
    );

    // *Which store the republish is handed* — the half the ordering assertions above do not pin.
    let call_site = &code[republish..dropped];
    assert!(
        call_site.contains("bulk_signing_store.as_ref()"),
        "run_worker must hand republish_bundle the unwrap-once bulk-signing store, never \
         InboundHandoff::store: `bulk_signing_store.as_ref()` does not appear between the \
         republish call and the drop. Passing `store.as_ref()` here compiles, keeps every other \
         assertion in this file green, and restores the ~190 s file-backed \"Unlocking\" freeze \
         task 4.43 exists to close — got: {call_site}"
    );

    let spawn_args = &code[spawn..];
    let spawn_args = &spawn_args[..spawn_args
        .find("));")
        .expect("the spawn call must terminate")];
    assert!(
        !spawn_args.contains("bulk_signing_store"),
        "run_inbound_loop must be handed InboundHandoff::store, never the raw-seed bulk-signing \
         store (see task 4.43's \"The boundary\") — got: {spawn_args}"
    );
}

// ---------------------------------------------------------------------------
// (8) a failed republish never prevents run_inbound_loop from starting (task 4.43 re-checks 4.39's
//     guarantee against the *new* wiring, which now destructures the handoff)
// ---------------------------------------------------------------------------

/// Deliverable 5 of task 4.43: the wiring around `republish_bundle` changed (the handoff is now
/// destructured, a different store is passed, and the bulk store is dropped between the call and the
/// spawn), so the "a failed republish must never block the receive loop" guarantee test (4) proves
/// for `republish_bundle` itself is re-checked here at the *call-site* level, for a file-backed
/// account, against a deliberately unreachable server.
///
/// Structural, for the same reason test (7) is: what this asserts is that `run_worker`'s republish
/// call has no early return, no `?`, and no `unwrap`/`expect` between it and the spawn — the spawn is
/// unconditional. Paired with test (4)'s runtime proof that a failed republish returns a plain
/// `Err(String)`, and with the file-backed failure run below, that is the whole guarantee.
#[test]
fn a_failed_file_backed_republish_still_reaches_the_inbound_loop_spawn() {
    // Runtime half: a real file-backed handoff, a real (unreachable) server, the real call —
    // it must return `Err`, not panic, not hang, and leave the handoff's own `store` intact for the
    // spawn that follows.
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let passphrase = "correct horse battery staple";

    let mut session = OnboardingSession::default();
    let (_generated, keyfile) = block_on(onboard_file_account(
        &server,
        &mut session,
        passphrase,
        "self-org.test",
    ));
    let handoff = block_on(unlock_and_hand_off(&keyfile, passphrase, &mut session));

    let result = block_on(republish_bundle(
        handoff.bulk_signing_store.as_ref(),
        &handoff.handle,
        handoff.account_pub,
        "ws://127.0.0.1:1",
    ));
    match result {
        Err(e) => assert!(
            e.contains("connecting to"),
            "expected a connect-stage error message, got {e:?}"
        ),
        Ok(()) => panic!("republish_bundle must not succeed against an unreachable server"),
    }
    // The per-delivery store `run_inbound_loop` receives is untouched by that failure.
    handoff
        .store
        .use_key(&handoff.handle, SignOrDh::Sign, b"probe")
        .expect("InboundHandoff::store must still be usable after a failed republish");

    // Structural half: nothing between the republish call and the spawn can short-circuit.
    // Bounded to `run_worker`'s own body by the same helper test (7) uses — an unrelated helper
    // elsewhere in `lib.rs` must never be what this reads.
    let code = run_worker_source();
    let republish = find_exactly_once(&code, "worker::republish_bundle(");
    let spawn = find_exactly_once(&code, "tokio::spawn(worker::run_inbound_loop(");
    let between = &code[republish..spawn];
    for forbidden in ["return", "continue", "break", ".unwrap()", ".expect("] {
        assert!(
            !between.contains(forbidden),
            "run_worker must reach tokio::spawn(run_inbound_loop(..)) unconditionally after the \
             republish — found `{forbidden}` between the two"
        );
    }
}
