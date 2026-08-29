//! `meridian_tui::worker` — task 4.30's own test target
//! (`cargo nextest run -p meridian-tui --test run_worker_account`).
//!
//! Dispatches `GenerateAccount`/`Register`/`PublishBundle`/`Unlock` effects directly against
//! `meridian_tui::worker::dispatch` (no live screen stack, no channel plumbing) and asserts the real
//! `account.json`/keystore/registration/bundle-publish side effects this task's own goal names — the
//! exact hang task 4.28 reproduced (`meridian tui` stuck on "Generating your identity…") is this
//! function never having existed until now.
//!
//! `StoreChoice::Os` is deliberately not exercised here — the same reason `apps/cli/tests/` never
//! drives `--store os`: it needs a real platform credential store (Keychain/DPAPI/Secret Service),
//! which a headless CI runner does not have. `StoreChoice::File` covers every code path this task
//! actually adds (`open_store`/`open_store_for_bulk_signing` branch identically on `StoreChoice`;
//! only the underlying `SecretStore` differs), so it is the only variant driven below.
//!
//! ## Proving the connection-reuse invariant
//! [`CountingStore`] wraps a real in-process `meridian-rendezvous` server's [`meridian_rendezvous::Store`]
//! to count successful authentications (`register_account` is called exactly once per successful
//! `auth` handshake — see `apps/rendezvous/src/ws.rs::authenticate`). If `Effect::PublishBundle`'s
//! execution reconnected instead of reusing the live `SignalingClient`
//! `Effect::Register`'s execution cached, this counter would read 2 for a single onboarding run; the
//! reuse test below asserts it reads 1 — a falsifiable proof of the exact invariant
//! `RegisterRequest`'s own doc comment (`crate::app`) requires, not just an absence-of-error check.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use meridian_core::account;
use meridian_core::identity::{generate_account, FileSecretStore};
use meridian_proto::PrekeyBundle;
use meridian_rendezvous::{serve, AppState, Config, MemoryStore, Store};

use meridian_tui::app::{
    Effect, GenerateAccountEffect, GenerateAccountRequest, PublishBundleEffect,
    PublishBundleRequest, RegisterRequest, SessionOutcome, StoreChoice, UnlockEffect,
    UnlockRequest, WorkerEvent,
};
use meridian_tui::worker::{dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` environment guard — mirrors `apps/core/src/account.rs`'s own private test-only
// `EnvGuard` / `apps/tui/tests/at_rest_audit.rs`'s reproduction of it.
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

// ---------------------------------------------------------------------------
// In-process rendezvous server — mirrors `apps/cli/tests/rendezvous_demo.rs::spawn_server` exactly.
// ---------------------------------------------------------------------------

/// Wraps a real [`MemoryStore`] to count successful registrations (one per successful `auth`
/// handshake — `apps/rendezvous/src/ws.rs::authenticate` calls `register_account` exactly once per
/// connection that gets past the challenge-response check), so a test can assert *how many separate
/// connections* a sequence of effects actually opened. Can also be told to fail exactly one
/// `put_bundle` call ([`CountingStore::new_failing_first_publish`]) so a test can exercise a real
/// `PublishBundle` failure *after* a successful `Register` — see
/// `publish_bundle_retry_after_a_transient_failure_reuses_the_cached_connection` below.
struct CountingStore {
    inner: MemoryStore,
    register_calls: AtomicUsize,
    /// When `true`, the *next* `put_bundle` call fails with a real backend error and resets this
    /// back to `false` — so exactly one call fails, and every call after (including a retry) hits
    /// the real, working `inner` store.
    fail_next_publish: AtomicBool,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            register_calls: AtomicUsize::new(0),
            fail_next_publish: AtomicBool::new(false),
        }
    }

    /// Same as [`CountingStore::new`], but the very first `put_bundle` call against it fails.
    fn new_failing_first_publish() -> Self {
        Self {
            fail_next_publish: AtomicBool::new(true),
            ..Self::new()
        }
    }
}

#[async_trait]
impl Store for CountingStore {
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> Result<(), meridian_rendezvous::store::StoreError> {
        self.register_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .register_account(account_pub, admission, max_bundle_v)
            .await
    }

    async fn put_bundle(
        &self,
        bundle: PrekeyBundle,
    ) -> Result<(), meridian_rendezvous::store::StoreError> {
        if self.fail_next_publish.swap(false, Ordering::SeqCst) {
            return Err(meridian_rendezvous::store::StoreError::Backend(
                "simulated transient put_bundle failure".to_string(),
            ));
        }
        self.inner.put_bundle(bundle).await
    }

    async fn get_bundle(
        &self,
        target: &[u8; 32],
    ) -> Result<Option<PrekeyBundle>, meridian_rendezvous::store::StoreError> {
        self.inner.get_bundle(target).await
    }

    async fn total_otks(&self) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner.total_otks().await
    }

    // (task 8.8) Forwarded to `self.inner`, exactly like every other method above — without
    // these, the trait's own default impls (`StoreError::Backend("... not implemented")`, added
    // task 8.1) apply instead. See `run_worker_chat.rs::BundleFetchCountingStore`'s identical
    // forwarding (and its doc comment) for the concrete failure this closes: a route to an
    // offline recipient (task 8.5) calls these against `Config::default()`'s non-zero
    // `ttl_days` and would hard-fail with `bad_request "store failed"` without them.
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
        now: u64,
    ) -> Result<Vec<meridian_rendezvous::store::MailboxEntry>, meridian_rendezvous::store::StoreError>
    {
        self.inner
            .mailbox_list_for_recipient(recipient_pub, now)
            .await
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
        now: u64,
    ) -> Result<u64, meridian_rendezvous::store::StoreError> {
        self.inner
            .mailbox_size_bytes_for_recipient(recipient_pub, now)
            .await
    }
}

/// Starts the real rendezvous server on a background OS thread with its own runtime (so it keeps
/// running independently of whatever runtime `#[tokio::test]` gives the calling test), bound to an
/// ephemeral port. Returns the `ws://` URL and a handle to the counting store behind it.
fn spawn_server() -> (String, Arc<CountingStore>) {
    spawn_server_from(CountingStore::new())
}

/// Same as [`spawn_server`], but behind a caller-supplied [`CountingStore`] — e.g.
/// [`CountingStore::new_failing_first_publish`] — instead of a fresh default one.
fn spawn_server_from(store: CountingStore) -> (String, Arc<CountingStore>) {
    let store = Arc::new(store);
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
// Small helpers
// ---------------------------------------------------------------------------

/// Runs a future to completion on a fresh current-thread runtime — this crate's own dependency list
/// only pulls in `tokio`'s `net` feature for dev-dependencies (see `Cargo.toml`), so plain
/// `#[tokio::test]` (which needs the `rt`/`macros` features already present) works; kept as a named
/// helper purely so every test body reads the same "dispatch, then assert" shape as
/// `apps/cli/tests/rendezvous_demo.rs`.
fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime")
        .block_on(fut)
}

fn keyfile_path(tmp: &Path) -> PathBuf {
    tmp.join("account.key")
}

// ---------------------------------------------------------------------------
// GenerateAccount
// ---------------------------------------------------------------------------

#[test]
fn generate_account_file_store_writes_account_json_and_keyfile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());

    let mut session = OnboardingSession::default();
    let effect = Effect::GenerateAccount(GenerateAccountEffect {
        request: GenerateAccountRequest {
            store: StoreChoice::File {
                passphrase: "correct horse battery staple".to_string(),
            },
            hint: "self-org.test".to_string(),
        },
        outcome: None,
    });

    let outcome = block_on(dispatch(effect, &mut session));
    let generated = match outcome {
        WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            outcome: Some(generated),
            ..
        })) => generated,
        other => panic!("expected a completed GenerateAccount with an outcome, got {other:?}"),
    };

    assert!(generated.id.starts_with("mrd1:"));
    assert!(generated.id.ends_with("@self-org.test"));
    assert_eq!(generated.label, hex::encode(generated.account_pub));

    // Real account.json, readable back through the same shared descriptor type the CLI/onboarding
    // screen both use.
    let descriptor = account::AccountDescriptor::load().expect("account.json was written");
    assert_eq!(descriptor.pubkey, generated.label);
    assert_eq!(descriptor.hint, "self-org.test");
    assert_eq!(descriptor.store, account::StoreKind::File);
    assert_eq!(descriptor.id_string().unwrap(), generated.id);

    // Real keyfile, at the worker's own default location next to account.json.
    let keyfile = descriptor
        .keyfile
        .expect("file-store descriptor carries a keyfile path");
    assert_eq!(keyfile, keyfile_path(tmp.path()));
    assert!(keyfile.exists(), "keyfile must actually exist on disk");
    let raw = std::fs::read(&keyfile).expect("read keyfile");
    assert!(!raw.is_empty());
    // age-encrypted, not a bare 32-byte seed dump.
    assert_ne!(raw.len(), 32);
}

#[test]
fn generate_account_rejects_an_invalid_hint_without_touching_disk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());

    let mut session = OnboardingSession::default();
    let effect = Effect::GenerateAccount(GenerateAccountEffect {
        request: GenerateAccountRequest {
            store: StoreChoice::File {
                passphrase: "whatever".to_string(),
            },
            hint: String::new(), // empty hint is invalid — meridian_core::identity::validate_hint
        },
        outcome: None,
    });

    let outcome = block_on(dispatch(effect, &mut session));
    match outcome {
        WorkerEvent::Failed(
            Effect::GenerateAccount(GenerateAccountEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(!message.is_empty());
        }
        other => panic!("expected a failed GenerateAccount, got {other:?}"),
    }
    assert!(
        !tmp.path().join("account.json").exists(),
        "a rejected hint must never reach account.json"
    );
}

// ---------------------------------------------------------------------------
// Register -> PublishBundle: one live connection, never a reconnect between them
// ---------------------------------------------------------------------------

#[test]
fn register_then_publish_bundle_reuses_one_connection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, store) = spawn_server();

    let mut session = OnboardingSession::default();
    let passphrase = "correct horse battery staple".to_string();

    // --- GenerateAccount --------------------------------------------------
    let generate_effect = Effect::GenerateAccount(GenerateAccountEffect {
        request: GenerateAccountRequest {
            store: StoreChoice::File {
                passphrase: passphrase.clone(),
            },
            hint: "self-org.test".to_string(),
        },
        outcome: None,
    });
    let generated = match block_on(dispatch(generate_effect, &mut session)) {
        WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            outcome: Some(generated),
            ..
        })) => generated,
        other => panic!("expected a completed GenerateAccount, got {other:?}"),
    };

    // --- Register, then PublishBundle -- both dispatched under the *same* runtime, mirroring the
    // real worker: `crate::run_worker`'s loop runs as a single tokio task for the whole process
    // lifetime, so the `SignalingClient` a `Register` dispatch caches always gets reused under the
    // very runtime that created it. Splitting these two dispatches across separate `block_on` calls
    // here (each spinning up its own throwaway runtime) would tear down the cached client's
    // underlying I/O resources between them — an artifact of this test harness, not a real
    // constraint on `OnboardingSession` itself.
    let register_effect = Effect::Register(RegisterRequest {
        server: server.clone(),
        invite: None,
        store: StoreChoice::File {
            passphrase: passphrase.clone(),
        },
        label: generated.label.clone(),
        account_pub: generated.account_pub,
    });
    let publish_effect = Effect::PublishBundle(PublishBundleEffect {
        request: PublishBundleRequest {
            server: server.clone(),
            store: StoreChoice::File { passphrase },
            label: generated.label.clone(),
            account_pub: generated.account_pub,
            otk_count: 5,
        },
        outcome: None,
    });
    block_on(async {
        match dispatch(register_effect, &mut session).await {
            WorkerEvent::Completed(Effect::Register(_)) => {}
            other => panic!("expected a completed Register, got {other:?}"),
        }
        match dispatch(publish_effect, &mut session).await {
            WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
                outcome: Some(published),
                ..
            })) => {
                assert_eq!(published.otk_count, 5);
            }
            other => panic!("expected a completed PublishBundle, got {other:?}"),
        }
    });

    // The falsifiable proof: exactly one successful auth handshake happened for this account —
    // Register's connection was reused for the publish, never a second connect.
    assert_eq!(
        store.register_calls.load(Ordering::SeqCst),
        1,
        "PublishBundle must reuse Register's live connection, never open a second one"
    );
}

#[test]
fn publish_bundle_without_a_prior_register_fails_closed_never_silently_reconnects() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, store) = spawn_server();

    // A fresh session with nothing cached — no Effect::Register was ever dispatched into it.
    let mut session = OnboardingSession::default();
    let publish_effect = Effect::PublishBundle(PublishBundleEffect {
        request: PublishBundleRequest {
            server,
            store: StoreChoice::File {
                passphrase: "irrelevant".to_string(),
            },
            label: hex::encode([0x11u8; 32]),
            account_pub: [0x11u8; 32],
            otk_count: 5,
        },
        outcome: None,
    });

    match block_on(dispatch(publish_effect, &mut session)) {
        WorkerEvent::Failed(
            Effect::PublishBundle(PublishBundleEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                message.contains("no active registration session"),
                "message: {message}"
            );
        }
        other => panic!("expected a failed PublishBundle, got {other:?}"),
    }
    // Never opened any connection at all — no auth handshake against the real server.
    assert_eq!(store.register_calls.load(Ordering::SeqCst), 0);
}

/// The exact scenario `worker.rs`'s own module doc comment reasons about: `Register` succeeds, and
/// then the *following* `PublishBundle` call itself fails (a transient server-side error, simulated
/// here via [`CountingStore::new_failing_first_publish`]) — not "no prior `Register` at all"
/// (already covered above). Proves two things a naive `session.take(...)` *before* the fallible
/// `publish_bundle` call would get wrong:
///   (a) the first failure surfaces the real underlying error, never the "no active registration
///       session" masking message — that message is reserved for the *no cached connection at all*
///       case;
///   (b) a retry of the identical effect afterwards reuses the *same* still-cached connection and
///       succeeds, without a second `Register`/auth handshake (`register_calls` still reads 1).
#[test]
fn publish_bundle_retry_after_a_transient_failure_reuses_the_cached_connection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (server, store) = spawn_server_from(CountingStore::new_failing_first_publish());

    let mut session = OnboardingSession::default();
    let passphrase = "correct horse battery staple".to_string();

    // --- GenerateAccount --------------------------------------------------
    let generate_effect = Effect::GenerateAccount(GenerateAccountEffect {
        request: GenerateAccountRequest {
            store: StoreChoice::File {
                passphrase: passphrase.clone(),
            },
            hint: "self-org.test".to_string(),
        },
        outcome: None,
    });
    let generated = match block_on(dispatch(generate_effect, &mut session)) {
        WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            outcome: Some(generated),
            ..
        })) => generated,
        other => panic!("expected a completed GenerateAccount, got {other:?}"),
    };

    let register_effect = Effect::Register(RegisterRequest {
        server: server.clone(),
        invite: None,
        store: StoreChoice::File {
            passphrase: passphrase.clone(),
        },
        label: generated.label.clone(),
        account_pub: generated.account_pub,
    });
    // Dispatched twice below (the failed attempt, then its retry) — same request both times, exactly
    // how `crate::screens::onboarding`'s `Failed::retry` re-dispatches on Enter/`r`. Kept as the
    // request struct (not a whole `Effect`) so it can be cloned for the second dispatch: `Effect`
    // itself deliberately does not implement `Clone` (see its own doc comment in `crate::app`) — a
    // real retry re-dispatches a freshly built `Effect` from the same request data, never clones a
    // live `Effect` value, exactly what this rewrites the test to do.
    let publish_request = PublishBundleRequest {
        server: server.clone(),
        store: StoreChoice::File { passphrase },
        label: generated.label.clone(),
        account_pub: generated.account_pub,
        otk_count: 5,
    };

    // Same runtime for the whole sequence — see the identical note on
    // `register_then_publish_bundle_reuses_one_connection` above for why.
    block_on(async {
        match dispatch(register_effect, &mut session).await {
            WorkerEvent::Completed(Effect::Register(_)) => {}
            other => panic!("expected a completed Register, got {other:?}"),
        }

        // First PublishBundle attempt: the server's store fails this one `put_bundle` call. Must
        // surface the real backend error, never the masking "no active registration session"
        // message — that would mean the connection was already gone before this call even ran.
        let first_attempt = Effect::PublishBundle(PublishBundleEffect {
            request: publish_request.clone(),
            outcome: None,
        });
        match dispatch(first_attempt, &mut session).await {
            WorkerEvent::Failed(
                Effect::PublishBundle(PublishBundleEffect { outcome: None, .. }),
                message,
            ) => {
                assert!(
                    !message.contains("no active registration session"),
                    "a real publish failure must not be masked as a missing session: {message}"
                );
            }
            other => panic!("expected a failed PublishBundle, got {other:?}"),
        }

        // Retry: dispatching the identical request again (as a freshly built `Effect`) must reuse the
        // same still-cached connection and succeed.
        let retry = Effect::PublishBundle(PublishBundleEffect {
            request: publish_request,
            outcome: None,
        });
        match dispatch(retry, &mut session).await {
            WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
                outcome: Some(published),
                ..
            })) => {
                assert_eq!(published.otk_count, 5);
            }
            other => panic!("expected the retried PublishBundle to complete, got {other:?}"),
        }
    });

    // The falsifiable proof: still exactly one successful auth handshake for this account — the
    // retry reused Register's live connection, it never opened a second one.
    assert_eq!(
        store.register_calls.load(Ordering::SeqCst),
        1,
        "a PublishBundle retry must reuse the cached connection, never open a second one"
    );
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

#[test]
fn unlock_with_the_correct_passphrase_succeeds_and_loads_a_real_live_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("returning-user.key");
    let fs = FileSecretStore::new(&keyfile, "the-right-passphrase");
    let acct = generate_account(&fs, "org-a.test").expect("seed a returning-user keyfile");
    account::AccountDescriptor::new_file(&acct, &keyfile)
        .save()
        .expect("save account.json for the returning user");

    let mut session = OnboardingSession::default();
    let effect = Effect::Unlock(Box::new(UnlockEffect {
        request: UnlockRequest {
            keyfile,
            passphrase: "the-right-passphrase".to_string(),
        },
        outcome: SessionOutcome::empty(),
    }));
    match block_on(dispatch(effect, &mut session)) {
        WorkerEvent::Completed(Effect::Unlock(effect)) => {
            let UnlockEffect { outcome, .. } = *effect;
            let live = outcome
                .into_option()
                .expect("a completed Unlock must carry a real LiveSession");
            assert_eq!(
                live.account.pubkey,
                hex::encode(acct.public_key().as_bytes())
            );
            // Nothing was ever sealed for this brand-new returning-user account, so every store
            // defaults — never an error — exactly `LiveSession::empty`'s own shape.
            assert_eq!(live.trust.contacts().count(), 0);
            assert!(!live.chat.has_session(&[0u8; 32]));
            assert!(live.contacts.contacts.is_empty());
        }
        other => panic!("expected a completed Unlock, got {other:?}"),
    }
}

#[test]
fn unlock_with_the_wrong_passphrase_fails_without_leaking_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("returning-user.key");
    let fs = FileSecretStore::new(&keyfile, "the-right-passphrase");
    let acct = generate_account(&fs, "org-a.test").expect("seed a returning-user keyfile");
    account::AccountDescriptor::new_file(&acct, &keyfile)
        .save()
        .expect("save account.json for the returning user");

    let mut session = OnboardingSession::default();
    let effect = Effect::Unlock(Box::new(UnlockEffect {
        request: UnlockRequest {
            keyfile,
            passphrase: "totally-wrong-guess".to_string(),
        },
        outcome: SessionOutcome::empty(),
    }));
    match block_on(dispatch(effect, &mut session)) {
        WorkerEvent::Failed(Effect::Unlock(effect), message) => {
            let UnlockEffect { outcome, .. } = *effect;
            assert!(!message.contains("totally-wrong-guess"));
            assert!(!message.contains("the-right-passphrase"));
            assert!(outcome.into_option().is_none());
        }
        other => panic!("expected a failed Unlock, got {other:?}"),
    }
}

/// Never let `StoreChoice::File`'s passphrase (or `UnlockRequest`'s) leak through `Effect`'s own
/// `Debug` — this task's own risk note. Not a new redaction mechanism; just proves the existing
/// hand-rolled `Debug` impls (`crate::app::StoreChoice`/`UnlockRequest`) actually cover every
/// `Effect` variant this module dispatches.
#[test]
fn effect_debug_never_leaks_a_passphrase() {
    let secret = "SENTINEL-DO-NOT-LEAK-b6f2";
    let effects = [
        Effect::GenerateAccount(GenerateAccountEffect {
            request: GenerateAccountRequest {
                store: StoreChoice::File {
                    passphrase: secret.to_string(),
                },
                hint: "org.test".to_string(),
            },
            outcome: None,
        }),
        Effect::Register(RegisterRequest {
            server: "ws://example".to_string(),
            invite: None,
            store: StoreChoice::File {
                passphrase: secret.to_string(),
            },
            label: "deadbeef".to_string(),
            account_pub: [0u8; 32],
        }),
        Effect::PublishBundle(PublishBundleEffect {
            request: PublishBundleRequest {
                server: "ws://example".to_string(),
                store: StoreChoice::File {
                    passphrase: secret.to_string(),
                },
                label: "deadbeef".to_string(),
                account_pub: [0u8; 32],
                otk_count: 1,
            },
            outcome: None,
        }),
        Effect::Unlock(Box::new(UnlockEffect {
            request: UnlockRequest {
                keyfile: PathBuf::from("/tmp/x.key"),
                passphrase: secret.to_string(),
            },
            outcome: SessionOutcome::empty(),
        })),
    ];
    for effect in &effects {
        let dump = format!("{effect:?}");
        assert!(
            !dump.contains(secret),
            "Effect::Debug leaked a passphrase: {dump}"
        );
    }
}
