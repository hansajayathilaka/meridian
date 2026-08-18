//! `Effect::LoadSession` / `Effect::Unlock`'s extended outcome — task 4.29's own test target
//! (`cargo nextest run -p meridian-tui --test load_session`).
//!
//! Dispatches `LoadSession`/`Unlock` directly against `meridian_tui::worker::dispatch` (no live
//! screen stack, no channel plumbing — the same harness shape `apps/tui/tests/run_worker_account.rs`
//! already established for the rest of the account-lifecycle effects) and asserts the real
//! `LiveSession` a worker builds off real, on-disk `trust.bin`/`sessions.bin`/`contacts.json`.
//!
//! **`StoreChoice::Os` / the OS-keystore path is exercised by exactly one test below, and it is
//! `#[ignore]`d.** Mirrors `run_worker_account.rs`'s own documented precedent (`StoreChoice::Os` is
//! "deliberately not exercised" there either) for the identical reason: it needs a real platform
//! credential store (Keychain/DPAPI/Secret Service), which a headless CI runner — and this sandbox —
//! does not have (confirmed directly: a bare `keyring::Entry::new(..).set_password(..)` in this
//! environment fails with "no secret service provider or dbus session found"). The loading logic that
//! branch shares with the file-backed one (`load_live_session` and everything it calls) is proven
//! thoroughly both here (via `Effect::Unlock`, which shares that exact code path — see
//! `apps/tui/src/worker.rs::run_unlock`/`run_load_session`, both of which call the same
//! `load_live_session`) and by `meridian_tui`'s own `worker::tests` unit tests (`cargo nextest run -p
//! meridian-tui --lib worker::tests`), which drive it directly against a `MemorySecretStore`. Only the
//! thin `keyring`-backed `OsSecretStore::new`/`init_os_keystore` glue itself is untestable headlessly;
//! `run_load_session`'s own body keeps that surface to one small, easily-audited branch.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::identity::{generate_account, FileSecretStore};
use meridian_core::trust::TrustStore;

use meridian_tui::app::{
    Effect, LoadSessionEffect, LoadSessionOutcome, LoadSessionRequest, SessionOutcome,
    UnlockEffect, UnlockRequest, WorkerEvent,
};
use meridian_tui::worker::{dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` environment guard — mirrors `apps/tui/tests/run_worker_account.rs`'s own
// reproduction of `apps/core/src/account.rs`'s private test-only `EnvGuard`.
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

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

fn load_session_effect() -> Effect {
    Effect::LoadSession(LoadSessionEffect {
        request: LoadSessionRequest,
        outcome: None,
    })
}

// ---------------------------------------------------------------------------
// LoadSession: no account.json at all
// ---------------------------------------------------------------------------

#[test]
fn load_session_with_no_account_json_returns_no_account_not_an_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let mut session = OnboardingSession::default();

    match block_on(dispatch(load_session_effect(), &mut session)) {
        WorkerEvent::Completed(Effect::LoadSession(LoadSessionEffect {
            outcome: Some(LoadSessionOutcome::NoAccount),
            ..
        })) => {}
        other => panic!("expected Completed(LoadSession(NoAccount)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// LoadSession: a file-backed account.json must never load through this effect
// ---------------------------------------------------------------------------

#[test]
fn load_session_with_an_existing_file_backed_account_fails_closed_never_touching_unlock_only_data()
{
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("account.key");
    let fs = FileSecretStore::new(&keyfile, "correct horse battery staple");
    let account = generate_account(&fs, "example.org").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");

    let mut session = OnboardingSession::default();
    match block_on(dispatch(load_session_effect(), &mut session)) {
        WorkerEvent::Failed(Effect::LoadSession(_), message) => {
            assert!(
                message.contains("Unlock"),
                "expected the message to point the caller at Effect::Unlock, got: {message}"
            );
        }
        other => panic!("expected a failed LoadSession, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Unlock: the file-backed path's own extended outcome — a real, loaded LiveSession
// ---------------------------------------------------------------------------

#[test]
fn unlock_loads_a_real_live_session_from_real_sealed_trust_and_contacts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("account.key");
    let passphrase = "correct horse battery staple".to_string();
    let fs = FileSecretStore::new(&keyfile, passphrase.clone());
    let account = generate_account(&fs, "example.org").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");
    let handle = account.handle().clone();

    // A real, sealed trust.bin with one pinned contact.
    let mut trust = TrustStore::default();
    trust.observe([0x42u8; 32], "peer.example", 1_760_000_000);
    let trust_sealed = trust.seal_at_rest(&fs, &handle).expect("seal trust.bin");
    let trust_path = account::trust_path().expect("trust_path");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, trust_sealed).expect("write trust.bin");

    // A real, sealed contacts.json with one entry.
    let contacts_doc = meridian_tui::store::contacts::ContactsDocument {
        v: meridian_tui::store::contacts::CURRENT_VERSION,
        contacts: vec![meridian_tui::store::contacts::ContactRecord {
            pubkey: hex::encode([0x42u8; 32]),
            id: account.to_id_string(),
            hint: "peer.example".to_string(),
            petname: Some("Bobby".to_string()),
            trust: meridian_tui::store::contacts::TrustLabel::Pinned,
            pinned_key_history: Vec::new(),
            device_record_version_seen: None,
            policy_override: None,
            added_at: 1_760_000_000,
            last_activity_at: 1_760_000_000,
            unread: 0,
            conv_handle: None,
        }],
    };
    meridian_tui::store::contacts::save(&contacts_doc, &fs, &handle).expect("save contacts.json");

    let mut session = OnboardingSession::default();
    let effect = Effect::Unlock(Box::new(UnlockEffect {
        request: UnlockRequest {
            keyfile,
            passphrase,
        },
        outcome: SessionOutcome::empty(),
    }));
    match block_on(dispatch(effect, &mut session)) {
        WorkerEvent::Completed(Effect::Unlock(effect)) => {
            let UnlockEffect { outcome, .. } = *effect;
            let live = outcome.into_option().expect("a real LiveSession");
            assert_eq!(
                live.account.pubkey,
                hex::encode(account.public_key().as_bytes())
            );
            assert_eq!(live.trust.contacts().count(), 1);
            assert!(live.trust.contact(&[0x42u8; 32]).is_some());
            assert!(!live.chat.has_session(&[0u8; 32]));
            assert_eq!(live.contacts.contacts.len(), 1);
            assert_eq!(live.contacts.contacts[0].petname.as_deref(), Some("Bobby"));
        }
        other => panic!("expected a completed Unlock with a real LiveSession, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Fail-closed: a corrupt/wrong-key trust.bin or sessions.bin must never be silently reinitialized
// ---------------------------------------------------------------------------

#[test]
fn unlock_fails_closed_on_a_corrupt_trust_bin_never_silently_reinitializing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("account.key");
    let passphrase = "correct horse battery staple".to_string();
    let fs = FileSecretStore::new(&keyfile, passphrase.clone());
    let account = generate_account(&fs, "example.org").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");

    let trust_path = account::trust_path().expect("trust_path");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, b"not a real sealed trust store").expect("write garbage trust.bin");

    let mut session = OnboardingSession::default();
    let effect = Effect::Unlock(Box::new(UnlockEffect {
        request: UnlockRequest {
            keyfile,
            passphrase,
        },
        outcome: SessionOutcome::empty(),
    }));
    match block_on(dispatch(effect, &mut session)) {
        WorkerEvent::Failed(Effect::Unlock(effect), message) => {
            let UnlockEffect { outcome, .. } = *effect;
            assert!(
                outcome.into_option().is_none(),
                "a failed Unlock must never carry a fabricated LiveSession"
            );
            assert!(!message.is_empty());
        }
        other => {
            panic!("expected a failed Unlock (fail closed on corrupt trust.bin), got {other:?}")
        }
    }
}

#[test]
fn unlock_fails_closed_on_a_sessions_bin_sealed_under_a_different_account_never_reinitializing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("account.key");
    let passphrase = "correct horse battery staple".to_string();
    let fs = FileSecretStore::new(&keyfile, passphrase.clone());
    let account = generate_account(&fs, "example.org").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");

    // A real sessions.bin, but sealed under an entirely different account's key.
    let other_fs = FileSecretStore::new(tmp.path().join("other.key"), "some-other-passphrase");
    let other_account = generate_account(&other_fs, "other.example").expect("other account");
    let other_handle = other_account.handle().clone();
    let wrong_key_sessions = meridian_core::chat::ChatState::default()
        .seal_at_rest(&other_fs, &other_handle)
        .expect("seal sessions.bin under a different key");
    let sessions_path = account::sessions_path().expect("sessions_path");
    std::fs::create_dir_all(sessions_path.parent().unwrap()).unwrap();
    std::fs::write(&sessions_path, wrong_key_sessions).expect("write wrong-key sessions.bin");

    let mut session = OnboardingSession::default();
    let effect = Effect::Unlock(Box::new(UnlockEffect {
        request: UnlockRequest {
            keyfile,
            passphrase,
        },
        outcome: SessionOutcome::empty(),
    }));
    match block_on(dispatch(effect, &mut session)) {
        WorkerEvent::Failed(Effect::Unlock(effect), message) => {
            let UnlockEffect { outcome, .. } = *effect;
            assert!(
                outcome.into_option().is_none(),
                "a failed Unlock must never carry a fabricated LiveSession"
            );
            assert!(!message.is_empty());
        }
        other => panic!(
            "expected a failed Unlock (fail closed on a wrong-key sessions.bin), got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// OS-keystore: real, but not runnable headlessly — see this file's own module doc.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a real OS keychain/secret-service backend, unavailable in headless CI — see \
            this file's own module doc, and apps/tui/tests/run_worker_account.rs's identical \
            StoreChoice::Os precedent"]
fn load_session_with_an_existing_os_keystore_account_loads_a_real_live_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());

    let mut session = OnboardingSession::default();
    let generate_effect = Effect::GenerateAccount(meridian_tui::app::GenerateAccountEffect {
        request: meridian_tui::app::GenerateAccountRequest {
            store: meridian_tui::app::StoreChoice::Os,
            hint: "example.org".to_string(),
        },
        outcome: None,
    });
    let generated = match block_on(dispatch(generate_effect, &mut session)) {
        WorkerEvent::Completed(Effect::GenerateAccount(
            meridian_tui::app::GenerateAccountEffect {
                outcome: Some(generated),
                ..
            },
        )) => generated,
        other => panic!("expected a completed GenerateAccount, got {other:?}"),
    };

    match block_on(dispatch(load_session_effect(), &mut session)) {
        WorkerEvent::Completed(Effect::LoadSession(LoadSessionEffect {
            outcome: Some(LoadSessionOutcome::Loaded(outcome)),
            ..
        })) => {
            let live = outcome.into_option().expect("a real LiveSession");
            assert_eq!(live.account.pubkey, generated.label);
        }
        other => panic!("expected Completed(LoadSession(Loaded(..))), got {other:?}"),
    }
}
