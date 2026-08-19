//! Task 4.44's own new test target (`cargo nextest run -p meridian-tui --test history_load`) —
//! proves (or refutes) the traced gap: does opening a chat over a peer with existing, sealed,
//! on-disk history (`crate::store::history`, task 4.15) actually render that history, or does
//! `crate::screens::main::handle_key`'s `ContactsAction::OpenChat` arm really construct every chat
//! with a literal empty `Vec<HistoryEntry>` as traced?
//!
//! Mirrors `tests/accept_to_chat.rs`'s own `boot_to_main`/`EnvGuard`/real-`worker::dispatch` idiom —
//! a real, OS-keystore-backed `$MERIDIAN_HOME`, a real `Screen::Main` built through a real
//! `Effect::LoadSession`, real `crossterm` key events through `App`, and (once `Effect::LoadHistory`
//! exists) the real worker executing it against the real sealed `history/<peer>.jsonl` file.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::identity::{generate_account, install_mock_keystore, AccountId, OsSecretStore};

use meridian_tui::app::{App, AppEvent, Effect, Screen};
use meridian_tui::config::TuiConfig;
use meridian_tui::preflight::{preflight_route, InitialRoute};
use meridian_tui::store::contacts::{ContactRecord, ContactsDocument, TrustLabel, CURRENT_VERSION};
use meridian_tui::store::history::{self, Direction as MsgDirection, HistoryEntry, MessageState};
use meridian_tui::worker::{dispatch, OnboardingSession};

const SERVICE: &str = "meridian-tui-history-load-test";
const NOW: u64 = 1_760_000_000;

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors `tests/accept_to_chat.rs`'s own
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
            let _ = keyring::Entry::new("meridian-tui-history-load-warmup", "warmup");
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

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

// ---------------------------------------------------------------------------
// Fixture: a real account, one already-known contact, and a real sealed history/<peer>.jsonl
// ---------------------------------------------------------------------------

fn setup_os_account() -> AccountId {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "self.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    account
}

fn write_contacts_doc(me: &AccountId, doc: &ContactsDocument) {
    let os = OsSecretStore::new(SERVICE);
    meridian_tui::store::contacts::save(doc, &os, me.handle()).expect("save contacts.json");
}

fn seed_bob_contact_and_history(me: &AccountId, bob_pubkey: [u8; 32], entries: &[HistoryEntry]) {
    let doc = ContactsDocument {
        v: CURRENT_VERSION,
        contacts: vec![ContactRecord {
            pubkey: hex::encode(bob_pubkey),
            id: meridian_core::identity::to_id_string(&bob_pubkey, "bob.example").unwrap(),
            hint: "bob.example".to_string(),
            petname: Some("bob".to_string()),
            trust: TrustLabel::Pinned,
            pinned_key_history: Vec::new(),
            device_record_version_seen: None,
            policy_override: None,
            added_at: NOW,
            last_activity_at: NOW,
            unread: 0,
            conv_handle: None,
        }],
    };
    write_contacts_doc(me, &doc);

    // Also give `bob` a real, pinned `trust.bin` record — `crate::screens::main::build_contact_entries`
    // joins `contacts.json` against `trust.bin`; a `contacts.json`-only row still renders (the
    // defensive `None` fallback), but a real fixture should look like a genuinely-observed contact.
    let os = OsSecretStore::new(SERVICE);
    let mut trust = meridian_core::trust::TrustStore::default();
    trust.observe(bob_pubkey, "bob.example", NOW);
    trust
        .set_petname(&bob_pubkey, Some("bob".to_string()))
        .unwrap();
    let sealed = trust
        .seal_at_rest(&os, me.handle())
        .expect("seal trust.bin");
    std::fs::write(account::trust_path().unwrap(), sealed).expect("write trust.bin");

    let os = OsSecretStore::new(SERVICE);
    let handle = me.handle();
    let peer_hex = hex::encode(bob_pubkey);
    for entry in entries {
        history::append(&peer_hex, entry, &os, handle).expect("seed sealed history/<peer>.jsonl");
    }
}

fn sample_entries() -> Vec<HistoryEntry> {
    vec![
        HistoryEntry {
            v: history::CURRENT_VERSION,
            mid: "11111111111111111111111111111111".to_string(),
            dir: MsgDirection::In,
            ts: NOW - 20,
            stream: "mrd.chat/1".to_string(),
            body: "hi from a previous session".to_string(),
            state: MessageState::Received,
        },
        HistoryEntry {
            v: history::CURRENT_VERSION,
            mid: "22222222222222222222222222222222".to_string(),
            dir: MsgDirection::Out,
            ts: NOW - 10,
            stream: "mrd.chat/1".to_string(),
            body: "hey yourself".to_string(),
            state: MessageState::Delivered,
        },
    ]
}

async fn boot_to_main() -> (App, OnboardingSession) {
    let descriptor = AccountDescriptor::load().expect("read account.json");
    let route = preflight_route(Some(descriptor));
    assert!(matches!(route, InitialRoute::LoadSession));
    let (mut app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(matches!(app.current_screen(), Screen::Placeholder));
    let effect = initial_effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::LoadSession(_)));

    let mut session = OnboardingSession::default();
    let event = dispatch(effect, &mut session).await;
    app.update(AppEvent::Worker(Box::new(event)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));
    (app, session)
}

// ---------------------------------------------------------------------------
// Deliverable 1 — the reproducing test.
// ---------------------------------------------------------------------------

/// Opens `bob`'s chat (real `Enter` key, real `Screen::Main`, real sealed `history/<peer>.jsonl`
/// already on disk) and asserts the rendered transcript actually reflects that persisted history —
/// the T17 acceptance criterion "restart restores contacts, history, and ratchet state" this whole
/// task exists to make true. Before the fix, `crate::screens::main::handle_key`'s `OpenChat` arm
/// constructs every chat with a literal `Vec::new()`, so this fails with an empty transcript
/// regardless of what is sealed on disk.
#[tokio::test]
async fn opening_a_chat_with_existing_history_on_disk_renders_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let me = setup_os_account();
    let bob_pubkey = [0x42u8; 32];
    let entries = sample_entries();
    seed_bob_contact_and_history(&me, bob_pubkey, &entries);

    let (mut app, mut session) = boot_to_main().await;
    match app.current_screen() {
        Screen::Main(main) => assert_eq!(main.contacts.entries.len(), 1, "fixture sanity: bob"),
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    // Drive whatever effect(s) opening the chat now dispatches through the real worker — once
    // `Effect::LoadHistory` exists, this is how the transcript actually gets loaded (never inside
    // `handle_key` itself — see this crate's own "no I/O in update" boundary).
    for effect in effects {
        let event = dispatch(effect, &mut session).await;
        app.update(AppEvent::Worker(Box::new(event)));
    }

    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(state.peer_pubkey, bob_pubkey);
            assert_eq!(
                state.entries, entries,
                "expected the real, sealed on-disk transcript to be loaded when the chat opened, \
                 in the same order it was written"
            );
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Deliverable 4 — correct on *both* paths a chat opens: after a restart, and a same-session re-open.
// ---------------------------------------------------------------------------

/// The literal restart case: run 1 opens the chat, sends a message (a real `Effect::SendMessage` +
/// `Effect::PersistHistory` round trip against the real worker, appending to the real sealed
/// `history/<peer>.jsonl`), then the whole `App`/`OnboardingSession` is dropped and rebuilt from
/// disk only — mirrors `tests/accept_to_chat.rs::the_accepted_sender_is_still_reachable_after_a_
/// restart`'s own "drop everything, rebuild from disk" shape.
#[tokio::test]
async fn history_survives_a_restart_in_the_correct_order() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let me = setup_os_account();
    let bob_pubkey = [0x42u8; 32];
    let entries = sample_entries();
    seed_bob_contact_and_history(&me, bob_pubkey, &entries);

    // --- Run 1: open the chat, confirm the seeded history loads, then drop everything ------------
    {
        let (mut app, mut session) = boot_to_main().await;
        let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
        for effect in effects {
            let event = dispatch(effect, &mut session).await;
            app.update(AppEvent::Worker(Box::new(event)));
        }
        match app.current_screen() {
            Screen::Chat(state) => assert_eq!(state.entries, entries),
            other => panic!("expected Screen::Chat, got {other:?}"),
        }
    }

    // --- Run 2: a brand-new App + a brand-new OnboardingSession, rebuilt from disk only -----------
    let (mut app, mut session) = boot_to_main().await;
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    for effect in effects {
        let event = dispatch(effect, &mut session).await;
        app.update(AppEvent::Worker(Box::new(event)));
    }
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries, entries,
            "the same sealed transcript must survive a real restart, in the same order"
        ),
        other => panic!("expected Screen::Chat after a restart, got {other:?}"),
    }
}

/// The same-session re-open case (task 4.44's second named path): `Esc` out of a chat, back into
/// `Screen::Main`, then `Enter` again — a fresh `Effect::LoadHistory`, run through the real worker
/// again, must show the same transcript rather than the empty one `ChatState::new` always starts
/// with. Closes the exact gap this task's own Goal names: "which today discards the popped
/// `ChatState`'s entries."
#[tokio::test]
async fn re_opening_a_chat_within_the_same_session_shows_the_transcript_again() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let me = setup_os_account();
    let bob_pubkey = [0x42u8; 32];
    let entries = sample_entries();
    seed_bob_contact_and_history(&me, bob_pubkey, &entries);

    let (mut app, mut session) = boot_to_main().await;

    // First open.
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    for effect in effects {
        let event = dispatch(effect, &mut session).await;
        app.update(AppEvent::Worker(Box::new(event)));
    }
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.entries, entries),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // Esc back to Main — the popped `ChatState`'s in-memory `entries` are discarded (by design; see
    // `crate::app::App::reclaim_trust`'s own doc — only `trust` is reclaimed, never `entries`).
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));

    // Re-open: a fresh Screen::Chat starts empty again, but the fresh Effect::LoadHistory this
    // dispatches, run for real, restores the same transcript from the still-sealed file on disk.
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert!(
            state.entries.is_empty(),
            "the screen itself starts empty again on every open — the effect round trip is what \
             restores it"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
    for effect in effects {
        let event = dispatch(effect, &mut session).await;
        app.update(AppEvent::Worker(Box::new(event)));
    }
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries, entries,
            "a same-session re-open must show the transcript again, not stay empty"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `crate::store::history::load_or_default`'s own "no file yet" contract still holds for a
// never-messaged contact — never an error, an empty transcript.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn opening_a_chat_with_a_contact_that_has_no_history_yet_is_not_an_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let me = setup_os_account();
    let bob_pubkey = [0x42u8; 32];
    seed_bob_contact_and_history(&me, bob_pubkey, &[]);

    let (mut app, mut session) = boot_to_main().await;
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::LoadHistory(_) => {}
        other => panic!("expected Effect::LoadHistory, got {other:?}"),
    }
    let event = dispatch(effects.into_iter().next().unwrap(), &mut session).await;
    match &event {
        meridian_tui::app::WorkerEvent::Completed(Effect::LoadHistory(e)) => {
            assert_eq!(e.outcome, Some(Vec::new()))
        }
        other => panic!("expected a completed LoadHistory with an empty transcript, got {other:?}"),
    }
    app.update(AppEvent::Worker(Box::new(event)));
    match app.current_screen() {
        Screen::Chat(state) => assert!(state.entries.is_empty()),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}
