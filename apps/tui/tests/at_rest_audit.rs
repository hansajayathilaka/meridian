//! At-rest audit harness (task 4.27) — the on-disk counterpart to `meridian demo opacity-audit`
//! (`apps/cli/src/opacity.rs`). Scripts a full, realistic conversation headlessly, then recursively
//! scans every byte of every file the run wrote under a temp `$MERIDIAN_HOME` and asserts none of
//! them contain a message body, a petname, a contact's pubkey/`mrd1:` id, or key material in
//! plaintext. Per [ADR 0021](../../../docs/adr/0021-client-local-store-config-formats.md) condition
//! 2, `state.json` gets one extra, specific assertion: its conversation reference is an opaque,
//! non-identifying handle, never a raw pubkey/id.
//!
//! ## Why this harness plays the role of a minimal, real worker
//! Every screen task since 4.16 builds [`Effect`]s for `App::update` to *dispatch*, but
//! `meridian_tui::run_worker` — the function that would actually execute an `Effect` against real
//! disk/network — has remained an unconditional-success stub through this whole phase (see its own
//! doc comment). Driving a scripted conversation through `App::update` alone therefore produces
//! `Effect`s but performs **no real file I/O** — there would be nothing on disk for this audit to
//! scan. So, for every `Effect` the scripted flow below produces, this harness itself calls the
//! *real* corresponding store function (`meridian_tui::store::contacts::save`,
//! `store::history::append`, `store::outbox::save`, `store::state::save`,
//! `meridian_core::trust::TrustStore::seal_at_rest`, `meridian_tui::config_write::write_setting_at`,
//! …) against a real temp `$MERIDIAN_HOME`, exactly mirroring what a real worker will eventually do
//! — then feeds the outcome back into `App::update` as a `WorkerEvent`, so the screen state machines
//! themselves stay exactly as they are today. This is legitimate scope for an *audit harness* that
//! needs real files to scan (task 4.27's own framing) — it is not a redesign of `run_worker`, which
//! this file never touches or wires up.
//!
//! ## Screen navigation: `App::push_screen`/`pop_screen`, not yet-unbuilt `Preflight` wiring
//! `Screen::Contacts`/`Screen::Chat`/`Screen::Verify` are all, by their own doc comments, "not
//! constructed by `App::new` yet" — the `Preflight` routing step that will one day decide *when* to
//! push them doesn't exist. This harness pushes/pops them directly via `App`'s own public
//! `push_screen`/`pop_screen` (exactly the seam those doc comments say a future navigation task will
//! use), standing in for that not-yet-built step. Every *effect-producing* interaction still goes
//! through `App::update(AppEvent::Key(..))`/`App::update(AppEvent::Worker(..))`, per the task's own
//! "driving `App::update` directly" framing — navigation is the only thing done via the pub
//! push/pop seam, and only because reclaiming a screen's own `TrustStore` (not `Clone`, by design —
//! see `trust.rs`) to carry into the next screen requires taking ownership back out of the popped
//! `Screen`.
//!
//! ## Getting a real, sealed account into a temp dir
//! `Effect::GenerateAccount`'s own doc comment says its real execution is "mint a fresh Ed25519
//! keypair via `meridian_core::identity::generate_account` ... and persist the non-secret
//! `account.json` descriptor" — so that's exactly what this harness's "worker" does on that effect,
//! using a [`MemorySecretStore`] (the same in-process, no-disk-no-D-Bus secret store every other
//! test in this crate already uses — `tests/store.rs`'s own `fresh_account`, `apps/cli/src/opacity.rs`'s
//! `Party`). `$MERIDIAN_HOME` is pointed at a real `tempfile::TempDir` for the run (mirrors
//! `apps/core/src/account.rs`'s own private `EnvGuard` test pattern, reproduced here since it is
//! private to that crate) so `account.json`/`sessions.bin`/`trust.bin` — and, transitively,
//! `tui/contacts.json`/`tui/history/*.jsonl`/`tui/outbox.json`/`tui/state.json`/`tui/config.toml` via
//! `meridian_core::account::config_dir()` — all resolve to real paths under it, written by the exact
//! same `apps/cli`-shared code paths (`AccountDescriptor::save`, `ChatState::seal_at_rest`,
//! `TrustStore::seal_at_rest`), not a TUI-specific wrapper.
//!
//! `Effect::Register`/`Effect::PublishBundle` are the onboarding flow's two *network* steps — no
//! rendezvous server runs in this test (this harness stays deterministic/CI-safe, like
//! `opacity.rs`'s own "no network, no real server" design). Neither writes anything under the
//! audited file inventory (registering/publishing a bundle are pure network calls in this crate), so
//! this harness's "worker" reports them as immediately successful without a real connection —
//! documented here as a deliberate scope narrowing, not an oversight.
//!
//! `Effect::SendMessage` belongs in that same "faked, out of scope" group, not the "executed for
//! real" one — its own doc comment in `crate::app` makes clear its real execution is itself a
//! network/crypto step needing a live `SignalingClient`/`ChatState` session, exactly like
//! `Register`/`PublishBundle`. This harness fabricates `SendMessage`'s outcome
//! (`SentMessage { mid, ts, delivered: true }`) by hand, the same way it fabricates
//! `Register`/`PublishBundle`'s — real message-send/crypto is out of this task's scope, covered by
//! `opacity.rs`'s own dedicated ratchet-opacity audit instead (and, since the sessions.bin section
//! below, by a real X3DH exchange this harness drives directly against `meridian_core::chat`, not
//! through `App::update`). What *is* executed for real is only the second half of the chain: the
//! fabricated `SentMessage` outcome is fed through the real `App::update` state machine into a real
//! `PersistHistory` effect, which this harness executes against the real `store::history::append`.
//! So of this whole group, only `GenerateAccount`, `AddContact`, `PersistHistory` (following
//! `SendMessage`), and `MarkVerified` are genuinely executed for real through `App::update`.
//!
//! ## The scripted flow
//! Onboard (real account, `account.json`), then add a contact with a petname (real
//! `TrustStore::observe`, `set_petname`, `contacts.json`), then open the conversation
//! (mints/persists the opaque `conv_handle`, writes `state.json`), then send a message with a
//! sentinel body (`SendMessage` then `PersistHistory`, real `history/<peer>.jsonl`), then simulate
//! one inbound message directly via `store::history::append` (this crate's chat screen has no
//! receive-path `Effect` yet — its own module doc says so explicitly — so this harness calls the
//! store function directly, standing in for that not-yet-built path, exactly as this file's own
//! module doc describes for screen navigation), then a pending outbox entry (also no `Effect`
//! drives `outbox.json` yet — same direct-call treatment, `TODO: confirm` per that store module's
//! own doc on the schema being provisional), then verify the contact (`MarkVerified`, real
//! `trust.bin`), then one `config.toml` setting write via `config_write::write_setting_at`.
//!
//! ## Sentinel strategy
//! Every value that must never appear in plaintext gets its own distinct, greppable sentinel string
//! (mirroring `opacity.rs`'s own "obviously-searchable" marker convention) — a message-body marker
//! for the outbound send, a different one for the simulated inbound message, a third for the outbox
//! entry, and a distinct petname marker — so a failure names exactly *which* value leaked and into
//! which file, not just "a leak somewhere".

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::account;
use meridian_core::identity::{generate_account, KeyHandle, MemorySecretStore};
use meridian_core::signaling::DEFAULT_OTK_COUNT;
use meridian_core::trust::{PinnedKey, TrustState, TrustStore};

use meridian_tui::app::{
    AddContactEffect, AddContactRequest, AddedContact, Effect, GenerateAccountEffect,
    GeneratedAccount, LoadSessionEffect, LoadSessionOutcome, LoadSessionRequest,
    MarkVerifiedEffect, PersistHistoryEffect, PublishBundleEffect, PublishedBundle,
    SendMessageEffect, SentMessage, SessionOutcome, SettingValue, WorkerEvent,
};
use meridian_tui::config_write::write_setting_at;
use meridian_tui::screens::chat::ChatState as TuiChatState;
use meridian_tui::screens::contacts::ContactsState;
use meridian_tui::screens::verify::VerifyState;
use meridian_tui::session::LiveSession;
use meridian_tui::store;
use meridian_tui::store::contacts::{ContactRecord, ContactsDocument, PinnedKeyRecord, TrustLabel};
use meridian_tui::store::history::{Direction as HistoryDirection, HistoryEntry, MessageState};
use meridian_tui::store::outbox::{OutboxDocument, OutboxEntry};
use meridian_tui::store::state::StateDocument;
use meridian_tui::{App, AppEvent, Screen};

// ---------------------------------------------------------------------------
// Sentinels — every one of these must never appear in plaintext anywhere on disk.
// ---------------------------------------------------------------------------

const MARKER_OUTBOUND_BODY: &str = "SENTINEL-OUTBOUND-7f2b9e1c4a3d4f0b9c2e11aa22bb33cc";
const MARKER_INBOUND_BODY: &str = "SENTINEL-INBOUND-3d9a7c2e1b4f4a0d8e6c44dd55ee66ff";
const MARKER_OUTBOX_BODY: &str = "SENTINEL-OUTBOX-9c4e2a7b1f3d4c0a8b6e77aa88bb99cc";
const MARKER_PETNAME: &str = "SENTINEL-PETNAME-bobby-1a2b3c4d5e6f";

/// A fixed wall-clock reading for every effect outcome this harness fabricates — mirrors this
/// crate's own "time is injected, not read" discipline (`crate::app`'s doc comment on
/// `AddedContact::added_at`), kept deterministic rather than reading `SystemTime::now()`.
const FIXED_NOW: u64 = 1_760_000_000;

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` environment guard — mirrors `apps/core/src/account.rs`'s own private test-only
// `EnvGuard` (reproduced here since that one is private to `meridian-core`'s own test module).
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
        // SAFETY: serialized by ENV_LOCK; this is the only place in this test binary that touches
        // `MERIDIAN_HOME`.
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
// Key-event helpers (mirrors `tests/screens_onboarding.rs`'s own `key`/`char_key`/`type_str`)
// ---------------------------------------------------------------------------

fn key_event(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(app: &mut App, code: KeyCode) -> Vec<Effect> {
    app.update(AppEvent::Key(key_event(code)))
}

fn type_str(app: &mut App, s: &str) {
    for c in s.chars() {
        app.update(AppEvent::Key(key_event(KeyCode::Char(c))));
    }
}

fn worker(app: &mut App, event: WorkerEvent) -> Vec<Effect> {
    app.update(AppEvent::Worker(Box::new(event)))
}

// ---------------------------------------------------------------------------
// The recursive, raw-byte scanner
// ---------------------------------------------------------------------------

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Recursively scans every **file content** (deliberately not file *names* — `history/<peer-pubkey-
/// hex>.jsonl`'s own filename embeds the peer's pubkey hex by design, tui-client.md §5's documented
/// layout, not a content leak this audit polices) under `root` for each `(label, needle)` marker.
/// Returns one human-readable violation per (file, marker) match; empty means clean.
fn scan_for_leaks(root: &Path, markers: &[(&str, &[u8])]) -> Vec<String> {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    let mut violations = Vec::new();
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        for (label, needle) in markers {
            if contains(&bytes, needle) {
                violations.push(format!("{label} found in {}", path.display()));
            }
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Trust-state plumbing (harness-local — production mapping lives in `crate::screens::contacts`)
// ---------------------------------------------------------------------------

fn to_trust_label(state: TrustState) -> TrustLabel {
    match state {
        TrustState::New => TrustLabel::New,
        TrustState::Pinned => TrustLabel::Pinned,
        TrustState::Verified => TrustLabel::Verified,
        TrustState::Blocked => TrustLabel::Blocked,
        // `contacts.json`'s `TrustLabel` has no matching variant (see that module's own doc on why
        // `ContactRecord` "structurally cannot represent `TrustState::PinnedKeyChanged`") —
        // unreachable in this harness's own scripted flow (never produced), approximated here only
        // because `to_trust_label` must be total.
        TrustState::PinnedKeyChanged => TrustLabel::Pinned,
    }
}

fn to_pinned_key_records(history: &[PinnedKey]) -> Vec<PinnedKeyRecord> {
    history
        .iter()
        .map(|k| PinnedKeyRecord {
            pubkey: hex::encode(k.pubkey),
            first_seen: k.first_seen_unix,
            last_seen: k.last_seen_unix,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The end-to-end audit
// ---------------------------------------------------------------------------

#[test]
fn at_rest_audit_finds_no_plaintext_leaks() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());

    let mut app = App::new();

    // === Onboarding: ChooseStore (Os, the default selection) -> Enter ===================
    let effects = press(&mut app, KeyCode::Enter);
    assert!(
        effects.is_empty(),
        "ChooseStore->Enter should not dispatch yet"
    );

    // === OrgHint: type a hint, Enter -> Effect::GenerateAccount =========================
    type_str(&mut app, "self-org.test");
    let effects = press(&mut app, KeyCode::Enter);
    let generate_request = match effects.as_slice() {
        [Effect::GenerateAccount(GenerateAccountEffect {
            request,
            outcome: None,
        })] => request.clone(),
        other => panic!("expected a single GenerateAccount effect, got {other:?}"),
    };

    // --- Harness-as-worker: really mint the account and really write account.json -------
    let self_store = MemorySecretStore::new();
    let self_account =
        generate_account(&self_store, &generate_request.hint).expect("generate_account");
    let self_handle: KeyHandle = self_account.handle().clone();
    let self_account_pub: [u8; 32] = *self_account.public_key().as_bytes();
    account::AccountDescriptor::new_os(&self_account, "meridian-tui-audit")
        .save()
        .expect("save account.json for real");

    let generated = GeneratedAccount {
        id: self_account.to_id_string(),
        label: hex::encode(self_account_pub),
        account_pub: self_account_pub,
    };
    let effects = worker(
        &mut app,
        WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            request: generate_request,
            outcome: Some(generated),
        })),
    );
    assert!(
        effects.is_empty(),
        "GenerateAccount completion dispatches nothing itself"
    );

    // === ShowIdentity: server field is prefilled (`wss://<hint>`) -> Enter -> Register ===
    let effects = press(&mut app, KeyCode::Enter);
    let register_request = match effects.as_slice() {
        [Effect::Register(request)] => request.clone(),
        other => panic!("expected a single Register effect, got {other:?}"),
    };
    // No real rendezvous server in this test — see the module doc's "network steps" note. Nothing
    // in the audited file inventory is produced by this step.
    let effects = worker(
        &mut app,
        WorkerEvent::Completed(Effect::Register(register_request)),
    );
    let publish_request = match effects.as_slice() {
        [Effect::PublishBundle(PublishBundleEffect {
            request,
            outcome: None,
        })] => request.clone(),
        other => panic!("expected a single PublishBundle effect, got {other:?}"),
    };
    let effects = worker(
        &mut app,
        WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
            request: publish_request,
            outcome: Some(PublishedBundle {
                otk_count: DEFAULT_OTK_COUNT,
            }),
        })),
    );
    assert!(effects.is_empty());

    // === Success -> Enter finishes onboarding (task 4.37: Screen::Onboarding -> the
    // Screen::Placeholder "loading" interim screen, dispatching Effect::LoadSession for this
    // OS-keystore account rather than the pre-4.37 Screen::Placeholder-forever stand-in) =========
    let effects = press(&mut app, KeyCode::Enter);
    assert!(matches!(effects.as_slice(), [Effect::LoadSession(_)]));
    assert!(matches!(app.current_screen(), Screen::Placeholder));

    // --- Harness-as-worker, faked (same "out of scope for this harness" group as
    // Register/PublishBundle above): a real `Effect::LoadSession` execution needs a real OS
    // keystore (`init_os_keystore`), unavailable headlessly — see
    // `apps/tui/tests/load_session.rs`'s own module doc. Hands back the trivially-empty
    // `LiveSession` a genuine first-ever load of this exact, freshly-onboarded account would
    // produce (nothing sealed on disk for it yet — trust/contacts are populated for real,
    // separately, a few steps below), landing on the real `Screen::Main` task 4.37 wires this
    // account to. ---
    let session_descriptor =
        account::AccountDescriptor::new_os(&self_account, "meridian-tui-audit");
    let effects = worker(
        &mut app,
        WorkerEvent::Completed(Effect::LoadSession(LoadSessionEffect {
            request: LoadSessionRequest,
            outcome: Some(LoadSessionOutcome::Loaded(Box::new(SessionOutcome::ready(
                LiveSession::empty(session_descriptor),
            )))),
        })),
    );
    assert!(effects.is_empty());
    assert!(matches!(app.current_screen(), Screen::Main(_)));

    // === Contacts: add a peer with a petname =============================================
    let peer_store = MemorySecretStore::new();
    let peer_account =
        generate_account(&peer_store, "org-bob.test").expect("peer generate_account");
    let peer_pubkey: [u8; 32] = *peer_account.public_key().as_bytes();
    let peer_id = peer_account.to_id_string();
    let peer_pubkey_hex = hex::encode(peer_pubkey);

    app.push_screen(Screen::Contacts(Box::new(ContactsState::new(Vec::new()))));
    press(&mut app, KeyCode::Char('n')); // open add-contact form
    type_str(&mut app, &peer_id);
    press(&mut app, KeyCode::Enter); // parse id -> EnterPetname
    type_str(&mut app, MARKER_PETNAME);
    let effects = press(&mut app, KeyCode::Enter); // -> Effect::AddContact
    let add_request: AddContactRequest = match effects.as_slice() {
        [Effect::AddContact(AddContactEffect {
            request,
            outcome: None,
        })] => request.clone(),
        other => panic!("expected a single AddContact effect, got {other:?}"),
    };
    assert_eq!(add_request.pubkey, peer_pubkey);
    assert_eq!(add_request.petname.as_deref(), Some(MARKER_PETNAME));

    // --- Harness-as-worker: really observe + set_petname on TrustStore, really seal trust.bin
    // and contacts.json ------------------------------------------------------------------
    let mut trust = TrustStore::default();
    trust.observe(add_request.pubkey, &add_request.hint, FIXED_NOW);
    trust
        .set_petname(&add_request.pubkey, add_request.petname.clone())
        .expect("contact was just observed");
    let contact = trust
        .contact(&add_request.pubkey)
        .expect("just observed")
        .clone();
    let added = AddedContact {
        pubkey: add_request.pubkey,
        id: add_request.id.clone(),
        hint: contact.hint.clone(),
        petname: contact.petname.clone(),
        added_at: FIXED_NOW,
        trust: contact.state,
        user_blocked: contact.user_blocked,
        pinned_key_history: contact.pinned_key_history.clone(),
    };

    let trust_sealed = trust
        .seal_at_rest(&self_store, &self_handle)
        .expect("seal trust.bin");
    let trust_path = account::trust_path().expect("trust_path");
    std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
    std::fs::write(&trust_path, trust_sealed).expect("write trust.bin");

    let contacts_doc = ContactsDocument {
        v: store::contacts::CURRENT_VERSION,
        contacts: vec![ContactRecord {
            pubkey: peer_pubkey_hex.clone(),
            id: add_request.id.clone(),
            hint: contact.hint.clone(),
            petname: contact.petname.clone(),
            trust: to_trust_label(contact.state),
            pinned_key_history: to_pinned_key_records(&contact.pinned_key_history),
            device_record_version_seen: None,
            policy_override: None,
            added_at: FIXED_NOW,
            last_activity_at: FIXED_NOW,
            unread: 0,
            conv_handle: None,
        }],
    };
    store::contacts::save(&contacts_doc, &self_store, &self_handle).expect("save contacts.json");

    let effects = worker(
        &mut app,
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            request: add_request,
            outcome: Some(added),
        })),
    );
    assert!(effects.is_empty());

    // Close the add-contact form / pop back to Placeholder.
    press(&mut app, KeyCode::Esc);

    // === Opening the conversation: mint + persist the opaque `conv_handle`, write state.json ===
    let mut reloaded_contacts =
        store::contacts::load_or_default(&self_store, &self_handle).expect("reload contacts.json");
    let record = reloaded_contacts
        .contacts
        .iter_mut()
        .find(|c| c.pubkey == peer_pubkey_hex)
        .expect("contact just added");
    let conv_handle = record.conv_handle_or_mint().expect("mint conv_handle");
    store::contacts::save(&reloaded_contacts, &self_store, &self_handle)
        .expect("resave contacts.json with conv_handle");

    store::state::save(&StateDocument {
        v: store::state::CURRENT_VERSION,
        last_conversation: Some(conv_handle),
        panes: Default::default(),
        scroll: Default::default(),
    })
    .expect("save state.json");

    // === Chat: send an outbound message carrying the outbound sentinel ===================
    app.push_screen(Screen::Chat(Box::new(TuiChatState::new(
        peer_pubkey,
        contact.hint.clone(),
        trust,
        Vec::new(),
        0,
    ))));
    type_str(&mut app, MARKER_OUTBOUND_BODY);
    let effects = press(&mut app, KeyCode::Enter);
    let send_request = match effects.as_slice() {
        [Effect::SendMessage(SendMessageEffect {
            request,
            outcome: None,
        })] => request.clone(),
        other => panic!("expected a single SendMessage effect, got {other:?}"),
    };
    assert_eq!(send_request.body, MARKER_OUTBOUND_BODY);

    let sent = SentMessage {
        mid: hex::encode([0x51u8; 16]),
        ts: FIXED_NOW,
        delivered: true,
    };
    let effects = worker(
        &mut app,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request: send_request,
            outcome: Some(sent),
        })),
    );
    let persist_request = match effects.as_slice() {
        [Effect::PersistHistory(PersistHistoryEffect {
            request,
            outcome: None,
        })] => request.clone(),
        other => panic!("expected a single PersistHistory effect, got {other:?}"),
    };
    assert_eq!(persist_request.entry.body, MARKER_OUTBOUND_BODY);

    // --- Harness-as-worker: really append to the sealed history/<peer>.jsonl -------------
    store::history::append(
        &peer_pubkey_hex,
        &persist_request.entry,
        &self_store,
        &self_handle,
    )
    .expect("append outbound history entry");
    worker(
        &mut app,
        WorkerEvent::Completed(Effect::PersistHistory(PersistHistoryEffect {
            request: persist_request,
            outcome: Some(()),
        })),
    );

    // === Simulate one inbound message directly via the store function ====================
    // `crate::screens::chat`'s own module doc: "No receive-path wiring either ... there is no
    // Effect/WorkerEvent for an inbound message arriving live in this task" — so there is no
    // App::update path to drive here yet. This harness calls the real store function directly,
    // standing in for that not-yet-built receive path (documented judgment call — see this file's
    // module doc), so history/<peer>.jsonl still gets a real, sealed inbound entry to scan.
    store::history::append(
        &peer_pubkey_hex,
        &HistoryEntry {
            v: store::history::CURRENT_VERSION,
            mid: hex::encode([0x52u8; 16]),
            dir: HistoryDirection::In,
            ts: FIXED_NOW + 1,
            stream: "mrd.chat/1".to_string(),
            body: MARKER_INBOUND_BODY.to_string(),
            state: MessageState::Received,
        },
        &self_store,
        &self_handle,
    )
    .expect("append inbound history entry");

    // === A pending outbox entry ============================================================
    // No `Effect` drives `outbox.json` yet either (`store::outbox`'s own module doc: "TODO:
    // confirm this schema ... nothing downstream depends on this exact shape yet") — same direct
    // call, standing in for a future retry-queue persist.
    store::outbox::save(
        &OutboxDocument {
            v: store::outbox::CURRENT_VERSION,
            entries: vec![OutboxEntry {
                peer_pubkey: peer_pubkey_hex.clone(),
                mid: hex::encode([0x53u8; 16]),
                stream: "mrd.chat/1".to_string(),
                body: MARKER_OUTBOX_BODY.to_string(),
                attempt_count: 1,
                next_retry_at: FIXED_NOW + 30,
                created_at: FIXED_NOW,
            }],
        },
        &self_store,
        &self_handle,
    )
    .expect("save outbox.json");

    // Reclaim the (unmutated by chat) TrustStore back out of the popped Chat screen.
    let trust = match app.pop_screen() {
        Some(Screen::Chat(state)) => state.trust,
        other => panic!("expected to pop Screen::Chat, got {other:?}"),
    };

    // === Verify: mark the contact verified ================================================
    app.push_screen(Screen::Verify(Box::new(VerifyState::new(
        self_account_pub,
        peer_pubkey,
        contact.hint.clone(),
        trust,
    ))));
    press(&mut app, KeyCode::Char('v')); // -> Confirm(Verify)
    let effects = press(&mut app, KeyCode::Char('y')); // -> apply_action mutates state.trust in place
    let mark_verified_request = match effects.as_slice() {
        [Effect::MarkVerified(MarkVerifiedEffect {
            request,
            outcome: None,
        })] => request.clone(),
        other => panic!("expected a single MarkVerified effect, got {other:?}"),
    };
    assert_eq!(mark_verified_request.pubkey, peer_pubkey);
    worker(
        &mut app,
        WorkerEvent::Completed(Effect::MarkVerified(MarkVerifiedEffect {
            request: mark_verified_request,
            outcome: Some(()),
        })),
    );

    let trust = match app.pop_screen() {
        Some(Screen::Verify(state)) => state.trust,
        other => panic!("expected to pop Screen::Verify, got {other:?}"),
    };
    assert_eq!(trust.trust_state(&peer_pubkey), TrustState::Verified);

    // --- Harness-as-worker: really re-seal trust.bin with the verified state -------------
    let trust_sealed = trust
        .seal_at_rest(&self_store, &self_handle)
        .expect("seal verified trust.bin");
    std::fs::write(&trust_path, trust_sealed).expect("rewrite trust.bin");

    // === sessions.bin: run a REAL X3DH exchange so the sealed `ChatState` holds genuine key
    // material — a populated `PrekeyVault` (real SPK/OTK secrets) and an established `Session`
    // keyed by the peer's real pubkey — never `ChatState::default()`'s empty vault/session map.
    // `docs/testing/strategy.md` §5b and this task's own goal statement both name this file's
    // key material explicitly, so sealing an empty state here would leave nothing for the byte
    // scan below to have a chance of catching (review finding, task 4.27).
    //
    // Mirrors `apps/cli/src/opacity.rs::Party`'s pattern, narrowed to what's needed here: `self`
    // publishes a real bundle (`meridian_core::signaling::generate_bundle`, exactly the "worker"
    // for `Effect::PublishBundle` above would have done had this test run it against a real
    // server), the peer (a throwaway `ChatState` standing in for their own client/process — never
    // itself persisted; only `self`'s `sessions.bin` is under audit) initiates a real session
    // against it and seals one real opening (X3DH-preamble-carrying) envelope, and `self` opens it
    // for real via `ChatState::open_inbound` — the exact establishment path `apps/cli`'s own
    // inbound flow drives, invoked directly rather than through a live network fetch (this harness
    // stays deterministic/CI-safe, like `opacity.rs`'s own "no network, no real server" design).
    let self_bundle = meridian_core::signaling::generate_bundle(
        &self_store,
        &self_handle,
        self_account_pub,
        DEFAULT_OTK_COUNT,
    )
    .expect("generate a real bundle for self");
    // Captured as independent, `Copy` stack values (not the `Zeroizing` wrapper `generate_bundle`
    // returns) so they stay valid as scan markers below regardless of when `self_bundle` drops.
    let self_spk_secret: [u8; 32] = *self_bundle.spk_secret;
    let self_otk_secret: [u8; 32] = *self_bundle.otk_secrets[0];

    let mut core_sessions = meridian_core::chat::ChatState::default();
    let self_otks: Vec<([u8; 32], [u8; 32])> = self_bundle
        .bundle
        .otks
        .iter()
        .zip(self_bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    core_sessions.vault.set_bundle(
        self_bundle.bundle.spk,
        self_spk_secret,
        self_otks,
        FIXED_NOW,
    );

    // The peer's own session state — real X3DH, but OTK-*free* (`peer_opk: None`) deliberately, so
    // every one of `self`'s vault OTK secrets (including `self_otk_secret` above) stays genuinely
    // present, unconsumed, in `core_sessions` through to the seal below (a consumed OTK is removed
    // from the vault by `PrekeyVault::take_otk_secret` — single-use — which would otherwise make
    // that specific marker vacuously absent from the pre-seal plaintext too, not because sealing
    // ran, but because it was never there to begin with; OTK-free X3DH is legal — see
    // `ChatState::MAX_PENDING_REQUESTS`'s doc for this crate's own precedent on that).
    let peer_handle: KeyHandle = peer_account.handle().clone();
    let mut peer_chat_state = meridian_core::chat::ChatState::default();
    peer_chat_state
        .start_initiator_session(
            &peer_store,
            &peer_handle,
            &peer_pubkey,
            &self_account_pub,
            &self_bundle.bundle.spk,
            None,
        )
        .expect("peer initiates a real X3DH session against self's real bundle");
    let opening_blob = peer_chat_state
        .seal_outbound(
            &peer_store,
            &peer_handle,
            &peer_pubkey,
            &self_account_pub,
            &meridian_core::envelope::ChatContent::Text {
                id: [0x54u8; 16],
                body: "session-establishment probe (never persisted as a history entry)"
                    .to_string(),
            },
        )
        .expect("peer seals a real opening (X3DH-preamble-carrying) envelope");

    // `self` opens it for real: verifies the signature, runs X3DH as responder, and installs a
    // genuine `Session` keyed by the peer's real pubkey. It's a first contact, so this lands as a
    // pending message request (system-design §3.5) rather than delivered content — the crypto
    // establishment is complete regardless (`ChatState::open_inbound`'s own doc: "gating is
    // delivery-only, never a crypto shortcut").
    match core_sessions.open_inbound(
        &self_store,
        &self_handle,
        &self_account_pub,
        &peer_pubkey,
        &opening_blob,
    ) {
        Err(meridian_core::chat::ChatError::MessageRequest) => {
            core_sessions
                .accept_request(&peer_pubkey)
                .expect("just gated by open_inbound");
        }
        other => panic!("expected a gated first-contact MessageRequest, got {other:?}"),
    }
    assert!(
        core_sessions.has_session(&peer_pubkey),
        "establishing the responder session must leave a real Session keyed by the peer's real pubkey"
    );

    // A session/chain-key sentinel: independently recompute the same X3DH result
    // `ChatState::open_inbound` derived internally (`x3dh::respond` is a pure function of inputs
    // this harness already holds — our own account key/store, the real SPK secret, and the peer's
    // ephemeral pubkey off the real opening envelope's prekey preamble — never reaching into
    // `Session`'s deliberately private ratchet fields; this crate depends on `meridian-core` only,
    // per ADR 0020). The raw X3DH root itself is transformed away by the ratchet's very first DH
    // step (an intentional, immediate forward-secrecy property — see
    // `meridian_crypto::ratchet::DoubleRatchet::dh_ratchet`) and so is never literally present at
    // rest, but the two X3DH-derived *header* keys (`hka`/`nhkb`) are moved into the ratchet's
    // `hks`/`hkr` slots verbatim by that same first step and are not touched again until a second,
    // different message is exchanged — which never happens in this harness — so `hka` genuinely IS
    // present, unchanged, in `core_sessions`'s pre-seal plaintext as this session's `hkr` field.
    let opening_prekey = meridian_core::envelope::MessageEnvelope::from_blob(&opening_blob)
        .expect("decode the real opening envelope")
        .prekey
        .expect("a first-contact envelope carries the X3DH preamble");
    let session_header_key_sentinel = meridian_core::crypto::x3dh::respond(
        &self_store,
        &self_handle,
        &self_account_pub,
        &peer_pubkey,
        &opening_prekey.ek_pub,
        &self_spk_secret,
        None,
    )
    .expect("independently recompute the same X3DH result `open_inbound` derived internally")
    .hka;

    let sessions_sealed = core_sessions
        .seal_at_rest(&self_store, &self_handle)
        .expect("seal sessions.bin");
    std::fs::write(
        account::sessions_path().expect("sessions_path"),
        sessions_sealed,
    )
    .expect("write sessions.bin");

    // === config.toml: a hand-authored file, then one real setting write ==================
    let config_path = meridian_tui::config::default_config_path().expect("default_config_path");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(
        &config_path,
        "[account]\n# hand-authored — task 4.14/4.24\n\n[ui]\ntheme = \"dark\"\n",
    )
    .expect("write initial config.toml");
    write_setting_at(
        &config_path,
        &SettingValue::ServerUrl(Some("wss://override.self-org.test".to_string())),
    )
    .expect("write_setting_at");

    // =======================================================================================
    // The audit itself
    // =======================================================================================

    let markers: &[(&str, &[u8])] = &[
        (
            "outbound message body sentinel",
            MARKER_OUTBOUND_BODY.as_bytes(),
        ),
        (
            "inbound message body sentinel",
            MARKER_INBOUND_BODY.as_bytes(),
        ),
        (
            "outbox message body sentinel",
            MARKER_OUTBOX_BODY.as_bytes(),
        ),
        ("petname sentinel", MARKER_PETNAME.as_bytes()),
        ("contact pubkey (hex)", peer_pubkey_hex.as_bytes()),
        ("contact mrd1: id", peer_id.as_bytes()),
        ("contact pubkey (raw bytes)", &peer_pubkey),
        ("real prekey-vault SPK secret", &self_spk_secret),
        ("real prekey-vault OTK secret", &self_otk_secret),
        (
            "real session header-key sentinel (X3DH hka, preserved as the responder session's \
             ratchet `hkr` field)",
            &session_header_key_sentinel,
        ),
    ];
    let violations = scan_for_leaks(tmp.path(), markers);
    assert!(
        violations.is_empty(),
        "at-rest plaintext leak(s) found — this is a security defect, fix the leak in the \
         relevant store/screen, never loosen this assertion:\n{}",
        violations.join("\n")
    );

    // === state.json's own extra, specific assertion (ADR 0021 condition 2) ===============
    let state_path = store::state_path().expect("state_path");
    let state_bytes = std::fs::read(&state_path).expect("read state.json");
    // Plaintext by design (task 4.15's own doc), but must still contain no identifying data —
    // confirmed structurally, not just by the generic scan above.
    let state_doc: StateDocument =
        serde_json::from_slice(&state_bytes).expect("state.json is valid JSON");
    assert_eq!(
        state_doc.last_conversation,
        Some(conv_handle),
        "state.json's conversation reference must be the same opaque handle contacts.json minted"
    );
    assert!(
        !contains(&state_bytes, peer_pubkey_hex.as_bytes()),
        "state.json must never contain the contact's pubkey"
    );
    assert!(
        !contains(&state_bytes, peer_id.as_bytes()),
        "state.json must never contain the contact's mrd1: id"
    );
    assert!(
        !contains(&state_bytes, MARKER_PETNAME.as_bytes()),
        "state.json must never contain a petname"
    );

    // === Sanity: the sealed files really are opaque ciphertext, not merely JSON/CBOR that
    // happens not to contain the markers (would otherwise make the scan above vacuous for these
    // files) ================================================================================
    for sealed_path in [
        store::contacts_path().unwrap(),
        store::outbox_path().unwrap(),
        store::history_path(&peer_pubkey_hex).unwrap(),
    ] {
        let raw = std::fs::read(&sealed_path).expect("read sealed file");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&raw).is_err(),
            "{} must not be plaintext-parseable JSON — it should be an opaque sealed blob",
            sealed_path.display()
        );
    }
    // `trust.bin`/`sessions.bin` are CBOR (not JSON) pre-seal (`TrustStore::seal_at_rest`/
    // `ChatState::seal_at_rest` both call `ciborium::into_writer`), so the JSON-parseability check
    // above is vacuous for them — raw CBOR essentially never happens to parse as valid JSON
    // regardless of whether sealing actually ran, so it would pass identically for a regression
    // that silently skipped sealing on either path (review finding, task 4.27). Decode the raw
    // sealed bytes directly as the real pre-seal CBOR-encoded type instead, and assert that decode
    // also fails — a check that's actually falsifiable if sealing were skipped.
    {
        let raw = std::fs::read(&trust_path).expect("read trust.bin");
        assert!(
            ciborium::from_reader::<TrustStore, _>(&raw[..]).is_err(),
            "trust.bin must not be plaintext-decodable CBOR for TrustStore — it should be an \
             opaque sealed blob"
        );
    }
    {
        let raw = std::fs::read(account::sessions_path().unwrap()).expect("read sessions.bin");
        assert!(
            ciborium::from_reader::<meridian_core::chat::ChatState, _>(&raw[..]).is_err(),
            "sessions.bin must not be plaintext-decodable CBOR for ChatState — it should be an \
             opaque sealed blob"
        );
    }
}

// ---------------------------------------------------------------------------
// Non-vacuity: prove the scanning primitive itself actually catches an injected leak, rather
// than only ever asserting a clean pass above — mirrors `opacity.rs`'s own
// `federated_opacity_scan_is_sensitive_to_a_fed_only_leak` discipline.
// ---------------------------------------------------------------------------

#[test]
fn scan_for_leaks_catches_an_injected_plaintext_leak() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join("tui/history")).unwrap();
    std::fs::write(
        tmp.path().join("clean.json"),
        b"{\"nothing\":\"interesting\"}",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("tui/history/leaky.jsonl"),
        b"{\"body\":\"oops SENTINEL-LEAK-TEST-VALUE here\"}",
    )
    .unwrap();

    let markers: &[(&str, &[u8])] = &[
        ("test leak", b"SENTINEL-LEAK-TEST-VALUE"),
        ("never present", b"THIS-STRING-IS-NEVER-WRITTEN"),
    ];
    let violations = scan_for_leaks(tmp.path(), markers);
    assert_eq!(violations.len(), 1, "violations: {violations:?}");
    assert!(violations[0].contains("test leak"));
    assert!(violations[0].contains("leaky.jsonl"));
}
