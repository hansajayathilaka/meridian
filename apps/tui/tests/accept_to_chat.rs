//! Task 4.42's own new test target (`cargo nextest run -p meridian-tui --test accept_to_chat`) —
//! the first **screen-level** coverage in this crate of the responder side of a first-contact
//! exchange: accept a message request in the live TUI, then reach that sender's chat and
//! verification screen using on-screen affordances only.
//!
//! ## Why a new file, and why this level
//! Task 4.41's exit-gate pass established that `apps/tui/tests/live_session_e2e.rs` — the demo
//! harness three consecutive exit-gate attempts ran green — **never touches
//! `apps/tui/src/screens/`** at all: it drives `worker::dispatch` directly. That is exactly why the
//! live UI could be structurally broken (Defect C: an accepted sender was reachable from no screen
//! at all, and could not even be re-added by hand, because `Contact::id_string()` fails for a
//! contact with an empty hint) while every worker-level test passed. So this file deliberately
//! drives **real `crossterm` key events through `App`**, with the **real** `worker::dispatch`
//! executing each `Effect` those keys produce against a **real**, sealed `$MERIDIAN_HOME` — no
//! hand-built `WorkerEvent`s standing in for the worker on the accept path, and no hand-built
//! `LiveSession`: every `Screen::Main` below is built by a real `Effect::LoadSession`, routed to by
//! the real [`preflight_route`], reading real `trust.bin`/`sessions.bin`/`contacts.json` off disk.
//!
//! ## Why `OsSecretStore` + `install_mock_keystore`, not a file-backed account
//! Same reasoning as `tests/run_worker_trust.rs`'s own module doc, plus one this file adds: a
//! `FileSecretStore` re-runs a full age/scrypt unwrap on **every** sealed read and write, and the
//! flows below perform dozens of them per test (unlock/load, accept's three documents, the restart's
//! second load). Against a mock keystore the same flows are structurally identical but not
//! dominated by KDF cost. The **file-backed** half of this task's own store change is covered where
//! that concern already lives: `tests/live_session_file_backed.rs::
//! file_backed_session_supports_accept_request_post_unlock` asserts the same synthesized
//! `contacts.json` row through a real `Effect::Unlock` + cached live store.
//!
//! It is a new file rather than an extension of `tests/screens_requests.rs`/`tests/screen_main.rs`
//! because it is the only test in this crate that spans **both** halves at once (screen stack *and*
//! real worker I/O against a real `$MERIDIAN_HOME`): `screens_requests.rs` is a pure state-machine
//! file with no store at all, and `screen_main.rs` is built against a deliberately fabricated
//! `LiveSession` per task 4.36's own scope note. Putting a store-backed, `EnvGuard`-serialized flow
//! into either would undercut both files' own stated contracts.
//!
//! ## The end-state properties this file pins (task 4.42's Scope)
//! 1. [`accept_makes_the_sender_reachable_for_chat_and_verify_from_on_screen_affordances_alone`] —
//!    after a real `Effect::AcceptRequest` completes: a Contacts row exists, `Enter` opens a
//!    `Screen::Chat` for that sender, a typed reply really dispatches `Effect::SendMessage` for that
//!    peer, and `v` opens a `Screen::Verify` showing the *same* 60-digit safety number the request
//!    detail pane showed.
//! 2. [`the_accepted_sender_is_still_reachable_after_a_restart`] — a second, fresh `App` built from
//!    on-disk state only. Task 4.49 extended this to also assert restart-parity for the intro
//!    `worker::run_accept_request` now writes: it survives the restart in the correct *position*
//!    relative to a reply persisted after it (file order, matching write order).
//! 3. [`the_accepted_senders_rendered_trust_state_is_the_real_tofu_pin_never_verified`] — the
//!    rendered trust state is read back from the real `TrustStore`, and an accept produces a TOFU
//!    pin and nothing more; verification still requires the real out-of-band step
//!    ([`marking_verified_after_an_accept_works_because_the_pin_was_replayed_in_memory`] proves that
//!    step is *reachable*, which it is not without piece C's in-memory `trust.observe` replay —
//!    `TrustStore::mark_verified` would err `UnknownContact`).
//! 4. [`an_accepted_request_restored_from_sessions_bin_does_not_reappear`] — the
//!    `main.chat.accept_request` half of piece C.
//!
//! ## Review-round additions (task 4.42's review pass)
//! 5. [`accepting_a_request_behind_an_already_open_chat_still_leaves_the_sender_verifiable`]
//!    (Finding 1) — `Ctrl-R` is a global binding, reachable with a `Screen::Chat`/`Screen::Verify`
//!    already open on top of `Screen::Main` (which has `mem::take`n `MainState::trust` for the
//!    duration); `App::apply_accepted_request` must route its `trust.observe` replay to wherever the
//!    live `TrustStore` for this session actually is, never a placeholder left behind on `Main`.
//! 6. [`a_rejected_request_restored_from_sessions_bin_does_not_reappear`] (Finding 3) — the reject
//!    mirror of property 4: `App::apply_rejected_request` replays `main.chat.reject_request` the same
//!    way piece C's accept path replays `accept_request`, so a rejected request does not re-appear on
//!    a later `Ctrl-R`/`r` either.
//!
//! ## Task 4.46 additions — the initiator-side half of the same acceptance criterion
//! 7. [`add_contact_makes_the_added_peer_reachable_for_verify`] — the mirror of property 1/3 above
//!    for the plain `n`-add flow (`Effect::AddContact`) instead of accept: `App::apply_added_contact`
//!    replays `trust.observe` into the live `TrustStore` the same way `apply_accepted_request` already
//!    does, so a peer added this session is immediately reachable for `Screen::Verify`, no restart
//!    required.
//! 8. [`a_ctrl_r_interleaved_while_add_contact_is_in_flight_still_reconciles_the_live_contacts_list`]
//!    — the interleaving-gap fix this task's own planning pass traced: `Ctrl-R` is reachable mid
//!    `AddContactState::Adding` (unlike the accept flow, the add-contact sub-flow is embedded in
//!    `Screen::Main` itself, not a separately pushed screen), so the completion can land with
//!    `Screen::Requests` on top instead of `Screen::Main`; `App::apply_added_contact` must reconcile
//!    the display row and close the sub-flow regardless.
//!
//! ## Task 4.49 addition — the intro actually reaches the sender's own transcript
//! 9. [`the_accepted_senders_intro_appears_exactly_once_in_the_opened_chat_transcript`] — screen-level
//!    coverage of task 4.49's own fix (`worker::run_accept_request` now also appends the accepted
//!    [`meridian_core::chat::MessageRequest`]'s `intro` into `history.jsonl`): accepts a real request,
//!    opens the resulting `Screen::Chat` (a real `Effect::LoadHistory` round trip, not just the
//!    in-memory transition), and asserts the intro appears **exactly once** in `ChatState::entries` —
//!    proving `App::apply_loaded_history`'s dedup-by-`mid` (task 4.44) genuinely coalesces this new
//!    writer's disk entry with whatever the screen already holds in memory, not just that the file on
//!    disk is correct in isolation (`tests/run_worker_trust.rs` already covers that half).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::chat::ChatState;
use meridian_core::crypto::display_groups;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    generate_account, install_mock_keystore, AccountId, MemorySecretStore, OsSecretStore,
};
use meridian_core::signaling::generate_bundle;
use meridian_core::trust::{TrustState, TrustStore};

use meridian_tui::app::{
    App, AppEvent, Effect, InboundEvent, PersistHistoryEffect, PersistHistoryRequest, Screen,
};
use meridian_tui::config::TuiConfig;
use meridian_tui::preflight::{preflight_route, InitialRoute};
use meridian_tui::screens::contacts::short_pubkey;
use meridian_tui::store::contacts::{ContactRecord, ContactsDocument, TrustLabel, CURRENT_VERSION};
use meridian_tui::store::history::{Direction as HistDirection, HistoryEntry, MessageState};
use meridian_tui::worker::{dispatch, OnboardingSession};

const SERVICE: &str = "meridian-tui-accept-to-chat-test";
const NOW: u64 = 1_760_000_000;

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors `tests/run_worker_trust.rs`'s own
// `EnvGuard` exactly, including its `KEYRING_WARMUP` (see that file's own doc comment for why every
// test binary in this crate that reaches `worker.rs::init_os_keystore` needs its own).
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
            let _ = keyring::Entry::new("meridian-tui-accept-to-chat-warmup", "warmup");
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
// Fixture: a real account with one genuine, gated message request already sealed on disk
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// Mints a real OS-keystore-backed account (against the mock keystore [`EnvGuard::set`] installed)
/// and saves its real `account.json` — the exact shape `preflight_route`/`worker::run_load_session`
/// resolve everything else from.
fn setup_os_account() -> AccountId {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "self.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    account
}

fn write_chat(bob: &AccountId, chat: &ChatState) {
    let os = OsSecretStore::new(SERVICE);
    let path = account::sessions_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sealed = chat
        .seal_at_rest(&os, bob.handle())
        .expect("seal sessions.bin");
    std::fs::write(&path, sealed).expect("write sessions.bin");
}

/// The real, sealed `history/<sender>.jsonl` for `sender_ik`, as it stands on disk — read back
/// through the same `crate::store::history` loader the TUI itself uses (task 4.49: restart-parity
/// coverage for the intro `worker::run_accept_request` now writes there).
fn read_history(
    bob: &AccountId,
    sender_ik: &[u8; 32],
) -> Vec<meridian_tui::store::history::HistoryEntry> {
    let os = OsSecretStore::new(SERVICE);
    meridian_tui::store::history::load_or_default(&hex::encode(sender_ik), &os, bob.handle())
        .expect("load history.jsonl")
}

/// Drives a real, offline X3DH first contact from an independent `alice` into `bob`'s own
/// `ChatState`, landing a genuine `meridian_core::chat::MessageRequest` in his pending queue —
/// mirrors `tests/run_worker_trust.rs::receive_first_contact`/`tests/live_session_file_backed.rs`'s
/// identical fixture (never a hand-constructed `MessageRequest`). Returns alice's identity key.
fn receive_first_contact(bob: &AccountId, bob_chat: &mut ChatState) -> [u8; 32] {
    let os = OsSecretStore::new(SERVICE);
    let bob_ik = *bob.public_key().as_bytes();
    let gen = generate_bundle(&os, bob.handle(), bob_ik, 5).expect("generate_bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = gen
        .bundle
        .otks
        .iter()
        .zip(gen.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob_chat
        .vault
        .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, NOW);

    let alice_store = MemorySecretStore::new();
    let alice = generate_account(&alice_store, "alice.example").expect("generate_account");
    let alice_ik = *alice.public_key().as_bytes();

    let mut alice_chat = ChatState::default();
    alice_chat
        .start_initiator_session(
            &alice_store,
            alice.handle(),
            &alice_ik,
            &bob_ik,
            &gen.bundle.spk,
            Some(gen.bundle.otks[0]),
        )
        .expect("start_initiator_session");
    let blob = alice_chat
        .seal_outbound(
            &alice_store,
            alice.handle(),
            &alice_ik,
            &bob_ik,
            &ChatContent::Text {
                id: [1u8; 16],
                body: "hi bob, it's alice".into(),
            },
        )
        .expect("seal_outbound");

    let outcome = bob_chat.open_inbound(&os, bob.handle(), &bob_ik, &alice_ik, &blob);
    assert!(
        matches!(outcome, Err(meridian_core::chat::ChatError::MessageRequest)),
        "fixture setup sanity: a first-contact envelope must land in the request queue, got \
         {outcome:?}"
    );
    alice_ik
}

/// The whole on-disk fixture: a real account whose sealed `sessions.bin` already holds one genuine,
/// gated message request from `alice` — i.e. exactly the state a responder's client is in when it
/// starts up with a request waiting.
fn setup_home_with_a_pending_request() -> (AccountId, [u8; 32]) {
    let bob = setup_os_account();
    let mut bob_chat = ChatState::default();
    let alice_ik = receive_first_contact(&bob, &mut bob_chat);
    write_chat(&bob, &bob_chat);
    (bob, alice_ik)
}

fn write_trust(bob: &AccountId, trust: &TrustStore) {
    let os = OsSecretStore::new(SERVICE);
    let path = account::trust_path().expect("trust_path");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sealed = trust
        .seal_at_rest(&os, bob.handle())
        .expect("seal trust.bin");
    std::fs::write(&path, sealed).expect("write trust.bin");
}

fn write_contacts_doc(bob: &AccountId, doc: &ContactsDocument) {
    let os = OsSecretStore::new(SERVICE);
    meridian_tui::store::contacts::save(doc, &os, bob.handle()).expect("save contacts.json");
}

/// The review-round fixture for the review Finding 1 regression test below: on top of
/// [`setup_home_with_a_pending_request`]'s own genuine message request from `alice`, this also seeds
/// an **already-established** contact `carol` — a real `trust.bin` `Pinned` record plus its matching
/// `contacts.json` display row, exactly the shape `worker::run_add_contact` would have produced for
/// an ordinary (non-message-request) add — so `Screen::Main`'s contacts pane has someone to open
/// `Screen::Chat` for *before* `alice`'s request is ever touched. `carol`'s pubkey needs no real X3DH
/// material of her own (this test never sends her a message, only opens her `Screen::Chat`), so it is
/// a plain, arbitrary 32 bytes distinct from `alice_ik` and from bob's own key.
fn setup_home_with_a_pending_request_and_an_established_contact() -> (AccountId, [u8; 32], [u8; 32])
{
    let bob = setup_os_account();
    let carol_ik = [0x77u8; 32];

    let mut trust = TrustStore::default();
    trust.observe(carol_ik, "carol.example", NOW);
    write_trust(&bob, &trust);

    let doc = ContactsDocument {
        v: CURRENT_VERSION,
        contacts: vec![ContactRecord {
            pubkey: hex::encode(carol_ik),
            id: String::new(),
            hint: "carol.example".to_string(),
            petname: None,
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
    write_contacts_doc(&bob, &doc);

    let mut bob_chat = ChatState::default();
    let alice_ik = receive_first_contact(&bob, &mut bob_chat);
    write_chat(&bob, &bob_chat);

    (bob, carol_ik, alice_ik)
}

/// Builds an `App` exactly the way a real start-up does — [`preflight_route`] off the on-disk
/// `account.json`, which for an OS-keystore account means `Screen::Placeholder` plus a real
/// `Effect::LoadSession` — then runs that effect through the **real** `worker::dispatch` and feeds
/// the completion back in, landing on a real `Screen::Main` built from real sealed files.
async fn boot_to_main() -> (App, OnboardingSession) {
    let descriptor = AccountDescriptor::load().expect("read account.json");
    let route = preflight_route(Some(descriptor));
    assert!(
        matches!(route, InitialRoute::LoadSession),
        "an OS-keystore account must route straight to Effect::LoadSession"
    );
    let (mut app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(matches!(app.current_screen(), Screen::Placeholder));
    assert_eq!(initial_effects.len(), 1);
    let effect = initial_effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::LoadSession(_)));

    let mut session = OnboardingSession::default();
    let event = dispatch(effect, &mut session).await;
    app.update(AppEvent::Worker(Box::new(event)));
    assert!(
        matches!(app.current_screen(), Screen::Main(_)),
        "a completed LoadSession must land on the real Screen::Main"
    );
    (app, session)
}

fn render_to_text(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    format!("{}", terminal.backend())
}

/// `r` on `Screen::Main` → `Screen::Requests`, and the safety number the request detail pane shows
/// for the (single) queued request.
fn open_requests(app: &mut App) -> String {
    let effects = app.update(AppEvent::Key(char_key('r')));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => {
            assert_eq!(
                state.entries.len(),
                1,
                "the request restored from sessions.bin must be in the live queue"
            );
            state.entries[0].safety_number.clone()
        }
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
}

/// `a`, `y` on `Screen::Requests` → the real `Effect::AcceptRequest`, executed by the real worker,
/// with its completion fed back into `App`.
async fn accept_selected_request(app: &mut App, session: &mut OnboardingSession) {
    app.update(AppEvent::Key(char_key('a')));
    let effects = app.update(AppEvent::Key(char_key('y')));
    assert_eq!(effects.len(), 1, "y must dispatch Effect::AcceptRequest");
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::AcceptRequest(_)));

    let event = dispatch(effect, session).await;
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => assert!(
            state.entries.is_empty(),
            "a completed accept must clear the decided request out of the queue"
        ),
        other => panic!("expected to still be on Screen::Requests, got {other:?}"),
    }
}

/// `r`, `y` on `Screen::Requests` → the real `Effect::RejectRequest`, executed by the real worker,
/// with its completion fed back into `App`. Mirrors [`accept_selected_request`] exactly.
async fn reject_selected_request(app: &mut App, session: &mut OnboardingSession) {
    app.update(AppEvent::Key(char_key('r')));
    let effects = app.update(AppEvent::Key(char_key('y')));
    assert_eq!(effects.len(), 1, "y must dispatch Effect::RejectRequest");
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::RejectRequest(_)));

    let event = dispatch(effect, session).await;
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => assert!(
            state.entries.is_empty(),
            "a completed reject must clear the decided request out of the queue"
        ),
        other => panic!("expected to still be on Screen::Requests, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Review-round regression (task 4.42 review, Finding 3): a rejected request, same as an accepted
// one, must not re-appear on a later `Ctrl-R`/`r` in the same session — `App::apply_rejected_request`
// mirrors `App::apply_accepted_request`'s own `main.chat.accept_request` replay for the reject side.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_request_restored_from_sessions_bin_does_not_reappear() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, alice_ik) = setup_home_with_a_pending_request();

    let (mut app, mut session) = boot_to_main().await;
    open_requests(&mut app);
    reject_selected_request(&mut app, &mut session).await;
    app.update(AppEvent::Key(key(KeyCode::Esc)));

    // Re-open the queue via `r` — `App::requests_snapshot` rebuilds it from `MainState::chat`'s own
    // in-memory `pending_requests()`, so without `App::apply_rejected_request`'s
    // `main.chat.reject_request` replay the already-decided request would be offered again.
    let effects = app.update(AppEvent::Key(char_key('r')));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => assert!(
            state.entries.is_empty(),
            "a rejected request must not re-appear on the next `r`: {:?}",
            state
                .entries
                .iter()
                .map(|e| e.sender_ik)
                .collect::<Vec<_>>()
        ),
        other => panic!("expected Screen::Requests, got {other:?}"),
    }

    // The same via the global `Ctrl-R` path.
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('r'),
        KeyModifiers::CONTROL,
    )));
    match app.current_screen() {
        Screen::Requests(state) => assert!(
            !state.entries.iter().any(|e| e.sender_ik == alice_ik),
            "nor via Ctrl-R, the other dispatch site sharing App::requests_snapshot"
        ),
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Property 1 — the whole point: accept, then reach the sender with on-screen affordances only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accept_makes_the_sender_reachable_for_chat_and_verify_from_on_screen_affordances_alone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, alice_ik) = setup_home_with_a_pending_request();

    let (mut app, mut session) = boot_to_main().await;
    // Nothing to reach yet: a pristine responder has no contacts at all.
    match app.current_screen() {
        Screen::Main(main) => assert!(main.contacts.entries.is_empty()),
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    let request_safety_number = open_requests(&mut app);
    let requests_pane = render_to_text(&app, 80, 24);
    accept_selected_request(&mut app, &mut session).await;

    // Esc — the only navigation the user is given from here — must land back on Main with the
    // accepted sender now present in the contacts pane.
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    let entry = match app.current_screen() {
        Screen::Main(main) => {
            assert_eq!(
                main.contacts.entries.len(),
                1,
                "the accepted sender must be reachable from Screen::Main's own contacts pane — \
                 this is task 4.41's Defect C, and the reason Shape A + piece C both exist"
            );
            main.contacts.entries[0].clone()
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    };
    assert_eq!(entry.pubkey, alice_ik);
    assert_eq!(
        entry.id, "",
        "no `mrd1:` id exists for a sender whose hint is empty — the row records that honestly \
         rather than inventing a hint-less id form (ADR 0001)"
    );
    assert_eq!(entry.hint, "");
    assert_eq!(entry.petname, None);
    assert_eq!(
        entry.display_label(),
        short_pubkey(&alice_ik),
        "with no petname and no hint, the row falls back to the same fingerprint the Requests \
         pane showed — zero new rendering work required"
    );

    // It renders, too — not just present in the model.
    let main_pane = render_to_text(&app, 80, 24);
    assert!(
        main_pane.contains(&short_pubkey(&alice_ik)[..12]),
        "expected the accepted sender's fingerprint in the contacts pane:\n{main_pane}"
    );

    // --- Enter opens a real Screen::Chat for that sender, and a reply really dispatches ---------
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.peer_pubkey, alice_ik),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
    for c in "hello alice".chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1, "a reply must dispatch exactly one effect");
    match &effects[0] {
        Effect::SendMessage(send) => {
            assert_eq!(send.request.peer_pubkey, alice_ik);
            assert_eq!(send.request.body, "hello alice");
            assert_eq!(
                send.request.peer_hint, "",
                "no advisory hint exists for a message-request sender — the send path must carry \
                 the honest empty string, never a fabricated one"
            );
        }
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    }

    // --- Esc back to Main, then `v` opens a real Screen::Verify with the same safety number -----
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));
    app.update(AppEvent::Key(char_key('v')));
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(state.peer_pubkey, alice_ik);
            assert_eq!(
                state.safety_number, request_safety_number,
                "Screen::Verify must show exactly the 60-digit safety number the request detail \
                 pane already showed — same peers, same primitive, no re-derivation drift"
            );
        }
        other => panic!("expected Screen::Verify, got {other:?}"),
    }
    let verify_pane = render_to_text(&app, 80, 24);
    let grouped = display_groups(&request_safety_number);
    let first_group = grouped.split(' ').next().unwrap();
    assert!(
        requests_pane.contains(first_group),
        "fixture sanity: the request detail pane really did render the grouped safety \
         number:\n{requests_pane}"
    );
    assert!(
        verify_pane.contains(first_group),
        "expected the same grouped safety number on Screen::Verify:\n{verify_pane}"
    );
}

// ---------------------------------------------------------------------------
// Property 9 (task 4.49) — the accepted sender's intro survives into the *rendered* transcript,
// through the real Effect::LoadHistory round trip, not merely onto disk in isolation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_accepted_senders_intro_appears_exactly_once_in_the_opened_chat_transcript() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, alice_ik) = setup_home_with_a_pending_request();

    let (mut app, mut session) = boot_to_main().await;
    open_requests(&mut app);
    accept_selected_request(&mut app, &mut session).await;
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));

    // --- Enter opens Screen::Chat and dispatches a real Effect::LoadHistory (task 4.44) -----------
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.peer_pubkey, alice_ik),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
    let load_history = effects
        .into_iter()
        .find(|e| matches!(e, Effect::LoadHistory(_)))
        .expect("opening a chat must dispatch Effect::LoadHistory (task 4.44)");

    // --- Race a live, in-memory duplicate of the same intro into ChatState::entries BEFORE the
    // Effect::LoadHistory round trip completes — this is what actually exercises the dedup path.
    // Without this, ChatState::entries is empty at this point (`ContactsAction::OpenChat` opens with
    // `Vec::new()`), so `App::apply_loaded_history`'s `chat.entries.drain(..)` loop below would
    // iterate zero times and `chat::insert_deduped` would never run at all — the "exactly once, not
    // twice" half of this test's own name would then be unverified by construction, not merely
    // untriggered. Plausible in reality: a locally-sent echo or a retried delivery producing the same
    // wire-level `id` while history is still loading. Same `mid` (`hex::encode([1u8; 16])`) the real
    // on-disk intro carries. ---------------------------------------------------------------------
    let racing_duplicate = HistoryEntry {
        v: meridian_tui::store::history::CURRENT_VERSION,
        mid: hex::encode([1u8; 16]),
        dir: HistDirection::In,
        ts: 1_760_000_000,
        stream: "mrd.chat/1".to_string(),
        body: "hi bob, it's alice".to_string(),
        state: MessageState::Received,
    };
    let live_effects = app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: alice_ik,
        entry: racing_duplicate,
    })));
    assert!(
        live_effects.iter().any(|e| matches!(e, Effect::PersistHistory(_))),
        "a live inbound message must still dispatch Effect::PersistHistory even while a load is in \
         flight — this test doesn't need to route it further, just prove the race is realistic"
    );
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries.len(),
            1,
            "the racing live duplicate must already be in ChatState::entries before the disk load \
             completes, so the merge below has something real to dedup against"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // --- Round-trip it through the real worker, exactly like a real event-loop iteration would ----
    let event = dispatch(load_history, &mut session).await;
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    // --- The intro this accept just wrote to history.jsonl (task 4.49) must now be in the live,
    // rendered transcript — exactly once, not zero (the fifth defect this task fixes) and not twice
    // (which would mean apply_loaded_history's dedup-by-mid failed to coalesce this new writer's
    // entry with the live-arrived duplicate seeded above — the property this test's setup now
    // actually forces `chat::insert_deduped` to be exercised for, not merely asserted). -------------
    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(
                state.entries.len(),
                1,
                "the accepted sender's intro must appear exactly once in the opened transcript, \
                 got {:?}",
                state.entries
            );
            let entry = &state.entries[0];
            assert_eq!(entry.mid, hex::encode([1u8; 16]));
            assert_eq!(entry.dir, HistDirection::In);
            assert_eq!(entry.stream, "mrd.chat/1");
            assert_eq!(entry.body, "hi bob, it's alice");
            assert_eq!(entry.state, MessageState::Received);
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // Renders, too — not just present in the model.
    let chat_pane = render_to_text(&app, 80, 24);
    assert!(
        chat_pane.contains("hi bob, it's alice"),
        "expected the intro's body in the rendered transcript:\n{chat_pane}"
    );
}

// ---------------------------------------------------------------------------
// Property 3 — the rendered trust state is the real TrustStore's TOFU pin, never `verified`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_accepted_senders_rendered_trust_state_is_the_real_tofu_pin_never_verified() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, alice_ik) = setup_home_with_a_pending_request();

    let (mut app, mut session) = boot_to_main().await;
    open_requests(&mut app);
    accept_selected_request(&mut app, &mut session).await;
    app.update(AppEvent::Key(key(KeyCode::Esc)));

    match app.current_screen() {
        Screen::Main(main) => {
            // Read back off the *real* post-mutation TrustStore, not the display row.
            assert_eq!(
                main.trust.trust_state(&alice_ik),
                TrustState::Pinned,
                "accepting a message request produces a TOFU pin and nothing more"
            );
            let contact = main.trust.contact(&alice_ik).expect("pinned contact");
            assert_eq!(contact.hint, "");
            assert_eq!(contact.petname, None);
            assert!(!contact.user_blocked);
            assert_eq!(
                contact.pinned_key_history.len(),
                1,
                "one freshly-stamped history entry — a genuine first observation"
            );
            // And the display row agrees with it, rather than asserting something stronger.
            assert_eq!(
                main.contacts.entries[0].trust,
                main.trust.trust_state(&alice_ik)
            );
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    let main_pane = render_to_text(&app, 80, 24);
    assert!(
        main_pane.contains("pinned"),
        "expected the honest `pinned` trust label:\n{main_pane}"
    );
    assert!(
        !main_pane.contains("verified"),
        "an accepted request must never render as verified — verification is an out-of-band \
         safety-number compare, and nothing here performed one:\n{main_pane}"
    );

    // The same, on the verification screen itself: it offers the verify step, it does not skip it.
    app.update(AppEvent::Key(char_key('v')));
    let verify_pane = render_to_text(&app, 80, 24);
    assert!(
        verify_pane.contains("pinned"),
        "expected Screen::Verify to show the real pinned state:\n{verify_pane}"
    );
    match app.current_screen() {
        Screen::Verify(state) => assert_eq!(state.trust.trust_state(&alice_ik), TrustState::Pinned),
        other => panic!("expected Screen::Verify, got {other:?}"),
    }
}

/// Piece C's `trust.observe` replay is what makes the verify step *reachable* at all: without it the
/// live `TrustStore` has never heard of the sender and `TrustStore::mark_verified` errs
/// `TrustError::UnknownContact`, so `v` → `y` would silently do nothing. This asserts the real,
/// user-driven transition works — and that it takes the full confirm step, never a shortcut.
#[tokio::test]
async fn marking_verified_after_an_accept_works_because_the_pin_was_replayed_in_memory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, alice_ik) = setup_home_with_a_pending_request();

    let (mut app, mut session) = boot_to_main().await;
    open_requests(&mut app);
    accept_selected_request(&mut app, &mut session).await;
    app.update(AppEvent::Key(key(KeyCode::Esc)));

    app.update(AppEvent::Key(char_key('v')));
    // `v` alone only arms the confirmation — nothing is marked verified by a single keypress.
    app.update(AppEvent::Key(char_key('v')));
    match app.current_screen() {
        Screen::Verify(state) => assert_eq!(state.trust.trust_state(&alice_ik), TrustState::Pinned),
        other => panic!("expected Screen::Verify, got {other:?}"),
    }
    let effects = app.update(AppEvent::Key(char_key('y')));
    assert_eq!(effects.len(), 1, "y must dispatch Effect::MarkVerified");
    match &effects[0] {
        Effect::MarkVerified(e) => assert_eq!(e.request.pubkey, alice_ik),
        other => panic!("expected Effect::MarkVerified, got {other:?}"),
    }
    match app.current_screen() {
        Screen::Verify(state) => assert_eq!(
            state.trust.trust_state(&alice_ik),
            TrustState::Verified,
            "mark_verified must have found a real contact record to transition — the exact thing \
             piece C's in-memory trust.observe replay exists to guarantee"
        ),
        other => panic!("expected Screen::Verify, got {other:?}"),
    }

    // And it really persists, through the real worker, for the accepted sender.
    let effect = effects.into_iter().next().unwrap();
    match dispatch(effect, &mut session).await {
        meridian_tui::app::WorkerEvent::Completed(Effect::MarkVerified(_)) => {}
        other => panic!("expected MarkVerified to complete against the real trust.bin: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Property 4 — an accepted request restored from sessions.bin does not re-appear.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_accepted_request_restored_from_sessions_bin_does_not_reappear() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, alice_ik) = setup_home_with_a_pending_request();

    let (mut app, mut session) = boot_to_main().await;
    open_requests(&mut app);
    accept_selected_request(&mut app, &mut session).await;
    app.update(AppEvent::Key(key(KeyCode::Esc)));

    // Re-open the queue: `App::requests_snapshot` rebuilds it from `MainState::chat`'s own
    // in-memory `pending_requests()`, so without piece C's `main.chat.accept_request` the
    // already-decided request would be offered for decision all over again.
    let effects = app.update(AppEvent::Key(char_key('r')));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => assert!(
            state.entries.is_empty(),
            "an accepted request must not re-appear on the next `r`: {:?}",
            state
                .entries
                .iter()
                .map(|e| e.sender_ik)
                .collect::<Vec<_>>()
        ),
        other => panic!("expected Screen::Requests, got {other:?}"),
    }

    // The same via the global `Ctrl-R` path (the other dispatch site sharing `requests_snapshot`).
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('r'),
        KeyModifiers::CONTROL,
    )));
    match app.current_screen() {
        Screen::Requests(state) => assert!(
            !state.entries.iter().any(|e| e.sender_ik == alice_ik),
            "nor via Ctrl-R, the other dispatch site sharing App::requests_snapshot"
        ),
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Property 2 — still reachable after a restart (a fresh App, built from disk only).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_accepted_sender_is_still_reachable_after_a_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (bob, alice_ik) = setup_home_with_a_pending_request();

    // --- Run 1: accept, then drop the whole App and its session cache ---------------------------
    {
        let (mut app, mut session) = boot_to_main().await;
        open_requests(&mut app);
        accept_selected_request(&mut app, &mut session).await;

        // Task 4.49 restart-parity: the accept just wrote the intro to history.jsonl. Persist a
        // reply after it — mirroring what `App`'s own `Effect::SendMessage` completion handling
        // does (a `PersistHistoryRequest` for the sent body) — so this test can assert the intro
        // survives a restart in the correct *position*, not merely present in isolation. `ts` is
        // deliberately the intro's own real `ts` (read back off disk, never guessed) plus one, so
        // ordering is asserted on real data even if both writes land within the same wall-clock
        // second.
        let intro_ts = read_history(&bob, &alice_ik)
            .first()
            .expect("accept must have already written the intro")
            .ts;
        let reply = Effect::PersistHistory(PersistHistoryEffect {
            request: PersistHistoryRequest {
                peer_pubkey: alice_ik,
                entry: HistoryEntry {
                    v: meridian_tui::store::history::CURRENT_VERSION,
                    mid: hex::encode([2u8; 16]),
                    dir: HistDirection::Out,
                    ts: intro_ts + 1,
                    stream: "mrd.chat/1".to_string(),
                    body: "hello alice, from bob".to_string(),
                    state: MessageState::Delivered,
                },
            },
            outcome: None,
        });
        match dispatch(reply, &mut session).await {
            meridian_tui::app::WorkerEvent::Completed(Effect::PersistHistory(_)) => {}
            other => panic!("expected PersistHistory (reply) to complete, got {other:?}"),
        }
    }

    // --- Run 2: a brand-new App + a brand-new OnboardingSession, rebuilt from disk only ---------
    let (mut app, mut session) = boot_to_main().await;
    match app.current_screen() {
        Screen::Main(main) => {
            assert_eq!(
                main.contacts.entries.len(),
                1,
                "the sealed contacts.json row written on accept must survive a restart — this is \
                 the half Shape A owns"
            );
            assert_eq!(main.contacts.entries[0].pubkey, alice_ik);
            assert_eq!(main.contacts.entries[0].id, "");
            assert_eq!(
                main.contacts.entries[0].trust,
                TrustState::Pinned,
                "the restored row's trust state comes from the real trust.bin join"
            );
            assert_eq!(main.trust.trust_state(&alice_ik), TrustState::Pinned);
            assert!(
                main.chat.has_session(&alice_ik),
                "the delivered session survives too — accept is a delivery decision, not a \
                 session teardown"
            );
            assert!(
                main.chat.pending_request(&alice_ik).is_none(),
                "and the request is genuinely gone from the restored sessions.bin"
            );
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // Reachable, not merely present: chat and verify both open for the restored row.
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.peer_pubkey, alice_ik),
        other => panic!("expected Screen::Chat after a restart, got {other:?}"),
    }

    // Task 4.49 restart-parity: round-trip the real Effect::LoadHistory this open dispatches (task
    // 4.44) and assert the intro is present, in the correct position relative to the reply
    // persisted above — file order, since `history::append` never reorders by `ts`.
    let load_history = effects
        .into_iter()
        .find(|e| matches!(e, Effect::LoadHistory(_)))
        .expect("opening a chat must dispatch Effect::LoadHistory (task 4.44)");
    let event = dispatch(load_history, &mut session).await;
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());
    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(
                state.entries.len(),
                2,
                "expected exactly the intro and the reply after restart, got {:?}",
                state.entries
            );
            assert_eq!(state.entries[0].mid, hex::encode([1u8; 16]));
            assert_eq!(state.entries[0].dir, HistDirection::In);
            assert_eq!(state.entries[0].body, "hi bob, it's alice");
            assert_eq!(state.entries[1].mid, hex::encode([2u8; 16]));
            assert_eq!(state.entries[1].dir, HistDirection::Out);
            assert_eq!(state.entries[1].body, "hello alice, from bob");
        }
        other => panic!("expected Screen::Chat after LoadHistory, got {other:?}"),
    }

    app.update(AppEvent::Key(key(KeyCode::Esc)));
    app.update(AppEvent::Key(char_key('v')));
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(state.peer_pubkey, alice_ik);
            assert_eq!(state.trust.trust_state(&alice_ik), TrustState::Pinned);
        }
        other => panic!("expected Screen::Verify after a restart, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Review-round regression (task 4.42 review, Finding 1): `Ctrl-R` is a *global* binding, reachable
// even with a `Screen::Chat`/`Screen::Verify` already open on top of `Screen::Main` — which
// `std::mem::take`s `MainState::trust` for the duration, leaving a placeholder `TrustStore::default()`
// behind on the `Main` frame. Before the fix, `App::apply_accepted_request`'s stack walk landed the
// accept's `trust.observe` on that placeholder (silently discarded once `App::reclaim_trust`
// overwrites `main.trust` wholesale on pop), so the accepted sender's contacts row rendered `pinned`
// but the live `TrustStore` had never actually heard of them — `Screen::Verify` for that sender then
// failed `TrustError::UnknownContact`. Reproduces the exact sequence: open Chat with an already-
// established contact (`carol`) -> `Ctrl-R` -> `Screen::Requests` pushed on top of that -> accept a
// *different* sender's request (`alice`) -> close back down to `Screen::Main` -> open `Screen::Verify`
// for `alice` and assert it actually succeeds.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accepting_a_request_behind_an_already_open_chat_still_leaves_the_sender_verifiable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let (_bob, carol_ik, alice_ik) = setup_home_with_a_pending_request_and_an_established_contact();

    let (mut app, mut session) = boot_to_main().await;
    match app.current_screen() {
        Screen::Main(main) => assert_eq!(
            main.contacts.entries.len(),
            1,
            "fixture sanity: only carol (an already-established contact) is present before \
             alice's request is ever decided"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // --- Open Chat with carol first — the real screen, real `Enter`, `trust` really `mem::take`n
    // out of `MainState` for the duration. -----------------------------------------------------
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.peer_pubkey, carol_ik),
        other => panic!("expected Screen::Chat(carol), got {other:?}"),
    }

    // --- `Ctrl-R`, global, reachable with Chat still open -----------------------------------------
    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('r'),
        KeyModifiers::CONTROL,
    )));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => assert_eq!(
            state.entries.len(),
            1,
            "alice's request must still be queued, reachable via Ctrl-R even with Chat open"
        ),
        other => panic!("expected Screen::Requests pushed on top of Chat, got {other:?}"),
    }

    // --- Accept alice's request while the stack is [Main(placeholder trust), Chat(carol, real
    // trust), Requests]. -----------------------------------------------------------------------
    accept_selected_request(&mut app, &mut session).await;

    // --- Back down to Main: Esc pops Requests, Esc again pops Chat — reclaiming carol's (now
    // alice-observing) TrustStore back into Main. ----------------------------------------------
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(
        matches!(app.current_screen(), Screen::Chat(_)),
        "Chat(carol) must still be underneath the popped Requests screen"
    );
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    match app.current_screen() {
        Screen::Main(main) => assert_eq!(
            main.contacts.entries.len(),
            2,
            "both carol and the newly-accepted alice must be present in the contacts pane"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // --- The regression itself: Verify for alice must actually succeed, not error with
    // TrustError::UnknownContact. ----------------------------------------------------------------
    app.update(AppEvent::Key(key(KeyCode::Down)));
    match app.current_screen() {
        Screen::Main(main) => assert_eq!(
            main.contacts.entries[main.contacts.selected].pubkey, alice_ik,
            "selection must be on alice's row before opening Verify"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }
    app.update(AppEvent::Key(char_key('v')));
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(state.peer_pubkey, alice_ik);
            assert_eq!(
                state.trust.trust_state(&alice_ik),
                TrustState::Pinned,
                "the accept's trust.observe must have landed on whichever TrustStore was actually \
                 live at the time (Chat(carol)'s, here) — not a placeholder TrustStore::default() \
                 left behind on Screen::Main by the mem::take that opened Chat"
            );
        }
        other => panic!(
            "expected Screen::Verify to open successfully for alice, got {other:?} — a screen \
             stuck showing TrustError::UnknownContact here is exactly the bug review Finding 1 \
             reports"
        ),
    }

    // And driven the whole way through: `v`, `y` really marks alice verified — the exact reviewer
    // repro was `Screen::Verify` landing in `VerifyMode::Error("... no contact recorded for this
    // key")` at this step (`TrustStore::mark_verified` erroring `TrustError::UnknownContact` against
    // the placeholder store), not merely `Screen::Verify` failing to open at all.
    app.update(AppEvent::Key(char_key('v')));
    let effects = app.update(AppEvent::Key(char_key('y')));
    assert_eq!(
        effects.len(),
        1,
        "mark-verified must have actually dispatched Effect::MarkVerified, not silently failed"
    );
    match &effects[0] {
        Effect::MarkVerified(e) => assert_eq!(e.request.pubkey, alice_ik),
        other => panic!("expected Effect::MarkVerified, got {other:?}"),
    }
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(
                state.mode,
                meridian_tui::screens::verify::VerifyMode::View,
                "mark-verified must have succeeded (back to View), never VerifyMode::Error — a \
                 TrustError::UnknownContact here is exactly the review Finding 1 defect"
            );
            assert_eq!(state.trust.trust_state(&alice_ik), TrustState::Verified);
        }
        other => panic!("expected Screen::Verify, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Task 4.46 — `Effect::AddContact` reconciliation into the live in-memory `TrustStore`.
//
// This file already owns the harness these two properties need (real `crossterm` key events through
// `App`, real `worker::dispatch` against a real sealed `$MERIDIAN_HOME`, `EnvGuard`/`boot_to_main`/
// `render_to_text` — see this file's own module doc's "Why a new file, and why this level") — reused
// here rather than duplicated into a new file. Mirrors this file's own
// `accepting_a_request_behind_an_already_open_chat_still_leaves_the_sender_verifiable` (the
// interleaving precedent, task 4.42's review Finding 1) and
// `marking_verified_after_an_accept_works_because_the_pin_was_replayed_in_memory` (the same-session
// verify precedent), just for the plain `n`-add flow (`Effect::AddContact`) instead of the
// accept-a-request flow (`Effect::AcceptRequest`) — closing the initiator-side half of T17's own
// acceptance criterion, the responder-side half already closed by 4.42.
// ---------------------------------------------------------------------------

/// A second, independent identity — the peer these two tests add via the plain `n`-add flow. Mirrors
/// `tests/run_worker_contacts.rs::peer_id` exactly (a real `mrd1:` id string a real `parse_id` inside
/// `crate::screens::contacts::handle_enter_id` must accept) — inlined here rather than shared across
/// files, since this crate's integration test binaries have no shared `tests/support` module (every
/// other file in this crate that needs an id fixture duplicates its own, the same way).
fn peer_identity() -> (String, [u8; 32]) {
    let store = MemorySecretStore::new();
    let peer = generate_account(&store, "peer.example").expect("peer generate_account");
    (peer.to_id_string(), *peer.public_key().as_bytes())
}

/// Types `text` into whatever text field is currently focused, one real `KeyCode::Char` at a time —
/// the same one-char-per-key discipline
/// `accept_makes_the_sender_reachable_for_chat_and_verify_from_on_screen_affordances_alone`'s own
/// `for c in "hello alice".chars() { ... }` reply-typing step already uses, pulled out here since both
/// tests below type two fields (id, then petname) rather than one.
fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
}

/// Drives the plain `n`-add flow's first two steps from `Screen::Main` — `n`, paste `id`, `Enter`,
/// type `petname`, `Enter` — and returns the single `Effect::AddContact` the last `Enter` dispatches.
/// Deliberately stops short of running it through the worker: the interleaving test below needs that
/// window open (to press `Ctrl-R` while it's still in flight); the plain reachability test dispatches
/// it immediately after.
fn start_add_contact(app: &mut App, id: &str, petname: &str) -> Effect {
    let effects = app.update(AppEvent::Key(char_key('n')));
    assert!(
        effects.is_empty(),
        "n alone only opens the add-contact form"
    );
    type_text(app, id);
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert!(
        effects.is_empty(),
        "Enter on a valid id only advances to the petname step, dispatches nothing yet"
    );
    type_text(app, petname);
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(
        effects.len(),
        1,
        "Enter on the petname step must dispatch exactly one Effect::AddContact"
    );
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::AddContact(_)));
    effect
}

// ---------------------------------------------------------------------------
// Deliverable 3 (task 4.46) — same-session reachability: add, then verify, no restart in between.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_contact_makes_the_added_peer_reachable_for_verify() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, peer_pubkey) = peer_identity();

    let (mut app, mut session) = boot_to_main().await;
    match app.current_screen() {
        Screen::Main(main) => assert!(
            main.contacts.entries.is_empty(),
            "fixture sanity: a pristine account has no contacts yet"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    let effect = start_add_contact(&mut app, &id, "Peer");
    let event = dispatch(effect, &mut session).await;
    assert!(
        matches!(
            event,
            meridian_tui::app::WorkerEvent::Completed(Effect::AddContact(_))
        ),
        "expected Effect::AddContact to complete against the real trust.bin, got {event:?}"
    );
    let completed_added_at = match &event {
        meridian_tui::app::WorkerEvent::Completed(Effect::AddContact(effect)) => {
            effect
                .outcome
                .as_ref()
                .expect("the fixture's request must succeed")
                .added_at
        }
        _ => unreachable!("matched above"),
    };
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    // The new contact is present, the add form is closed, and — the actual defect this task exists
    // to fix — the live in-memory TrustStore genuinely knows about the peer, not just the display
    // row `contacts::handle_worker`'s own per-screen path already produced.
    match app.current_screen() {
        Screen::Main(main) => {
            assert!(
                main.contacts.add.is_none(),
                "the add-contact form must close on completion"
            );
            assert_eq!(main.contacts.entries.len(), 1);
            let entry = &main.contacts.entries[0];
            assert_eq!(entry.pubkey, peer_pubkey);
            assert_eq!(entry.id, id);
            assert_eq!(entry.petname.as_deref(), Some("Peer"));
            assert_eq!(
                main.trust.trust_state(&peer_pubkey),
                TrustState::Pinned,
                "the real, live TrustStore must already have observed this peer — this is task \
                 4.46's own defect: without App::apply_added_contact this would still read \
                 TrustState::default(), and mark-verified below would fail with \
                 TrustError::UnknownContact"
            );
            // The live observe() must genuinely replay the worker-supplied added_at, not a
            // wall-clock stand-in or a hardcoded value — read back from the real TrustStore, not
            // from the display-row copy (ContactEntry's own added_at is sourced independently,
            // straight from AddedContact, so it can't catch a divergence in the trust.observe()
            // call this test actually exists to exercise).
            let contact = main
                .trust
                .contact(&peer_pubkey)
                .expect("trust.observe() must have created a Contact record");
            assert_eq!(
                contact.pinned_key_history[0].first_seen_unix, completed_added_at,
                "App::apply_added_contact must replay the worker-supplied added_at into \
                 trust.observe(), not App::update's own wall-clock or a stale value"
            );
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // Reachable for verify, in the SAME session, no restart — Screen::Verify must render the real
    // safety number rather than erroring on an unknown contact.
    app.update(AppEvent::Key(char_key('v')));
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(state.peer_pubkey, peer_pubkey);
            assert_eq!(state.trust.trust_state(&peer_pubkey), TrustState::Pinned);
            assert!(
                !state.safety_number.is_empty(),
                "a real safety number must render, not an UnknownContact error"
            );
        }
        other => panic!(
            "expected Screen::Verify to open successfully for the newly-added peer, got {other:?}"
        ),
    }
    let verify_pane = render_to_text(&app, 80, 24);
    assert!(
        !verify_pane.to_lowercase().contains("unknown contact"),
        "must never render TrustError::UnknownContact for a peer just added this session:\n{}",
        verify_pane
    );

    // v -> y really marks the peer verified, and reads back from the real post-mutation store —
    // never fabricated by the UI, same discipline as 4.42's own Deliverable 3 property 3.
    app.update(AppEvent::Key(char_key('v')));
    let effects = app.update(AppEvent::Key(char_key('y')));
    assert_eq!(effects.len(), 1, "y must dispatch Effect::MarkVerified");
    match &effects[0] {
        Effect::MarkVerified(e) => assert_eq!(e.request.pubkey, peer_pubkey),
        other => panic!("expected Effect::MarkVerified, got {other:?}"),
    }
    match app.current_screen() {
        Screen::Verify(state) => assert_eq!(
            state.trust.trust_state(&peer_pubkey),
            TrustState::Verified,
            "mark_verified must have found a real contact record to transition"
        ),
        other => panic!("expected Screen::Verify, got {other:?}"),
    }

    // And it really persists through the real worker.
    let effect = effects.into_iter().next().unwrap();
    match dispatch(effect, &mut session).await {
        meridian_tui::app::WorkerEvent::Completed(Effect::MarkVerified(_)) => {}
        other => panic!("expected MarkVerified to complete against the real trust.bin: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Deliverable 4 (task 4.46) — the interleaving-gap regression: `Ctrl-R` fires while
// `Effect::AddContact` is still in flight (a global, unconditional binding — `App::handle_key` checks
// it before any screen-specific key interception, reachable even while `ContactsState.add` is
// `Some(Adding)`), pushing `Screen::Requests` on top of `Screen::Main`. The completion must still
// reconcile into `Screen::Main` (`App::apply_added_contact`, matched on the event, not on top of the
// stack) rather than being silently swallowed by `requests::handle_worker`, which forwards nothing —
// and the add-contact sub-flow must not be left stuck in `Adding` forever.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_ctrl_r_interleaved_while_add_contact_is_in_flight_still_reconciles_the_live_contacts_list(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, peer_pubkey) = peer_identity();

    let (mut app, mut session) = boot_to_main().await;
    let effect = start_add_contact(&mut app, &id, "Peer");
    match app.current_screen() {
        Screen::Main(main) => assert!(
            matches!(
                main.contacts.add,
                Some(meridian_tui::screens::contacts::AddContactState::Adding(_))
            ),
            "fixture sanity: the add-contact sub-flow must genuinely be mid-Adding before Ctrl-R"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // Ctrl-R, global and unconditional, reachable mid-`Adding` — pushes Screen::Requests on top of
    // Screen::Main while Effect::AddContact is still out with the worker.
    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('r'),
        KeyModifiers::CONTROL,
    )));
    assert!(effects.is_empty());
    assert!(
        matches!(app.current_screen(), Screen::Requests(_)),
        "Ctrl-R must have pushed Screen::Requests on top of Screen::Main mid-Adding"
    );

    // The completion arrives while Screen::Requests is on top — the exact interleaving window this
    // test exists to cover.
    let event = dispatch(effect, &mut session).await;
    assert!(
        matches!(
            event,
            meridian_tui::app::WorkerEvent::Completed(Effect::AddContact(_))
        ),
        "expected Effect::AddContact to complete against the real trust.bin, got {event:?}"
    );
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    // Esc back to Main.
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    match app.current_screen() {
        Screen::Main(main) => {
            assert!(
                main.contacts.add.is_none(),
                "the add-contact form must not be left stuck in Adding — this is task 4.46's own \
                 interleaving-gap defect"
            );
            assert_eq!(
                main.contacts.entries.len(),
                1,
                "the new contact must appear in the live Contacts list even though the completion \
                 landed with Screen::Requests on top"
            );
            let entry = &main.contacts.entries[0];
            assert_eq!(entry.pubkey, peer_pubkey);
            assert_eq!(entry.petname.as_deref(), Some("Peer"));
            assert_eq!(
                main.trust.trust_state(&peer_pubkey),
                TrustState::Pinned,
                "the live TrustStore must also have observed the peer, not just the display row"
            );
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // And reachable for verify, same session, no restart.
    app.update(AppEvent::Key(char_key('v')));
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(state.peer_pubkey, peer_pubkey);
            assert_eq!(state.trust.trust_state(&peer_pubkey), TrustState::Pinned);
        }
        other => panic!(
            "expected Screen::Verify to open successfully for the newly-added peer, got {other:?}"
        ),
    }
}
