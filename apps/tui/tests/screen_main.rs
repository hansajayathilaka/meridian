//! `Screen::Main` + live navigation (task 4.36) — `cargo test -p meridian-tui --test screen_main`.
//!
//! Built and tested against a **fabricated** [`LiveSession`], per this task's own scope note — zero
//! dependency on `Preflight` (task 4.37) or a real `run_worker` existing. Covers this task's own
//! named deliverables:
//! 1. `screens::main` + `Screen::Main`, constructed from a `LiveSession` (`MainState::from_session`).
//! 2. `Contacts`'s `Enter` opens a real `Screen::Chat`; the new dedicated `i` key opens
//!    `Screen::ContactDetail`; `v` opens a real `Screen::Verify` — all wired through `Screen::Main`
//!    as the hub, with the moved `TrustStore` reclaimed (and that contact's own display row
//!    refreshed) once the child screen pops.
//! 3. A working "open Settings" palette command.
//! 4. Screen-snapshot tests at 80x24 and a narrow width.
//!
//! Also covers the live `Ctrl-R`/`r` request-queue snapshot (task 4.36's own narrowed scope: as of
//! session load, not live arrivals — see `crate::screens::main`'s own module doc), using a real,
//! offline (no network, no rendezvous server) X3DH-gated `MessageRequest`, mirroring
//! `apps/core/tests/message_request_gate.rs`'s own minimal recipe.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::account::{AccountDescriptor, StoreKind};
use meridian_core::chat::ChatState as CoreChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, MemorySecretStore};
use meridian_core::signaling::generate_bundle;
use meridian_core::trust::{TrustState, TrustStore};

use meridian_tui::app::{App, AppEvent, Screen};
use meridian_tui::screens::main::{self, MainState};
use meridian_tui::session::LiveSession;
use meridian_tui::store::contacts::{ContactRecord, ContactsDocument, PolicyOverride, TrustLabel};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::CONTROL)
}

fn account_descriptor(pubkey: [u8; 32]) -> AccountDescriptor {
    AccountDescriptor {
        v: 1,
        pubkey: hex::encode(pubkey),
        hint: "self.example".to_string(),
        store: StoreKind::Os,
        keyfile: None,
        service: Some("meridian".to_string()),
        label: hex::encode(pubkey),
        server: None,
    }
}

/// A `LiveSession` with one already-pinned contact (`bob`) — the fabricated fixture this whole file
/// is built and tested against, per this task's own scope note.
fn session_with_bob() -> ([u8; 32], [u8; 32], LiveSession) {
    let own_pubkey = [0x11u8; 32];
    let bob_pubkey = [0x42u8; 32];

    let mut trust = TrustStore::default();
    trust.observe(bob_pubkey, "bob.example", 1_000);
    trust
        .set_petname(&bob_pubkey, Some("bob".to_string()))
        .unwrap();

    let mut contacts = ContactsDocument {
        v: meridian_tui::store::contacts::CURRENT_VERSION,
        contacts: Vec::new(),
    };
    contacts.contacts.push(ContactRecord {
        pubkey: hex::encode(bob_pubkey),
        id: meridian_core::identity::to_id_string(&bob_pubkey, "bob.example").unwrap(),
        hint: "bob.example".to_string(),
        petname: Some("bob".to_string()),
        trust: TrustLabel::Pinned,
        pinned_key_history: Vec::new(),
        device_record_version_seen: None,
        policy_override: Some(PolicyOverride::Direct),
        added_at: 1_000,
        last_activity_at: 1_000,
        unread: 2,
        conv_handle: None,
    });

    let session = LiveSession {
        account: account_descriptor(own_pubkey),
        trust,
        chat: CoreChatState::default(),
        contacts,
    };
    (own_pubkey, bob_pubkey, session)
}

/// Pushes `Screen::Main` directly, mirroring every other screen's own "independently reachable via
/// `App::push_screen`" pattern before its own live-navigation task landed — `App` itself has no
/// public constructor for a live `Screen::Main` yet (Preflight, task 4.37, is what will add one),
/// so tests build one by hand exactly like `apps/tui/tests/at_rest_audit.rs` already does for
/// `Screen::Chat`/`Screen::Verify`.
fn push_main(app: &mut App, state: MainState) {
    app.push_screen(Screen::Main(Box::new(state)));
}

fn app_with_main() -> (App, [u8; 32], [u8; 32]) {
    let (own_pubkey, bob_pubkey, session) = session_with_bob();
    let mut app = App::new();
    push_main(&mut app, MainState::from_session(session));
    (app, own_pubkey, bob_pubkey)
}

fn render_to_text(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    format!("{}", terminal.backend())
}

/// Real, offline (no network) X3DH-gated `MessageRequest`, installed straight into `receiver`'s own
/// `ChatState` — mirrors `apps/core/tests/message_request_gate.rs::Party::publish`/`send`/`recv`
/// exactly, just collapsed into one function for this file's own narrow need: proving
/// `App::requests_snapshot` actually reads `Screen::Main`'s `chat.pending_requests()`, not only
/// `App::pending_inbound_requests`.
fn establish_pending_request(receiver: &mut CoreChatState) -> [u8; 32] {
    // A fresh, independent identity for this helper's own X3DH round trip — deliberately not tied
    // to `session_with_bob`'s own `own_pubkey`/`account_descriptor` fixture (`ChatState::
    // open_inbound` only needs a real `SecretStore`/`KeyHandle` matching whichever identity ran the
    // handshake, never the caller's own separately-fabricated `AccountDescriptor`).
    let receiver_store = MemorySecretStore::new();
    let receiver_account = generate_account(&receiver_store, "receiver.example").unwrap();

    let gen = generate_bundle(
        &receiver_store,
        receiver_account.handle(),
        *receiver_account.public_key().as_bytes(),
        5,
    )
    .expect("generate_bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = gen
        .bundle
        .otks
        .iter()
        .zip(gen.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    receiver
        .vault
        .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, 1_700_000_000);

    let sender_store = MemorySecretStore::new();
    let sender_account = generate_account(&sender_store, "sender.example").unwrap();
    let sender_pub = *sender_account.public_key().as_bytes();
    let receiver_pub = *receiver_account.public_key().as_bytes();

    let mut sender_chat = CoreChatState::default();
    sender_chat
        .start_initiator_session(
            &sender_store,
            sender_account.handle(),
            &sender_pub,
            &receiver_pub,
            &gen.bundle.spk,
            gen.bundle.otks.first().copied(),
        )
        .expect("start_initiator_session");
    let blob = sender_chat
        .seal_outbound(
            &sender_store,
            sender_account.handle(),
            &sender_pub,
            &receiver_pub,
            &ChatContent::Text {
                id: [7u8; 16],
                body: "hi, new here".to_string(),
            },
        )
        .expect("seal_outbound");

    let err = receiver
        .open_inbound(
            &receiver_store,
            receiver_account.handle(),
            &receiver_pub,
            &sender_pub,
            &blob,
        )
        .expect_err("a first contact is gated, not delivered");
    assert!(matches!(
        err,
        meridian_core::chat::ChatError::MessageRequest
    ));
    sender_pub
}

// ---------------------------------------------------------------------------
// MainState::from_session — the join (further coverage of `crate::screens::main`'s own unit tests)
// ---------------------------------------------------------------------------

#[test]
fn main_state_from_session_builds_a_contacts_list_from_the_join() {
    let (_own, bob_pubkey, session) = session_with_bob();
    let state = MainState::from_session(session);
    assert_eq!(state.contacts.entries.len(), 1);
    assert_eq!(state.contacts.entries[0].pubkey, bob_pubkey);
    assert_eq!(state.contacts.entries[0].petname.as_deref(), Some("bob"));
}

// ---------------------------------------------------------------------------
// Enter -> Screen::Chat, with the TrustStore moved and reclaimed on Esc
// ---------------------------------------------------------------------------

#[test]
fn enter_opens_a_real_chat_screen_and_esc_reclaims_the_trust_store_into_main() {
    let (mut app, _own, bob_pubkey) = app_with_main();

    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(state.peer_pubkey, bob_pubkey);
            assert!(
                state.entries.is_empty(),
                "no per-peer history in this task's own scope — see crate::screens::main's module doc"
            );
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));
    match app.current_screen() {
        Screen::Main(main) => {
            assert_eq!(
                main.trust.contacts().count(),
                1,
                "the TrustStore must be reclaimed back into Main on Esc"
            );
            assert!(main.trust.contact(&bob_pubkey).is_some());
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `i` -> Screen::ContactDetail, edits reconciled back into Main's own contacts list
// ---------------------------------------------------------------------------

#[test]
fn i_opens_contact_detail_and_esc_reconciles_a_petname_edit_back_into_main() {
    let (mut app, _own, _bob) = app_with_main();

    app.update(AppEvent::Key(key(KeyCode::Char('i'))));
    assert!(matches!(app.current_screen(), Screen::ContactDetail(_)));

    app.update(AppEvent::Key(key(KeyCode::Char('p'))));
    for _ in 0..3 {
        app.update(AppEvent::Key(key(KeyCode::Backspace)));
    }
    for c in "Bobby".chars() {
        app.update(AppEvent::Key(key(KeyCode::Char(c))));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    let effect = effects.into_iter().next().expect("SetPetname effect");
    app.update(AppEvent::Worker(Box::new(
        meridian_tui::app::WorkerEvent::Completed(effect),
    )));
    app.update(AppEvent::Key(key(KeyCode::Esc)));

    match app.current_screen() {
        Screen::Main(main) => {
            assert_eq!(main.contacts.entries.len(), 1);
            assert_eq!(main.contacts.entries[0].petname.as_deref(), Some("Bobby"));
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `v` -> Screen::Verify, mark-verified reclaimed AND reflected in Main's own trust glyph
// ---------------------------------------------------------------------------

#[test]
fn v_opens_verify_and_marking_verified_is_reflected_in_mains_contacts_list_after_esc() {
    let (mut app, own_pubkey, bob_pubkey) = app_with_main();

    app.update(AppEvent::Key(key(KeyCode::Char('v'))));
    match app.current_screen() {
        Screen::Verify(state) => {
            assert_eq!(state.own_pubkey, own_pubkey);
            assert_eq!(state.peer_pubkey, bob_pubkey);
        }
        other => panic!("expected Screen::Verify, got {other:?}"),
    }

    app.update(AppEvent::Key(key(KeyCode::Char('v')))); // -> Confirm(Verify)
    let effects = app.update(AppEvent::Key(key(KeyCode::Char('y'))));
    assert_eq!(effects.len(), 1, "expects Effect::MarkVerified");

    app.update(AppEvent::Key(key(KeyCode::Esc)));
    match app.current_screen() {
        Screen::Main(main) => {
            assert_eq!(
                main.trust.trust_state(&bob_pubkey),
                TrustState::Verified,
                "the mark-verified mutation must be reclaimed into Main's own TrustStore"
            );
            assert_eq!(
                main.contacts.entries[0].trust,
                TrustState::Verified,
                "and Main's own contacts-list display row must be refreshed, not stale"
            );
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Ctrl-R / `r`: live pending_requests() snapshot (task 4.36's own narrowed scope)
// ---------------------------------------------------------------------------

#[test]
fn ctrl_r_reflects_mains_own_live_pending_requests_as_of_session_load() {
    let (_own, _bob, mut session) = session_with_bob();
    let sender_ik = establish_pending_request(&mut session.chat);

    let mut app = App::new();
    push_main(&mut app, MainState::from_session(session));

    let effects = app.update(AppEvent::Key(ctrl(KeyCode::Char('r'))));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Requests(state) => {
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.entries[0].sender_ik, sender_ik);
        }
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
}

#[test]
fn ctrl_r_merges_the_live_session_load_snapshot_with_anything_that_arrived_live() {
    let (_own, _bob, mut session) = session_with_bob();
    let sender_ik = establish_pending_request(&mut session.chat);

    let mut app = App::new();
    push_main(&mut app, MainState::from_session(session));

    // A second, distinct request arrives live (task 4.35's own mechanism) before Ctrl-R is pressed.
    let live_entry = meridian_tui::screens::requests::RequestEntry {
        sender_ik: [0x99u8; 32],
        safety_number: "0".repeat(60),
        intro: ChatContent::Text {
            id: [1u8; 16],
            body: "hi".to_string(),
        },
    };
    app.update(AppEvent::Inbound(Box::new(
        meridian_tui::app::InboundEvent::MessageRequest(live_entry.clone()),
    )));

    app.update(AppEvent::Key(ctrl(KeyCode::Char('r'))));
    match app.current_screen() {
        Screen::Requests(state) => {
            assert_eq!(state.entries.len(), 2);
            assert!(state.entries.iter().any(|e| e.sender_ik == sender_ik));
            assert!(state
                .entries
                .iter()
                .any(|e| e.sender_ik == live_entry.sender_ik));
        }
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Settings palette command (deliverable 3)
// ---------------------------------------------------------------------------

#[test]
fn settings_is_reachable_end_to_end_from_the_palette_and_is_idempotent() {
    let mut app = App::new();
    assert!(app.commands().get("nav.settings").is_some());

    app.update(AppEvent::Key(ctrl(KeyCode::Char('k'))));
    assert!(matches!(app.current_screen(), Screen::Palette(_)));

    // "Diagnostics" (nav.diagnostics) sorts before "Settings" (nav.settings) — move down once.
    app.update(AppEvent::Key(key(KeyCode::Down)));
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert!(effects.is_empty(), "PushScreen dispatches no worker Effect");
    assert!(matches!(app.current_screen(), Screen::Settings(_)));

    // Re-opening the palette and selecting Settings again must not stack a duplicate — popping
    // once must land straight back on the root (Onboarding), never needing a second pop.
    app.update(AppEvent::Key(ctrl(KeyCode::Char('k'))));
    app.update(AppEvent::Key(key(KeyCode::Down)));
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert!(matches!(app.current_screen(), Screen::Settings(_)));
    let popped = app.pop_screen();
    assert!(matches!(popped, Some(Screen::Settings(_))));
    assert!(
        matches!(app.current_screen(), Screen::Onboarding(_)),
        "exactly one pop must reach the root — no duplicate Settings screen was stacked"
    );
}

// ---------------------------------------------------------------------------
// Screen-snapshot tests (deliverable 4): 80x24 and a narrow width
// ---------------------------------------------------------------------------

#[test]
fn snapshot_screen_main_at_80x24_and_narrow_width() {
    let (app, _own, _bob) = app_with_main();
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(&app, w, h);
        assert!(
            text.contains("bob"),
            "expected the petname to render at {w}x{h}:\n{text}"
        );
        assert!(
            text.contains("not connected"),
            "expected the honest disconnected status bar at {w}x{h}:\n{text}"
        );
    }
}

#[test]
fn main_render_function_works_directly_against_a_test_backend() {
    let (_own, _bob, session) = session_with_bob();
    let state = MainState::from_session(session);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| main::render(&state, frame))
            .expect("draw");
    }
}

#[test]
fn snapshot_screen_main_with_no_contacts_yet() {
    let session = LiveSession::empty(account_descriptor([0x22u8; 32]));
    let state = MainState::from_session(session);
    assert!(state.contacts.entries.is_empty());
    let mut app = App::new();
    push_main(&mut app, state);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(&app, w, h);
        assert!(text.contains("no contacts"));
    }
}
