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
//!
//! ## Task 4.44 additions — the `Effect::LoadHistory` completion/merge/dedup properties
//! `App`-level, against this file's own fabricated `LiveSession` (no real worker/store I/O — the
//! real, sealed-on-disk end-to-end proof is `tests/history_load.rs`): `Effect::LoadHistory`
//! dispatched on open (covered above), its completion merged into the open `Screen::Chat` in the
//! right order, a live inbound arriving after that load is not double-listed (dedup by `mid`, reused
//! from `crate::screens::chat::insert_deduped`), a same-session re-open (`Esc` then `Enter` again)
//! dispatches a fresh load, and a stale completion for an already-popped `Screen::Chat` is a
//! harmless no-op.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::account::{AccountDescriptor, StoreKind};
use meridian_core::chat::ChatState as CoreChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, MemorySecretStore};
use meridian_core::signaling::generate_bundle;
use meridian_core::trust::{TrustState, TrustStore};

use meridian_tui::app::{
    App, AppEvent, Effect, InboundEvent, LoadHistoryEffect, Screen, WorkerEvent,
};
use meridian_tui::screens::main::{self, MainState};
use meridian_tui::session::LiveSession;
use meridian_tui::store::contacts::{ContactRecord, ContactsDocument, PolicyOverride, TrustLabel};
use meridian_tui::store::history::{self, Direction as MsgDirection, HistoryEntry, MessageState};

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
    assert_eq!(
        effects.len(),
        1,
        "opening a chat must dispatch exactly one Effect::LoadHistory (task 4.44)"
    );
    match &effects[0] {
        meridian_tui::app::Effect::LoadHistory(e) => {
            assert_eq!(e.request.peer_pubkey, bob_pubkey)
        }
        other => panic!("expected Effect::LoadHistory, got {other:?}"),
    }
    match app.current_screen() {
        Screen::Chat(state) => {
            assert_eq!(state.peer_pubkey, bob_pubkey);
            assert!(
                state.entries.is_empty(),
                "the screen opens instantly with an empty transcript — the real, persisted \
                 history is merged in once Effect::LoadHistory completes (task 4.44), see \
                 crate::app::App::apply_loaded_history"
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
// Task 4.44: a completed Effect::LoadHistory is merged into the open Screen::Chat, in order
// ---------------------------------------------------------------------------

fn history_entry(
    mid: &str,
    dir: MsgDirection,
    ts: u64,
    body: &str,
    state: MessageState,
) -> HistoryEntry {
    HistoryEntry {
        v: history::CURRENT_VERSION,
        mid: mid.to_string(),
        dir,
        ts,
        stream: "mrd.chat/1".to_string(),
        body: body.to_string(),
        state,
    }
}

fn completed_load_history(peer_pubkey: [u8; 32], entries: Vec<HistoryEntry>) -> WorkerEvent {
    WorkerEvent::Completed(Effect::LoadHistory(LoadHistoryEffect {
        request: meridian_tui::app::LoadHistoryRequest { peer_pubkey },
        outcome: Some(entries),
    }))
}

#[test]
fn a_completed_load_history_populates_the_open_chats_transcript_in_order() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert!(state.entries.is_empty()),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    let loaded = vec![
        history_entry(
            "1".repeat(32).as_str(),
            MsgDirection::In,
            1_000,
            "hi",
            MessageState::Received,
        ),
        history_entry(
            "2".repeat(32).as_str(),
            MsgDirection::Out,
            1_001,
            "hey",
            MessageState::Delivered,
        ),
    ];
    let leftover = app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        loaded.clone(),
    ))));
    assert!(leftover.is_empty());

    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries, loaded,
            "the loaded transcript must appear in the same order it was persisted"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// Deliverable 4's own named dedup assertion: an inbound message arriving live for a peer whose
/// history was *just* loaded must not be double-listed — reuses `crate::screens::chat::
/// insert_deduped` on both the load-completion merge and the live-inbound append, so whichever
/// arrives first, the second is a deduped no-op against the same `mid`.
#[test]
fn a_live_inbound_message_after_a_completed_load_is_not_double_listed() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));

    let already_persisted = history_entry(
        "3".repeat(32).as_str(),
        MsgDirection::In,
        1_000,
        "already on disk",
        MessageState::Received,
    );
    app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        vec![already_persisted.clone()],
    ))));

    // The same message arrives again live (e.g. a re-delivered envelope, or a race with the
    // worker's own unconditional persist — see `App::handle_inbound`'s own doc comment) — same
    // `mid`, must not double-list.
    app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: bob_pubkey,
        entry: already_persisted.clone(),
    })));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries,
            vec![already_persisted.clone()],
            "a re-delivered mid must not be double-listed"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // A genuinely new message, with a new `mid`, is appended normally.
    let new_message = history_entry(
        "4".repeat(32).as_str(),
        MsgDirection::In,
        1_002,
        "a new one",
        MessageState::Received,
    );
    app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: bob_pubkey,
        entry: new_message.clone(),
    })));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.entries, vec![already_persisted, new_message]),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// A live inbound message arriving *before* the history load completes must still end up after the
/// loaded (older) entries once the load does complete — `App::apply_loaded_history` puts `loaded`
/// first, then folds in whatever was already appended, preserving chronological order rather than
/// letting a slow disk read shuffle a message that arrived first behind older history.
#[test]
fn a_completed_load_arriving_after_a_live_inbound_still_orders_history_first() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));

    let live_first = history_entry(
        "5".repeat(32).as_str(),
        MsgDirection::In,
        2_000,
        "arrived while the load was still in flight",
        MessageState::Received,
    );
    app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: bob_pubkey,
        entry: live_first.clone(),
    })));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.entries, vec![live_first.clone()]),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    let older = history_entry(
        "6".repeat(32).as_str(),
        MsgDirection::Out,
        1_000,
        "older, already on disk",
        MessageState::Delivered,
    );
    app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        vec![older.clone()],
    ))));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries,
            vec![older, live_first],
            "loaded history must come first, with whatever arrived live folded in afterward"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// Permanent regression for the exact race `App::apply_loaded_history`'s own doc comment names: a
/// message already flushed to disk by the time `Effect::LoadHistory`'s read ran (so it is present in
/// `loaded`) that is *also* separately delivered live while that same load is still in flight (same
/// `mid`, arriving **before** the completion lands) must appear exactly once in the final transcript,
/// not doubled. Unlike `a_live_inbound_message_after_a_completed_load_is_not_double_listed` above
/// (live arrival *after* the load completes), this pins the opposite ordering of the same race.
#[test]
fn same_mid_in_both_loaded_and_a_still_in_flight_live_arrival_is_deduped_not_doubled() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));

    let shared = history_entry(
        "a".repeat(32).as_str(),
        MsgDirection::In,
        1_000,
        "flushed to disk, then also delivered live before the load completed",
        MessageState::Received,
    );

    // Arrives live first, while Effect::LoadHistory is still in flight.
    app.update(AppEvent::Inbound(Box::new(InboundEvent::Message {
        peer_pubkey: bob_pubkey,
        entry: shared.clone(),
    })));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.entries, vec![shared.clone()]),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // The load then completes; its own read of the sealed file also carries the same entry (same
    // mid — it was already flushed to disk by the time the read ran).
    app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        vec![shared.clone()],
    ))));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries,
            vec![shared],
            "the same mid present in both the loaded transcript and a still-in-flight live arrival \
             must be deduped, not doubled"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// A same-session re-open (`Esc` then `Enter` again) dispatches a fresh `Effect::LoadHistory` and,
/// once it completes, shows the transcript again — closing the second half of this task's own named
/// gap ("Esc out of a chat and back in, which today discards the popped `ChatState`'s entries").
#[test]
fn re_opening_a_chat_after_esc_dispatches_a_fresh_load_and_restores_the_transcript() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    let loaded = vec![history_entry(
        "7".repeat(32).as_str(),
        MsgDirection::In,
        1_000,
        "seen once already",
        MessageState::Received,
    )];
    app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        loaded.clone(),
    ))));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.entries, loaded),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // Esc pops Chat — today (pre-4.44-fix) this would have discarded `entries` for good.
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));

    // Re-open: a fresh Screen::Chat, empty again, plus a fresh Effect::LoadHistory dispatch.
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1);
    assert!(matches!(&effects[0], Effect::LoadHistory(_)));
    match app.current_screen() {
        Screen::Chat(state) => assert!(state.entries.is_empty()),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    // Completing that fresh load restores the same transcript (as `load_or_default` would, reading
    // the same still-sealed file — nothing was lost by the Esc/re-open round trip).
    app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        loaded.clone(),
    ))));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(state.entries, loaded),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// The interleaving `App::apply_loaded_history`'s own doc comment cites as *why* it walks the whole
/// screen stack rather than assuming `Screen::Chat` is on top: `Ctrl-R` is a global binding, reachable
/// even with a `Screen::Chat` already open, and pushes `Screen::Requests` on top of it while that
/// chat's own `Effect::LoadHistory` is still in flight. This is the same defect *class* task 4.42's
/// `apply_accepted_request` was found missing (Finding 1) — mechanically verified by code inspection
/// there, but until now untested for the `LoadHistory` completion path.
#[test]
fn a_load_history_completion_lands_correctly_behind_an_interleaved_ctrl_r_requests_screen() {
    let (mut app, _own, bob_pubkey) = app_with_main();

    // Open the chat — dispatches Effect::LoadHistory, still in flight.
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1);
    assert!(matches!(&effects[0], Effect::LoadHistory(_)));
    assert!(matches!(app.current_screen(), Screen::Chat(_)));

    // Ctrl-R pushes Screen::Requests on top of the still-open Chat while the LoadHistory dispatched
    // above is still in flight.
    app.update(AppEvent::Key(ctrl(KeyCode::Char('r'))));
    assert!(matches!(app.current_screen(), Screen::Requests(_)));

    // The pending Effect::LoadHistory now completes while Requests sits on top.
    let loaded = vec![history_entry(
        "9".repeat(32).as_str(),
        MsgDirection::In,
        1_000,
        "loaded while Requests was on top",
        MessageState::Received,
    )];
    let leftover = app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        loaded.clone(),
    ))));
    assert!(leftover.is_empty());

    // Navigation must be undisturbed — still on Screen::Requests.
    assert!(matches!(app.current_screen(), Screen::Requests(_)));

    // Pop back to the Chat screen underneath and confirm the transcript actually landed there — not
    // lost, and not misrouted onto Requests or dropped on the floor.
    let popped = app.pop_screen();
    assert!(matches!(popped, Some(Screen::Requests(_))));
    match app.current_screen() {
        Screen::Chat(state) => assert_eq!(
            state.entries, loaded,
            "the completed LoadHistory must land on the Screen::Chat frame underneath the \
             interleaved Ctrl-R Screen::Requests, not be lost or misrouted"
        ),
        other => panic!("expected Screen::Chat underneath Requests, got {other:?}"),
    }
}

/// A stale `Effect::LoadHistory` completion for a `Screen::Chat` that has already been popped (e.g.
/// a slow load racing a quick `Esc`) is a harmless no-op — nothing to merge it into, and nothing
/// already-persisted is lost (the next `OpenChat` reads it fresh off disk).
#[test]
fn a_stale_load_history_completion_with_no_matching_chat_screen_is_a_no_op() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));

    let leftover = app.update(AppEvent::Worker(Box::new(completed_load_history(
        bob_pubkey,
        vec![history_entry(
            "8".repeat(32).as_str(),
            MsgDirection::In,
            1_000,
            "stale",
            MessageState::Received,
        )],
    ))));
    assert!(leftover.is_empty());
    assert!(matches!(app.current_screen(), Screen::Main(_)));
}

// ---------------------------------------------------------------------------
// A failed Effect::LoadHistory (App::note_history_load_failure) — previously untested.
// ---------------------------------------------------------------------------

fn failed_load_history(peer_pubkey: [u8; 32], message: &str) -> WorkerEvent {
    WorkerEvent::Failed(
        Effect::LoadHistory(LoadHistoryEffect {
            request: meridian_tui::app::LoadHistoryRequest { peer_pubkey },
            outcome: None,
        }),
        message.to_string(),
    )
}

/// A failed `Effect::LoadHistory` completion surfaces a notice on the still-open `Screen::Chat` for
/// the matching peer — mirrors `crate::screens::chat::handle_worker`'s own `Effect::PersistHistory`
/// failure notice. Nothing already shown is lost: `entries` is left exactly as it was.
#[test]
fn a_failed_load_history_surfaces_a_notice_on_the_matching_open_chat() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Chat(state) => assert!(state.notice.is_none()),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }

    let leftover = app.update(AppEvent::Worker(Box::new(failed_load_history(
        bob_pubkey,
        "disk read failed",
    ))));
    assert!(leftover.is_empty());
    match app.current_screen() {
        Screen::Chat(state) => {
            assert!(
                state.entries.is_empty(),
                "a failed load must not fabricate or lose any transcript entries"
            );
            let notice = state
                .notice
                .as_deref()
                .expect("a failure notice must be shown on the matching open chat");
            assert!(
                notice.contains("disk read failed"),
                "expected the worker's own failure message to appear in the notice, got: {notice}"
            );
        }
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

/// The same failed completion arriving after the matching `Screen::Chat` has already been popped
/// (e.g. a slow failing load racing a quick `Esc`) must be a safe no-op — not a panic, not a
/// misdirected write onto whatever screen is current now.
#[test]
fn a_failed_load_history_for_an_already_popped_chat_is_a_safe_no_op() {
    let (mut app, _own, bob_pubkey) = app_with_main();
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    app.update(AppEvent::Key(key(KeyCode::Esc)));
    assert!(matches!(app.current_screen(), Screen::Main(_)));

    let leftover = app.update(AppEvent::Worker(Box::new(failed_load_history(
        bob_pubkey,
        "disk read failed",
    ))));
    assert!(leftover.is_empty());
    assert!(matches!(app.current_screen(), Screen::Main(_)));
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
// Task 4.42 (piece C): a completed Effect::AcceptRequest is reconciled into the live Screen::Main
// that sits *below* Screen::Requests on the stack — the in-memory half of the fix for 4.41's
// Defect C, isolated here against this file's own fabricated `LiveSession` (the end-to-end version,
// driven by the real worker against real sealed files, lives in `tests/accept_to_chat.rs`).
// ---------------------------------------------------------------------------

#[test]
fn a_completed_accept_request_is_replayed_into_the_main_screen_underneath_requests() {
    let (_own, _bob, mut session) = session_with_bob();
    let sender_ik = establish_pending_request(&mut session.chat);

    let mut app = App::new();
    push_main(&mut app, MainState::from_session(session));
    app.update(AppEvent::Key(ctrl(KeyCode::Char('r'))));
    assert!(matches!(app.current_screen(), Screen::Requests(_)));

    // The worker's own completion payload for a genuine first-contact accept: an empty id/hint
    // (`MessageRequest` carries no hint, so `Contact::id_string()` cannot succeed) and a plain TOFU
    // pin. `Screen::Requests` is on top; `Screen::Main` is underneath, and is what must be updated.
    let added = meridian_tui::app::AddedContact {
        pubkey: sender_ik,
        id: String::new(),
        hint: String::new(),
        petname: None,
        added_at: 1_760_000_000,
        trust: TrustState::Pinned,
        user_blocked: false,
        pinned_key_history: vec![meridian_core::trust::PinnedKey {
            pubkey: sender_ik,
            first_seen_unix: 1_760_000_000,
            last_seen_unix: 1_760_000_000,
        }],
    };
    // Enter `Deciding` for this sender first, so the Requests screen itself reacts realistically.
    app.update(AppEvent::Key(key(KeyCode::Char('a'))));
    let effects = app.update(AppEvent::Key(key(KeyCode::Char('y'))));
    assert_eq!(effects.len(), 1);
    let request = match effects.into_iter().next().unwrap() {
        meridian_tui::app::Effect::AcceptRequest(e) => e.request,
        other => panic!("expected Effect::AcceptRequest, got {other:?}"),
    };
    app.update(AppEvent::Worker(Box::new(
        meridian_tui::app::WorkerEvent::Completed(meridian_tui::app::Effect::AcceptRequest(
            meridian_tui::app::AcceptRequestEffect {
                request,
                outcome: Some(added),
            },
        )),
    )));

    app.update(AppEvent::Key(key(KeyCode::Esc)));
    match app.current_screen() {
        Screen::Main(main) => {
            // 1. the display row (previously only `bob`)
            assert_eq!(main.contacts.entries.len(), 2);
            let entry = main
                .contacts
                .entries
                .iter()
                .find(|e| e.pubkey == sender_ik)
                .expect("the accepted sender must be reachable from the live contacts list");
            assert_eq!(entry.trust, TrustState::Pinned);
            assert_eq!(entry.id, "");
            // 2. the live TrustStore — without this, `v` -> Verify -> mark_verified would err
            //    `UnknownContact` against a store that never heard of this sender.
            assert_eq!(main.trust.trust_state(&sender_ik), TrustState::Pinned);
            assert_eq!(
                main.trust
                    .contact(&sender_ik)
                    .expect("pinned contact")
                    .pinned_key_history
                    .len(),
                1,
                "replayed with the worker-supplied timestamp — one entry, not a second stamp"
            );
            // 3. the live ChatState's pending queue
            assert!(
                main.chat.pending_request(&sender_ik).is_none(),
                "the accepted request must be gone from Screen::Main's own in-memory queue too"
            );
        }
        other => panic!("expected Screen::Main, got {other:?}"),
    }

    // ...and therefore does not re-appear on the next Ctrl-R.
    app.update(AppEvent::Key(ctrl(KeyCode::Char('r'))));
    match app.current_screen() {
        Screen::Requests(state) => assert!(state.entries.is_empty()),
        other => panic!("expected Screen::Requests, got {other:?}"),
    }
}

/// The same completion arriving with **no** `Screen::Main` anywhere on the stack (a `Screen::
/// Requests` pushed standalone, as several tests in this crate do) must be a harmless no-op, not a
/// panic — mirrors `App::reclaim_trust`'s own "nothing to give it back to" contract.
#[test]
fn a_completed_accept_request_with_no_main_screen_on_the_stack_is_a_no_op() {
    let mut app = App::new();
    app.push_screen(Screen::Requests(Box::new(
        meridian_tui::screens::requests::RequestsState::new(Vec::new()),
    )));
    let added = meridian_tui::app::AddedContact {
        pubkey: [0x77u8; 32],
        id: String::new(),
        hint: String::new(),
        petname: None,
        added_at: 1_760_000_000,
        trust: TrustState::Pinned,
        user_blocked: false,
        pinned_key_history: Vec::new(),
    };
    let effects = app.update(AppEvent::Worker(Box::new(
        meridian_tui::app::WorkerEvent::Completed(meridian_tui::app::Effect::AcceptRequest(
            meridian_tui::app::AcceptRequestEffect {
                request: meridian_tui::app::AcceptRequestRequest {
                    sender_ik: [0x77u8; 32],
                },
                outcome: Some(added),
            },
        )),
    )));
    assert!(effects.is_empty());
    assert!(matches!(app.current_screen(), Screen::Requests(_)));
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
