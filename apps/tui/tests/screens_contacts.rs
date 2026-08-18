//! `meridian_tui::screens::contacts` + `meridian_tui::screens::contact_detail` — task 4.19's own
//! test target (`cargo nextest run -p meridian-tui --test screens_contacts`).
//!
//! State-machine coverage for both screens (add-contact's paste/QR-import/petname sub-steps,
//! filter/search, list navigation, and contact detail's petname/block/policy-override/delete),
//! screen-snapshot tests at 80x24 and the narrow 40x24 established by `screens_onboarding.rs`/
//! `screens_unlock.rs`, the petname-never-from-wire regression this screen must replicate from
//! `apps/cli/tests/contact_mgmt.rs`, and — this task's one named security-relevant deliverable —
//! a dedicated test asserting the key fingerprint renders alongside the petname wherever a spoofed
//! display name could mislead (tui-client.md §6 rule 2).
//!
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`handle_worker` the same way `screens_onboarding.rs`/`screens_unlock.rs` do,
//! simulating what a future worker's `WorkerEvent::Completed`/`Failed` would report.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::identity::to_id_string;
use meridian_core::trust::{PinnedKey, TrustState};

use meridian_tui::app::{
    AddContactEffect, AddedContact, DeleteContactEffect, DeleteContactRequest, Effect,
    ImportContactQrEffect, SetPetnameEffect, SetPetnameRequest, SetPolicyOverrideEffect,
    SetPolicyOverrideRequest, SetUserBlockedEffect, SetUserBlockedRequest, WorkerEvent,
};
use meridian_tui::screens::contact_detail::{self, ContactDetailState, DetailMode};
use meridian_tui::screens::contacts::{
    self, short_pubkey, AddContactState, ContactEntry, ContactsAction, ContactsState, EnterId,
    EnterIdFocus,
};
use meridian_tui::store::contacts::PolicyOverride;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn type_str(mut state: ContactsState, s: &str) -> ContactsState {
    for c in s.chars() {
        let _ = contacts::handle_key(&mut state, char_key(c));
    }
    state
}

/// A [`ContactEntry`] fixture, keyed by `tag` (so distinct tags never collide).
fn entry(tag: u8, petname: Option<&str>, trust: TrustState) -> ContactEntry {
    let pubkey = [tag; 32];
    ContactEntry {
        pubkey,
        id: format!("mrd1:contact-{tag:02x}@example.test"),
        hint: "example.test".into(),
        petname: petname.map(|p| p.to_string()),
        trust,
        user_blocked: false,
        pinned_key_history: vec![PinnedKey {
            pubkey,
            first_seen_unix: 1_000,
            last_seen_unix: 2_000,
        }],
        policy_override: None,
        added_at: 1_000,
        last_activity_at: 2_000,
        unread: 0,
    }
}

fn render_contacts_to_text(state: &ContactsState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| contacts::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

fn render_detail_to_text(state: &ContactDetailState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| contact_detail::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

// ---------------------------------------------------------------------------
// Contacts pane: list navigation + filter
// ---------------------------------------------------------------------------

#[test]
fn new_state_starts_on_an_empty_selection_with_no_filter_or_form_open() {
    let state = ContactsState::new(vec![entry(1, Some("alice"), TrustState::Pinned)]);
    assert_eq!(state.selected, 0);
    assert!(state.filter.is_empty());
    assert!(!state.filtering);
    assert!(state.add.is_none());
    assert!(state.notice.is_none());
}

#[test]
fn enter_with_no_contacts_does_nothing() {
    let mut state = ContactsState::new(Vec::new());
    let (effects, action) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(matches!(action, ContactsAction::None));
}

/// Task 4.36: `Enter` now opens `Screen::Chat`, repointed from the old task-4.19 stand-in that
/// opened Contact detail — see `ContactsAction::OpenChat`'s own doc comment.
#[test]
fn enter_on_a_contact_opens_chat_with_a_full_clone_of_the_entry() {
    let e = entry(1, Some("alice"), TrustState::Verified);
    let mut state = ContactsState::new(vec![e.clone()]);
    let (effects, action) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    match action {
        ContactsAction::OpenChat(opened) => {
            assert_eq!(opened.pubkey, e.pubkey);
            assert_eq!(opened.petname, e.petname);
            assert_eq!(opened.trust, e.trust);
        }
        other => panic!("expected OpenChat, got {other:?}"),
    }
}

/// Task 4.36: `i` ("info") is `Screen::ContactDetail`'s own new dedicated key, now that `Enter`
/// opens `Screen::Chat` instead.
#[test]
fn i_on_a_contact_opens_detail_with_a_full_clone_of_the_entry() {
    let e = entry(1, Some("alice"), TrustState::Verified);
    let mut state = ContactsState::new(vec![e.clone()]);
    let (effects, action) = contacts::handle_key(&mut state, char_key('i'));
    assert!(effects.is_empty());
    match action {
        ContactsAction::OpenDetail(opened) => {
            assert_eq!(opened.pubkey, e.pubkey);
            assert_eq!(opened.petname, e.petname);
            assert_eq!(opened.trust, e.trust);
        }
        other => panic!("expected OpenDetail, got {other:?}"),
    }
}

#[test]
fn esc_in_plain_list_mode_asks_the_caller_to_pop() {
    let mut state = ContactsState::new(vec![entry(1, None, TrustState::Pinned)]);
    let (effects, action) = contacts::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(matches!(action, ContactsAction::Pop));
}

#[test]
fn up_down_navigation_clamps_at_the_ends_without_wrapping() {
    let mut state = ContactsState::new(vec![
        entry(1, Some("alice"), TrustState::Pinned),
        entry(2, Some("bob"), TrustState::Pinned),
    ]);
    contacts::handle_key(&mut state, key(KeyCode::Down));
    assert_eq!(state.selected, 1);
    contacts::handle_key(&mut state, key(KeyCode::Down));
    assert_eq!(state.selected, 1, "must not wrap past the last entry");
    contacts::handle_key(&mut state, key(KeyCode::Up));
    assert_eq!(state.selected, 0);
    contacts::handle_key(&mut state, key(KeyCode::Up));
    assert_eq!(state.selected, 0, "must not wrap past the first entry");
}

#[test]
fn filter_matches_petname_hint_or_id_case_insensitively() {
    let mut state = ContactsState::new(vec![
        entry(1, Some("Alice"), TrustState::Pinned),
        entry(2, Some("Bob"), TrustState::Pinned),
    ]);
    contacts::handle_key(&mut state, char_key('/'));
    assert!(state.filtering);
    state = type_str(state, "ali");
    assert_eq!(state.filter, "ali");

    // Only "Alice" matches — confirmed by pressing Enter (opens chat) and checking which entry
    // came back, since the filtered *view* isn't itself a public field.
    contacts::handle_key(&mut state, key(KeyCode::Enter)); // closes the filter box
    assert!(!state.filtering);
    let (_, action) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    match action {
        ContactsAction::OpenChat(opened) => assert_eq!(opened.petname.as_deref(), Some("Alice")),
        other => panic!("expected OpenChat, got {other:?}"),
    }
}

#[test]
fn esc_while_filtering_never_destroys_the_typed_filter_text() {
    // tui-client.md §3: "Esc always means back and never destroys typed input."
    let mut state = ContactsState::new(vec![entry(1, Some("alice"), TrustState::Pinned)]);
    contacts::handle_key(&mut state, char_key('/'));
    state = type_str(state, "ali");
    contacts::handle_key(&mut state, key(KeyCode::Esc));
    assert!(!state.filtering);
    assert_eq!(state.filter, "ali", "Esc must not clear the filter text");
}

/// Task 4.36: `v` now routes to a real `Screen::Verify` (replacing task 4.19's own "not implemented
/// yet" stand-in notice) — see `ContactsAction::OpenVerify`'s own doc comment.
#[test]
fn v_on_a_contact_opens_verify_with_a_full_clone_of_the_entry() {
    let e = entry(1, Some("alice"), TrustState::Pinned);
    let mut state = ContactsState::new(vec![e.clone()]);
    let (effects, action) = contacts::handle_key(&mut state, char_key('v'));
    assert!(effects.is_empty());
    match action {
        ContactsAction::OpenVerify(opened) => {
            assert_eq!(opened.pubkey, e.pubkey);
            assert_eq!(opened.petname, e.petname);
        }
        other => panic!("expected OpenVerify, got {other:?}"),
    }
}

#[test]
fn v_with_no_contacts_does_nothing() {
    let mut state = ContactsState::new(Vec::new());
    let (effects, action) = contacts::handle_key(&mut state, char_key('v'));
    assert!(effects.is_empty());
    assert!(matches!(action, ContactsAction::None));
}

// ---------------------------------------------------------------------------
// Add-contact: paste an id
// ---------------------------------------------------------------------------

fn valid_id() -> String {
    to_id_string(&[7u8; 32], "org-b.test").unwrap()
}

#[test]
fn n_opens_the_add_contact_form_on_enter_id() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    assert!(matches!(state.add, Some(AddContactState::EnterId(_))));
}

#[test]
fn esc_at_enter_id_cancels_the_whole_add_contact_flow() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    assert!(state.add.is_some());
    contacts::handle_key(&mut state, key(KeyCode::Esc));
    assert!(state.add.is_none());
}

#[test]
fn pasting_an_invalid_id_shows_an_inline_error_and_stays_on_enter_id() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, "not-a-valid-id");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    match &state.add {
        Some(AddContactState::EnterId(e)) => assert!(e.error.is_some()),
        other => panic!("expected EnterId with an error, got {other:?}"),
    }
}

#[test]
fn pasting_a_valid_id_moves_to_enter_petname_with_no_effect_dispatched() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &valid_id());
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    // Parsing the id is pure — no I/O yet at this point (mirrors onboarding's validate_hint gate).
    assert!(effects.is_empty());
    match &state.add {
        Some(AddContactState::EnterPetname(p)) => {
            assert_eq!(p.pubkey, [7u8; 32]);
            assert_eq!(p.hint, "org-b.test");
            assert_eq!(p.id, valid_id());
            assert!(p.petname_input.is_empty());
        }
        other => panic!("expected EnterPetname, got {other:?}"),
    }
}

/// The petname-never-from-wire regression, replicated from `apps/cli/tests/contact_mgmt.rs`'s own
/// discipline: an id whose hint is crafted to look exactly like a petname must never end up
/// pre-filling (or, on submit with a blank field, becoming) this contact's petname.
#[test]
fn a_name_like_hint_never_becomes_the_petname() {
    let hostile_id = to_id_string(&[9u8; 32], "totallylegitalice.example").unwrap();
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &hostile_id);
    contacts::handle_key(&mut state, key(KeyCode::Enter));

    match &state.add {
        Some(AddContactState::EnterPetname(p)) => {
            assert!(
                p.petname_input.is_empty(),
                "the hostile hint must never pre-fill the petname field"
            );
        }
        other => panic!("expected EnterPetname, got {other:?}"),
    }

    // Submitting with the field left blank must produce a `None` petname, not anything derived
    // from `hint`/`id`.
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::AddContact(AddContactEffect { request, .. }) => {
            assert_eq!(request.hint, "totallylegitalice.example");
            assert_eq!(
                request.petname, None,
                "observe-equivalent path must never populate petname from the hint"
            );
        }
        other => panic!("expected Effect::AddContact, got {other:?}"),
    }
}

#[test]
fn enter_petname_esc_returns_to_enter_id_preserving_the_id_text() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &valid_id());
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    contacts::handle_key(&mut state, key(KeyCode::Esc));
    match &state.add {
        Some(AddContactState::EnterId(e)) => assert_eq!(e.id_input, valid_id()),
        other => panic!("expected EnterId, got {other:?}"),
    }
}

#[test]
fn typing_a_petname_and_submitting_dispatches_add_contact_with_it() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &valid_id());
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    state = type_str(state, "Bob (real friend)");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::AddContact(AddContactEffect { request, .. }) => {
            assert_eq!(request.pubkey, [7u8; 32]);
            assert_eq!(request.hint, "org-b.test");
            assert_eq!(request.petname.as_deref(), Some("Bob (real friend)"));
        }
        other => panic!("expected Effect::AddContact, got {other:?}"),
    }
    assert!(matches!(state.add, Some(AddContactState::Adding(_))));
}

#[test]
fn add_contact_completion_inserts_the_new_entry_and_closes_the_form() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &valid_id());
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    state = type_str(state, "Bob");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let effect = effects.into_iter().next().unwrap();
    let request = match effect {
        Effect::AddContact(AddContactEffect { request, .. }) => request,
        other => panic!("expected Effect::AddContact, got {other:?}"),
    };

    let added = AddedContact {
        pubkey: request.pubkey,
        id: request.id.clone(),
        hint: request.hint.clone(),
        petname: request.petname.clone(),
        added_at: 12_345,
        // A genuine first observation: this is exactly the shape a worker's real
        // `TrustStore::observe` call would report back for a pubkey it has never seen before.
        trust: TrustState::Pinned,
        user_blocked: false,
        pinned_key_history: vec![PinnedKey {
            pubkey: request.pubkey,
            first_seen_unix: 12_345,
            last_seen_unix: 12_345,
        }],
    };
    contacts::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            request,
            outcome: Some(added),
        })),
    );

    assert!(state.add.is_none());
    assert_eq!(state.entries.len(), 1);
    let inserted = &state.entries[0];
    assert_eq!(inserted.pubkey, [7u8; 32]);
    assert_eq!(inserted.petname.as_deref(), Some("Bob"));
    assert_eq!(inserted.trust, TrustState::Pinned);
    assert!(!inserted.user_blocked);
    assert_eq!(inserted.pinned_key_history.len(), 1);
    assert_eq!(inserted.pinned_key_history[0].first_seen_unix, 12_345);
    assert_eq!(inserted.added_at, 12_345);
}

// ---------------------------------------------------------------------------
// Review fix (task 4.19, Finding 1): `Effect::AddContact`'s completion path must never mis-display
// a pubkey `TrustStore` already knows about as a fabricated "freshly pinned" contact — see
// `AddedContact`'s doc comment in `meridian_tui::app` and `ContactEntry::from_added`'s.
// ---------------------------------------------------------------------------

/// Builds the [`AddedContact`] a real worker would report for a **repeat** observation of an
/// already-known pubkey at the given `trust`/`user_blocked`/history — i.e. exactly what
/// `TrustStore::observe` (plus, for `petname`, a conditional `set_petname`) actually produces when
/// the contact isn't new, not the "must be fresh" shape a naive implementation might assume.
fn repeat_observation_added(
    pubkey: [u8; 32],
    trust: TrustState,
    user_blocked: bool,
    petname: Option<&str>,
) -> AddedContact {
    let id = to_id_string(&pubkey, "example.test").unwrap();
    AddedContact {
        pubkey,
        id: id.clone(),
        hint: "example.test".into(),
        petname: petname.map(|p| p.to_string()),
        added_at: 5_000,
        trust,
        user_blocked,
        // A real repeat observation's history has more than the single fresh entry a first
        // observation would — e.g. an original pin plus a later key change.
        pinned_key_history: vec![
            PinnedKey {
                pubkey,
                first_seen_unix: 1_000,
                last_seen_unix: 1_000,
            },
            PinnedKey {
                pubkey,
                first_seen_unix: 4_000,
                last_seen_unix: 5_000,
            },
        ],
    }
}

/// Drives an add-contact flow (paste path) all the way to a completed [`Effect::AddContact`],
/// applying `added` as the worker's outcome, and returns the resulting entry.
fn complete_add_contact(id: &str, added: AddedContact) -> ContactEntry {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, id);
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let request = match effects.into_iter().next().unwrap() {
        Effect::AddContact(AddContactEffect { request, .. }) => request,
        other => panic!("expected Effect::AddContact, got {other:?}"),
    };
    contacts::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            request,
            outcome: Some(added),
        })),
    );
    state.entries.into_iter().next().expect("entry inserted")
}

#[test]
fn re_adding_a_verified_contact_displays_its_true_verified_state_not_a_fabricated_fresh_pin() {
    let pubkey = [0x11u8; 32];
    let id = to_id_string(&pubkey, "example.test").unwrap();
    let added = repeat_observation_added(pubkey, TrustState::Verified, false, Some("Alice"));
    let inserted = complete_add_contact(&id, added);
    assert_eq!(inserted.trust, TrustState::Verified);
    assert_eq!(
        inserted.pinned_key_history.len(),
        2,
        "real history must survive, not be replaced"
    );
}

#[test]
fn re_adding_a_blocked_contact_displays_its_true_blocked_state_not_a_fabricated_fresh_pin() {
    let pubkey = [0x22u8; 32];
    let id = to_id_string(&pubkey, "example.test").unwrap();
    let added = repeat_observation_added(pubkey, TrustState::Blocked, false, Some("Mallory?"));
    let inserted = complete_add_contact(&id, added);
    assert_eq!(
        inserted.trust,
        TrustState::Blocked,
        "a re-added contact that TrustStore has as Blocked (verified contact, key changed) must \
         never silently display as a fresh, harmless pin"
    );
    assert_eq!(inserted.pinned_key_history.len(), 2);
}

#[test]
fn re_adding_a_pinned_key_changed_contact_displays_its_true_warning_state() {
    let pubkey = [0x33u8; 32];
    let id = to_id_string(&pubkey, "example.test").unwrap();
    let added = repeat_observation_added(pubkey, TrustState::PinnedKeyChanged, false, None);
    let inserted = complete_add_contact(&id, added);
    assert_eq!(inserted.trust, TrustState::PinnedKeyChanged);
}

#[test]
fn re_adding_a_user_blocked_contact_preserves_the_local_block_flag() {
    let pubkey = [0x44u8; 32];
    let id = to_id_string(&pubkey, "example.test").unwrap();
    let added = repeat_observation_added(pubkey, TrustState::Pinned, true, None);
    let inserted = complete_add_contact(&id, added);
    assert!(
        inserted.user_blocked,
        "a real local block must survive a re-add, not silently reset to false"
    );
}

/// Finding 1, petname-clobbering half: a re-add with the add-contact form's petname field left
/// blank must not blank out an existing real petname — the effect outcome's `petname` must be
/// whatever the worker actually found on record (not a verbatim echo of the blank request field).
#[test]
fn re_adding_with_a_blank_petname_field_does_not_clobber_the_existing_real_petname() {
    let pubkey = [0x55u8; 32];
    let id = to_id_string(&pubkey, "example.test").unwrap();
    // The request's own petname is None (form left blank), but the worker's outcome reports the
    // real, already-set petname it found on `TrustStore`/`ContactRecord` — exactly what a real
    // worker must do per `AddedContact::petname`'s doc.
    let added = repeat_observation_added(pubkey, TrustState::Verified, false, Some("Real Name"));
    let inserted = complete_add_contact(&id, added);
    assert_eq!(
        inserted.petname.as_deref(),
        Some("Real Name"),
        "the outcome's real petname must win over a blank request field, not be clobbered"
    );
}

/// Finding 1, the add-contact-flow guard: pasting an id whose pubkey already matches a known
/// contact never re-runs the add flow at all — it routes straight to Contact detail for the
/// existing entry, so a re-add can never even reach a completion path that could display wrong.
#[test]
fn pasting_an_id_for_an_already_known_contact_opens_its_existing_detail_instead_of_re_adding() {
    let existing = entry(0x66, Some("Already Known"), TrustState::Blocked);
    let mut state = ContactsState::new(vec![existing.clone()]);
    contacts::handle_key(&mut state, char_key('n'));
    // The fixture's own `id` field is a display placeholder, not a real encoding of `pubkey` — use
    // the real encoder so `parse_id` actually recovers `existing.pubkey`.
    let id_str = to_id_string(&existing.pubkey, &existing.hint).unwrap();
    state = type_str(state, &id_str);
    let (effects, action) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "must never dispatch Effect::AddContact for an already-known pubkey"
    );
    assert!(state.add.is_none(), "the add-contact form must close");
    match action {
        ContactsAction::OpenDetail(opened) => {
            assert_eq!(opened.pubkey, existing.pubkey);
            assert_eq!(opened.trust, TrustState::Blocked);
        }
        other => panic!("expected OpenDetail for the existing entry, got {other:?}"),
    }
}

/// Same guard, QR-import side — the pubkey only becomes known after
/// [`Effect::ImportContactQr`] completes, so the check has to happen there instead.
#[test]
fn qr_import_of_an_already_known_contact_opens_its_existing_detail_instead_of_re_adding() {
    let existing = entry(
        0x77,
        Some("Already Known (QR)"),
        TrustState::PinnedKeyChanged,
    );
    let mut state = ContactsState::new(vec![existing.clone()]);
    contacts::handle_key(&mut state, char_key('n'));
    contacts::handle_key(&mut state, key(KeyCode::Tab));
    state = type_str(state, "/tmp/contact.png");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let request = match effects.into_iter().next().unwrap() {
        Effect::ImportContactQr(ImportContactQrEffect { request, .. }) => request,
        other => panic!("expected Effect::ImportContactQr, got {other:?}"),
    };

    // Same real-encoding caveat as the paste-path test above.
    let id_str = to_id_string(&existing.pubkey, &existing.hint).unwrap();
    let (effects, action) = contacts::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::ImportContactQr(ImportContactQrEffect {
            request,
            outcome: Some(id_str),
        })),
    );
    assert!(effects.is_empty());
    assert!(state.add.is_none(), "the add-contact form must close");
    match action {
        ContactsAction::OpenDetail(opened) => {
            assert_eq!(opened.pubkey, existing.pubkey);
            assert_eq!(opened.trust, TrustState::PinnedKeyChanged);
        }
        other => panic!("expected OpenDetail for the existing entry, got {other:?}"),
    }
}

#[test]
fn add_contact_failure_shows_an_error_with_a_working_back() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &valid_id());
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let effect = effects.into_iter().next().unwrap();
    contacts::handle_worker(
        &mut state,
        WorkerEvent::Failed(effect, "network unreachable".into()),
    );
    match &state.add {
        Some(AddContactState::Error(err)) => assert_eq!(err.message, "network unreachable"),
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(state.entries.is_empty());

    // Enter/Esc goes back to a fresh EnterId.
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert!(matches!(state.add, Some(AddContactState::EnterId(_))));
}

// ---------------------------------------------------------------------------
// Add-contact: import via QR
// ---------------------------------------------------------------------------

#[test]
fn qr_path_field_dispatches_import_effect_and_moves_to_importing() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    contacts::handle_key(&mut state, key(KeyCode::Tab));
    match &state.add {
        Some(AddContactState::EnterId(e)) => assert_eq!(e.focus, EnterIdFocus::QrPath),
        other => panic!("expected EnterId focused on QrPath, got {other:?}"),
    }
    state = type_str(state, "/tmp/contact.png");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::ImportContactQr(ImportContactQrEffect { request, .. }) => {
            assert_eq!(request.path, PathBuf::from("/tmp/contact.png"));
        }
        other => panic!("expected Effect::ImportContactQr, got {other:?}"),
    }
    assert!(matches!(state.add, Some(AddContactState::ImportingQr(_))));
}

#[test]
fn qr_import_completion_with_a_valid_id_moves_to_enter_petname() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    contacts::handle_key(&mut state, key(KeyCode::Tab));
    state = type_str(state, "/tmp/contact.png");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let effect = effects.into_iter().next().unwrap();
    let request = match effect {
        Effect::ImportContactQr(ImportContactQrEffect { request, .. }) => request,
        other => panic!("expected Effect::ImportContactQr, got {other:?}"),
    };

    contacts::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::ImportContactQr(ImportContactQrEffect {
            request,
            outcome: Some(valid_id()),
        })),
    );
    match &state.add {
        Some(AddContactState::EnterPetname(p)) => {
            assert_eq!(p.pubkey, [7u8; 32]);
            assert!(
                p.petname_input.is_empty(),
                "QR must never pre-fill a petname"
            );
        }
        other => panic!("expected EnterPetname, got {other:?}"),
    }
}

#[test]
fn qr_import_completion_with_garbage_content_shows_an_error() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    contacts::handle_key(&mut state, key(KeyCode::Tab));
    state = type_str(state, "/tmp/contact.png");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let effect = effects.into_iter().next().unwrap();
    let request = match effect {
        Effect::ImportContactQr(ImportContactQrEffect { request, .. }) => request,
        other => panic!("expected Effect::ImportContactQr, got {other:?}"),
    };

    contacts::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::ImportContactQr(ImportContactQrEffect {
            request,
            outcome: Some("not an mrd1 id at all".into()),
        })),
    );
    assert!(matches!(state.add, Some(AddContactState::Error(_))));
}

#[test]
fn qr_import_failure_shows_an_error() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    contacts::handle_key(&mut state, key(KeyCode::Tab));
    state = type_str(state, "/tmp/missing.png");
    let (effects, _) = contacts::handle_key(&mut state, key(KeyCode::Enter));
    let effect = effects.into_iter().next().unwrap();
    contacts::handle_worker(
        &mut state,
        WorkerEvent::Failed(effect, "no such file or directory".into()),
    );
    match &state.add {
        Some(AddContactState::Error(err)) => assert_eq!(err.message, "no such file or directory"),
        other => panic!("expected Error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// apply_update
// ---------------------------------------------------------------------------

#[test]
fn apply_update_upserts_by_pubkey() {
    let mut state = ContactsState::new(vec![entry(1, Some("alice"), TrustState::Pinned)]);
    let mut updated = entry(1, Some("alice-renamed"), TrustState::Verified);
    updated.unread = 3;
    contacts::apply_update(&mut state, updated, false);
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.entries[0].petname.as_deref(), Some("alice-renamed"));
    assert_eq!(state.entries[0].trust, TrustState::Verified);
}

#[test]
fn apply_update_inserts_when_not_already_present() {
    let mut state = ContactsState::new(Vec::new());
    contacts::apply_update(
        &mut state,
        entry(1, Some("alice"), TrustState::Pinned),
        false,
    );
    assert_eq!(state.entries.len(), 1);
}

#[test]
fn apply_update_removes_on_delete() {
    let mut state = ContactsState::new(vec![
        entry(1, Some("alice"), TrustState::Pinned),
        entry(2, Some("bob"), TrustState::Pinned),
    ]);
    contacts::apply_update(
        &mut state,
        entry(1, Some("alice"), TrustState::Pinned),
        true,
    );
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.entries[0].pubkey, [2u8; 32]);
}

// ---------------------------------------------------------------------------
// Contacts pane: screen snapshots at 80x24 and a narrow 40x24
// ---------------------------------------------------------------------------

#[test]
fn snapshot_empty_contacts_list() {
    let state = ContactsState::new(Vec::new());
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_contacts_to_text(&state, w, h);
        assert!(text.contains("Contacts"));
        assert!(text.contains("no contacts"));
    }
}

#[test]
fn snapshot_add_contact_enter_id() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_contacts_to_text(&state, w, h);
        assert!(text.contains("Add a contact"));
        assert!(text.contains("mrd1"));
    }
}

#[test]
fn snapshot_add_contact_enter_petname_shows_fingerprint() {
    let mut state = ContactsState::new(Vec::new());
    contacts::handle_key(&mut state, char_key('n'));
    state = type_str(state, &valid_id());
    contacts::handle_key(&mut state, key(KeyCode::Enter));
    let expected_fingerprint = short_pubkey(&[7u8; 32]);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_contacts_to_text(&state, w, h);
        assert!(text.contains("Petname"));
        assert!(text.contains(&expected_fingerprint));
    }
}

/// The task's dedicated security-relevant deliverable: the key fingerprint must render alongside
/// the petname wherever a spoofed display name could mislead (tui-client.md §6 rule 2).
#[test]
fn security_fingerprint_renders_alongside_petname_in_the_contacts_list() {
    let spoofed = entry(
        3,
        Some("Bank Support (Official, Trust Me)"),
        TrustState::Pinned,
    );
    let expected_fingerprint = short_pubkey(&spoofed.pubkey);
    let state = ContactsState::new(vec![spoofed]);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_contacts_to_text(&state, w, h);
        assert!(
            text.contains("Bank Support"),
            "expected the petname to render at {w}x{h}, got:\n{text}"
        );
        assert!(
            text.contains(&expected_fingerprint),
            "expected the fingerprint {expected_fingerprint:?} to render alongside the petname \
             at {w}x{h}, got:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Contact detail: state machine
// ---------------------------------------------------------------------------

fn detail_entry() -> ContactEntry {
    entry(5, Some("carol"), TrustState::PinnedKeyChanged)
}

#[test]
fn new_detail_state_starts_in_view_mode_not_deleted() {
    let state = ContactDetailState::new(detail_entry());
    assert!(matches!(state.mode, DetailMode::View));
    assert!(!state.deleted);
}

#[test]
fn esc_in_view_mode_signals_exit_to_the_caller() {
    let mut state = ContactDetailState::new(detail_entry());
    let (effects, exit) = contact_detail::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(exit);
}

#[test]
fn p_opens_edit_petname_prefilled_with_the_current_value() {
    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('p'));
    match &state.mode {
        DetailMode::EditPetname(e) => assert_eq!(e.input, "carol"),
        other => panic!("expected EditPetname, got {other:?}"),
    }
}

#[test]
fn edit_petname_esc_cancels_back_to_view_without_exiting_the_screen() {
    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('p'));
    let (effects, exit) = contact_detail::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!exit);
    assert!(matches!(state.mode, DetailMode::View));
}

#[test]
fn edit_petname_submit_dispatches_set_petname_with_only_the_typed_value() {
    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('p'));
    // Clear the pre-filled value first, then type a fresh one — proving the submitted value is
    // exactly what was typed, not silently derived from `entry.id`/`entry.hint`.
    for _ in 0..5 {
        contact_detail::handle_key(&mut state, key(KeyCode::Backspace));
    }
    for c in "Carol (verified friend)".chars() {
        contact_detail::handle_key(&mut state, char_key(c));
    }
    let (effects, exit) = contact_detail::handle_key(&mut state, key(KeyCode::Enter));
    assert!(!exit);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::SetPetname(SetPetnameEffect { request, .. }) => {
            assert_eq!(request.pubkey, state.entry.pubkey);
            assert_eq!(request.petname.as_deref(), Some("Carol (verified friend)"));
        }
        other => panic!("expected Effect::SetPetname, got {other:?}"),
    }
    assert!(matches!(state.mode, DetailMode::SavingPetname(_)));
}

#[test]
fn set_petname_completion_updates_the_entry_and_returns_to_view() {
    let mut state = ContactDetailState::new(detail_entry());
    let pubkey = state.entry.pubkey;
    state.mode = DetailMode::SavingPetname(Some("Carol V.".into()));
    let (effects, exit) = contact_detail::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SetPetname(SetPetnameEffect {
            request: SetPetnameRequest {
                pubkey,
                petname: Some("Carol V.".into()),
            },
            outcome: Some(()),
        })),
    );
    assert!(effects.is_empty());
    assert!(!exit);
    assert_eq!(state.entry.petname.as_deref(), Some("Carol V."));
    assert!(matches!(state.mode, DetailMode::View));
}

#[test]
fn set_petname_failure_shows_an_error() {
    let mut state = ContactDetailState::new(detail_entry());
    let pubkey = state.entry.pubkey;
    state.mode = DetailMode::SavingPetname(Some("Carol V.".into()));
    let (_, exit) = contact_detail::handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::SetPetname(SetPetnameEffect {
                request: SetPetnameRequest {
                    pubkey,
                    petname: Some("Carol V.".into()),
                },
                outcome: None,
            }),
            "disk full".into(),
        ),
    );
    assert!(!exit);
    match &state.mode {
        DetailMode::Error(message) => assert_eq!(message, "disk full"),
        other => panic!("expected Error, got {other:?}"),
    }
    // The entry itself is left untouched on failure.
    assert_eq!(state.entry.petname.as_deref(), Some("carol"));
}

#[test]
fn block_confirm_flow_toggles_user_blocked() {
    let mut state = ContactDetailState::new(detail_entry());
    assert!(!state.entry.user_blocked);

    contact_detail::handle_key(&mut state, char_key('b'));
    assert!(matches!(state.mode, DetailMode::ConfirmBlock));

    // 'n' cancels without dispatching anything.
    let (effects, _) = contact_detail::handle_key(&mut state, char_key('n'));
    assert!(effects.is_empty());
    assert!(matches!(state.mode, DetailMode::View));

    contact_detail::handle_key(&mut state, char_key('b'));
    let (effects, _) = contact_detail::handle_key(&mut state, char_key('y'));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::SetUserBlocked(SetUserBlockedEffect { request, .. }) => {
            assert!(request.blocked, "first confirm should block");
        }
        other => panic!("expected Effect::SetUserBlocked, got {other:?}"),
    }
    let pubkey = state.entry.pubkey;
    contact_detail::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SetUserBlocked(SetUserBlockedEffect {
            request: SetUserBlockedRequest {
                pubkey,
                blocked: true,
            },
            outcome: Some(()),
        })),
    );
    assert!(state.entry.user_blocked);

    // Confirming again now unblocks.
    contact_detail::handle_key(&mut state, char_key('b'));
    let (effects, _) = contact_detail::handle_key(&mut state, char_key('y'));
    match &effects[0] {
        Effect::SetUserBlocked(SetUserBlockedEffect { request, .. }) => {
            assert!(!request.blocked, "second confirm should unblock");
        }
        other => panic!("expected Effect::SetUserBlocked, got {other:?}"),
    }
}

#[test]
fn delete_confirm_flow_sets_deleted_and_signals_exit_only_on_success() {
    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('d'));
    assert!(matches!(state.mode, DetailMode::ConfirmDelete));

    let (effects, exit) = contact_detail::handle_key(&mut state, char_key('y'));
    assert!(
        !exit,
        "confirming only dispatches the effect, doesn't exit yet"
    );
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], Effect::DeleteContact(_)));
    assert!(!state.deleted);

    let pubkey = state.entry.pubkey;
    let (effects, exit) = contact_detail::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::DeleteContact(DeleteContactEffect {
            request: DeleteContactRequest { pubkey },
            outcome: Some(()),
        })),
    );
    assert!(effects.is_empty());
    assert!(
        exit,
        "a successful delete must signal exit so the caller pops"
    );
    assert!(state.deleted);
}

#[test]
fn delete_failure_does_not_set_deleted_or_exit() {
    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('d'));
    contact_detail::handle_key(&mut state, char_key('y'));
    let pubkey = state.entry.pubkey;
    let (_, exit) = contact_detail::handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::DeleteContact(DeleteContactEffect {
                request: DeleteContactRequest { pubkey },
                outcome: None,
            }),
            "could not write contacts.json".into(),
        ),
    );
    assert!(!exit);
    assert!(!state.deleted);
    assert!(matches!(state.mode, DetailMode::Error(_)));
}

#[test]
fn o_cycles_relay_policy_override_through_all_four_states() {
    let mut state = ContactDetailState::new(detail_entry());
    assert_eq!(state.entry.policy_override, None);

    let expect_cycle = [
        Some(PolicyOverride::Direct),
        Some(PolicyOverride::PreferRelay),
        Some(PolicyOverride::RelayOnly),
        None,
    ];
    for expected in expect_cycle {
        let (effects, _) = contact_detail::handle_key(&mut state, char_key('o'));
        assert_eq!(effects.len(), 1);
        let dispatched = match &effects[0] {
            Effect::SetPolicyOverride(SetPolicyOverrideEffect { request, .. }) => {
                request.policy_override
            }
            other => panic!("expected Effect::SetPolicyOverride, got {other:?}"),
        };
        assert_eq!(dispatched, expected);
        let pubkey = state.entry.pubkey;
        contact_detail::handle_worker(
            &mut state,
            WorkerEvent::Completed(Effect::SetPolicyOverride(SetPolicyOverrideEffect {
                request: SetPolicyOverrideRequest {
                    pubkey,
                    policy_override: expected,
                },
                outcome: Some(()),
            })),
        );
        assert_eq!(state.entry.policy_override, expected);
    }
}

#[test]
fn irrelevant_worker_event_in_view_mode_is_a_no_op() {
    let mut state = ContactDetailState::new(detail_entry());
    let (effects, exit) =
        contact_detail::handle_worker(&mut state, WorkerEvent::Completed(Effect::FetchBundle));
    assert!(effects.is_empty());
    assert!(!exit);
    assert!(matches!(state.mode, DetailMode::View));
}

// ---------------------------------------------------------------------------
// Contact detail: screen snapshots
// ---------------------------------------------------------------------------

#[test]
fn snapshot_contact_detail_shows_trust_glyph_and_key_history() {
    let state = ContactDetailState::new(detail_entry());
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_detail_to_text(&state, w, h);
        assert!(text.contains("carol"));
        assert!(text.contains("key history"));
        assert!(text.contains("▲"));
    }
}

#[test]
fn snapshot_confirm_block_and_confirm_delete_prompts() {
    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('b'));
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_detail_to_text(&state, w, h);
        assert!(text.contains("block"));
        assert!(text.contains("y/n"));
    }

    let mut state = ContactDetailState::new(detail_entry());
    contact_detail::handle_key(&mut state, char_key('d'));
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_detail_to_text(&state, w, h);
        assert!(text.contains("y/n"));
        // Finding 2's fix: the prompt must disclose that trust state/key history survive a
        // "delete" and reappear if this contact is added again — not just say "delete".
        assert!(text.contains("local contact list"));
        assert!(text.contains("trust and key history are kept"));
    }
}

/// The dedicated security-relevant test, contact-detail side: the fingerprint renders directly
/// alongside the (freely user-editable) petname here too.
#[test]
fn security_fingerprint_renders_alongside_petname_in_contact_detail() {
    let spoofed = entry(6, Some("IT Helpdesk — Verify Now"), TrustState::Verified);
    let expected_fingerprint = short_pubkey(&spoofed.pubkey);
    let state = ContactDetailState::new(spoofed);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_detail_to_text(&state, w, h);
        assert!(text.contains("IT Helpdesk"));
        assert!(text.contains(&expected_fingerprint));
    }
}

#[test]
fn edit_id_default_focus_starts_on_id_field() {
    let e = EnterId::default();
    assert_eq!(e.focus, EnterIdFocus::Id);
    assert!(e.id_input.is_empty());
    assert!(e.qr_path_input.is_empty());
}
