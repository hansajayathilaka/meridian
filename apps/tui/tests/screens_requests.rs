//! `meridian_tui::screens::requests` — task 4.21's own test target
//! (`cargo nextest run -p meridian-tui --test screens_requests`).
//!
//! State-machine coverage (list navigation, confirm-then-decide for both accept and reject, worker
//! completion/failure), screen-snapshot tests at 80x24 and the narrow 40x24 established by every
//! prior screen's test file, and this task's own named security-relevant deliverable: a dedicated
//! test asserting reject leaves no trace, mirroring
//! `apps/core/tests/message_request_gate.rs::
//! reject_produces_no_wire_signal_and_no_distinguishing_local_trace` at the UI layer.
//!
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`handle_worker`, exactly like `screens_contacts.rs`/`screens_chat.rs` do.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::envelope::ChatContent;

use meridian_tui::app::{
    AcceptRequestEffect, AcceptRequestRequest, AddedContact, Effect, RejectRequestEffect,
    RejectRequestRequest, WorkerEvent,
};
use meridian_tui::screens::requests::{self, Decision, RequestEntry, RequestsMode, RequestsState};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// A [`RequestEntry`] fixture, keyed by `tag` (so distinct tags never collide).
fn entry(tag: u8, body: &str) -> RequestEntry {
    RequestEntry {
        sender_ik: [tag; 32],
        safety_number: "1".repeat(60),
        intro: ChatContent::Text {
            id: [tag; 16],
            body: body.to_string(),
        },
    }
}

/// The [`AddedContact`] a real, completed `Effect::AcceptRequest` carries back since task 4.42 —
/// exactly the shape `worker::run_accept_request` produces for a genuine first-contact sender: an
/// empty `id`/`hint` (`MessageRequest` carries no hint, so `Contact::id_string()` cannot succeed —
/// see that function's own doc comment) and a plain TOFU `Pinned` state, never `Verified`.
///
/// This screen deliberately ignores the outcome — its own contract is unchanged, and the tests below
/// that feed one in are asserting exactly that (the reconcile into `Screen::Main` is
/// `App::apply_accepted_request`'s job, covered in `tests/accept_to_chat.rs`).
fn accepted(tag: u8) -> AddedContact {
    AddedContact {
        pubkey: [tag; 32],
        id: String::new(),
        hint: String::new(),
        petname: None,
        added_at: 1_760_000_000,
        trust: meridian_core::trust::TrustState::Pinned,
        user_blocked: false,
        pinned_key_history: vec![meridian_core::trust::PinnedKey {
            pubkey: [tag; 32],
            first_seen_unix: 1_760_000_000,
            last_seen_unix: 1_760_000_000,
        }],
    }
}

fn render_requests_to_text(state: &RequestsState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| requests::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

// ---------------------------------------------------------------------------
// New state basics
// ---------------------------------------------------------------------------

#[test]
fn new_state_starts_in_list_mode_at_index_zero() {
    let state = RequestsState::new(vec![entry(1, "hi")]);
    assert!(matches!(state.mode, RequestsMode::List));
    assert_eq!(state.selected, 0);
    assert_eq!(state.entries.len(), 1);
}

#[test]
fn request_entry_from_core_message_request_copies_all_three_exposed_fields() {
    use meridian_core::chat::MessageRequest;
    let req = MessageRequest {
        sender_ik: [9u8; 32],
        safety_number: "42".to_string(),
        intro: ChatContent::Text {
            id: [9u8; 16],
            body: "hello".to_string(),
        },
    };
    let converted = RequestEntry::from(&req);
    assert_eq!(converted.sender_ik, req.sender_ik);
    assert_eq!(converted.safety_number, req.safety_number);
    assert_eq!(converted.intro, req.intro);
}

// ---------------------------------------------------------------------------
// List navigation
// ---------------------------------------------------------------------------

#[test]
fn up_down_move_the_selection_and_clamp_at_the_ends() {
    let mut state = RequestsState::new(vec![entry(1, "a"), entry(2, "b"), entry(3, "c")]);
    requests::handle_key(&mut state, key(KeyCode::Down));
    assert_eq!(state.selected, 1);
    requests::handle_key(&mut state, key(KeyCode::Down));
    assert_eq!(state.selected, 2);
    // Clamped at the last entry.
    requests::handle_key(&mut state, key(KeyCode::Down));
    assert_eq!(state.selected, 2);
    requests::handle_key(&mut state, key(KeyCode::Up));
    assert_eq!(state.selected, 1);
    // jk work identically to the arrow keys.
    requests::handle_key(&mut state, char_key('k'));
    assert_eq!(state.selected, 0);
    requests::handle_key(&mut state, char_key('k'));
    assert_eq!(state.selected, 0);
}

#[test]
fn esc_in_list_mode_asks_the_caller_to_pop() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    let (effects, exit) = requests::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(exit);
}

#[test]
fn accept_or_reject_on_an_empty_queue_is_a_no_op() {
    let mut state = RequestsState::new(Vec::new());
    let (effects, exit) = requests::handle_key(&mut state, char_key('a'));
    assert!(effects.is_empty());
    assert!(!exit);
    assert!(matches!(state.mode, RequestsMode::List));
    let (effects, exit) = requests::handle_key(&mut state, char_key('r'));
    assert!(effects.is_empty());
    assert!(!exit);
    assert!(matches!(state.mode, RequestsMode::List));
}

// ---------------------------------------------------------------------------
// Accept flow
// ---------------------------------------------------------------------------

#[test]
fn a_enters_confirm_accept_for_the_selected_entry() {
    let mut state = RequestsState::new(vec![entry(1, "a"), entry(2, "b")]);
    requests::handle_key(&mut state, key(KeyCode::Down));
    requests::handle_key(&mut state, char_key('a'));
    match &state.mode {
        RequestsMode::Confirm {
            sender_ik,
            decision,
        } => {
            assert_eq!(*sender_ik, [2u8; 32]);
            assert_eq!(*decision, Decision::Accept);
        }
        other => panic!("expected Confirm, got {other:?}"),
    }
}

#[test]
fn confirm_accept_n_or_esc_cancels_back_to_list_without_dispatching() {
    for cancel in [char_key('n'), char_key('N'), key(KeyCode::Esc)] {
        let mut state = RequestsState::new(vec![entry(1, "a")]);
        requests::handle_key(&mut state, char_key('a'));
        let (effects, exit) = requests::handle_key(&mut state, cancel);
        assert!(effects.is_empty());
        assert!(!exit);
        assert!(matches!(state.mode, RequestsMode::List));
        assert_eq!(
            state.entries.len(),
            1,
            "cancelling must not remove anything"
        );
    }
}

#[test]
fn confirm_accept_y_dispatches_effect_accept_request_and_enters_deciding() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('a'));
    let (effects, exit) = requests::handle_key(&mut state, char_key('y'));
    assert!(!exit);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::AcceptRequest(AcceptRequestEffect { request, outcome }) => {
            assert_eq!(request.sender_ik, [1u8; 32]);
            assert!(outcome.is_none());
        }
        other => panic!("expected Effect::AcceptRequest, got {other:?}"),
    }
    assert!(matches!(state.mode, RequestsMode::Deciding { .. }));
    // No input is accepted while deciding — mirrors every other in-flight sub-mode in this crate.
    let (effects, exit) = requests::handle_key(&mut state, char_key('y'));
    assert!(effects.is_empty());
    assert!(!exit);
    assert_eq!(
        state.entries.len(),
        1,
        "still present until the effect completes"
    );
}

#[test]
fn accept_completion_removes_the_entry_and_returns_to_list() {
    let mut state = RequestsState::new(vec![entry(1, "a"), entry(2, "b")]);
    requests::handle_key(&mut state, char_key('a'));
    let (effects, _) = requests::handle_key(&mut state, char_key('y'));
    let effect = effects.into_iter().next().unwrap();

    let more = requests::handle_worker(&mut state, WorkerEvent::Completed(effect));
    assert!(more.is_empty());
    assert!(matches!(state.mode, RequestsMode::List));
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.entries[0].sender_ik, [2u8; 32]);
}

#[test]
fn accept_failure_shows_an_error_and_leaves_the_entry_in_place() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('a'));
    let (effects, _) = requests::handle_key(&mut state, char_key('y'));
    let effect = effects.into_iter().next().unwrap();

    requests::handle_worker(
        &mut state,
        WorkerEvent::Failed(effect, "disk full".to_string()),
    );
    match &state.mode {
        RequestsMode::Error(message) => assert_eq!(message, "disk full"),
        other => panic!("expected Error, got {other:?}"),
    }
    assert_eq!(
        state.entries.len(),
        1,
        "a failed accept must not drop the request"
    );

    // Enter/Esc return to the list without touching entries.
    requests::handle_key(&mut state, key(KeyCode::Enter));
    assert!(matches!(state.mode, RequestsMode::List));
    assert_eq!(state.entries.len(), 1);
}

// ---------------------------------------------------------------------------
// Reject flow, and the "leaves no trace" property (this task's named deliverable)
// ---------------------------------------------------------------------------

#[test]
fn r_enters_confirm_reject_for_the_selected_entry() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('r'));
    match &state.mode {
        RequestsMode::Confirm {
            sender_ik,
            decision,
        } => {
            assert_eq!(*sender_ik, [1u8; 32]);
            assert_eq!(*decision, Decision::Reject);
        }
        other => panic!("expected Confirm, got {other:?}"),
    }
}

#[test]
fn confirm_reject_y_dispatches_effect_reject_request() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('r'));
    let (effects, _) = requests::handle_key(&mut state, char_key('y'));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::RejectRequest(RejectRequestEffect { request, outcome }) => {
            assert_eq!(request.sender_ik, [1u8; 32]);
            assert!(outcome.is_none());
        }
        other => panic!("expected Effect::RejectRequest, got {other:?}"),
    }
}

/// This task's own named deliverable: after rejecting a request, this screen's state for that
/// sender must be indistinguishable from a sender that was never in the queue at all — mirrors
/// `apps/core/tests/message_request_gate.rs::
/// reject_produces_no_wire_signal_and_no_distinguishing_local_trace`'s exact comparison at the core
/// level, replicated here at the UI layer.
#[test]
fn reject_leaves_no_trace_indistinguishable_from_a_sender_never_queued_at_all() {
    let rejected_sender = [0x42u8; 32];
    let mut state = RequestsState::new(vec![RequestEntry {
        sender_ik: rejected_sender,
        safety_number: "9".repeat(60),
        intro: ChatContent::Text {
            id: [0x42u8; 16],
            body: "a real, now-discarded request".to_string(),
        },
    }]);

    requests::handle_key(&mut state, char_key('r'));
    let (effects, _) = requests::handle_key(&mut state, char_key('y'));
    let effect = effects.into_iter().next().unwrap();
    requests::handle_worker(&mut state, WorkerEvent::Completed(effect));

    // A screen that never saw this sender at all (the "stranger" baseline, exactly mirroring the
    // core test's `stranger_ik`).
    let never_queued = RequestsState::new(Vec::new());

    // No leftover entry for the rejected sender — same as the stranger case.
    assert!(state.entries.iter().all(|e| e.sender_ik != rejected_sender));
    assert_eq!(
        state.entries.len(),
        never_queued.entries.len(),
        "post-rejection, the entries list must be exactly as empty as it would be for a sender \
         who was never queued — no tombstone, no leftover 'rejected' row"
    );
    assert!(
        matches!(state.mode, RequestsMode::List),
        "no lingering Confirm/Deciding/Error sub-mode naming the rejected sender"
    );

    // The full observable shape (mode + entries) is identical between the two — the exact property
    // the core-level test pins one layer down.
    assert!(matches!(never_queued.mode, RequestsMode::List));
    assert_eq!(state.entries, never_queued.entries);

    // The detail panel, which is the one place a sender's key/safety-number/intro would ever be
    // rendered, now shows the same "nothing pending" copy for both — never a residual "declined"
    // notice mentioning this specific sender.
    let rejected_view = render_requests_to_text(&state, 80, 24);
    let never_queued_view = render_requests_to_text(&never_queued, 80, 24);
    assert_eq!(rejected_view, never_queued_view);
    assert!(!rejected_view.contains("42424242")); // no fragment of the rejected sender's key
}

#[test]
fn reject_failure_shows_an_error_and_leaves_the_entry_in_place() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('r'));
    let (effects, _) = requests::handle_key(&mut state, char_key('y'));
    let effect = effects.into_iter().next().unwrap();

    requests::handle_worker(
        &mut state,
        WorkerEvent::Failed(effect, "network error".to_string()),
    );
    match &state.mode {
        RequestsMode::Error(message) => assert_eq!(message, "network error"),
        other => panic!("expected Error, got {other:?}"),
    }
    assert_eq!(
        state.entries.len(),
        1,
        "a failed reject must not drop the request"
    );
}

// ---------------------------------------------------------------------------
// Worker events that don't match what's in flight are ignored, not a panic
// ---------------------------------------------------------------------------

#[test]
fn irrelevant_worker_event_in_list_mode_is_a_no_op() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    let effects = requests::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            request: AcceptRequestRequest {
                sender_ik: [1u8; 32],
            },
            outcome: Some(accepted(1)),
        })),
    );
    assert!(effects.is_empty());
    assert!(matches!(state.mode, RequestsMode::List));
    assert_eq!(state.entries.len(), 1);
}

#[test]
fn a_completion_for_the_wrong_decision_is_ignored() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('a'));
    requests::handle_key(&mut state, char_key('y'));
    // A reject-shaped completion arrives while an accept is in flight — must not be applied.
    let effects = requests::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::RejectRequest(RejectRequestEffect {
            request: RejectRequestRequest {
                sender_ik: [1u8; 32],
            },
            outcome: Some(()),
        })),
    );
    assert!(effects.is_empty());
    assert!(matches!(state.mode, RequestsMode::Deciding { .. }));
    assert_eq!(state.entries.len(), 1);
}

#[test]
fn a_completion_naming_a_different_sender_is_ignored_even_with_a_matching_effect_variant() {
    // Two queued requests. Start deciding (accept) on the *second* one (0xBB) — 0xAA stays
    // untouched in the queue, first in `entries`, unselected.
    let mut state = RequestsState::new(vec![entry(0xAA, "from aa"), entry(0xBB, "from bb")]);
    requests::handle_key(&mut state, key(KeyCode::Down));
    assert_eq!(state.selected, 1);
    requests::handle_key(&mut state, char_key('a'));
    requests::handle_key(&mut state, char_key('y'));
    assert!(matches!(
        state.mode,
        RequestsMode::Deciding {
            sender_ik: [0xBB, ..],
            decision: Decision::Accept,
        }
    ));

    // The *right* effect variant (AcceptRequest) and the *right* decision kind (Accept) arrive,
    // but naming 0xAA — a sender other than the one this screen is actually waiting on (0xBB).
    // This must be ignored exactly like a wrong-variant event: neither entry is removed, and the
    // screen stays in `Deciding` for 0xBB rather than silently treating 0xBB as decided.
    let effects = requests::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            request: AcceptRequestRequest {
                sender_ik: [0xAA; 32],
            },
            outcome: Some(accepted(0xAA)),
        })),
    );
    assert!(effects.is_empty());
    assert!(matches!(
        state.mode,
        RequestsMode::Deciding {
            sender_ik: [0xBB, ..],
            decision: Decision::Accept,
        }
    ));
    assert_eq!(state.entries.len(), 2);
    assert!(state.entries.iter().any(|e| e.sender_ik == [0xAA; 32]));
    assert!(state.entries.iter().any(|e| e.sender_ik == [0xBB; 32]));
}

// ---------------------------------------------------------------------------
// Screen-snapshot tests
// ---------------------------------------------------------------------------

#[test]
fn render_empty_queue_works_and_shows_the_empty_copy() {
    let state = RequestsState::new(Vec::new());
    let text = render_requests_to_text(&state, 80, 24);
    assert!(text.contains("Requests (0)"));
    assert!(text.contains("no pending requests"));
}

#[test]
fn render_populated_queue_shows_sender_safety_number_and_intro() {
    let state = RequestsState::new(vec![entry(0xab, "hi there, it's a stranger")]);
    let text = render_requests_to_text(&state, 80, 24);
    assert!(text.contains("Requests (1)"));
    assert!(text.contains("hi there, it's a stranger"));
    // The grouped safety number (spaces every 5 digits) appears somewhere in the detail panel.
    assert!(text.contains("11111"));
}

#[test]
fn render_confirm_and_deciding_and_error_modes_all_work_against_test_backend() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('a'));
    let confirm_text = render_requests_to_text(&state, 80, 24);
    assert!(confirm_text.contains("accept this request?"));

    let (effects, _) = requests::handle_key(&mut state, char_key('y'));
    let deciding_text = render_requests_to_text(&state, 80, 24);
    assert!(deciding_text.contains("please wait"));

    let effect = effects.into_iter().next().unwrap();
    requests::handle_worker(&mut state, WorkerEvent::Failed(effect, "boom".to_string()));
    let error_text = render_requests_to_text(&state, 80, 24);
    assert!(error_text.contains("boom"));
}

#[test]
fn render_reject_confirm_mentions_discarding_the_session() {
    let mut state = RequestsState::new(vec![entry(1, "a")]);
    requests::handle_key(&mut state, char_key('r'));
    let text = render_requests_to_text(&state, 80, 24);
    assert!(text.contains("discards the session"));
}

#[test]
fn render_at_the_narrow_40x24_terminal_works_too() {
    let state = RequestsState::new(vec![entry(1, "a"), entry(2, "b")]);
    let text = render_requests_to_text(&state, 40, 24);
    assert!(text.contains("Requests (2)"));
}
