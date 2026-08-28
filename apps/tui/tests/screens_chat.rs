//! `meridian_tui::screens::chat` — task 4.20's own test target
//! (`cargo nextest run -p meridian-tui --test screens_chat`).
//!
//! State-machine coverage (composer typing/newline/clear/recall, the send-gate wiring's three
//! branches, local dedup by `mid`, retry, scroll/focus), screen-snapshot tests at 80x24 and the
//! narrow 40x24 established by every prior screen's test file, and this task's two named
//! security-relevant deliverables:
//! - a dedicated test asserting a `Blocked` contact's composer refuses to enqueue a send (defense in
//!   depth alongside `apps/core/src/trust.rs`'s own `can_send`/gate tests — this one is UI-level);
//! - a dedicated test asserting no "delivered when they come online" language appears anywhere in
//!   this screen's failure copy.
//!
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`handle_worker`, exactly like `screens_contacts.rs`/`screens_onboarding.rs` do.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::trust::TrustStore;

use meridian_tui::app::{
    Effect, PersistHistoryEffect, SendMessageEffect, SendMessageRequest, SentMessage, WorkerEvent,
};
use meridian_tui::screens::chat::{
    self, offline_failure_copy, queued_notice_copy, send_error_copy, ChatFocus, ChatState,
    ComposerMode,
};
use meridian_tui::store::history::{Direction, HistoryEntry, MessageState};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn ctrl_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn type_str(state: &mut ChatState, s: &str) {
    for c in s.chars() {
        chat::handle_key(state, char_key(c));
    }
}

/// A pinned (TOFU), not-yet-verified contact — `SendGate::Ok`.
fn pinned_state(pubkey: [u8; 32]) -> ChatState {
    let mut trust = TrustStore::default();
    trust.observe(pubkey, "example.test", 1_000);
    ChatState::new(pubkey, "example.test".into(), trust, Vec::new(), 0)
}

/// A pinned contact whose key then changed — `SendGate::Warn`. The *current* pubkey (what the
/// screen is opened against) is the post-change one.
fn warn_state() -> ChatState {
    let old = [0x10u8; 32];
    let new = [0x11u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(old, "example.test", 1_000);
    trust
        .observe_key_change(&old, new, "example.test", 2_000)
        .unwrap();
    ChatState::new(new, "example.test".into(), trust, Vec::new(), 0)
}

/// A verified contact whose key then changed — `SendGate::Blocked` (key-change flavor).
fn blocked_state() -> ChatState {
    let old = [0x20u8; 32];
    let new = [0x21u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(old, "example.test", 1_000);
    trust.mark_verified(&old).unwrap();
    trust
        .observe_key_change(&old, new, "example.test", 2_000)
        .unwrap();
    ChatState::new(new, "example.test".into(), trust, Vec::new(), 0)
}

/// A pinned contact the user has locally blocked — `SendGate::Blocked` (user-block flavor).
fn user_blocked_state(pubkey: [u8; 32]) -> ChatState {
    let mut trust = TrustStore::default();
    trust.observe(pubkey, "example.test", 1_000);
    trust.set_user_blocked(&pubkey, true).unwrap();
    ChatState::new(pubkey, "example.test".into(), trust, Vec::new(), 0)
}

fn render_chat_to_text(state: &ChatState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| chat::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

fn out_entry(mid: &str, body: &str, state: MessageState) -> HistoryEntry {
    HistoryEntry {
        v: 1,
        mid: mid.to_string(),
        dir: Direction::Out,
        ts: 5_000,
        stream: "mrd.chat/1".to_string(),
        body: body.to_string(),
        state,
    }
}

// ---------------------------------------------------------------------------
// New state basics
// ---------------------------------------------------------------------------

#[test]
fn new_state_starts_empty_composer_composer_focus_normal_mode() {
    let state = pinned_state([1u8; 32]);
    assert!(state.composer.is_empty());
    assert_eq!(state.focus, ChatFocus::Composer);
    assert!(matches!(state.mode, ComposerMode::Normal));
    assert!(state.sending.is_none());
    assert!(state.entries.is_empty());
}

// ---------------------------------------------------------------------------
// Composer editing
// ---------------------------------------------------------------------------

#[test]
fn typing_appends_to_the_composer() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hello");
    assert_eq!(state.composer, "hello");
}

#[test]
fn backspace_removes_the_last_character() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hello");
    chat::handle_key(&mut state, key(KeyCode::Backspace));
    assert_eq!(state.composer, "hell");
}

#[test]
fn alt_enter_and_ctrl_j_insert_a_newline_instead_of_sending() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "line one");
    let (effects, _) =
        chat::handle_key(&mut state, KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
    assert!(effects.is_empty());
    type_str(&mut state, "line two");
    let (effects, _) = chat::handle_key(&mut state, ctrl_key('j'));
    assert!(effects.is_empty());
    type_str(&mut state, "line three");
    assert_eq!(state.composer, "line one\nline two\nline three");
}

#[test]
fn ctrl_u_clears_the_composer() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hello");
    chat::handle_key(&mut state, ctrl_key('u'));
    assert!(state.composer.is_empty());
}

#[test]
fn ctrl_w_deletes_the_last_word_only() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hello there world");
    chat::handle_key(&mut state, ctrl_key('w'));
    assert_eq!(state.composer, "hello there ");
}

#[test]
fn up_arrow_recalls_the_last_sent_message_only_when_composer_is_empty() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "first message");
    chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(state.composer.is_empty());
    assert_eq!(state.last_sent.as_deref(), Some("first message"));

    chat::handle_key(&mut state, key(KeyCode::Up));
    assert_eq!(state.composer, "first message");

    // Typing something first means Up must not clobber it.
    state.composer.clear();
    type_str(&mut state, "partial");
    chat::handle_key(&mut state, key(KeyCode::Up));
    assert_eq!(state.composer, "partial");
}

// ---------------------------------------------------------------------------
// Send-gate wiring — Ok
// ---------------------------------------------------------------------------

#[test]
fn enter_with_an_ok_gate_dispatches_send_message_and_clears_the_composer() {
    let pubkey = [1u8; 32];
    let mut state = pinned_state(pubkey);
    type_str(&mut state, "hey there");
    let (effects, exit) = chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(!exit);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::SendMessage(SendMessageEffect { request, outcome }) => {
            assert_eq!(request.peer_pubkey, pubkey);
            assert_eq!(request.body, "hey there");
            assert!(outcome.is_none());
        }
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    }
    assert!(state.composer.is_empty());
    assert_eq!(state.sending.as_deref(), Some("hey there"));
}

#[test]
fn empty_composer_dispatches_nothing_on_enter() {
    let mut state = pinned_state([1u8; 32]);
    let (effects, _) = chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
}

#[test]
fn a_second_enter_while_a_send_is_already_in_flight_is_a_no_op() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "first");
    chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(state.sending.is_some());

    type_str(&mut state, "second");
    let (effects, _) = chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "must not dispatch a second concurrent send"
    );
}

/// The bug this covers: the transcript used to stay empty (or stuck on "(no messages yet)") for the
/// *entire* `Effect::SendMessage` round trip — a message a user just sent was invisible until the
/// worker's completion event landed, seconds later on a real network. The composer already clears
/// and `state.sending` is already set the instant `Enter` is pressed (see the test above); this
/// proves the transcript actually renders that in-flight body right away, not just the internal
/// state field — a provisional row (never persisted into `state.entries`, see
/// `chat::complete_send`'s own doc comment) rather than nothing at all.
#[test]
fn a_send_in_flight_is_visible_in_the_transcript_immediately_not_only_after_it_completes() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hey there");
    chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(
        state.entries.is_empty(),
        "not persisted yet — still in flight"
    );

    let text = render_chat_to_text(&state, 80, 24);
    assert!(
        text.contains("hey there"),
        "the just-sent body must render immediately, before the send completes:\n{text}"
    );
    assert!(
        !text.contains("no messages yet"),
        "must not still show the empty-transcript placeholder while a send is in flight:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// Send-gate wiring — Blocked (this task's named security deliverable)
// ---------------------------------------------------------------------------

/// This task's own named deliverable: a `Blocked` contact's composer refuses to enqueue a send —
/// defense in depth alongside `apps/core/src/trust.rs`'s own `can_send` tests, exercised here at the
/// UI-wiring level.
#[test]
fn security_blocked_contact_composer_refuses_to_type_or_enqueue() {
    for mut state in [blocked_state(), user_blocked_state([2u8; 32])] {
        // Typing itself is refused — tui-client.md §6 rule 1's "composer is disabled", not merely
        // "Enter refuses".
        type_str(&mut state, "this should never be sent");
        assert!(
            state.composer.is_empty(),
            "typing must be refused outright while sends are blocked"
        );

        // Even if some text is already present (e.g. typed before the block took effect), Enter
        // must refuse to enqueue it — never partially, never silently.
        state.composer = "already typed before the block".to_string();
        let (effects, exit) = chat::handle_key(&mut state, key(KeyCode::Enter));
        assert!(!exit);
        assert!(
            effects.is_empty(),
            "Blocked must never dispatch Effect::SendMessage"
        );
        assert_eq!(
            state.composer, "already typed before the block",
            "refused text must not be silently cleared or queued"
        );
        assert!(state.entries.is_empty());
        assert!(state.sending.is_none());
    }
}

#[test]
fn security_blocked_banner_is_always_shown_live_not_only_after_a_failed_attempt() {
    let state = blocked_state();
    // No Enter was ever pressed — the banner must still be present on a plain render.
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        assert!(text.contains("SENDS BLOCKED"), "at {w}x{h}:\n{text}");
        assert!(
            text.contains("safety number"),
            "the canonical trust.rs wording must appear verbatim, at {w}x{h}:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Send-gate wiring — Warn
// ---------------------------------------------------------------------------

#[test]
fn enter_with_a_warn_gate_holds_the_text_instead_of_sending() {
    let mut state = warn_state();
    type_str(&mut state, "sensitive text");
    let (effects, _) = chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(state.composer.is_empty());
    match &state.mode {
        ComposerMode::AwaitingAck { held, reason } => {
            assert_eq!(held, "sensitive text");
            assert!(reason.contains("safety number"));
        }
        other => panic!("expected AwaitingAck, got {other:?}"),
    }
}

#[test]
fn acknowledging_a_warn_re_checks_the_gate_and_then_sends() {
    let mut state = warn_state();
    let pubkey = state.peer_pubkey;
    type_str(&mut state, "sensitive text");
    chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(matches!(state.mode, ComposerMode::AwaitingAck { .. }));

    type_str(&mut state, "y");
    let (effects, exit) = chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(!exit);
    assert!(matches!(state.mode, ComposerMode::Normal));
    // Acknowledging re-pins — a real re-check of the gate, not a bypass.
    assert_eq!(
        state.trust.trust_state(&pubkey),
        meridian_core::trust::TrustState::Pinned
    );
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::SendMessage(SendMessageEffect { request, .. }) => {
            assert_eq!(request.body, "sensitive text");
        }
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    }
}

#[test]
fn declining_a_warn_discards_the_held_text_and_sends_nothing() {
    let mut state = warn_state();
    type_str(&mut state, "sensitive text");
    chat::handle_key(&mut state, key(KeyCode::Enter));

    type_str(&mut state, "n");
    let (effects, _) = chat::handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(matches!(state.mode, ComposerMode::Normal));
    assert!(state.notice.is_some());
    assert!(state.entries.is_empty());
}

#[test]
fn esc_while_awaiting_ack_cancels_without_exiting_the_screen() {
    let mut state = warn_state();
    type_str(&mut state, "sensitive text");
    chat::handle_key(&mut state, key(KeyCode::Enter));

    let (effects, exit) = chat::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!exit, "Esc here cancels the prompt, not the whole screen");
    assert!(matches!(state.mode, ComposerMode::Normal));
}

// ---------------------------------------------------------------------------
// Worker completion — delivered / offline / hard failure
// ---------------------------------------------------------------------------

#[test]
fn completed_send_with_delivered_true_inserts_a_sent_entry_and_persists_it() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hi");
    let effects = chat::handle_key(&mut state, key(KeyCode::Enter)).0;
    let request = match effects.into_iter().next().unwrap() {
        Effect::SendMessage(SendMessageEffect { request, .. }) => request,
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    };

    let sent = SentMessage {
        mid: "aaaa".into(),
        ts: 9_000,
        delivered: true,
        queued: false,
    };
    let effects = chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(sent),
        })),
    );
    assert!(state.sending.is_none());
    assert_eq!(state.entries.len(), 1);
    // Transport handoff alone only ever earns the single-tick `Sent` state — see
    // `chat::complete_send`'s own doc comment. `Delivered` (double tick) is reserved for a real,
    // later `ChatContent::Receipt`, applied by `chat::apply_receipt` — covered separately below.
    assert_eq!(state.entries[0].state, MessageState::Sent);
    assert_eq!(state.entries[0].mid, "aaaa");
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::PersistHistory(PersistHistoryEffect { request, .. }) => {
            assert_eq!(request.entry.mid, "aaaa");
        }
        other => panic!("expected Effect::PersistHistory, got {other:?}"),
    }
}

/// The real delivery receipt (`InboundEvent::Receipt`, auto-acked by the peer's own inbound loop)
/// is the only thing that ever earns the double-tick `Delivered` state — `chat::apply_receipt`'s own
/// "`Sent` → `Delivered`" transition, exercised here directly against the row `complete_send` just
/// inserted as `Sent`.
#[test]
fn apply_receipt_transitions_a_sent_entry_to_delivered() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hi");
    let effects = chat::handle_key(&mut state, key(KeyCode::Enter)).0;
    let request = match effects.into_iter().next().unwrap() {
        Effect::SendMessage(SendMessageEffect { request, .. }) => request,
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    };
    chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "aaaa".into(),
                ts: 9_000,
                delivered: true,
                queued: false,
            }),
        })),
    );
    assert_eq!(state.entries[0].state, MessageState::Sent);

    chat::apply_receipt(&mut state, "aaaa");
    assert_eq!(state.entries[0].state, MessageState::Delivered);
}

/// A no-op if no matching `Out`/`Sent` row is loaded — never a panic (mirrors every other
/// screen's tolerant `handle_worker`/`handle_inbound` shape in this crate, per `apply_receipt`'s own
/// doc comment).
#[test]
fn apply_receipt_for_an_unknown_mid_is_a_no_op() {
    let mut state = pinned_state([1u8; 32]);
    state
        .entries
        .push(out_entry("aaaa", "hi", MessageState::Sent));
    chat::apply_receipt(&mut state, "not-the-right-mid");
    assert_eq!(state.entries[0].state, MessageState::Sent);
}

#[test]
fn completed_send_with_delivered_false_marks_failed_with_the_offline_copy() {
    let mut state = pinned_state([1u8; 32]);
    state.trust.set_petname(&[1u8; 32], Some("bob".into())).ok();
    type_str(&mut state, "hi");
    let effects = chat::handle_key(&mut state, key(KeyCode::Enter)).0;
    let request = match effects.into_iter().next().unwrap() {
        Effect::SendMessage(SendMessageEffect { request, .. }) => request,
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    };

    chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "bbbb".into(),
                ts: 9_000,
                delivered: false,
                queued: false,
            }),
        })),
    );
    assert_eq!(state.entries[0].state, MessageState::Failed);
    let copy = state.failure_reasons.get("bbbb").expect("reason recorded");
    assert!(copy.contains("not delivered"));
    assert!(copy.contains("offline"));
    assert!(copy.to_lowercase().contains("retry"));
}

/// Task 8.15: `{delivered:false, queued:true}` (T07 mailbox) must land as `Sent`, not `Failed` —
/// the message genuinely reached the server durably, so it must never be shown as something the
/// user needs to `r`-retry, and `failure_reasons` must stay empty for it (mirrors the `delivered:
/// true` case's own `failure_reasons.remove`, not the `Failed` case's `insert`). The one place this
/// outcome is surfaced at all is the transient `state.notice`.
#[test]
fn completed_send_with_queued_true_inserts_a_sent_entry_and_shows_the_queued_notice() {
    let mut state = pinned_state([1u8; 32]);
    state.trust.set_petname(&[1u8; 32], Some("bob".into())).ok();
    type_str(&mut state, "hi");
    let effects = chat::handle_key(&mut state, key(KeyCode::Enter)).0;
    let request = match effects.into_iter().next().unwrap() {
        Effect::SendMessage(SendMessageEffect { request, .. }) => request,
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    };

    chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "cccc".into(),
                ts: 9_000,
                delivered: false,
                queued: true,
            }),
        })),
    );
    assert_eq!(
        state.entries[0].state,
        MessageState::Sent,
        "a durably-queued send is not a failure — never Failed"
    );
    assert!(
        !state.failure_reasons.contains_key("cccc"),
        "a queued send must not carry a failure reason: {:?}",
        state.failure_reasons.get("cccc")
    );
    let notice = state.notice.expect("a queued send must show a notice");
    assert!(notice.contains("bob"), "must name the peer: {notice:?}");
    assert!(
        notice.contains("queued"),
        "must say the message was queued: {notice:?}"
    );
    assert!(
        !notice.to_lowercase().contains("retry"),
        "a queued send must never invite a retry — it already reached the server: {notice:?}"
    );
}

#[test]
fn hard_worker_failure_shows_an_error_notice_without_inserting_an_entry() {
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "hi");
    let effects = chat::handle_key(&mut state, key(KeyCode::Enter)).0;
    let request = match effects.into_iter().next().unwrap() {
        Effect::SendMessage(SendMessageEffect { request, .. }) => request,
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    };

    chat::handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect {
                request,
                outcome: None,
            }),
            "sealing message: no session".into(),
        ),
    );
    assert!(state.sending.is_none());
    assert!(state.entries.is_empty());
    let notice = state.notice.expect("notice set");
    assert!(notice.contains("sealing message: no session"));
}

// ---------------------------------------------------------------------------
// Security-review fixes (Findings 1 and 3, post-4.20 review)
// ---------------------------------------------------------------------------

/// Finding 1: `App::handle_worker` routes every `WorkerEvent` to whichever screen is topmost purely
/// by `Screen` variant, with no correlation to which in-flight request an event belongs to. Once
/// `Screen::Chat` is wired into real navigation, a stale `SendMessage` completion/failure for a
/// *different* conversation's peer must never be silently accepted as this screen's own.
#[test]
fn worker_event_for_a_different_peer_is_silently_ignored() {
    let this_peer = [1u8; 32];
    let other_peer = [9u8; 32];
    let mut state = pinned_state(this_peer);
    // Simulate this screen's own send in flight, to prove a stale event for a *different* peer's
    // send does not clear it out from under the "second Enter while sending" guard.
    state.sending = Some("my own in-flight body".to_string());

    let stray_request = SendMessageRequest {
        peer_pubkey: other_peer,
        peer_hint: "other.test".into(),
        body: "someone else's message".into(),
    };
    let effects = chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request: stray_request.clone(),
            outcome: Some(SentMessage {
                mid: "stray-completed".into(),
                ts: 1,
                delivered: true,
                queued: false,
            }),
        })),
    );
    assert!(
        effects.is_empty(),
        "a different peer's completion must dispatch nothing"
    );
    assert!(
        state.entries.is_empty(),
        "must not insert into this screen's own transcript"
    );
    assert!(
        state.failure_reasons.is_empty(),
        "must not record a failure reason for a different peer's mid"
    );
    assert_eq!(
        state.sending.as_deref(),
        Some("my own in-flight body"),
        "must not clear this screen's own in-flight send guard"
    );

    // Same check for the Failed variant.
    let effects = chat::handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect {
                request: stray_request,
                outcome: None,
            }),
            "boom".into(),
        ),
    );
    assert!(effects.is_empty());
    assert!(
        state.notice.is_none(),
        "must not set a notice for a different peer's failure"
    );
    assert_eq!(state.sending.as_deref(), Some("my own in-flight body"));
}

/// Finding 3: a repeat report for an already-recorded `mid`, claiming a *different* outcome than the
/// first report, must not corrupt `failure_reasons` even though `insert_deduped` correctly refuses
/// to touch the frozen `entries` row. Covers the "legitimate `delivered: true` arrives after a
/// `Failed` row was already recorded" case: without the fix, `failure_reasons` would lose the
/// specific offline copy while `entries` still shows `Failed`, falling back to the generic retry
/// line and inviting a genuine duplicate send.
#[test]
fn a_second_report_for_the_same_mid_with_a_different_outcome_does_not_corrupt_state() {
    let mut state = pinned_state([1u8; 32]);
    let request = SendMessageRequest {
        peer_pubkey: state.peer_pubkey,
        peer_hint: "example.test".into(),
        body: "hi".into(),
    };

    let first = chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request: request.clone(),
            outcome: Some(SentMessage {
                mid: "flip".into(),
                ts: 1,
                delivered: false,
                queued: false,
            }),
        })),
    );
    assert_eq!(first.len(), 1, "first report persists");
    assert_eq!(state.entries[0].state, MessageState::Failed);
    assert!(state.failure_reasons.contains_key("flip"));

    // A later, second report for the SAME mid claims `delivered: true`.
    let second = chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "flip".into(),
                ts: 2,
                delivered: true,
                queued: false,
            }),
        })),
    );
    assert!(
        second.is_empty(),
        "a repeat mid must never re-dispatch Effect::PersistHistory"
    );
    assert_eq!(state.entries.len(), 1);
    assert_eq!(
        state.entries[0].state,
        MessageState::Failed,
        "the original frozen entry must be untouched"
    );
    assert!(
        state.failure_reasons.contains_key("flip"),
        "failure_reasons must stay in lockstep with entries — a stray later report claiming \
         delivered must not erase the specific offline copy for the still-Failed row"
    );
}

// ---------------------------------------------------------------------------
// Local dedup by mid
// ---------------------------------------------------------------------------

#[test]
fn the_same_completed_send_reported_twice_is_deduped_by_mid() {
    let mut state = pinned_state([1u8; 32]);
    let request = SendMessageRequest {
        peer_pubkey: state.peer_pubkey,
        peer_hint: "example.test".into(),
        body: "hi".into(),
    };
    let sent = || SentMessage {
        mid: "dupe".into(),
        ts: 1,
        delivered: true,
        queued: false,
    };
    let effect = || {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request: request.clone(),
            outcome: Some(sent()),
        }))
    };
    let first = chat::handle_worker(&mut state, effect());
    assert_eq!(state.entries.len(), 1);
    assert_eq!(first.len(), 1, "first insertion persists");

    let second = chat::handle_worker(&mut state, effect());
    assert_eq!(
        state.entries.len(),
        1,
        "a repeat mid must never be re-inserted as a duplicate row"
    );
    assert!(
        second.is_empty(),
        "a deduped insert must not re-dispatch Effect::PersistHistory"
    );
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

#[test]
fn retry_resends_the_most_recent_failed_entry_through_the_gate() {
    let pubkey = [1u8; 32];
    let mut state = pinned_state(pubkey);
    state
        .entries
        .push(out_entry("f1", "old body", MessageState::Failed));
    state.focus = ChatFocus::Transcript;

    let (effects, _) = chat::handle_key(&mut state, char_key('r'));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::SendMessage(SendMessageEffect { request, .. }) => {
            assert_eq!(request.body, "old body");
        }
        other => panic!("expected Effect::SendMessage, got {other:?}"),
    }
}

#[test]
fn retry_re_checks_the_gate_and_refuses_if_now_blocked() {
    let mut state = blocked_state();
    state
        .entries
        .push(out_entry("f1", "old body", MessageState::Failed));
    state.focus = ChatFocus::Transcript;

    let (effects, _) = chat::handle_key(&mut state, char_key('r'));
    assert!(
        effects.is_empty(),
        "retry must not bypass a gate that is now Blocked"
    );
}

#[test]
fn retry_with_no_failed_entry_is_a_no_op() {
    let mut state = pinned_state([1u8; 32]);
    state.focus = ChatFocus::Transcript;
    let (effects, _) = chat::handle_key(&mut state, char_key('r'));
    assert!(effects.is_empty());
}

// ---------------------------------------------------------------------------
// Focus / scroll
// ---------------------------------------------------------------------------

#[test]
fn tab_toggles_focus_between_composer_and_transcript() {
    let mut state = pinned_state([1u8; 32]);
    assert_eq!(state.focus, ChatFocus::Composer);
    chat::handle_key(&mut state, key(KeyCode::Tab));
    assert_eq!(state.focus, ChatFocus::Transcript);
    chat::handle_key(&mut state, key(KeyCode::Tab));
    assert_eq!(state.focus, ChatFocus::Composer);
}

#[test]
fn scroll_keys_only_apply_in_transcript_focus_and_clamp() {
    let mut state = pinned_state([1u8; 32]);
    for i in 0..3 {
        state
            .entries
            .push(out_entry(&format!("m{i}"), "msg", MessageState::Delivered));
    }
    state.focus = ChatFocus::Transcript;

    chat::handle_key(&mut state, key(KeyCode::PageUp));
    assert_eq!(state.scroll_from_bottom, 3, "clamped to entries.len()");

    chat::handle_key(&mut state, key(KeyCode::End));
    assert_eq!(state.scroll_from_bottom, 0);

    chat::handle_key(&mut state, key(KeyCode::Home));
    assert_eq!(state.scroll_from_bottom, 3);
}

#[test]
fn letter_scroll_shortcuts_never_leak_into_composer_typing() {
    // g/G/u/j/k/r must only scroll while transcript-focused, never be interpreted as scroll
    // commands while the user is typing them into the composer.
    let mut state = pinned_state([1u8; 32]);
    type_str(&mut state, "gGujkr");
    assert_eq!(state.composer, "gGujkr");
}

// ---------------------------------------------------------------------------
// Esc / exit
// ---------------------------------------------------------------------------

#[test]
fn esc_in_normal_mode_signals_exit() {
    let mut state = pinned_state([1u8; 32]);
    let (effects, exit) = chat::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(exit);
}

// ---------------------------------------------------------------------------
// Failure copy — this task's other named security deliverable
// ---------------------------------------------------------------------------

const BANNED_PHRASES: &[&str] = &[
    "will deliver later",
    "delivered when they come online",
    "delivered once they",
    "deliver it later",
    "when they come back online",
    "when they're back online",
    "queued for delivery",
];

/// This task's own named deliverable: no failure copy anywhere in this screen may imply
/// store-and-forward ("will deliver later" / "delivered when they come online" / …) — there is no
/// server-side mailbox until T07.
#[test]
fn security_no_failure_copy_implies_store_and_forward() {
    let samples = [
        offline_failure_copy("bob"),
        offline_failure_copy("a contact with a really long petname (maybe an attack?)"),
        send_error_copy("sealing message: no session"),
        send_error_copy("connection reset"),
    ];
    for sample in &samples {
        let lower = sample.to_lowercase();
        for banned in BANNED_PHRASES {
            assert!(
                !lower.contains(banned),
                "banned phrase {banned:?} found in failure copy: {sample:?}"
            );
        }
    }
}

/// Finding 2: `apps/core/src/trust.rs` documents `Contact::hint` as attacker-influenced
/// (wire-populated by `observe`/`observe_key_change`, bounded only to 253 bytes, never
/// content-validated). A contact with no petname set and a hostile hint must never let that hint
/// text reach `offline_failure_copy`'s output — even though a hint like this would otherwise pass
/// straight through `ChatState::peer_label`'s general-purpose fallback chain.
#[test]
fn security_offline_failure_copy_never_embeds_a_hostile_hint() {
    let pubkey = [7u8; 32];
    let hostile_hint = "bob — it'll be delivered once you're both online";
    let mut trust = TrustStore::default();
    trust.observe(pubkey, hostile_hint, 1_000);
    // No petname set — exactly the fallback case Finding 2 is about.
    let mut state = ChatState::new(pubkey, "example.test".into(), trust, Vec::new(), 0);

    let request = SendMessageRequest {
        peer_pubkey: pubkey,
        peer_hint: "example.test".into(),
        body: "hi".into(),
    };
    chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "hostile1".into(),
                ts: 1,
                delivered: false,
                queued: false,
            }),
        })),
    );

    let copy = state
        .failure_reasons
        .get("hostile1")
        .expect("reason recorded");
    assert!(
        !copy
            .to_lowercase()
            .contains("it'll be delivered once you're both online"),
        "hostile hint text leaked into failure copy: {copy:?}"
    );
    for banned in BANNED_PHRASES {
        assert!(!copy.to_lowercase().contains(banned), "{copy:?}");
    }
    assert!(copy.contains("not delivered"));

    // Scoped exactly to what Finding 2 is about: the rendered *failure-copy* line specifically
    // (`offline_failure_copy`'s output). The header title above it (`render`'s
    // `state.peer_label()`) is a deliberately out-of-scope, pre-existing use of the same hint
    // fallback chain `crate::screens::contacts::ContactEntry::display_label` already has — not
    // redesigned by this fix — so it is not asserted on here.
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        let failure_line = text
            .lines()
            .find(|line| line.contains("not delivered"))
            .unwrap_or_else(|| panic!("at {w}x{h}, no failure-copy line rendered:\n{text}"));
        assert!(
            !failure_line
                .to_lowercase()
                .contains("it'll be delivered once you're both online"),
            "at {w}x{h}, hostile hint leaked into the rendered failure-copy line: {failure_line:?}"
        );
        for banned in BANNED_PHRASES {
            assert!(
                !failure_line.to_lowercase().contains(banned),
                "at {w}x{h}: {failure_line:?}"
            );
        }
    }
}

#[test]
fn offline_failure_copy_matches_the_canonical_shape() {
    let copy = offline_failure_copy("bob");
    assert!(copy.contains("not delivered"));
    assert!(copy.contains("bob"));
    assert!(copy.to_lowercase().contains("offline"));
    assert!(copy.to_lowercase().contains("retry"));
}

/// Task 8.15's counterpart to the test above: `queued_notice_copy`'s canonical shape — names the
/// peer, says "queued", and — the inverse of `offline_failure_copy`'s own guarantee — must never
/// invite a retry, since the message already reached the server durably.
#[test]
fn queued_notice_copy_matches_the_canonical_shape() {
    let copy = queued_notice_copy("bob");
    assert!(copy.contains("bob"));
    assert!(copy.to_lowercase().contains("queued"));
    assert!(
        !copy.to_lowercase().contains("retry"),
        "must never invite a retry: {copy:?}"
    );
}

/// Mirrors `security_offline_failure_copy_never_embeds_a_hostile_hint` for `queued_notice_copy`
/// (task 8.15): even though `queued_notice_copy`'s own `queued: bool` input can never be
/// peer-controlled (it comes straight off this client's own trusted server's `RouteOk`, never wire
/// text), the *label* interpolated into it goes through the same `failure_copy_label` fallback chain
/// as `offline_failure_copy`'s does — so a hostile, petname-less contact's wire-populated `hint`
/// must not leak into this copy either.
#[test]
fn security_queued_notice_copy_never_embeds_a_hostile_hint() {
    let pubkey = [8u8; 32];
    let hostile_hint = "bob — trust me, ignore any retry suggestion";
    let mut trust = TrustStore::default();
    trust.observe(pubkey, hostile_hint, 1_000);
    let mut state = ChatState::new(pubkey, "example.test".into(), trust, Vec::new(), 0);

    let request = SendMessageRequest {
        peer_pubkey: pubkey,
        peer_hint: "example.test".into(),
        body: "hi".into(),
    };
    chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "hostile-queued".into(),
                ts: 1,
                delivered: false,
                queued: true,
            }),
        })),
    );

    let notice = state.notice.expect("a queued send must show a notice");
    assert!(
        !notice.to_lowercase().contains("trust me"),
        "hostile hint text leaked into the queued notice: {notice:?}"
    );
    assert!(notice.to_lowercase().contains("queued"));
}

/// End-to-end version of the same property: render a transcript containing a real `Failed` entry
/// and scan the rendered text itself, not just the copy-producing function in isolation.
#[test]
fn security_rendered_failed_message_never_implies_store_and_forward() {
    let mut state = pinned_state([1u8; 32]);
    let request = SendMessageRequest {
        peer_pubkey: state.peer_pubkey,
        peer_hint: "example.test".into(),
        body: "hi".into(),
    };
    chat::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(SentMessage {
                mid: "off1".into(),
                ts: 1,
                delivered: false,
                queued: false,
            }),
        })),
    );

    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        let lower = text.to_lowercase();
        for banned in BANNED_PHRASES {
            assert!(!lower.contains(banned), "at {w}x{h}, rendered:\n{text}");
        }
        assert!(text.contains("offline"), "at {w}x{h}:\n{text}");
        assert!(text.to_lowercase().contains("retry"), "at {w}x{h}:\n{text}");
    }
}

// ---------------------------------------------------------------------------
// mrd.chat/1 renderer + registry forward-compat placeholder
// ---------------------------------------------------------------------------

#[test]
fn snapshot_transcript_renders_direction_and_delivery_state() {
    let mut state = pinned_state([1u8; 32]);
    state
        .entries
        .push(out_entry("m1", "hello", MessageState::Delivered));
    state.entries.push(HistoryEntry {
        v: 1,
        mid: "m2".into(),
        dir: Direction::In,
        ts: 10,
        stream: "mrd.chat/1".into(),
        body: "hi back".into(),
        state: MessageState::Received,
    });
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        assert!(text.contains("hello"), "at {w}x{h}:\n{text}");
        assert!(text.contains("hi back"), "at {w}x{h}:\n{text}");
    }
}

#[test]
fn unknown_stream_type_renders_the_registrys_forward_compat_placeholder() {
    let mut state = pinned_state([1u8; 32]);
    state.entries.push(HistoryEntry {
        v: 1,
        mid: "m3".into(),
        dir: Direction::In,
        ts: 10,
        stream: "mrd.exotic/1".into(),
        body: "opaque payload".into(),
        state: MessageState::Received,
    });
    let text = render_chat_to_text(&state, 80, 24);
    assert!(text.contains("unsupported: mrd.exotic/1"), "got:\n{text}");
    assert!(!text.contains("opaque payload"), "got:\n{text}");
}

#[test]
fn snapshot_empty_transcript() {
    let state = pinned_state([1u8; 32]);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        assert!(text.contains("no messages yet"), "at {w}x{h}:\n{text}");
    }
}

#[test]
fn snapshot_unread_divider_appears_before_the_right_entry() {
    let mut state = pinned_state([1u8; 32]);
    state
        .entries
        .push(out_entry("m1", "old", MessageState::Delivered));
    state.entries.push(HistoryEntry {
        v: 1,
        mid: "m2".into(),
        dir: Direction::In,
        ts: 10,
        stream: "mrd.chat/1".into(),
        body: "new unread".into(),
        state: MessageState::Received,
    });
    state.unread_count = 1;
    let text = render_chat_to_text(&state, 80, 24);
    assert!(text.contains("unread"));
    let unread_pos = text.find("unread ──").unwrap();
    let new_pos = text.find("new unread").unwrap();
    assert!(
        unread_pos < new_pos,
        "the divider must render before the unread message, got:\n{text}"
    );
}

#[test]
fn snapshot_awaiting_ack_prompt() {
    let mut state = warn_state();
    type_str(&mut state, "hi");
    chat::handle_key(&mut state, key(KeyCode::Enter));
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        assert!(text.contains("acknowledge"), "at {w}x{h}:\n{text}");
        assert!(text.contains("safety number"), "at {w}x{h}:\n{text}");
    }
}
