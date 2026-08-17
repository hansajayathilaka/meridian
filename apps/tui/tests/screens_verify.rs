//! `meridian_tui::screens::verify` — task 4.22's own test target
//! (`cargo nextest run -p meridian-tui --test screens_verify`).
//!
//! This is the phase's central security-critical screen, so this file's own bar is higher than the
//! rest of this crate's screen tests: alongside the usual state-machine + screen-snapshot coverage
//! (mirroring `screens_chat.rs`/`screens_requests.rs`'s own conventions), it carries two
//! security-relevant, explicitly named deliverables:
//!
//! 1. **Canonical wording, verbatim, checked in.** `render_blocked_gate_shows_the_canonical_wording_verbatim`
//!    and `render_warn_gate_shows_the_canonical_wording_verbatim` assert the rendered screen contains
//!    the *exact* reason string [`meridian_core::trust::TrustStore::can_send`] produced (never a
//!    screen-derived paraphrase), plus the specific load-bearing substrings
//!    `docs/security/verification-ux.md` calls out by name: the benign-reinstall explanation, the
//!    interception possibility (hard prohibition #2 — never state the former without the latter),
//!    that sends are paused/blocked (not a warning-with-continue — hard prohibition #3), and the
//!    Verify path. A future change that softens `trust.rs`'s own wording, or that has this screen
//!    stop rendering it verbatim, fails these tests as a content diff, not just a manual read.
//! 2. **No dismiss-without-verify, by exhaustive keyspace enumeration.**
//!    `blocked_gate_no_key_sequence_clears_blocked_except_via_confirmed_verify` and
//!    `warn_gate_no_key_sequence_clears_the_warning_except_via_verify_or_acknowledge` iterate every
//!    practical `KeyCode` this crate's screens ever match on (see `all_keycodes`), crossed with every
//!    practical modifier combination (`all_modifiers`), from every sub-mode
//!    `crate::screens::verify::handle_key` actually dispatches on — not a sampled handful of
//!    "suspicious" keys.
//!
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`handle_worker`, exactly like `screens_contacts.rs`/`screens_chat.rs`/
//! `screens_requests.rs` do.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::trust::{SendGate, TrustState, TrustStore};

use meridian_tui::app::{
    AcknowledgeKeyChangeEffect, AcknowledgeKeyChangeRequest, Effect, MarkVerifiedEffect,
    MarkVerifiedRequest, SetUserBlockedEffect, SetUserBlockedRequest, WorkerEvent,
};
use meridian_tui::screens::verify::{self, VerifyAction, VerifyMode, VerifyState};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const OWN: [u8; 32] = [1u8; 32];

/// A **verified** contact whose key then changed — `TrustStore::can_send` returns
/// `SendGate::Blocked`. The contact is keyed at `peer_b` (the *new*, currently-presented key) —
/// mirrors `apps/core/tests/key_change_gate.rs`'s own fixture shape.
fn blocked_fixture() -> ([u8; 32], TrustStore) {
    let peer_a = [2u8; 32];
    let peer_b = [3u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(peer_a, "peer.example", 1_000);
    trust.mark_verified(&peer_a).expect("known contact");
    trust
        .observe_key_change(&peer_a, peer_b, "peer.example", 2_000)
        .expect("known contact, distinct new key");
    (peer_b, trust)
}

/// A **pinned** (TOFU, never verified) contact whose key then changed — `can_send` returns
/// `SendGate::Warn`.
fn warn_fixture() -> ([u8; 32], TrustStore) {
    let peer_a = [4u8; 32];
    let peer_b = [5u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(peer_a, "peer.example", 1_000);
    trust
        .observe_key_change(&peer_a, peer_b, "peer.example", 2_000)
        .expect("known contact, distinct new key");
    (peer_b, trust)
}

/// An ordinary pinned contact with no key-change incident — `can_send` returns `SendGate::Ok`.
fn ok_fixture() -> ([u8; 32], TrustStore) {
    let peer = [6u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(peer, "peer.example", 1_000);
    (peer, trust)
}

fn state_from(peer: [u8; 32], trust: TrustStore) -> VerifyState {
    VerifyState::new(OWN, peer, "peer.example".to_string(), trust)
}

/// Same shape as [`state_from`], but skips [`VerifyState::new`]'s
/// `meridian_core::crypto::safety_number` computation (an iterated SHA-512 — real, deliberate work,
/// see that constructor's own doc comment) by constructing the struct directly with a placeholder
/// value instead. **Only for tests that never read `safety_number`** — the two exhaustive
/// keyspace-enumeration tests below construct thousands of fresh fixtures each (one per
/// key/modifier/start-mode combination), and none of them ever inspects the safety number itself;
/// recomputing it identically every time would be pure, wasted CPU that (this task's own experience
/// building it) turns an otherwise-sub-second test into a multi-minute one for no behavioral
/// difference. All the render/basic tests above still use [`state_from`], which computes the real
/// value.
fn state_from_cheap(peer: [u8; 32], trust: TrustStore) -> VerifyState {
    VerifyState {
        own_pubkey: OWN,
        peer_pubkey: peer,
        peer_hint: "peer.example".to_string(),
        trust,
        safety_number: String::new(),
        notice: None,
        mode: VerifyMode::View,
        banner_scroll: 0,
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// Renders to an in-memory buffer and reassembles the **inner** (border-stripped) cell content, one
/// space-joined string per row, all rows then joined with a single space.
///
/// **Not** `format!("{}", terminal.backend())` (the convention `screens_chat.rs`/
/// `screens_requests.rs` use for their own, shorter, never-wrapped substring checks): that `Display`
/// impl quotes each row (for buffer-diffing) and embeds this screen's outer `Block` border
/// characters directly adjacent to row-edge content with no separating whitespace. A phrase that
/// `Paragraph`'s word-wrap splits across two rows — e.g. this screen's own canonical wording
/// wrapping between "switched" and "devices" — would then have the second row's content glued
/// straight onto a border character (`"│devices"`), silently breaking any `.contains("switched
/// devices")` check across the wrap point even though a sighted user reads it as one continuous
/// sentence. Stripping the border and joining every row with a plain space reconstructs exactly
/// that continuous reading order regardless of where `Paragraph` happened to wrap.
fn render_verify_to_text(state: &VerifyState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| verify::render(state, frame))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let area = buffer.area;
    let mut rows = Vec::new();
    for y in area.y.saturating_add(1)..area.y.saturating_add(area.height).saturating_sub(1) {
        let mut row = String::new();
        for x in area.x.saturating_add(1)..area.x.saturating_add(area.width).saturating_sub(1) {
            if let Some(cell) = buffer.cell((x, y)) {
                row.push_str(cell.symbol());
            }
        }
        rows.push(row.trim_end().to_string());
    }
    rows.join(" ")
}

/// Every practical `KeyCode` this crate's screens ever match against — the exhaustive keyspace the
/// "no dismiss without verify" tests below sweep, per this task's own "exhaustive action
/// enumeration, not a sampled check" requirement.
fn all_keycodes() -> Vec<KeyCode> {
    let mut codes = Vec::new();
    for c in 'a'..='z' {
        codes.push(KeyCode::Char(c));
    }
    for c in 'A'..='Z' {
        codes.push(KeyCode::Char(c));
    }
    for c in '0'..='9' {
        codes.push(KeyCode::Char(c));
    }
    for c in [
        '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}',
        ';', ':', '\'', '"', ',', '.', '<', '>', '/', '?', '\\', '|', '`', '~', ' ',
    ] {
        codes.push(KeyCode::Char(c));
    }
    codes.extend([
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Backspace,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Delete,
        KeyCode::Insert,
        KeyCode::Null,
    ]);
    for n in 1..=12 {
        codes.push(KeyCode::F(n));
    }
    codes
}

fn all_modifiers() -> Vec<KeyModifiers> {
    vec![
        KeyModifiers::NONE,
        KeyModifiers::CONTROL,
        KeyModifiers::ALT,
        KeyModifiers::SHIFT,
        KeyModifiers::CONTROL | KeyModifiers::ALT,
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
    ]
}

fn is_confirm_yes(code: KeyCode) -> bool {
    matches!(code, KeyCode::Char('y') | KeyCode::Char('Y'))
}

// ---------------------------------------------------------------------------
// New state basics
// ---------------------------------------------------------------------------

#[test]
fn new_state_starts_in_view_mode_with_no_notice() {
    let (peer, trust) = ok_fixture();
    let state = state_from(peer, trust);
    assert!(matches!(state.mode, VerifyMode::View));
    assert!(state.notice.is_none());
}

#[test]
fn safety_number_matches_the_core_computation() {
    let (peer, trust) = ok_fixture();
    let state = state_from(peer, trust);
    assert_eq!(
        state.safety_number,
        meridian_core::crypto::safety_number(&OWN, &peer)
    );
    // Order-independent, per the core computation's own contract.
    assert_eq!(
        state.safety_number,
        meridian_core::crypto::safety_number(&peer, &OWN)
    );
}

#[test]
fn gate_reflects_the_live_trust_store_for_each_fixture() {
    let (peer, trust) = ok_fixture();
    assert_eq!(state_from(peer, trust).gate(), SendGate::Ok);

    let (peer, trust) = warn_fixture();
    assert!(matches!(state_from(peer, trust).gate(), SendGate::Warn(_)));

    let (peer, trust) = blocked_fixture();
    assert!(matches!(
        state_from(peer, trust).gate(),
        SendGate::Blocked(_)
    ));
}

// ---------------------------------------------------------------------------
// Ordinary verify/block flow (SendGate::Ok)
// ---------------------------------------------------------------------------

#[test]
fn v_enters_confirm_verify_and_esc_cancels_without_mutating_trust() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_key(&mut state, char_key('v'));
    assert!(matches!(
        state.mode,
        VerifyMode::Confirm(VerifyAction::Verify)
    ));

    let (effects, exit) = verify::handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!exit);
    assert!(matches!(state.mode, VerifyMode::View));
    assert_eq!(state.trust.trust_state(&peer), TrustState::Pinned);
}

#[test]
fn confirm_verify_y_marks_verified_and_dispatches_effect_mark_verified() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_key(&mut state, char_key('v'));
    let (effects, exit) = verify::handle_key(&mut state, char_key('y'));
    assert!(!exit);
    assert_eq!(state.trust.trust_state(&peer), TrustState::Verified);
    assert!(matches!(state.mode, VerifyMode::View));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::MarkVerified(MarkVerifiedEffect { request, outcome }) => {
            assert_eq!(request.pubkey, peer);
            assert!(outcome.is_none());
        }
        other => panic!("expected Effect::MarkVerified, got {other:?}"),
    }
}

#[test]
fn confirm_verify_for_an_unknown_contact_errors_without_dispatching() {
    let mut state = state_from([9u8; 32], TrustStore::default());
    verify::handle_key(&mut state, char_key('v'));
    let (effects, _) = verify::handle_key(&mut state, char_key('y'));
    assert!(effects.is_empty());
    assert!(matches!(state.mode, VerifyMode::Error(_)));
}

#[test]
fn block_toggles_and_dispatches_effect_set_user_blocked_in_the_correct_direction() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    assert!(!state.user_blocked());

    verify::handle_key(&mut state, char_key('b'));
    let (effects, _) = verify::handle_key(&mut state, char_key('y'));
    assert!(state.user_blocked());
    match &effects[0] {
        Effect::SetUserBlocked(SetUserBlockedEffect { request, .. }) => {
            assert_eq!(request.pubkey, peer);
            assert!(request.blocked);
        }
        other => panic!("expected Effect::SetUserBlocked, got {other:?}"),
    }
    // Trust state (the key-change lifecycle) is untouched by a local block.
    assert_eq!(state.trust.trust_state(&peer), TrustState::Pinned);

    // Pressing it again unblocks.
    verify::handle_key(&mut state, char_key('b'));
    let (effects, _) = verify::handle_key(&mut state, char_key('y'));
    assert!(!state.user_blocked());
    match &effects[0] {
        Effect::SetUserBlocked(SetUserBlockedEffect { request, .. }) => {
            assert!(!request.blocked);
        }
        other => panic!("expected Effect::SetUserBlocked, got {other:?}"),
    }
}

#[test]
fn confirm_block_n_or_esc_or_other_keys_cancel_without_mutating() {
    for cancel in [
        char_key('n'),
        char_key('N'),
        key(KeyCode::Esc),
        char_key('x'),
    ] {
        let (peer, trust) = ok_fixture();
        let mut state = state_from(peer, trust);
        verify::handle_key(&mut state, char_key('b'));
        let (effects, _) = verify::handle_key(&mut state, cancel);
        assert!(effects.is_empty());
        assert!(matches!(state.mode, VerifyMode::View));
        assert!(!state.user_blocked());
    }
}

// ---------------------------------------------------------------------------
// Acknowledge — only reachable while the gate is genuinely Warn
// ---------------------------------------------------------------------------

#[test]
fn a_is_a_no_op_unless_the_gate_is_currently_warn() {
    for (peer, trust) in [ok_fixture(), blocked_fixture()] {
        let mut state = state_from(peer, trust);
        let (effects, exit) = verify::handle_key(&mut state, char_key('a'));
        assert!(effects.is_empty());
        assert!(!exit);
        assert!(
            matches!(state.mode, VerifyMode::View),
            "'a' must not open the acknowledge confirm outside SendGate::Warn"
        );
    }
}

#[test]
fn a_enters_confirm_acknowledge_when_the_gate_is_warn() {
    let (peer, trust) = warn_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_key(&mut state, char_key('a'));
    assert!(matches!(
        state.mode,
        VerifyMode::Confirm(VerifyAction::Acknowledge)
    ));
}

#[test]
fn confirm_acknowledge_y_repins_and_dispatches_effect_acknowledge_key_change() {
    let (peer, trust) = warn_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_key(&mut state, char_key('a'));
    let (effects, _) = verify::handle_key(&mut state, char_key('y'));
    assert_eq!(state.trust.trust_state(&peer), TrustState::Pinned);
    assert_eq!(state.gate(), SendGate::Ok);
    match &effects[0] {
        Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect { request, .. }) => {
            assert_eq!(request.pubkey, peer);
        }
        other => panic!("expected Effect::AcknowledgeKeyChange, got {other:?}"),
    }
}

#[test]
fn confirm_verify_y_from_warn_also_clears_the_warning_verifying_is_always_at_least_as_strong() {
    let (peer, trust) = warn_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_key(&mut state, char_key('v'));
    verify::handle_key(&mut state, char_key('y'));
    assert_eq!(state.trust.trust_state(&peer), TrustState::Verified);
}

// ---------------------------------------------------------------------------
// Worker-event correlation (the bug class tasks 4.20/4.21 both hit)
// ---------------------------------------------------------------------------

#[test]
fn worker_completion_for_the_right_peer_clears_the_notice() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    state.notice = Some("stale".to_string());
    verify::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::MarkVerified(MarkVerifiedEffect {
            request: MarkVerifiedRequest { pubkey: peer },
            outcome: Some(()),
        })),
    );
    assert!(state.notice.is_none());
}

#[test]
fn worker_failure_for_the_right_peer_sets_a_notice() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::MarkVerified(MarkVerifiedEffect {
                request: MarkVerifiedRequest { pubkey: peer },
                outcome: None,
            }),
            "disk full".to_string(),
        ),
    );
    assert!(state.notice.as_deref().unwrap().contains("disk full"));
}

#[test]
fn worker_event_naming_a_different_peer_is_ignored_even_with_a_matching_effect_variant() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    state.notice = Some("must survive".to_string());
    let other_peer = [0xAAu8; 32];
    assert_ne!(other_peer, peer);

    let effects = verify::handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::MarkVerified(MarkVerifiedEffect {
                request: MarkVerifiedRequest { pubkey: other_peer },
                outcome: None,
            }),
            "unrelated failure".to_string(),
        ),
    );
    assert!(effects.is_empty());
    assert_eq!(state.notice.as_deref(), Some("must survive"));

    // Same guard for SetUserBlocked/AcknowledgeKeyChange completions.
    verify::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::SetUserBlocked(SetUserBlockedEffect {
            request: SetUserBlockedRequest {
                pubkey: other_peer,
                blocked: true,
            },
            outcome: Some(()),
        })),
    );
    assert_eq!(state.notice.as_deref(), Some("must survive"));
    verify::handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
            request: AcknowledgeKeyChangeRequest { pubkey: other_peer },
            outcome: Some(()),
        })),
    );
    assert_eq!(state.notice.as_deref(), Some("must survive"));
}

#[test]
fn irrelevant_worker_event_shapes_are_ignored_not_a_panic() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    let effects = verify::handle_worker(&mut state, WorkerEvent::Completed(Effect::FetchBundle));
    assert!(effects.is_empty());
}

// ---------------------------------------------------------------------------
// "No dismiss without verify" — exhaustive keyspace enumeration (this task's own
// explicitly-named deliverable: "exhaustive action enumeration, not a sampled check").
// ---------------------------------------------------------------------------

/// From every sub-mode this screen's `handle_key` actually dispatches on (including
/// `Confirm(Acknowledge)`, which is not *reachable* via `handle_view_key` while the gate is
/// `Blocked` — see `a_is_a_no_op_unless_the_gate_is_currently_warn` above — but is exercised here
/// too as a defense-in-depth check: even if this mode were somehow force-entered,
/// `TrustStore::acknowledge_key_change` itself refuses to touch a `Blocked` contact), sweeping every
/// practical key/modifier combination: `TrustState::Blocked` is cleared if and only if the exact
/// sequence "enter Confirm(Verify), then y/Y" runs, which is the only path that calls
/// `TrustStore::mark_verified`. Every other combination must leave the contact exactly as blocked
/// as it started.
#[test]
fn blocked_gate_no_key_sequence_clears_blocked_except_via_confirmed_verify() {
    let start_modes = [
        VerifyMode::View,
        VerifyMode::Confirm(VerifyAction::Verify),
        VerifyMode::Confirm(VerifyAction::Block),
        VerifyMode::Confirm(VerifyAction::Acknowledge),
        VerifyMode::Error("a previous error".to_string()),
    ];

    let mut checked = 0usize;
    for start_mode in &start_modes {
        for code in all_keycodes() {
            for modifiers in all_modifiers() {
                let (peer, trust) = blocked_fixture();
                let mut state = state_from_cheap(peer, trust);
                state.mode = start_mode.clone();

                verify::handle_key(&mut state, KeyEvent::new(code, modifiers));
                checked += 1;

                let legit_verify = matches!(start_mode, VerifyMode::Confirm(VerifyAction::Verify))
                    && is_confirm_yes(code);
                if legit_verify {
                    assert_eq!(
                        state.trust.trust_state(&peer),
                        TrustState::Verified,
                        "y/Y from Confirm(Verify) must actually call mark_verified"
                    );
                } else {
                    assert_eq!(
                        state.trust.trust_state(&peer),
                        TrustState::Blocked,
                        "key {code:?} (mods {modifiers:?}) from {start_mode:?} must not clear a \
                         verified contact's key-change block"
                    );
                }
            }
        }
    }
    // Sanity: this really did sweep a large keyspace, not a handful of keys.
    assert!(
        checked > 3000,
        "expected an exhaustive sweep, got {checked} cases"
    );
}

/// Same shape as the Blocked test above, for `TrustState::PinnedKeyChanged`. Two — and only two —
/// paths may clear it: "enter Confirm(Verify), then y/Y" (`mark_verified`, always at least as
/// strong) and "enter Confirm(Acknowledge), then y/Y" (`acknowledge_key_change`, the pinned-case
/// re-pin verification-ux.md specifies). Every other combination must leave the contact exactly as
/// warned as it started.
#[test]
fn warn_gate_no_key_sequence_clears_the_warning_except_via_verify_or_acknowledge() {
    let start_modes = [
        VerifyMode::View,
        VerifyMode::Confirm(VerifyAction::Verify),
        VerifyMode::Confirm(VerifyAction::Block),
        VerifyMode::Confirm(VerifyAction::Acknowledge),
        VerifyMode::Error("a previous error".to_string()),
    ];

    let mut checked = 0usize;
    for start_mode in &start_modes {
        for code in all_keycodes() {
            for modifiers in all_modifiers() {
                let (peer, trust) = warn_fixture();
                let mut state = state_from_cheap(peer, trust);
                state.mode = start_mode.clone();

                verify::handle_key(&mut state, KeyEvent::new(code, modifiers));
                checked += 1;

                let legit_verify = matches!(start_mode, VerifyMode::Confirm(VerifyAction::Verify))
                    && is_confirm_yes(code);
                let legit_ack =
                    matches!(start_mode, VerifyMode::Confirm(VerifyAction::Acknowledge))
                        && is_confirm_yes(code);

                if legit_verify {
                    assert_eq!(state.trust.trust_state(&peer), TrustState::Verified);
                } else if legit_ack {
                    assert_eq!(state.trust.trust_state(&peer), TrustState::Pinned);
                } else {
                    assert_eq!(
                        state.trust.trust_state(&peer),
                        TrustState::PinnedKeyChanged,
                        "key {code:?} (mods {modifiers:?}) from {start_mode:?} must not silently \
                         clear a pending key-change warning"
                    );
                }
            }
        }
    }
    assert!(
        checked > 3000,
        "expected an exhaustive sweep, got {checked} cases"
    );
}

/// Esc from `View` always pops the screen (tui-client.md §3: "Esc always means back") and never
/// itself resolves a pending key-change block/warning — the trust state a fresh, freshly-constructed
/// screen for the same peer would see is identical before and after.
#[test]
fn esc_from_view_pops_without_touching_trust_state_for_both_blocked_and_warn() {
    for (peer, trust) in [blocked_fixture(), warn_fixture()] {
        let mut state = state_from(peer, trust);
        let before = state.gate();
        let (effects, exit) = verify::handle_key(&mut state, key(KeyCode::Esc));
        assert!(effects.is_empty());
        assert!(exit);
        assert_eq!(state.gate(), before);
    }
}

// ---------------------------------------------------------------------------
// Screen-snapshot tests, including the canonical-wording-verbatim deliverable
// ---------------------------------------------------------------------------

#[test]
fn render_ok_gate_shows_no_key_change_banner_and_shows_number_and_qr() {
    let (peer, trust) = ok_fixture();
    let state = state_from(peer, trust);
    let text = render_verify_to_text(&state, 80, 30);
    assert!(!text.contains("KEY CHANGE"));
    // The grouped safety number (spaces every 5 digits) appears somewhere in the number panel.
    assert!(text.contains(&meridian_core::crypto::display_groups(&state.safety_number)[..5]));
    // A QR code was actually rendered (unicode block glyphs), not an error placeholder.
    assert!(!text.contains("QR unavailable"));
}

/// This task's own named deliverable #2: the checked-in text includes the canonical warning copy
/// verbatim — sourced live from `TrustStore::can_send` (never hand-typed here, so a future change to
/// `trust.rs`'s own wording cannot silently drift out of sync with what this test expects), plus the
/// specific load-bearing substrings verification-ux.md's "Key change on a VERIFIED contact — BLOCK"
/// section calls out by name.
#[test]
fn render_blocked_gate_shows_the_canonical_wording_verbatim() {
    let (peer, trust) = blocked_fixture();
    let reason = match trust.can_send(&peer) {
        SendGate::Blocked(reason) => reason,
        other => panic!("expected SendGate::Blocked from the blocked fixture, got {other:?}"),
    };
    let state = state_from(peer, trust);
    let text = render_verify_to_text(&state, 100, 40);
    // `Paragraph`'s word-wrap can turn an inter-word space into a row boundary (a newline in the
    // `TestBackend` dump), so every substring check below runs against a whitespace-flattened copy
    // rather than the raw, row-wrapped dump — reassembling exactly what a sighted user reads as one
    // continuous sentence.
    let flattened: String = text.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(flattened.contains("KEY CHANGE"));
    assert!(flattened.contains("SENDS BLOCKED"));
    // The load-bearing substrings verification-ux.md names for this case.
    assert!(flattened.contains("reinstalled or"));
    assert!(flattened.contains("switched devices"));
    assert!(flattened.contains("intercepting your messages"));
    assert!(flattened.contains("blocked"));
    assert!(flattened.contains("verify"));
    // Hard prohibition #1: no "trust anyway"/dismiss wording, and no acknowledge option at all for
    // the verified-key-change case (tui-client.md §6 rule 1: "no third option").
    assert!(!flattened.to_lowercase().contains("trust anyway"));
    assert!(!flattened.to_lowercase().contains("acknowledge"));

    // The exact live-computed reason string, verbatim.
    let reason_flattened: String = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flattened.contains(&reason_flattened),
        "rendered output must contain the exact SendGate::Blocked reason string verbatim"
    );
}

/// Same shape as the Blocked test above, for `SendGate::Warn`'s "Key change on a PINNED contact —
/// PROMINENT WARNING" wording.
#[test]
fn render_warn_gate_shows_the_canonical_wording_verbatim() {
    let (peer, trust) = warn_fixture();
    let reason = match trust.can_send(&peer) {
        SendGate::Warn(reason) => reason,
        other => panic!("expected SendGate::Warn from the warn fixture, got {other:?}"),
    };
    let state = state_from(peer, trust);
    let text = render_verify_to_text(&state, 100, 40);
    let flattened: String = text.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(flattened.contains("KEY CHANGE WARNING"));
    assert!(flattened.contains("reinstalled or"));
    assert!(flattened.contains("switched devices"));
    assert!(flattened.contains("intercepting your messages"));
    assert!(flattened.contains("paused"));
    assert!(flattened.contains("verify"));
    // Acknowledge exists here (the pinned case's legitimate re-pin path), but Verify is still
    // presented — never bare "trust anyway" wording.
    assert!(!flattened.to_lowercase().contains("trust anyway"));

    let reason_flattened: String = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flattened.contains(&reason_flattened),
        "rendered output must contain the exact SendGate::Warn reason string verbatim"
    );
}

/// Security-review regression: `render_body` (`apps/tui/src/screens/verify.rs`) used to clamp the
/// banner's computed height with `.min(area.height.saturating_sub(3))`, always reserving 3 rows for
/// the number/QR pane *at the direct expense of clipping the security banner* on a short-enough
/// terminal — reintroducing the exact "canonical wording silently clipped" bug the module's own
/// `wrapped_height` helper exists to prevent, just gated on height instead of width. None of the
/// existing height-varying assertions caught it (`render_blocked_gate_.../render_warn_gate_...` use
/// height 40, `render_at_the_narrow_40x24_terminal_works...` uses height 24 — neither is short enough
/// to hit the clamp at width 80/100). This test picks a height that actually stresses the constraint
/// math worked out against `blocked_reason`/`warn_reason`'s real wrapped row count at width 80 (both
/// wrap to 6 rows at this width, so header + wrapped reason + blank line needs 8 banner rows; the old
/// clamp would have capped this well below that at height 12), and asserts the *entire* flattened
/// reason string survives — not cherry-picked substrings, mirroring the verbatim tests above but at a
/// height chosen to genuinely exercise the fix rather than one where the bug happens not to trigger.
#[test]
fn render_at_a_short_12_row_terminal_still_shows_the_full_canonical_wording() {
    for (peer, trust) in [blocked_fixture(), warn_fixture()] {
        let reason = match trust.can_send(&peer) {
            SendGate::Blocked(reason) | SendGate::Warn(reason) => reason,
            SendGate::Ok => panic!("fixture must produce Blocked or Warn"),
        };
        let state = state_from(peer, trust);
        let text = render_verify_to_text(&state, 80, 12);
        let flattened: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let reason_flattened: String = reason.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flattened.contains(&reason_flattened),
            "at an 80x12 terminal the full canonical reason must still be present verbatim, not \
             clipped to make room for the number/QR pane; got: {flattened:?}"
        );
    }
}

/// Security-review regression: `banner_lines` used to hardcode the `SendGate::Blocked` header to
/// "KEY CHANGE — SENDS BLOCKED" for every cause, including a purely local, user-initiated block
/// (`Contact::user_blocked`, task 4.6) that carries no key-change/interception concern at all — see
/// `TrustStore::can_send`'s own doc comment for why it checks `user_blocked` before key-change state.
/// A user who blocked a contact locally for an unrelated reason (spam, harassment) must not see a
/// banner falsely announcing a key-change/interception incident.
#[test]
fn render_user_blocked_gate_shows_a_header_that_does_not_claim_a_key_change() {
    let (peer, mut trust) = ok_fixture();
    trust.set_user_blocked(&peer, true).expect("known contact");
    assert!(matches!(trust.can_send(&peer), SendGate::Blocked(_)));
    let state = state_from(peer, trust);
    let text = render_verify_to_text(&state, 100, 30);
    let flattened: String = text.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        !flattened.contains("KEY CHANGE"),
        "a purely local, user-initiated block must not claim a key change occurred; got: \
         {flattened:?}"
    );
    assert!(flattened.contains("SENDS BLOCKED") || flattened.contains("BLOCKED"));
    assert!(flattened.contains("blocked"));
}

#[test]
fn render_confirm_and_error_modes_all_work_against_test_backend() {
    let (peer, trust) = ok_fixture();
    let mut state = state_from(peer, trust);
    verify::handle_key(&mut state, char_key('v'));
    let confirm_text = render_verify_to_text(&state, 80, 24);
    assert!(confirm_text.contains("(y/n)"));

    state.mode = VerifyMode::Error("boom".to_string());
    let error_text = render_verify_to_text(&state, 80, 24);
    assert!(error_text.contains("boom"));
}

#[test]
fn footer_hints_never_offer_acknowledge_while_blocked() {
    let (peer, trust) = blocked_fixture();
    let state = state_from(peer, trust);
    let text = render_verify_to_text(&state, 80, 24);
    assert!(!text.to_lowercase().contains("acknowledge"));
    assert!(text.contains("verify"));
    assert!(text.contains("block"));
}

#[test]
fn render_at_the_narrow_40x24_terminal_works_for_every_gate_state() {
    for (peer, trust) in [ok_fixture(), warn_fixture(), blocked_fixture()] {
        let state = state_from(peer, trust);
        let text = render_verify_to_text(&state, 40, 24);
        assert!(!text.is_empty());
    }
}
