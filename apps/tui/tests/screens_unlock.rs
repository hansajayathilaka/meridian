//! `meridian_tui::screens::unlock` — task 4.17's own test target
//! (`cargo nextest run -p meridian-tui --test screens_unlock`).
//!
//! State-machine coverage (passphrase entry, submit, retry-with-attempt-count on a wrong
//! passphrase, success) plus screen-snapshot tests at 80x24 and the narrow 40x24 established by
//! `screens_onboarding.rs` (see its own doc comment for why 40 was chosen), plus the
//! no-secret-rendered structural checks (masked with `•`, and never in a `{:?}` dump).
//!
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`handle_worker` the same way `screens_onboarding.rs` does, simulating what a
//! future worker's `WorkerEvent::Completed`/`Failed` would report for `Effect::Unlock`.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_tui::app::{Effect, UnlockRequest, WorkerEvent};
use meridian_tui::screens::unlock::{handle_key, handle_worker, render, Entering, UnlockState};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn type_str(mut state: UnlockState, s: &str) -> UnlockState {
    for c in s.chars() {
        let _ = handle_key(&mut state, char_key(c));
    }
    state
}

fn keyfile() -> PathBuf {
    PathBuf::from("/home/user/.config/meridian/account.age")
}

fn id() -> String {
    "mrd1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@chat.example".into()
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[test]
fn new_state_starts_entering_with_zero_attempts() {
    let state = UnlockState::new(keyfile(), id());
    match state {
        UnlockState::Entering(e) => {
            assert_eq!(e.attempts, 0);
            assert!(e.passphrase.is_empty());
            assert!(e.error.is_none());
            assert_eq!(e.keyfile, keyfile());
            assert_eq!(e.id, id());
        }
        other => panic!("expected Entering, got {other:?}"),
    }
}

#[test]
fn esc_at_entering_is_a_no_op() {
    let mut state = UnlockState::new(keyfile(), id());
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!finished);
    assert!(matches!(state, UnlockState::Entering(_)));
}

#[test]
fn enter_with_empty_passphrase_does_not_submit() {
    let mut state = UnlockState::new(keyfile(), id());
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(!finished);
    assert!(matches!(state, UnlockState::Entering(_)));
}

#[test]
fn enter_with_a_passphrase_dispatches_unlock_effect_and_moves_to_unlocking() {
    let mut state = UnlockState::new(keyfile(), id());
    state = type_str(state, "hunter2");
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(!finished);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::Unlock(UnlockRequest {
            keyfile: kf,
            passphrase,
        }) => {
            assert_eq!(kf, &keyfile());
            assert_eq!(passphrase, "hunter2");
        }
        other => panic!("expected Effect::Unlock, got {other:?}"),
    }
    match &state {
        UnlockState::Unlocking(u) => {
            assert_eq!(u.attempts, 0);
            assert_eq!(u.id, id());
        }
        other => panic!("expected Unlocking, got {other:?}"),
    }
}

#[test]
fn unlocking_ignores_key_input() {
    let mut state = UnlockState::Unlocking(meridian_tui::screens::unlock::Unlocking {
        id: id(),
        attempts: 0,
        request: UnlockRequest {
            keyfile: keyfile(),
            passphrase: "hunter2".into(),
        },
    });
    let (effects, finished) = handle_key(&mut state, char_key('x'));
    assert!(effects.is_empty());
    assert!(!finished);
    assert!(matches!(state, UnlockState::Unlocking(_)));
}

#[test]
fn worker_completed_signals_finished() {
    let mut state = UnlockState::Unlocking(meridian_tui::screens::unlock::Unlocking {
        id: id(),
        attempts: 0,
        request: UnlockRequest {
            keyfile: keyfile(),
            passphrase: "hunter2".into(),
        },
    });
    let (effects, finished) = handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::Unlock(UnlockRequest {
            keyfile: keyfile(),
            passphrase: "hunter2".into(),
        })),
    );
    assert!(effects.is_empty());
    assert!(finished);
}

/// The core retry-with-attempt-count property: a wrong passphrase increments the counter, returns
/// to `Entering` (never a lockout — nothing here refuses the very next attempt), and clears the
/// stale passphrase buffer.
#[test]
fn worker_failed_increments_attempts_and_returns_to_entering_with_no_lockout() {
    let mut state = UnlockState::Unlocking(meridian_tui::screens::unlock::Unlocking {
        id: id(),
        attempts: 0,
        request: UnlockRequest {
            keyfile: keyfile(),
            passphrase: "wrong-one".into(),
        },
    });
    let (effects, finished) = handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::Unlock(UnlockRequest {
                keyfile: keyfile(),
                passphrase: "wrong-one".into(),
            }),
            "could not unwrap keyfile (wrong passphrase or corrupt data)".into(),
        ),
    );
    assert!(effects.is_empty());
    assert!(!finished);
    match &state {
        UnlockState::Entering(e) => {
            assert_eq!(e.attempts, 1);
            assert!(e.passphrase.is_empty());
            assert_eq!(
                e.error.as_deref(),
                Some("could not unwrap keyfile (wrong passphrase or corrupt data)")
            );
        }
        other => panic!("expected Entering, got {other:?}"),
    }

    // No lockout: immediately retry, and it dispatches a fresh Effect::Unlock exactly like the
    // very first attempt did — nothing about attempts > 0 refuses submission.
    state = type_str(state, "correct-one");
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(!finished);
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], Effect::Unlock(_)));
    match &state {
        UnlockState::Unlocking(u) => assert_eq!(u.attempts, 1),
        other => panic!("expected Unlocking, got {other:?}"),
    }

    // A second wrong attempt increments to 2, still no lockout.
    let (_, finished) = handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::Unlock(UnlockRequest {
                keyfile: keyfile(),
                passphrase: "correct-one".into(),
            }),
            "could not unwrap keyfile (wrong passphrase or corrupt data)".into(),
        ),
    );
    assert!(!finished);
    match &state {
        UnlockState::Entering(e) => assert_eq!(e.attempts, 2),
        other => panic!("expected Entering, got {other:?}"),
    }
}

#[test]
fn irrelevant_worker_event_is_ignored() {
    let mut state = UnlockState::new(keyfile(), id());
    let (effects, finished) =
        handle_worker(&mut state, WorkerEvent::Completed(Effect::FetchBundle));
    assert!(effects.is_empty());
    assert!(!finished);
    assert!(matches!(state, UnlockState::Entering(_)));
}

/// `Entering`'s hand-rolled `Debug` impl must redact `passphrase` unconditionally, mirroring
/// `crate::screens::onboarding::ChooseStore`'s (see 4.16's own review-caught bug this guards
/// against) — `Entering` sits inside `UnlockState`/`Screen`/`App`, all of which derive `Debug`, so
/// any `{:?}` anywhere up that chain (including a stray `panic!("{other:?}")` fallback like the
/// ones in this very test file) must never leak it.
#[test]
fn entering_debug_redacts_passphrase() {
    let e = Entering {
        keyfile: keyfile(),
        id: id(),
        passphrase: "correct horse battery staple".into(),
        attempts: 2,
        error: None,
    };
    let debug = format!("{e:?}");
    assert!(!debug.contains("correct horse battery staple"));
    assert!(debug.contains("redacted"));
}

/// Same redaction property, but for `UnlockRequest` (which travels inside `Effect` and therefore
/// through `WorkerEvent`, both `derive(Debug)`) — the in-flight counterpart to the check above.
#[test]
fn unlock_request_debug_redacts_passphrase() {
    let req = UnlockRequest {
        keyfile: keyfile(),
        passphrase: "correct horse battery staple".into(),
    };
    let debug = format!("{req:?}");
    assert!(!debug.contains("correct horse battery staple"));
    assert!(debug.contains("redacted"));
}

// ---------------------------------------------------------------------------
// Screen snapshots — 80x24 and a narrow 40x24, matching screens_onboarding.rs.
// ---------------------------------------------------------------------------

fn render_to_text(state: &UnlockState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| render(state, frame)).expect("draw");
    format!("{}", terminal.backend())
}

fn assert_renders_at_both_widths(state: &UnlockState, must_contain: &[&str]) {
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(state, w, h);
        for needle in must_contain {
            assert!(
                text.contains(needle),
                "expected {w}x{h} render to contain {needle:?}, got:\n{text}"
            );
        }
    }
}

#[test]
fn snapshot_entering_fresh() {
    let state = UnlockState::new(keyfile(), id());
    assert_renders_at_both_widths(&state, &["Unlock", "passphrase:"]);
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(&state, w, h);
        assert!(!text.contains("failed attempt"));
    }
}

#[test]
fn snapshot_entering_never_shows_raw_passphrase_and_masks_it() {
    let state = UnlockState::Entering(Entering {
        keyfile: keyfile(),
        id: id(),
        passphrase: "hunter2".into(),
        attempts: 0,
        error: None,
    });
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(&state, w, h);
        assert!(!text.contains("hunter2"));
        assert!(text.contains("•".repeat(7).as_str()));
    }
}

#[test]
fn snapshot_entering_shows_attempt_count_and_error_after_a_failure() {
    let state = UnlockState::Entering(Entering {
        keyfile: keyfile(),
        id: id(),
        passphrase: String::new(),
        attempts: 1,
        error: Some("could not unwrap keyfile (wrong passphrase or corrupt data)".into()),
    });
    // The error message fits on one row at 80 cols, so it must appear contiguously there; at 40
    // cols it legitimately wraps across two rows (each row in `render_to_text`'s dump is its own
    // quoted line), so only its prefix — which always lands on the first row regardless of width
    // — is checked at both widths, same width-independence approach as
    // `screens_onboarding.rs::snapshot_show_identity_renders_public_id_and_qr`.
    assert!(render_to_text(&state, 80, 24)
        .contains("could not unwrap keyfile (wrong passphrase or corrupt data)"));
    assert_renders_at_both_widths(&state, &["1 failed attempt", "could not unwrap keyfile"]);
    // Singular "attempt", not "attempts", for exactly one failure.
    let text = render_to_text(&state, 80, 24);
    assert!(!text.contains("1 failed attempts"));
}

#[test]
fn snapshot_entering_pluralizes_attempt_count() {
    let state = UnlockState::Entering(Entering {
        keyfile: keyfile(),
        id: id(),
        passphrase: String::new(),
        attempts: 3,
        error: None,
    });
    assert_renders_at_both_widths(&state, &["3 failed attempts"]);
}

#[test]
fn snapshot_unlocking_in_progress() {
    let state = UnlockState::Unlocking(meridian_tui::screens::unlock::Unlocking {
        id: id(),
        attempts: 0,
        request: UnlockRequest {
            keyfile: keyfile(),
            passphrase: "hunter2".into(),
        },
    });
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(&state, w, h);
        assert!(text.contains("Unlocking"));
        assert!(!text.contains("hunter2"));
    }
}
