//! `meridian_tui::screens::unlock` — task 4.17's own test target
//! (`cargo nextest run -p meridian-tui --test screens_unlock`).
//!
//! State-machine coverage (passphrase entry, submit, retry-with-attempt-count on a wrong
//! passphrase, success) plus screen-snapshot tests at 80x24 and the narrow 40x24 established by
//! `screens_onboarding.rs` (see its own doc comment for why 40 was chosen), plus the
//! no-secret-rendered structural checks (masked with `•`, and never in a `{:?}` dump).
//!
//! Every test up to the "App-level boot test" section below drives transitions by directly
//! feeding `handle_key`/`handle_worker` the same way `screens_onboarding.rs` does, simulating what
//! a worker's `WorkerEvent::Completed`/`Failed` would report for `Effect::Unlock` — a real worker
//! now exists (task 4.29/4.37), and task 5.8's own boot test at the bottom of this file drives it
//! for real: a typed passphrase, through real `crossterm` key events into a real `App`, dispatched
//! through the real `meridian_tui::worker::dispatch` against a real, sealed `$MERIDIAN_HOME`,
//! landing on a real `Screen::Main` — mirroring `apps/tui/tests/accept_to_chat.rs`'s own harness
//! discipline (that file's own module doc names the precedent this one follows for the same reason:
//! every downstream screen-level test in this crate bypasses the unlock step entirely via a
//! pre-provisioned account fixture, so nothing before task 5.8 ever proved the passphrase → real
//! `Effect::Unlock` → real `Screen::Main` path end to end).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::identity::{generate_account, FileSecretStore};

use meridian_tui::app::{
    App, AppEvent, Effect, Screen, SessionOutcome, UnlockEffect, UnlockRequest, WorkerEvent,
};
use meridian_tui::config::TuiConfig;
use meridian_tui::preflight::{preflight_route, InitialRoute};
use meridian_tui::screens::unlock::{handle_key, handle_worker, render, Entering, UnlockState};
use meridian_tui::worker::{dispatch, OnboardingSession};

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
        Effect::Unlock(effect) => {
            let UnlockEffect {
                request:
                    UnlockRequest {
                        keyfile: kf,
                        passphrase,
                    },
                ..
            } = effect.as_ref();
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
        WorkerEvent::Completed(Effect::Unlock(Box::new(UnlockEffect {
            request: UnlockRequest {
                keyfile: keyfile(),
                passphrase: "hunter2".into(),
            },
            outcome: SessionOutcome::empty(),
        }))),
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
            Effect::Unlock(Box::new(UnlockEffect {
                request: UnlockRequest {
                    keyfile: keyfile(),
                    passphrase: "wrong-one".into(),
                },
                outcome: SessionOutcome::empty(),
            })),
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
            Effect::Unlock(Box::new(UnlockEffect {
                request: UnlockRequest {
                    keyfile: keyfile(),
                    passphrase: "correct-one".into(),
                },
                outcome: SessionOutcome::empty(),
            })),
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

// ---------------------------------------------------------------------------
// App-level boot test (task 5.8) — a typed passphrase, driven by real `crossterm` key events
// through a real `App`, dispatched through the real `meridian_tui::worker::dispatch` against a
// real, sealed `$MERIDIAN_HOME`, landing on a real `Screen::Main`. See this file's own module doc
// for why this closes a real coverage gap rather than duplicating the state-machine tests above.
// ---------------------------------------------------------------------------

const APP_TEST_PASSPHRASE: &str = "correct horse battery staple";

/// `$MERIDIAN_HOME` environment guard — mirrors `apps/tui/tests/run_worker_account.rs`'s own
/// (no OS-keystore warmup needed: unlocking a **file-backed** account never touches `keyring`).
static ENV_LOCK: Mutex<()> = Mutex::new(());

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

/// Seeds a real, on-disk file-backed account — a real `age`/`scrypt`-wrapped keyfile plus its
/// matching `account.json` — exactly the shape a returning user's `$MERIDIAN_HOME` holds when
/// `meridian tui` starts up and `Preflight` routes it to `Screen::Unlock`.
fn setup_file_backed_account() -> String {
    let keyfile = account::config_dir()
        .expect("config_dir")
        .join("account.key");
    std::fs::create_dir_all(keyfile.parent().unwrap()).unwrap();
    let fs = FileSecretStore::new(&keyfile, APP_TEST_PASSPHRASE);
    let account = generate_account(&fs, "chat.example").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");
    account.to_id_string()
}

fn render_app_to_text(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    format!("{}", terminal.backend())
}

/// Property 1: a correctly typed passphrase, submitted through real key events, unlocks a real
/// keyfile through the real worker and lands the real `App` on `Screen::Main`.
#[tokio::test]
async fn typed_passphrase_through_a_real_unlock_effect_lands_on_a_real_screen_main() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let expected_id = setup_file_backed_account();

    // --- Preflight really routes a file-backed account to Screen::Unlock --------------------------
    let descriptor = AccountDescriptor::load().expect("read account.json");
    let route = preflight_route(Some(descriptor));
    assert!(
        matches!(route, InitialRoute::Unlock(_)),
        "a file-backed account must route to Screen::Unlock, not straight to Screen::Main"
    );
    let (mut app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(
        initial_effects.is_empty(),
        "Unlock needs no effect until a passphrase is actually submitted"
    );
    match app.current_screen() {
        Screen::Unlock(state) => match state.as_ref() {
            UnlockState::Entering(e) => assert_eq!(e.id, expected_id),
            other => panic!("expected UnlockState::Entering, got {other:?}"),
        },
        other => panic!("expected Screen::Unlock, got {other:?}"),
    }

    // --- Real key events: type the passphrase one char at a time, exactly like a real terminal ----
    for c in APP_TEST_PASSPHRASE.chars() {
        let effects = app.update(AppEvent::Key(char_key(c)));
        assert!(
            effects.is_empty(),
            "typing a character must not dispatch anything"
        );
    }
    let rendered = render_app_to_text(&app, 80, 24);
    assert!(
        !rendered.contains(APP_TEST_PASSPHRASE),
        "the typed passphrase must never render in cleartext:\n{rendered}"
    );

    // --- Enter submits: a real Effect::Unlock, executed by the real worker ------------------------
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(
        effects.len(),
        1,
        "Enter with a non-empty passphrase must dispatch Effect::Unlock"
    );
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::Unlock(_)));
    match app.current_screen() {
        Screen::Unlock(state) => assert!(matches!(state.as_ref(), UnlockState::Unlocking(_))),
        other => panic!("expected Screen::Unlock(Unlocking), got {other:?}"),
    }

    let mut session = OnboardingSession::default();
    let event = dispatch(effect, &mut session).await;
    assert!(
        matches!(event, WorkerEvent::Completed(Effect::Unlock(_))),
        "the correct passphrase must succeed against the real keyfile: {event:?}"
    );
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    // --- The real end state: Screen::Main, built from a real (empty, brand-new) LiveSession -------
    match app.current_screen() {
        Screen::Main(main) => assert!(
            main.contacts.entries.is_empty(),
            "a brand-new account has no contacts yet"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }
}

/// Property 2: a wrong passphrase, submitted through real key events, really fails against the
/// real keyfile (never a lockout — task 4.17's own no-lockout contract), and the very next,
/// correct attempt still reaches `Screen::Main` in the same session — the retry-with-attempt-count
/// property from the state-machine tests above, now proven against the real worker instead of a
/// hand-built `WorkerEvent`.
#[tokio::test]
async fn a_real_wrong_passphrase_retries_in_place_before_the_correct_one_reaches_main() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_file_backed_account();

    let descriptor = AccountDescriptor::load().expect("read account.json");
    let route = preflight_route(Some(descriptor));
    let (mut app, _) = App::new_with_route(TuiConfig::default(), route);
    let mut session = OnboardingSession::default();

    for c in "totally-wrong-guess".chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::Unlock(_)));

    let event = dispatch(effect, &mut session).await;
    let message = match &event {
        WorkerEvent::Failed(Effect::Unlock(_), message) => {
            assert!(!message.contains("totally-wrong-guess"));
            message.clone()
        }
        other => panic!("a wrong passphrase against the real keyfile must fail: {other:?}"),
    };
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    match app.current_screen() {
        Screen::Unlock(state) => match state.as_ref() {
            UnlockState::Entering(e) => {
                assert_eq!(e.attempts, 1);
                assert!(e.passphrase.is_empty());
                assert_eq!(e.error.as_deref(), Some(message.as_str()));
            }
            other => panic!("expected Entering after a real failure, got {other:?}"),
        },
        other => panic!("expected Screen::Unlock, got {other:?}"),
    }

    // No lockout: the correct passphrase, typed right after, still reaches Main in this same
    // session.
    for c in APP_TEST_PASSPHRASE.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    let effect = effects.into_iter().next().unwrap();
    let event = dispatch(effect, &mut session).await;
    assert!(matches!(event, WorkerEvent::Completed(Effect::Unlock(_))));
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());
    assert!(matches!(app.current_screen(), Screen::Main(_)));
}
