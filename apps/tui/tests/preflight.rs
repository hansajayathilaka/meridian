//! `Preflight` routing (task 4.37) — `cargo nextest run -p meridian-tui --test preflight`.
//!
//! Covers this task's own Deliverable 4, end to end at the `App` boundary (not just
//! `preflight_route`'s own pure-function unit tests in `apps/tui/src/preflight.rs`):
//! (a) no `account.json` → `Screen::Onboarding` (regression — unchanged from this crate's
//!     pre-4.37 behavior);
//! (b) an existing file-backed account → `Screen::Unlock`;
//! (c) an existing OS-keystore account → `Effect::LoadSession`, then `Screen::Main` once that
//!     effect resolves (no real OS keychain touched anywhere here — the worker completion is
//!     simulated by hand, exactly the way `apps/tui/src/app.rs`'s own tests already simulate every
//!     other effect completion; the real worker execution behind `Effect::LoadSession` is task
//!     4.29's own already-covered scope — see `apps/tui/tests/load_session.rs`);
//! (d) a wrong passphrase at `Unlock` retries in place, attempt count incrementing, **no lockout
//!     invented** (`docs/architecture/tui-client.md §7`).

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::account::{AccountDescriptor, StoreKind};

use meridian_tui::app::{
    App, AppEvent, Effect, LoadSessionEffect, LoadSessionOutcome, LoadSessionRequest, Screen,
    SessionOutcome, WorkerEvent,
};
use meridian_tui::config::TuiConfig;
use meridian_tui::preflight::{preflight_route, InitialRoute};
use meridian_tui::session::LiveSession;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn os_descriptor() -> AccountDescriptor {
    AccountDescriptor {
        v: 1,
        pubkey: "1".repeat(64),
        hint: "chat.example".to_string(),
        store: StoreKind::Os,
        keyfile: None,
        service: Some("meridian".to_string()),
        label: "1".repeat(64),
        server: None,
    }
}

fn file_descriptor(keyfile: PathBuf) -> AccountDescriptor {
    AccountDescriptor {
        v: 1,
        pubkey: "2".repeat(64),
        hint: "chat.example".to_string(),
        store: StoreKind::File,
        keyfile: Some(keyfile),
        service: None,
        label: "2".repeat(64),
        server: None,
    }
}

// ---------------------------------------------------------------------------
// (a) No account.json — Onboarding, unchanged from pre-4.37 behavior.
// ---------------------------------------------------------------------------

#[test]
fn a_no_account_routes_to_onboarding_unchanged_from_pre_4_37_behavior() {
    let route = preflight_route(None);
    assert!(matches!(route, InitialRoute::Onboarding));

    let (app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
    assert!(initial_effects.is_empty());

    // Regression: identical observable starting point to the I/O-free `App::new()` every other
    // test in this crate already relies on.
    let plain = App::new();
    assert!(matches!(plain.current_screen(), Screen::Onboarding(_)));
}

// ---------------------------------------------------------------------------
// (b) An existing file-backed account — Unlock.
// ---------------------------------------------------------------------------

#[test]
fn b_file_backed_account_routes_to_unlock() {
    let keyfile = PathBuf::from("/home/user/.config/meridian/account.key");
    let descriptor = file_descriptor(keyfile.clone());
    let expected_id = descriptor.id_string().unwrap();

    let route = preflight_route(Some(descriptor));
    assert!(matches!(route, InitialRoute::Unlock(_)));

    let (app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(initial_effects.is_empty());
    match app.current_screen() {
        Screen::Unlock(_) => {}
        other => panic!("expected Screen::Unlock, got {other:?}"),
    }
    // The rendered screen actually names *this* account, not a generic placeholder — proven via
    // the same `ratatui::backend::TestBackend` snapshot idiom every other screen test in this
    // crate already uses (`apps/tui/tests/screens_unlock.rs::render_to_text`), since
    // `UnlockState`'s own fields are private to `crate::screens::unlock`.
    let backend = ratatui::backend::TestBackend::new(80, 24);
    let mut terminal = ratatui::Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    let text = format!("{}", terminal.backend());
    // The id wraps across two rows at 80 columns (it's longer than the pane is wide) — assert on
    // its unwrapped prefix rather than the whole string, same accommodation
    // `apps/tui/tests/screens_onboarding.rs`'s own `ShowIdentity` snapshot tests make for the
    // identical wrapping behavior.
    assert!(text.contains(&expected_id[..40]));
    let _ = keyfile;
}

// ---------------------------------------------------------------------------
// (c) An existing OS-keystore account — LoadSession, then Main once it resolves.
// ---------------------------------------------------------------------------

#[test]
fn c_os_keystore_account_routes_to_load_session_then_main_once_resolved() {
    let route = preflight_route(Some(os_descriptor()));
    assert!(matches!(route, InitialRoute::LoadSession));

    let (mut app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(matches!(app.current_screen(), Screen::Placeholder));
    assert_eq!(initial_effects.len(), 1);
    assert!(matches!(initial_effects[0], Effect::LoadSession(_)));

    // Simulate the worker completing `Effect::LoadSession` (task 4.29's own already-tested
    // execution — see `apps/tui/tests/load_session.rs`) with a real, freshly-loaded LiveSession —
    // no real OS keychain touched here, exactly like `apps/tui/src/app.rs`'s own worker-completion
    // tests simulate every other effect.
    let outcome = LoadSessionOutcome::Loaded(Box::new(SessionOutcome::ready(LiveSession::empty(
        os_descriptor(),
    ))));
    let effects = app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(
        Effect::LoadSession(LoadSessionEffect {
            request: LoadSessionRequest,
            outcome: Some(outcome),
        }),
    ))));
    assert!(effects.is_empty());
    assert!(matches!(app.current_screen(), Screen::Main(_)));
}

// ---------------------------------------------------------------------------
// (d) A wrong passphrase at Unlock retries in place — no lockout invented.
// ---------------------------------------------------------------------------

#[test]
fn d_wrong_passphrase_at_unlock_retries_in_place_with_no_lockout() {
    let keyfile = PathBuf::from("/home/user/.config/meridian/account.key");
    let route = preflight_route(Some(file_descriptor(keyfile)));
    let (mut app, initial_effects) = App::new_with_route(TuiConfig::default(), route);
    assert!(initial_effects.is_empty());

    // First attempt: type a (wrong) passphrase and submit.
    for c in "wrong-pass".chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1);
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(app.current_screen(), Screen::Unlock(_)));

    // The worker reports failure (task 4.29's own already-tested `Effect::Unlock` execution) —
    // this is *this* task's own concern: retry-in-place, never a lockout, never silently absorbed.
    let effects = app.update(AppEvent::Worker(Box::new(WorkerEvent::Failed(
        effect,
        "wrong passphrase".to_string(),
    ))));
    assert!(effects.is_empty());

    // Still on Unlock — never bounced to Onboarding, a dead end, or any other screen — and the
    // user can immediately retype and resubmit: no attempt-count gate ever refuses a retry.
    assert!(matches!(app.current_screen(), Screen::Unlock(_)));
    for c in "correct-this-time".chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(
        effects.len(),
        1,
        "a second attempt must be able to dispatch Effect::Unlock again — no lockout"
    );
    assert!(matches!(effects[0], Effect::Unlock(_)));
    assert!(matches!(app.current_screen(), Screen::Unlock(_)));
}
