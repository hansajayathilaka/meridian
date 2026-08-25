//! `meridian_tui::screens::settings` — task 4.24's own test target
//! (`cargo nextest run -p meridian-tui --test screens_settings`).
//!
//! State-machine coverage (list navigation, enum cycling, free-text editing with validation,
//! cancel-without-mutating, worker completion/failure), screen-snapshot tests at 80x24 and the
//! narrow 40x24 established by every prior screen's test file, and this task's own named
//! deliverable: [`a_settings_change_either_persists_with_comments_intact_or_is_marked_session_only_never_silently_neither`]
//! exercises **both** branches the task requires — a genuine `meridian_tui::config_write` round
//! trip against a real, commented `config.toml` on disk (the "persists with comments intact"
//! branch), and the screen's own `handle_worker` on a `WorkerEvent::Failed` (the "session-only"
//! branch) — rather than only exercising one and assuming the other, per the task's own explicit
//! instruction.
//!
//! Most tests below drive transitions by directly feeding `handle_key`/`handle_worker`, exactly like
//! `screens_chat.rs`/`screens_requests.rs`/`screens_verify.rs` do — no real `App`, no real worker.
//! The "never silent" test above also calls `meridian_tui::config_write::write_setting_at` directly
//! — standing in for what a worker executing `Effect::SaveSetting` would do — since that is the only
//! way to prove the "genuinely persists" branch is real rather than merely asserted.
//!
//! ## Task 5.7 — App-level reconciliation (this file's own final section)
//! Every test above this point stops at the screen layer: it never goes through `crate::app::App`'s
//! own screen-stack dispatch, and (aside from the direct `config_write` calls above) never goes
//! through `crate::worker::dispatch` either. That is exactly the gap class that took Phase 4 six
//! gap-closure waves to find and fix for contacts/requests/chat (see
//! `apps/tui/tests/accept_to_chat.rs`'s own module doc) — a live-UI reconciliation path invisible to
//! lower-layer tests. The final section of this file closes that gap for Settings: a real key edit,
//! reached through the real command palette (`Ctrl+K`) on a real `App`, producing a real
//! `Effect::SaveSetting` that a real `meridian_tui::worker::dispatch` executes against a real, sealed
//! `$MERIDIAN_HOME/tui/config.toml` — then the completion, fed back through `App::update`, must
//! reconcile into the live `Screen::Settings` still on the stack. Both the `Saved` and
//! `SessionOnly` outcomes are driven this way, not just one with the other assumed.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_tui::app::{
    App, AppEvent, Effect, SaveSettingEffect, SaveSettingRequest, Screen, SettingValue, WorkerEvent,
};
use meridian_tui::config::{Bell, NetworkPolicy, Theme, Timestamps, TuiConfig};
use meridian_tui::config_write;
use meridian_tui::screens::settings::{self, PersistOutcome, SettingsMode, SettingsState};
use meridian_tui::worker::{dispatch as worker_dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn type_str(state: &mut SettingsState, s: &str) {
    for c in s.chars() {
        settings::handle_key(state, char_key(c));
    }
}

fn state() -> SettingsState {
    SettingsState::new(
        TuiConfig::default(),
        PathBuf::from("/nonexistent/config.toml"),
    )
}

fn render_to_text(state: &SettingsState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| settings::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

/// Extracts the single [`Effect::SaveSetting`] a `handle_key`/`handle_edit_text` call produced.
fn only_save_effect(effects: Vec<Effect>) -> SaveSettingEffect {
    assert_eq!(
        effects.len(),
        1,
        "expected exactly one effect, got {effects:?}"
    );
    match effects.into_iter().next().unwrap() {
        Effect::SaveSetting(e) => e,
        other => panic!("expected Effect::SaveSetting, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

#[test]
fn selection_starts_at_zero_and_clamps_at_both_ends() {
    let mut s = state();
    assert_eq!(s.selected, 0);

    settings::handle_key(&mut s, key(KeyCode::Up));
    assert_eq!(s.selected, 0, "cannot go above the first row");

    for _ in 0..20 {
        settings::handle_key(&mut s, key(KeyCode::Down));
    }
    let max = s.selected;
    settings::handle_key(&mut s, key(KeyCode::Down));
    assert_eq!(s.selected, max, "cannot go below the last row");

    settings::handle_key(&mut s, key(KeyCode::Up));
    assert_eq!(s.selected, max - 1);
}

#[test]
fn j_and_k_navigate_the_same_as_arrow_keys() {
    let mut s = state();
    settings::handle_key(&mut s, char_key('j'));
    assert_eq!(s.selected, 1);
    settings::handle_key(&mut s, char_key('j'));
    assert_eq!(s.selected, 2);
    settings::handle_key(&mut s, char_key('k'));
    assert_eq!(s.selected, 1);
}

#[test]
fn esc_in_list_mode_asks_to_pop() {
    let mut s = state();
    let (effects, pop) = settings::handle_key(&mut s, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(pop);
}

// ---------------------------------------------------------------------------
// Enum cycling (relay policy, theme, timestamps, bell)
// ---------------------------------------------------------------------------

#[test]
fn enter_on_relay_policy_cycles_through_all_four_variants_and_wraps() {
    let mut s = state();
    s.selected = 1; // RelayPolicy — see settings::FIELDS' declared order
    assert_eq!(s.config.network.policy, NetworkPolicy::Inherit);

    let expect_cycle = [
        NetworkPolicy::Direct,
        NetworkPolicy::PreferRelay,
        NetworkPolicy::RelayOnly,
        NetworkPolicy::Inherit,
    ];
    for expected in expect_cycle {
        let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
        let effect = only_save_effect(effects);
        assert_eq!(effect.request.value, SettingValue::RelayPolicy(expected));
        assert_eq!(s.config.network.policy, expected, "applied immediately");
        assert!(matches!(s.mode, SettingsMode::Saving(_)));
        // Resolve it before cycling again — Saving blocks all input.
        settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));
    }
}

#[test]
fn enter_on_theme_cycles_through_all_four_variants_and_wraps() {
    let mut s = state();
    s.selected = 2; // Theme
    let expect_cycle = [Theme::Dark, Theme::Light, Theme::Mono, Theme::Auto];
    for expected in expect_cycle {
        let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
        let effect = only_save_effect(effects);
        assert_eq!(s.config.ui.theme, expected);
        settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));
    }
}

#[test]
fn enter_on_timestamps_cycles_through_all_three_variants_and_wraps() {
    let mut s = state();
    s.selected = 3; // Timestamps
    let expect_cycle = [Timestamps::Clock, Timestamps::Off, Timestamps::Relative];
    for expected in expect_cycle {
        let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
        let effect = only_save_effect(effects);
        assert_eq!(s.config.ui.timestamps, expected);
        settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));
    }
}

#[test]
fn enter_on_bell_cycles_through_all_three_variants_and_wraps() {
    let mut s = state();
    s.selected = 4; // Bell
    let expect_cycle = [Bell::Mention, Bell::Never, Bell::Message];
    for expected in expect_cycle {
        let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
        let effect = only_save_effect(effects);
        assert_eq!(s.config.ui.bell, expected);
        settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));
    }
}

// ---------------------------------------------------------------------------
// Free-text fields
// ---------------------------------------------------------------------------

#[test]
fn server_url_edits_and_empty_input_clears_to_none() {
    let mut s = state();
    s.selected = 0; // ServerUrl
    settings::handle_key(&mut s, key(KeyCode::Enter));
    assert!(matches!(s.mode, SettingsMode::EditText { .. }));

    type_str(&mut s, "chat.example");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);
    assert_eq!(
        effect.request.value,
        SettingValue::ServerUrl(Some("chat.example".to_string()))
    );
    assert_eq!(s.config.account.server.as_deref(), Some("chat.example"));
    settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));

    // Now clear it back out.
    settings::handle_key(&mut s, key(KeyCode::Enter));
    for _ in 0.."chat.example".len() {
        settings::handle_key(&mut s, key(KeyCode::Backspace));
    }
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);
    assert_eq!(effect.request.value, SettingValue::ServerUrl(None));
    assert_eq!(s.config.account.server, None);
}

#[test]
fn retain_days_accepts_a_number_and_rejects_garbage() {
    let mut s = state();
    s.selected = 5; // RetainDays
    settings::handle_key(&mut s, key(KeyCode::Enter));
    type_str(&mut s, "30");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);
    assert_eq!(effect.request.value, SettingValue::RetainDays(30));
    assert_eq!(s.config.history.retain_days, 30);
    settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));

    settings::handle_key(&mut s, key(KeyCode::Enter));
    type_str(&mut s, "not a number");
    let (effects, pop) = settings::handle_key(&mut s, key(KeyCode::Enter));
    assert!(effects.is_empty(), "invalid input dispatches no effect");
    assert!(!pop);
    assert!(matches!(s.mode, SettingsMode::Error(_)));
    // The config value is untouched by the rejected input.
    assert_eq!(s.config.history.retain_days, 30);
}

#[test]
fn max_messages_per_conversation_accepts_zero_as_unlimited() {
    let mut s = state();
    s.selected = 6; // MaxMessagesPerConversation
    settings::handle_key(&mut s, key(KeyCode::Enter));
    for _ in 0.."10000".len() {
        settings::handle_key(&mut s, key(KeyCode::Backspace));
    }
    type_str(&mut s, "0");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);
    assert_eq!(
        effect.request.value,
        SettingValue::MaxMessagesPerConversation(0)
    );
    assert_eq!(s.config.history.max_messages_per_conversation, 0);
}

#[test]
fn reconnect_backoff_ms_parses_a_comma_separated_list_and_rejects_a_bad_entry() {
    let mut s = state();
    s.selected = 7; // ReconnectBackoffMs
    settings::handle_key(&mut s, key(KeyCode::Enter));
    // Clear the pre-filled default text first.
    if let SettingsMode::EditText { input, .. } = s.mode.clone() {
        for _ in 0..input.len() {
            settings::handle_key(&mut s, key(KeyCode::Backspace));
        }
    }
    type_str(&mut s, "100, 200,400");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);
    assert_eq!(
        effect.request.value,
        SettingValue::ReconnectBackoffMs(vec![100, 200, 400])
    );
    assert_eq!(s.config.network.reconnect_backoff_ms, vec![100, 200, 400]);
    settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));

    settings::handle_key(&mut s, key(KeyCode::Enter));
    if let SettingsMode::EditText { input, .. } = s.mode.clone() {
        for _ in 0..input.len() {
            settings::handle_key(&mut s, key(KeyCode::Backspace));
        }
    }
    type_str(&mut s, "100, oops, 400");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(matches!(s.mode, SettingsMode::Error(_)));
    assert_eq!(
        s.config.network.reconnect_backoff_ms,
        vec![100, 200, 400],
        "rejected input never touches config"
    );
}

/// Regression for the `config_write::target()` `as i64` cast wrapping negative on any raw `u64`
/// value above `i64::MAX`: `u64::MAX` must be rejected right here, at the parse/validation step, with
/// a clear error — never dispatched as a `SaveSetting` effect, never reaching
/// `config_write::write_setting_at`, and never wrapping to a negative `config.toml` value that
/// `crate::config::load_from` would then refuse to parse on the next launch.
#[test]
fn reconnect_backoff_ms_rejects_a_value_that_would_wrap_negative_through_config_writes_i64_cast() {
    let mut s = state();
    s.selected = 7; // ReconnectBackoffMs
    settings::handle_key(&mut s, key(KeyCode::Enter));
    if let SettingsMode::EditText { input, .. } = s.mode.clone() {
        for _ in 0..input.len() {
            settings::handle_key(&mut s, key(KeyCode::Backspace));
        }
    }
    type_str(&mut s, "100, 18446744073709551615, 400");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "an out-of-range backoff value must never reach a SaveSetting effect"
    );
    assert!(matches!(s.mode, SettingsMode::Error(_)));
    assert_eq!(
        s.config.network.reconnect_backoff_ms,
        TuiConfig::default().network.reconnect_backoff_ms,
        "rejected input never touches config"
    );

    // Belt-and-suspenders: even if something upstream of parse_edit_text were bypassed, prove
    // config_write itself is never handed the offending value — the real defense is the rejection
    // above, but this pins that `write_setting_at` would otherwise happily write the wrapped
    // negative (i.e. that skipping validation really would be a live bug, not a hypothetical one).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[network]\nreconnect_backoff_ms = [500]\n").unwrap();
    config_write::write_setting_at(&path, &SettingValue::ReconnectBackoffMs(vec![u64::MAX]))
        .expect("write_setting_at itself has no bound — the fix lives in parse_edit_text");
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains("reconnect_backoff_ms = [-1]"),
        "confirms the wraparound this test guards against is real: {raw}"
    );
    let err = meridian_tui::config::load_from(&path, &[])
        .expect_err("the app's own loader then refuses to read the file it just wrote");
    assert!(
        err.to_string().contains("reconnect_backoff_ms"),
        "got: {err}"
    );
}

#[test]
fn esc_from_edit_text_cancels_without_dispatching_or_mutating() {
    let mut s = state();
    s.selected = 0;
    settings::handle_key(&mut s, key(KeyCode::Enter));
    type_str(&mut s, "should not be saved");
    let (effects, pop) = settings::handle_key(&mut s, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!pop);
    assert!(matches!(s.mode, SettingsMode::List));
    assert_eq!(s.config.account.server, None);
}

#[test]
fn error_mode_returns_to_list_on_enter_or_esc() {
    let mut s = state();
    s.selected = 5;
    settings::handle_key(&mut s, key(KeyCode::Enter));
    for _ in 0.."0".len() {
        settings::handle_key(&mut s, key(KeyCode::Backspace));
    }
    type_str(&mut s, "nope");
    settings::handle_key(&mut s, key(KeyCode::Enter));
    assert!(matches!(s.mode, SettingsMode::Error(_)));

    settings::handle_key(&mut s, key(KeyCode::Esc));
    assert!(matches!(s.mode, SettingsMode::List));
}

// ---------------------------------------------------------------------------
// Saving mode blocks input; worker correlation
// ---------------------------------------------------------------------------

#[test]
fn saving_mode_accepts_no_input_including_esc() {
    let mut s = state();
    s.selected = 1;
    settings::handle_key(&mut s, key(KeyCode::Enter));
    assert!(matches!(s.mode, SettingsMode::Saving(_)));

    let (effects, pop) = settings::handle_key(&mut s, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!pop, "cannot leave the screen mid-save");
    assert!(matches!(s.mode, SettingsMode::Saving(_)));
}

/// The correlation guard: a stale worker event for a *different* field than the one currently
/// `Saving` is silently ignored — mirrors `screens_verify.rs`'s/`screens_requests.rs`'s identical
/// tests for the same tasks-4.20/4.21/4.22 lesson.
#[test]
fn worker_event_for_a_different_field_than_the_one_saving_is_ignored() {
    let mut s = state();
    s.selected = 1; // RelayPolicy
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let real_effect = only_save_effect(effects);
    assert!(matches!(s.mode, SettingsMode::Saving(_)));

    // A stale completion for an unrelated field (Theme) — wrong shape entirely for what's saving.
    let stale = Effect::SaveSetting(SaveSettingEffect {
        request: SaveSettingRequest {
            config_path: PathBuf::from("/nonexistent/config.toml"),
            value: SettingValue::Theme(Theme::Mono),
        },
        outcome: None,
    });
    settings::handle_worker(&mut s, WorkerEvent::Completed(stale));
    assert!(
        matches!(s.mode, SettingsMode::Saving(_)),
        "mismatched-field event must not resolve the in-flight save"
    );
    assert!(s.notice.is_none());
    assert!(s.last_persist.is_none());

    // The real, matching event does resolve it.
    settings::handle_worker(
        &mut s,
        WorkerEvent::Completed(Effect::SaveSetting(real_effect)),
    );
    assert!(matches!(s.mode, SettingsMode::List));
    assert_eq!(s.last_persist, Some(PersistOutcome::Saved));
}

// ---------------------------------------------------------------------------
// Screen snapshots
// ---------------------------------------------------------------------------

#[test]
fn render_list_mode_works_against_test_backend_80x24() {
    let s = state();
    let text = render_to_text(&s, 80, 24);
    assert!(text.contains("Settings"));
    assert!(text.contains("server URL"));
    assert!(text.contains("relay policy"));
    assert!(text.contains("reconnect backoff"));
}

#[test]
fn render_works_against_the_narrow_40x24_backend() {
    let s = state();
    let backend = TestBackend::new(40, 24);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| settings::render(&s, frame))
        .expect("draw");
}

#[test]
fn render_edit_text_and_error_and_saving_modes_all_work_against_test_backend() {
    let mut s = state();
    s.selected = 0;
    settings::handle_key(&mut s, key(KeyCode::Enter));
    type_str(&mut s, "example.test");
    let text = render_to_text(&s, 80, 24);
    assert!(text.contains("new value for server URL"));

    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let text = render_to_text(&s, 80, 24);
    assert!(text.contains("saving") || text.contains("please wait"));

    let effect = only_save_effect(effects);
    settings::handle_worker(
        &mut s,
        WorkerEvent::Failed(Effect::SaveSetting(effect), "disk full".to_string()),
    );
    let text = render_to_text(&s, 80, 24);
    assert!(text.contains("session-only"));
}

// ---------------------------------------------------------------------------
// The load-bearing "never silent" deliverable
// ---------------------------------------------------------------------------

const SAMPLE_CONFIG: &str = r#"# Meridian TUI configuration — hand-authored, see docs/architecture/tui-client.md §5.

[account]
# The server this account registered against.
server = "old.example"

[ui]
theme = "dark"

[network]
policy = "direct"
"#;

/// **This task's own load-bearing deliverable.** A settings change either genuinely persists to
/// `config.toml` with comments intact, or the screen clearly marks it session-only — never silently
/// either. This test exercises both branches directly, rather than only one with the other assumed:
///
/// 1. **Persists, comments intact**: `meridian_tui::config_write::write_setting_at` (what a future
///    worker executing `Effect::SaveSetting` would call) against a real, commented `config.toml` on
///    disk — the file's comments and untouched keys survive byte-for-byte, only the targeted value
///    changes.
/// 2. **Session-only, clearly marked**: the *same* kind of change, driven through the screen itself
///    (`handle_key` → `Effect::SaveSetting` → a simulated `WorkerEvent::Failed`, standing in for a
///    write that could not be safely applied) — the in-memory config still reflects the change (it
///    really did take effect for this session), but `SettingsState::notice` unambiguously says so
///    was not saved, and `SettingsState::last_persist` is the typed `PersistOutcome::SessionOnly`,
///    never left as `None`/unset the way a silently-dropped outcome would leave it.
#[test]
fn a_settings_change_either_persists_with_comments_intact_or_is_marked_session_only_never_silently_neither(
) {
    // --- Branch 1: genuinely persists, comments intact. ---
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, SAMPLE_CONFIG).unwrap();

    config_write::write_setting_at(
        &path,
        &SettingValue::ServerUrl(Some("new.example".to_string())),
    )
    .expect("a real, existing, well-formed config.toml can be patched");

    let updated = std::fs::read_to_string(&path).unwrap();
    assert!(updated.contains("# Meridian TUI configuration"));
    assert!(updated.contains("# The server this account registered against."));
    assert!(updated.contains(r#"theme = "dark""#));
    assert!(updated.contains(r#"policy = "direct""#));
    assert!(updated.contains(r#"server = "new.example""#));
    assert!(!updated.contains("old.example"));

    // --- Branch 2: honestly marked session-only when persistence cannot be confirmed. ---
    let mut s = SettingsState::new(
        TuiConfig::default(),
        PathBuf::from("/nonexistent/config.toml"),
    );
    s.selected = 0; // ServerUrl
    settings::handle_key(&mut s, key(KeyCode::Enter));
    type_str(&mut s, "session-only.example");
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);

    // The change is already live for this session, before the worker ever resolves.
    assert_eq!(
        s.config.account.server.as_deref(),
        Some("session-only.example")
    );

    settings::handle_worker(
        &mut s,
        WorkerEvent::Failed(
            Effect::SaveSetting(effect),
            "no config.toml exists yet — nothing to preserve".to_string(),
        ),
    );

    // Never silent: both the typed outcome and the human-readable notice are unambiguously set.
    assert_eq!(s.last_persist, Some(PersistOutcome::SessionOnly));
    let notice = s.notice.expect("a failed save must always leave a notice");
    assert!(notice.contains("session-only"));
    assert!(notice.contains("not saved"));
    // The change itself is not reverted — "session-only" means it took effect for this session.
    assert_eq!(
        s.config.account.server.as_deref(),
        Some("session-only.example")
    );
}

/// The mirror-image property: a successful save is *also* never silent — `notice` and
/// `last_persist` are set just as unambiguously on the `Saved` branch, not just on failure.
#[test]
fn a_successful_save_is_also_never_silent() {
    let mut s = state();
    s.selected = 1; // RelayPolicy
    let (effects, _) = settings::handle_key(&mut s, key(KeyCode::Enter));
    let effect = only_save_effect(effects);

    settings::handle_worker(&mut s, WorkerEvent::Completed(Effect::SaveSetting(effect)));

    assert_eq!(s.last_persist, Some(PersistOutcome::Saved));
    let notice = s
        .notice
        .expect("a completed save must always leave a notice");
    assert!(notice.contains("saved"));
    assert!(!notice.contains("session-only"));
}

// ---------------------------------------------------------------------------
// Task 5.7 — App-level reconciliation: real key events through a real `App`, reached via the real
// command palette, a real `Effect::SaveSetting` executed by the real `meridian_tui::worker::dispatch`
// against a real, sealed `$MERIDIAN_HOME/tui/config.toml` — see this file's own module doc's "Task
// 5.7" section.
// ---------------------------------------------------------------------------

/// Serializes test access to `$MERIDIAN_HOME`, which is process-global — mirrors
/// `tests/accept_to_chat.rs::EnvGuard` exactly (minus that file's mock-keystore setup, which nothing
/// below needs: `Effect::SaveSetting` touches only `config_path`, never identity/`SecretStore`).
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    prev_home: Option<String>,
}

impl EnvGuard {
    fn set(dir: &std::path::Path) -> Self {
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

fn render_app_to_text(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    format!("{}", terminal.backend())
}

fn type_str_app(app: &mut App, s: &str) {
    for c in s.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
}

/// `Ctrl+K`, then a query narrowing the palette down to exactly one entry, then `Enter` — the real
/// navigation path a user takes to reach a first-party built-in screen, mirroring
/// `tests/screens_help_palette.rs::diagnostics_is_reachable_end_to_end_through_the_palette`'s own
/// shape, reused here for "Settings". `query` is chosen so it matches only the intended command's
/// combined name+description under `PaletteState`'s subsequence fuzzy match, never both built-in
/// commands at once (verified by hand against the exact registered strings in
/// `App::register_builtin_commands`, not merely assumed).
fn open_via_palette(app: &mut App, query: &str) {
    app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('k'),
        KeyModifiers::CONTROL,
    )));
    assert!(matches!(app.current_screen(), Screen::Palette(_)));
    for c in query.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert!(
        effects.is_empty(),
        "opening a screen/pane from the palette dispatches no effect"
    );
}

const SAMPLE_CONFIG_FOR_APP_LEVEL_TEST: &str = r#"# Meridian TUI configuration — hand-authored.

[account]
# The server this account registered against.
server = "old.example"

[ui]
theme = "dark"

[network]
policy = "direct"
"#;

/// **The load-bearing property this task exists to close (the `Saved` branch).** A real key edit,
/// driven through a real `App` reached via the real command palette (not a hand-built
/// `SettingsState`), produces a real `Effect::SaveSetting` that a real `meridian_tui::worker::
/// dispatch` executes against a real, sealed `$MERIDIAN_HOME/tui/config.toml` — and the completion,
/// fed back through `App::update`, reconciles into the live `Screen::Settings` still on the stack:
/// `notice`/`last_persist` render `Saved`, and both the in-memory `config` and the real file on disk
/// changed, comments intact.
#[tokio::test]
async fn a_real_key_edit_through_the_live_app_persists_through_a_real_worker_dispatch_and_renders_saved(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let config_path = tmp.path().join("tui").join("config.toml");
    std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir tui/");
    std::fs::write(&config_path, SAMPLE_CONFIG_FOR_APP_LEVEL_TEST).expect("write config.toml");

    // `App::new` resolves `nav.settings`'s own `config_path` from `$MERIDIAN_HOME` at construction
    // time (`crate::config::default_config_path`) — set *before* constructing `App`, mirroring every
    // other test in this crate that needs a real on-disk fixture in place first.
    let mut app = App::new();
    open_via_palette(&mut app, "settings");
    assert!(matches!(app.current_screen(), Screen::Settings(_)));

    // ServerUrl is field 0 (the default selection) — a real key edit, one KeyCode::Char at a time.
    app.update(AppEvent::Key(key(KeyCode::Enter)));
    match app.current_screen() {
        Screen::Settings(state) => assert!(matches!(state.mode, SettingsMode::EditText { .. })),
        other => panic!("expected Screen::Settings, got {other:?}"),
    }
    type_str_app(&mut app, "new.example");
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    let effect = only_save_effect(effects);
    assert_eq!(
        effect.request.config_path, config_path,
        "the effect must carry the real, on-disk config_path App::new resolved via $MERIDIAN_HOME"
    );
    match app.current_screen() {
        Screen::Settings(state) => {
            assert!(matches!(state.mode, SettingsMode::Saving(_)));
            // Applied immediately, before the worker ever resolves — same "screen already knows the
            // answer" property the direct-dispatch tests above already pin, now proven live on the
            // App's own screen stack.
            assert_eq!(state.config.account.server.as_deref(), Some("new.example"));
        }
        other => panic!("expected Screen::Settings, got {other:?}"),
    }

    // The real worker, not a hand-built WorkerEvent.
    let mut session = OnboardingSession::default();
    let event = worker_dispatch(Effect::SaveSetting(effect), &mut session).await;
    match &event {
        WorkerEvent::Completed(Effect::SaveSetting(SaveSettingEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected a completed SaveSetting, got {other:?}"),
    }
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    match app.current_screen() {
        Screen::Settings(state) => {
            assert_eq!(state.last_persist, Some(PersistOutcome::Saved));
            let notice = state
                .notice
                .as_deref()
                .expect("a completed save must leave a notice");
            assert!(notice.contains("saved"));
            assert!(matches!(state.mode, SettingsMode::List));
        }
        other => panic!("expected Screen::Settings, got {other:?}"),
    }

    let text = render_app_to_text(&app, 80, 24);
    assert!(
        text.contains("saved"),
        "expected the saved notice rendered live in the real app:\n{text}"
    );
    assert!(
        text.contains("new.example"),
        "expected the new value rendered live in the real app:\n{text}"
    );

    // And it genuinely persisted, comments intact — not merely asserted in memory.
    let updated = std::fs::read_to_string(&config_path).expect("read back config.toml");
    assert!(updated.contains("# Meridian TUI configuration"));
    assert!(updated.contains(r#"server = "new.example""#));
    assert!(!updated.contains("old.example"));
    assert!(updated.contains(r#"theme = "dark""#));
}

/// **The mirror-image branch: `SessionOnly`.** Same real-App/real-palette/real-worker path as above,
/// but `$MERIDIAN_HOME/tui/config.toml` is deliberately never created — a real, honest
/// `ConfigWriteError::NoFile` — and the live `Screen::Settings` must reconcile that into a clearly
/// marked session-only notice, never silently either (this task's own `handle_key`/`handle_worker`
/// unit tests above already pin this property against a hand-built `SettingsState`; this proves the
/// same reconciliation holds through `App::update`'s real screen-stack dispatch too).
#[tokio::test]
async fn a_real_key_edit_through_the_live_app_is_honestly_marked_session_only_when_no_config_toml_exists_on_disk(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let config_path = tmp.path().join("tui").join("config.toml");

    let mut app = App::new();
    open_via_palette(&mut app, "settings");
    assert!(matches!(app.current_screen(), Screen::Settings(_)));

    app.update(AppEvent::Key(key(KeyCode::Enter))); // ServerUrl -> EditText
    type_str_app(&mut app, "session-only.example");
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    let effect = only_save_effect(effects);

    match app.current_screen() {
        Screen::Settings(state) => assert_eq!(
            state.config.account.server.as_deref(),
            Some("session-only.example"),
            "the change is already live for this session, before the worker ever resolves"
        ),
        other => panic!("expected Screen::Settings, got {other:?}"),
    }

    let mut session = OnboardingSession::default();
    let event = worker_dispatch(Effect::SaveSetting(effect), &mut session).await;
    match &event {
        WorkerEvent::Failed(
            Effect::SaveSetting(SaveSettingEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                message.contains("no config.toml exists yet"),
                "expected the honest ConfigWriteError::NoFile message, got: {message}"
            );
        }
        other => {
            panic!("expected a failed SaveSetting (no config.toml to preserve), got {other:?}")
        }
    }
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    match app.current_screen() {
        Screen::Settings(state) => {
            assert_eq!(state.last_persist, Some(PersistOutcome::SessionOnly));
            let notice = state
                .notice
                .as_deref()
                .expect("a failed save must leave a notice");
            assert!(notice.contains("session-only"));
            assert!(notice.contains("not saved"));
            // Not reverted — session-only still means it took effect for this session.
            assert_eq!(
                state.config.account.server.as_deref(),
                Some("session-only.example")
            );
        }
        other => panic!("expected Screen::Settings, got {other:?}"),
    }

    let text = render_app_to_text(&app, 80, 24);
    assert!(
        text.contains("session-only"),
        "expected the session-only notice rendered live in the real app:\n{text}"
    );

    assert!(
        !config_path.exists(),
        "the worker must never author a config.toml from nothing"
    );
}
