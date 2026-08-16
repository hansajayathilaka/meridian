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
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`handle_worker`, exactly like `screens_chat.rs`/`screens_requests.rs`/
//! `screens_verify.rs` do. The one exception is the dedicated "never silent" test above, which also
//! calls `meridian_tui::config_write::write_setting_at` directly — standing in for what a future
//! worker executing `Effect::SaveSetting` would do — since that is the only way to prove the
//! "genuinely persists" branch is real rather than merely asserted.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_tui::app::{Effect, SaveSettingEffect, SaveSettingRequest, SettingValue, WorkerEvent};
use meridian_tui::config::{Bell, NetworkPolicy, Theme, Timestamps, TuiConfig};
use meridian_tui::config_write;
use meridian_tui::screens::settings::{self, PersistOutcome, SettingsMode, SettingsState};

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
