//! The settings screen (task 4.24): a form over `config.toml`'s fields — server URL, relay policy,
//! theme, timestamps, bell, retention, reconnect backoff — reached from the command palette. Like
//! every other screen in this crate, [`handle_key`]/[`handle_worker`] only ever mutate a
//! [`SettingsState`] and return the [`Effect`]s a (future) worker should execute; [`render`] is a
//! pure view function.
//!
//! ## The core design problem: comment-preserving write-back vs. session-only
//! `config.toml` is hand-authored and "never rewritten wholesale" (tui-client.md §5,
//! `crate::config`'s own module doc). A change made here always takes effect **immediately** for
//! this running session — [`apply_change`] mutates [`SettingsState::config`] synchronously, the
//! same "screen already knows the answer" shape `crate::screens::verify::apply_action` uses for
//! `TrustStore` — and *separately* dispatches [`Effect::SaveSetting`] asking a future worker to run
//! [`crate::config_write::write_setting_at`] against the real file on disk. That write either
//! succeeds (comments preserved, byte-identical apart from the one changed key — see
//! `crate::config_write`'s own tests for the round-trip proof) or fails for one of the honest,
//! named reasons `crate::config_write::ConfigWriteError` enumerates (no file yet, malformed TOML, a
//! non-table section, or a bare I/O error).
//!
//! **The "never silent" property this task's own deliverable names**: [`handle_worker`] always sets
//! both [`SettingsState::notice`] (a human-readable sentence) *and* [`SettingsState::last_persist`]
//! (a typed [`PersistOutcome`]) on the *first* worker event that resolves an in-flight save —
//! [`PersistOutcome::Saved`] on `WorkerEvent::Completed`, [`PersistOutcome::SessionOnly`] on
//! `WorkerEvent::Failed`. There is no third path: every [`SettingsMode::Saving`] the screen ever
//! enters resolves to exactly one of those two, never silently back to
//! [`SettingsMode::List`] with `notice`/`last_persist` left as they were before. See
//! `apps/tui/tests/screens_settings.rs`'s dedicated test for both branches, including a genuine
//! `crate::config_write` round-trip proving the `Saved` branch is not merely asserted but real.
//!
//! ## Worker-event correlation (the bug tasks 4.20/4.21/4.22 all hit)
//! [`handle_worker`] only applies a `Completed`/`Failed` event whose carried
//! [`SaveSettingRequest::value`]'s own [`SettingValue::field`] matches the [`SettingField`] this
//! screen is currently [`SettingsMode::Saving`] for — a stale completion for a field this screen is
//! no longer waiting on (unreachable today, since [`SettingsMode::Saving`] blocks all further input
//! including `Esc` until it resolves — mirrors `crate::screens::contact_detail::DetailMode`'s
//! identical in-flight blocking — but defense-in-depth per the lesson those three tasks already
//! documented) is silently ignored, never applied to the wrong row.
//!
//! ## Not yet wired into live navigation
//! Per the task file: `PaletteRegistry::find_binding` is not yet called from `crate::app::App::
//! handle_key` at all (deferred to task 4.25). This screen exists fully wired
//! (`handle_key`/`handle_worker`/`render` all dispatch to it from `crate::app`) and independently
//! reachable via `crate::app::App::push_screen`, exactly like `crate::screens::verify` before its
//! own navigation-integration task — see `crate::app::Screen::Settings`'s own doc comment.
//!
//! ## Config path travels with the screen, not re-derived
//! [`SettingsState::new`] takes `config`/`config_path` directly (already loaded — mirrors
//! `crate::screens::verify::VerifyState::new`'s identical "constructed with what it needs" shape)
//! rather than calling `crate::config::default_config_path`/`load` itself: this crate's `update`
//! never performs I/O (see the crate-level module doc), and a future Preflight step is what will
//! thread the one real, already-loaded `TuiConfig` this process started with into this screen,
//! exactly as it will for every other screen currently constructed only via `push_screen` in tests.

use std::path::PathBuf;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{
    Effect, SaveSettingEffect, SaveSettingRequest, SettingField, SettingValue, WorkerEvent,
};
use crate::config::{Bell, NetworkPolicy, Theme, Timestamps, TuiConfig};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The full, fixed, display-order list of editable rows — every field named in the task's own
/// scope, and no others.
const FIELDS: [SettingField; 8] = [
    SettingField::ServerUrl,
    SettingField::RelayPolicy,
    SettingField::Theme,
    SettingField::Timestamps,
    SettingField::Bell,
    SettingField::RetainDays,
    SettingField::MaxMessagesPerConversation,
    SettingField::ReconnectBackoffMs,
];

/// Whether the most recently resolved save actually landed on disk — see the module doc's "never
/// silent" section. `pub` so tests can assert on this typed outcome directly rather than parsing
/// `notice`'s prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistOutcome {
    Saved,
    SessionOnly,
}

#[derive(Debug, Clone)]
pub struct SettingsState {
    /// The in-memory config this screen edits — see the module doc for why every change is applied
    /// here synchronously, regardless of whether the on-disk write later succeeds.
    pub config: TuiConfig,
    pub config_path: PathBuf,
    pub selected: usize,
    pub mode: SettingsMode,
    /// A human-readable line describing the outcome of the most recently resolved save — always set
    /// (never left over from a previous field's outcome) the instant a save resolves; see
    /// [`handle_worker`].
    pub notice: Option<String>,
    /// The typed counterpart to `notice` — see [`PersistOutcome`]'s own doc.
    pub last_persist: Option<PersistOutcome>,
}

#[derive(Debug, Clone)]
pub enum SettingsMode {
    List,
    /// Free-text editing for the four non-enum fields — `input` starts pre-filled with the field's
    /// current textual representation (see [`initial_edit_text`]).
    EditText {
        field: SettingField,
        input: String,
    },
    /// A save is in flight for `field` — mirrors
    /// `crate::screens::contact_detail::DetailMode::SavingPetname`'s identical "no input to give
    /// while an effect is out" blocking, including `Esc`.
    Saving(SettingField),
    /// A validation failure (never a config-write failure — that's `Saving`'s `Failed` outcome,
    /// which resolves back to `List` with `notice` set, not this mode) on committing an `EditText`
    /// buffer.
    Error(String),
}

impl SettingsState {
    pub fn new(config: TuiConfig, config_path: PathBuf) -> Self {
        Self {
            config,
            config_path,
            selected: 0,
            mode: SettingsMode::List,
            notice: None,
            last_persist: None,
        }
    }

    fn selected_field(&self) -> SettingField {
        FIELDS[self.selected]
    }
}

// ---------------------------------------------------------------------------
// Field metadata
// ---------------------------------------------------------------------------

fn field_label(field: SettingField) -> &'static str {
    match field {
        SettingField::ServerUrl => "server URL",
        SettingField::RelayPolicy => "relay policy",
        SettingField::Theme => "theme",
        SettingField::Timestamps => "timestamps",
        SettingField::Bell => "bell",
        SettingField::RetainDays => "retain history (days, 0 = forever)",
        SettingField::MaxMessagesPerConversation => "max messages per conversation (0 = unlimited)",
        SettingField::ReconnectBackoffMs => "reconnect backoff (ms, comma-separated)",
    }
}

/// Whether `field` is edited via free text ([`SettingsMode::EditText`]) rather than cycled in place
/// on `Enter` from [`SettingsMode::List`].
fn is_text_field(field: SettingField) -> bool {
    matches!(
        field,
        SettingField::ServerUrl
            | SettingField::RetainDays
            | SettingField::MaxMessagesPerConversation
            | SettingField::ReconnectBackoffMs
    )
}

fn field_value_display(config: &TuiConfig, field: SettingField) -> String {
    match field {
        SettingField::ServerUrl => config
            .account
            .server
            .clone()
            .unwrap_or_else(|| "(inherit from registration)".to_string()),
        SettingField::RelayPolicy => network_policy_str(config.network.policy).to_string(),
        SettingField::Theme => theme_str(config.ui.theme).to_string(),
        SettingField::Timestamps => timestamps_str(config.ui.timestamps).to_string(),
        SettingField::Bell => bell_str(config.ui.bell).to_string(),
        SettingField::RetainDays => {
            if config.history.retain_days == 0 {
                "forever".to_string()
            } else {
                format!("{} days", config.history.retain_days)
            }
        }
        SettingField::MaxMessagesPerConversation => {
            if config.history.max_messages_per_conversation == 0 {
                "unlimited".to_string()
            } else {
                config.history.max_messages_per_conversation.to_string()
            }
        }
        SettingField::ReconnectBackoffMs => {
            if config.network.reconnect_backoff_ms.is_empty() {
                "(none)".to_string()
            } else {
                let parts: Vec<String> = config
                    .network
                    .reconnect_backoff_ms
                    .iter()
                    .map(u64::to_string)
                    .collect();
                format!("{} ms", parts.join(", "))
            }
        }
    }
}

fn initial_edit_text(config: &TuiConfig, field: SettingField) -> String {
    match field {
        SettingField::ServerUrl => config.account.server.clone().unwrap_or_default(),
        SettingField::RetainDays => config.history.retain_days.to_string(),
        SettingField::MaxMessagesPerConversation => {
            config.history.max_messages_per_conversation.to_string()
        }
        SettingField::ReconnectBackoffMs => config
            .network
            .reconnect_backoff_ms
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        // Not a text field — never actually read for the other four.
        SettingField::RelayPolicy
        | SettingField::Theme
        | SettingField::Timestamps
        | SettingField::Bell => String::new(),
    }
}

/// The largest value [`parse_edit_text`] accepts for a single `ReconnectBackoffMs` element: 24
/// hours in milliseconds — already a generous ceiling for a *reconnect delay*, and, more load-
/// bearingly, comfortably clear of `i64::MAX`. `crate::config_write::target()` narrows each element
/// with `as i64` before handing it to `toml_edit::value` (TOML integers are signed 64-bit); any raw
/// `u64` value above `i64::MAX` would silently wrap negative on that cast, writing a `config.toml`
/// that `crate::config::load_from` (which expects `u64`) then refuses to parse on the next launch —
/// an unrecoverable-without-hand-editing state. Rejecting out-of-range values here, before they ever
/// reach `config_write`, is the fix.
const MAX_RECONNECT_BACKOFF_MS: u64 = 24 * 60 * 60 * 1000;

/// Parses `input` (as committed from [`SettingsMode::EditText`]) into a [`SettingValue`] for `field`
/// — `Err` (validation failure, never touches `state.config`) with a human-readable reason on a bad
/// number/list, mirroring `crate::screens::onboarding`'s `validate_hint` gate.
fn parse_edit_text(field: SettingField, input: &str) -> Result<SettingValue, String> {
    match field {
        SettingField::ServerUrl => {
            let trimmed = input.trim();
            let value = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
            Ok(SettingValue::ServerUrl(value))
        }
        SettingField::RetainDays => input
            .trim()
            .parse::<u32>()
            .map(SettingValue::RetainDays)
            .map_err(|_| "enter a whole number of days (0 = forever)".to_string()),
        SettingField::MaxMessagesPerConversation => input
            .trim()
            .parse::<u32>()
            .map(SettingValue::MaxMessagesPerConversation)
            .map_err(|_| "enter a whole number (0 = unlimited)".to_string()),
        SettingField::ReconnectBackoffMs => {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return Ok(SettingValue::ReconnectBackoffMs(Vec::new()));
            }
            let mut values = Vec::new();
            for part in trimmed.split(',') {
                let part = part.trim();
                let n: u64 = part
                    .parse()
                    .map_err(|_| format!("'{part}' is not a whole number of milliseconds"))?;
                if n > MAX_RECONNECT_BACKOFF_MS {
                    return Err(format!(
                        "'{part}' is too large for a reconnect backoff (max \
                         {MAX_RECONNECT_BACKOFF_MS} ms, about 24 hours)"
                    ));
                }
                values.push(n);
            }
            Ok(SettingValue::ReconnectBackoffMs(values))
        }
        SettingField::RelayPolicy
        | SettingField::Theme
        | SettingField::Timestamps
        | SettingField::Bell => Err("not a text field".to_string()),
    }
}

fn cycle_value(config: &TuiConfig, field: SettingField) -> Option<SettingValue> {
    match field {
        SettingField::RelayPolicy => Some(SettingValue::RelayPolicy(next_policy(
            config.network.policy,
        ))),
        SettingField::Theme => Some(SettingValue::Theme(next_theme(config.ui.theme))),
        SettingField::Timestamps => Some(SettingValue::Timestamps(next_timestamps(
            config.ui.timestamps,
        ))),
        SettingField::Bell => Some(SettingValue::Bell(next_bell(config.ui.bell))),
        _ => None,
    }
}

fn next_policy(current: NetworkPolicy) -> NetworkPolicy {
    match current {
        NetworkPolicy::Inherit => NetworkPolicy::Direct,
        NetworkPolicy::Direct => NetworkPolicy::PreferRelay,
        NetworkPolicy::PreferRelay => NetworkPolicy::RelayOnly,
        NetworkPolicy::RelayOnly => NetworkPolicy::Inherit,
    }
}

fn next_theme(current: Theme) -> Theme {
    match current {
        Theme::Auto => Theme::Dark,
        Theme::Dark => Theme::Light,
        Theme::Light => Theme::Mono,
        Theme::Mono => Theme::Auto,
    }
}

fn next_timestamps(current: Timestamps) -> Timestamps {
    match current {
        Timestamps::Relative => Timestamps::Clock,
        Timestamps::Clock => Timestamps::Off,
        Timestamps::Off => Timestamps::Relative,
    }
}

fn next_bell(current: Bell) -> Bell {
    match current {
        Bell::Never => Bell::Message,
        Bell::Message => Bell::Mention,
        Bell::Mention => Bell::Never,
    }
}

fn network_policy_str(p: NetworkPolicy) -> &'static str {
    match p {
        NetworkPolicy::Inherit => "inherit",
        NetworkPolicy::Direct => "direct",
        NetworkPolicy::PreferRelay => "prefer-relay",
        NetworkPolicy::RelayOnly => "relay-only",
    }
}

fn theme_str(t: Theme) -> &'static str {
    match t {
        Theme::Auto => "auto",
        Theme::Dark => "dark",
        Theme::Light => "light",
        Theme::Mono => "mono",
    }
}

fn timestamps_str(t: Timestamps) -> &'static str {
    match t {
        Timestamps::Relative => "relative",
        Timestamps::Clock => "clock",
        Timestamps::Off => "off",
    }
}

fn bell_str(b: Bell) -> &'static str {
    match b {
        Bell::Never => "never",
        Bell::Message => "message",
        Bell::Mention => "mention",
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the effects (if any) and whether `App` should pop this screen —
/// `true` only for a plain `Esc` while [`SettingsMode::List`] (this screen is always pushed on top
/// of something else). `Esc` in every other sub-mode instead cancels back to `List` without leaving
/// the screen, except [`SettingsMode::Saving`], which accepts no input at all until it resolves —
/// see the module doc.
pub fn handle_key(state: &mut SettingsState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match state.mode.clone() {
        SettingsMode::List => handle_list_key(state, key),
        SettingsMode::EditText { field, input } => handle_edit_text_key(state, field, input, key),
        SettingsMode::Saving(_) => (Vec::new(), false),
        SettingsMode::Error(_) => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                state.mode = SettingsMode::List;
            }
            (Vec::new(), false)
        }
    }
}

fn handle_list_key(state: &mut SettingsState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Esc => return (Vec::new(), true),
        KeyCode::Up | KeyCode::Char('k') if is_plain_char(key.modifiers) => {
            state.selected = state.selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if is_plain_char(key.modifiers) => {
            if state.selected + 1 < FIELDS.len() {
                state.selected += 1;
            }
        }
        KeyCode::Enter => {
            let field = state.selected_field();
            if let Some(value) = cycle_value(&state.config, field) {
                return (apply_change(state, value), false);
            }
            if is_text_field(field) {
                state.mode = SettingsMode::EditText {
                    field,
                    input: initial_edit_text(&state.config, field),
                };
            }
        }
        _ => {}
    }
    (Vec::new(), false)
}

fn handle_edit_text_key(
    state: &mut SettingsState,
    field: SettingField,
    mut input: String,
    key: KeyEvent,
) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Esc => {
            state.mode = SettingsMode::List;
            return (Vec::new(), false);
        }
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => input.push(c),
        KeyCode::Enter => match parse_edit_text(field, &input) {
            Ok(value) => return (apply_change(state, value), false),
            Err(message) => {
                state.mode = SettingsMode::Error(message);
                return (Vec::new(), false);
            }
        },
        _ => {}
    }
    state.mode = SettingsMode::EditText { field, input };
    (Vec::new(), false)
}

/// Applies `value` to [`SettingsState::config`] synchronously and dispatches the matching
/// [`Effect::SaveSetting`] — the "apply now, persist later" split the module doc describes. The
/// **only** function in this module that ever mutates `state.config` or transitions into
/// [`SettingsMode::Saving`].
fn apply_change(state: &mut SettingsState, value: SettingValue) -> Vec<Effect> {
    let field = value.field();
    value.apply_to(&mut state.config);
    state.mode = SettingsMode::Saving(field);
    vec![Effect::SaveSetting(SaveSettingEffect {
        request: SaveSettingRequest {
            config_path: state.config_path.clone(),
            value,
        },
        outcome: None,
    })]
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`] arriving while this screen is current — see the module doc's "never
/// silent" and "worker-event correlation" sections. Never itself produces a further `Effect`.
pub fn handle_worker(state: &mut SettingsState, event: WorkerEvent) -> Vec<Effect> {
    if let SettingsMode::Saving(field) = state.mode {
        match event {
            WorkerEvent::Completed(Effect::SaveSetting(SaveSettingEffect { request, .. }))
                if request.value.field() == field =>
            {
                state.notice = Some(format!("{} saved to config.toml", field_label(field)));
                state.last_persist = Some(PersistOutcome::Saved);
                state.mode = SettingsMode::List;
            }
            WorkerEvent::Failed(
                Effect::SaveSetting(SaveSettingEffect { request, .. }),
                message,
            ) if request.value.field() == field => {
                state.notice = Some(format!(
                    "{} — session-only, not saved to config.toml: {message}",
                    field_label(field)
                ));
                state.last_persist = Some(PersistOutcome::SessionOnly);
                state.mode = SettingsMode::List;
            }
            _ => {}
        }
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — see the module doc.
pub fn render(state: &SettingsState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Settings");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let lines = body_lines(state);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), rows[0]);

    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

fn body_lines(state: &SettingsState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, field) in FIELDS.iter().copied().enumerate() {
        let selected = i == state.selected;
        let cursor = if selected { "> " } else { "  " };
        let text = format!(
            "{cursor}{}: {}",
            field_label(field),
            field_value_display(&state.config, field)
        );
        let style = if selected {
            Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(text, style)));
    }

    lines.push(Line::from(""));
    match &state.mode {
        SettingsMode::List => {}
        SettingsMode::EditText { field, input } => {
            lines.push(Line::from(format!(
                "new value for {}: {input}",
                field_label(*field)
            )));
        }
        SettingsMode::Saving(field) => {
            lines.push(Line::from(format!(
                "saving {}, please wait…",
                field_label(*field)
            )));
        }
        SettingsMode::Error(message) => {
            lines.push(Line::from(Span::styled(
                message.clone(),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from("Press Enter or Esc to continue."));
        }
    }

    if let Some(notice) = &state.notice {
        let color = match state.last_persist {
            Some(PersistOutcome::Saved) => Color::Green,
            Some(PersistOutcome::SessionOnly) => Color::Yellow,
            None => Color::Reset,
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            notice.clone(),
            Style::default().fg(color),
        )));
    }

    lines
}

fn footer_hint(state: &SettingsState) -> String {
    match &state.mode {
        SettingsMode::List => "↑/↓ select · Enter edit/cycle · Esc back".to_string(),
        SettingsMode::EditText { .. } => "type new value · Enter save · Esc cancel".to_string(),
        SettingsMode::Saving(_) => "please wait…".to_string(),
        SettingsMode::Error(_) => "Enter/Esc continue".to_string(),
    }
}
