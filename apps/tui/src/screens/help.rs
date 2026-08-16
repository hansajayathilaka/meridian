//! The help screen (task 4.25): `F1`, generated from a snapshot of the live
//! [`crate::surface::PaletteRegistry`] taken when it is pushed — **never hand-written**, so a future
//! feature that registers a new [`crate::surface::PaletteCommand`] needs no edit here to become
//! discoverable (tui-client.md §3: "the help screen is generated from the binding table"). The
//! dynamic section of [`body_lines`] is literally `state.commands.iter()` walked and formatted;
//! nothing about a specific command's name/description/binding is duplicated by hand anywhere in this
//! module.
//!
//! ## The one hand-written section, and why it does not violate "generated, never hand-written"
//! [`GLOBAL_KEYS`] — `F1`/`Ctrl+K`/`Ctrl+Q`/`Ctrl+R`/`Esc` — is the one static part of this screen's
//! content. `F1`/`Ctrl+K`/`Ctrl+Q`/`Ctrl+R` really are `crate::app::App::handle_key`'s own hardcoded,
//! unconditional global checks (the same tier `Ctrl+Q` already occupied before this task; `F1`/
//! `Ctrl+K` join it, per the task's own addendum) — checked ahead of every screen's own handling,
//! regardless of which screen is on top. `Esc` is different from the other four: every screen decides
//! its own meaning for it in `App::handle_key`'s per-`Screen` match arms (most converge on "pop the
//! screen stack", but e.g. onboarding/unlock treat it as "go back one sub-step", and several screens
//! cancel an in-flight nested mode instead of leaving); it is listed here as the aggregate, common-case
//! behavior a user actually experiences, not as a claim that a single hardcoded check handles it the
//! way the other four chords are. Since nothing in this crate consults `config.toml`'s `[keys]` rebind
//! map yet (see `crate::config`'s own module doc), none of these five is rebindable today.
//! [`crate::surface::PaletteCommand::keybinding`]'s own doc comment is what names "the binding table"
//! this task must generate from; these five chords are structurally outside that table, not a
//! hand-written duplicate of part of it.
//!
//! **`Tab`/`Shift+Tab` are deliberately not listed here**, unlike `docs/architecture/tui-client.md
//! §3`'s own "Global" row, which names them "cycle panes" / "cycle panes (reverse)" — that row
//! describes an aspiration this crate has not built: `App::handle_key` has no global check for either
//! key. `Tab` is instead handled independently, per screen, with a different meaning each time
//! (toggles composer/transcript focus in `crate::screens::chat`, id/QR-path focus in
//! `crate::screens::contacts`, server/invite focus in `crate::screens::onboarding`), and
//! `Shift+Tab`/`BackTab` is not handled anywhere in this crate's screen logic at all — pressing it
//! today does nothing. Listing them here as working global chords would be exactly the "help screen
//! goes stale" failure this whole "generated, never hand-written" design exists to prevent, so
//! `GLOBAL_KEYS` only ever names chords `App::handle_key` genuinely treats as global (or, for `Esc`,
//! genuinely converges on across screens) — see
//! `screens_help_palette.rs`'s own
//! `global_keys_chords_reproduce_their_own_documented_effect_in_a_real_app` for the regression test
//! pinning this against real `App` behavior, not just this constant's own text.
//!
//! Consequently this section does **not** "match tui-client.md §3's 'Global' row exactly" — it is a
//! narrower, accurate subset of it (that row's `Tab`/`S-Tab` are omitted as unbuilt, above; that row
//! also omits `Ctrl+R`, which this crate documents here instead, since §3's own table lists `^R` only
//! on the Requests screen's row, not the Global row — both tables describe real, current behavior,
//! just organized differently).
//!
//! The *extensible* part — every registered command, present and future — is exactly what the dynamic
//! section below generates mechanically, which is the property the task's own acceptance test
//! (`tests/screens_help_palette.rs`) pins.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::{Effect, WorkerEvent};
use crate::surface::PaletteRegistry;

/// The fixed, hand-written global keys — see the module doc for why these, and only these, are not
/// generated from [`PaletteRegistry`], and for why this is an accurate subset of tui-client.md §3's
/// "Global" row rather than an exact match of it.
pub const GLOBAL_KEYS: [(&str, &str); 5] = [
    ("F1", "open this help screen"),
    ("Ctrl+K", "open the command palette"),
    ("Ctrl+Q", "quit"),
    ("Ctrl+R", "open message requests"),
    ("Esc", "back / close overlay"),
];

/// The whole Help screen's state: a snapshot of the registry at push time. Not a live reference —
/// see [`crate::screens::palette::PaletteState`]'s identical choice for the same reasoning (a
/// snapshot is simple, `Clone`-cheap for this crate's registry sizes today, and consistent with how
/// this crate never stores `&App` inside a screen anywhere else).
#[derive(Debug, Clone)]
pub struct HelpState {
    pub commands: PaletteRegistry,
}

impl HelpState {
    pub fn new(commands: PaletteRegistry) -> Self {
        Self { commands }
    }
}

/// Handles one key event. `Esc` is the only interactive behavior — this screen has nothing to edit,
/// select, or confirm. Returns whether `App` should pop this screen, mirroring every other screen's
/// `(Vec<Effect>, bool)` contract even though the `Vec<Effect>` half is always empty here.
pub fn handle_key(_state: &mut HelpState, key: KeyEvent) -> (Vec<Effect>, bool) {
    (Vec::new(), key.code == KeyCode::Esc)
}

/// This screen dispatches no effects, so it never has one to correlate a [`WorkerEvent`] against.
pub fn handle_worker(_state: &mut HelpState, _event: WorkerEvent) -> Vec<Effect> {
    Vec::new()
}

/// Pure view function — see the module doc.
pub fn render(state: &HelpState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Help");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(body_lines(state)).wrap(Wrap { trim: false }),
        rows[0],
    );

    let footer = Paragraph::new(Line::from(Span::styled(
        "Esc back",
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

fn body_lines(state: &HelpState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "Global",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    for (key, desc) in GLOBAL_KEYS {
        lines.push(Line::from(format!("  {key:<12} {desc}")));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Commands",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    if state.commands.iter().count() == 0 {
        lines.push(Line::from("  (none registered yet)"));
    }
    for command in state.commands.iter() {
        let binding = command
            .keybinding
            .map(|b| b.to_string())
            .unwrap_or_else(|| "palette only".to_string());
        lines.push(Line::from(format!(
            "  {binding:<12} {} — {}",
            command.name, command.description
        )));
    }
    lines
}
