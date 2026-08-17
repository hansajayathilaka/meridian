//! The command palette (task 4.25): `Ctrl+K`, fuzzy-searchable, listing every
//! [`crate::surface::PaletteCommand`] registered in the [`PaletteRegistry`] snapshot taken when it is
//! pushed — the palette and [`crate::screens::help`] both read from the same registry
//! ([`crate::surface`]'s own module doc: "the (future) palette and help screens both read from"), so
//! neither can list a command the other doesn't.
//!
//! ## Dispatch: this screen decides *what*, `App` decides *how*
//! Selecting a command and pressing `Enter` never runs anything itself: [`handle_key`] returns
//! [`PaletteOutcome::Run`] carrying the selected [`PaletteAction`], and only `crate::app::App` — the
//! one thing with `push_screen` access — actually dispatches it (`App::dispatch_palette_action`),
//! either handing an [`Effect`] to the worker or pushing the [`crate::surface::ExtensionPane`] a
//! `PushPane` factory builds. **This is why the palette is a dedicated [`crate::app::Screen`] variant
//! rather than a `Screen::Extension` pane** like the panes it opens:
//! [`crate::surface::ExtensionPane::handle_key`] can only return `Vec<Effect>`, with no way back to
//! the screen stack — a pane cannot push another pane itself, only `App` can. The same reasoning
//! applies to [`crate::screens::help`] (kept as a dedicated variant too, for the same construction
//! shape, even though it never itself needs to push anything).
//!
//! ## Fuzzy filter, deliberately simple
//! [`PaletteState::filtered`] is a case-insensitive, in-order *subsequence* match against each
//! command's name and description combined — the smallest thing that can honestly be called "fuzzy"
//! (`fzf`'s minimal core idea), not a scored/ranked matcher. Good enough for the tiny command counts
//! this crate registers today; a ranking pass is a straightforward, purely additive improvement for a
//! later task if the registered set ever grows large enough to need one.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Effect, WorkerEvent};
use crate::surface::{PaletteAction, PaletteCommand, PaletteRegistry};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The whole Palette screen's state: a snapshot of the registry at push time, plus the in-progress
/// filter query and the currently selected row within the *filtered* list. See the module doc for why
/// this is a snapshot rather than a live `&PaletteRegistry` (mirrors
/// [`crate::screens::help::HelpState`]'s identical choice).
#[derive(Debug, Clone)]
pub struct PaletteState {
    pub commands: PaletteRegistry,
    pub query: String,
    pub selected: usize,
}

impl PaletteState {
    pub fn new(commands: PaletteRegistry) -> Self {
        Self {
            commands,
            query: String::new(),
            selected: 0,
        }
    }

    /// The commands currently matching [`PaletteState::query`], in registry (id) order — see the
    /// module doc's "fuzzy filter" section. Empty query matches everything. `pub` so
    /// `tests/screens_help_palette.rs` can assert on filtering directly.
    pub fn filtered(&self) -> Vec<&PaletteCommand> {
        self.commands
            .iter()
            .filter(|c| fuzzy_match(&self.query, &format!("{} {}", c.name, c.description)))
            .collect()
    }
}

/// Case-insensitive, in-order subsequence match: every character of `query`, in order, must appear
/// somewhere in `haystack` (not necessarily contiguous). An empty query matches everything.
fn fuzzy_match(query: &str, haystack: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let haystack_lower = haystack.to_lowercase();
    let mut hay_iter = haystack_lower.chars();
    for qc in query.to_lowercase().chars() {
        let mut found = false;
        for hc in hay_iter.by_ref() {
            if hc == qc {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

/// What [`handle_key`] asks `App` to do next — mirrors `crate::screens::contacts::ContactsAction`'s
/// shape (a screen reporting a navigation intent it cannot itself carry out).
#[derive(Debug, Clone)]
pub enum PaletteOutcome {
    /// Nothing for `App` to do beyond applying `handle_key`'s own state mutation.
    None,
    /// `Esc` — `App` should pop this screen.
    Close,
    /// `Enter` on a selected command — `App` should dispatch this action
    /// (`App::dispatch_palette_action`) and then pop this screen (selecting a command always closes
    /// the palette, the same "act, then get out of the way" shape every confirm-then-act screen in
    /// this crate already uses).
    Run(PaletteAction),
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the effects (always empty — this screen itself never dispatches an
/// effect directly, only reports one via [`PaletteOutcome::Run`] for `App` to dispatch) and the
/// [`PaletteOutcome`] describing what `App` should do next.
pub fn handle_key(state: &mut PaletteState, key: KeyEvent) -> (Vec<Effect>, PaletteOutcome) {
    match key.code {
        KeyCode::Esc => (Vec::new(), PaletteOutcome::Close),
        KeyCode::Up => {
            state.selected = state.selected.saturating_sub(1);
            (Vec::new(), PaletteOutcome::None)
        }
        KeyCode::Down => {
            let len = state.filtered().len();
            if len > 0 && state.selected + 1 < len {
                state.selected += 1;
            }
            (Vec::new(), PaletteOutcome::None)
        }
        KeyCode::Backspace => {
            state.query.pop();
            state.selected = 0;
            (Vec::new(), PaletteOutcome::None)
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => {
            state.query.push(c);
            state.selected = 0;
            (Vec::new(), PaletteOutcome::None)
        }
        KeyCode::Enter => {
            let action = state
                .filtered()
                .get(state.selected)
                .map(|c| c.action.clone());
            match action {
                Some(action) => (Vec::new(), PaletteOutcome::Run(action)),
                None => (Vec::new(), PaletteOutcome::None),
            }
        }
        _ => (Vec::new(), PaletteOutcome::None),
    }
}

/// This screen dispatches no effects itself, so it never has one to correlate a [`WorkerEvent`]
/// against.
pub fn handle_worker(_state: &mut PaletteState, _event: WorkerEvent) -> Vec<Effect> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — see the module doc.
pub fn render(state: &PaletteState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Palette");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(format!("> {}", state.query))),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new(body_lines(state)).wrap(Wrap { trim: false }),
        rows[1],
    );

    let footer = Paragraph::new(Line::from(Span::styled(
        "type to filter · ↑/↓ select · Enter run · Esc close",
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[2]);
}

fn body_lines(state: &PaletteState) -> Vec<Line<'static>> {
    let filtered = state.filtered();
    if filtered.is_empty() {
        return vec![Line::from("no matching commands")];
    }
    filtered
        .into_iter()
        .enumerate()
        .map(|(i, command)| {
            let cursor = if i == state.selected { "> " } else { "  " };
            let binding = command
                .keybinding
                .map(|b| b.to_string())
                .unwrap_or_else(|| "—".to_string());
            let text = format!(
                "{cursor}{binding:<10} {} — {}",
                command.name, command.description
            );
            let style = if i == state.selected {
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::default()
            };
            Line::from(Span::styled(text, style))
        })
        .collect()
}
