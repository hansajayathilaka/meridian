//! The Elm-style application core: `App` owns all state, `update` is a synchronous, pure state
//! transition, and `render` is a pure view function. **Neither ever performs I/O or awaits** — see
//! docs/architecture/tui-client.md §4. This is what makes `App::render` testable headlessly through
//! `ratatui::backend::TestBackend` (the basis for every screen-snapshot test from 4.16 onward).
//!
//! Screens are placeholders at this stage (scope of 4.11); real screen content lands in 4.16+.

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Events the runtime feeds into [`App::update`]. Produced by crossterm input, the worker-response
/// channel, or the 250ms tick — see the event-loop diagram in tui-client.md §4.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Fired every 250ms so the UI can animate/expire things without new input.
    Tick,
    /// A raw key event from crossterm.
    Key(KeyEvent),
    /// The terminal was resized to (columns, rows).
    Resize(u16, u16),
    /// Bracketed-paste text from crossterm.
    Paste(String),
    /// A worker task finished (or failed) executing an [`Effect`].
    Worker(WorkerEvent),
}

/// The only path from `update` to the network, the keystore, or disk. A worker task executes these
/// and reports the outcome back as [`WorkerEvent`] / [`AppEvent::Worker`], so a slow rendezvous can
/// never freeze the UI. Variants are placeholders at this stage — payloads (recipient, stream body,
/// bundle bytes, …) land with the tasks that give each effect real behavior (composer/session wiring,
/// 4.14/4.15 store, 4.16+ screens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    SendMessage,
    FetchBundle,
    PublishBundle,
    PersistHistory,
    Unlock,
}

/// The outcome of a worker task executing an [`Effect`], reported back as [`AppEvent::Worker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEvent {
    Completed(Effect),
    Failed(Effect, String),
}

/// A screen on the navigation stack. Placeholder-only until 4.16+ (see tui-client.md §2 for the
/// full set: Onboarding, Unlock, Main, Add contact, Requests, Verify, Contact detail, Settings,
/// Diagnostics, Help, Palette).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Stand-in root screen until real screens land.
    Placeholder,
}

/// Owns all application state. Constructed once by the runtime; `update` and `render` are the only
/// two ways anything reaches or reads it.
#[derive(Debug)]
pub struct App {
    screens: Vec<Screen>,
    should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            screens: vec![Screen::Placeholder],
            should_quit: false,
        }
    }

    /// Whether the runtime should stop the event loop and let the [`crate::terminal::TerminalGuard`]
    /// restore the terminal.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// The screen currently on top of the stack.
    pub fn current_screen(&self) -> Screen {
        *self.screens.last().unwrap_or(&Screen::Placeholder)
    }

    /// Pushes a new screen on top of the stack (overlays render on top without unmounting what's
    /// beneath — tui-client.md §2).
    pub fn push_screen(&mut self, screen: Screen) {
        self.screens.push(screen);
    }

    /// Pops the top screen, unless it is the last one (there is always a root screen to render).
    /// Returns the popped screen, if any.
    pub fn pop_screen(&mut self) -> Option<Screen> {
        if self.screens.len() > 1 {
            self.screens.pop()
        } else {
            None
        }
    }

    /// The one and only state transition function. Synchronous, pure apart from mutating `self` —
    /// no I/O, no `.await`. Returns the [`Effect`]s (if any) the runtime's worker task should
    /// execute as a result of this event.
    pub fn update(&mut self, event: AppEvent) -> Vec<Effect> {
        match event {
            AppEvent::Key(key) => self.handle_key(key),
            AppEvent::Tick | AppEvent::Resize(_, _) | AppEvent::Paste(_) | AppEvent::Worker(_) => {
                Vec::new()
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Vec<Effect> {
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), m) if m.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            (KeyCode::Esc, _) => {
                self.pop_screen();
            }
            _ => {}
        }
        Vec::new()
    }

    /// The one and only view function. Pure — no I/O, no `.await` — so it can run against a real
    /// terminal or `ratatui::backend::TestBackend` identically.
    pub fn render(&self, frame: &mut Frame<'_>) {
        let area = frame.area();
        let title = format!("Meridian — {:?}", self.current_screen());
        let block = Block::default().borders(Borders::ALL).title(title);
        let body = Paragraph::new(Line::from("screen content lands in 4.16+"))
            .style(Style::default().add_modifier(Modifier::DIM))
            .alignment(Alignment::Center)
            .block(block);
        frame.render_widget(body, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn new_app_has_one_placeholder_screen() {
        let app = App::new();
        assert_eq!(app.current_screen(), Screen::Placeholder);
        assert!(!app.should_quit());
    }

    #[test]
    fn ctrl_q_sets_should_quit_and_emits_no_effects() {
        let mut app = App::new();
        let effects = app.update(AppEvent::Key(key(
            KeyCode::Char('q'),
            KeyModifiers::CONTROL,
        )));
        assert!(effects.is_empty());
        assert!(app.should_quit());
    }

    #[test]
    fn plain_q_does_not_quit() {
        let mut app = App::new();
        app.update(AppEvent::Key(key(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(!app.should_quit());
    }

    #[test]
    fn esc_pops_screen_but_never_below_the_root() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        assert_eq!(app.screens.len(), 2);

        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.screens.len(), 1);

        // Popping the last screen is a no-op — there is always a root screen to render.
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.screens.len(), 1);
    }

    #[test]
    fn tick_resize_paste_and_worker_events_are_no_ops_for_now() {
        let mut app = App::new();
        assert!(app.update(AppEvent::Tick).is_empty());
        assert!(app.update(AppEvent::Resize(80, 24)).is_empty());
        assert!(app.update(AppEvent::Paste("hi".into())).is_empty());
        assert!(app
            .update(AppEvent::Worker(WorkerEvent::Completed(
                Effect::FetchBundle
            )))
            .is_empty());
        assert!(!app.should_quit());
    }

    /// `render` must be usable against an in-memory backend with no real terminal — the property
    /// every later screen-snapshot test (4.16+) depends on.
    #[test]
    fn render_is_pure_and_works_against_test_backend() {
        let app = App::new();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }
}
