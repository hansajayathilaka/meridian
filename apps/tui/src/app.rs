//! The Elm-style application core: `App` owns all state, `update` is a synchronous, pure state
//! transition, and `render` is a pure view function. **Neither ever performs I/O or awaits** — see
//! docs/architecture/tui-client.md §4. This is what makes `App::render` testable headlessly through
//! `ratatui::backend::TestBackend` (the basis for every screen-snapshot test from 4.16 onward).
//!
//! Screen content lives in [`crate::screens`] — one module per [`Screen`] variant, each owning its
//! own sub-state, `update`, and `render`; this module only dispatches to them and owns the pieces
//! that are genuinely global (quit, the screen stack).

use std::fmt;

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::screens::onboarding::{self, OnboardingState};

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

/// Which secret store an onboarding user chose to protect their private key with. The choice
/// itself performs no I/O — that only happens once a (future) worker executes
/// [`Effect::GenerateAccount`], via `meridian_core::identity::{FileSecretStore, OsSecretStore}`,
/// mirroring `apps/cli/src/main.rs::cmd_new`'s two branches (and its `OS_KEYSTORE_SERVICE`/default
/// keyfile location — onboarding doesn't ask the user for a custom path, only the choice of kind
/// and, for `File`, the passphrase).
#[derive(Clone, PartialEq, Eq)]
pub enum StoreChoice {
    Os,
    File { passphrase: String },
}

impl fmt::Debug for StoreChoice {
    /// Hand-rolled rather than derived: `File`'s `passphrase` must never appear in a `{:?}` dump
    /// (accidental `debug!()`/panic-message logging), even though [`Effect`] otherwise derives
    /// `Debug` freely — every type that embeds a [`StoreChoice`] inherits this redaction for free.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreChoice::Os => write!(f, "Os"),
            StoreChoice::File { .. } => write!(f, "File {{ passphrase: \"<redacted>\" }}"),
        }
    }
}

/// Inputs for onboarding's Generate sub-step (`Effect::GenerateAccount`): mint a fresh Ed25519
/// keypair via `meridian_core::identity::generate_account`, store the private seed in the chosen
/// [`StoreChoice`], and persist the non-secret `account.json` descriptor
/// (`meridian_core::account::AccountDescriptor`) — this crate's counterpart to
/// `apps/cli/src/main.rs::cmd_new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAccountRequest {
    pub store: StoreChoice,
    pub hint: String,
}

/// What generating an account actually produced. `update` cannot compute this itself — the keypair
/// is fresh randomness minted inside the worker's execution of [`Effect::GenerateAccount`] — so it
/// travels back inside the completed [`Effect`] for [`crate::screens::onboarding`] to pick up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAccount {
    /// Canonical `mrd1:…@hint` id string — public, safe to render/QR-encode.
    pub id: String,
    /// The store label (`KeyHandle::from_label`) — the public-key hex, same shape
    /// `AccountDescriptor::label` uses.
    pub label: String,
    /// Raw Ed25519 public key bytes, as `SignalingClient::connect`'s `account_pub` parameter wants
    /// them.
    pub account_pub: [u8; 32],
}

/// [`Effect::GenerateAccount`]'s payload: the request going out, and (once a worker has executed
/// it) the [`GeneratedAccount`] coming back. `outcome` is always `None` on the way out; a worker
/// populates it before wrapping this same value in `WorkerEvent::Completed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAccountEffect {
    pub request: GenerateAccountRequest,
    pub outcome: Option<GeneratedAccount>,
}

/// Inputs for onboarding's Register sub-step (`Effect::Register`): connect and authenticate to a
/// rendezvous server, optionally redeeming an invite token —
/// `meridian_core::signaling::SignalingClient::connect`, mirroring
/// `apps/cli/src/main.rs::cmd_register`'s connect half. Carries no separate outcome payload: the
/// request's own fields are everything [`Effect::PublishBundle`] needs next, and the mere fact this
/// arrived wrapped in `WorkerEvent::Completed` is the only signal `update` needs.
///
/// **Note for the worker that eventually executes this (not built by this task):** because an
/// invite token is normally single-use, the live, authenticated `SignalingClient` this effect's
/// execution produces must be the *same* connection [`Effect::PublishBundle`]'s execution publishes
/// through — re-connecting from scratch for the publish step would try to redeem the invite twice.
/// This is why this type and [`PublishBundleRequest`] both carry `account_pub: [u8; 32]` (alongside
/// `label`): it is the intended cache key for a worker to look up the `SignalingClient` opened by
/// this request's execution and reuse it for the later `PublishBundleRequest`, rather than
/// reconnecting — mirroring `apps/cli/src/main.rs::cmd_register`'s inline single-connection pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub server: String,
    pub invite: Option<String>,
    pub store: StoreChoice,
    pub label: String,
    pub account_pub: [u8; 32],
}

/// Inputs for onboarding's PublishBundle sub-step (`Effect::PublishBundle`): publish a fresh
/// prekey bundle over the already-registered session —
/// `meridian_core::signaling::SignalingClient::publish_bundle`, mirroring
/// `apps/cli/src/main.rs::cmd_register`'s publish half. Deliberately carries no `invite` field —
/// only [`RegisterRequest`]'s execution ever redeems one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBundleRequest {
    pub server: String,
    pub store: StoreChoice,
    pub label: String,
    pub account_pub: [u8; 32],
    pub otk_count: usize,
}

/// What publishing a bundle actually produced — how many one-time prekeys went out, for the
/// terminal success screen (mirrors `cmd_register`'s own "published bundle with N one-time
/// prekeys" line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedBundle {
    pub otk_count: usize,
}

/// [`Effect::PublishBundle`]'s payload — same request/outcome shape as
/// [`GenerateAccountEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBundleEffect {
    pub request: PublishBundleRequest,
    pub outcome: Option<PublishedBundle>,
}

/// The only path from `update` to the network, the keystore, or disk. A worker task executes these
/// and reports the outcome back as [`WorkerEvent`] / [`AppEvent::Worker`], so a slow rendezvous can
/// never freeze the UI. `SendMessage`/`FetchBundle`/`PersistHistory`/`Unlock` are still placeholders
/// (payloads land with the tasks that give each effect real behavior — composer/session wiring,
/// 4.17+); `GenerateAccount`/`Register`/`PublishBundle` are onboarding's (task 4.16) three
/// I/O-requiring sub-steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    SendMessage,
    FetchBundle,
    PublishBundle(PublishBundleEffect),
    PersistHistory,
    Unlock,
    GenerateAccount(GenerateAccountEffect),
    Register(RegisterRequest),
}

/// The outcome of a worker task executing an [`Effect`], reported back as [`AppEvent::Worker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEvent {
    Completed(Effect),
    Failed(Effect, String),
}

/// A screen on the navigation stack (tui-client.md §2 for the full eventual set: Onboarding,
/// Unlock, Main, Add contact, Requests, Verify, Contact detail, Settings, Diagnostics, Help,
/// Palette). [`Screen::Onboarding`] (task 4.16) is the first real one; every other screen is still
/// a stand-in until its own task lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// Stand-in root screen until real screens land — also onboarding's own completion target: a
    /// future task (4.19/4.20+) swaps this for `Screen::Main` without redesigning the onboarding
    /// flow that transitions into it (see [`App::handle_key`]'s onboarding-finished branch).
    Placeholder,
    /// Take a user with no `account.json` on disk to a registered, published identity — see
    /// [`crate::screens::onboarding`]. Boxed: `OnboardingState` is far larger than `Placeholder`
    /// (it carries whichever sub-step's fields — QR text, ids, form input — are live), and
    /// `clippy::large_enum_variant` flags the resulting size gap between `Screen`'s variants
    /// otherwise.
    Onboarding(Box<OnboardingState>),
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
    /// A fresh app starts on [`Screen::Onboarding`] — this crate has no way (yet) to detect an
    /// existing `account.json` and skip straight past it (that's the returning-user Unlock path,
    /// task 4.17, explicitly out of scope here) — so every run starts a new user from the top of
    /// the onboarding flow.
    pub fn new() -> Self {
        Self {
            screens: vec![Screen::Onboarding(Box::default())],
            should_quit: false,
        }
    }

    /// Whether the runtime should stop the event loop and let the [`crate::terminal::TerminalGuard`]
    /// restore the terminal.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// The screen currently on top of the stack.
    pub fn current_screen(&self) -> &Screen {
        self.screens
            .last()
            .expect("screens invariant: constructor pushes one, pop_screen never empties it")
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
            AppEvent::Worker(worker_event) => self.handle_worker(worker_event),
            AppEvent::Tick | AppEvent::Resize(_, _) | AppEvent::Paste(_) => Vec::new(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Vec<Effect> {
        // Global, regardless of screen: Ctrl+Q always quits.
        if key.code == KeyCode::Char('q') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return Vec::new();
        }

        match self.screens.last_mut() {
            Some(Screen::Onboarding(state)) => {
                // Onboarding owns its own key handling entirely, *including* what Esc means —
                // deliberately not the generic "Esc pops the screen stack" handler below. There is
                // nothing beneath onboarding on a first run (it is always the root screen), so
                // popping it would either no-op (same outcome, misleadingly) or, if it were ever
                // pushed on top of something else, would exit onboarding by fiat rather than by
                // finishing it. Instead each onboarding sub-step decides for itself what Esc means
                // (usually "go back one sub-step to fix an answer"; a no-op at the very first
                // sub-step, ChooseStore, and during an effect that's in flight, since there's
                // nothing to cancel back to synchronously) — see
                // `crate::screens::onboarding::handle_key`.
                let (effects, finished) = onboarding::handle_key(state, key);
                if finished {
                    // Onboarding → Main on completion. `Screen::Main` doesn't exist yet (lands in
                    // a later task, 4.19/4.20+); `Screen::Placeholder` stands in for it so that
                    // future task only has to change the line below, not this flow.
                    *self
                        .screens
                        .last_mut()
                        .expect("screens invariant: never empty") = Screen::Placeholder;
                }
                effects
            }
            _ => {
                if key.code == KeyCode::Esc {
                    self.pop_screen();
                }
                Vec::new()
            }
        }
    }

    fn handle_worker(&mut self, event: WorkerEvent) -> Vec<Effect> {
        match self.screens.last_mut() {
            Some(Screen::Onboarding(state)) => onboarding::handle_worker(state, event),
            _ => Vec::new(),
        }
    }

    /// The one and only view function. Pure — no I/O, no `.await` — so it can run against a real
    /// terminal or `ratatui::backend::TestBackend` identically.
    pub fn render(&self, frame: &mut Frame<'_>) {
        match self.current_screen() {
            Screen::Onboarding(state) => onboarding::render(state, frame),
            Screen::Placeholder => render_placeholder(frame),
        }
    }
}

fn render_placeholder(frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Placeholder");
    let body = Paragraph::new(Line::from("screen content lands in later tasks"))
        .style(Style::default().add_modifier(Modifier::DIM))
        .alignment(Alignment::Center)
        .block(block);
    frame.render_widget(body, area);
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
    fn new_app_starts_on_onboarding() {
        let app = App::new();
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
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

        // Popping the last screen is a no-op — there is always a root screen to render. The root
        // is onboarding at this point, so this also exercises onboarding's own "Esc at the first
        // sub-step is a no-op" rule rather than the generic pop handler, and the observable outcome
        // (stack length unchanged) is identical either way.
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.screens.len(), 1);
    }

    #[test]
    fn tick_resize_and_paste_events_are_no_ops_for_now() {
        let mut app = App::new();
        assert!(app.update(AppEvent::Tick).is_empty());
        assert!(app.update(AppEvent::Resize(80, 24)).is_empty());
        assert!(app.update(AppEvent::Paste("hi".into())).is_empty());
        assert!(!app.should_quit());
    }

    /// A worker event with nothing to do with the current screen (e.g. arriving after the screen
    /// already moved on) is silently ignored, not a panic.
    #[test]
    fn irrelevant_worker_event_on_placeholder_is_a_no_op() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        assert!(app
            .update(AppEvent::Worker(WorkerEvent::Completed(
                Effect::FetchBundle
            )))
            .is_empty());
    }

    /// `render` must be usable against an in-memory backend with no real terminal — the property
    /// every screen-snapshot test (4.16+) depends on.
    #[test]
    fn render_is_pure_and_works_against_test_backend() {
        let app = App::new();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    #[test]
    fn render_placeholder_works_against_test_backend() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    #[test]
    fn store_choice_debug_redacts_file_passphrase() {
        let choice = StoreChoice::File {
            passphrase: "correct horse battery staple".into(),
        };
        let debug = format!("{choice:?}");
        assert!(!debug.contains("correct horse battery staple"));
        assert!(debug.contains("redacted"));
    }
}
