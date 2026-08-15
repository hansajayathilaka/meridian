//! The Unlock screen (task 4.17): lets a returning user with an existing **file-backed** account
//! unlock it via a masked passphrase. OS-keystore-backed accounts skip this screen entirely — that
//! routing decision belongs to the (not-yet-built) `Preflight` step from
//! `docs/architecture/diagrams/tui-screen-flow.mermaid`
//! (`Preflight --> Unlock: account exists, file-backed store` /
//! `Preflight --> Main: account exists, OS keystore`), not this module.
//!
//! The mermaid transitions this screen itself owns:
//! ```text
//! Unlock --> Main: passphrase accepted
//! Unlock --> Unlock: wrong passphrase, retry with attempt count
//! Unlock --> [*]: user quits
//! ```
//! "user quits" is already handled globally (`Ctrl+Q`, `App::handle_key`) and needs nothing extra
//! here. Like [`crate::screens::onboarding`], everything in this module is synchronous and
//! I/O-free: [`handle_key`]/[`handle_worker`] only ever mutate an [`UnlockState`] and return the
//! [`Effect`]s a (future) worker should execute; [`render`] is a pure view function. The actual
//! unlock attempt (unwrapping the age/scrypt keyfile) is `meridian_core::store::FileSecretStore`'s
//! job, requested via [`Effect::Unlock`] and never performed here.
//!
//! **No lockout policy is invented.** Per `docs/architecture/tui-client.md §7`'s own row for this
//! exact condition ("Locked keystore / wrong passphrase | Retry with attempt count, no lockout
//! invented"), [`Entering::attempts`] is tracked and shown to the user so they know how many tries
//! they have made, but nothing in this module ever refuses a retry because of it.
//!
//! **The passphrase is a live secret and is never rendered** — masked with `•`, and redacted from
//! every `Debug` dump (see [`Entering`]'s hand-rolled `impl Debug`, mirroring
//! `crate::screens::onboarding::ChooseStore`'s exact pattern, and [`crate::app::UnlockRequest`]'s).

use std::path::PathBuf;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Effect, UnlockRequest, WorkerEvent};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The unlock sub-step. Only two: type the passphrase, or wait on the in-flight unlock attempt —
/// unlike onboarding, a wrong passphrase returns straight to [`Entering`] rather than a separate
/// terminal `Failed` state, since there is nowhere else for this single-step screen to "go back"
/// to and the mermaid diagram itself collapses that case into a self-loop
/// (`Unlock --> Unlock: wrong passphrase, retry with attempt count`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockState {
    Entering(Entering),
    Unlocking(Unlocking),
}

impl UnlockState {
    /// Starts a fresh unlock attempt at zero failed attempts. `keyfile` and `id` are public,
    /// non-secret data a (future) `Preflight` step would already have from the loaded
    /// `AccountDescriptor` (`meridian_core::account::AccountDescriptor`) before ever reaching this
    /// screen — `id` is shown so the user knows *which* identity they are unlocking.
    pub fn new(keyfile: PathBuf, id: String) -> Self {
        UnlockState::Entering(Entering {
            keyfile,
            id,
            passphrase: String::new(),
            attempts: 0,
            error: None,
        })
    }
}

/// Sub-step 1: the editable passphrase field, plus the account being unlocked and however many
/// prior attempts have already failed.
#[derive(Clone, PartialEq, Eq)]
pub struct Entering {
    pub keyfile: PathBuf,
    pub id: String,
    /// Never rendered in cleartext — masked with `•` (see [`entering_lines`]).
    pub passphrase: String,
    /// Number of *failed* attempts so far — shown to the user, never used to block a retry (see
    /// the module doc's no-lockout note).
    pub attempts: u32,
    /// The error from the most recent failed attempt, if any (cleared once the user starts typing
    /// again — see [`handle_entering`]).
    pub error: Option<String>,
}

impl std::fmt::Debug for Entering {
    /// Hand-rolled rather than derived: `passphrase` holds the raw text of a live unlock
    /// passphrase for the entire time this variant is active, so it must never appear in a `{:?}`
    /// dump — mirrors `crate::screens::onboarding::ChooseStore`'s hand-rolled `Debug` exactly.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entering")
            .field("keyfile", &self.keyfile)
            .field("id", &self.id)
            .field("passphrase", &"<redacted>")
            .field("attempts", &self.attempts)
            .field("error", &self.error)
            .finish()
    }
}

/// Sub-step 2 (in-flight only): [`Effect::Unlock`] is out; nothing left to type. Deliberately does
/// **not** hold a raw `passphrase: String` field — it only holds the already-built
/// [`UnlockRequest`] (which has its own hand-rolled redaction), so this struct can safely derive
/// `Debug` like [`crate::screens::onboarding::Generating`] does for the equivalent reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlocking {
    pub id: String,
    pub attempts: u32,
    pub request: UnlockRequest,
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the [`Effect`]s (if any) this key produced, and whether the
/// unlock just succeeded (the caller, `App::handle_key`, is responsible for swapping the screen on
/// `true` — this module has no reach into the screen stack itself, mirroring
/// `crate::screens::onboarding::handle_key`'s contract).
pub fn handle_key(state: &mut UnlockState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match state {
        UnlockState::Entering(e) => {
            let (next, effects) = handle_entering(e, key);
            if let Some(next) = next {
                *state = next;
            }
            (effects, false)
        }
        // In-flight: no input to give while an Effect is out — mirrors onboarding's
        // Generating/Registering/PublishingBundle arms. There is no cancel mechanism in this
        // synchronous model yet.
        UnlockState::Unlocking(_) => (Vec::new(), false),
    }
}

fn handle_entering(e: &mut Entering, key: KeyEvent) -> (Option<UnlockState>, Vec<Effect>) {
    match key.code {
        // `Unlock` is always the root of the screen stack it's pushed onto (there is nothing
        // beneath it to go back to, same as onboarding's `ChooseStore`), so Esc here is a
        // deliberate no-op — quitting is the global `Ctrl+Q` handler's job, not Esc's.
        KeyCode::Esc => {}
        KeyCode::Backspace => {
            e.passphrase.pop();
            e.error = None;
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => {
            e.passphrase.push(c);
            e.error = None;
        }
        KeyCode::Enter if !e.passphrase.is_empty() => {
            let request = UnlockRequest {
                keyfile: e.keyfile.clone(),
                passphrase: e.passphrase.clone(),
            };
            let next = UnlockState::Unlocking(Unlocking {
                id: e.id.clone(),
                attempts: e.attempts,
                request: request.clone(),
            });
            return (Some(next), vec![Effect::Unlock(request)]);
        }
        _ => {}
    }
    (None, Vec::new())
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`] — the (future) worker reporting [`Effect::Unlock`] finished or
/// failed. Returns the [`Effect`]s (if any — there are none on either outcome) and whether the
/// unlock just succeeded, same contract as [`handle_key`]. A worker event that doesn't match the
/// current in-flight attempt (e.g. a stale reply after the user already retried) or that arrives
/// while not waiting on one is silently ignored, never a panic — mirrors
/// `crate::screens::onboarding::handle_worker`.
pub fn handle_worker(state: &mut UnlockState, event: WorkerEvent) -> (Vec<Effect>, bool) {
    match state {
        UnlockState::Unlocking(u) => match event {
            WorkerEvent::Completed(Effect::Unlock(_)) => (Vec::new(), true),
            WorkerEvent::Failed(Effect::Unlock(_), message) => {
                // Back to Entering with the passphrase cleared (never retained across a failed
                // attempt — shortens how long a known-wrong secret sits live in memory) and the
                // attempt counter incremented. No lockout: the user can retype and resubmit
                // immediately (see the module doc's no-lockout note).
                *state = UnlockState::Entering(Entering {
                    keyfile: u.request.keyfile.clone(),
                    id: u.id.clone(),
                    passphrase: String::new(),
                    attempts: u.attempts + 1,
                    error: Some(message),
                });
                (Vec::new(), false)
            }
            _ => (Vec::new(), false),
        },
        UnlockState::Entering(_) => (Vec::new(), false),
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — see the module doc.
pub fn render(state: &UnlockState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Unlock");
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

fn footer_hint(state: &UnlockState) -> &'static str {
    match state {
        UnlockState::Entering(_) => "type passphrase · Enter unlock",
        UnlockState::Unlocking(_) => "please wait…",
    }
}

fn body_lines(state: &UnlockState) -> Vec<Line<'static>> {
    match state {
        UnlockState::Entering(e) => entering_lines(e),
        UnlockState::Unlocking(u) => vec![
            Line::from(format!("Unlocking {}…", u.id)),
            Line::from(""),
            Line::from("Decrypting your passphrase-wrapped keyfile."),
        ],
    }
}

fn entering_lines(e: &Entering) -> Vec<Line<'static>> {
    // Masked with `•`, never the raw passphrase — same convention as
    // `crate::screens::onboarding::choose_store_lines`.
    let masked: String = "•".repeat(e.passphrase.chars().count());
    let mut lines = vec![
        Line::from(format!("Unlock {}", e.id)),
        Line::from(""),
        Line::from(format!("passphrase: {masked}")),
    ];
    if e.attempts > 0 {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "{} failed attempt{}",
            e.attempts,
            if e.attempts == 1 { "" } else { "s" }
        )));
    }
    if let Some(err) = &e.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    lines
}
