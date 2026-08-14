//! `meridian-tui` — the interactive terminal client (feature T17).
//!
//! Owns all ratatui/crossterm code in the workspace (ADR 0020). Depends on `meridian-core` only,
//! never on `meridian-cli` — `meridian-cli` depends on this crate, launching it via a thin
//! `meridian tui` subcommand (task 4.12). No protocol logic lands here: this crate orchestrates
//! `meridian-core` exactly like the CLI does, and is never more capable than the headless CLI, only
//! nicer (docs/architecture/tui-client.md §1).
//!
//! The runtime is an Elm-style split (docs/architecture/tui-client.md §4):
//!
//! ```text
//!         crossterm events ─┐
//!    tokio worker events ───┼──► AppEvent ──► App::update(&mut self, ev) ──► Vec<Effect>
//!              tick (250ms) ┘                        │                            │
//!                                                    ▼                            ▼
//!                                           App::render(&self, frame)      worker task runs it
//!                                           (pure, no I/O, no await)       (network, store, crypto)
//! ```
//!
//! `App::update`/`App::render` never perform I/O or await — see [`app`]. [`Effect`] is the only path
//! to the network/keystore/disk; a worker task executes effects and reports back as
//! [`AppEvent::Worker`]. The terminal's raw mode + alternate screen are owned by an RAII guard whose
//! `Drop`, panic hook, and `SIGINT`/`SIGTERM` handler all restore it — see [`terminal`].
//!
//! Screens are placeholders at this stage; real screen content lands in task 4.16+.

pub mod app;
pub mod config;
pub mod store;
pub mod terminal;

pub use app::{App, AppEvent, Effect, Screen, WorkerEvent};
pub use config::{load as load_config, load_from as load_config_from, TuiConfig};
pub use terminal::{spawn_signal_watch, CrosstermOps, TerminalGuard, TerminalOps};

use std::io;
use std::sync::Arc;
use std::time::Duration;

use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use tokio::sync::mpsc;

/// The terminal's current size (columns, rows), as reported by crossterm on stdout.
///
/// Exposed so `meridian-cli`'s `meridian tui` subcommand (task 4.12) can gate entry — refusing on an
/// undersized terminal — before calling [`run`], without needing a crossterm dependency of its own:
/// ADR 0020 condition 1 keeps all crossterm usage inside this crate.
pub fn terminal_size() -> io::Result<(u16, u16)> {
    crossterm::terminal::size()
}

/// Runs the TUI to completion: installs the terminal guard, wires the event loop
/// (crossterm input + worker responses + 250ms tick) into `App::update`/`App::render`, and restores
/// the terminal on the way out (normal exit, error, or panic). Called from `meridian-cli`'s `tui`
/// subcommand (task 4.12); not itself invoked by any test in this crate, since it requires a real
/// terminal.
pub async fn run() -> io::Result<()> {
    let ops: Arc<dyn TerminalOps> = Arc::new(CrosstermOps);
    let guard = TerminalGuard::install(Arc::clone(&ops))?;
    let (signal_ops, signal_restored) = guard.restore_handle();
    spawn_signal_watch(signal_ops, signal_restored);

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    // crossterm events arrive on a dedicated OS thread (crossterm::event::read is blocking) and
    // are forwarded as AppEvents.
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<AppEvent>();
    spawn_input_thread(input_tx);

    // The worker task executes Effects and reports outcomes back as AppEvents.
    let (effect_tx, effect_rx) = mpsc::unbounded_channel::<Effect>();
    let (worker_tx, mut worker_rx) = mpsc::unbounded_channel::<AppEvent>();
    tokio::spawn(run_worker(effect_rx, worker_tx));

    let mut tick = tokio::time::interval(Duration::from_millis(250));

    terminal.draw(|frame| app.render(frame))?;

    loop {
        let event = tokio::select! {
            Some(event) = input_rx.recv() => event,
            Some(event) = worker_rx.recv() => event,
            _ = tick.tick() => AppEvent::Tick,
        };

        let effects = app.update(event);
        for effect in effects {
            let _ = effect_tx.send(effect);
        }

        terminal.draw(|frame| app.render(frame))?;

        if app.should_quit() {
            break;
        }
    }

    drop(guard);
    Ok(())
}

/// Reads crossterm events on a blocking OS thread (crossterm's `read` blocks, so it cannot run
/// directly on a Tokio worker) and forwards the ones `App` understands.
fn spawn_input_thread(tx: mpsc::UnboundedSender<AppEvent>) {
    std::thread::spawn(move || {
        while let Ok(event) = crossterm::event::read() {
            if let Some(app_event) = translate_event(event) {
                if tx.send(app_event).is_err() {
                    break;
                }
            }
        }
    });
}

fn translate_event(event: crossterm::event::Event) -> Option<AppEvent> {
    match event {
        crossterm::event::Event::Key(key) => Some(AppEvent::Key(key)),
        crossterm::event::Event::Resize(w, h) => Some(AppEvent::Resize(w, h)),
        crossterm::event::Event::Paste(text) => Some(AppEvent::Paste(text)),
        _ => None,
    }
}

/// Executes [`Effect`]s and reports outcomes back as [`AppEvent::Worker`]. Effects have no real
/// behavior yet (placeholder scope, task 4.11) — the network/store/crypto wiring for each lands with
/// the tasks named on [`Effect`]'s doc comment.
async fn run_worker(
    mut effects: mpsc::UnboundedReceiver<Effect>,
    replies: mpsc::UnboundedSender<AppEvent>,
) {
    while let Some(effect) = effects.recv().await {
        let outcome = WorkerEvent::Completed(effect);
        if replies.send(AppEvent::Worker(outcome)).is_err() {
            break;
        }
    }
}
