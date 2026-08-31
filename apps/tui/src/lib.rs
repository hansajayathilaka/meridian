//! `meridian-tui` — the interactive terminal client (feature T17).
//!
//! Owns all ratatui/crossterm code in the workspace
//! ([ADR 0020](../../../docs/adr/0020-tui-packaging.md)). Depends on `meridian-core` only,
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
//! Real screen content lives in [`screens`], one module per [`app::Screen`] variant — starting
//! with [`screens::onboarding`] (task 4.16); the rest are still [`app::Screen::Placeholder`] stand-
//! ins until their own tasks land.
//!
//! [`surface`] (task 4.18) is the extension registry every *later* feature's TUI surface plugs
//! into: a message renderer keyed by stream-type id, palette commands, and/or a pane pushed onto
//! the screen stack via `Screen::Extension` — registered there, never added by editing this
//! crate's core (docs/architecture/tui-client.md §8).

pub mod app;
pub mod config;
pub mod config_write;
pub mod preflight;
pub mod screens;
pub mod session;
pub mod statusbar;
pub mod store;
pub mod streams;
pub mod surface;
pub mod terminal;
pub mod theme;
pub mod worker;

pub use app::{App, AppEvent, Effect, Screen, WorkerEvent};
pub use config::{load as load_config, load_from as load_config_from, TuiConfig};
pub use session::LiveSession;
pub use terminal::{spawn_signal_watch, CrosstermOps, TerminalGuard, TerminalOps};
pub use theme::RenderCtx;

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
    // Task 4.26: load the real `config.toml` (if any) so `ui.unicode`/`ui.theme` are a first-class,
    // actually-live degradation path for a real session, not just a testable-in-isolation mechanism —
    // see `crate::theme`'s own module doc. Mirrors `crate::config`'s own "fail closed on a malformed
    // file, default on a missing one" contract: a config that fails to load is a hard error here too,
    // never a silent fallback to defaults that would mask a typo the user needs to see.
    let config = load_config(&[]).map_err(io::Error::other)?;

    // Task 4.37 (`Preflight`): the synchronous `account.json` check this crate's own setup phase
    // already does I/O for — same "fail closed on a malformed file, default/absent on a missing
    // one" precedent `load_config` above already established, applied to one more file, not a new
    // pattern. `crate::preflight::preflight_route` is the pure decision this feeds.
    let account = load_existing_account()?;
    let route = preflight::preflight_route(account);

    let ops: Arc<dyn TerminalOps> = Arc::new(CrosstermOps);
    let guard = TerminalGuard::install(Arc::clone(&ops))?;
    let (signal_ops, signal_restored) = guard.restore_handle();
    spawn_signal_watch(signal_ops, signal_restored);

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let (mut app, initial_effects) = App::new_with_route(config, route);

    // crossterm events arrive on a dedicated OS thread (crossterm::event::read is blocking) and
    // are forwarded as AppEvents.
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<AppEvent>();
    spawn_input_thread(input_tx);

    // The worker task executes Effects and reports outcomes back as AppEvents.
    let (effect_tx, effect_rx) = mpsc::unbounded_channel::<Effect>();
    let (worker_tx, mut worker_rx) = mpsc::unbounded_channel::<AppEvent>();
    tokio::spawn(run_worker(effect_rx, worker_tx));

    // Task 5.10 (F10): how many `Effect::PersistHistory` values have been sent to the worker via
    // `effect_tx` but have not yet come back acknowledged (`WorkerEvent::Completed`/`Failed`) on
    // `worker_rx` — incremented at both `effect_tx.send` sites below, decremented as acks arrive in
    // the event loop. Drained to zero (bounded) right before this function returns — see
    // `drain_pending_persist_history`'s own doc comment for why this exists and what it does not
    // cover.
    let mut pending_persist_history: u32 = 0;

    // Task 4.37: the `Preflight` route's own initial effect (if any — one `Effect::LoadSession`
    // for the OS-keystore route, none for `Onboarding`/`Unlock`), dispatched before the event loop
    // starts so it reaches the worker exactly like every later effect `App::update` returns.
    for effect in initial_effects {
        if matches!(effect, Effect::PersistHistory(_)) {
            pending_persist_history += 1;
        }
        let _ = effect_tx.send(effect);
    }

    let mut tick = tokio::time::interval(Duration::from_millis(250));

    terminal.draw(|frame| app.render(frame))?;

    loop {
        let event = tokio::select! {
            Some(event) = input_rx.recv() => event,
            Some(event) = worker_rx.recv() => event,
            _ = tick.tick() => AppEvent::Tick,
        };

        // Task 5.10: count down `pending_persist_history` on its matching ack *before* `event` is
        // moved into `app.update` below — this is the only place a `WorkerEvent::Completed`/`Failed`
        // for a `PersistHistory` effect is ever observed.
        if is_persist_history_ack(&event) {
            pending_persist_history = pending_persist_history.saturating_sub(1);
        }

        let effects = app.update(event);
        for effect in effects {
            if matches!(effect, Effect::PersistHistory(_)) {
                pending_persist_history += 1;
            }
            let _ = effect_tx.send(effect);
        }

        terminal.draw(|frame| app.render(frame))?;

        if app.should_quit() {
            break;
        }
    }

    // Task 5.10 (F10): give any `Effect::PersistHistory` the loop above dispatched but never saw
    // acknowledged a bounded window to actually land on disk before the process exits — see
    // `drain_pending_persist_history`'s own doc comment.
    drain_pending_persist_history(
        &mut worker_rx,
        pending_persist_history,
        PERSIST_HISTORY_DRAIN_TIMEOUT,
    )
    .await;

    drop(guard);
    Ok(())
}

/// How long [`run`]'s shutdown drain ([`drain_pending_persist_history`]) waits for outstanding
/// `Effect::PersistHistory` writes to be acknowledged before giving up — chosen to comfortably
/// cover the finding's own "~2s" window (`docs/tasks/phase-5/5.10-persist-history-drain-on-
/// shutdown.md`, review finding F10) while still being bounded (see that function's own doc
/// comment for why bounded, not indefinite).
const PERSIST_HISTORY_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Waits (up to `timeout`) for `pending` outstanding `Effect::PersistHistory` writes — dispatched
/// to the worker task via `effect_tx` but not yet acknowledged back on `worker_rx` — to complete,
/// closing task 5.10 / review finding F10: without this, `run`'s old shutdown path (`drop(guard);
/// Ok(())` with no intervening await) could return, and the process go on to exit, while a
/// `PersistHistory` effect a user had already seen rendered was still sitting unpolled in
/// `effect_tx`'s channel buffer or mid-flight in the worker task — losing that message across a
/// restart. `run_persist_history` (`crate::worker`) itself needed no change to make this safe: it
/// is a synchronous, non-yielding write (no `.await` inside it), so by the time its
/// `WorkerEvent::Completed`/`Failed` ack is sent, the write has already landed — that ack is
/// already exactly the completion signal this drain needs, nothing new had to be built in
/// `worker.rs` to supply one.
///
/// **Scoped to `PersistHistory` only** (this task's own Scope) — no other in-flight `Effect` (a
/// `SendMessage` mid-network-round-trip, say) is waited on here; it is simply dropped along with
/// the worker task once this returns or `timeout` elapses. A broader shutdown-durability audit is
/// explicitly out of this task's scope.
///
/// **Bounded, not indefinite.** The worker's effect queue is strictly FIFO (`run_worker`'s single
/// `while let Some(effect) = effects.recv().await` loop), so a `PersistHistory` effect queued
/// behind one that never completes (e.g. `run_worker`'s own documented residual: an in-flight
/// prekey-bundle republish's `SignalingClient::connect` has no timeout against a black-holed
/// server) would otherwise hang shutdown forever. Giving up after `timeout` trades a vanishingly
/// rare residual loss for a shutdown that always terminates.
///
/// **Does not cover `spawn_signal_watch`'s `SIGINT`/`SIGTERM` path** (`crate::terminal`): that
/// handler calls `std::process::exit` directly, without ever returning through this function, so a
/// `PersistHistory` effect still in flight at the moment of a signal is not drained by this at all.
/// That path is not named in this task's own Scope (only `lib.rs::run()` and `worker.rs` are), and
/// closing it would need the signal handler itself to await a drain before exiting — left as a
/// separate, deliberately out-of-scope concern (this task's own "Out" note: "a broader
/// shutdown-durability audit is a separate concern if warranted later").
async fn drain_pending_persist_history(
    worker_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
    mut pending: u32,
    timeout: Duration,
) {
    if pending == 0 {
        return;
    }
    let deadline = tokio::time::Instant::now() + timeout;
    while pending > 0 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, worker_rx.recv()).await {
            Ok(Some(event)) => {
                if is_persist_history_ack(&event) {
                    pending -= 1;
                }
            }
            // The worker task ended (channel closed) or the wait timed out — nothing left to do.
            Ok(None) | Err(_) => break,
        }
    }
}

/// True for the `AppEvent::Worker` outcome of dispatching an `Effect::PersistHistory` —
/// [`drain_pending_persist_history`] (and `run`'s own main loop, to keep its `pending_persist_
/// history` counter accurate) count this down. Both `WorkerEvent::Completed` and `WorkerEvent::
/// Failed` count: a *failed* persist write is still a worker that is done attempting it — nothing
/// more in flight to wait on — it just didn't land, which is a separate, already-handled concern
/// (`crate::screens::chat::handle_worker`'s own failure-notice arm for this effect).
fn is_persist_history_ack(event: &AppEvent) -> bool {
    matches!(
        event,
        AppEvent::Worker(worker_event)
            if matches!(
                worker_event.as_ref(),
                WorkerEvent::Completed(Effect::PersistHistory(_))
                    | WorkerEvent::Failed(Effect::PersistHistory(_), _)
            )
    )
}

/// The `Preflight` step's own synchronous I/O (task 4.37): whatever `account.json` (if any) is on
/// disk under `$MERIDIAN_HOME`, loaded once, up front, exactly like `load_config` above already does
/// for `config.toml`. Checked directly against the filesystem first (never via
/// `AccountDescriptor::load()`'s own error string alone), mirroring `worker::run_load_session`'s
/// identical discipline — so a genuinely corrupt `account.json` still fails closed as a hard error
/// here (never silently mistaken for "never onboarded yet"), while a missing one cleanly means "no
/// account yet" rather than an error.
fn load_existing_account() -> io::Result<Option<meridian_core::account::AccountDescriptor>> {
    let config_dir = meridian_core::account::config_dir().map_err(io::Error::other)?;
    if !config_dir.join("account.json").exists() {
        return Ok(None);
    }
    meridian_core::account::AccountDescriptor::load()
        .map(Some)
        .map_err(io::Error::other)
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
        // Windows' console backend reports both key-down and key-up as separate `Event::Key`
        // values; Unix ttys only ever emit key-down (there's no key-up without the Kitty
        // keyboard protocol, which this crate doesn't enable). Forwarding `Release`/`Repeat`
        // unfiltered double-fires every keystroke on Windows only — each press types twice, each
        // backspace deletes two — while looking correct on Linux, where they never occur.
        crossterm::event::Event::Key(key) if key.kind == crossterm::event::KeyEventKind::Press => {
            Some(AppEvent::Key(key))
        }
        crossterm::event::Event::Key(_) => None,
        crossterm::event::Event::Resize(w, h) => Some(AppEvent::Resize(w, h)),
        crossterm::event::Event::Paste(text) => Some(AppEvent::Paste(text)),
        _ => None,
    }
}

/// Executes [`Effect`]s and reports outcomes back as [`AppEvent::Worker`]. The account-lifecycle
/// four (`GenerateAccount`/`Register`/`PublishBundle`/`Unlock`) run for real via
/// [`worker::dispatch`] (task 4.30); every other `Effect` variant still falls through to
/// [`worker::dispatch`]'s own placeholder-echo arm until its own task lands — see that function's
/// doc comment. One [`worker::OnboardingSession`] lives for this task's whole lifetime, threaded
/// through every dispatch, so a `Register` effect's live connection survives to be reused by the
/// `PublishBundle` effect that follows it (never reconnecting between them — see
/// [`worker::OnboardingSession`]'s doc comment).
///
/// **Task 4.35:** after every dispatched effect, [`worker::inbound_handoff`] peeks (never consumes)
/// the resulting [`WorkerEvent`] for a *successful* `Effect::LoadSession`/`Effect::Unlock` — the
/// first (and, per `inbound_started`, only) time that happens in a session, this spawns
/// [`worker::run_inbound_loop`] as its own tokio task, handing it the config's
/// `[network] reconnect_backoff_ms` and a clone of `replies` so its `AppEvent::Inbound`/
/// `AppEvent::ConnectionStatus` pushes reach `App` exactly like every other worker-originated event.
/// The persistent connection this spawns is deliberately never re-derived on a later effect — see
/// that function's own doc comment for the architect-approved lifecycle this realizes.
///
/// **Task 4.39:** immediately before that spawn — still inside the same `inbound_started`-guarded,
/// once-per-session branch, so it too runs exactly once per session — this awaits
/// [`worker::republish_bundle`] against the handoff's bulk-signing store and handle (destructured
/// out of the `handoff` here; the remaining fields are then moved into `run_inbound_loop` right
/// after, per that struct's own doc comment on why `republish_bundle` takes its inputs by
/// reference/value rather than `&InboundHandoff`), closing task 4.38's Defect A: without this, no
/// `meridian-tui` session ever persisted a bundle's secret scalars into `sessions.bin`'s
/// `PrekeyVault`, so a peer's first-contact message could never be decrypted. A failed republish is
/// logged (by `worker::republish_bundle` itself) and otherwise never blocks `run_inbound_loop` from
/// starting — see that function's own doc comment for the considered, `TODO: confirm`-flagged
/// failure UX.
///
/// **Task 4.43 (the store that call gets, and the ordering around it).** That republish is handed
/// [`worker::InboundHandoff::bulk_signing_store`] — for a file-backed account, a `MemorySecretStore`
/// unwrapped exactly once inside `worker::inbound_handoff` — not [`worker::InboundHandoff::store`],
/// whose raw `FileSecretStore` re-ran a full age/scrypt unwrap on each of the 101 signatures and so
/// froze a file-backed session start on "Unlocking" for ~190 s (measured live by task 4.41,
/// re-measured at 194.5 s by 4.43 before its fix). The bulk store is then **dropped before**
/// `run_inbound_loop` is spawned, which is what bounds raw-seed residency to the republish itself.
///
/// The republish is still awaited **before** `replies.send(AppEvent::Worker(..))` below — i.e. it
/// remains on the critical path to `Screen::Main`, deliberately (task 4.43's own recorded decision,
/// not an oversight). Now that it costs ~0.05 s rather than ~190 s, keeping it inline preserves a
/// simple, useful invariant: by the time `App` renders `Screen::Main`, this session's prekey vault
/// is already persisted and the inbound loop is already live, so there is no window in which the app
/// looks ready while a first-contact envelope would still find no vault entry and no listener, and
/// none in which a user-dispatched effect sits unserviced behind an unexplained multi-second stall
/// on a screen that shows no progress at all. The "Unlocking…" screen is the honest place for that
/// wait. Moving the send earlier would not change the `inbound_started` one-shot guard's meaning
/// (it is a plain local `bool` set *before* the await, in a strictly sequential
/// `while let Some(effect) = effects.recv().await` loop — no second handoff can be processed
/// concurrently under either ordering, which is exactly what
/// `tests/republish_bundle.rs::republish_only_fires_once_per_session_via_the_inbound_started_guard`
/// pins), but it would trade a visible wait for an invisible one; if a later task wants it
/// off the critical path it should land a visible status affordance with it.
///
/// Note what is and is not being traded here (task 4.43's measurement): the ~1.5-2 s a file-backed
/// session start still costs is **not** this republish (~0.052 s of it) — ~97% is the single
/// age/scrypt keyfile unwrap `worker::inbound_handoff` performs *before* this branch is reached.
/// Moving the send earlier would therefore not make "Unlocking" meaningfully shorter.
///
/// **Residual (`TODO: confirm` — a follow-up task's scope, not 4.43's): the wait above is bounded
/// only when the server answers.** `worker::republish_bundle`'s first act is
/// `SignalingClient::connect`, which is a bare `connect_async(url).await` with **no timeout**
/// (`apps/signaling/src/client.rs`), so against a black-holed or unroutable rendezvous server this
/// inline await can hold "Unlocking" for the OS's whole SYN-retry budget (~130 s on Linux) with no
/// progress indication at all. This is **not** a regression — task 4.39's wiring had the same shape
/// — and it does not change the inline-vs-off-critical-path decision recorded above; but that
/// decision's "it now costs ~0.05 s" premise describes the happy path only, and the unbounded tail
/// should be read alongside it rather than discovered later. Candidate fixes (wrap the republish in
/// `tokio::time::timeout`, or defer it off the critical path together with a visible status
/// affordance) belong in their own task.
async fn run_worker(
    mut effects: mpsc::UnboundedReceiver<Effect>,
    replies: mpsc::UnboundedSender<AppEvent>,
) {
    let mut session = worker::OnboardingSession::default();
    let mut inbound_started = false;
    while let Some(effect) = effects.recv().await {
        let outcome = worker::dispatch(effect, &mut session).await;

        if !inbound_started {
            if let Some(handoff) = worker::inbound_handoff(&outcome).await {
                inbound_started = true;
                // Destructured (task 4.43) rather than field-accessed, so `bulk_signing_store` is a
                // local this function can drop at a precise point — see the `drop` below.
                let worker::InboundHandoff {
                    store,
                    bulk_signing_store,
                    handle,
                    account_pub,
                    server,
                } = handoff;
                if let Err(e) = worker::republish_bundle(
                    bulk_signing_store.as_ref(),
                    &handle,
                    account_pub,
                    &server,
                )
                .await
                {
                    eprintln!("meridian tui: could not republish prekey bundle: {e}");
                }
                // Task 4.43, load-bearing and not merely tidy: for a file-backed account
                // `bulk_signing_store` is the one object in this process holding the *raw* account
                // seed (a `MemorySecretStore`'s `Zeroizing<Vec<u8>>`) rather than the passphrase.
                // Dropping it here zeroizes it at republish completion — ~50 ms after
                // `inbound_handoff` built it, per task 4.43's measurement (the republish is
                // ~0.052 s; the ~1.5-2 s session start is dominated by the single scrypt unwrap
                // that precedes this store's existence) — instead of at process exit, which is
                // exactly why this task's shape *reduces* key residency rather than extending
                // it — see
                // `worker::InboundHandoff::bulk_signing_store`'s own doc comment. `run_inbound_loop`
                // below is deliberately handed `store` (the per-delivery store), never this one:
                // handing it the raw-seed store would turn a ~50 ms residency into a
                // session-lifetime one, which is a different decision needing its own security
                // sign-off.
                drop(bulk_signing_store);
                let backoff_ms = load_config(&[])
                    .map(|c| c.network.reconnect_backoff_ms)
                    .unwrap_or_default();
                tokio::spawn(worker::run_inbound_loop(
                    store,
                    handle,
                    account_pub,
                    server,
                    backoff_ms,
                    replies.clone(),
                ));
            }
        }

        if replies.send(AppEvent::Worker(Box::new(outcome))).is_err() {
            break;
        }
    }
}

/// Task 5.10 (F10): a test-only seam exposing `run`'s real shutdown-drain machinery — otherwise
/// entirely private — to `tests/persist_history_drain.rs`, which cannot reach `run` itself (its own
/// doc comment: "not itself invoked by any test in this crate, since it requires a real terminal").
/// Mirrors `terminal::test_support`'s identical `#[cfg(any(test, feature = "test-support"))]`
/// pattern for the exact same reason: an integration test crate only sees this crate's genuinely
/// `pub` surface, so the pieces under test have to be re-exported through a seam like this one
/// rather than the test reaching into `lib.rs`'s private items directly.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::{AppEvent, Effect};

    /// Re-exports `run`'s own [`super::run_worker`] under a `pub` wrapper (rather than `pub use`,
    /// which would require `run_worker` itself to be `pub` — see this module's own doc comment):
    /// this submodule, as a descendant of the module `run_worker` is defined in, already has
    /// visibility to call it directly; wrapping it is what lets that visibility reach outside the
    /// crate without widening `run_worker`'s own declared visibility for normal (non-test)
    /// callers.
    pub async fn run_worker(
        effects: mpsc::UnboundedReceiver<Effect>,
        replies: mpsc::UnboundedSender<AppEvent>,
    ) {
        super::run_worker(effects, replies).await
    }

    /// Re-exports [`super::drain_pending_persist_history`] — see [`run_worker`]'s own doc comment
    /// for why a wrapper, not a `pub use`.
    pub async fn drain_pending_persist_history(
        worker_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
        pending: u32,
        timeout: Duration,
    ) {
        super::drain_pending_persist_history(worker_rx, pending, timeout).await
    }

    /// Re-exports [`super::is_persist_history_ack`] — see [`run_worker`]'s own doc comment for why
    /// a wrapper, not a `pub use`.
    pub fn is_persist_history_ack(event: &AppEvent) -> bool {
        super::is_persist_history_ack(event)
    }

    /// Re-exports [`super::PERSIST_HISTORY_DRAIN_TIMEOUT`].
    pub const PERSIST_HISTORY_DRAIN_TIMEOUT: Duration = super::PERSIST_HISTORY_DRAIN_TIMEOUT;
}

#[cfg(test)]
mod tests {
    use super::translate_event;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key_event(kind: KeyEventKind) -> Event {
        Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::NONE,
            kind,
            state: KeyEventState::NONE,
        })
    }

    /// Windows' console backend reports a `Release` (and, with enhanced keyboard support, a
    /// `Repeat`) event alongside every `Press`; Unix ttys never emit either. Forwarding them
    /// unfiltered double-fires each keystroke on Windows only — the bug this test guards against.
    #[test]
    fn only_key_press_events_are_forwarded() {
        assert!(translate_event(key_event(KeyEventKind::Press)).is_some());
        assert!(translate_event(key_event(KeyEventKind::Release)).is_none());
        assert!(translate_event(key_event(KeyEventKind::Repeat)).is_none());
    }
}
