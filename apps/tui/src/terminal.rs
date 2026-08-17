//! RAII terminal guard, panic hook, and signal handling.
//!
//! Terminal restoration is a reliability invariant, not a nicety
//! (docs/architecture/tui-client.md §4): a crash — or a `SIGINT`/`SIGTERM` — must never leave the
//! user's shell stuck in raw mode on the alternate screen. Three things cooperate to guarantee that:
//!
//! 1. [`TerminalGuard::install`] enters raw mode + the alternate screen and installs a panic hook
//!    that restores them *before* the default panic message prints (so panics — including under a
//!    `panic = "abort"` profile, where destructors never run — still leave the terminal usable).
//! 2. [`TerminalGuard`]'s `Drop` restores them again on the normal exit path. Restoration is
//!    idempotent and **blocking**, guarded by a [`std::sync::Once`]: whichever caller (Drop, the
//!    panic hook, or the signal watch) arrives first performs the actual restoration; any other
//!    caller *waits* for that in-flight restoration to finish rather than returning immediately
//!    and racing ahead — this matters because the signal-watch path calls `std::process::exit`
//!    right after, which must not fire before a concurrent winner's restoration syscalls complete.
//! 3. [`spawn_signal_watch`] restores them on `SIGINT`/`SIGTERM` before the process exits.
//!
//! The actual raw-mode/alternate-screen calls are behind the [`TerminalOps`] trait rather than
//! called directly, so tests can substitute [`RecordingOps`] (or any fake) instead of requiring a
//! real TTY — `enable_raw_mode` performs a `termios` ioctl that fails on the non-terminal stdout a
//! test harness normally provides.

use std::io;
use std::sync::{Arc, Once};

use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};

/// The terminal-mode operations the guard performs. Abstracted so tests can substitute a fake that
/// doesn't require a real TTY. [`CrosstermOps`] is the real implementation.
pub trait TerminalOps: Send + Sync {
    fn enable_raw_mode(&self) -> io::Result<()>;
    fn disable_raw_mode(&self) -> io::Result<()>;
    fn enter_alternate_screen(&self) -> io::Result<()>;
    fn leave_alternate_screen(&self) -> io::Result<()>;
}

/// The real terminal, driven through crossterm on stdout.
#[derive(Debug, Default, Clone, Copy)]
pub struct CrosstermOps;

impl TerminalOps for CrosstermOps {
    fn enable_raw_mode(&self) -> io::Result<()> {
        crossterm::terminal::enable_raw_mode()
    }

    fn disable_raw_mode(&self) -> io::Result<()> {
        crossterm::terminal::disable_raw_mode()
    }

    fn enter_alternate_screen(&self) -> io::Result<()> {
        crossterm::execute!(io::stdout(), EnterAlternateScreen)
    }

    fn leave_alternate_screen(&self) -> io::Result<()> {
        crossterm::execute!(io::stdout(), LeaveAlternateScreen)
    }
}

/// Restores the terminal exactly once, regardless of how many of Drop / the panic hook / the
/// signal handler race to call it. Order is the mirror of entry: leave the alternate screen before
/// dropping out of raw mode.
///
/// Uses [`Once::call_once`] rather than a swapped `AtomicBool` flag: `call_once` **blocks** any
/// caller that loses the race until the winner's closure has actually returned, so a concurrent
/// caller can never observe "already restored" before the restoration syscalls are done — in
/// particular, [`spawn_signal_watch`]'s `std::process::exit` immediately after this call cannot
/// fire while another thread's restoration (started via a racing panic or `Drop`) is still
/// in-flight. The closure itself cannot panic under either `TerminalOps` impl this crate ships
/// (`TerminalOps` methods return `Result`, and errors are discarded, never `unwrap`ked), so there
/// is no risk of poisoning `Once`.
fn restore_once(ops: &dyn TerminalOps, restored: &Once) {
    restored.call_once(|| {
        let _ = ops.leave_alternate_screen();
        let _ = ops.disable_raw_mode();
    });
}

/// RAII guard that owns the terminal's raw-mode + alternate-screen state for the lifetime of the
/// TUI session. See the module docs for the three restoration paths this guard is part of.
pub struct TerminalGuard {
    ops: Arc<dyn TerminalOps>,
    restored: Arc<Once>,
}

impl TerminalGuard {
    /// Enters raw mode + the alternate screen and installs the panic hook that restores them ahead
    /// of the default panic output. Does **not** install the `SIGINT`/`SIGTERM` watch — that needs
    /// a running Tokio runtime, so callers spawn it separately with [`spawn_signal_watch`] once one
    /// is available (see `run` in `lib.rs`).
    ///
    /// **Partial-failure safety.** If `enable_raw_mode` succeeds but `enter_alternate_screen` then
    /// fails, raw mode is rolled back before returning `Err` — otherwise the terminal would be left
    /// stuck in raw mode with no `TerminalGuard` ever constructed to restore it (no `Drop`, no panic
    /// hook installed yet). This does not need a panic to trigger, just an ordinary I/O error on the
    /// second call.
    ///
    /// **Narrow unprotected window.** Between `enable_raw_mode`/`enter_alternate_screen` succeeding
    /// and the panic hook actually being installed a few lines later, a panic on that thread would
    /// not be caught by this guard's hook. This window is small (no I/O, no allocation that can
    /// reasonably panic) and accepted as a residual, not eliminated.
    pub fn install(ops: Arc<dyn TerminalOps>) -> io::Result<Self> {
        ops.enable_raw_mode()?;
        if let Err(e) = ops.enter_alternate_screen() {
            let _ = ops.disable_raw_mode();
            return Err(e);
        }

        let restored = Arc::new(Once::new());
        install_panic_hook(Arc::clone(&ops), Arc::clone(&restored));

        Ok(Self { ops, restored })
    }

    /// The shared restoration flag, so a caller can hand it (and the same `ops`) to
    /// [`spawn_signal_watch`].
    pub fn restore_handle(&self) -> (Arc<dyn TerminalOps>, Arc<Once>) {
        (Arc::clone(&self.ops), Arc::clone(&self.restored))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_once(self.ops.as_ref(), self.restored.as_ref());
    }
}

/// Installs a panic hook that restores the terminal before delegating to whatever hook was
/// previously installed (so panic output — message, backtrace — still prints normally, just onto a
/// sane terminal instead of a raw-mode alternate screen the user can't read or escape).
///
/// `std::panic::set_hook` is **process-global**: a future test added to `tests/terminal_guard.rs`
/// that also calls [`TerminalGuard::install`] must not run concurrently with an existing one in the
/// same test binary (parallel test threads share the hook) — keep such tests in one `#[test]` or
/// serialize them, the way `apps/core/src/account.rs`'s `ENV_LOCK` serializes its own process-global
/// state.
fn install_panic_hook(ops: Arc<dyn TerminalOps>, restored: Arc<Once>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_once(ops.as_ref(), restored.as_ref());
        previous(info);
    }));
}

/// Spawns a task that restores the terminal and exits the process on `SIGINT`/`SIGTERM` (Unix) or
/// Ctrl-C (all platforms). Requires a running Tokio runtime — call this from within `run`, after
/// [`TerminalGuard::install`].
///
/// Exit code follows the usual `128 + signal` convention: `130` for `SIGINT`/Ctrl-C, `143` for
/// `SIGTERM`.
pub fn spawn_signal_watch(
    ops: Arc<dyn TerminalOps>,
    restored: Arc<Once>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        let exit_code = {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(sig) => sig,
                    Err(_) => return,
                };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => 130,
                _ = sigterm.recv() => 143,
            }
        };
        #[cfg(not(unix))]
        let exit_code = {
            let _ = tokio::signal::ctrl_c().await;
            130
        };

        restore_once(ops.as_ref(), restored.as_ref());
        std::process::exit(exit_code);
    })
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    //! A fake [`TerminalOps`] that records state transitions instead of touching a real terminal —
    //! shared between this crate's unit tests and the integration test in `tests/`.
    use super::TerminalOps;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Default)]
    pub struct RecordingOps {
        raw_mode: AtomicBool,
        alt_screen: AtomicBool,
    }

    impl RecordingOps {
        pub fn raw_mode_enabled(&self) -> bool {
            self.raw_mode.load(Ordering::SeqCst)
        }

        pub fn alt_screen_entered(&self) -> bool {
            self.alt_screen.load(Ordering::SeqCst)
        }
    }

    impl TerminalOps for RecordingOps {
        fn enable_raw_mode(&self) -> io::Result<()> {
            self.raw_mode.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn disable_raw_mode(&self) -> io::Result<()> {
            self.raw_mode.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn enter_alternate_screen(&self) -> io::Result<()> {
            self.alt_screen.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn leave_alternate_screen(&self) -> io::Result<()> {
            self.alt_screen.store(false, Ordering::SeqCst);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::RecordingOps;
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Succeeds `enable_raw_mode`, always fails `enter_alternate_screen` — reproduces the
    /// partial-install failure `TerminalGuard::install` must roll back cleanly from.
    #[derive(Debug, Default)]
    struct FailAltScreenOps {
        raw_mode: AtomicBool,
    }

    impl TerminalOps for FailAltScreenOps {
        fn enable_raw_mode(&self) -> io::Result<()> {
            self.raw_mode.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn disable_raw_mode(&self) -> io::Result<()> {
            self.raw_mode.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn enter_alternate_screen(&self) -> io::Result<()> {
            Err(io::Error::other("simulated alt-screen failure"))
        }
        fn leave_alternate_screen(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_alt_screen_entry_rolls_back_raw_mode() {
        let ops = Arc::new(FailAltScreenOps::default());
        let err = TerminalGuard::install(ops.clone())
            .err()
            .expect("enter_alternate_screen failure must propagate");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            !ops.raw_mode.load(Ordering::SeqCst),
            "raw mode must be rolled back when the alternate-screen step fails, \
             not left stuck on with no guard to restore it"
        );
    }

    #[test]
    fn install_enters_raw_mode_and_alt_screen() {
        let ops = Arc::new(RecordingOps::default());
        let guard = TerminalGuard::install(ops.clone()).expect("install");
        assert!(ops.raw_mode_enabled());
        assert!(ops.alt_screen_entered());
        drop(guard);
        assert!(!ops.raw_mode_enabled());
        assert!(!ops.alt_screen_entered());
    }

    #[test]
    fn restore_is_idempotent() {
        let ops = Arc::new(RecordingOps::default());
        let restored = Arc::new(Once::new());
        ops.enable_raw_mode().unwrap();
        ops.enter_alternate_screen().unwrap();

        restore_once(ops.as_ref(), restored.as_ref());
        assert!(!ops.raw_mode_enabled());

        // A second call (simulating Drop racing the panic hook / signal handler) must not panic
        // and must not re-toggle anything.
        ops.enable_raw_mode().unwrap();
        restore_once(ops.as_ref(), restored.as_ref());
        assert!(
            ops.raw_mode_enabled(),
            "second restore must be a no-op, not a re-toggle"
        );
    }

    /// A concurrent `restore_once` caller must *block* until an in-flight winner's restoration
    /// syscalls actually complete — not just avoid double-toggling. This is the property that
    /// keeps `spawn_signal_watch`'s `std::process::exit` from firing while a racing panic-hook or
    /// `Drop` restoration on another thread is still mid-flight (the gap `Once` closes that a
    /// swapped `AtomicBool` flag does not).
    #[test]
    fn concurrent_restore_blocks_until_winner_finishes() {
        use std::sync::mpsc;
        use std::sync::Mutex;
        use std::thread;
        use std::time::Duration;

        /// Blocks inside `leave_alternate_screen` until told to proceed, and signals the moment
        /// it entered — so the test can deterministically know the "winner" is mid-restoration
        /// before starting the "loser".
        struct BlockingOps {
            entered: mpsc::Sender<()>,
            proceed: Mutex<mpsc::Receiver<()>>,
        }

        impl TerminalOps for BlockingOps {
            fn enable_raw_mode(&self) -> io::Result<()> {
                Ok(())
            }
            fn disable_raw_mode(&self) -> io::Result<()> {
                Ok(())
            }
            fn enter_alternate_screen(&self) -> io::Result<()> {
                Ok(())
            }
            fn leave_alternate_screen(&self) -> io::Result<()> {
                let _ = self.entered.send(());
                let _ = self.proceed.lock().unwrap().recv();
                Ok(())
            }
        }

        let (entered_tx, entered_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        let ops: Arc<BlockingOps> = Arc::new(BlockingOps {
            entered: entered_tx,
            proceed: Mutex::new(proceed_rx),
        });
        let once = Arc::new(Once::new());

        let winner_ops = Arc::clone(&ops);
        let winner_once = Arc::clone(&once);
        let winner = thread::spawn(move || {
            restore_once(
                winner_ops.as_ref() as &dyn TerminalOps,
                winner_once.as_ref(),
            );
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("winner must enter leave_alternate_screen");

        let loser_ops = Arc::clone(&ops);
        let loser_once = Arc::clone(&once);
        let (done_tx, done_rx) = mpsc::channel();
        let loser = thread::spawn(move || {
            restore_once(loser_ops.as_ref() as &dyn TerminalOps, loser_once.as_ref());
            let _ = done_tx.send(());
        });

        // The loser is racing a still-in-flight winner: it must not complete yet.
        assert!(
            done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "a concurrent restore_once call must block on an in-flight winner, not race ahead"
        );

        proceed_tx.send(()).expect("release the winner");
        winner.join().expect("winner thread");

        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("loser unblocks promptly once the winner finishes");
        loser.join().expect("loser thread");
    }
}
