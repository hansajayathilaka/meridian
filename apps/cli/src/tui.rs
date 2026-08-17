//! `meridian tui` subcommand (task 4.12): launches the interactive terminal client
//! (`meridian_tui::run`, task 4.11) behind the default-on `tui` Cargo feature (ADR 0020).
//!
//! Before touching the real terminal, [`run`] checks the environment can actually render a TUI —
//! `TERM=dumb`, a non-TTY stdout (piped/redirected), or a terminal smaller than [`MIN_COLS`]x
//! [`MIN_ROWS`] all refuse with a plain-text message naming the headless CLI equivalent, exit code
//! 1, never a garbled screen and never a panic (feature 17's acceptance criteria,
//! docs/architecture/features/17-terminal-tui-client.md). The gate itself
//! ([`check_environment`]) is a pure function of its inputs so it can be tested without a real
//! terminal — [`run`] only supplies those inputs from the real environment.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use meridian_core::identity::KeyHandle;

/// The terminal size the TUI needs to render (feature 17's acceptance criteria: "renders correctly
/// at 80×24").
const MIN_COLS: u16 = 80;
const MIN_ROWS: u16 = 24;

/// The closest scriptable equivalent to point users at when the TUI refuses to start. `chat --json`
/// is the CLI's own end-to-end messaging surface (feature 17 promises capability parity, ADR 0020
/// condition 5) — other subcommands (`doctor --json`, `session demo --json`, `session connect
/// --json`) have the same `--json` shape for their own scope.
const HEADLESS_EQUIVALENT: &str = "meridian chat <id> --json";

/// Pure environment gate: given the inputs a real terminal would provide, decide whether it is safe
/// to hand control to `meridian_tui::run()`. Kept free of I/O (no env reads, no terminal queries) so
/// tests can drive every branch directly.
///
/// - `term_env`: the `TERM` environment variable's value, if set.
/// - `is_tty`: whether stdout is a real terminal (`std::io::IsTerminal`).
/// - `size`: the terminal's `(columns, rows)`, if it could be determined at all.
///
/// Order matters for the message a user sees: `TERM=dumb` is checked first because it's the
/// clearest signal of "not a real terminal" regardless of what a size probe might return; the TTY
/// check comes next since a piped/redirected stdout can still spuriously report a size; the size
/// check is last, only reachable once we know we're looking at an actual interactive terminal.
pub(crate) fn check_environment(
    term_env: Option<&str>,
    is_tty: bool,
    size: Option<(u16, u16)>,
) -> Result<(), String> {
    if term_env == Some("dumb") {
        return Err(refusal("TERM=dumb does not support an interactive TUI"));
    }
    if !is_tty {
        return Err(refusal(
            "stdout is not a terminal (input/output looks piped or redirected)",
        ));
    }
    match size {
        Some((cols, rows)) if cols < MIN_COLS || rows < MIN_ROWS => Err(refusal(&format!(
            "terminal is too small ({cols}x{rows}); the TUI needs at least {MIN_COLS}x{MIN_ROWS}"
        ))),
        Some(_) => Ok(()),
        None => Err(refusal("could not determine the terminal size")),
    }
}

fn refusal(reason: &str) -> String {
    format!(
        "meridian tui: refusing to start — {reason}.\n\
         Use the headless CLI instead, e.g. `{HEADLESS_EQUIVALENT}` (every interactive subcommand \
         has a scriptable --json mode)."
    )
}

/// Entry point for the `meridian tui` subcommand. Runs [`check_environment`] against the real
/// terminal first; only on success does it hand off to `meridian_tui::run()`.
pub(crate) fn run() -> Result<ExitCode, String> {
    let term_env = std::env::var("TERM").ok();
    let is_tty = std::io::stdout().is_terminal();
    let size = meridian_tui::terminal_size().ok();

    if let Err(message) = check_environment(term_env.as_deref(), is_tty, size) {
        eprintln!("{message}");
        return Ok(ExitCode::FAILURE);
    }

    crate::block_on(crate::runtime()?, meridian_tui::run()).map_err(|e| format!("tui: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

/// `meridian tui --export-json <path>` (task 4.15). Bypasses the interactive terminal entirely —
/// no environment gate, no `App`/event loop — and delegates the actual read/decrypt/write work to
/// `meridian_tui::store::export::export_json`, the plain function that crate exposes for exactly
/// this purpose (its own doc comment explains the `apps/cli` vs `apps/tui` split: ADR 0020 keeps
/// `apps/tui` core-only, so the flag lives here while the store-reading logic stays there).
///
/// Reuses the same account-loading path `cmd_chat`/`session connect` already use
/// (`AccountDescriptor::load` + `crate::load_store` + `KeyHandle::from_label`) rather than
/// inventing a second one.
pub(crate) fn export_json(dest: &Path) -> Result<ExitCode, String> {
    let descriptor = crate::account::AccountDescriptor::load()?;
    let store = crate::load_store(&descriptor)?;
    let handle = KeyHandle::from_label(&descriptor.label);

    meridian_tui::store::export::export_json(dest, store.as_ref(), &handle)
        .map_err(|e| format!("export-json: {e}"))?;
    println!("exported unsealed store documents to {}", dest.display());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_dumb_is_refused_before_anything_else() {
        // Even a perfectly good TTY + size must not save a TERM=dumb session.
        let err = check_environment(Some("dumb"), true, Some((120, 40)))
            .expect_err("TERM=dumb must refuse");
        assert!(err.contains("TERM=dumb"), "message: {err}");
        assert!(
            err.contains(HEADLESS_EQUIVALENT),
            "refusal must name the headless equivalent: {err}"
        );
    }

    #[test]
    fn non_tty_stdout_is_refused() {
        let err = check_environment(Some("xterm-256color"), false, Some((120, 40)))
            .expect_err("non-TTY stdout must refuse");
        assert!(err.contains("not a terminal"), "message: {err}");
        assert!(err.contains(HEADLESS_EQUIVALENT), "message: {err}");
    }

    #[test]
    fn undersized_terminal_is_refused() {
        let err = check_environment(Some("xterm-256color"), true, Some((79, 24)))
            .expect_err("79 columns is below the 80x24 floor");
        assert!(err.contains("too small"), "message: {err}");
        assert!(err.contains("79x24"), "message: {err}");

        let err = check_environment(Some("xterm-256color"), true, Some((80, 23)))
            .expect_err("23 rows is below the 80x24 floor");
        assert!(err.contains("too small"), "message: {err}");
    }

    #[test]
    fn unknown_size_is_refused_not_assumed_ok() {
        // Fail closed: an undetermined size must never be treated as "big enough".
        let err = check_environment(Some("xterm-256color"), true, None)
            .expect_err("an undetermined size must refuse, not be assumed fine");
        assert!(err.contains("could not determine"), "message: {err}");
        assert!(err.contains(HEADLESS_EQUIVALENT), "message: {err}");
    }

    #[test]
    fn exactly_minimum_size_is_accepted() {
        check_environment(Some("xterm-256color"), true, Some((MIN_COLS, MIN_ROWS)))
            .expect("exactly 80x24 must be accepted, not refused");
    }

    #[test]
    fn generous_terminal_with_no_term_set_is_accepted() {
        // `TERM` unset (None) is not the same as `TERM=dumb` — must not be refused on that basis
        // alone.
        check_environment(None, true, Some((200, 60))).expect("no TERM set must not itself refuse");
    }

    #[test]
    fn refusal_message_never_panics_and_is_plain_text() {
        // A light sweep of the input space: every branch must return a plain String, never panic.
        for term in [None, Some("dumb"), Some("xterm-256color"), Some("")] {
            for is_tty in [true, false] {
                for size in [
                    None,
                    Some((0, 0)),
                    Some((80, 24)),
                    Some((u16::MAX, u16::MAX)),
                ] {
                    let _ = check_environment(term, is_tty, size);
                }
            }
        }
    }
}
