//! Terminal-restoration is a reliability invariant (docs/architecture/tui-client.md §4): a crash
//! must never leave the user's terminal stuck in raw mode on the alternate screen. This test forces
//! a panic mid-render and asserts both are undone — via the panic hook, which is what actually
//! guards against `panic = "abort"` profiles where destructors never run, not just `Drop`.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_tui::terminal::test_support::RecordingOps;
use meridian_tui::{App, TerminalGuard};

#[test]
fn panic_mid_render_restores_terminal() {
    let ops = Arc::new(RecordingOps::default());
    let guard = TerminalGuard::install(ops.clone()).expect("install must succeed against the fake");

    assert!(
        ops.raw_mode_enabled(),
        "guard must enter raw mode on install"
    );
    assert!(
        ops.alt_screen_entered(),
        "guard must enter the alternate screen on install"
    );

    // Simulate a panic occurring mid-render, exactly the way a bug in a screen's render function
    // would. The guard (`guard`) is deliberately declared *outside* this closure so that
    // `catch_unwind` stops the unwind before it would reach (and Drop) the guard — this isolates
    // the assertion to the panic hook's own restoration, not Drop's.
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| {
                App::new().render(frame);
                panic!("simulated panic mid-render");
            })
            .ok();
    }));

    assert!(
        result.is_err(),
        "the simulated panic must propagate out of catch_unwind"
    );
    assert!(
        !ops.raw_mode_enabled(),
        "the panic hook must disable raw mode before the panic message prints"
    );
    assert!(
        !ops.alt_screen_entered(),
        "the panic hook must leave the alternate screen before the panic message prints"
    );

    // The guard is still in scope (its Drop has not run yet) — dropping it now must be a safe,
    // idempotent no-op, not a second (incorrect) toggle back into raw mode / the alternate screen.
    drop(guard);
    assert!(!ops.raw_mode_enabled());
    assert!(!ops.alt_screen_entered());
}
