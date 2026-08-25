//! `crate::screens::help` + `crate::screens::palette` — task 4.25's own named test target
//! (`cargo nextest run -p meridian-tui --test screens_help_palette`).
//!
//! The load-bearing property this file exists to prove, per the task's own deliverable #2: **every
//! command registered in a [`PaletteRegistry`] appears, by name and (if bound) by its exact binding
//! text, in both the generated help screen's render and the palette's render** — walking the actual
//! registered set, not a hand-copied list, so a future feature that registers a new command needs no
//! edit to either screen to become discoverable. Synthetic registrations for that property (mirrors
//! `surface_registry.rs`'s own scope boundary — no real chat/file/call content), plus a check against
//! the crate's own real, built-in registered set (`App::commands`).
//!
//! Also covers: fuzzy filtering, list navigation and clamping, Esc-closes, an empty registry not
//! panicking, and the App-level global dispatch wiring this task's own addendum names as its real,
//! non-optional scope (`F1`, `Ctrl+K`, and the built-in `Diagnostics` command reachable end to end
//! through the palette). See `app.rs`'s own `#[cfg(test)] mod tests` for the
//! `PaletteRegistry::find_binding` ordering-regression coverage (`Ctrl+Q`/`Ctrl+R` unaffected, a
//! screen's own same-key use documented and tested) that needs private `App` access this external test
//! file doesn't have.
//!
//! ## Task 5.7 — App-level reconciliation for Diagnostics (this file's own final section)
//! `diagnostics_is_reachable_end_to_end_through_the_palette` above only proves the palette *opens*
//! the pane — it never presses `r`, never runs a real `Effect::RunDoctor` through
//! `crate::worker::dispatch`, and never checks that the completion reconciles back into the live
//! `Screen::Extension`'s own `DiagnosticsPane`. That is exactly the gap class that took Phase 4 six
//! gap-closure waves to find and fix for contacts/requests/chat (see
//! `apps/tui/tests/accept_to_chat.rs`'s own module doc). The final section of this file closes it:
//! `Ctrl+K` → the real `Diagnostics` pane → a real `r` → a real `Effect::RunDoctor` → the real
//! worker's real subprocess call to `crate::screens::diagnostics::DOCTOR_BINARY` (`"meridian"`,
//! resolved via `$PATH` at invocation time — hardcoded, not injectable, so both branches below drive
//! it by controlling the test process's own `$PATH` rather than the request) → fed back through
//! `App::update` → rendered in the live pane. Both the not-on-`PATH` failure path and a genuine
//! success path (a real, tiny, on-`PATH` stand-in executable, since this crate cannot depend on
//! `meridian-cli` to build a real one — ADR 0020) are driven, not just one with the other assumed.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::{Frame, Terminal};

use meridian_tui::app::{
    App, AppEvent, Effect, RunDoctorEffect, Screen, SendMessageEffect, SendMessageRequest,
    WorkerEvent,
};
use meridian_tui::screens::help::{self, HelpState};
use meridian_tui::screens::palette::{self, PaletteOutcome, PaletteState};
use meridian_tui::surface::{KeyBinding, PaletteAction, PaletteCommand, PaletteRegistry};
use meridian_tui::worker::{dispatch as worker_dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn render_to_text<F: Fn(&mut Frame<'_>)>(width: u16, height: u16, draw: F) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| draw(frame)).expect("draw");
    format!("{}", terminal.backend())
}

/// Two synthetic commands: one with a real keybinding, one without — proves both the "with binding"
/// and "palette only" display paths.
fn synthetic_registry() -> PaletteRegistry {
    let mut registry = PaletteRegistry::new();
    registry.register(PaletteCommand {
        id: "demo.alpha",
        name: "Alpha Command",
        description: "the first synthetic command, bound to Ctrl+A",
        keybinding: Some(KeyBinding::new(KeyCode::Char('a'), KeyModifiers::CONTROL)),
        action: PaletteAction::Effect(std::sync::Arc::new(|| Effect::FetchBundle)),
    });
    registry.register(PaletteCommand {
        id: "demo.beta",
        name: "Beta Command",
        description: "the second synthetic command, palette only, no binding",
        keybinding: None,
        action: PaletteAction::Effect(std::sync::Arc::new(|| {
            Effect::SendMessage(SendMessageEffect {
                request: SendMessageRequest {
                    peer_pubkey: [0u8; 32],
                    peer_hint: String::new(),
                    body: String::new(),
                },
                outcome: None,
            })
        })),
    });
    registry
}

// ---------------------------------------------------------------------------
// 1. The load-bearing property: every registered command in both surfaces
// ---------------------------------------------------------------------------

#[test]
fn every_registered_command_appears_in_both_help_and_palette_by_name_and_binding() {
    let registry = synthetic_registry();

    let help_state = HelpState::new(registry.clone());
    let help_text = render_to_text(100, 30, |f| help::render(&help_state, f));

    let palette_state = PaletteState::new(registry.clone());
    let palette_text = render_to_text(100, 30, |f| palette::render(&palette_state, f));

    assert_eq!(
        registry.iter().count(),
        2,
        "sanity: the registry this test walks actually has entries"
    );

    for command in registry.iter() {
        assert!(
            help_text.contains(command.name),
            "help screen missing command name {:?}\n---\n{help_text}",
            command.name
        );
        assert!(
            palette_text.contains(command.name),
            "palette missing command name {:?}\n---\n{palette_text}",
            command.name
        );
        if let Some(binding) = command.keybinding {
            let rendered = binding.to_string();
            assert!(
                help_text.contains(&rendered),
                "help screen missing binding {rendered:?} for {}\n---\n{help_text}",
                command.name
            );
            assert!(
                palette_text.contains(&rendered),
                "palette missing binding {rendered:?} for {}\n---\n{palette_text}",
                command.name
            );
        }
    }
}

/// Same property, walked against the crate's own real, built-in registered set (`App::new`'s
/// `register_builtin_commands`) rather than a synthetic one — proves the mechanism holds for
/// production data, not only test fixtures.
#[test]
fn every_command_app_actually_registers_appears_in_both_surfaces() {
    let app = App::new();
    let registry = app.commands().clone();
    assert!(
        registry.iter().count() >= 1,
        "App::new registers at least Diagnostics"
    );

    let help_text = render_to_text(100, 30, |f| {
        help::render(&HelpState::new(registry.clone()), f)
    });
    let palette_text = render_to_text(100, 30, |f| {
        palette::render(&PaletteState::new(registry.clone()), f)
    });

    for command in registry.iter() {
        assert!(help_text.contains(command.name));
        assert!(palette_text.contains(command.name));
    }
}

/// An empty registry must render both screens without panicking, and must say so honestly rather
/// than showing a blank/misleading screen — mirrors the "forward compatibility" discipline
/// `surface_registry.rs` pins for the message-renderer half of this same registration mechanism.
#[test]
fn an_empty_registry_renders_both_screens_without_panicking() {
    let registry = PaletteRegistry::new();
    let help_text = render_to_text(80, 24, |f| {
        help::render(&HelpState::new(registry.clone()), f)
    });
    let palette_text = render_to_text(80, 24, |f| {
        palette::render(&PaletteState::new(registry.clone()), f)
    });

    assert!(help_text.contains("none registered"));
    assert!(palette_text.contains("no matching"));
}

// ---------------------------------------------------------------------------
// 2. Help screen's own behavior
// ---------------------------------------------------------------------------

#[test]
fn help_esc_asks_to_exit() {
    let mut state = HelpState::new(PaletteRegistry::new());
    let (effects, exit) = help::handle_key(&mut state, key(KeyCode::Esc, KeyModifiers::NONE));
    assert!(effects.is_empty());
    assert!(exit);
}

#[test]
fn help_global_keys_section_documents_the_fixed_chords() {
    let state = HelpState::new(PaletteRegistry::new());
    let text = render_to_text(100, 30, |f| help::render(&state, f));
    for (chord, _) in help::GLOBAL_KEYS {
        assert!(
            text.contains(chord),
            "missing global chord {chord:?}\n---\n{text}"
        );
    }
}

/// Review fix (task 4.25, Finding 2) regression test: `GLOBAL_KEYS` must not drift from
/// `App::handle_key`'s *real* global behavior. Unlike `help_global_keys_section_documents_the_fixed_
/// chords` above (which only proves each entry's own text renders — a tautology that would pass even
/// if a description were wrong), this drives each entry's chord through a real `App` and checks it
/// actually produces the effect its own description promises. It also pins the exact chord set/order,
/// so an entry that isn't a real global check (like the old `Tab`/`Shift+Tab` pair, which
/// `App::handle_key` never checks at all) can't be silently reintroduced without this test failing.
#[test]
fn global_keys_chords_reproduce_their_own_documented_effect_in_a_real_app() {
    let chords: Vec<&str> = help::GLOBAL_KEYS.iter().map(|(chord, _)| *chord).collect();
    assert_eq!(
        chords,
        vec!["F1", "Ctrl+K", "Ctrl+Q", "Ctrl+R", "Esc"],
        "GLOBAL_KEYS must only list chords App::handle_key actually treats as global, in this \
         set — see help.rs's module doc for why Tab/Shift+Tab don't belong here"
    );

    // "F1 — open this help screen"
    let mut app = App::new();
    app.update(AppEvent::Key(key(KeyCode::F(1), KeyModifiers::NONE)));
    assert!(matches!(app.current_screen(), Screen::Help(_)));

    // "Ctrl+K — open the command palette"
    let mut app = App::new();
    app.update(AppEvent::Key(key(
        KeyCode::Char('k'),
        KeyModifiers::CONTROL,
    )));
    assert!(matches!(app.current_screen(), Screen::Palette(_)));

    // "Ctrl+Q — quit"
    let mut app = App::new();
    app.update(AppEvent::Key(key(
        KeyCode::Char('q'),
        KeyModifiers::CONTROL,
    )));
    assert!(app.should_quit());

    // "Ctrl+R — open message requests"
    let mut app = App::new();
    app.update(AppEvent::Key(key(
        KeyCode::Char('r'),
        KeyModifiers::CONTROL,
    )));
    assert!(matches!(app.current_screen(), Screen::Requests(_)));

    // "Esc — back / close overlay": exercised via the help/palette overlays this file already opens
    // elsewhere (`esc_from_help_pops_back` / `esc_from_palette_pops_back_without_dispatching_anything`
    // in `app.rs`'s own test module); not re-proven here since, per the module doc, `Esc` is the
    // aggregate common-case across per-screen handling rather than one single hardcoded check this
    // file could exercise the same way as the four above.
}

// ---------------------------------------------------------------------------
// 3. Palette screen's own behavior: filtering, navigation, dispatch outcome
// ---------------------------------------------------------------------------

#[test]
fn typing_filters_to_a_subsequence_match() {
    let mut state = PaletteState::new(synthetic_registry());
    for c in "alph".chars() {
        palette::handle_key(&mut state, char_key(c));
    }
    let filtered = state.filtered();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, "demo.alpha");
}

#[test]
fn a_query_matching_nothing_yields_an_empty_filtered_list_and_says_so() {
    let mut state = PaletteState::new(synthetic_registry());
    for c in "zzzznomatch".chars() {
        palette::handle_key(&mut state, char_key(c));
    }
    assert!(state.filtered().is_empty());
    let text = render_to_text(100, 30, |f| palette::render(&state, f));
    assert!(text.contains("no matching"));
}

#[test]
fn backspace_clears_the_filter_one_character_at_a_time() {
    let mut state = PaletteState::new(synthetic_registry());
    for c in "alpha".chars() {
        palette::handle_key(&mut state, char_key(c));
    }
    assert_eq!(state.filtered().len(), 1);
    for _ in 0.."alpha".len() {
        palette::handle_key(&mut state, key(KeyCode::Backspace, KeyModifiers::NONE));
    }
    assert_eq!(state.query, "");
    assert_eq!(
        state.filtered().len(),
        2,
        "empty query matches everything again"
    );
}

#[test]
fn selection_does_not_move_above_the_top_or_below_the_bottom() {
    let mut state = PaletteState::new(synthetic_registry());
    palette::handle_key(&mut state, key(KeyCode::Up, KeyModifiers::NONE));
    assert_eq!(state.selected, 0, "saturating at the top");

    palette::handle_key(&mut state, key(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(state.selected, 1);
    palette::handle_key(&mut state, key(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(
        state.selected, 1,
        "clamped at the bottom (2 entries, index 1)"
    );
}

#[test]
fn enter_on_the_selected_command_reports_run_with_its_action() {
    let mut state = PaletteState::new(synthetic_registry());
    // Default selection is index 0 — "demo.alpha".
    let (effects, outcome) =
        palette::handle_key(&mut state, key(KeyCode::Enter, KeyModifiers::NONE));
    assert!(
        effects.is_empty(),
        "the screen itself never dispatches — App does, via the outcome"
    );
    match outcome {
        PaletteOutcome::Run(PaletteAction::Effect(factory)) => {
            assert!(matches!(factory(), Effect::FetchBundle));
        }
        other => panic!("expected Run(Effect(FetchBundle)), got {other:?}"),
    }
}

#[test]
fn enter_with_no_matches_is_a_no_op_outcome() {
    let mut state = PaletteState::new(synthetic_registry());
    for c in "zzzznomatch".chars() {
        palette::handle_key(&mut state, char_key(c));
    }
    let (effects, outcome) =
        palette::handle_key(&mut state, key(KeyCode::Enter, KeyModifiers::NONE));
    assert!(effects.is_empty());
    assert!(matches!(outcome, PaletteOutcome::None));
}

#[test]
fn palette_esc_reports_close() {
    let mut state = PaletteState::new(synthetic_registry());
    let (effects, outcome) = palette::handle_key(&mut state, key(KeyCode::Esc, KeyModifiers::NONE));
    assert!(effects.is_empty());
    assert!(matches!(outcome, PaletteOutcome::Close));
}

// ---------------------------------------------------------------------------
// 4. App-level global dispatch wiring (the addendum's own named scope)
// ---------------------------------------------------------------------------

#[test]
fn f1_opens_help_showing_the_apps_own_registered_commands() {
    let mut app = App::new();
    app.update(AppEvent::Key(key(KeyCode::F(1), KeyModifiers::NONE)));
    assert!(matches!(app.current_screen(), Screen::Help(_)));

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    let text = format!("{}", terminal.backend());
    for command in app.commands().iter() {
        assert!(text.contains(command.name));
    }
}

#[test]
fn ctrl_k_opens_palette_showing_the_apps_own_registered_commands() {
    let mut app = App::new();
    app.update(AppEvent::Key(key(
        KeyCode::Char('k'),
        KeyModifiers::CONTROL,
    )));
    assert!(matches!(app.current_screen(), Screen::Palette(_)));

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    let text = format!("{}", terminal.backend());
    for command in app.commands().iter() {
        assert!(text.contains(command.name));
    }
}

/// End-to-end: `Ctrl+K` → palette shows the built-in `Diagnostics` entry → `Enter` selects it →
/// `App::dispatch_palette_action` runs its `PaletteAction::PushPane` → `Screen::Extension` (the
/// `DiagnosticsPane`) is now current, and the palette itself is gone.
#[test]
fn diagnostics_is_reachable_end_to_end_through_the_palette() {
    let mut app = App::new();
    app.update(AppEvent::Key(key(
        KeyCode::Char('k'),
        KeyModifiers::CONTROL,
    )));
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
    assert!(effects.is_empty());
    assert!(matches!(app.current_screen(), Screen::Extension(_)));
}

// ---------------------------------------------------------------------------
// 5. Task 5.7 — App-level reconciliation: a real `r`, a real `Effect::RunDoctor`, a real
// `meridian_tui::worker::dispatch` subprocess call, fed back into the live `Screen::Extension` pane —
// see this file's own module doc's "Task 5.7" section.
// ---------------------------------------------------------------------------

/// Serializes test access to `$PATH`, which is process-global — same discipline
/// `tests/accept_to_chat.rs::EnvGuard` uses for `$MERIDIAN_HOME`. `DiagnosticsPane` hardcodes
/// `DOCTOR_BINARY = "meridian"` (never injectable through the effect/request — see that module's own
/// doc comment), so the only way to drive a real subprocess call down either branch (found vs.
/// not-found) from a real, live pane is to control what `"meridian"` resolves to on `$PATH`.
static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct PathGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev_path: Option<String>,
}

impl PathGuard {
    fn set(dir: &std::path::Path) -> Self {
        let lock = PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_path = std::env::var("PATH").ok();
        // SAFETY: serialized by PATH_LOCK, the only place in this test binary touching this var.
        unsafe {
            std::env::set_var("PATH", dir);
        }
        Self {
            _lock: lock,
            prev_path,
        }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        // SAFETY: see `PathGuard::set`.
        unsafe {
            match &self.prev_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
    }
}

fn render_app_to_text(app: &App, width: u16, height: u16) -> String {
    render_to_text(width, height, |f| app.render(f))
}

/// `Ctrl+K` → filter to the built-in `Diagnostics` command → `Enter` — lands on the real
/// `Screen::Extension` pane, exactly like `diagnostics_is_reachable_end_to_end_through_the_palette`
/// above, pulled out here since both tests below need it plus a following `r`.
fn open_diagnostics_via_palette(app: &mut App) {
    app.update(AppEvent::Key(key(
        KeyCode::Char('k'),
        KeyModifiers::CONTROL,
    )));
    assert!(matches!(app.current_screen(), Screen::Palette(_)));
    for c in "diagnostics".chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
    assert!(effects.is_empty(), "PushPane dispatches no worker Effect");
    assert!(matches!(app.current_screen(), Screen::Extension(_)));
}

/// **The not-on-`PATH` failure branch.** `$PATH` is pointed at an empty temp directory — guaranteed
/// to contain no `meridian` binary — so the real worker's real subprocess call genuinely fails to
/// even start the process, surfacing `std::io::ErrorKind::NotFound`. Proves the whole chain: real
/// `r` key → real `Effect::RunDoctor` → real `worker::dispatch` → real `WorkerEvent::Failed` → real
/// reconciliation into the live pane's `DiagnosticsStatus::Error`, rendered.
#[tokio::test]
async fn ctrl_k_diagnostics_r_runs_doctor_and_renders_a_real_not_on_path_failure() {
    let empty_path_dir = tempfile::tempdir().expect("tempdir");
    let _path_guard = PathGuard::set(empty_path_dir.path());

    let mut app = App::new();
    open_diagnostics_via_palette(&mut app);

    let effects = app.update(AppEvent::Key(char_key('r')));
    assert_eq!(effects.len(), 1, "r must dispatch exactly one effect");
    let effect = effects.into_iter().next().unwrap();
    match &effect {
        Effect::RunDoctor(RunDoctorEffect { request, .. }) => {
            assert_eq!(
                request.binary,
                meridian_tui::screens::diagnostics::DOCTOR_BINARY
            );
        }
        other => panic!("expected Effect::RunDoctor, got {other:?}"),
    }

    // The real worker — a real `std::process::Command` spawn attempt, not a hand-built
    // `WorkerEvent`.
    let mut session = OnboardingSession::default();
    let event = worker_dispatch(effect, &mut session).await;
    let message = match &event {
        WorkerEvent::Failed(Effect::RunDoctor(RunDoctorEffect { outcome: None, .. }), message) => {
            assert!(
                message.contains("not found"),
                "expected an honest not-found message, got: {message}"
            );
            message.clone()
        }
        other => panic!(
            "the doctor-binary-not-found path must surface as WorkerEvent::Failed against a real \
             $PATH with no meridian binary on it, got {other:?}"
        ),
    };

    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    let text = render_app_to_text(&app, 80, 24);
    assert!(
        text.contains(&message),
        "expected the real not-found message rendered live in the diagnostics pane:\n{text}"
    );
    assert!(
        text.contains("doctor failed"),
        "expected the pane's own honest failure framing:\n{text}"
    );
}

/// **The success branch, through a real subprocess.** `apps/tui` cannot depend on `apps/cli` at all
/// (ADR 0020 — see `crate::screens::diagnostics`'s own module doc), so this cannot invoke the real
/// `meridian doctor --json`. Instead `$PATH` is pointed at a tiny temp directory containing a real,
/// executable, on-`PATH` script literally named `meridian` that answers `doctor --json` with one
/// valid report line — a genuine subprocess spawn and a genuine stdout capture/parse
/// (`crate::screens::diagnostics::run_doctor_binary`/`parse_doctor_json`), standing in only for the
/// *content* `apps/cli`'s own real binary would have produced, never for the spawn/parse mechanism
/// itself. Unix-only (`std::os::unix::fs::PermissionsExt` for `chmod +x`; the shebang line requires a
/// POSIX shell) — mirrors `apps/tui/src/store/export.rs`'s own `#[cfg(unix)]` precedent for
/// filesystem-permission-dependent tests in this crate.
#[cfg(unix)]
#[tokio::test]
async fn ctrl_k_diagnostics_r_runs_doctor_and_renders_a_real_success_report_from_a_real_subprocess()
{
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = tempfile::tempdir().expect("tempdir");
    let script_path = bin_dir.path().join("meridian");
    std::fs::write(
        &script_path,
        "#!/bin/sh\n\
         echo '{\"nat\":\"full-cone\",\"host\":true,\"srflx\":true,\"relay\":true,\"path\":\"direct\"}'\n",
    )
    .expect("write fake meridian script");
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod +x the fake meridian script");
    let _path_guard = PathGuard::set(bin_dir.path());

    let mut app = App::new();
    open_diagnostics_via_palette(&mut app);

    let effects = app.update(AppEvent::Key(char_key('r')));
    assert_eq!(effects.len(), 1, "r must dispatch exactly one effect");
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::RunDoctor(_)));

    let mut session = OnboardingSession::default();
    let event = worker_dispatch(effect, &mut session).await;
    match &event {
        WorkerEvent::Completed(Effect::RunDoctor(RunDoctorEffect {
            outcome: Some(report),
            ..
        })) => {
            assert_eq!(report.cells.len(), 1);
            assert_eq!(report.cells[0].nat, "full-cone");
            assert_eq!(report.cells[0].path, "direct");
        }
        other => panic!(
            "expected a completed RunDoctor against the real fake-meridian subprocess, got {other:?}"
        ),
    }

    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    let text = render_app_to_text(&app, 80, 24);
    assert!(
        text.contains("full-cone"),
        "expected the real subprocess's report rendered live in the diagnostics pane:\n{text}"
    );
    assert!(text.contains("direct"));
    assert!(
        !text.to_lowercase().contains("doctor failed"),
        "a successful run must never render as a failure:\n{text}"
    );
}
