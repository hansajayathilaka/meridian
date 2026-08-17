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

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::{Frame, Terminal};

use meridian_tui::app::{App, AppEvent, Effect, Screen, SendMessageEffect, SendMessageRequest};
use meridian_tui::screens::help::{self, HelpState};
use meridian_tui::screens::palette::{self, PaletteOutcome, PaletteState};
use meridian_tui::surface::{KeyBinding, PaletteAction, PaletteCommand, PaletteRegistry};

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
        action: PaletteAction::Effect(Box::new(Effect::FetchBundle)),
    });
    registry.register(PaletteCommand {
        id: "demo.beta",
        name: "Beta Command",
        description: "the second synthetic command, palette only, no binding",
        keybinding: None,
        action: PaletteAction::Effect(Box::new(Effect::SendMessage(SendMessageEffect {
            request: SendMessageRequest {
                peer_pubkey: [0u8; 32],
                peer_hint: String::new(),
                body: String::new(),
            },
            outcome: None,
        }))),
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
        PaletteOutcome::Run(PaletteAction::Effect(effect)) => {
            assert_eq!(*effect, Effect::FetchBundle);
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
