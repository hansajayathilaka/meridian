//! `meridian_tui::surface` — task 4.18's own test target
//! (`cargo nextest run -p meridian-tui --test surface_registry`).
//!
//! The acceptance criterion this file exists to prove, per
//! `docs/architecture/tui-client.md §8`: **an entry whose stream type has no registered renderer
//! renders as the labeled placeholder instead of breaking the transcript** — never a panic, never a
//! dropped entry, never corruption of a neighboring entry. The tests below are deliberately
//! adversarial about what "unknown" means (a made-up id, an empty string, a very long string, one
//! with unicode/control-ish characters) and prove the property holds for a whole `App` on the
//! screen stack too, not just the registry in isolation — a client that does not understand a
//! stream type must remain fully usable.
//!
//! Also covers the other two registration points (palette commands with key bindings, and
//! `Screen::Extension`/`ExtensionPane` reaching the real `App` event loop) with synthetic
//! registrations only — no concrete chat/file/call content, per this task's scope boundary (that is
//! 4.20's and later features' job, registering *against* this file's mechanism).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

use meridian_tui::app::{
    App, AppEvent, Effect, Screen, SendMessageEffect, SendMessageRequest, WorkerEvent,
};
use meridian_tui::store::history::{Direction as HistDir, HistoryEntry, MessageState};
use meridian_tui::surface::{
    placeholder_text, register_message_renderer, register_palette_command, ExtensionPane,
    KeyBinding, MessageRenderer, MessageRendererRegistry, PaletteAction, PaletteCommand,
    PaletteRegistry, SurfaceRegistry,
};

fn entry(stream: &str, body: &str) -> HistoryEntry {
    HistoryEntry {
        v: 1,
        mid: "0011223344556677".to_string(),
        dir: HistDir::In,
        ts: 1_763_000_000,
        stream: stream.to_string(),
        body: body.to_string(),
        state: MessageState::Received,
    }
}

// ---------------------------------------------------------------------------
// 1. Message renderer / placeholder fallback
// ---------------------------------------------------------------------------

/// A synthetic renderer standing in for a real feature's — proves the *mechanism*, not any real
/// stream type's content (out of scope for this task).
struct UppercaseEcho;
impl MessageRenderer for UppercaseEcho {
    fn stream_type(&self) -> &'static str {
        "mrd.synthetic/1"
    }
    fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>> {
        vec![Line::from(entry.body.to_uppercase())]
    }
}

#[test]
fn unknown_stream_type_renders_exact_placeholder_wording() {
    let registry = MessageRendererRegistry::new();
    let lines = registry.render(&entry("mrd.foo/1", "irrelevant"));
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0].to_string(),
        "[unsupported: mrd.foo/1 — update your client]"
    );
    assert_eq!(
        placeholder_text("mrd.foo/1"),
        "[unsupported: mrd.foo/1 — update your client]"
    );
}

/// A genuinely made-up, never-registered-anywhere stream-type id must still render safely — not a
/// crash, not a dropped row. This is the adversarial core of the acceptance criterion: nothing
/// about an attacker- or future-version-controlled `stream` string may do anything but land in the
/// placeholder format string.
#[test]
fn adversarial_unknown_stream_types_never_panic_and_always_produce_a_row() {
    let registry = MessageRendererRegistry::new();
    let hostile_ids = [
        "mrd.totally-made-up-type-nobody-registered/999999",
        "",
        "\0\0\0",
        "mrd.unicode/1 \u{1F600}\u{202E}right-to-left-override",
        &"mrd.long/1".repeat(200),
        "not-even-a-plausible-stream-id at all, with spaces and \"quotes\"",
    ];
    for id in hostile_ids {
        let lines = registry.render(&entry(id, "body"));
        assert!(!lines.is_empty(), "expected at least one row for {id:?}");
        assert!(
            lines[0].to_string().contains(id)
                || id.is_empty() && lines[0].to_string().contains("[unsupported: ")
        );
    }
}

/// Registering a renderer makes it win over the placeholder; everything else remains on the
/// placeholder path — registration is additive and per-key, never global.
#[test]
fn registered_renderer_wins_others_stay_on_placeholder() {
    let mut registry = MessageRendererRegistry::new();
    assert!(!registry.supports("mrd.synthetic/1"));
    registry.register(Arc::new(UppercaseEcho));
    assert!(registry.supports("mrd.synthetic/1"));

    let known = registry.render(&entry("mrd.synthetic/1", "hello"));
    assert_eq!(known[0].to_string(), "HELLO");

    let unknown = registry.render(&entry("mrd.other/1", "hello"));
    assert_eq!(
        unknown[0].to_string(),
        "[unsupported: mrd.other/1 — update your client]"
    );
}

/// The property the whole task exists for: a transcript mixing known and unknown stream types
/// renders **every** entry, in order, with the unknown ones placeholder'd and the known ones intact
/// — nothing about one bad entry corrupts, drops, or reorders its neighbors.
#[test]
fn interleaved_known_and_unknown_entries_all_survive_intact_and_in_order() {
    let mut registry = MessageRendererRegistry::new();
    registry.register(Arc::new(UppercaseEcho));

    let transcript = [
        entry("mrd.synthetic/1", "first"),
        entry("mrd.bogus/7", "second"),
        entry("mrd.synthetic/1", "third"),
        entry("mrd.another-bogus/1", "fourth"),
        entry("mrd.synthetic/1", "fifth"),
    ];

    let rendered: Vec<Vec<Line<'static>>> = transcript.iter().map(|e| registry.render(e)).collect();

    assert_eq!(rendered.len(), transcript.len());
    assert_eq!(rendered[0][0].to_string(), "FIRST");
    assert_eq!(
        rendered[1][0].to_string(),
        "[unsupported: mrd.bogus/7 — update your client]"
    );
    assert_eq!(rendered[2][0].to_string(), "THIRD");
    assert_eq!(
        rendered[3][0].to_string(),
        "[unsupported: mrd.another-bogus/1 — update your client]"
    );
    assert_eq!(rendered[4][0].to_string(), "FIFTH");
}

/// [`adversarial_unknown_stream_types_never_panic_and_always_produce_a_row`] only asserts against
/// `Line::to_string()`, which is raw, unfiltered concatenation — it does not exercise the actual
/// mechanism this crate relies on for safety. Ratatui strips control characters in
/// `Buffer::set_stringn` (`.filter(|symbol| !symbol.contains(char::is_control))`), which only runs
/// when a `Line`/`Span`/`Paragraph` is actually drawn to a `Buffer`/`Frame` — not in `Display`. Since
/// `HistoryEntry::stream` arrives via a peer-controlled `Hello.streams[].name` negotiation
/// (`docs/api/stream-types-v1.md`), a hostile peer choosing a stream-type id containing raw
/// ESC/CSI/OSC bytes is exactly the adversary this forward-compat guarantee must survive. This test
/// draws the placeholder rows through a real `Paragraph` + `TestBackend` (mirroring
/// `render_current`/`CounterPane`'s pattern below) and inspects the rendered buffer's cells directly,
/// pinning the actual regression-tested guarantee instead of only its appearance.
#[test]
fn hostile_stream_type_control_bytes_are_stripped_when_actually_drawn_to_a_buffer() {
    let registry = MessageRendererRegistry::new();
    let hostile_ids = [
        "mrd.esc/1\u{1b}[31mred\u{1b}[0m-reset",
        "mrd.osc/1\u{1b}]0;window-title\u{7}",
        "mrd.ctl/1\u{0}\u{1}\u{7}\u{8}",
        "mrd.unicode/1 \u{1F600}\u{202E}right-to-left-override",
    ];
    for id in hostile_ids {
        let lines = registry.render(&entry(id, "body"));
        let backend = TestBackend::new(160, 5);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| {
                let area = frame.area();
                frame.render_widget(Paragraph::new(lines.clone()), area);
            })
            .expect("draw");
        for cell in terminal.backend().buffer().content() {
            for ch in cell.symbol().chars() {
                assert!(
                    !ch.is_control(),
                    "control character {ch:?} survived into the rendered buffer for hostile id {id:?}"
                );
            }
        }
    }
}

/// Pins [`MessageRendererRegistry::register`]'s documented collision contract: registering a second
/// renderer under a stream-type id that already has one silently overwrites it (last-write-wins, no
/// error) — see the doc comment on `register` for why this is the intended contract, not an
/// unexamined accident.
#[test]
fn renderer_registration_is_last_write_wins() {
    struct First;
    impl MessageRenderer for First {
        fn stream_type(&self) -> &'static str {
            "mrd.collide/1"
        }
        fn render(&self, _entry: &HistoryEntry) -> Vec<Line<'static>> {
            vec![Line::from("first")]
        }
    }
    struct Second;
    impl MessageRenderer for Second {
        fn stream_type(&self) -> &'static str {
            "mrd.collide/1"
        }
        fn render(&self, _entry: &HistoryEntry) -> Vec<Line<'static>> {
            vec![Line::from("second")]
        }
    }

    let mut registry = MessageRendererRegistry::new();
    registry.register(Arc::new(First));
    registry.register(Arc::new(Second));

    let lines = registry.render(&entry("mrd.collide/1", "irrelevant"));
    assert_eq!(lines[0].to_string(), "second");
}

/// No normalization exists anywhere on a stream-type id (confirmed by grep over `surface.rs`) — two
/// ids differing only by case are two distinct, non-colliding registry entries. Not a bug, just an
/// undocumented contract this test makes explicit for future maintainers.
#[test]
fn stream_type_ids_compare_byte_exact_not_case_insensitively() {
    struct Lower;
    impl MessageRenderer for Lower {
        fn stream_type(&self) -> &'static str {
            "mrd.chat/1"
        }
        fn render(&self, _entry: &HistoryEntry) -> Vec<Line<'static>> {
            vec![Line::from("lower")]
        }
    }
    struct Upper;
    impl MessageRenderer for Upper {
        fn stream_type(&self) -> &'static str {
            "mrd.Chat/1"
        }
        fn render(&self, _entry: &HistoryEntry) -> Vec<Line<'static>> {
            vec![Line::from("upper")]
        }
    }

    let mut registry = MessageRendererRegistry::new();
    registry.register(Arc::new(Lower));
    registry.register(Arc::new(Upper));

    assert!(registry.supports("mrd.chat/1"));
    assert!(registry.supports("mrd.Chat/1"));
    assert_eq!(
        registry.render(&entry("mrd.chat/1", "x"))[0].to_string(),
        "lower"
    );
    assert_eq!(
        registry.render(&entry("mrd.Chat/1", "x"))[0].to_string(),
        "upper"
    );
}

// ---------------------------------------------------------------------------
// 2. Palette commands
// ---------------------------------------------------------------------------

#[test]
fn palette_command_registers_and_is_findable_by_binding() {
    let mut registry = PaletteRegistry::new();
    registry.register(PaletteCommand {
        id: "demo.ping",
        name: "Ping",
        description: "a synthetic demo command",
        keybinding: Some(KeyBinding::new(KeyCode::Char('p'), KeyModifiers::CONTROL)),
        action: PaletteAction::Effect(Arc::new(|| Effect::FetchBundle)),
    });

    assert_eq!(registry.iter().count(), 1);
    let found = registry
        .find_binding(&KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL))
        .expect("binding should be found");
    assert_eq!(found.id, "demo.ping");
    assert!(matches!(
        &found.action,
        PaletteAction::Effect(factory) if matches!(factory(), Effect::FetchBundle)
    ));

    // An unrelated key never matches.
    assert!(registry
        .find_binding(&KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE))
        .is_none());
}

/// Pins [`PaletteRegistry::register`]'s documented collision contract: registering a second command
/// under an id that already exists silently overwrites it (last-write-wins, no error) — see the doc
/// comment on `register` for why this is the intended contract, not an unexamined accident.
#[test]
fn palette_command_registration_is_last_write_wins() {
    let mut registry = PaletteRegistry::new();
    registry.register(PaletteCommand {
        id: "demo.collide",
        name: "First",
        description: "the first registration",
        keybinding: None,
        action: PaletteAction::Effect(Arc::new(|| Effect::FetchBundle)),
    });
    registry.register(PaletteCommand {
        id: "demo.collide",
        name: "Second",
        description: "the second registration",
        keybinding: None,
        action: PaletteAction::Effect(Arc::new(|| {
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

    assert_eq!(
        registry.iter().count(),
        1,
        "second registration overwrites, does not add"
    );
    let command = registry.get("demo.collide").expect("command present");
    assert_eq!(command.name, "Second");
    assert!(matches!(
        &command.action,
        PaletteAction::Effect(factory) if matches!(factory(), Effect::SendMessage(_))
    ));
}

#[test]
fn surface_registry_bundles_renderers_and_commands_with_zero_cross_edits() {
    let mut registry = SurfaceRegistry::new();
    register_message_renderer(&mut registry, Arc::new(UppercaseEcho));
    register_palette_command(
        &mut registry,
        PaletteCommand {
            id: "demo.ping",
            name: "Ping",
            description: "a synthetic demo command",
            keybinding: None,
            action: PaletteAction::Effect(Arc::new(|| Effect::FetchBundle)),
        },
    );

    assert!(registry.renderers().supports("mrd.synthetic/1"));
    assert!(registry.commands().get("demo.ping").is_some());
    assert_eq!(
        registry.render(&entry("mrd.synthetic/1", "hi"))[0].to_string(),
        "HI"
    );
    // Registering into one sub-registry never touches the other.
    assert_eq!(registry.commands().iter().count(), 1);
}

// ---------------------------------------------------------------------------
// 3. Extension panes reaching the real App/Screen stack
// ---------------------------------------------------------------------------

/// A synthetic pane proving the mechanism: it counts keys and worker events it has seen, and
/// renders its title plus the count — nothing chat/file/call-specific (out of scope).
struct CounterPane {
    title: String,
    keys_seen: AtomicU32,
    workers_seen: AtomicU32,
}

impl CounterPane {
    fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            keys_seen: AtomicU32::new(0),
            workers_seen: AtomicU32::new(0),
        }
    }
}

impl ExtensionPane for CounterPane {
    fn title(&self) -> &str {
        &self.title
    }

    fn handle_key(&mut self, _key: KeyEvent) -> Vec<Effect> {
        self.keys_seen.fetch_add(1, Ordering::SeqCst);
        vec![Effect::FetchBundle]
    }

    fn handle_worker(&mut self, _event: WorkerEvent) -> Vec<Effect> {
        self.workers_seen.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }

    fn render(&self, frame: &mut Frame<'_>) {
        let area = frame.area();
        let text = format!(
            "{} keys={} workers={}",
            self.title,
            self.keys_seen.load(Ordering::SeqCst),
            self.workers_seen.load(Ordering::SeqCst)
        );
        frame.render_widget(Paragraph::new(text), area);
    }
}

fn render_current(app: &App) -> String {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    format!("{}", terminal.backend())
}

#[test]
fn extension_pane_reaches_stack_without_editing_screen_dispatch_by_hand() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new(
        "demo-transfers",
    ))));

    assert!(matches!(app.current_screen(), Screen::Extension(_)));
    let text = render_current(&app);
    assert!(text.contains("demo-transfers"));
    assert!(text.contains("keys=0"));
}

#[test]
fn non_esc_keys_route_to_the_extension_pane_and_dispatch_its_effects() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new("demo-pane"))));

    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('x'),
        KeyModifiers::NONE,
    )));
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], Effect::FetchBundle));

    let text = render_current(&app);
    assert!(text.contains("keys=1"));
}

/// `Esc` always means "back" (tui-client.md §3) — even for a registered extension pane, which never
/// has to implement its own pop logic. Popping never goes below the root screen.
#[test]
fn esc_pops_the_extension_pane_generically() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new("demo-pane"))));
    assert!(matches!(app.current_screen(), Screen::Extension(_)));

    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Esc,
        KeyModifiers::NONE,
    )));
    assert!(effects.is_empty());
    // Back to onboarding (the root screen a fresh App starts on).
    assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
}

#[test]
fn worker_events_route_to_the_extension_pane() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new("demo-pane"))));

    let effects = app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(
        Effect::FetchBundle,
    ))));
    assert!(effects.is_empty());
    let text = render_current(&app);
    assert!(text.contains("workers=1"));
}

/// Two stacked `Screen::Extension` panes: routing (keys and worker events) only ever reaches the top
/// one, and `Esc` pops exactly one level, revealing the correct underlying pane with its own,
/// independently tracked counts untouched by anything that happened while it was covered.
#[test]
fn two_stacked_extension_panes_route_only_to_the_top_and_esc_reveals_the_correct_one() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new("bottom-pane"))));
    app.push_screen(Screen::Extension(Box::new(CounterPane::new("top-pane"))));

    assert!(matches!(app.current_screen(), Screen::Extension(_)));
    let text = render_current(&app);
    assert!(text.contains("top-pane"));
    assert!(!text.contains("bottom-pane"));

    // Non-Esc keys route only to the top pane; the bottom pane underneath never sees them.
    for _ in 0..2 {
        let effects = app.update(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
        )));
        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], Effect::FetchBundle));
    }
    assert!(render_current(&app).contains("top-pane keys=2 workers=0"));

    // A worker event likewise routes only to the top pane.
    app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(
        Effect::FetchBundle,
    ))));
    assert!(render_current(&app).contains("top-pane keys=2 workers=1"));

    // Esc pops exactly the top pane, revealing the bottom one — its counts are still zero, since
    // nothing routed to it while it was covered.
    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Esc,
        KeyModifiers::NONE,
    )));
    assert!(effects.is_empty());
    assert!(matches!(app.current_screen(), Screen::Extension(_)));
    let text = render_current(&app);
    assert!(text.contains("bottom-pane keys=0 workers=0"));
    assert!(!text.contains("top-pane"));

    // Esc again pops back below both extension panes to the root screen, same as the single-pane
    // case in `esc_pops_the_extension_pane_generically`.
    app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Esc,
        KeyModifiers::NONE,
    )));
    assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
}

/// Global `Ctrl+Q` still quits even while an extension pane is on top of the stack — a registered
/// feature pane can never block the one global escape hatch the app has.
#[test]
fn ctrl_q_still_quits_from_within_an_extension_pane() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new("demo-pane"))));
    app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('q'),
        KeyModifiers::CONTROL,
    )));
    assert!(app.should_quit());
}

/// `Debug`-formatting an `App`/`Screen` stack holding an extension pane must not panic — proves the
/// hand-rolled `Screen` `Debug` impl (required since `Box<dyn ExtensionPane>` can't derive it)
/// actually works end-to-end, and shows the pane's title rather than nothing/garbage.
#[test]
fn debug_formatting_a_screen_stack_with_an_extension_pane_does_not_panic() {
    let mut app = App::new();
    app.push_screen(Screen::Extension(Box::new(CounterPane::new(
        "debug-demo-pane",
    ))));
    let debug = format!("{app:?}");
    assert!(debug.contains("debug-demo-pane"));
}
