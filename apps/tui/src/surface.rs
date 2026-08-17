//! The extension registry every later feature's TUI surface plugs into — the mechanism behind
//! Definition of Done gate 9 ("every user-visible feature ships a TUI surface... registered, never
//! by editing the TUI core"), per
//! [tui-client.md §8](../../../docs/architecture/tui-client.md#8-extension-contract--every-feature-ships-a-tui-surface).
//!
//! This module mirrors `apps/core/src/streams.rs`'s philosophy and API shape deliberately: a new
//! feature **registers** its surface — it never edits this crate's event loop, layout engine, or
//! store. Review changes here as if third parties will implement against them, because eventually
//! they will (T07, T09, T10, T13, T15, T16 all build their TUI surface against this file, and this
//! task ships the mechanism only — T17's own chat renderer is 4.20's job, not this one's).
//!
//! Three independent registration points, kept as three focused traits/types rather than one giant
//! "surface" trait (a feature might register only one of them):
//!
//! 1. [`MessageRenderer`] — keyed by stream-type id (`mrd.chat/1`, `mrd.file/1`, …), turns one
//!    [`HistoryEntry`] into the rows it renders as. [`MessageRendererRegistry::render`] is the
//!    **forward-compatibility guarantee**: an entry naming a stream type with no registered
//!    renderer renders as [`placeholder_lines`] instead of panicking or being dropped — a client
//!    that does not understand a stream type must remain fully usable.
//! 2. [`PaletteCommand`] — a name, description, optional [`KeyBinding`], and a [`PaletteAction`] to
//!    run, collected in a [`PaletteRegistry`] the (future) palette and help screens both read from.
//! 3. [`ExtensionPane`] — a trait a feature's pane/screen implements. `app.rs`'s [`crate::app::Screen`]
//!    gains exactly **one** new variant for this, `Screen::Extension(Box<dyn ExtensionPane>)`,
//!    added once by this task; every future feature's pane implements the trait instead of adding
//!    its own `Screen` variant (that would defeat "zero core edits").
//!
//! [`SurfaceRegistry`] bundles (1) and (2) into the single instance a future screen/palette will
//! hold; (3) has no map to register into — a pane reaches the screen stack by being boxed into
//! `Screen::Extension` directly (see [`PaletteAction::PushPane`]), not by being looked up by key.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::text::Line;
use ratatui::Frame;

use crate::app::{Effect, WorkerEvent};
use crate::store::history::HistoryEntry;

// ---------------------------------------------------------------------------
// 1. Message renderer, keyed by stream-type id
// ---------------------------------------------------------------------------

/// Turns one transcript entry into the rows it renders as. Implemented once per stream type
/// (`mrd.chat/1`, `mrd.file/1`, `mrd.location/1`, `mrd.call/1`, …) and registered via
/// [`register_message_renderer`] / [`MessageRendererRegistry::register`] — never by editing this
/// crate's transcript rendering directly.
///
/// Takes [`HistoryEntry`] directly (task 4.15's store schema, `stream: String` field) rather than a
/// narrower projection of it: it is already the minimal shape a transcript entry has in this crate
/// (id, direction, timestamp, stream-type id, body, delivery state), so a narrower view would just
/// duplicate those same fields with no schema left to trim — a future chat renderer (4.20) can
/// implement this trait against the real store type with no redesign.
///
/// **Known coupling, accepted deliberately (architect review, task 4.18 fix pass):** binding this
/// trait to the store's *concrete* `HistoryEntry` type, rather than a narrower/more abstract view,
/// means every registered renderer breaks simultaneously the moment 4.15's store schema changes —
/// there is no indirection layer absorbing that change. This is judged defensible today only because
/// no second real renderer exists yet to prove out an alternative shape (T09/T15 land later); once
/// one does, revisit whether `render` should take a narrower projection instead of the raw store
/// struct. Do not redesign this signature speculatively before that renderer exists.
pub trait MessageRenderer: Send + Sync {
    /// Registry key: the stream-type id this renderer handles, e.g. `"mrd.chat/1"`. Matches
    /// `HistoryEntry::stream` and `meridian_core::streams::StreamType::name`'s shape (`"mrd.<x>/<n>"`).
    fn stream_type(&self) -> &'static str;
    /// Turn one transcript entry into the rows it renders as. Pure — no I/O, consistent with every
    /// other `render` function in this crate (`docs/architecture/tui-client.md §4`).
    fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>>;
}

/// The exact forward-compatibility wording from
/// [tui-client.md §8](../../../docs/architecture/tui-client.md#8-extension-contract--every-feature-ships-a-tui-surface):
/// `[unsupported: mrd.foo/1 — update your client]`. A client that does not recognize a stream type
/// must remain fully usable — this is the string that makes that true instead of a panic or a
/// dropped entry.
pub fn placeholder_text(stream_type: &str) -> String {
    format!("[unsupported: {stream_type} — update your client]")
}

/// [`placeholder_text`] wrapped as the single-line row shape [`MessageRenderer::render`] returns,
/// so [`MessageRendererRegistry::render`]'s fallback and any direct caller share one formatting.
pub fn placeholder_lines(stream_type: &str) -> Vec<Line<'static>> {
    vec![Line::from(placeholder_text(stream_type))]
}

/// The set of registered [`MessageRenderer`]s, keyed by stream-type id. Built empty; features
/// extend it via [`register_message_renderer`] / [`MessageRendererRegistry::register`] with zero
/// edits to this type.
#[derive(Default)]
pub struct MessageRendererRegistry {
    renderers: BTreeMap<String, Arc<dyn MessageRenderer>>,
}

impl MessageRendererRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a renderer. The only mutation point downstream features use.
    ///
    /// **Collision contract:** registering a [`MessageRenderer::stream_type`] that already has a
    /// renderer silently overwrites the previous one (last-write-wins, no error) — a bare
    /// `BTreeMap::insert`, same intended contract as [`PaletteRegistry::register`]'s (see its doc
    /// comment for the rationale). Pinned by `surface_registry.rs`'s
    /// `renderer_registration_is_last_write_wins` test.
    pub fn register(&mut self, renderer: Arc<dyn MessageRenderer>) {
        self.renderers
            .insert(renderer.stream_type().to_string(), renderer);
    }

    /// Whether a stream-type id has a registered renderer.
    pub fn supports(&self, stream_type: &str) -> bool {
        self.renderers.contains_key(stream_type)
    }

    /// Look up a registered renderer by stream-type id.
    pub fn get(&self, stream_type: &str) -> Option<Arc<dyn MessageRenderer>> {
        self.renderers.get(stream_type).cloned()
    }

    /// Render one transcript entry: the registered renderer for `entry.stream` if one exists,
    /// [`placeholder_lines`] otherwise. **This never panics and never drops the entry** — the
    /// property the forward-compatibility acceptance criterion depends on. Every entry in a
    /// transcript — known or unknown — always produces at least one row.
    pub fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>> {
        match self.renderers.get(&entry.stream) {
            Some(renderer) => renderer.render(entry),
            None => placeholder_lines(&entry.stream),
        }
    }
}

/// Free-function form of [`MessageRendererRegistry::register`], mirroring
/// `meridian_core::streams::register_stream_type`'s shape so the two registries read identically at
/// call sites. Additive renderers use ONLY this (or the equivalent method) — never a core edit.
pub fn register_message_renderer(
    registry: &mut SurfaceRegistry,
    renderer: Arc<dyn MessageRenderer>,
) {
    registry.renderers.register(renderer);
}

// ---------------------------------------------------------------------------
// 2. Palette commands (+ optional key bindings)
// ---------------------------------------------------------------------------

/// A key chord a [`PaletteCommand`] can optionally bind to, e.g. `Ctrl+N`. Deliberately narrower
/// than crossterm's own [`KeyEvent`] (no `kind`/`state`) — only the two fields that matter for
/// matching a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBinding {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl KeyBinding {
    pub fn new(code: KeyCode, modifiers: KeyModifiers) -> Self {
        Self { code, modifiers }
    }

    /// Whether `key` triggers this binding.
    pub fn matches(&self, key: &KeyEvent) -> bool {
        self.code == key.code && self.modifiers == key.modifiers
    }
}

impl fmt::Display for KeyBinding {
    /// Human-readable form used by `crate::screens::help`/`crate::screens::palette` (task 4.25) —
    /// e.g. `"Ctrl+K"`, `"F1"`, `"y"`, `"Shift+Tab"`. **Not** a `config.toml` serialization format:
    /// nothing in this crate parses a `[keys]` rebind string back into a [`KeyBinding`] yet (see
    /// `crate::config`'s own module doc) — this exists purely for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            write!(f, "Ctrl+")?;
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            write!(f, "Alt+")?;
        }
        if self.modifiers.contains(KeyModifiers::SHIFT) {
            write!(f, "Shift+")?;
        }
        match self.code {
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::F(n) => write!(f, "F{n}"),
            KeyCode::Enter => write!(f, "Enter"),
            KeyCode::Esc => write!(f, "Esc"),
            KeyCode::Tab => write!(f, "Tab"),
            KeyCode::BackTab => write!(f, "Shift+Tab"),
            KeyCode::Backspace => write!(f, "Backspace"),
            KeyCode::Up => write!(f, "Up"),
            KeyCode::Down => write!(f, "Down"),
            KeyCode::Left => write!(f, "Left"),
            KeyCode::Right => write!(f, "Right"),
            KeyCode::Home => write!(f, "Home"),
            KeyCode::End => write!(f, "End"),
            KeyCode::PageUp => write!(f, "PageUp"),
            KeyCode::PageDown => write!(f, "PageDown"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// What triggering a [`PaletteCommand`] does — consistent with the existing [`Effect`]/
/// [`crate::app::Screen`] split (`docs/architecture/tui-client.md §4`): either dispatch a fixed
/// effect for the worker to run, or push a freshly built [`ExtensionPane`] onto the screen stack.
///
/// `PushPane` carries a *factory*, not a pane instance: a pane holds its own live state (e.g. a
/// transfer list's in-progress items), so each trigger of the command must build a fresh one rather
/// than share/reuse a single instance across invocations.
pub enum PaletteAction {
    /// Dispatch this effect for the (future) worker to execute.
    ///
    /// Boxed (task 4.19 review fix): once [`crate::app::AddedContact`] grew a real
    /// `Vec<meridian_core::trust::PinnedKey>` (Finding 1 — the effect-outcome payload must carry
    /// back a contact's *actual* trust state/history, not an assumed-fresh shape), [`Effect`] grew
    /// large enough that `PaletteAction`'s size gap against `PushPane`'s thin `Arc` tripped
    /// `clippy::large_enum_variant` — the same reason `crate::app::AppEvent::Worker` is boxed.
    Effect(Box<Effect>),
    /// Push a freshly constructed extension pane onto the screen stack
    /// (`Screen::Extension(pane())`).
    PushPane(Arc<dyn Fn() -> Box<dyn ExtensionPane> + Send + Sync>),
}

impl Clone for PaletteAction {
    fn clone(&self) -> Self {
        match self {
            PaletteAction::Effect(effect) => PaletteAction::Effect(effect.clone()),
            PaletteAction::PushPane(factory) => PaletteAction::PushPane(Arc::clone(factory)),
        }
    }
}

impl fmt::Debug for PaletteAction {
    /// Hand-rolled: `PushPane`'s `Arc<dyn Fn() -> ...>` has no `Debug` impl to derive.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaletteAction::Effect(effect) => f.debug_tuple("Effect").field(effect).finish(),
            PaletteAction::PushPane(_) => write!(f, "PushPane(<fn>)"),
        }
    }
}

/// One entry in the palette (and, automatically, in the generated help screen — tui-client.md §3:
/// "the palette lists the binding next to each entry", "the help screen is generated from the
/// binding table"). Registered via [`register_palette_command`] / [`PaletteRegistry::register`].
#[derive(Clone, Debug)]
pub struct PaletteCommand {
    /// Stable registry key, e.g. `"file.send"`. Not shown to the user — [`name`](Self::name) is.
    pub id: &'static str,
    /// Human-readable label shown in the palette/help.
    pub name: &'static str,
    /// One-line description shown alongside `name`.
    pub description: &'static str,
    /// The optional key chord that also triggers this command directly, without opening the
    /// palette.
    pub keybinding: Option<KeyBinding>,
    /// What happens when this command runs.
    pub action: PaletteAction,
}

/// The set of registered [`PaletteCommand`]s, keyed by [`PaletteCommand::id`]. Built empty;
/// features extend it via [`register_palette_command`] / [`PaletteRegistry::register`] with zero
/// edits to this type, the (future) palette screen, or the (future) generated help screen.
#[derive(Default, Clone, Debug)]
pub struct PaletteRegistry {
    commands: BTreeMap<String, PaletteCommand>,
}

impl PaletteRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a command. The only mutation point downstream features use.
    ///
    /// **Collision contract:** registering a [`PaletteCommand::id`] that already exists silently
    /// overwrites the previous registration (last-write-wins, no error) — a bare `BTreeMap::insert`.
    /// This is the intended, documented contract for this fix pass, not an unexamined accident: since
    /// features register independently without seeing each other's code, a hard error on collision
    /// would be a bigger design decision than this task scopes; pin today's actual behavior instead
    /// (`surface_registry.rs`'s `*_registration_is_last_write_wins` tests) and revisit only if
    /// real-world collisions turn out to be common enough to warrant one.
    pub fn register(&mut self, command: PaletteCommand) {
        self.commands.insert(command.id.to_string(), command);
    }

    /// Look up a registered command by id.
    pub fn get(&self, id: &str) -> Option<&PaletteCommand> {
        self.commands.get(id)
    }

    /// Every registered command, in id order — what [`crate::screens::help`] and
    /// [`crate::screens::palette`] iterate to build their content.
    pub fn iter(&self) -> impl Iterator<Item = &PaletteCommand> {
        self.commands.values()
    }

    /// The registered command (if any) whose [`KeyBinding`] matches `key` — the global key-dispatch
    /// step `crate::app::App::handle_key` consults before falling through to a screen's own handling.
    ///
    /// **Wired (task 4.25, closing the gap the 4.18 fix pass flagged here):** `App::handle_key` calls
    /// this method directly, after its own fixed, hardcoded global checks (`Ctrl+Q`/`Ctrl+R`/`F1`/
    /// `Ctrl+K`) and strictly before any screen-specific handling — see that method's own doc comment
    /// for the exact ordering and `app.rs`'s `#[cfg(test)] mod tests` for the ordering-regression
    /// coverage (a registered binding intercepts a screen's own same-key use; an unregistered key is
    /// completely unaffected).
    ///
    /// **Tie-break contract for two commands sharing a [`KeyBinding`]:** undefined by iteration order
    /// today — whichever command happens to come first in [`BTreeMap`] key (id) order wins. Not
    /// pinned as a deliberate design choice (unlike [`Self::register`]'s last-write-wins collision
    /// contract), just documented as the current, unexamined behavior.
    pub fn find_binding(&self, key: &KeyEvent) -> Option<&PaletteCommand> {
        self.commands
            .values()
            .find(|c| c.keybinding.as_ref().is_some_and(|b| b.matches(key)))
    }
}

/// Free-function form of [`PaletteRegistry::register`], mirroring [`register_message_renderer`]'s
/// shape.
pub fn register_palette_command(registry: &mut SurfaceRegistry, command: PaletteCommand) {
    registry.commands.register(command);
}

// ---------------------------------------------------------------------------
// 3. Panes / screens
// ---------------------------------------------------------------------------

/// A feature-registered pane or screen, pushed onto the screen stack as
/// `Screen::Extension(Box::new(pane))` (e.g. a transfer list for T09, a call status panel for T10).
/// Mirrors the shape every built-in screen module already has
/// (`crate::screens::onboarding`/`crate::screens::unlock`'s `handle_key`/`handle_worker`/`render`
/// trio), as a trait object instead of a bespoke `Screen` variant per feature — this is the one
/// mechanism that lets `app.rs`'s `Screen` enum gain exactly one new variant, ever, for every future
/// feature pane, rather than one per feature.
///
/// `Send + Sync` for the same reason `meridian_core::streams::StreamType` is: this crate's own
/// module doc treats every trait here as something a third-party-shaped feature will implement
/// against, so the bound is load-bearing from day one rather than added under later pressure.
pub trait ExtensionPane: Send + Sync {
    /// A short human-readable name — shown in a tab/breadcrumb if the (future) chrome around the
    /// screen stack wants one, and used by `Screen`'s hand-rolled `Debug` impl (trait objects can't
    /// derive `Debug`, so this is the only thing that ends up in a `{:?}` dump of an extension
    /// screen).
    fn title(&self) -> &str;
    /// Handle one key event; mirrors `crate::screens::*::handle_key`'s contract (synchronous, pure
    /// apart from mutating `self`, returns the [`Effect`]s a worker should execute). `Esc` is
    /// **not** routed here: `App::handle_key` treats an extension pane like any other non-root
    /// screen and pops it on `Esc` before this is ever called (tui-client.md §3: "Esc always means
    /// back"), so implementations do not need to special-case it.
    fn handle_key(&mut self, key: KeyEvent) -> Vec<Effect>;
    /// Handle a worker event completing/failing an effect this pane dispatched. Mirrors
    /// `crate::screens::*::handle_worker`'s contract.
    fn handle_worker(&mut self, event: WorkerEvent) -> Vec<Effect>;
    /// Pure view function — no I/O, no `.await`, same contract as every other `render` in this
    /// crate.
    fn render(&self, frame: &mut Frame<'_>);
}

// ---------------------------------------------------------------------------
// The combined registry
// ---------------------------------------------------------------------------

/// Bundles [`MessageRendererRegistry`] and [`PaletteRegistry`] — the single instance a future
/// screen (the transcript view for (1), the palette/help screens for (2)) will own and read from.
/// [`ExtensionPane`] (3) has no map here by design: a pane reaches the screen stack by being boxed
/// into `Screen::Extension` directly (typically via a [`PaletteAction::PushPane`] factory), not by
/// registry lookup.
#[derive(Default)]
pub struct SurfaceRegistry {
    renderers: MessageRendererRegistry,
    commands: PaletteRegistry,
}

impl fmt::Debug for SurfaceRegistry {
    /// Hand-rolled (task 4.25, `crate::app::App` grew a `SurfaceRegistry` field and needs `App`'s own
    /// `#[derive(Debug)]` to keep working): [`MessageRendererRegistry`] holds `Arc<dyn
    /// MessageRenderer>` trait objects with no `Debug` impl to derive through, so `renderers` is
    /// represented opaquely; `commands` is real (`PaletteRegistry` already derives `Debug`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SurfaceRegistry")
            .field("renderers", &"<opaque>")
            .field("commands", &self.commands)
            .finish()
    }
}

impl SurfaceRegistry {
    /// An empty registry — no renderers, no commands.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a message renderer. Equivalent to [`register_message_renderer`].
    pub fn register_renderer(&mut self, renderer: Arc<dyn MessageRenderer>) {
        self.renderers.register(renderer);
    }

    /// Register a palette command. Equivalent to [`register_palette_command`].
    pub fn register_command(&mut self, command: PaletteCommand) {
        self.commands.register(command);
    }

    /// The message-renderer sub-registry.
    pub fn renderers(&self) -> &MessageRendererRegistry {
        &self.renderers
    }

    /// The palette-command sub-registry.
    pub fn commands(&self) -> &PaletteRegistry {
        &self.commands
    }

    /// Render one transcript entry through the renderer registry — see
    /// [`MessageRendererRegistry::render`] for the placeholder-fallback guarantee.
    pub fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>> {
        self.renderers.render(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(stream: &str, body: &str) -> HistoryEntry {
        HistoryEntry {
            v: 1,
            mid: "deadbeef".to_string(),
            dir: crate::store::history::Direction::In,
            ts: 0,
            stream: stream.to_string(),
            body: body.to_string(),
            state: crate::store::history::MessageState::Received,
        }
    }

    struct Echo;
    impl MessageRenderer for Echo {
        fn stream_type(&self) -> &'static str {
            "mrd.exotic/1"
        }
        fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>> {
            vec![Line::from(entry.body.clone())]
        }
    }

    #[test]
    fn empty_registry_renders_placeholder() {
        let registry = MessageRendererRegistry::new();
        let lines = registry.render(&entry("mrd.exotic/1", "hi"));
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].to_string(),
            "[unsupported: mrd.exotic/1 — update your client]"
        );
    }

    #[test]
    fn registered_renderer_is_used_once_registered() {
        let mut registry = MessageRendererRegistry::new();
        assert!(!registry.supports("mrd.exotic/1"));
        registry.register(Arc::new(Echo));
        assert!(registry.supports("mrd.exotic/1"));
        let lines = registry.render(&entry("mrd.exotic/1", "hi"));
        assert_eq!(lines[0].to_string(), "hi");
    }

    #[test]
    fn palette_registry_register_and_lookup() {
        let mut registry = PaletteRegistry::new();
        registry.register(PaletteCommand {
            id: "test.cmd",
            name: "Test",
            description: "a test command",
            keybinding: Some(KeyBinding::new(KeyCode::Char('t'), KeyModifiers::CONTROL)),
            action: PaletteAction::Effect(Box::new(Effect::FetchBundle)),
        });
        assert!(registry.get("test.cmd").is_some());
        assert_eq!(registry.iter().count(), 1);
        let key = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
        assert_eq!(registry.find_binding(&key).unwrap().id, "test.cmd");
        let other = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        assert!(registry.find_binding(&other).is_none());
    }

    #[test]
    fn surface_registry_bundles_both() {
        let mut registry = SurfaceRegistry::new();
        register_message_renderer(&mut registry, Arc::new(Echo));
        register_palette_command(
            &mut registry,
            PaletteCommand {
                id: "test.cmd",
                name: "Test",
                description: "a test command",
                keybinding: None,
                action: PaletteAction::Effect(Box::new(Effect::FetchBundle)),
            },
        );
        assert!(registry.renderers().supports("mrd.exotic/1"));
        assert!(registry.commands().get("test.cmd").is_some());
        assert_eq!(
            registry.render(&entry("mrd.exotic/1", "hi"))[0].to_string(),
            "hi"
        );
    }
}
