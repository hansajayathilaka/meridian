//! TUI surface for `mrd.file/1` (T09 file transfer, task 10.11): a [`crate::surface::MessageRenderer`]
//! for transcript rows, a transfers-list [`crate::surface::ExtensionPane`], and a
//! [`crate::surface::PaletteCommand`] to reach it — registered entirely through `crate::surface`'s
//! three-point extension mechanism (task 4.18), per
//! `docs/architecture/tui-client.md §8` and `docs/tasks/phase-10/10.11-tui-surface.md`.
//!
//! ## Dependency boundary: this module does not, and cannot, depend on `apps/streams`
//! `meridian-tui` depends on `meridian-core` only ([ADR 0020](../../../../docs/adr/0020-tui-packaging.md)
//! condition 3), enforced structurally by `tools/lint-tui-no-cli.sh`'s allowlist (`meridian-tui`,
//! `-core`, `-proto`, `-envelope`, `-identity`, `-store`, `-crypto`, `-transport`, `-signaling` —
//! **no `meridian-streams`**). `apps/streams`'s sender/receiver engines (tasks 10.7/10.8) and the
//! not-yet-landed resume protocol (task 10.9, `docs/tasks/phase-10/10.9-resume-protocol.md`, still
//! `Status: pending` as of this task) are therefore unreachable from this module by construction, not
//! by choice — this is a real, CI-enforced architectural boundary, not a style preference this task
//! could route around. Everything below operates purely on this crate's own local types
//! ([`crate::store::history::HistoryEntry`] for the renderer, a TUI-local [`TransferEntry`] for the
//! pane) — exactly the same shape `crate::screens::diagnostics`'s own module doc describes for its
//! analogous `apps/cli`-boundary problem ("wrapping the existing output", never the other crate's
//! internal types).
//!
//! ## The registry-wiring gap this task flags rather than works around
//! [`register`] bundles this module's [`FileMessageRenderer`] and [`palette_command`] into a
//! [`crate::surface::SurfaceRegistry`] — the correct, sanctioned mechanism. **It is deliberately never
//! called from `crate::app`.** The only place a live `App` builds its own `SurfaceRegistry` is
//! `crate::app::App::new_with_config`, via the private free function
//! `crate::app::register_builtin_commands` — reaching it from here would mean editing `app.rs`, which
//! task 10.11's own scope names as review-blocking ("if this task needs [an edit to app.rs] ... the
//! surface registry (from Phase 4, task 4.18) has a gap this task should flag rather than work around
//! with a core edit"). Concretely: **today, nothing outside `apps/tui/src/app.rs` itself can add a
//! [`crate::surface::PaletteCommand`] or [`crate::surface::MessageRenderer`] to a real, running
//! session** — `crate::surface::SurfaceRegistry::register_command`/`register_renderer` are `pub`, but
//! the one live instance they would need to mutate is constructed and populated entirely inside
//! `app.rs`, with no `pub` seam (e.g. an `App::register_extension` method, or a `Vec` of registration
//! closures `App::new_with_config` folds over) for a downstream module to reach it. This is the exact
//! shape of gap `crate::surface`'s own module doc anticipates ("a new feature registers its surface,
//! it never edits this crate's event loop, layout engine, or store") but does not yet actually close
//! for the *command palette / renderer* register step the way it already does for
//! [`crate::surface::ExtensionPane`] (any pane reaches the stack via the already-`pub`
//! `App::push_screen`/`Screen::Extension`, with zero `app.rs` edit needed — see this module's own
//! tests, which exercise [`TransfersPane`] against a real `App` exactly that way). Closing it for real
//! is a Phase 4 follow-up (extending `crate::surface`'s own mechanism with a public registration seam
//! on `App`), not something this task's scope authorizes fixing by editing `app.rs` directly.
//!
//! Everything below is fully built and independently tested against `crate::surface`'s registries
//! directly (mirroring `tests/surface_registry.rs`'s own test shape) and, for the pane, against a
//! real `App`/`Screen::Extension` — proving the mechanism genuinely works the moment a future task
//! adds the one missing wiring call, without needing this module to change at all.
//!
//! ## Inline image preview: what's real here, and the one thing that still can't reach a terminal
//! [`ImageProtocol`]/[`detect_image_protocol`] is genuine env-based sixel/kitty capability
//! detection — **originated by this task, not reused from an existing implementation**: despite the
//! Risks/notes section of `docs/architecture/tui-client.md §8`'s T09 row assuming task 4.26
//! (terminal-constraint-degradation) already built this, a full repository grep for
//! `sixel`/`kitty`/`Sixel`/`Kitty` before this task turned up nothing outside this file — 4.26's own
//! `crate::theme` module (its actual, checked scope) covers only `NO_COLOR`/ASCII-glyph/narrow-width
//! degradation, never terminal *graphics*-protocol capability. That premise correction is recorded
//! here rather than silently assumed away.
//!
//! **Why [`FileMessageRenderer::render`] never actually emits a raw sixel/kitty escape sequence, even
//! when [`ImageProtocol`] detects support.** [`crate::surface::MessageRenderer::render`] returns
//! `Vec<Line<'static>>`, which only ever reaches a real terminal by being drawn into a ratatui
//! `Buffer` — and `ratatui::buffer::Buffer::set_stringn` strips every control character
//! (`.filter(|symbol| !symbol.contains(char::is_control))`) before a `Line`/`Span`/`Paragraph` is
//! actually rendered. This is not a guess: it is the exact, already-shipped, already-tested behavior
//! `tests/surface_registry.rs::hostile_stream_type_control_bytes_are_stripped_when_actually_drawn_to_a_buffer`
//! pins for this crate's own hostile-input hardening. A sixel/kitty escape sequence is, definitionally,
//! made of control bytes (ESC, and for kitty the APC introducer) — so embedding one in a `Line` cannot
//! survive to the real terminal through this trait's contract today, regardless of how correctly it is
//! built. A genuine live preview needs a raw-passthrough rendering path that bypasses `Buffer`'s normal
//! cell-diffing entirely (the approach dedicated crates such as `ratatui-image` take: writing the
//! escape sequence directly to the terminal at a screen position coordinated with, but not routed
//! through, the normal `Frame`/`Buffer` draw) — a layout-engine-level capability this crate does not
//! have, and adding one is exactly the kind of core edit this task's own scope excludes rather than
//! silently works around. **Consequence, and why this is not merely a hypothetical fallback path but
//! the actual, always-taken one today:** [`FileMessageRenderer::render`] always renders the text/
//! progress summary line, in every case, regardless of what [`ImageProtocol`] detects — proving, not
//! just documenting, this task's own risk note ("never assume support, always have the text-only
//! fallback path tested").

use ratatui::layout::{Constraint, Direction as LayoutDirection, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::app::{Effect, WorkerEvent};
use crate::store::history::{Direction as MsgDirection, HistoryEntry, MessageState};
use crate::surface::{
    ExtensionPane, MessageRenderer, PaletteAction, PaletteCommand, SurfaceRegistry,
};
use crate::theme::{color_or_none, glyph, GlyphKind, RenderCtx};

/// Registry name for this stream type — matches `apps/streams/src/file.rs::NAME` and
/// [`crate::surface::MessageRenderer::stream_type`]'s expected shape.
pub const NAME: &str = "mrd.file/1";

// ---------------------------------------------------------------------------
// Sixel/kitty terminal-graphics capability detection
// ---------------------------------------------------------------------------

/// Which inline-image escape-sequence dialect (if any) the terminal this process is attached to is
/// likely to understand — env-based, like every other terminal-capability signal this crate resolves
/// (mirrors [`crate::theme::RenderCtx::resolve`]'s split between a pure resolver and an env-reading
/// entry point). **Never assumed** — [`ImageProtocol::None`] is the default for anything not
/// positively recognized, matching this task's own risk note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageProtocol {
    /// Neither dialect recognized — the always-safe default.
    None,
    /// The kitty terminal graphics protocol (kitty itself, and terminals emulating it).
    Kitty,
    /// The DEC sixel graphics protocol (xterm built with `--enable-sixel-graphics`, mlterm, foot,
    /// WezTerm, …).
    Sixel,
}

/// The pure half of detection — see [`detect_image_protocol`] for the real-environment entry point.
/// Kitty takes precedence when both could plausibly match (a kitty-derived terminal setting `TERM`
/// to something sixel-suggestive alongside `KITTY_WINDOW_ID` should still get the richer, better-
/// specified kitty protocol).
pub fn resolve_image_protocol(
    term: Option<&str>,
    term_program: Option<&str>,
    kitty_window_id: Option<&str>,
) -> ImageProtocol {
    if kitty_window_id.is_some() || term == Some("xterm-kitty") {
        return ImageProtocol::Kitty;
    }
    let sixel_term_program = matches!(term_program, Some("WezTerm") | Some("mlterm"));
    let sixel_term = term.is_some_and(|t| t.contains("sixel") || t.contains("mlterm"));
    if sixel_term_program || sixel_term {
        return ImageProtocol::Sixel;
    }
    ImageProtocol::None
}

/// Resolves [`ImageProtocol`] against the real process environment. Read once at
/// [`FileMessageRenderer::new`] construction time, not per-render — [`MessageRenderer::render`] takes
/// no context argument (a stable, third-party-shaped trait signature; see
/// `crate::screens::chat::ChatMessageRenderer`'s own doc comment for the identical constraint), so a
/// renderer that needs an environment-derived input bakes it in at construction, the same pattern
/// that renderer already established for [`RenderCtx`].
pub fn detect_image_protocol() -> ImageProtocol {
    resolve_image_protocol(
        std::env::var("TERM").ok().as_deref(),
        std::env::var("TERM_PROGRAM").ok().as_deref(),
        std::env::var("KITTY_WINDOW_ID").ok().as_deref(),
    )
}

// ---------------------------------------------------------------------------
// mrd.file/1 message renderer
// ---------------------------------------------------------------------------

/// The JSON body this renderer parses out of a `mrd.file/1` [`HistoryEntry::body`] — **`TODO:
/// confirm`**: no earlier task pins this shape. Task 10.10 (`meridian send`, the CLI surface that
/// would be this convention's other writer) is still pending as of this task, and nothing in this
/// crate constructs a `mrd.file/1` history entry today, so there is no existing producer to match
/// against. This is a minimal, reasonable stand-in with something concrete to parse and test; a
/// future task reconciling it with 10.9/10.10's real shape can change it freely without touching
/// [`FileMessageRenderer`]'s own logic below, which only reads the fields here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileEntryBody {
    name: String,
    size: u64,
    #[serde(default)]
    bytes_done: u64,
    #[serde(default)]
    completed: bool,
}

impl FileEntryBody {
    /// Parses `body`; malformed/foreign JSON (e.g. this renderer registered against an entry that
    /// isn't actually shaped like this, or a hostile/future-version peer influencing history content)
    /// returns `None` rather than panicking — [`FileMessageRenderer::render`]'s caller,
    /// `crate::surface::MessageRendererRegistry::render`, must never panic on any entry (the
    /// forward-compatibility invariant this whole registry exists for).
    fn parse(body: &str) -> Option<Self> {
        serde_json::from_str(body).ok()
    }

    fn percent(&self) -> u8 {
        if self.completed {
            return 100;
        }
        if self.size == 0 {
            return 0;
        }
        let done = self.bytes_done.min(self.size);
        ((done as f64 / self.size as f64) * 100.0)
            .round()
            .clamp(0.0, 100.0) as u8
    }
}

/// Renders one `mrd.file/1` transcript entry as a single-line name/progress/state summary — see the
/// module doc's "inline image preview" section for why this is the *only* thing this renderer ever
/// actually produces today, and [`ImageProtocol`] for the (real, tested, but currently unreachable-
/// through-this-trait) capability detection this task also delivers.
///
/// Carries a [`RenderCtx`] snapshot, not a signature change to [`MessageRenderer::render`] — same
/// reasoning and same pattern as `crate::screens::chat::ChatMessageRenderer`'s own doc comment.
pub struct FileMessageRenderer {
    ctx: RenderCtx,
    /// Recorded at construction (see [`detect_image_protocol`]'s own doc comment) — read only by
    /// [`Self::image_protocol`], since [`Self::render`] never emits an image escape sequence today.
    image_protocol: ImageProtocol,
}

impl Default for FileMessageRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl FileMessageRenderer {
    /// Detects [`ImageProtocol`] from the real environment and resolves [`RenderCtx`] against
    /// [`crate::config::TuiConfig::default`] — the same "reasonable default until a live integration
    /// hands over a real one" contract [`RenderCtx::default`] itself documents.
    pub fn new() -> Self {
        Self {
            ctx: RenderCtx::default(),
            image_protocol: detect_image_protocol(),
        }
    }

    /// Test/integration seam: an explicit [`RenderCtx`] and [`ImageProtocol`], bypassing both real
    /// environment reads.
    pub fn with_ctx_and_protocol(ctx: RenderCtx, image_protocol: ImageProtocol) -> Self {
        Self {
            ctx,
            image_protocol,
        }
    }

    /// The [`ImageProtocol`] this renderer detected at construction — exposed for tests and for a
    /// future raw-passthrough rendering path (see the module doc) to consult without re-detecting.
    pub fn image_protocol(&self) -> ImageProtocol {
        self.image_protocol
    }
}

impl MessageRenderer for FileMessageRenderer {
    fn stream_type(&self) -> &'static str {
        NAME
    }

    fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>> {
        let Some(body) = FileEntryBody::parse(&entry.body) else {
            // Never panics, never drops the row — same discipline
            // `crate::surface::placeholder_lines` itself follows, just scoped to *this* renderer's
            // own malformed-body case rather than an entirely unknown stream type.
            return vec![Line::from(format!(
                "[{NAME}: could not read this transfer's details]"
            ))];
        };

        let who = match entry.dir {
            MsgDirection::Out => "sending",
            MsgDirection::In => "receiving",
        };
        let percent = body.percent();
        let bar = progress_bar(percent, 10, self.ctx.unicode);
        let marker = transfer_state_marker(entry.state, &self.ctx);
        let mut style = Style::default();
        if entry.state == MessageState::Failed {
            if let Some(color) = color_or_none(Color::Red, &self.ctx) {
                style = style.fg(color);
            }
        }

        vec![Line::from(Span::styled(
            format!(
                "{who:<9} {}  {bar} {percent:>3}%  ({} bytes){marker}",
                body.name, body.size
            ),
            style,
        ))]
    }
}

/// A `width`-slot ASCII/unicode progress bar — mirrors `crate::theme`'s own unicode/ASCII-fallback
/// convention (never assumes unicode rendering support) without adding a new
/// [`crate::theme::GlyphKind`] variant for a single, file-transfer-specific glyph pair.
fn progress_bar(percent: u8, width: usize, unicode: bool) -> String {
    let filled = ((percent as usize) * width / 100).min(width);
    let (fill_ch, empty_ch) = if unicode { ('▓', '░') } else { ('#', '-') };
    let mut bar = String::with_capacity(width);
    for i in 0..width {
        bar.push(if i < filled { fill_ch } else { empty_ch });
    }
    bar
}

/// Delivery/transfer-state marker, reusing `crate::theme`'s existing [`GlyphKind`] delivery variants
/// (the same enum `crate::screens::chat`'s own `state_marker` reads) rather than inventing a parallel
/// one — [`HistoryEntry::state`] is the same [`MessageState`] enum for every stream type, transfers
/// included.
fn transfer_state_marker(state: MessageState, ctx: &RenderCtx) -> String {
    match state {
        MessageState::Composing => " (preparing)".to_string(),
        MessageState::Pending => " (pending)".to_string(),
        MessageState::Sent => format!(" {}", glyph(GlyphKind::DeliverySent, ctx)),
        MessageState::Delivered => format!(" {}", glyph(GlyphKind::DeliveryDelivered, ctx)),
        MessageState::Failed => format!(" {}", glyph(GlyphKind::DeliveryFailed, ctx)),
        MessageState::Received => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Transfers-list extension pane
// ---------------------------------------------------------------------------

/// Which side of a [`TransferEntry`] this process is on — a pane-local concept, independent of
/// [`HistoryEntry::dir`] (this pane's rows are not sourced from history entries at all; see the
/// module doc's dependency-boundary section for why there is no live producer wiring this yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Send,
    Receive,
}

/// One transfer's status. [`TransferStatus::ResumeRequested`] is a *UI-only* acknowledgement of the
/// resume affordance below — never fabricated into [`TransferStatus::InProgress`], because
/// `docs/architecture/tui-client.md §6` rule 10 ("the UI never renders an optimistic checkmark for a
/// send the transport did not confirm") applies just as much to "resumed" as it does to "delivered".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    InProgress,
    Completed,
    /// No progress for a while — plausibly recoverable via the resume affordance.
    Stalled,
    Failed(String),
    /// The user pressed the resume key on a [`TransferStatus::Stalled`]/[`TransferStatus::Failed`]
    /// entry; see [`handle_key`]'s own doc comment for exactly why nothing is actually dispatched yet.
    ResumeRequested,
}

/// One row in the transfers list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferEntry {
    /// Opaque display id (e.g. a short stream/session identifier) — never a full pubkey or path,
    /// consistent with this crate's "petname/fingerprint, never raw identifiers in the UI unless
    /// already the established convention" posture.
    pub id: String,
    pub name: String,
    pub direction: TransferDirection,
    pub total_bytes: u64,
    pub bytes_done: u64,
    pub status: TransferStatus,
}

impl TransferEntry {
    pub fn percent(&self) -> u8 {
        if matches!(self.status, TransferStatus::Completed) {
            return 100;
        }
        if self.total_bytes == 0 {
            return 0;
        }
        let done = self.bytes_done.min(self.total_bytes);
        ((done as f64 / self.total_bytes as f64) * 100.0)
            .round()
            .clamp(0.0, 100.0) as u8
    }

    /// Whether the resume affordance applies to this entry — [`TransferStatus::Stalled`] or
    /// [`TransferStatus::Failed`] only, mirroring the feature spec's "resume after redial" framing
    /// (`docs/architecture/features/09-file-transfer.md`).
    pub fn can_resume(&self) -> bool {
        matches!(
            self.status,
            TransferStatus::Stalled | TransferStatus::Failed(_)
        )
    }
}

/// [`TransfersPane`]'s own state — separated from the pane wrapper the same way every other screen in
/// this crate splits a plain state struct from its `handle_key`/`handle_worker`/`render` trio (and,
/// for extension panes specifically, from the [`ExtensionPane`] adapter — see
/// `crate::screens::diagnostics::DiagnosticsPane`'s identical split).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransfersPaneState {
    pub transfers: Vec<TransferEntry>,
    pub selected: usize,
}

/// Handles one key event for the transfers list: `↑`/`k` and `↓`/`j` move the selection (clamped,
/// never panicking on an empty list); `r`/`R`/`Enter` triggers the resume affordance for the selected
/// entry if [`TransferEntry::can_resume`] — see the doc comment on the match arm below for exactly
/// why this never dispatches an [`Effect`] today. `Esc` is never handled here — see [`ExtensionPane::
/// handle_key`]'s own doc comment; `crate::app::App`'s dispatch pops this pane before this function
/// is ever called for `Esc`, mirroring every other screen's identical contract in this crate.
pub fn handle_key(state: &mut TransfersPaneState, key: KeyEvent) -> Vec<Effect> {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => {
            if !state.transfers.is_empty() {
                state.selected = (state.selected + 1).min(state.transfers.len() - 1);
            }
            Vec::new()
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.selected = state.selected.saturating_sub(1);
            Vec::new()
        }
        KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
            if let Some(entry) = state.transfers.get_mut(state.selected) {
                if entry.can_resume() {
                    entry.status = TransferStatus::ResumeRequested;
                }
            }
            // TODO(task 10.9): the in-stream missing-range-bitmap resume protocol
            // (`docs/tasks/phase-10/10.9-resume-protocol.md`) is still `Status: pending` as of this
            // task, and even once it lands, `apps/tui` structurally cannot call into
            // `apps/streams`'s sender/receiver engines directly (see this module's own "dependency
            // boundary" doc section — `tools/lint-tui-no-cli.sh`'s allowlist has no
            // `meridian-streams` entry). Once both exist, this arm should dispatch whatever `Effect`
            // a future worker-wiring task adds for "re-request missing ranges for transfer `id`",
            // mirroring `crate::screens::diagnostics`'s own `Effect::RepairAcceptedContact`
            // request/outcome round trip — and this pane's own `handle_worker` below is exactly
            // where the resulting `WorkerEvent` would land.
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// No [`Effect`] this pane dispatches has a real worker outcome yet (see [`handle_key`]'s own `TODO`)
/// — a future worker-wiring task extends this to move a [`TransferStatus::ResumeRequested`] entry
/// back to [`TransferStatus::InProgress`]/[`TransferStatus::Failed`] on the real round trip, mirroring
/// `crate::screens::diagnostics::handle_worker`'s identical `Completed`/`Failed` split.
pub fn handle_worker(_state: &mut TransfersPaneState, _event: WorkerEvent) -> Vec<Effect> {
    Vec::new()
}

/// Pure view function — same contract as every other `render` in this crate.
pub fn render(state: &TransfersPaneState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — File Transfers (mrd.file/1)");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let ctx = RenderCtx::default();
    let lines: Vec<Line<'static>> = if state.transfers.is_empty() {
        vec![Line::from(
            "no transfers yet — use the palette's \"Send File\" command to start one",
        )]
    } else {
        state
            .transfers
            .iter()
            .enumerate()
            .map(|(i, t)| transfer_row(t, i == state.selected, &ctx))
            .collect()
    };
    frame.render_widget(Paragraph::new(lines), rows[0]);

    let footer = Paragraph::new(Line::from(footer_hint(state)));
    frame.render_widget(footer, rows[1]);
}

fn transfer_row(entry: &TransferEntry, selected: bool, ctx: &RenderCtx) -> Line<'static> {
    let arrow = match entry.direction {
        TransferDirection::Send => "\u{2191}",
        TransferDirection::Receive => "\u{2193}",
    };
    let percent = entry.percent();
    let bar = progress_bar(percent, 10, ctx.unicode);
    let status = match &entry.status {
        TransferStatus::InProgress => "in progress".to_string(),
        TransferStatus::Completed => "completed".to_string(),
        TransferStatus::Stalled => "stalled — press r to resume".to_string(),
        TransferStatus::Failed(reason) => format!("failed: {reason}"),
        TransferStatus::ResumeRequested => "resume requested…".to_string(),
    };
    let cursor = if selected { ">" } else { " " };
    let text = format!(
        "{cursor} {arrow} {}  {bar} {percent:>3}%  {status}",
        entry.name
    );
    if selected {
        Line::from(Span::styled(
            text,
            Style::default().add_modifier(ratatui::style::Modifier::BOLD),
        ))
    } else {
        Line::from(text)
    }
}

fn footer_hint(state: &TransfersPaneState) -> String {
    if state
        .transfers
        .get(state.selected)
        .is_some_and(TransferEntry::can_resume)
    {
        "↑↓/jk select · r resume · Esc back".to_string()
    } else {
        "↑↓/jk select · Esc back".to_string()
    }
}

/// The [`ExtensionPane`] wrapper — reached via [`palette_command`]'s `PaletteAction::PushPane`, same
/// pattern as `crate::screens::diagnostics::DiagnosticsPane`.
#[derive(Debug, Default)]
pub struct TransfersPane {
    state: TransfersPaneState,
}

impl TransfersPane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test/integration seam: construct with a starting transfer list rather than empty.
    pub fn with_transfers(transfers: Vec<TransferEntry>) -> Self {
        Self {
            state: TransfersPaneState {
                transfers,
                selected: 0,
            },
        }
    }
}

impl ExtensionPane for TransfersPane {
    fn title(&self) -> &str {
        "File Transfers"
    }

    fn handle_key(&mut self, key: KeyEvent) -> Vec<Effect> {
        handle_key(&mut self.state, key)
    }

    fn handle_worker(&mut self, event: WorkerEvent) -> Vec<Effect> {
        handle_worker(&mut self.state, event)
    }

    fn render(&self, frame: &mut Frame<'_>) {
        render(&self.state, frame)
    }
}

// ---------------------------------------------------------------------------
// Palette command + registration
// ---------------------------------------------------------------------------

/// The palette command that both reaches the transfers list *and* is this feature's "initiate a
/// send" entry point (task 10.11's Deliverable 3): the pane is the send-initiation surface (a future
/// worker-wiring task adds the actual file-picker/`Effect::SendFile` round trip this pane's own
/// `handle_key` doc comment anticipates), exactly as Deliverable 2 already describes it
/// ("ExtensionPane transfers list, registered/reachable via a PaletteCommand
/// (`PaletteAction::PushPane`)"). `id` matches the exact example `crate::surface::PaletteCommand::id`'s
/// own doc comment already names (`"file.send"`).
pub fn palette_command() -> PaletteCommand {
    PaletteCommand {
        id: "file.send",
        name: "Send File",
        description: "send a file over mrd.file/1 and view active/completed transfers, with \
                       progress and resume",
        keybinding: None,
        action: PaletteAction::PushPane(Arc::new(|| {
            Box::new(TransfersPane::new()) as Box<dyn ExtensionPane>
        })),
    }
}

/// Registers this module's [`FileMessageRenderer`] and [`palette_command`] into `surface` — the
/// sanctioned mechanism (mirrors `crate::app::register_builtin_commands`'s own two `surface.register_*`
/// calls). **Not called from `crate::app` today** — see the module doc's "registry-wiring gap" section
/// for exactly why, and what a future task needs to do to close it.
pub fn register(surface: &mut SurfaceRegistry) {
    surface.register_renderer(Arc::new(FileMessageRenderer::new()));
    surface.register_command(palette_command());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::{App, AppEvent, Screen};
    use crate::store::history::Direction as HistDir;
    use crate::surface::{placeholder_text, MessageRendererRegistry};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn file_entry(body: &str) -> HistoryEntry {
        HistoryEntry {
            v: 1,
            mid: "aabbccdd11223344".to_string(),
            dir: HistDir::In,
            ts: 1_763_000_000,
            stream: NAME.to_string(),
            body: body.to_string(),
            state: MessageState::Received,
        }
    }

    // -----------------------------------------------------------------------
    // Image-protocol detection — pure
    // -----------------------------------------------------------------------

    #[test]
    fn kitty_window_id_alone_is_enough_to_detect_kitty() {
        assert_eq!(
            resolve_image_protocol(None, None, Some("1")),
            ImageProtocol::Kitty
        );
    }

    #[test]
    fn xterm_kitty_term_detects_kitty_without_the_env_var() {
        assert_eq!(
            resolve_image_protocol(Some("xterm-kitty"), None, None),
            ImageProtocol::Kitty
        );
    }

    #[test]
    fn wezterm_term_program_detects_sixel() {
        assert_eq!(
            resolve_image_protocol(Some("xterm-256color"), Some("WezTerm"), None),
            ImageProtocol::Sixel
        );
    }

    #[test]
    fn kitty_takes_precedence_over_a_sixel_suggestive_term_program() {
        assert_eq!(
            resolve_image_protocol(None, Some("WezTerm"), Some("1")),
            ImageProtocol::Kitty
        );
    }

    #[test]
    fn an_ordinary_terminal_detects_neither() {
        assert_eq!(
            resolve_image_protocol(Some("xterm-256color"), None, None),
            ImageProtocol::None
        );
        // No env at all (a very common CI/non-interactive case) must degrade to `None`, never panic
        // or assume support.
        assert_eq!(
            resolve_image_protocol(None, None, None),
            ImageProtocol::None
        );
    }

    // -----------------------------------------------------------------------
    // FileMessageRenderer — deliverable/test 1: expected rows for a real entry
    // -----------------------------------------------------------------------

    #[test]
    fn renders_expected_row_for_a_well_formed_entry() {
        let renderer =
            FileMessageRenderer::with_ctx_and_protocol(RenderCtx::default(), ImageProtocol::None);
        let entry = file_entry(r#"{"name":"vacation.mp4","size":1000,"bytes_done":380}"#);
        let lines = renderer.render(&entry);
        assert_eq!(lines.len(), 1);
        let text = lines[0].to_string();
        assert!(text.contains("vacation.mp4"), "got: {text}");
        assert!(text.contains("38%"), "got: {text}");
        assert!(text.contains("1000 bytes"), "got: {text}");
        assert!(text.contains("receiving"), "got: {text}");
    }

    #[test]
    fn a_completed_transfer_always_renders_100_percent() {
        let renderer =
            FileMessageRenderer::with_ctx_and_protocol(RenderCtx::default(), ImageProtocol::None);
        let entry = file_entry(r#"{"name":"a.png","size":500,"bytes_done":100,"completed":true}"#);
        let text = renderer.render(&entry)[0].to_string();
        assert!(text.contains("100%"), "got: {text}");
    }

    #[test]
    fn a_zero_byte_incomplete_transfer_renders_zero_percent_without_dividing_by_zero() {
        let renderer = FileMessageRenderer::new();
        let entry = file_entry(r#"{"name":"empty.txt","size":0}"#);
        let text = renderer.render(&entry)[0].to_string();
        assert!(text.contains("0%"), "got: {text}");
    }

    #[test]
    fn an_outbound_entry_renders_sending_not_receiving() {
        let renderer = FileMessageRenderer::new();
        let mut entry = file_entry(r#"{"name":"a.bin","size":10,"bytes_done":10}"#);
        entry.dir = HistDir::Out;
        let text = renderer.render(&entry)[0].to_string();
        assert!(text.contains("sending"), "got: {text}");
    }

    #[test]
    fn a_malformed_body_renders_an_honest_message_never_panics() {
        let renderer = FileMessageRenderer::new();
        let entry = file_entry("not json at all");
        let lines = renderer.render(&entry);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].to_string().contains(NAME));
    }

    #[test]
    fn a_failed_transfer_is_styled_but_still_glyph_labeled_not_color_only() {
        let renderer = FileMessageRenderer::new();
        let mut entry = file_entry(r#"{"name":"a.bin","size":10,"bytes_done":3}"#);
        entry.state = MessageState::Failed;
        let text = renderer.render(&entry)[0].to_string();
        // Glyph + label, never color alone (tui-client.md §6 rule 2): the delivery-failed glyph
        // must appear in the plain rendered text itself, not only as a `Style` the assertion above
        // cannot see.
        assert!(
            text.contains('\u{2717}') || text.contains('x'),
            "got: {text}"
        );
    }

    // -----------------------------------------------------------------------
    // Deliverable/test 2: forward-compatibility regression guard — mirrors
    // `surface.rs`'s own `empty_registry_renders_placeholder` test, using a real `mrd.file/1`-shaped
    // entry to prove an *older client with no registered renderer at all* still falls back safely.
    // -----------------------------------------------------------------------

    #[test]
    fn an_older_client_with_no_registered_file_renderer_still_falls_back_to_the_placeholder() {
        let registry = MessageRendererRegistry::new();
        let entry = file_entry(r#"{"name":"vacation.mp4","size":1000,"bytes_done":380}"#);
        let lines = registry.render(&entry);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].to_string(), placeholder_text(NAME));
    }

    #[test]
    fn once_registered_the_real_renderer_wins_over_the_placeholder() {
        let mut registry = MessageRendererRegistry::new();
        assert!(!registry.supports(NAME));
        registry.register(Arc::new(FileMessageRenderer::new()));
        assert!(registry.supports(NAME));
        let entry = file_entry(r#"{"name":"vacation.mp4","size":1000,"bytes_done":380}"#);
        let lines = registry.render(&entry);
        assert_ne!(lines[0].to_string(), placeholder_text(NAME));
        assert!(lines[0].to_string().contains("vacation.mp4"));
    }

    #[test]
    fn register_bundles_both_the_renderer_and_the_palette_command() {
        let mut surface = SurfaceRegistry::new();
        register(&mut surface);
        assert!(surface.renderers().supports(NAME));
        assert!(surface.commands().get("file.send").is_some());
    }

    // -----------------------------------------------------------------------
    // Deliverable/test 3: the pane responds to key events per `ExtensionPane`'s contract
    // -----------------------------------------------------------------------

    fn sample_transfers() -> Vec<TransferEntry> {
        vec![
            TransferEntry {
                id: "t1".to_string(),
                name: "one.bin".to_string(),
                direction: TransferDirection::Send,
                total_bytes: 100,
                bytes_done: 100,
                status: TransferStatus::Completed,
            },
            TransferEntry {
                id: "t2".to_string(),
                name: "two.bin".to_string(),
                direction: TransferDirection::Receive,
                total_bytes: 100,
                bytes_done: 40,
                status: TransferStatus::Stalled,
            },
        ]
    }

    #[test]
    fn down_and_up_move_the_selection_and_clamp_at_both_ends() {
        let mut state = TransfersPaneState {
            transfers: sample_transfers(),
            selected: 0,
        };
        handle_key(&mut state, key(KeyCode::Up));
        assert_eq!(state.selected, 0, "must not go below zero");
        handle_key(&mut state, key(KeyCode::Down));
        handle_key(&mut state, key(KeyCode::Down));
        assert_eq!(state.selected, 1, "must clamp at the last index");
    }

    #[test]
    fn moving_selection_on_an_empty_list_never_panics() {
        let mut state = TransfersPaneState::default();
        handle_key(&mut state, key(KeyCode::Down));
        handle_key(&mut state, key(KeyCode::Up));
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn resume_on_a_stalled_entry_marks_it_resume_requested_and_dispatches_nothing_yet() {
        let mut state = TransfersPaneState {
            transfers: sample_transfers(),
            selected: 1,
        };
        let effects = handle_key(&mut state, key(KeyCode::Char('r')));
        assert!(effects.is_empty());
        assert_eq!(state.transfers[1].status, TransferStatus::ResumeRequested);
    }

    #[test]
    fn resume_on_a_completed_entry_is_a_no_op() {
        let mut state = TransfersPaneState {
            transfers: sample_transfers(),
            selected: 0,
        };
        handle_key(&mut state, key(KeyCode::Char('r')));
        assert_eq!(state.transfers[0].status, TransferStatus::Completed);
    }

    #[test]
    fn handle_worker_is_a_documented_no_op_today() {
        let mut state = TransfersPaneState::default();
        let effects = handle_worker(&mut state, WorkerEvent::Completed(Effect::FetchBundle));
        assert!(effects.is_empty());
    }

    #[test]
    fn render_works_against_a_test_backend_empty_and_populated() {
        for transfers in [Vec::new(), sample_transfers()] {
            let state = TransfersPaneState {
                transfers,
                selected: 0,
            };
            let backend = TestBackend::new(80, 24);
            let mut terminal = Terminal::new(backend).expect("test backend");
            terminal.draw(|f| render(&state, f)).expect("draw");
        }
    }

    #[test]
    fn extension_pane_title_and_render_work() {
        let pane = TransfersPane::with_transfers(sample_transfers());
        assert_eq!(pane.title(), "File Transfers");
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|f| pane.render(f)).expect("draw");
    }

    /// Proves the pane genuinely reaches a real `App`'s dispatch through the already-`pub`
    /// `Screen::Extension`/`App::push_screen` mechanism — no `app.rs` edit needed for this half of
    /// the contract (see the module doc's "registry-wiring gap" section for the half that still
    /// does).
    #[test]
    fn the_pane_reaches_a_real_app_and_responds_to_keys_there() {
        let mut app = App::new();
        app.push_screen(Screen::Extension(Box::new(TransfersPane::with_transfers(
            sample_transfers(),
        ))));
        assert!(matches!(app.current_screen(), Screen::Extension(_)));

        let effects = app.update(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('j'),
            KeyModifiers::NONE,
        )));
        assert!(effects.is_empty());

        let effects = app.update(AppEvent::Key(KeyEvent::new(
            KeyCode::Char('r'),
            KeyModifiers::NONE,
        )));
        assert!(effects.is_empty());

        // `Esc` pops the pane generically, exactly like every other registered extension pane.
        app.update(AppEvent::Key(KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        )));
        assert!(!matches!(app.current_screen(), Screen::Extension(_)));
    }
}
