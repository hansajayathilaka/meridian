//! The message-request queue screen (task 4.21): the first-contact gate (system-design.md §3.5,
//! task 2.10, finalized for trust in task 4.7) as an actual reviewable UI — sender key, safety
//! number, short intro, accept/reject. Like every other screen in this crate,
//! [`handle_key`]/[`handle_worker`] only ever mutate a [`RequestsState`] and return the [`Effect`]s
//! a (future) worker should execute; [`render`] is a pure view function.
//!
//! ## No new trust decision made here
//! Everything this screen displays and acts on already exists, already reviewed, in
//! `meridian_core::chat::{ChatState, MessageRequest}` (task 2.10) and its task-4.7 trust glue
//! (`apps/cli/src/chat.rs::answer_request`). By the time a [`MessageRequest`] exists, the crypto
//! underneath it is done — X3DH ran, the envelope's signature verified, a live session is
//! installed — see [`MessageRequest`]'s own doc comment. What this screen gates is *delivery to the
//! user's own decision*, not authentication; this task is UI orchestration of that already-reviewed
//! glue, never a new protocol or trust primitive.
//!
//! ## [`RequestEntry`] — a screen-local display copy, not [`MessageRequest`] itself
//! Mirrors `crate::screens::contacts::ContactEntry`'s own precedent: [`MessageRequest`] derives only
//! `Clone`/`Serialize`/`Deserialize` (no `Debug`/`PartialEq`), which this crate's every other
//! screen state needs for `Screen`'s hand-rolled `Debug` impl and this task's own snapshot/
//! no-trace tests. [`RequestEntry`] is a small, independent copy of exactly the three fields §3.5/
//! 2.10 expose (`sender_ik`, `safety_number`, `intro`) — never a richer join like `ContactEntry`
//! needed, since there is no second store to reconcile here.
//!
//! ## State split: in-memory queue here, real persistence deferred to a future worker
//! [`RequestsState::entries`] is already-loaded, non-secret display data — mirrors
//! `crate::screens::contacts::ContactsState::entries`'s and `crate::screens::chat::ChatState::
//! entries`'s identical "a future Preflight step already has this" contract (a snapshot of
//! `meridian_core::chat::ChatState::pending_requests()`, out of this task's scope to load). This
//! screen owns no live `meridian_core::chat::ChatState`/`meridian_core::trust::TrustStore` handle at
//! all — unlike `crate::screens::chat::ChatState`, which owns a real `TrustStore` because its one
//! job (the send gate) is a pure, already-in-memory check with nothing to persist. Accepting or
//! rejecting a request is different: `meridian_core::chat::ChatState::accept_request`/
//! `reject_request` (and, on accept, `meridian_core::trust::TrustStore::observe` to TOFU-pin) must
//! run against the *real*, persisted stores and be re-sealed to disk — I/O this crate's `update`
//! never performs directly. So a decision here only ever transitions [`RequestsMode::List`] →
//! [`RequestsMode::Confirm`] → [`RequestsMode::Deciding`] (dispatching [`Effect::AcceptRequest`]/
//! [`Effect::RejectRequest`]) → back to [`RequestsMode::List`] with the entry removed, once
//! [`handle_worker`] sees the effect complete — the exact same "optimistic-nothing, wait for
//! `WorkerEvent::Completed`" shape `crate::screens::contacts`' own `AddContactState::Adding` uses
//! for [`Effect::AddContact`], not `crate::screens::chat`'s "mutate the owned copy directly"
//! shape, because there is no local copy of the real stores to mutate.
//!
//! ## Accept: order, and why there is no `peer_hint`
//! [`Effect::AcceptRequest`]'s doc comment carries the full reasoning: the future worker executing
//! it must call `accept_request` **then** `TrustStore::observe` (task 4.7's own fix — never pin
//! before the user decides), and must pass an empty hint, since `MessageRequest` carries none.
//! Delivering the accepted `intro` into a conversation transcript was out of task 4.21's scope, and
//! **task 4.42 looked at it again and deliberately deferred it** rather than leaving the question
//! floating — see [`crate::app::AcceptRequestRequest`]'s own doc comment for the three reasons
//! (chiefly: it means a sealed per-peer history *write*, and task 4.44 owns the matching *read*).
//!
//! There is still no `Screen::Requests` → `Screen::Chat` navigation from this screen: task 4.42
//! evaluated it ("Shape B") and severed it as optional, because it is not needed to reach the
//! accepted sender at all. Accepting now synthesizes that sender's `contacts.json` row and replays
//! it into the live `Screen::Main` (`worker::run_accept_request` + `crate::app::App::
//! apply_accepted_request`), so `Esc` back to Main lists them like any other contact, where `Enter`
//! opens `Screen::Chat` and `v` opens `Screen::Verify` — which is also the only route
//! `docs/architecture/tui-client.md §2` gives Verify at all, so a direct jump from here would not
//! have sufficed on its own.
//!
//! ## Reject: the "leaves no trace" property, at this UI layer
//! `meridian_core::chat::ChatState::reject_request`'s own doc comment (and
//! `apps/core/tests/message_request_gate.rs::
//! reject_produces_no_wire_signal_and_no_distinguishing_local_trace`) establish that, at the core
//! level, rejecting a real (now-discarded) request and rejecting a key that was never contacted at
//! all leave the exact same local trace: no pending request, no session. This screen mirrors that
//! property structurally: a rejected [`RequestEntry`] is *removed* from [`RequestsState::entries`]
//! on [`Effect::RejectRequest`]'s completion — there is no tombstone, no "rejected" flag, no
//! separate collection a rejected sender's key ever lands in. Once removed, `entries` for that
//! sender is indistinguishable from a sender who was never queued — see `tests/screens_requests.rs`
//! for the dedicated test asserting this. [`RequestsState`] itself is never sealed to disk (it is
//! pure UI state, rebuilt fresh from `pending_requests()` on next load), so the confirm-step
//! literal digression of typing `y` leaves no trace beyond this in-memory, ephemeral session either.
//!
//! ## Confirm-before-decide, not a single keypress
//! Unlike `crate::screens::contacts`' single-key `v`/`b` actions, both accept and reject here go
//! through [`RequestsMode::Confirm`] first (`y`/`n`) — mirrors
//! `crate::screens::contact_detail::DetailMode::ConfirmBlock`/`ConfirmDelete`'s identical shape.
//! Accept TOFU-pins a previously-unknown key; reject permanently discards the established session's
//! key material. Both are consequential enough that this screen's own judgment is that they warrant
//! the same explicit confirmation step contact detail already uses for block/delete, even though
//! `crate::screens::contacts`' `n`/`p`/`o` actions do not need one.
//!
//! ## Safety-number display: already computed, never recomputed
//! [`detail_lines`] renders [`RequestEntry::safety_number`] straight through
//! `meridian_core::crypto::display_groups` — a pure formatting function (digits → `"12345 67890 …"`
//! groups for readability), not a call to `meridian_core::crypto::safety_number` itself. This screen
//! never has (and does not need) `own_pubkey`/`peer_pubkey` to recompute anything — the digits were
//! already computed by `ChatState::open_inbound_gated` at the moment the request was queued, exactly
//! as an accepted contact's would be (§4.4). Verifying those digits out-of-band and marking a
//! contact `Verified` is task 4.22's `^V` flow, out of this task's scope — this screen only
//! *displays* the number alongside the intro for the accept/reject decision.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::chat::MessageRequest;
use meridian_core::crypto::display_groups;
use meridian_core::envelope::ChatContent;

use crate::app::{
    AcceptRequestEffect, AcceptRequestRequest, Effect, RejectRequestEffect, RejectRequestRequest,
    WorkerEvent,
};
use crate::screens::contacts::short_pubkey;

// ---------------------------------------------------------------------------
// RequestEntry — the screen-local display copy described in the module doc
// ---------------------------------------------------------------------------

/// One pending message request as this screen displays it — see the module doc's "`RequestEntry` —
/// a screen-local display copy" section for why this exists instead of holding
/// [`MessageRequest`] directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEntry {
    pub sender_ik: [u8; 32],
    pub safety_number: String,
    pub intro: ChatContent,
}

impl From<&MessageRequest> for RequestEntry {
    fn from(req: &MessageRequest) -> Self {
        Self {
            sender_ik: req.sender_ik,
            safety_number: req.safety_number.clone(),
            intro: req.intro.clone(),
        }
    }
}

/// A one-line summary of a request's intro content for the detail panel. `Text` shows the body
/// directly; `Receipt` (structurally possible — [`ChatContent`] has no way to statically forbid a
/// first envelope from being one, even though in practice a genuine first contact is always `Text`)
/// gets an honest placeholder rather than a panic or a blank line.
fn intro_summary(intro: &ChatContent) -> String {
    match intro {
        ChatContent::Text { body, .. } => body.clone(),
        ChatContent::Receipt { .. } => "(not a text message — a delivery receipt)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The whole Requests screen's state — see the module doc's "State split" section for why this
/// holds a plain [`Vec<RequestEntry>`] rather than a live `ChatState`.
#[derive(Debug, Clone)]
pub struct RequestsState {
    pub entries: Vec<RequestEntry>,
    /// Index into `entries`. Not read while [`RequestsMode::Confirm`]/[`RequestsMode::Deciding`] is
    /// active for a *different* purpose than display — the sender under decision is carried in
    /// those modes' own `sender_ik` field, not re-derived from `selected`, so a (currently
    /// unreachable, since list navigation is disabled outside `List` mode) stale index could never
    /// misdirect an in-flight decision.
    pub selected: usize,
    pub mode: RequestsMode,
}

impl RequestsState {
    /// `entries` is already-loaded, non-secret display data — mirrors
    /// `crate::screens::contacts::ContactsState::new`'s "a future Preflight step already has this"
    /// contract (see the module doc).
    pub fn new(entries: Vec<RequestEntry>) -> Self {
        Self {
            entries,
            selected: 0,
            mode: RequestsMode::List,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject,
}

/// The screen's own sub-mode — mirrors `crate::screens::contact_detail::DetailMode`'s
/// confirm-then-save shape (see the module doc's "Confirm-before-decide" section).
#[derive(Debug, Clone)]
pub enum RequestsMode {
    List,
    /// Awaiting `y`/`n` for the named decision on `sender_ik` (always the request currently at
    /// `RequestsState::selected` at the moment `a`/`r` was pressed).
    Confirm {
        sender_ik: [u8; 32],
        decision: Decision,
    },
    /// [`Effect::AcceptRequest`]/[`Effect::RejectRequest`] is in flight for `sender_ik` — mirrors
    /// `crate::screens::contact_detail::DetailMode::SavingBlock`'s in-flight shape.
    Deciding {
        sender_ik: [u8; 32],
        decision: Decision,
    },
    Error(String),
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the effects (if any) and whether `App` should pop this screen
/// (only `true` for `Esc` at the outermost [`RequestsMode::List`] — every nested sub-mode's `Esc`
/// instead cancels back to `List` without leaving the screen, mirroring
/// `crate::screens::contact_detail::handle_key`'s identical contract).
pub fn handle_key(state: &mut RequestsState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match state.mode.clone() {
        RequestsMode::List => handle_list_key(state, key),
        RequestsMode::Confirm {
            sender_ik,
            decision,
        } => handle_confirm_key(state, sender_ik, decision, key),
        // In-flight: no input to give while an effect is out — mirrors onboarding's
        // Generating/Registering arms.
        RequestsMode::Deciding { .. } => (Vec::new(), false),
        RequestsMode::Error(_) => handle_error_key(state, key),
    }
}

fn handle_list_key(state: &mut RequestsState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Up => move_selection(state, -1),
        KeyCode::Down => move_selection(state, 1),
        KeyCode::Char('k') if is_plain_char(key.modifiers) => move_selection(state, -1),
        KeyCode::Char('j') if is_plain_char(key.modifiers) => move_selection(state, 1),
        KeyCode::Char('a') if is_plain_char(key.modifiers) => {
            if let Some(entry) = state.entries.get(state.selected) {
                state.mode = RequestsMode::Confirm {
                    sender_ik: entry.sender_ik,
                    decision: Decision::Accept,
                };
            }
        }
        KeyCode::Char('r') if is_plain_char(key.modifiers) => {
            if let Some(entry) = state.entries.get(state.selected) {
                state.mode = RequestsMode::Confirm {
                    sender_ik: entry.sender_ik,
                    decision: Decision::Reject,
                };
            }
        }
        KeyCode::Esc => return (Vec::new(), true),
        _ => {}
    }
    (Vec::new(), false)
}

fn move_selection(state: &mut RequestsState, delta: i32) {
    let n = state.entries.len();
    if n == 0 {
        state.selected = 0;
        return;
    }
    let cur = state.selected.min(n - 1) as i32;
    let next = (cur + delta).clamp(0, n as i32 - 1);
    state.selected = next as usize;
}

fn handle_confirm_key(
    state: &mut RequestsState,
    sender_ik: [u8; 32],
    decision: Decision,
    key: KeyEvent,
) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let effect = match decision {
                Decision::Accept => Effect::AcceptRequest(AcceptRequestEffect {
                    request: AcceptRequestRequest { sender_ik },
                    outcome: None,
                }),
                Decision::Reject => Effect::RejectRequest(RejectRequestEffect {
                    request: RejectRequestRequest { sender_ik },
                    outcome: None,
                }),
            };
            state.mode = RequestsMode::Deciding {
                sender_ik,
                decision,
            };
            (vec![effect], false)
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.mode = RequestsMode::List;
            (Vec::new(), false)
        }
        _ => (Vec::new(), false),
    }
}

fn handle_error_key(state: &mut RequestsState, key: KeyEvent) -> (Vec<Effect>, bool) {
    if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
        state.mode = RequestsMode::List;
    }
    (Vec::new(), false)
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Removes the entry for `sender_ik`, if any, and clamps `selected` back into range — the single
/// place a decided request leaves `entries`, on both the accept and reject paths (see the module
/// doc's "leaves no trace" section for why reject's removal has no other side effect than this).
fn remove_entry(state: &mut RequestsState, sender_ik: &[u8; 32]) {
    state.entries.retain(|e| &e.sender_ik != sender_ik);
    let n = state.entries.len();
    if state.selected >= n {
        state.selected = n.saturating_sub(1);
    }
}

/// Handles a [`WorkerEvent`] arriving while this screen is current. An event that doesn't match
/// what's currently deciding — no decision in flight, the right shape but a different
/// sender/effect, or (mirrors `crate::screens::chat::handle_worker`'s `peer_pubkey` guard) the
/// *right* effect variant and decision kind but naming a different `sender_ik` than the one this
/// screen is actually waiting on — is silently ignored, never a panic — mirrors every other
/// screen's `handle_worker` in this crate. Never itself produces a further `Effect` (unlike
/// `crate::screens::chat`'s acknowledgment-then-resend chain): accept/reject is a single
/// request/outcome round trip.
pub fn handle_worker(state: &mut RequestsState, event: WorkerEvent) -> Vec<Effect> {
    let RequestsMode::Deciding {
        sender_ik,
        decision,
    } = state.mode.clone()
    else {
        return Vec::new();
    };
    match (decision, event) {
        (
            Decision::Accept,
            WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect { request, .. })),
        ) if request.sender_ik == sender_ik => {
            remove_entry(state, &sender_ik);
            state.mode = RequestsMode::List;
        }
        (
            Decision::Accept,
            WorkerEvent::Failed(
                Effect::AcceptRequest(AcceptRequestEffect { request, .. }),
                message,
            ),
        ) if request.sender_ik == sender_ik => {
            state.mode = RequestsMode::Error(message);
        }
        (
            Decision::Reject,
            WorkerEvent::Completed(Effect::RejectRequest(RejectRequestEffect { request, .. })),
        ) if request.sender_ik == sender_ik => {
            remove_entry(state, &sender_ik);
            state.mode = RequestsMode::List;
        }
        (
            Decision::Reject,
            WorkerEvent::Failed(
                Effect::RejectRequest(RejectRequestEffect { request, .. }),
                message,
            ),
        ) if request.sender_ik == sender_ik => {
            state.mode = RequestsMode::Error(message);
        }
        _ => {}
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — see the module doc.
pub fn render(state: &RequestsState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let title = format!("Meridian — Requests ({})", state.entries.len());
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    render_list(state, frame, rows[0]);
    render_detail(state, frame, rows[1]);

    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[2]);
}

fn render_list(state: &RequestsState, frame: &mut Frame<'_>, area: Rect) {
    if state.entries.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "(no pending requests)",
                Style::default().add_modifier(Modifier::DIM),
            )))
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let lines: Vec<Line<'static>> = state
        .entries
        .iter()
        .enumerate()
        .map(|(i, entry)| request_row_line(entry, i == state.selected))
        .collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

/// One request-list row: selection marker, the mockup's `?` glyph (tui-client.md §2's `? mrd1:9c…
/// @org-b` row — a request is, by definition, not yet trusted at all, distinct from every
/// [`crate::screens::contacts::trust_glyph_and_label`] state), and the truncated pubkey fingerprint
/// (tui-client.md §6 rule 2's "glyph + label", applied here since there is no petname to pair it
/// with yet — a request's sender has no `Contact` record until accepted).
fn request_row_line(entry: &RequestEntry, selected: bool) -> Line<'static> {
    let marker = if selected { "> " } else { "  " };
    let short = short_pubkey(&entry.sender_ik);
    let text = format!("{marker}? {short}");
    let style = if selected {
        Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
    } else {
        Style::default().fg(Color::Yellow)
    };
    Line::from(Span::styled(text, style))
}

fn render_detail(state: &RequestsState, frame: &mut Frame<'_>, area: Rect) {
    let lines = detail_lines(state);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn detail_lines(state: &RequestsState) -> Vec<Line<'static>> {
    let Some(entry) = state.entries.get(state.selected) else {
        return vec![Line::from(Span::styled(
            "No pending message requests.",
            Style::default().add_modifier(Modifier::DIM),
        ))];
    };

    let mut lines = vec![
        Line::from(format!("from: {}", short_pubkey(&entry.sender_ik))),
        Line::from(""),
        Line::from("safety number (compare out of band before deciding):"),
        Line::from(display_groups(&entry.safety_number)),
        Line::from(""),
        Line::from("intro:"),
        Line::from(intro_summary(&entry.intro)),
    ];

    match &state.mode {
        RequestsMode::List => {}
        RequestsMode::Confirm { decision, .. } => {
            lines.push(Line::from(""));
            let prompt = match decision {
                Decision::Accept => "accept this request? (y/n)".to_string(),
                Decision::Reject => "reject this request? this discards the session — the \
                                      sender sees no difference from an unanswered message. (y/n)"
                    .to_string(),
            };
            lines.push(Line::from(Span::styled(
                prompt,
                Style::default().fg(Color::Red),
            )));
        }
        RequestsMode::Deciding { .. } => {
            lines.push(Line::from(""));
            lines.push(Line::from("please wait…"));
        }
        RequestsMode::Error(message) => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                message.clone(),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from("Press Enter or Esc to continue."));
        }
    }
    lines
}

fn footer_hint(state: &RequestsState) -> String {
    match &state.mode {
        RequestsMode::List if state.entries.is_empty() => "Esc back".to_string(),
        RequestsMode::List => "↑↓/jk move · a accept · r reject · Esc back".to_string(),
        RequestsMode::Confirm { .. } => "y confirm · n/Esc cancel".to_string(),
        RequestsMode::Deciding { .. } => "please wait…".to_string(),
        RequestsMode::Error(_) => "Enter/Esc continue".to_string(),
    }
}
