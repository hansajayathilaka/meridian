//! The verification screen (task 4.22): 60-digit safety number + QR side by side, mark-verified,
//! block, and the two un-softenable key-change modals — the phase's central security-critical
//! screen. Like every other screen in this crate, [`handle_key`]/[`handle_worker`] only ever mutate
//! a [`VerifyState`] and return the [`Effect`]s a (future) worker should execute; [`render`] is a
//! pure view function.
//!
//! ## No new trust logic — this screen is presentation over already-reviewed T08 primitives
//! Every trust-relevant decision this screen makes is a direct call into
//! `meridian_core::trust::TrustStore` — [`TrustStore::can_send`] (which modal to show, if any),
//! [`TrustStore::mark_verified`] (the *only* path that clears [`TrustState::Blocked`]),
//! [`TrustStore::acknowledge_key_change`] (the pinned-contact re-pin path), and
//! [`TrustStore::set_user_blocked`] (task 4.6's local block, reused verbatim from
//! `crate::screens::contact_detail`'s own action). This module never re-derives, truncates, or
//! paraphrases a `SendGate::Warn`/`Blocked` reason string — [`banner_lines`] renders whatever
//! [`TrustStore::can_send`] handed back, in full, and [`apps/core/tests`] already pins that those
//! strings preserve verification-ux.md's canonical intent. The 60-digit number and QR come straight
//! from `meridian_core::crypto::safety_number`/`display_groups` and
//! `meridian_core::identity::render_terminal` — exactly `apps/cli/src/verify.rs`'s own primitives,
//! not a parallel implementation.
//!
//! ## Modal selection: driven by `SendGate`, not a screen-local reimplementation
//! [`banner_lines`] and [`footer_hint`] both switch on [`VerifyState::gate`] — a live,
//! never-cached `TrustStore::can_send` call, exactly like `crate::screens::chat::ChatState::gate`
//! (see that module's doc for why this must never be a value computed once and stored: it would go
//! stale the instant this screen itself mutates `state.trust`). `SendGate::Blocked(reason)` renders
//! the **KeyChangeBlocked** banner; `SendGate::Warn(reason)` renders **KeyChangeWarning**;
//! `SendGate::Ok` renders neither — there is no third modal shape and no screen-local guess at
//! which one applies beyond matching the gate's own variant. The one exception is the `Blocked`
//! banner's *header line*: `TrustStore::can_send` checks `Contact::user_blocked` before key-change
//! state and returns `Blocked` for either cause, so [`banner_lines`] additionally reads
//! `state.user_blocked()` (still a live `TrustStore` read, not a screen-local guess) to choose
//! between the "CONTACT BLOCKED" header (purely local, task 4.6 block — no key-change/interception
//! framing) and the "KEY CHANGE — SENDS BLOCKED" header (a genuine key-change incident) — the body
//! `reason` text itself is always rendered verbatim from `can_send` either way.
//!
//! ## The "no dismiss without verify" property, precisely
//! [`handle_view_key`] only ever offers three entry points into a [`VerifyMode::Confirm`]
//! sub-mode — `v` (→ [`VerifyAction::Verify`]), `b` (→ [`VerifyAction::Block`]), and `a` (→
//! [`VerifyAction::Acknowledge`], and *only* when [`VerifyState::gate`] is currently
//! [`SendGate::Warn`] — see the guard in [`handle_view_key`], which is this screen's own
//! enforcement of tui-client.md §6 rule 1's "no third option" for the **Blocked** case: acknowledge
//! is never even reachable when the gate is `Blocked`, defense-in-depth on top of
//! [`TrustStore::acknowledge_key_change`]'s own `TrustError::NotAcknowledgeable` refusal for that
//! state. From any `Confirm` sub-mode, **every** key other than `y`/`Y` cancels back to
//! [`VerifyMode::View`] without calling anything on `state.trust` — [`handle_confirm_key`] is the
//! *only* function that can transition out of `Confirm`, and [`apply_action`] is the *only* function
//! that ever calls [`TrustStore::mark_verified`]/[`TrustStore::acknowledge_key_change`]/
//! [`TrustStore::set_user_blocked`] in this module — grep for those three names if that changes.
//! There is no timed dismissal, no "remember my choice", and Esc from `View` only pops the screen
//! (tui-client.md §3: "Esc always means back") — it never touches `state.trust`, so leaving this
//! screen can never be mistaken for resolving the block/warning. `tests/screens_verify.rs` verifies
//! this by exhaustive keyspace enumeration, not a sampled check — see its own module doc.
//!
//! ## Effects: local state transition now, disk persistence later — correlated by peer
//! Mirrors `crate::screens::chat`'s own precedent for `TrustStore::acknowledge_key_change`: this
//! screen's [`VerifyState::trust`] is a real, already-loaded, in-memory `TrustStore` (not a
//! display-only copy like `crate::screens::contacts::ContactEntry`), so [`apply_action`] applies the
//! pure state transition **synchronously** — the very next `render` (and the very next
//! `VerifyState::gate` call) sees it immediately, with no round trip through a worker required for
//! this screen's own display to be correct. [`Effect::MarkVerified`] /
//! [`Effect::AcknowledgeKeyChange`] / [`Effect::SetUserBlocked`] are dispatched *in addition*, purely
//! so a future worker re-seals the real, persisted `trust.bin` to match — the same "screen already
//! knows the answer, the worker's only job is durability" shape
//! `crate::screens::contact_detail::Effect::SetUserBlocked`/`Effect::SetPetname` already use.
//!
//! **Worker-event correlation (the bug tasks 4.20 and 4.21 both hit).** Every arm of
//! [`handle_worker`] below matches on `request.pubkey == state.peer_pubkey` before touching
//! anything — a stale completion/failure for a *different* contact's verify/block/acknowledge
//! effect (reachable once this screen has real navigation and a user can back out of `Verify(A)`
//! before its persist effect resolves and open `Verify(B)`) is silently ignored, exactly like
//! `crate::screens::chat::handle_worker`'s `peer_pubkey` guard and
//! `crate::screens::requests::handle_worker`'s `sender_ik` guard. Since the trust-state transition
//! is already applied locally at dispatch time, a `Failed` event only ever surfaces a notice
//! (`state.notice`) explaining that the change may not have persisted to disk — it deliberately does
//! **not** roll back `state.trust`, on the same fail-safe reasoning `chat.rs::fail_send` uses for a
//! failed send: if the process exits *before* the persist effect resolves (a crash, force-quit, or
//! power loss, not merely a `Failed` event — this module never rolls back on `Failed` either), the
//! next launch reloads whatever `trust.bin` last durably held, discarding the unpersisted local
//! transition. For [`VerifyAction::Verify`] and [`VerifyAction::Acknowledge`], and for
//! [`VerifyAction::Block`]'s true→false (unblock) direction, that reversion is always to a stricter
//! or equal state — [`mark_verified`](meridian_core::trust::TrustStore::mark_verified) and
//! [`acknowledge_key_change`](meridian_core::trust::TrustStore::acknowledge_key_change) only ever
//! move a contact *out of* `Blocked`/`PinnedKeyChanged`, so an unpersisted revert lands back on the
//! stricter prior state, never a state advancing without dispatch of a matching Effect having
//! actually persisted. **`VerifyAction::Block`'s false→true (block) direction is the one exception,
//! not covered by that guarantee**: `set_user_blocked` is a bidirectional toggle, so pressing `b` to
//! block flips `state.trust` to blocked immediately and dispatches `Effect::SetUserBlocked` for
//! later persistence same as everything else — but if the process is killed before that persist
//! durably lands, the next launch silently reverts to *unblocked* with no record the block was ever
//! attempted. That is a fail-*open* revert, the mirror image of every other case in this module,
//! inherited from the same local-apply-then-persist-later shape tasks 4.6/4.19's
//! `contact_detail.rs` already uses (closing this gap would mean redesigning that shared pattern,
//! out of scope here).
//!
//! ## `own_pubkey`, and why this screen is not yet reachable from `crate::screens::contacts`
//! [`VerifyState::new`] takes `own_pubkey`/`peer_pubkey`/`peer_hint`/an already-loaded `TrustStore`
//! directly — the same "constructed with what it needs, unit-tested in isolation, wired into real
//! navigation by a later task" shape `crate::screens::chat::ChatState`/
//! `crate::screens::requests::RequestsState` already established for tasks 4.20/4.21.
//! `crate::app::Screen::Verify`'s own doc comment explains exactly why `crate::screens::contacts`'s
//! `v` key still shows its task-4.19-authored "not implemented yet" stand-in rather than pushing
//! this screen: `ContactsState` has no `own_pubkey` field and no live `TrustStore` handle to build a
//! [`VerifyState`] from (it works off `ContactEntry`, a display-only join — see that module's own
//! doc). Wiring `^V` for real is exactly the kind of "future task that gives `App` a real, loaded
//! `TrustStore`" every other screen in this crate has been waiting on since task 4.19.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::crypto::{display_groups, safety_number};
use meridian_core::identity::render_terminal;
use meridian_core::trust::{SendGate, TrustStore};

use crate::app::{
    AcknowledgeKeyChangeEffect, AcknowledgeKeyChangeRequest, Effect, MarkVerifiedEffect,
    MarkVerifiedRequest, SetUserBlockedEffect, SetUserBlockedRequest, WorkerEvent,
};
use crate::screens::contacts::{short_pubkey, trust_glyph_and_label};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The whole Verify screen's state — see the module doc for why this owns a real, already-loaded
/// [`TrustStore`] (mirrors `crate::screens::chat::ChatState`'s identical reasoning) rather than a
/// display-only copy.
///
/// **`#[derive(Debug)]`, no redaction needed** — same reasoning as `ChatState`'s own doc comment:
/// `own_pubkey`/`peer_pubkey` are public keys, `safety_number` is a public fingerprint (the entire
/// point of this screen is to display it), and `TrustStore` itself already derives `Debug` on the
/// "every field reachable from here is already-public contact metadata" basis (see its own doc
/// comment). Nothing reachable from here is a passphrase or key material.
#[derive(Debug)]
pub struct VerifyState {
    pub own_pubkey: [u8; 32],
    pub peer_pubkey: [u8; 32],
    /// Fallback label source if `trust.contact(peer_pubkey)` has no record at all — mirrors
    /// `ChatState::peer_hint`'s identical defensive fallback.
    pub peer_hint: String,
    /// Already loaded — see the module doc.
    pub trust: TrustStore,
    /// Computed once in [`VerifyState::new`], not recomputed on every render:
    /// `meridian_core::crypto::safety_number` runs an iterated SHA-512 (5200 rounds,
    /// `apps/crypto/src/fingerprint.rs`) — real, deliberate work, not something to redo at up to
    /// 60fps (tui-client.md §4) on every frame.
    pub safety_number: String,
    /// A transient, non-persisted status line — mirrors `ChatState::notice`'s identical contract.
    pub notice: Option<String>,
    pub mode: VerifyMode,
}

/// The screen's own sub-mode — mirrors `crate::screens::requests::RequestsMode`'s confirm-then-act
/// shape (see the module doc's "no dismiss without verify" section for why `Confirm` is the only
/// gate any of the three trust-mutating actions pass through).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMode {
    View,
    /// Awaiting `y`/`n` for `action`, always against `VerifyState::peer_pubkey` (this screen is
    /// always scoped to exactly one contact — there is no list/selection to disambiguate, unlike
    /// `crate::screens::requests::RequestsMode::Confirm`'s `sender_ik` field).
    Confirm(VerifyAction),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyAction {
    /// Mark the contact verified — the *only* action that can ever clear
    /// [`meridian_core::trust::TrustState::Blocked`] (task 4.4's core invariant; see
    /// [`apply_action`]).
    Verify,
    /// Toggle the local, user-initiated block (`Contact::user_blocked`) — task 4.6's block,
    /// independent of key-change trust state. Always available, in every gate state, mirroring
    /// `crate::screens::contact_detail`'s own block action.
    Block,
    /// Acknowledge a pending [`meridian_core::trust::TrustState::PinnedKeyChanged`] warning without
    /// verifying — only reachable from [`handle_view_key`] while
    /// [`VerifyState::gate`] is [`SendGate::Warn`]; see the module doc.
    Acknowledge,
}

impl VerifyState {
    /// `trust` is already loaded — see the module doc's "`own_pubkey`, and why this screen is not
    /// yet reachable" section for why this constructor takes everything directly rather than this
    /// crate loading it.
    pub fn new(
        own_pubkey: [u8; 32],
        peer_pubkey: [u8; 32],
        peer_hint: String,
        trust: TrustStore,
    ) -> Self {
        let safety_number = safety_number(&own_pubkey, &peer_pubkey);
        Self {
            own_pubkey,
            peer_pubkey,
            peer_hint,
            trust,
            safety_number,
            notice: None,
            mode: VerifyMode::View,
        }
    }

    /// The live send gate for this screen's peer — see the module doc for why this is a direct,
    /// un-cached call into `TrustStore::can_send` every time, never a value computed once and
    /// stored (mirrors `ChatState::gate`).
    pub fn gate(&self) -> SendGate {
        self.trust.can_send(&self.peer_pubkey)
    }

    /// The best available human-facing label for this screen's peer — same fallback chain as
    /// `ChatState::peer_label`.
    pub fn peer_label(&self) -> String {
        if let Some(contact) = self.trust.contact(&self.peer_pubkey) {
            if let Some(p) = contact.petname.as_deref().filter(|p| !p.is_empty()) {
                return p.to_string();
            }
            if !contact.hint.is_empty() {
                return contact.hint.clone();
            }
        } else if !self.peer_hint.is_empty() {
            return self.peer_hint.clone();
        }
        short_pubkey(&self.peer_pubkey)
    }

    /// Whether `peer_pubkey`'s contact currently carries the local, user-initiated block
    /// (`Contact::user_blocked` — task 4.6). `pub` so `tests/screens_verify.rs` can assert the
    /// toggle direction of [`VerifyAction::Block`] directly.
    pub fn user_blocked(&self) -> bool {
        self.trust
            .contact(&self.peer_pubkey)
            .map(|c| c.user_blocked)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the effects (if any) and whether `App` should pop this screen —
/// `true` only for a plain `Esc` while [`VerifyMode::View`] (this screen is always pushed on top of
/// something else, same convention as `crate::screens::chat`/`crate::screens::requests`). `Esc`
/// while [`VerifyMode::Confirm`]/[`VerifyMode::Error`] instead cancels back to `View` without
/// leaving the screen.
pub fn handle_key(state: &mut VerifyState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match state.mode.clone() {
        VerifyMode::View => handle_view_key(state, key),
        VerifyMode::Confirm(action) => (handle_confirm_key(state, action, key), false),
        VerifyMode::Error(_) => {
            handle_error_key(state, key);
            (Vec::new(), false)
        }
    }
}

fn handle_view_key(state: &mut VerifyState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Esc => return (Vec::new(), true),
        KeyCode::Char('v') if is_plain_char(key.modifiers) => {
            state.mode = VerifyMode::Confirm(VerifyAction::Verify);
        }
        KeyCode::Char('b') if is_plain_char(key.modifiers) => {
            state.mode = VerifyMode::Confirm(VerifyAction::Block);
        }
        KeyCode::Char('a') if is_plain_char(key.modifiers) => {
            // Only reachable while the gate is actually Warn — see the module doc and
            // `VerifyAction::Acknowledge`'s own doc. `TrustStore::acknowledge_key_change` would
            // itself refuse (`TrustError::NotAcknowledgeable`) for any other state, but this screen
            // does not even offer the option, matching tui-client.md §6 rule 1's "no third option"
            // for the Blocked case at the UI layer, not just at the trust-module layer.
            if matches!(state.gate(), SendGate::Warn(_)) {
                state.mode = VerifyMode::Confirm(VerifyAction::Acknowledge);
            }
        }
        _ => {}
    }
    (Vec::new(), false)
}

/// Handles a key while [`VerifyMode::Confirm`] is active. `y`/`Y` is the *only* key that dispatches
/// [`apply_action`] — every other key (explicitly `n`/`N`/`Esc`, and implicitly everything else via
/// the catch-all) cancels back to [`VerifyMode::View`] without touching `state.trust` at all. See
/// the module doc's "no dismiss without verify" section — `tests/screens_verify.rs` enumerates the
/// full practical keyspace against this function to pin that property.
fn handle_confirm_key(state: &mut VerifyState, action: VerifyAction, key: KeyEvent) -> Vec<Effect> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => apply_action(state, action),
        _ => {
            state.mode = VerifyMode::View;
            Vec::new()
        }
    }
}

fn handle_error_key(state: &mut VerifyState, key: KeyEvent) {
    if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
        state.mode = VerifyMode::View;
    }
}

/// The **only** function in this module that ever calls
/// [`TrustStore::mark_verified`]/[`TrustStore::acknowledge_key_change`]/[`TrustStore::set_user_blocked`]
/// — grep for those three names if that changes. Always transitions `state.mode` back to
/// [`VerifyMode::View`] on success, or [`VerifyMode::Error`] on a (rare — `UnknownContact`/
/// `NotAcknowledgeable`, both defensive here since this screen only ever offers `Acknowledge` while
/// the gate is genuinely `Warn`) trust-module error. Never partially applies: each branch either
/// fully succeeds (mutates `state.trust` and returns the matching persist [`Effect`]) or fully fails
/// (mutates nothing, returns no effect).
fn apply_action(state: &mut VerifyState, action: VerifyAction) -> Vec<Effect> {
    match action {
        VerifyAction::Verify => match state.trust.mark_verified(&state.peer_pubkey) {
            Ok(()) => {
                state.notice = None;
                state.mode = VerifyMode::View;
                vec![Effect::MarkVerified(MarkVerifiedEffect {
                    request: MarkVerifiedRequest {
                        pubkey: state.peer_pubkey,
                    },
                    outcome: None,
                })]
            }
            Err(e) => {
                state.mode = VerifyMode::Error(format!("could not mark verified: {e}"));
                Vec::new()
            }
        },
        VerifyAction::Block => {
            let new_blocked = !state.user_blocked();
            match state
                .trust
                .set_user_blocked(&state.peer_pubkey, new_blocked)
            {
                Ok(()) => {
                    state.notice = None;
                    state.mode = VerifyMode::View;
                    vec![Effect::SetUserBlocked(SetUserBlockedEffect {
                        request: SetUserBlockedRequest {
                            pubkey: state.peer_pubkey,
                            blocked: new_blocked,
                        },
                        outcome: None,
                    })]
                }
                Err(e) => {
                    state.mode = VerifyMode::Error(format!("could not update block: {e}"));
                    Vec::new()
                }
            }
        }
        VerifyAction::Acknowledge => match state.trust.acknowledge_key_change(&state.peer_pubkey) {
            Ok(()) => {
                state.notice = None;
                state.mode = VerifyMode::View;
                vec![Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
                    request: AcknowledgeKeyChangeRequest {
                        pubkey: state.peer_pubkey,
                    },
                    outcome: None,
                })]
            }
            Err(e) => {
                state.mode = VerifyMode::Error(format!("could not acknowledge: {e}"));
                Vec::new()
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`] arriving while this screen is current — see the module doc's "Effects:
/// local state transition now, disk persistence later" section. Every arm below matches on
/// `request.pubkey == state.peer_pubkey` before touching `state.notice`, the same correlation guard
/// `crate::screens::chat::handle_worker`/`crate::screens::requests::handle_worker` use, to avoid the
/// bug class tasks 4.20 and 4.21 both hit. An event that doesn't match — wrong `Effect` shape, or the
/// right shape but naming a different peer — is silently ignored, never a panic, mirroring every
/// other screen's `handle_worker` in this crate. Never itself produces a further `Effect`.
pub fn handle_worker(state: &mut VerifyState, event: WorkerEvent) -> Vec<Effect> {
    match event {
        WorkerEvent::Completed(Effect::MarkVerified(MarkVerifiedEffect { request, .. }))
            if request.pubkey == state.peer_pubkey =>
        {
            state.notice = None;
        }
        WorkerEvent::Failed(Effect::MarkVerified(MarkVerifiedEffect { request, .. }), message)
            if request.pubkey == state.peer_pubkey =>
        {
            state.notice = Some(format!("verification may not have saved: {message}"));
        }
        WorkerEvent::Completed(Effect::SetUserBlocked(SetUserBlockedEffect {
            request, ..
        })) if request.pubkey == state.peer_pubkey => {
            state.notice = None;
        }
        WorkerEvent::Failed(
            Effect::SetUserBlocked(SetUserBlockedEffect { request, .. }),
            message,
        ) if request.pubkey == state.peer_pubkey => {
            state.notice = Some(format!("block change may not have saved: {message}"));
        }
        WorkerEvent::Completed(Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
            request,
            ..
        })) if request.pubkey == state.peer_pubkey => {
            state.notice = None;
        }
        WorkerEvent::Failed(
            Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect { request, .. }),
            message,
        ) if request.pubkey == state.peer_pubkey => {
            state.notice = Some(format!("acknowledgment may not have saved: {message}"));
        }
        _ => {}
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — see the module doc.
pub fn render(state: &VerifyState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let (glyph, label) = trust_glyph_and_label(state.trust.trust_state(&state.peer_pubkey));
    let title = format!(
        "Meridian — Verify · {}  {glyph} {label}",
        state.peer_label()
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    render_body(state, frame, rows[0]);

    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

fn render_body(state: &VerifyState, frame: &mut Frame<'_>, area: Rect) {
    let banner = banner_lines(state);
    // **Security-relevant sizing, not merely cosmetic.** The banner carries this screen's
    // un-softenable canonical wording (verification-ux.md hard prohibition #3: "no burying the
    // block behind an easily-missed banner"). `banner.len()` is the *logical* line count — one of
    // those lines is the entire `blocked_reason`/`warn_reason` sentence as a single unwrapped
    // `Line`, which `Wrap{trim:false}` will spread across several *terminal* rows at any realistic
    // width. Sizing this region off the logical count instead of the wrapped count would silently
    // clip the tail of the canonical wording off-screen — exactly the kind of easily-missed banner
    // the hard prohibition names — so [`wrapped_height`] measures the actual rendered height at
    // this area's real width instead.
    //
    // **The banner's computed height is never reduced to make room for the number/QR pane below
    // it.** An earlier version of this function additionally clamped the result with
    // `.min(area.height.saturating_sub(3))` to always reserve 3 rows for the number/QR pane —
    // which silently reintroduced the exact clipping bug this comment describes (just gated on
    // *height* instead of *width*) at any terminal short enough that the two panes together don't
    // fit. The un-truncated `blocked_reason`/`warn_reason` text takes priority: it is
    // security-critical and not re-derivable once clipped, whereas the number/QR pane is a pure,
    // cheap-to-recompute display of already-known data. So the banner always gets exactly the
    // height `wrapped_height` says it needs (clamped only to the *physical* area height, so the
    // layout itself never over-allocates), and the number/QR pane gets whatever is left —
    // shrinking toward zero, and disappearing first, if the terminal is too short for both.
    let banner_height = wrapped_height(&banner, area.width).min(area.height);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(banner_height), Constraint::Min(0)])
        .split(area);

    if banner_height > 0 {
        frame.render_widget(Paragraph::new(banner).wrap(Wrap { trim: false }), rows[0]);
    }
    render_number_and_qr(state, frame, rows[1]);
}

/// The number of terminal rows `lines` will actually occupy once word-wrapped (`Wrap{trim: false}`)
/// at `width` columns — a conservative, greedy word-wrap approximation of `ratatui`'s own wrapper
/// (good enough to size a [`Constraint::Length`] region without under-allocating; see
/// [`render_body`]'s doc comment for why under-allocating here is a security-relevant defect, not
/// just a cosmetic one). A word longer than `width` still counts as (at least) one row, matching
/// `Wrap{trim: false}`'s own "never silently drop content" behavior.
fn wrapped_height(lines: &[Line<'static>], width: u16) -> u16 {
    if width == 0 {
        return lines.len() as u16;
    }
    let width = width as usize;
    let total: usize = lines
        .iter()
        .map(|line| {
            let text: String = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            wrapped_row_count(&text, width)
        })
        .sum();
    total.min(u16::MAX as usize) as u16
}

fn wrapped_row_count(text: &str, width: usize) -> usize {
    let mut rows = 0usize;
    let mut current_width = 0usize;
    let mut row_started = false;
    for word in text.split(' ') {
        let word_width = word.chars().count();
        if !row_started {
            rows += 1;
            current_width = word_width;
            row_started = true;
            continue;
        }
        let needed = current_width + 1 + word_width;
        if needed <= width {
            current_width = needed;
        } else {
            rows += 1;
            current_width = word_width;
        }
    }
    rows.max(1)
}

/// **The KeyChangeBlocked / KeyChangeWarning modals, plus this screen's own confirm/error prompts.**
/// Renders whatever [`SendGate::Blocked`]/[`SendGate::Warn`]'s carried reason string actually is —
/// verbatim, never re-derived — see the module doc. Empty (nothing rendered) when the gate is
/// [`SendGate::Ok`] and no sub-mode is active.
fn banner_lines(state: &VerifyState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match state.gate() {
        SendGate::Blocked(reason) => {
            // `TrustStore::can_send` checks `Contact::user_blocked` *before* key-change state (see
            // that method's own doc comment), so a `Blocked` gate has exactly two possible causes:
            // a purely local, user-initiated block (task 4.6 — no safety number, no interception
            // concern at all) or a genuine verified-contact key-change incident. The header must
            // match whichever one actually produced `reason`, not assume key-change unconditionally
            // — otherwise a user who locally blocked a contact for an unrelated reason (spam,
            // harassment) would see a banner falsely announcing a key-change/interception incident.
            let header = if state.user_blocked() {
                "CONTACT BLOCKED — SENDS BLOCKED"
            } else {
                "KEY CHANGE — SENDS BLOCKED"
            };
            lines.push(Line::from(Span::styled(
                header,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                reason,
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(""));
        }
        SendGate::Warn(reason) => {
            lines.push(Line::from(Span::styled(
                "KEY CHANGE WARNING",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                reason,
                Style::default().fg(Color::Yellow),
            )));
            lines.push(Line::from(""));
        }
        SendGate::Ok => {}
    }
    match &state.mode {
        VerifyMode::View => {}
        VerifyMode::Confirm(VerifyAction::Verify) => {
            lines.push(Line::from(Span::styled(
                "Did both sides see the identical safety number/QR, compared out-of-band? Only \
                 confirm if they genuinely matched. (y/n)",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        VerifyMode::Confirm(VerifyAction::Block) => {
            let verb = if state.user_blocked() {
                "unblock"
            } else {
                "block"
            };
            lines.push(Line::from(Span::styled(
                format!("{verb} this contact? (y/n)"),
                Style::default().fg(Color::Red),
            )));
        }
        VerifyMode::Confirm(VerifyAction::Acknowledge) => {
            lines.push(Line::from(Span::styled(
                "acknowledge without verifying? this re-pins the new key but does not confirm it \
                 is genuinely theirs — verify instead if anything you're about to send is \
                 sensitive. (y/n)",
                Style::default().fg(Color::Yellow),
            )));
        }
        VerifyMode::Error(message) => {
            lines.push(Line::from(Span::styled(
                message.clone(),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from("Press Enter or Esc to continue."));
        }
    }
    lines
}

/// The side-by-side safety-number + QR display this task's own name comes from — via 4.5's already-
/// reviewed primitives, `meridian_core::crypto::{safety_number, display_groups}` and
/// `meridian_core::identity::render_terminal` (see the module doc).
fn render_number_and_qr(state: &VerifyState, frame: &mut Frame<'_>, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let mut number_lines = vec![
        Line::from(format!("safety number for {}:", state.peer_label())),
        Line::from(""),
        Line::from(display_groups(&state.safety_number)),
        Line::from(""),
        Line::from(
            "compare out-of-band with them — in person, over an existing trusted channel, or on a \
             video call. Never confirm over the channel you are trying to verify."
                .to_string(),
        ),
    ];
    if let Some(notice) = &state.notice {
        number_lines.push(Line::from(""));
        number_lines.push(Line::from(Span::styled(
            notice.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(
        Paragraph::new(number_lines).wrap(Wrap { trim: false }),
        cols[0],
    );

    let qr_lines: Vec<Line<'static>> = match render_terminal(&state.safety_number) {
        Ok(qr) => qr.lines().map(|l| Line::from(l.to_string())).collect(),
        Err(e) => vec![Line::from(format!("(QR unavailable: {e})"))],
    };
    frame.render_widget(Paragraph::new(qr_lines), cols[1]);
}

fn footer_hint(state: &VerifyState) -> String {
    match &state.mode {
        VerifyMode::View => match state.gate() {
            SendGate::Blocked(_) => "v verify · b block · Esc back".to_string(),
            SendGate::Warn(_) => {
                "v verify (recommended) · a acknowledge (re-pins, does not verify) · b block · \
                 Esc back"
                    .to_string()
            }
            SendGate::Ok => "v mark verified · b block · Esc back".to_string(),
        },
        VerifyMode::Confirm(VerifyAction::Verify) => {
            "y confirm match, mark verified · n/Esc cancel".to_string()
        }
        VerifyMode::Confirm(VerifyAction::Block) => "y confirm · n/Esc cancel".to_string(),
        VerifyMode::Confirm(VerifyAction::Acknowledge) => {
            "y confirm acknowledge (does not verify) · n/Esc cancel".to_string()
        }
        VerifyMode::Error(_) => "Enter/Esc continue".to_string(),
    }
}
