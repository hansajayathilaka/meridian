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
//! ## `own_pubkey`, and how this screen became reachable from `crate::screens::contacts` (task 4.36)
//! [`VerifyState::new`] takes `own_pubkey`/`peer_pubkey`/`peer_hint`/an already-loaded `TrustStore`
//! directly — the same "constructed with what it needs, unit-tested in isolation, wired into real
//! navigation by a later task" shape `crate::screens::chat::ChatState`/
//! `crate::screens::requests::RequestsState` already established for tasks 4.20/4.21. `Screen::Main`
//! (task 4.36) is that later task: it holds `own_pubkey` and a live `TrustStore` from `LiveSession`,
//! reclaims the `TrustStore` back out on return exactly as `Screen::Chat` does, and `v` in
//! `crate::screens::contacts` now pushes this screen for real, replacing the task-4.19-authored "not
//! implemented yet" stand-in.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use meridian_core::crypto::{display_groups, safety_number};
use meridian_core::identity::render_terminal;
use meridian_core::trust::{SendGate, TrustStore};

use crate::app::{
    AcknowledgeKeyChangeEffect, AcknowledgeKeyChangeRequest, Effect, MarkVerifiedEffect,
    MarkVerifiedRequest, SetUserBlockedEffect, SetUserBlockedRequest, WorkerEvent,
};
use crate::screens::contacts::{short_pubkey, trust_glyph_and_label};
use crate::theme::{color_or_none, RenderCtx};

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
    /// How many rows the security banner has been scrolled down by — task 4.26's carry-forward fix
    /// from 4.22's review (see [`render_body`]'s own doc comment). Only meaningful (and only ever
    /// reachable via a key) when the banner's own wrapped height exceeds the physical terminal height
    /// even after the number/QR pane has already been given up entirely; `0` (the ordinary case)
    /// means "top of the banner", matching every other screen's un-scrolled default.
    pub banner_scroll: u16,
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
            banner_scroll: 0,
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

/// Task 4.26's carry-forward fix from 4.22's review: `Up`/`Down`/`PageUp`/`PageDown` scroll the
/// security banner when — at an extreme post-launch resize — it needs more rows than the physical
/// terminal offers even with the number/QR pane given up entirely (see [`render_body`]'s own doc
/// comment). Only intercepted from [`VerifyMode::View`]/[`VerifyMode::Error`] — **deliberately never**
/// from [`VerifyMode::Confirm`], so this cannot weaken the "every key other than y/Y cancels back to
/// View" property `handle_confirm_key`'s own doc names as security-relevant and
/// `tests/screens_verify.rs`'s exhaustive keyspace sweep pins byte-for-byte; a scrolled banner during a
/// `Confirm` prompt still cancels on any non-`y`/`Y` key exactly as before, it just isn't scrollable
/// mid-prompt (an accepted, minor UX gap at an already-extreme terminal size, not a security-relevant
/// one — the confirm prompt's own text is short and always at the *end* of the banner, so scrolling to
/// it before pressing `v`/`b`/`a` is sufficient).
fn banner_scroll_delta(code: KeyCode) -> Option<i32> {
    match code {
        KeyCode::Down => Some(1),
        KeyCode::Up => Some(-1),
        KeyCode::PageDown => Some(10),
        KeyCode::PageUp => Some(-10),
        _ => None,
    }
}

fn apply_banner_scroll(state: &mut VerifyState, delta: i32) {
    let next = i32::from(state.banner_scroll).saturating_add(delta).max(0);
    state.banner_scroll = u16::try_from(next).unwrap_or(u16::MAX);
}

fn handle_view_key(state: &mut VerifyState, key: KeyEvent) -> (Vec<Effect>, bool) {
    if let Some(delta) = banner_scroll_delta(key.code) {
        apply_banner_scroll(state, delta);
        return (Vec::new(), false);
    }
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
    if let Some(delta) = banner_scroll_delta(key.code) {
        apply_banner_scroll(state, delta);
        return;
    }
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

/// Pure view function — degradation-unaware default (unicode on, color on) for any call site without
/// a [`RenderCtx`] handy. See [`render_with_ctx`] and `crate::theme`'s own module doc.
pub fn render(state: &VerifyState, frame: &mut Frame<'_>) {
    render_with_ctx(state, frame, &RenderCtx::default());
}

/// Pure view function — see the module doc and `crate::theme`'s own "retrofit scope" section.
pub fn render_with_ctx(state: &VerifyState, frame: &mut Frame<'_>, ctx: &RenderCtx) {
    let area = frame.area();
    let (glyph, label) = trust_glyph_and_label(state.trust.trust_state(&state.peer_pubkey), ctx);
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

    let overflowing = render_body(state, frame, rows[0], ctx);

    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state, overflowing),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

/// Renders the banner + number/QR pane. Returns whether the banner is in the extreme "even the whole
/// physical terminal isn't tall enough for it" overflow case — see the doc below and
/// [`footer_hint`]'s `banner_overflowing` parameter, which uses this to surface the scroll keys.
fn render_body(state: &VerifyState, frame: &mut Frame<'_>, area: Rect, ctx: &RenderCtx) -> bool {
    let banner = banner_lines(state, ctx);
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
    // height `wrapped_height` says it needs, and the number/QR pane gets whatever is left —
    // shrinking toward zero, and disappearing first, if the terminal is too short for both.
    //
    // **Task 4.26's carry-forward fix (from 4.22's review).** The clamp above only protects against
    // the banner *stealing* the number/QR pane's space — it does nothing for the more extreme case
    // where the banner's own wrapped height exceeds the *entire* physical terminal, e.g. a mid-session
    // resize to a handful of rows. Before this fix, `wrapped_height(...).min(area.height)` still
    // silently truncated the `Paragraph` to whatever fit, tail of the canonical wording clipped with
    // no way to read the rest. Now: when the banner alone needs more rows than `area` has, it gets the
    // *entire* area (the number/QR pane disappears completely — cheap, re-derivable display data, not
    // security-critical) and renders scrollable via [`VerifyState::banner_scroll`]
    // (`Up`/`Down`/`PageUp`/`PageDown` — see [`banner_scroll_delta`]), so the full canonical text is
    // always reachable, never silently dropped, no matter how short the terminal gets.
    let full_banner_height = wrapped_height(&banner, area.width);
    if area.height > 0 && full_banner_height > area.height {
        let max_scroll = full_banner_height.saturating_sub(area.height);
        let scroll = state.banner_scroll.min(max_scroll);
        let paragraph = Paragraph::new(banner)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0));
        frame.render_widget(paragraph, area);
        return true;
    }

    let banner_height = full_banner_height.min(area.height);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(banner_height), Constraint::Min(0)])
        .split(area);

    if banner_height > 0 {
        frame.render_widget(Paragraph::new(banner).wrap(Wrap { trim: false }), rows[0]);
    }
    render_number_and_qr(state, frame, rows[1], ctx);
    false
}

/// The number of terminal rows `lines` will actually occupy once word-wrapped (`Wrap{trim: false}`)
/// at `width` columns — a conservative, greedy word-wrap approximation of `ratatui`'s own wrapper
/// (good enough to size a [`Constraint::Length`] region without under-allocating; see
/// [`render_body`]'s doc comment for why under-allocating here is a security-relevant defect, not
/// just a cosmetic one). A word longer than `width` — reachable from wire-observed,
/// attacker-influenced text (e.g. a space-free `Contact::hint` flowing through
/// `blocked_reason`/`warn_reason`, see `apps/core/src/trust.rs`) — is broken across
/// `ceil(word_width / width)` rows, not one, matching `ratatui`'s real `WordWrapper`
/// (`line_composer_long_word` in its own `reflow.rs` test suite: a word that doesn't fit the
/// remaining space of the current row always starts a fresh row, and one wider than a whole fresh
/// row is then split grapheme-by-grapheme into `width`-cell-wide chunks). `word_width` itself is a
/// terminal display-cell width (see [`word_display_width`]), not a `char` count — double-width
/// characters (CJK, fullwidth forms, many emoji) occupy 2 cells per 1 `char`, and a `char`-count
/// measurement was a second, independent undercount this function once had alongside the row-count
/// one. Undercounting either one — the bugs this function once had — silently clips the tail of the
/// un-softenable Blocked/Warn banner text off-screen or under-allocates its render region entirely;
/// see [`wrapped_row_count`].
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
    // Guard against division by zero below — `wrapped_height` already special-cases `width == 0`
    // before ever calling this function, but this keeps the helper itself panic-free for any direct
    // caller (e.g. a unit test) too.
    let width = width.max(1);
    let mut rows = 0usize;
    let mut current_width = 0usize;
    let mut row_started = false;
    for word in text.split(' ') {
        let word_width = word_display_width(word);
        // (a) The word fits on the current row (with a separating space, unless the row is empty) —
        // append it in place, no new row.
        if row_started {
            let needed = current_width + 1 + word_width;
            if needed <= width {
                current_width = needed;
                continue;
            }
        }
        // The word does not fit on the current row (or there is no current row yet): it always
        // starts a fresh row, mirroring ratatui's real `WordWrapper` (see this function's caller,
        // `wrapped_height`, for the citation).
        if word_width <= width {
            // (b) It fits within a whole fresh row on its own.
            rows += 1;
            current_width = word_width;
        } else {
            // (c) It exceeds `width` even alone — ratatui splits it grapheme-by-grapheme (see
            // `word_display_width`) into `width`-cell-wide chunks, `ceil(word_width / width)` rows
            // in total (not one — the bug this function once had). The position on the last of
            // those rows is the remainder, so a
            // following word that fits after it is still accounted for correctly (`width` itself,
            // not `0`, when the word divides evenly — otherwise a phantom empty trailing row would
            // look like it has room for nothing, which is conservative but not accurate).
            rows += word_width.div_ceil(width);
            let remainder = word_width % width;
            current_width = if remainder == 0 { width } else { remainder };
        }
        row_started = true;
    }
    rows.max(1)
}

/// The terminal display-cell width of `word`, matching `ratatui`'s real `WordWrapper` (which
/// measures via `StyledGrapheme::symbol.cell_width()`) rather than a Unicode scalar (`char`) count.
/// A naive `word.chars().count()` undercounts any double-width character (CJK ideographs, fullwidth
/// forms, many emoji) by up to 2x — reachable from wire-observed, attacker-influenced text (e.g. a
/// space-free `Contact::hint`, unrestricted in charset, flowing through `blocked_reason`/
/// `warn_reason`; see `apps/core/src/trust.rs`), so this must be exact, not approximate.
///
/// Iterates by extended grapheme cluster (`unicode-segmentation`), not by `char`, so combining
/// characters and ZWJ sequences (e.g. a family emoji built from several joined codepoints) are
/// measured as the single visual unit `ratatui`'s own per-grapheme rendering treats them as, rather
/// than summing each constituent codepoint's width independently. Each grapheme's width comes from
/// `unicode-width`'s `UnicodeWidthStr::width` — the same crate `ratatui-core` itself depends on for
/// `cell_width()` — so this stays consistent with `ratatui`'s actual layout decisions, not a
/// second, potentially-diverging measurement.
fn word_display_width(word: &str) -> usize {
    word.graphemes(true).map(UnicodeWidthStr::width).sum()
}

/// **The KeyChangeBlocked / KeyChangeWarning modals, plus this screen's own confirm/error prompts.**
/// Renders whatever [`SendGate::Blocked`]/[`SendGate::Warn`]'s carried reason string actually is —
/// verbatim, never re-derived — see the module doc. Empty (nothing rendered) when the gate is
/// [`SendGate::Ok`] and no sub-mode is active.
fn banner_lines(state: &VerifyState, ctx: &RenderCtx) -> Vec<Line<'static>> {
    let red = |base: Style| match color_or_none(Color::Red, ctx) {
        Some(color) => base.fg(color),
        None => base,
    };
    let yellow = |base: Style| match color_or_none(Color::Yellow, ctx) {
        Some(color) => base.fg(color),
        None => base,
    };
    let cyan = |base: Style| match color_or_none(Color::Cyan, ctx) {
        Some(color) => base.fg(color),
        None => base,
    };

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
                red(Style::default().add_modifier(Modifier::BOLD)),
            )));
            lines.push(Line::from(Span::styled(reason, red(Style::default()))));
            lines.push(Line::from(""));
        }
        SendGate::Warn(reason) => {
            lines.push(Line::from(Span::styled(
                "KEY CHANGE WARNING",
                yellow(Style::default().add_modifier(Modifier::BOLD)),
            )));
            lines.push(Line::from(Span::styled(reason, yellow(Style::default()))));
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
                cyan(Style::default().add_modifier(Modifier::BOLD)),
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
                red(Style::default()),
            )));
        }
        VerifyMode::Confirm(VerifyAction::Acknowledge) => {
            lines.push(Line::from(Span::styled(
                "acknowledge without verifying? this re-pins the new key but does not confirm it \
                 is genuinely theirs — verify instead if anything you're about to send is \
                 sensitive. (y/n)",
                yellow(Style::default()),
            )));
        }
        VerifyMode::Error(message) => {
            lines.push(Line::from(Span::styled(
                message.clone(),
                red(Style::default()),
            )));
            lines.push(Line::from("Press Enter or Esc to continue."));
        }
    }
    lines
}

/// The side-by-side safety-number + QR display this task's own name comes from — via 4.5's already-
/// reviewed primitives, `meridian_core::crypto::{safety_number, display_groups}` and
/// `meridian_core::identity::render_terminal` (see the module doc).
fn render_number_and_qr(state: &VerifyState, frame: &mut Frame<'_>, area: Rect, ctx: &RenderCtx) {
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
        let mut style = Style::default();
        if let Some(color) = color_or_none(Color::Red, ctx) {
            style = style.fg(color);
        }
        number_lines.push(Line::from(Span::styled(notice.clone(), style)));
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

/// `banner_overflowing` is [`render_body`]'s own return value: `true` only in the extreme case where
/// the banner needed the whole physical terminal and is now scrollable — see [`banner_scroll_delta`].
fn footer_hint(state: &VerifyState, banner_overflowing: bool) -> String {
    let base = match &state.mode {
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
    };
    if banner_overflowing && !matches!(state.mode, VerifyMode::Confirm(_)) {
        format!("{base} · Up/Down/PgUp/PgDn scroll banner (too short to show it all)")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // wrapped_row_count — pure, no I/O. Security-review regression: this helper once treated any
    // single word longer than `width` as occupying exactly one row, undercounting the space
    // `render_body` reserves for the un-softenable Blocked/Warn banner text — see this function's
    // own doc comment and `render_body`'s for why undercounting here is a security-relevant defect,
    // not merely cosmetic. `text`/`hint` reaching this function is wire-observed and
    // attacker-influenced (`Contact::hint`, bounded to 253 bytes but never required to contain a
    // space — see `apps/core/src/trust.rs`), so these tests exercise exactly that shape: a long,
    // space-free token, not just the short fixed labels the screen-level tests use.
    // -----------------------------------------------------------------------

    #[test]
    fn short_text_that_fits_on_one_row_counts_as_one_row() {
        assert_eq!(wrapped_row_count("hello world", 40), 1);
    }

    #[test]
    fn empty_text_counts_as_one_row_never_zero() {
        assert_eq!(wrapped_row_count("", 40), 1);
    }

    #[test]
    fn ordinary_word_wrap_matches_a_simple_greedy_count() {
        // "aaaa bbbb cccc dddd" at width 9: "aaaa bbbb" (9 chars) fits row 1, "cccc dddd" (9 chars)
        // fits row 2 — two rows, no word individually exceeds the width.
        assert_eq!(wrapped_row_count("aaaa bbbb cccc dddd", 9), 2);
    }

    #[test]
    fn a_single_space_free_word_longer_than_width_spans_ceil_len_over_width_rows() {
        // The core fix this test pins: a lone 100-char space-free token (a hostile `Contact::hint`
        // with no spaces at all) at width 10 must occupy `ceil(100 / 10) = 10` rows, not 1.
        let hostile = "a".repeat(100);
        assert_eq!(wrapped_row_count(&hostile, 10), 10);
        // Not-evenly-divisible case: ceil(101 / 10) = 11.
        let hostile = "a".repeat(101);
        assert_eq!(wrapped_row_count(&hostile, 10), 11);
    }

    #[test]
    fn a_long_word_embedded_in_ordinary_surrounding_text_still_spans_every_row_it_needs() {
        // Mirrors the real shape of `blocked_reason`/`warn_reason`: ordinary words, then one hostile
        // long space-free token (the interpolated `label`), then more ordinary words. Every row the
        // long word itself needs must be counted, and the words after it must still be reachable
        // (not silently absorbed into an undercounted row).
        let hostile = "b".repeat(37); // ceil(37 / 10) = 4 rows on its own at width 10.
        let text = format!("The safety number for {hostile} has changed.");
        // "The safety" (10 chars incl. space... exact wrapping isn't the point here) plus the 4 rows
        // the long word needs plus at least one more row for the trailing words — comfortably more
        // than the old, buggy "1 row per over-long word" behavior would ever produce.
        let rows = wrapped_row_count(&text, 10);
        assert!(
            rows > 4,
            "expected at least 1 (leading words) + 4 (the long word's own rows), got {rows}"
        );
    }

    #[test]
    fn wrapped_height_of_a_hostile_long_hint_reason_is_never_undercounted_relative_to_a_direct_row_count(
    ) {
        // `wrapped_height` (this function's only caller) must sum exactly what `wrapped_row_count`
        // reports per line — this pins that composition against a realistic canonical-reason-shaped
        // string carrying a long, space-free hint.
        let hostile_label = "x".repeat(80);
        let reason = format!(
            "The safety number for {hostile_label} has changed. This can happen if they \
             reinstalled or switched devices — but it can also mean someone is intercepting your \
             messages. Sends to {hostile_label} are blocked until you verify the new safety \
             number with them through a channel you trust. Verify the new safety number to \
             resume, or leave this contact blocked — there is no way to send without doing one of \
             those."
        );
        let lines = vec![Line::from(reason.clone())];
        let width = 40u16;
        let height = wrapped_height(&lines, width);
        let direct = wrapped_row_count(&reason, width as usize);
        assert_eq!(height as usize, direct);
        // Sanity: the hostile label alone forces several rows at this width — if this were 1 (the
        // old bug), the rest of this test file's screen-level regressions wouldn't be exercising
        // anything real.
        assert!(height as usize >= 80usize.div_ceil(width as usize));
    }

    // -----------------------------------------------------------------------
    // word_display_width / wrapped_row_count with double-width characters — residual security-review
    // regression: `word_width` was once measured as `word.chars().count()` (a Unicode scalar count),
    // undercounting any double-width character (CJK ideographs, fullwidth forms, many emoji) by up to
    // 2x even after the row-count math itself (`ceil(word_width / width)`) was already correct. See
    // this module's doc comment on `word_display_width` and `apps/tui/tests/degradation.rs`'s
    // `verify_screen_ordinary_terminal_with_a_wide_hostile_hint_never_garbles_or_silently_drops_the_banner`
    // for the screen-level regression this closes.
    // -----------------------------------------------------------------------

    #[test]
    fn word_display_width_counts_ascii_as_one_cell_per_char() {
        assert_eq!(word_display_width("hello"), 5);
    }

    #[test]
    fn word_display_width_counts_double_width_cjk_as_two_cells_per_char() {
        // "中" (U+4E2D) is a single Unicode scalar value but renders as 2 terminal cells — the exact
        // gap a `chars().count()` measurement missed.
        let word = "\u{4e2d}".repeat(10);
        assert_eq!(word_display_width(&word), 20);
        assert_ne!(
            word_display_width(&word),
            word.chars().count(),
            "sanity: this case must actually diverge from a naive char count, or it isn't exercising \
             the bug"
        );
    }

    #[test]
    fn word_display_width_treats_a_zwj_emoji_sequence_as_one_grapheme_not_summed_per_codepoint() {
        // A ZWJ family emoji: several joined codepoints that render as a single glyph. Grapheme-cluster
        // iteration must measure it once (as `unicode-width` reports for the whole cluster's own
        // rendering), not once per constituent `char`.
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}"; // man-ZWJ-woman-ZWJ-girl
        let per_grapheme = word_display_width(family);
        let naive_char_sum: usize = family
            .chars()
            .map(|c| unicode_width::UnicodeWidthChar::width(c).unwrap_or(0))
            .sum();
        assert!(
            per_grapheme <= naive_char_sum,
            "grapheme-cluster measurement must never exceed summing every constituent char's own \
             width (got {per_grapheme} vs a naive per-char sum of {naive_char_sum})"
        );
    }

    #[test]
    fn a_single_space_free_double_width_word_spans_ceil_cell_width_over_render_width_rows() {
        // 84 repeats of a double-width CJK character = 168 display cells (matching the reviewer's own
        // 84-character reproduction) at width 40 must occupy `ceil(168 / 40) = 5` rows, not
        // `ceil(84 / 40) = 3` (the char-count-based undercount) and not 1 (the still-older row-count
        // bug).
        let hostile = "\u{4e2d}".repeat(84);
        assert_eq!(wrapped_row_count(&hostile, 40), 5);
    }
}
