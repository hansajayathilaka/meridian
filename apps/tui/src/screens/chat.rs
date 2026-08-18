//! The main conversation screen (task 4.20): scrollback, multi-line composer, per-message delivery
//! state, unread markers, restart-persistent history via task 4.15's sealed store, local dedup by
//! `mid` — gated by T08's send rules so a blocked contact cannot be messaged from here either. Like
//! every other screen in this crate, [`handle_key`]/[`handle_worker`] only ever mutate a
//! [`ChatState`] and return the [`Effect`]s a (future) worker should execute; [`render`] is a pure
//! view function.
//!
//! ## Why this screen owns a real `TrustStore`, not a duplicated trust snapshot
//! `crate::screens::contacts`' own module doc explains why *that* screen resolved its
//! `ContactEntry`/`TrustStore` tension by duplicating just the display-relevant fields (`trust`,
//! `user_blocked`, …) — its list rows need to join two independently-loaded stores
//! (`contacts.json` and `TrustStore`) into one row shape. This screen has no such join to do: its
//! **one and only** consumer of trust data is the send gate, and the task's own binding requirement
//! is that the composer "consults `meridian_core::trust::TrustStore::can_send(peer_ik)` before every
//! send" — literally, not a re-derived approximation of its logic. [`ChatState`] therefore holds an
//! actual, already-loaded [`TrustStore`] (mirrors [`crate::screens::contacts::ContactsState`]'s own
//! "entries is already-loaded, non-secret display data" contract — a future `Preflight`/navigation
//! step is what loads it, exactly as that screen's own entries are "already loaded... out of this
//! task's scope") and calls [`TrustStore::can_send`] on it directly. This means:
//! - The exact `Blocked`/`Warn` canonical wording ([`verification-ux.md`](../../../docs/security/verification-ux.md))
//!   is never re-typed or paraphrased here — it comes straight from `trust.rs`'s own (already
//!   reviewed) `blocked_reason`/`warn_reason`/`user_blocked_reason` functions, reached only through
//!   `SendGate`'s payload.
//! - There is no second, screen-local copy of the `Blocked`/`Warn`/`Ok` decision logic to drift out
//!   of sync with `trust.rs`'s own — the one and only decision point is [`TrustStore::can_send`].
//!
//! ## The send-gate wiring, precisely (the property this task's reviewer cares about most)
//! Every path that could turn composer text into a dispatched [`Effect::SendMessage`] —a fresh
//! `Enter`, and a retry (`r`) of a previously failed send — funnels through
//! [`dispatch_gated_send`], which is the **only** place in this file that ever constructs
//! `Effect::SendMessage`. It mirrors `apps/cli/src/chat.rs::send_gated`'s three-way match exactly:
//! - [`SendGate::Ok`]: dispatches the effect, clears the composer.
//! - [`SendGate::Blocked`]: dispatches **nothing** and leaves the composer text untouched (the
//!   message is refused, not silently dropped from view) — see [`handle_composer_key`]'s own guard,
//!   which additionally refuses ordinary **typing** while blocked (tui-client.md §6 rule 1: "the
//!   composer is disabled"), checked fresh from `state.trust` on every keystroke so it can never go
//!   stale, and [`render_composer`]'s live hard-stop banner, computed the same way on every render
//!   rather than cached from whatever the gate was the last time `Enter` was pressed.
//! - [`SendGate::Warn`]: holds the composer text in [`ComposerMode::AwaitingAck`] instead of sending
//!   it, mirroring `send_gated`'s `held`/`awaiting_ack` — see [`handle_awaiting_ack_key`]. Answering
//!   `y`/`yes` calls [`TrustStore::acknowledge_key_change`] and then calls
//!   [`dispatch_gated_send`] **again** on the held text (never a direct, ungated
//!   `Effect::SendMessage`) — the same "never blindly trust the acknowledgment, re-check the real
//!   gate" defense-in-depth `apps/cli/src/chat.rs::answer_key_change_warning`'s own doc comment
//!   calls out.
//!
//! No other function in this module ever constructs `Effect::SendMessage` — grep for it if that
//! changes.
//!
//! ## Failure copy (tui-client.md §7)
//! [`offline_failure_copy`] is the *only* place this screen renders the pre-T07 "peer offline"
//! wording, and [`send_error_copy`] the only place it renders a harder transport/crypto error. Both
//! are plain functions (no I/O, trivially unit-testable) specifically so a dedicated test can scan
//! their output for the banned "will deliver later"/"delivered when they come online" framing this
//! task names explicitly — see `tests/screens_chat.rs`. Neither implies store-and-forward: there is
//! no server-side mailbox until T07, and `config.toml`'s own doc (task 4.14) is explicit that
//! `pending` only ever means "this client will retry while it is running".
//!
//! **The label interpolated into `offline_failure_copy` is [`ChatState::failure_copy_label`], not
//! [`ChatState::peer_label`]** (security-review fix, Finding 2) — see that method's own doc comment
//! for why: `peer_label`'s hint fallback is wire-populated and attacker-influenced, and would
//! otherwise let a hostile peer smuggle store-and-forward-implying text straight through the one
//! copy this task's own tests are meant to police.
//!
//! ## Message rendering: through the registry, for real, but built locally
//! [`ChatMessageRenderer`] implements `crate::surface::MessageRenderer` for `mrd.chat/1` and IS the
//! renderer 4.18's own module doc anticipated this task registering — [`transcript_registry`]
//! registers it and [`transcript_lines`] renders every entry through the resulting
//! `MessageRendererRegistry`, never by reading `HistoryEntry::body` directly. This is not a
//! decoration: it is what gives a *future* stream type sharing this same transcript (e.g. a
//! `mrd.file/1` attachment embedded in an otherwise-`mrd.chat/1` conversation, per T09) the
//! registry's forward-compatibility placeholder (`[unsupported: mrd.foo/1 — update your client]`)
//! instead of a panic or a silently dropped row — exactly the case `crate::surface`'s own module doc
//! calls out as what the registry mechanism is really for.
//!
//! **Built fresh on every render call, not stored in [`ChatState`].** `MessageRendererRegistry`
//! derives neither `Debug` nor `Clone` today, and no `App`-level shared registry instance exists yet
//! to hold a persistent one in (`crate::surface`'s registry is not wired into `App` at all until a
//! future integration task). Rather than adding derives to `surface.rs` or inventing App-level
//! plumbing that is out of this task's scope, [`transcript_registry`] builds a registry containing
//! only this one renderer on every call — cheap (a couple of `BTreeMap` inserts) and pure, entirely
//! consistent with `render` already running up to 60fps per tui-client.md §4. A future task that
//! gives `App` a real, persistently-registered `SurfaceRegistry` can swap this for a borrowed
//! reference with no change to [`ChatMessageRenderer`] itself or its `mrd.chat/1` contract.
//!
//! ## What this screen does *not* do
//! `entries` starts pre-loaded (mirrors `ContactsState::new`'s "already loaded... out of this
//! task's scope" contract) from task 4.15's history store.
//!
//! ## Navigation wiring (task 4.36)
//! `crate::screens::contacts`'s `Enter` key opens this screen directly; `ContactDetail` got its own
//! dedicated key (`i`) instead — see [`crate::app::Screen::Chat`]'s doc comment and
//! `crate::screens::contacts`'s own module doc for the resolved key layout.
//!
//! ## Receive-path wiring (task 4.35)
//! [`handle_inbound_message`] is `crate::app::App::handle_inbound`'s one call into this module for a
//! live [`crate::app::InboundEvent::Message`]: it reuses [`insert_deduped`] **unchanged** — exactly
//! as this module's own doc used to anticipate before this task existed — so an inbound message and
//! a racing outbound completion (`complete_send`) can never both land the same `mid` twice, no
//! matter which one this screen sees first. [`apply_receipt`] is the same task's much smaller
//! counterpart for a live [`crate::app::InboundEvent::Receipt`]: an in-memory-only `Sent` →
//! `Delivered` transition (there is no disk-persistence effect for updating an already-written
//! `HistoryEntry` in place — [`retry_last_failed`]'s own doc comment already made this exact
//! "no history-mutation effect in this task's scope" judgment call for the outbound retry case; this
//! is the same call, just for an inbound receipt).
//!
//! **The worker's own persistent receive loop (`crate::worker::run_inbound_loop`) auto-acknowledges
//! every inbound `ChatContent::Text` with a `ChatContent::Receipt` before this screen ever sees the
//! message** — never gated by [`SendGate`], since a receipt only acknowledges content already
//! decrypted and seen (see that function's own doc comment for the full reasoning, mirroring
//! `apps/cli/src/chat.rs::deliver_content`'s identical auto-ack). This screen's own send-gate wiring
//! above is completely unaffected: [`dispatch_gated_send`] remains the *only* function in this
//! module that ever constructs `Effect::SendMessage`, and the auto-ack path never runs through it or
//! through this module at all — it is entirely the worker's, never this screen's.

use std::collections::BTreeMap;
use std::sync::Arc;

use ratatui::layout::{Constraint, Direction as LayoutDirection, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::trust::{SendGate, TrustStore};

use crate::app::{
    Effect, PersistHistoryEffect, PersistHistoryRequest, SendMessageEffect, SendMessageRequest,
    SentMessage, WorkerEvent,
};
use crate::screens::contacts::{short_pubkey, trust_glyph_and_label};
use crate::store::history::{
    Direction as MsgDirection, HistoryEntry, MessageState, CURRENT_VERSION,
};
use crate::surface::{MessageRenderer, MessageRendererRegistry};
use crate::theme::{color_or_none, glyph, GlyphKind, RenderCtx};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The whole conversation screen's state.
///
/// **`#[derive(Debug)]`, no redaction needed.** Unlike `crate::app::StoreChoice::File`'s passphrase
/// or `UnlockRequest`'s, nothing reachable from here is a *secret* in this crate's hand-rolled-`Debug`
/// sense — `composer`/`entries[].body` are sensitive conversation content, but they are not
/// passphrases or key material, and `TrustStore` itself already derives `Debug` on the same
/// reasoning ("every field reachable from here is already-public contact metadata... never key
/// material" — see its own doc comment). Verified rather than assumed, per this task's own
/// instruction to check that reasoning rather than copy it blindly.
#[derive(Debug)]
pub struct ChatState {
    pub peer_pubkey: [u8; 32],
    /// Fallback label source if `trust.contact(peer_pubkey)` has no record at all (defensive; should
    /// not happen in practice since a chat can only be opened for an already-known contact, but this
    /// screen does not assume that invariant is upheld elsewhere).
    pub peer_hint: String,
    /// Already loaded — see the module doc's "Why this screen owns a real `TrustStore`" section.
    pub trust: TrustStore,
    /// Already loaded — task 4.15's sealed history store, read once by a future Preflight/navigation
    /// step exactly like [`crate::screens::contacts::ContactsState::entries`].
    pub entries: Vec<HistoryEntry>,
    /// How many of the trailing `entries` are unread — drives the "── unread ──" divider and the `u`
    /// jump-to-first-unread key. Clearing this count (e.g. once the conversation has actually been
    /// viewed) is a reconciliation this task does not wire — see the module doc's "What this screen
    /// does not do".
    pub unread_count: u64,
    pub composer: String,
    /// The last successfully-sent body, for the `↑` recall key (tui-client.md §3).
    pub last_sent: Option<String>,
    pub focus: ChatFocus,
    /// Lines scrolled up from the bottom of the transcript; `0` means pinned to the newest message.
    pub scroll_from_bottom: usize,
    pub mode: ComposerMode,
    /// `Some(body)` while an [`Effect::SendMessage`] for `body` is in flight — blocks a second
    /// concurrent send (not typing a follow-up message) until it resolves.
    pub sending: Option<String>,
    /// A transient, non-persisted status line (worker-reported errors, an acknowledgment being
    /// discarded, …). Cleared by most further activity; see call sites.
    pub notice: Option<String>,
    /// `mid` → the exact failure copy shown beneath that entry's row — see [`offline_failure_copy`]/
    /// [`send_error_copy`]. Keyed separately from [`HistoryEntry`] (task 4.15's frozen schema has no
    /// field for this) so a `Failed` entry loaded from disk in a *previous* session still renders
    /// (with a generic fallback — see [`transcript_lines`]) even though this map starts empty.
    pub failure_reasons: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatFocus {
    Composer,
    Transcript,
}

/// The composer's own sub-mode — mirrors `crate::screens::contact_detail::DetailMode`'s "nested
/// mode with its own `Esc`" shape, just for the one nested state this screen has.
#[derive(Debug, Clone)]
pub enum ComposerMode {
    Normal,
    /// A [`SendGate::Warn`] is being held pending a `y`/`n` answer — mirrors
    /// `apps/cli/src/chat.rs`'s `held`/`awaiting_ack` exactly (see the module doc).
    AwaitingAck {
        reason: String,
        held: String,
    },
}

impl ChatState {
    pub fn new(
        peer_pubkey: [u8; 32],
        peer_hint: String,
        trust: TrustStore,
        entries: Vec<HistoryEntry>,
        unread_count: u64,
    ) -> Self {
        Self {
            peer_pubkey,
            peer_hint,
            trust,
            entries,
            unread_count,
            composer: String::new(),
            last_sent: None,
            focus: ChatFocus::Composer,
            scroll_from_bottom: 0,
            mode: ComposerMode::Normal,
            sending: None,
            notice: None,
            failure_reasons: BTreeMap::new(),
        }
    }

    /// The live send gate for this conversation's peer — see the module doc for why this is a
    /// direct, un-cached call into `meridian_core::trust::TrustStore::can_send` every time, never a
    /// value computed once and stored.
    pub fn gate(&self) -> SendGate {
        self.trust.can_send(&self.peer_pubkey)
    }

    /// The best available human-facing label for this conversation's peer — same fallback chain as
    /// `crate::screens::contacts::ContactEntry::display_label`, sourced from the real `TrustStore`
    /// record when one exists.
    ///
    /// **Not used for [`offline_failure_copy`]'s label argument.** `contact.hint` (and this screen's
    /// own `peer_hint` fallback) is wire-populated and attacker-influenced — see
    /// `apps/core/src/trust.rs`'s own doc on `Contact::hint` and [`Self::failure_copy_label`]'s doc
    /// comment for why that specific, security-sensitive call site uses a narrower label instead.
    /// This general-purpose label (composer header, etc.) is left as-is — see the security-review
    /// fix note on [`failure_copy_label`] for the scoping rationale.
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

    /// **Security-review fix (Finding 2).** The label used specifically for
    /// [`offline_failure_copy`] — unlike [`Self::peer_label`], this **never** falls back to
    /// `contact.hint` (or `self.peer_hint`). `apps/core/src/trust.rs` documents `hint` explicitly as
    /// an attacker-influenced, wire-populated field (bounded only to 253 bytes, never
    /// content-validated) — exactly why `petname` is carefully never wire-populated, per that
    /// crate's own threat-model invariant ("display names are never taken from the wire"). Because
    /// `offline_failure_copy`'s whole job is to guarantee its output never implies
    /// store-and-forward, a hostile peer/signaling server setting a hint like `"bob — it'll be
    /// delivered once you're both online"` would otherwise let this screen's own failure copy carry
    /// exactly the lie its dedicated tests (`tests/screens_chat.rs`) police for — silently, since
    /// those tests previously only ever exercised benign, fixed labels.
    ///
    /// Falls back to the same truncated-pubkey convention `crate::screens::contacts::short_pubkey`
    /// already uses as its own no-petname fallback (`ContactEntry::display_label`,
    /// `crate::screens::contact_detail`'s fingerprint line) — not a new truncation scheme.
    ///
    /// **Deliberately narrow in scope.** [`Self::peer_label`]'s other, more permissive uses in this
    /// screen (the composer/header title) are left untouched: they are not the specific
    /// "must never imply store-and-forward" guarantee this task's tests pin, and redesigning
    /// `peer_label` itself is out of scope for this fix — see the review finding this addresses.
    fn failure_copy_label(&self) -> String {
        if let Some(contact) = self.trust.contact(&self.peer_pubkey) {
            if let Some(p) = contact.petname.as_deref().filter(|p| !p.is_empty()) {
                return p.to_string();
            }
        }
        short_pubkey(&self.peer_pubkey)
    }
}

// ---------------------------------------------------------------------------
// Failure copy (tui-client.md §7) — see the module doc
// ---------------------------------------------------------------------------

/// Canonical failure copy for the pre-T07 "peer offline" case
/// ([tui-client.md §7](../../../docs/architecture/tui-client.md#7-what-the-user-sees-when-things-go-wrong)):
/// "not delivered — offline" plus a retry action, and — the load-bearing negative property this
/// task's own dedicated test pins — **never** anything implying store-and-forward ("will deliver
/// later", "delivered when they come online", …), because no such mailbox exists yet.
pub fn offline_failure_copy(peer_label: &str) -> String {
    format!("not delivered — {peer_label} is offline — press r to retry")
}

/// Copy for a harder transport/crypto failure (the send effect itself failed, not merely "peer
/// currently unreachable") — a different, less specific failure class than
/// [`offline_failure_copy`], so it says so rather than reusing the offline wording for a case that
/// isn't actually that.
pub fn send_error_copy(error: &str) -> String {
    format!("message not sent: {error}")
}

// ---------------------------------------------------------------------------
// mrd.chat/1 message renderer (task 4.18's registry) — see the module doc
// ---------------------------------------------------------------------------

/// Renders one `mrd.chat/1` transcript entry as a single row: direction word, body, and a delivery
/// marker (`✓`/`✓✓`/`✗`/…) — the mockup's `14:02 bob hey, are you around?` / `14:02 you just got
/// here ✓✓` rows, minus the clock rendering (`TODO: confirm` — no date/time-formatting crate is a
/// workspace dependency yet; `config.toml`'s `[ui] timestamps` mode has nothing to format against
/// today, so this task renders every row without one rather than hand-rolling epoch math).
///
/// Deliberately uses the generic "you"/"them" rather than the peer's real petname: `render` takes
/// only `&HistoryEntry` (`crate::surface::MessageRenderer`'s fixed signature — see that module's own
/// "known coupling, accepted deliberately" note), so no contact-label context reaches this impl.
/// This is a 1:1 conversation screen, so the header (see [`render`] below) already names the peer
/// once; per-line real names are not required for a two-party transcript the way they would be for
/// a group chat.
///
/// **Carries a [`RenderCtx`] snapshot (task 4.26), not a signature change to
/// [`crate::surface::MessageRenderer::render`].** That trait's signature is a stable, third-party-
/// shaped extension contract (`crate::surface`'s own module doc: "review changes here as if third
/// parties will implement against them") — widening it just for this one screen's degradation inputs
/// would ripple into every current and future `MessageRenderer` impl. Instead this struct is built
/// fresh with the resolved `ctx` on every render call (exactly like [`transcript_registry`] already
/// does for the registry itself — see that function's own doc), so `render`'s fixed
/// `&self`/`&HistoryEntry` signature never needs to change.
pub struct ChatMessageRenderer {
    ctx: RenderCtx,
}

impl MessageRenderer for ChatMessageRenderer {
    fn stream_type(&self) -> &'static str {
        "mrd.chat/1"
    }

    fn render(&self, entry: &HistoryEntry) -> Vec<Line<'static>> {
        let who = match entry.dir {
            MsgDirection::Out => "you",
            MsgDirection::In => "them",
        };
        let marker = state_marker(entry.state, &self.ctx);
        let mut style = Style::default();
        let color = if entry.state == MessageState::Failed {
            Some(Color::Red)
        } else {
            match entry.dir {
                MsgDirection::Out => None,
                MsgDirection::In => Some(Color::Cyan),
            }
        };
        if let Some(color) = color.and_then(|c| color_or_none(c, &self.ctx)) {
            style = style.fg(color);
        }
        vec![Line::from(Span::styled(
            format!("{who:>4}  {}{marker}", entry.body),
            style,
        ))]
    }
}

/// Delivery-state marker — glyph-only for the terminal states (never color alone: `Failed`'s `✗`/`x`
/// is a distinct glyph from `Sent`/`Delivered`'s `✓`/`v`/`vv`, not merely a different color on the same
/// mark), plus the two plain-English in-flight labels that were already ASCII. See `crate::theme`'s
/// own doc for the unicode/ASCII fallback [`GlyphKind`] provides.
fn state_marker(state: MessageState, ctx: &RenderCtx) -> std::borrow::Cow<'static, str> {
    match state {
        MessageState::Composing => " …".into(),
        MessageState::Pending => " (pending)".into(),
        MessageState::Sent => format!(" {}", glyph(GlyphKind::DeliverySent, ctx)).into(),
        MessageState::Delivered => format!(" {}", glyph(GlyphKind::DeliveryDelivered, ctx)).into(),
        MessageState::Failed => format!(" {}", glyph(GlyphKind::DeliveryFailed, ctx)).into(),
        MessageState::Received => "".into(),
    }
}

/// Builds a registry containing only [`ChatMessageRenderer`] — see the module doc for why this is
/// constructed fresh on every render call rather than stored in [`ChatState`].
fn transcript_registry(ctx: &RenderCtx) -> MessageRendererRegistry {
    let mut registry = MessageRendererRegistry::new();
    registry.register(Arc::new(ChatMessageRenderer { ctx: *ctx }));
    registry
}

// ---------------------------------------------------------------------------
// Local dedup by mid
// ---------------------------------------------------------------------------

/// Inserts `entry` into `entries` unless a `HistoryEntry` with the same `mid` is already present —
/// this task's own named "local dedup by `mid`" deliverable. Deliberately keyed only on `mid`, not
/// direction, so a future inbound-receive path can reuse this unchanged (see the module doc's "What
/// this screen does not do"). Returns whether the entry was actually inserted.
fn insert_deduped(entries: &mut Vec<HistoryEntry>, entry: HistoryEntry) -> bool {
    if entries.iter().any(|e| e.mid == entry.mid) {
        return false;
    }
    entries.push(entry);
    true
}

// ---------------------------------------------------------------------------
// Sending — the one path to Effect::SendMessage (see the module doc)
// ---------------------------------------------------------------------------

/// The **only** function in this module that ever constructs [`Effect::SendMessage`] — see the
/// module doc's "The send-gate wiring, precisely" section. Called both by a fresh `Enter` submit and
/// by a retry (`r`), so both paths get the identical, freshly-recomputed gate check.
fn dispatch_gated_send(state: &mut ChatState, body: String) -> Vec<Effect> {
    match state.gate() {
        SendGate::Ok => {
            state.composer.clear();
            state.notice = None;
            state.mode = ComposerMode::Normal;
            state.last_sent = Some(body.clone());
            state.sending = Some(body.clone());
            vec![Effect::SendMessage(SendMessageEffect {
                request: SendMessageRequest {
                    peer_pubkey: state.peer_pubkey,
                    peer_hint: state.peer_hint.clone(),
                    body,
                },
                outcome: None,
            })]
        }
        // Refuses ALL of `body` — there is nothing partial to refuse here (unlike
        // `apps/cli/src/chat.rs::send_gated`'s `Vec<String>` of separately-typed lines, this
        // composer always submits exactly one body per `Enter`), but the property is the same:
        // nothing is dispatched, nothing is queued for a later bypass. `render_composer`'s live
        // banner (recomputed every render, not this call's snapshot) is the persistent indication;
        // this leaves the composer text exactly as the user typed it so nothing is lost.
        SendGate::Blocked(_) => Vec::new(),
        SendGate::Warn(reason) => {
            state.composer.clear();
            state.mode = ComposerMode::AwaitingAck { reason, held: body };
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the effects (if any) and whether `App` should pop this screen —
/// `true` only for a plain `Esc` while [`ComposerMode::Normal`] (this screen is always pushed on top
/// of something else — see [`crate::app::Screen::Chat`]'s doc). `Esc` while
/// [`ComposerMode::AwaitingAck`] instead cancels the acknowledgment prompt without leaving the
/// screen, mirroring `crate::screens::contact_detail`'s nested-mode `Esc` convention.
pub fn handle_key(state: &mut ChatState, key: KeyEvent) -> (Vec<Effect>, bool) {
    if matches!(state.mode, ComposerMode::AwaitingAck { .. }) {
        return handle_awaiting_ack_key(state, key);
    }

    match key.code {
        KeyCode::Esc => return (Vec::new(), true),
        KeyCode::Tab => {
            state.focus = match state.focus {
                ChatFocus::Composer => ChatFocus::Transcript,
                ChatFocus::Transcript => ChatFocus::Composer,
            };
            return (Vec::new(), false);
        }
        _ => {}
    }

    let effects = match state.focus {
        ChatFocus::Composer => handle_composer_key(state, key),
        ChatFocus::Transcript => handle_transcript_key(state, key),
    };
    (effects, false)
}

fn handle_composer_key(state: &mut ChatState, key: KeyEvent) -> Vec<Effect> {
    // tui-client.md §6 rule 1: the composer is disabled while sends are hard-blocked — checked
    // fresh against `state.trust` on every keystroke (never a value cached from an earlier gate
    // check), so it can never go stale. Nothing typed here reaches `state.composer` at all.
    if matches!(state.gate(), SendGate::Blocked(_)) {
        return Vec::new();
    }

    match key.code {
        KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) => {
            state.composer.push('\n');
        }
        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.composer.push('\n');
        }
        KeyCode::Enter => return attempt_send(state),
        KeyCode::Backspace => {
            state.composer.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.composer.clear();
        }
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            delete_last_word(&mut state.composer);
        }
        KeyCode::Up if state.composer.is_empty() => {
            if let Some(last) = &state.last_sent {
                state.composer = last.clone();
            }
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => state.composer.push(c),
        _ => {}
    }
    Vec::new()
}

fn attempt_send(state: &mut ChatState) -> Vec<Effect> {
    let body = state.composer.trim().to_string();
    if body.is_empty() || state.sending.is_some() {
        return Vec::new();
    }
    dispatch_gated_send(state, body)
}

fn delete_last_word(s: &mut String) {
    while s.ends_with(' ') {
        s.pop();
    }
    while let Some(c) = s.chars().last() {
        if c == ' ' || c == '\n' {
            break;
        }
        s.pop();
    }
}

fn handle_awaiting_ack_key(state: &mut ChatState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Esc => {
            state.mode = ComposerMode::Normal;
            state.composer.clear();
            state.notice = Some("key-change warning not acknowledged — message discarded".into());
            (Vec::new(), false)
        }
        KeyCode::Backspace => {
            state.composer.pop();
            (Vec::new(), false)
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => {
            state.composer.push(c);
            (Vec::new(), false)
        }
        KeyCode::Enter => {
            let ComposerMode::AwaitingAck { held, .. } =
                std::mem::replace(&mut state.mode, ComposerMode::Normal)
            else {
                unreachable!("guarded by the AwaitingAck check in handle_key")
            };
            let answer = state.composer.trim().to_ascii_lowercase();
            state.composer.clear();
            if answer == "y" || answer == "yes" {
                match state.trust.acknowledge_key_change(&state.peer_pubkey) {
                    // Never a direct, ungated `Effect::SendMessage` — re-checks the real gate via
                    // `dispatch_gated_send` (see the module doc's defense-in-depth note).
                    Ok(()) => {
                        state.notice = None;
                        (dispatch_gated_send(state, held), false)
                    }
                    Err(e) => {
                        state.notice = Some(format!("could not acknowledge: {e}"));
                        (Vec::new(), false)
                    }
                }
            } else {
                state.notice = Some("message discarded".into());
                (Vec::new(), false)
            }
        }
        _ => (Vec::new(), false),
    }
}

fn handle_transcript_key(state: &mut ChatState, key: KeyEvent) -> Vec<Effect> {
    match key.code {
        KeyCode::PageUp => scroll(state, 5),
        KeyCode::PageDown => scroll(state, -5),
        KeyCode::Down | KeyCode::Char('j') if is_plain_char(key.modifiers) => scroll(state, -1),
        KeyCode::Up | KeyCode::Char('k') if is_plain_char(key.modifiers) => scroll(state, 1),
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => scroll(state, 5),
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => scroll(state, -5),
        KeyCode::Home => jump_top(state),
        KeyCode::Char('g') if is_plain_char(key.modifiers) => jump_top(state),
        KeyCode::End => jump_bottom(state),
        KeyCode::Char('G') if is_plain_char(key.modifiers) => jump_bottom(state),
        KeyCode::Char('u') if is_plain_char(key.modifiers) => jump_to_first_unread(state),
        KeyCode::Char('r') if is_plain_char(key.modifiers) => return retry_last_failed(state),
        _ => {}
    }
    Vec::new()
}

fn scroll(state: &mut ChatState, delta: i64) {
    let max = state.entries.len() as i64;
    let next = (state.scroll_from_bottom as i64 + delta).clamp(0, max);
    state.scroll_from_bottom = next as usize;
}

fn jump_top(state: &mut ChatState) {
    state.scroll_from_bottom = state.entries.len();
}

fn jump_bottom(state: &mut ChatState) {
    state.scroll_from_bottom = 0;
}

fn jump_to_first_unread(state: &mut ChatState) {
    let idx = state
        .entries
        .len()
        .saturating_sub(state.unread_count as usize);
    state.scroll_from_bottom = state.entries.len().saturating_sub(idx);
}

/// `r` in the transcript: retries the most recent failed outbound send, if any, re-running it
/// through [`dispatch_gated_send`] (never a direct `Effect::SendMessage`) so trust changes since the
/// original failure (e.g. the contact became blocked in the meantime) are re-checked, not assumed
/// still `Ok`.
///
/// **Judgment call.** Retrying does not remove or mutate the original `Failed` entry on disk — a
/// successful retry appends a brand-new entry (a new worker-minted `mid`), the same way any other
/// send does; there is no history-mutation effect in this task's scope to rewrite/replace the old
/// row in place. This keeps the retry path identical to an ordinary send rather than inventing a new
/// kind of effect.
fn retry_last_failed(state: &mut ChatState) -> Vec<Effect> {
    let Some(entry) = state
        .entries
        .iter()
        .rev()
        .find(|e| e.dir == MsgDirection::Out && e.state == MessageState::Failed)
    else {
        return Vec::new();
    };
    let body = entry.body.clone();
    dispatch_gated_send(state, body)
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`] arriving while this screen is current.
///
/// **Security-review fix (Finding 1).** `crate::app::App::handle_worker` routes every worker event
/// to whichever screen is currently topmost purely by `Screen` variant — it does not (and, given
/// today's `Effect`/`WorkerEvent` shapes, cannot cheaply) correlate an event to a specific
/// in-flight request. Once `Screen::Chat` is wired into real navigation, a user can back out of
/// `Chat(A)` before its send resolves and open `Chat(B)`; the stale completion/failure for A's send
/// would then arrive while `Chat(B)` is topmost. A `SendMessage` completion/failure is therefore
/// only ever applied when `request.peer_pubkey == state.peer_pubkey` — otherwise it is discarded
/// exactly like any other non-matching event, **without** touching `state.entries`,
/// `state.failure_reasons`, or clearing `state.sending` (clearing it for a different conversation's
/// request could let a second concurrent send slip past the "second Enter while sending" guard for
/// *this* screen's own real in-flight send).
///
/// An event that doesn't match what's in flight — wrong `Effect` shape, or the right shape but for a
/// different peer — is silently ignored, never a panic — mirrors every other screen's
/// `handle_worker` in this crate.
pub fn handle_worker(state: &mut ChatState, event: WorkerEvent) -> Vec<Effect> {
    match event {
        WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(sent),
        })) if request.peer_pubkey == state.peer_pubkey => complete_send(state, request.body, sent),
        WorkerEvent::Failed(Effect::SendMessage(SendMessageEffect { request, .. }), message)
            if request.peer_pubkey == state.peer_pubkey =>
        {
            fail_send(state, message)
        }
        WorkerEvent::Failed(Effect::PersistHistory(_), message) => {
            state.notice = Some(format!("could not save message history: {message}"));
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn complete_send(state: &mut ChatState, body: String, sent: SentMessage) -> Vec<Effect> {
    state.sending = None;
    let entry_state = if sent.delivered {
        MessageState::Delivered
    } else {
        MessageState::Failed
    };
    let entry = HistoryEntry {
        v: CURRENT_VERSION,
        mid: sent.mid.clone(),
        dir: MsgDirection::Out,
        ts: sent.ts,
        stream: "mrd.chat/1".to_string(),
        body,
        state: entry_state,
    };
    // Security-review fix (Finding 3): `failure_reasons` must only ever be mutated in lockstep with
    // whether `entries` actually accepted this report. If `insert_deduped` refuses the insert (this
    // `mid` was already recorded, presumably under its *original* outcome), a repeat report claiming
    // a different outcome must not touch `failure_reasons` either — otherwise a stray re-report could
    // either leak an orphaned reason for an already-`Delivered` row, or silently erase the specific
    // offline copy for an already-`Failed` row (falling back to the generic retry line while still
    // showing "Failed" — a user could then `r`-retry a send that had, per the frozen `entries` row,
    // already succeeded).
    if !insert_deduped(&mut state.entries, entry.clone()) {
        return Vec::new();
    }
    if sent.delivered {
        state.failure_reasons.remove(&sent.mid);
    } else {
        state
            .failure_reasons
            .insert(sent.mid, offline_failure_copy(&state.failure_copy_label()));
    }
    vec![Effect::PersistHistory(PersistHistoryEffect {
        request: PersistHistoryRequest {
            peer_pubkey: state.peer_pubkey,
            entry,
        },
        outcome: None,
    })]
}

fn fail_send(state: &mut ChatState, error: String) -> Vec<Effect> {
    state.sending = None;
    state.notice = Some(send_error_copy(&error));
    Vec::new()
}

// ---------------------------------------------------------------------------
// Live inbound events (task 4.35) — see the module doc's "Receive-path wiring" section
// ---------------------------------------------------------------------------

/// Applies a live inbound `mrd.chat/1` text message to this open conversation —
/// `crate::app::App::handle_inbound`'s one call into this module for a
/// [`crate::app::InboundEvent::Message`] whose peer matches this screen's own `peer_pubkey`.
///
/// Mirrors [`complete_send`]'s exact "only persist what was actually inserted" discipline, just for
/// the inbound direction: [`insert_deduped`] (reused unchanged, keyed only on `mid`, never on
/// direction — exactly as this module's own doc always intended) decides whether `entry` is new; a
/// duplicate (e.g. a re-delivered envelope, or a mid that happens to already be present from a
/// racing outbound completion) is silently discarded here, same as `complete_send`'s own repeat-
/// report guard, and dispatches no further effect. `entry` must already be direction-`In` /
/// state-`Received` — built by `crate::worker::run_inbound_loop`, never by this function.
pub fn handle_inbound_message(state: &mut ChatState, entry: HistoryEntry) -> Vec<Effect> {
    if !insert_deduped(&mut state.entries, entry.clone()) {
        return Vec::new();
    }
    vec![Effect::PersistHistory(PersistHistoryEffect {
        request: PersistHistoryRequest {
            peer_pubkey: state.peer_pubkey,
            entry,
        },
        outcome: None,
    })]
}

/// Applies a live delivery receipt to this open conversation — marks the matching outbound `Sent`
/// row `Delivered`, in memory only. See the module doc's "Receive-path wiring" section for why there
/// is no disk-persistence effect for this (yet): a no-op if no entry with `dir == Out` and
/// `mid == ack_mid` is currently loaded (e.g. the acknowledged send happened in an earlier session
/// and its `Sent` row was never re-loaded as such) — never a panic, mirrors every other screen's
/// tolerant `handle_worker`/`handle_inbound` shape in this crate.
pub fn apply_receipt(state: &mut ChatState, ack_mid: &str) {
    if let Some(entry) = state
        .entries
        .iter_mut()
        .find(|e| e.dir == MsgDirection::Out && e.mid == ack_mid)
    {
        entry.state = MessageState::Delivered;
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — degradation-unaware default (unicode on, color on) for any call site without
/// a [`RenderCtx`] handy. See [`render_with_ctx`] and `crate::theme`'s own module doc.
pub fn render(state: &ChatState, frame: &mut Frame<'_>) {
    render_with_ctx(state, frame, &RenderCtx::default());
}

/// Pure view function — see the module doc and `crate::theme`'s own "retrofit scope" section.
pub fn render_with_ctx(state: &ChatState, frame: &mut Frame<'_>, ctx: &RenderCtx) {
    let area = frame.area();
    let (glyph, label) = trust_glyph_and_label(state.trust.trust_state(&state.peer_pubkey), ctx);
    let title = format!("Meridian — Chat · {}  {glyph} {label}", state.peer_label());
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .split(inner);

    render_transcript(state, frame, rows[0], ctx);
    render_composer(state, frame, rows[1], ctx);

    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state, ctx),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[2]);
}

fn render_transcript(state: &ChatState, frame: &mut Frame<'_>, area: Rect, ctx: &RenderCtx) {
    let lines = transcript_lines(state, ctx);
    let total = lines.len() as u16;
    let max_scroll = total.saturating_sub(area.height);
    let scroll_from_bottom = u16::try_from(state.scroll_from_bottom).unwrap_or(u16::MAX);
    let offset = max_scroll.saturating_sub(scroll_from_bottom);
    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((offset, 0));
    frame.render_widget(paragraph, area);
}

fn transcript_lines(state: &ChatState, ctx: &RenderCtx) -> Vec<Line<'static>> {
    if state.entries.is_empty() {
        return vec![Line::from(Span::styled(
            "(no messages yet)",
            Style::default().add_modifier(Modifier::DIM),
        ))];
    }

    let registry = transcript_registry(ctx);
    let divider_index = state
        .entries
        .len()
        .saturating_sub(state.unread_count as usize);
    let mut lines = Vec::new();
    for (i, entry) in state.entries.iter().enumerate() {
        if state.unread_count > 0 && i == divider_index {
            let mut style = Style::default();
            if let Some(color) = color_or_none(Color::Yellow, ctx) {
                style = style.fg(color);
            }
            lines.push(Line::from(Span::styled(
                glyph(GlyphKind::UnreadDivider, ctx),
                style,
            )));
        }
        lines.extend(registry.render(entry));
        if entry.dir == MsgDirection::Out && entry.state == MessageState::Failed {
            let copy = state
                .failure_reasons
                .get(&entry.mid)
                .cloned()
                .unwrap_or_else(|| "not delivered — press r to retry".to_string());
            let mut style = Style::default();
            if let Some(color) = color_or_none(Color::Red, ctx) {
                style = style.fg(color);
            }
            lines.push(Line::from(Span::styled(format!("      {copy}"), style)));
        }
    }
    lines
}

fn render_composer(state: &ChatState, frame: &mut Frame<'_>, area: Rect, ctx: &RenderCtx) {
    let gate = state.gate();
    let red = |base: Style| match color_or_none(Color::Red, ctx) {
        Some(color) => base.fg(color),
        None => base,
    };
    let yellow = |base: Style| match color_or_none(Color::Yellow, ctx) {
        Some(color) => base.fg(color),
        None => base,
    };
    let lines: Vec<Line<'static>> = if let SendGate::Blocked(reason) = &gate {
        // tui-client.md §6 rule 1: a hard-stop banner replaces the composer while sends are
        // blocked — live, recomputed every render, never a stale snapshot from the last `Enter`.
        vec![
            Line::from(Span::styled(
                "SENDS BLOCKED",
                red(Style::default().add_modifier(Modifier::BOLD)),
            )),
            Line::from(Span::styled(reason.clone(), red(Style::default()))),
        ]
    } else if let ComposerMode::AwaitingAck { reason, .. } = &state.mode {
        vec![
            Line::from(Span::styled(
                reason.clone(),
                yellow(Style::default().add_modifier(Modifier::BOLD)),
            )),
            Line::from("type y to acknowledge and send, anything else cancels:"),
            Line::from(format!("> {}", state.composer)),
        ]
    } else {
        let mut lines = Vec::new();
        if let Some(notice) = &state.notice {
            lines.push(Line::from(Span::styled(
                notice.clone(),
                red(Style::default()),
            )));
        }
        lines.push(Line::from(format!("> {}", state.composer)));
        lines
    };
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn footer_hint(state: &ChatState, ctx: &RenderCtx) -> String {
    if matches!(state.gate(), SendGate::Blocked(_)) {
        return "Esc back (sends blocked — see banner above)".to_string();
    }
    let recall = glyph(GlyphKind::RecallUp, ctx);
    match (&state.mode, state.focus) {
        (ComposerMode::AwaitingAck { .. }, _) => {
            "type y to acknowledge and send · anything else/Esc cancels".to_string()
        }
        (ComposerMode::Normal, ChatFocus::Composer) => {
            format!(
                "Enter send · Alt+Enter/^J newline · ^U clear · ^W delete word · {recall} \
                 recall · Tab scroll · Esc back"
            )
        }
        (ComposerMode::Normal, ChatFocus::Transcript) => {
            "PgUp/PgDn/^U/^D/jk scroll · Home/End/g/G top/bottom · u unread · r retry failed · Tab \
             compose · Esc back"
                .to_string()
        }
    }
}
