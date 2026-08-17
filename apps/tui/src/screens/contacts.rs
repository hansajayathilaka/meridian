//! The Contacts pane (task 4.19): list + filter/search + add-contact, the first T17 screen to
//! consume T08's real trust module (`meridian_core::trust`). Like every other screen in this crate,
//! everything here is synchronous and I/O-free: [`handle_key`]/[`handle_worker`] only ever mutate a
//! [`ContactsState`] and return the [`Effect`]s a (future) worker should execute; [`render`] is a
//! pure view function.
//!
//! ## `ContactRecord` vs. `TrustStore` — a documented design/judgment call
//!
//! `crate::store::contacts`'s own module doc says the TUI-local `contacts.json` cache
//! "**deliberately duplicates**" `meridian_core::trust::TrustStore`/`Contact` and that it is "the
//! TUI's own display-oriented local cache **screens read from directly**". Read literally, that
//! points at `ContactRecord` as this screen's primary data source. But `ContactRecord`'s `TrustLabel`
//! enum only has four values (`new | pinned | verified | blocked`) and has no field at all for
//! `Contact::user_blocked` — it structurally **cannot** represent
//! `TrustState::PinnedKeyChanged` (the pinned-contact key-change *warning*, distinct from
//! `TrustState::Blocked`'s hard stop) or a user-initiated block, both of which tui-client.md §6 rule
//! 1 ("key-change handling is un-softenable") treats as security-critical, must-be-accurate display
//! state.
//!
//! **This screen's resolution:** [`ContactEntry`] is a *join* of both stores, assembled once
//! wherever this screen's initial state is built (a future `Screen::Main`/`Preflight` step, out of
//! this task's scope — the same "already loaded by a future step" relationship
//! [`crate::screens::unlock::Entering::keyfile`]/`id` have to a future `Preflight`). It takes
//! `pubkey`/`petname`/`trust`/`user_blocked`/`pinned_key_history` from
//! `meridian_core::trust::TrustStore` (the crypto-relevant source of truth, always accurate for
//! security-critical state) and `policy_override`/`added_at`/`last_activity_at`/`unread` from
//! `ContactRecord` (fields `TrustStore` has no concept of at all — `trust.rs`'s own module doc: "
//! `PolicyCtx` in `streams.rs` is still not wired to this module"). `id`/`hint` are duplicated in
//! both stores and kept in sync by every mutation this screen dispatches (`Effect::AddContact`/
//! `Effect::SetPetname` write both `trust.bin` and `contacts.json` together — see their doc comments
//! in `crate::app`). This is a deliberate choice for this task, not something the design docs pin
//! down explicitly — flagged here for the reviewer.
//!
//! ## Trust-state glyph + label (tui-client.md §2's mockup, §6 rule 2: never color alone)
//! [`trust_glyph_and_label`] is the one place this mapping lives:
//! - `New` → `○` "new" (kept for mockup fidelity; in practice unreachable for a real
//!   [`ContactEntry`] — `TrustStore` never persists `New` on a stored `Contact`, see its own doc).
//! - `Pinned` → `●` "pinned", `Verified` → `●` "verified" — same glyph for both (matches the mockup,
//!   which also uses `●` for `bob · verified` and `alice · pinned`); the adjacent text label is what
//!   disambiguates them, which is exactly what "glyph **+ label**, never color alone" requires — the
//!   label text differs even where the glyph coincides.
//! - `PinnedKeyChanged` → `▲` "key changed — ack needed" (matches the mockup's `▲ carol key change`).
//! - `Blocked` → `✕` "blocked — key changed" — **not** shown in the mockup (which has no hard-blocked
//!   row), but given a distinct glyph from `PinnedKeyChanged` deliberately: it is the strictly more
//!   severe, un-softenable hard stop (verification-ux.md), and this screen's own judgment is that
//!   collapsing it onto the same `▲` as the acknowledgeable warning would under-signal the
//!   difference tui-client.md §6 rule 1 requires stay visible.
//!
//! `Contact::user_blocked` (a purely local, independently-clearable block — see `trust.rs`'s doc) is
//! layered on top as a `[blocked]` suffix, reusing `apps/cli/src/contact.rs::cmd_list`'s own exact
//! convention (`"  [blocked]"`) rather than inventing new wording.
//!
//! ## Fingerprint-alongside-petname (tui-client.md §6 rule 2)
//! [`short_pubkey`] reuses `meridian_core::trust::contact_label`'s own already-reviewed truncation
//! (`&hex::encode(pubkey)[..12]`, plus an ellipsis) — not the 60-digit pairwise safety number
//! (`meridian_core::crypto::safety_number`), which needs *both* parties' keys and belongs to the
//! dedicated Verify flow (task 4.5/4.22), not an ordinary list/detail display. Every row in this
//! screen's list, and every place a petname/label is shown in `crate::screens::contact_detail`,
//! renders this truncated key alongside it — see `tests/screens_contacts.rs`'s dedicated security
//! test for the assertion this constraint gets, per this task's own `## Deliverables`.
//!
//! ## Petname discipline
//! Mirrors `apps/cli/src/contact.rs::cmd_add`'s invariant exactly: the only two sources of a
//! petname *value* this screen ever reads from are [`EnterPetname::petname_input`] (explicit typing
//! on this screen's own add-contact form) and `crate::screens::contact_detail`'s rename field —
//! never `id`/`pubkey`/`hint`, and never a QR payload. Importing a QR
//! ([`Effect::ImportContactQr`]) only ever recovers a candidate id string, which is then run through
//! `meridian_core::identity::parse_id` exactly like a pasted id would be — QR import and manual
//! paste converge on the *same* [`EnterPetname`] step before anything is added, so there is no
//! separate code path where a QR-derived value could reach [`AddContactRequest::petname`].

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::identity::parse_id;
use meridian_core::trust::{PinnedKey, TrustState};

use crate::app::{
    AddContactEffect, AddContactRequest, AddedContact, Effect, ImportContactQrEffect,
    ImportContactQrRequest, WorkerEvent,
};
use crate::store::contacts::PolicyOverride;
use crate::theme::{
    color_or_none, contacts_pane_layout, glyph, ContactsPaneLayout, GlyphKind, RenderCtx,
};

// ---------------------------------------------------------------------------
// ContactEntry — the join described in the module doc
// ---------------------------------------------------------------------------

/// One contact as this screen (and `crate::screens::contact_detail`) displays it — see the module
/// doc for which fields come from `meridian_core::trust::TrustStore` vs.
/// `crate::store::contacts::ContactRecord`.
#[derive(Debug, Clone)]
pub struct ContactEntry {
    pub pubkey: [u8; 32],
    pub id: String,
    pub hint: String,
    /// LOCAL ONLY — never taken from the wire/QR/id string. See the module doc's "Petname
    /// discipline" section.
    pub petname: Option<String>,
    pub trust: TrustState,
    pub user_blocked: bool,
    pub pinned_key_history: Vec<PinnedKey>,
    pub policy_override: Option<PolicyOverride>,
    pub added_at: u64,
    pub last_activity_at: u64,
    pub unread: u64,
}

impl ContactEntry {
    /// The best available human-facing label: petname if set, else the advisory hint, else a
    /// truncated key — mirrors `meridian_core::trust::contact_label`'s own fallback chain (that
    /// function is private to `trust.rs`, so this is a small, deliberate re-implementation, not a
    /// call to it).
    pub fn display_label(&self) -> String {
        if let Some(p) = self.petname.as_deref().filter(|p| !p.is_empty()) {
            p.to_string()
        } else if !self.hint.is_empty() {
            self.hint.clone()
        } else {
            short_pubkey(&self.pubkey)
        }
    }

    /// Builds the entry [`Effect::AddContact`]'s completion produces.
    ///
    /// **Review fix (task 4.19, Finding 1).** This used to hard-code `trust: TrustState::Pinned`,
    /// `user_blocked: false`, and a single freshly-stamped [`PinnedKey`] history entry, on the
    /// theory that `TrustStore::observe`'s contract guarantees exactly that shape. That is only
    /// true on a genuine *first* observation: `observe`'s own doc is explicit that a repeat
    /// observation of an already-known pubkey leaves `state`/`user_blocked` untouched and
    /// *appends* to history rather than replacing it — reachable here because this task's own
    /// `DeleteContactRequest` design (see its doc comment in `crate::app`) only ever removes the
    /// local `contacts.json` display row, never the underlying `TrustStore` record, so a deleted
    /// `Verified`/`Blocked`/`PinnedKeyChanged` contact re-added under the same pubkey is **not** a
    /// fresh TOFU pin. [`AddedContact`] now carries the real post-`observe` `trust`/`user_blocked`/
    /// `pinned_key_history` straight from the worker's read of the actual `Contact` — this method
    /// just copies them through, never assumes a shape.
    fn from_added(added: AddedContact) -> Self {
        Self {
            pubkey: added.pubkey,
            id: added.id,
            hint: added.hint,
            petname: added.petname,
            trust: added.trust,
            user_blocked: added.user_blocked,
            pinned_key_history: added.pinned_key_history,
            policy_override: None,
            added_at: added.added_at,
            last_activity_at: added.added_at,
            unread: 0,
        }
    }
}

/// Truncated-pubkey display convention — see the module doc's "Fingerprint-alongside-petname"
/// section for why this, not the 60-digit safety number, is what belongs here.
pub fn short_pubkey(pubkey: &[u8; 32]) -> String {
    format!("{}…", &hex::encode(pubkey)[..12])
}

/// The glyph + label for a [`TrustState`] — see the module doc's own section for the full mapping
/// rationale, and `crate::theme`'s own doc for the unicode/ASCII fallback [`GlyphKind`] provides.
/// `pub` so `crate::screens::contact_detail`/`crate::screens::verify`/`crate::screens::chat` reuse the
/// identical mapping rather than duplicating it — the full retrofit set named in `crate::theme`'s own
/// "retrofit scope" doc section.
pub fn trust_glyph_and_label(state: TrustState, ctx: &RenderCtx) -> (&'static str, &'static str) {
    match state {
        TrustState::New => (glyph(GlyphKind::TrustNew, ctx), "new"),
        TrustState::Pinned => (glyph(GlyphKind::TrustPinnedOrVerified, ctx), "pinned"),
        TrustState::Verified => (glyph(GlyphKind::TrustPinnedOrVerified, ctx), "verified"),
        TrustState::PinnedKeyChanged => (
            glyph(GlyphKind::TrustKeyChanged, ctx),
            "key changed — ack needed",
        ),
        TrustState::Blocked => (glyph(GlyphKind::TrustBlocked, ctx), "blocked — key changed"),
    }
}

fn trust_style(state: TrustState, ctx: &RenderCtx) -> Style {
    let base = match state {
        TrustState::New => Style::default(),
        TrustState::Pinned => Style::default(),
        TrustState::Verified => Style::default(),
        TrustState::PinnedKeyChanged => Style::default().add_modifier(Modifier::BOLD),
        TrustState::Blocked => Style::default().add_modifier(Modifier::BOLD),
    };
    let color = match state {
        TrustState::New => Color::DarkGray,
        TrustState::Pinned => Color::Yellow,
        TrustState::Verified => Color::Green,
        TrustState::PinnedKeyChanged => Color::Yellow,
        TrustState::Blocked => Color::Red,
    };
    match color_or_none(color, ctx) {
        Some(color) => base.fg(color),
        None => base,
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The whole Contacts pane's state: the in-memory list (pre-loaded — see the module doc), selection/
/// filter, a transient footer notice, and the optional add-contact form.
#[derive(Debug, Clone)]
pub struct ContactsState {
    pub entries: Vec<ContactEntry>,
    /// Index into the *filtered* list ([`filtered_entries`]), not `entries` directly.
    pub selected: usize,
    pub filter: String,
    pub filtering: bool,
    /// A transient status line (currently only the "Verify not implemented yet" stand-in — see the
    /// crate doc's `v`/`Ctrl+V` handling below). Cleared on the next key that isn't `v` itself.
    pub notice: Option<String>,
    /// `Some` while the add-contact form (`n`) is open.
    pub add: Option<AddContactState>,
}

impl ContactsState {
    /// `entries` is already-loaded, non-secret display data — mirrors
    /// `crate::screens::unlock::UnlockState::new`'s "a future Preflight step already has this"
    /// contract (see the module doc).
    pub fn new(entries: Vec<ContactEntry>) -> Self {
        Self {
            entries,
            selected: 0,
            filter: String::new(),
            filtering: false,
            notice: None,
            add: None,
        }
    }
}

/// The add-contact sub-flow (`n`), one variant per step — mirrors
/// `crate::screens::onboarding::OnboardingState`'s shape.
#[derive(Debug, Clone)]
pub enum AddContactState {
    EnterId(EnterId),
    ImportingQr(ImportingQr),
    EnterPetname(EnterPetname),
    Adding(Adding),
    Error(AddContactError),
}

/// Sub-step 1: paste an `mrd1:` id, or type the path to a QR image to import instead — `Tab` toggles
/// which field is focused, mirroring `crate::screens::onboarding::ShowIdentity`'s two-field pattern.
#[derive(Debug, Clone, Default)]
pub struct EnterId {
    pub id_input: String,
    pub qr_path_input: String,
    pub focus: EnterIdFocus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnterIdFocus {
    #[default]
    Id,
    QrPath,
}

/// Sub-step 1b (in-flight only): [`Effect::ImportContactQr`] is out.
#[derive(Debug, Clone)]
pub struct ImportingQr {
    pub qr_path: String,
}

/// Sub-step 2: the id parsed successfully (paste or QR alike — see the module doc); collect the
/// optional local petname before submitting.
#[derive(Debug, Clone)]
pub struct EnterPetname {
    pub pubkey: [u8; 32],
    pub hint: String,
    pub id: String,
    pub petname_input: String,
}

/// Sub-step 3 (in-flight only): [`Effect::AddContact`] is out.
#[derive(Debug, Clone)]
pub struct Adding {
    pub request: AddContactRequest,
}

/// Terminal (retryable) state: either the id failed to parse (paste or post-QR-decode), the QR
/// import itself failed, or [`Effect::AddContact`] failed. `Esc`/`Enter` return to `back`.
#[derive(Debug, Clone)]
pub struct AddContactError {
    pub message: String,
    pub back: Box<AddContactState>,
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// What a key event in [`ContactsState`]'s plain list-navigation mode asks `App` to do — the one
/// piece of screen-stack navigation this module can't perform itself (it has no reach into
/// `crate::app::App`'s screen stack), mirroring `crate::screens::onboarding::handle_key`'s
/// `(effects, finished)` contract, just with a richer payload than a bare `bool`.
#[derive(Debug, Clone)]
pub enum ContactsAction {
    /// Nothing for `App` to do beyond dispatching the returned effects.
    None,
    /// Push `Screen::ContactDetail` for this entry — see the module doc's note on `Enter` standing
    /// in for the not-yet-built `Screen::Conversation` (`docs/architecture/diagrams/tui-screen-
    /// flow.mermaid`'s `Contacts --> Conversation: Enter on a contact` transition) until task 4.20
    /// lands a real chat screen: today, `Enter` is the only way to reach `Contact detail`, so it
    /// opens that instead of a screen that doesn't exist yet. A future task repointing `Enter` at
    /// `Conversation` should give `Contact detail` its own key at that point (tui-client.md's own
    /// "Reached by ... Enter on a contact with the detail toggle" wording already anticipates a
    /// dedicated toggle distinct from plain `Enter`).
    OpenDetail(ContactEntry),
    /// Plain list navigation's own `Esc`, with nothing local to cancel (no add-contact form open, not
    /// filtering) — `App` should pop this screen, same outcome as the generic catch-all Esc-pop
    /// handler every other non-owning screen gets.
    Pop,
    /// `r` in plain list-navigation mode (tui-client.md §2's keymap table: "Contacts | ... · `r`
    /// requests ..."): push `Screen::Requests` (task 4.21) — this screen owns no message-request
    /// data itself (unlike `AddContact`'s `ContactEntry`/`AddedContact` payloads, there is nothing
    /// for this action to carry), so `App` is what actually constructs
    /// `crate::screens::requests::RequestsState` — see that variant's own doc comment for the
    /// "empty until a future Preflight loads real data" caveat this shares with the crate's other
    /// not-yet-fully-wired screens.
    OpenRequests,
}

/// Handles one key event. See [`ContactsAction`] for what `App` does with the second return value.
pub fn handle_key(state: &mut ContactsState, key: KeyEvent) -> (Vec<Effect>, ContactsAction) {
    if let Some(add) = state.add.as_mut() {
        let (effects, exit) = handle_add_contact_key(add, &state.entries, key);
        match exit {
            AddContactExit::Cancelled => {
                state.add = None;
            }
            // Finding 1's guard: the pasted/QR-derived pubkey already names a known contact —
            // close the add-contact form and open Contact detail for the *existing* entry instead
            // of re-running the add flow, so the truthful, already-known trust state is what the
            // user actually lands on (never a re-add that could display it wrong).
            AddContactExit::Duplicate(entry) => {
                state.add = None;
                return (effects, ContactsAction::OpenDetail(entry));
            }
            AddContactExit::None => {}
        }
        return (effects, ContactsAction::None);
    }

    // Any key other than `v` itself clears a stale "Verify not implemented" notice, so it doesn't
    // linger past whatever the user does next.
    if !matches!(key.code, KeyCode::Char('v')) {
        state.notice = None;
    }

    if state.filtering {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => state.filtering = false,
            KeyCode::Backspace => {
                state.filter.pop();
                state.selected = 0;
            }
            KeyCode::Char(c) if is_plain_char(key.modifiers) => {
                state.filter.push(c);
                state.selected = 0;
            }
            _ => {}
        }
        return (Vec::new(), ContactsAction::None);
    }

    match key.code {
        KeyCode::Up => move_selection(state, -1),
        KeyCode::Down => move_selection(state, 1),
        KeyCode::Char('k') if is_plain_char(key.modifiers) => move_selection(state, -1),
        KeyCode::Char('j') if is_plain_char(key.modifiers) => move_selection(state, 1),
        KeyCode::Enter => {
            if let Some(entry) = filtered_entries(state).get(state.selected) {
                let entry = (*entry).clone();
                return (Vec::new(), ContactsAction::OpenDetail(entry));
            }
        }
        KeyCode::Char('n') if is_plain_char(key.modifiers) => {
            state.add = Some(AddContactState::EnterId(EnterId::default()));
        }
        KeyCode::Char('r') if is_plain_char(key.modifiers) => {
            return (Vec::new(), ContactsAction::OpenRequests);
        }
        KeyCode::Char('/') => state.filtering = true,
        KeyCode::Char('v') if is_plain_char(key.modifiers) => {
            // The Verify screen (task 4.22) is out of this task's scope — see the module doc.
            // This just makes the key reachable/routed with a documented "not yet implemented"
            // notice, per this task's own `## Scope`.
            if !filtered_entries(state).is_empty() {
                state.notice = Some(
                    "Verify is not implemented yet (task 4.22) — press v again to dismiss".into(),
                );
            }
        }
        KeyCode::Esc => return (Vec::new(), ContactsAction::Pop),
        _ => {}
    }
    (Vec::new(), ContactsAction::None)
}

fn filtered_entries(state: &ContactsState) -> Vec<&ContactEntry> {
    if state.filter.is_empty() {
        return state.entries.iter().collect();
    }
    let needle = state.filter.to_lowercase();
    state
        .entries
        .iter()
        .filter(|e| {
            e.display_label().to_lowercase().contains(&needle)
                || e.hint.to_lowercase().contains(&needle)
                || e.id.to_lowercase().contains(&needle)
        })
        .collect()
}

fn move_selection(state: &mut ContactsState, delta: i32) {
    let n = filtered_entries(state).len();
    if n == 0 {
        state.selected = 0;
        return;
    }
    let cur = state.selected.min(n - 1) as i32;
    let next = (cur + delta).clamp(0, n as i32 - 1);
    state.selected = next as usize;
}

/// What the add-contact sub-flow asks its caller ([`handle_key`]/[`handle_worker`]) to do once it
/// needs to leave itself — mirrors [`ContactsAction`]'s "richer than a bare bool" shape, just for
/// the narrower set of things the sub-flow itself can trigger.
#[derive(Debug, Clone)]
enum AddContactExit {
    /// Nothing to do — the sub-flow is still running (including a plain internal step transition).
    None,
    /// The whole add-contact flow was cancelled (`Esc` at [`EnterId`], the first step) — close the
    /// form.
    Cancelled,
    /// **Finding 1's guard.** The pasted/QR-derived pubkey already matches a known entry in
    /// `state.entries` — close the form; the caller opens Contact detail for the *existing* entry
    /// instead of proceeding to [`EnterPetname`]/dispatching [`Effect::AddContact`]. This is
    /// checked as soon as the pubkey is known (right after `parse_id` succeeds, whether that id
    /// came from a paste or a decoded QR), before either the petname step or the effect exist —
    /// never after, so a re-add of an already-known contact can never reach
    /// [`ContactEntry::from_added`] with a fabricated "fresh TOFU pin" shape at all.
    Duplicate(ContactEntry),
}

/// Handles one key event for the add-contact sub-flow. Returns the effects (if any) and what the
/// caller should do about the sub-flow itself (see [`AddContactExit`]).
fn handle_add_contact_key(
    state: &mut AddContactState,
    entries: &[ContactEntry],
    key: KeyEvent,
) -> (Vec<Effect>, AddContactExit) {
    match state {
        AddContactState::EnterId(e) => {
            let (next, effects, exit) = handle_enter_id(e, entries, key);
            if let Some(next) = next {
                *state = next;
            }
            (effects, exit)
        }
        // In-flight: no input to give while an effect is out — mirrors onboarding's
        // Generating/Registering arms.
        AddContactState::ImportingQr(_) | AddContactState::Adding(_) => {
            (Vec::new(), AddContactExit::None)
        }
        AddContactState::EnterPetname(p) => {
            let (next, effects) = handle_enter_petname(p, key);
            if let Some(next) = next {
                *state = next;
            }
            (effects, AddContactExit::None)
        }
        AddContactState::Error(err) => {
            let next = handle_add_error(err, key);
            if let Some(next) = next {
                *state = next;
            }
            (Vec::new(), AddContactExit::None)
        }
    }
}

/// Looks up `entries` for a pubkey already known to this screen — the shared implementation behind
/// [`AddContactExit::Duplicate`]'s guard, used identically whether the pubkey came from a pasted id
/// ([`handle_enter_id`]) or a decoded QR ([`handle_add_contact_worker`]'s `ImportingQr` arm).
fn find_existing(entries: &[ContactEntry], pubkey: &[u8; 32]) -> Option<ContactEntry> {
    entries.iter().find(|e| &e.pubkey == pubkey).cloned()
}

fn handle_enter_id(
    e: &mut EnterId,
    entries: &[ContactEntry],
    key: KeyEvent,
) -> (Option<AddContactState>, Vec<Effect>, AddContactExit) {
    match key.code {
        // `EnterId` is the first step of the add-contact flow — Esc here cancels the whole thing.
        KeyCode::Esc => return (None, Vec::new(), AddContactExit::Cancelled),
        KeyCode::Tab => {
            e.focus = match e.focus {
                EnterIdFocus::Id => EnterIdFocus::QrPath,
                EnterIdFocus::QrPath => EnterIdFocus::Id,
            };
        }
        KeyCode::Backspace => {
            match e.focus {
                EnterIdFocus::Id => e.id_input.pop(),
                EnterIdFocus::QrPath => e.qr_path_input.pop(),
            };
            e.error = None;
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => {
            match e.focus {
                EnterIdFocus::Id => e.id_input.push(c),
                EnterIdFocus::QrPath => e.qr_path_input.push(c),
            }
            e.error = None;
        }
        KeyCode::Enter => match e.focus {
            EnterIdFocus::Id if !e.id_input.trim().is_empty() => {
                match parse_id(e.id_input.trim()) {
                    Ok(identity) => {
                        // Finding 1's guard: before ever reaching the petname step (let alone
                        // dispatching `Effect::AddContact`), check whether this pubkey already
                        // names a known contact.
                        if let Some(existing) = find_existing(entries, identity.pubkey()) {
                            return (None, Vec::new(), AddContactExit::Duplicate(existing));
                        }
                        let next = AddContactState::EnterPetname(EnterPetname {
                            pubkey: *identity.pubkey(),
                            hint: identity.hint().to_string(),
                            id: identity.to_id_string(),
                            petname_input: String::new(),
                        });
                        return (Some(next), Vec::new(), AddContactExit::None);
                    }
                    Err(err) => e.error = Some(err.to_string()),
                }
            }
            EnterIdFocus::QrPath if !e.qr_path_input.trim().is_empty() => {
                let path = std::path::PathBuf::from(e.qr_path_input.trim());
                let effect = Effect::ImportContactQr(ImportContactQrEffect {
                    request: ImportContactQrRequest { path },
                    outcome: None,
                });
                let next = AddContactState::ImportingQr(ImportingQr {
                    qr_path: e.qr_path_input.clone(),
                });
                return (Some(next), vec![effect], AddContactExit::None);
            }
            _ => {}
        },
        _ => {}
    }
    (None, Vec::new(), AddContactExit::None)
}

fn handle_enter_petname(
    p: &mut EnterPetname,
    key: KeyEvent,
) -> (Option<AddContactState>, Vec<Effect>) {
    match key.code {
        KeyCode::Esc => {
            // Back to EnterId, preserving what was typed there — mirrors onboarding's Esc-back
            // reconstruction (`ChooseStore::from_store`).
            let next = AddContactState::EnterId(EnterId {
                id_input: p.id.clone(),
                qr_path_input: String::new(),
                focus: EnterIdFocus::Id,
                error: None,
            });
            return (Some(next), Vec::new());
        }
        KeyCode::Backspace => {
            p.petname_input.pop();
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => p.petname_input.push(c),
        KeyCode::Enter => {
            // The ONLY source of this petname value: explicit typing into this field, right here —
            // see the module doc's "Petname discipline" section.
            let petname = if p.petname_input.trim().is_empty() {
                None
            } else {
                Some(p.petname_input.trim().to_string())
            };
            let request = AddContactRequest {
                id: p.id.clone(),
                pubkey: p.pubkey,
                hint: p.hint.clone(),
                petname,
            };
            let effect = Effect::AddContact(AddContactEffect {
                request: request.clone(),
                outcome: None,
            });
            let next = AddContactState::Adding(Adding { request });
            return (Some(next), vec![effect]);
        }
        _ => {}
    }
    (None, Vec::new())
}

fn handle_add_error(err: &mut AddContactError, key: KeyEvent) -> Option<AddContactState> {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => Some((*err.back).clone()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// What [`handle_add_contact_worker`] asks [`handle_worker`] to do — the worker-event counterpart
/// to [`AddContactExit`] (this one additionally reports a successful add, since that can only ever
/// arrive as a worker event, never a plain key event).
enum AddContactWorkerExit {
    /// Nothing for the caller to do beyond whatever internal step transition already happened.
    None,
    /// [`Effect::AddContact`] completed successfully — close the form and upsert this entry.
    Added(ContactEntry),
    /// **Finding 1's guard**, QR-import side: the pubkey the QR image decoded to already matches a
    /// known entry — same treatment as [`AddContactExit::Duplicate`], just reachable from a worker
    /// event (QR decode) instead of a key event (paste), since [`Effect::ImportContactQr`]'s
    /// completion is the only place a QR-derived pubkey ever becomes known to this screen.
    Duplicate(ContactEntry),
}

/// Handles a [`WorkerEvent`] arriving while this screen is current. An event that doesn't match
/// what's in flight (no add-contact form open, or a form open on a different sub-step) is silently
/// ignored, never a panic — mirrors `crate::screens::onboarding::handle_worker`. See
/// [`ContactsAction`] for what `App` does with the second return value (only ever `OpenDetail` or
/// `None` from here — this screen never asks `App` to pop itself from a worker event).
pub fn handle_worker(
    state: &mut ContactsState,
    event: WorkerEvent,
) -> (Vec<Effect>, ContactsAction) {
    if let Some(add) = state.add.as_mut() {
        match handle_add_contact_worker(add, &state.entries, event) {
            AddContactWorkerExit::Added(entry) => {
                apply_update(state, entry, false);
                state.add = None;
            }
            AddContactWorkerExit::Duplicate(entry) => {
                state.add = None;
                return (Vec::new(), ContactsAction::OpenDetail(entry));
            }
            AddContactWorkerExit::None => {}
        }
    }
    (Vec::new(), ContactsAction::None)
}

fn handle_add_contact_worker(
    add: &mut AddContactState,
    entries: &[ContactEntry],
    event: WorkerEvent,
) -> AddContactWorkerExit {
    match add {
        AddContactState::ImportingQr(importing) => {
            let qr_path = importing.qr_path.clone();
            match event {
                WorkerEvent::Completed(Effect::ImportContactQr(ImportContactQrEffect {
                    outcome: Some(id_str),
                    ..
                })) => match parse_id(&id_str) {
                    Ok(identity) => {
                        // Finding 1's guard, QR side — see `AddContactWorkerExit::Duplicate`.
                        if let Some(existing) = find_existing(entries, identity.pubkey()) {
                            return AddContactWorkerExit::Duplicate(existing);
                        }
                        *add = AddContactState::EnterPetname(EnterPetname {
                            pubkey: *identity.pubkey(),
                            hint: identity.hint().to_string(),
                            id: identity.to_id_string(),
                            petname_input: String::new(),
                        });
                    }
                    Err(err) => {
                        *add = AddContactState::Error(AddContactError {
                            message: format!("QR decoded, but is not a valid mrd1 id: {err}"),
                            back: Box::new(AddContactState::EnterId(EnterId {
                                qr_path_input: qr_path,
                                ..Default::default()
                            })),
                        });
                    }
                },
                WorkerEvent::Failed(Effect::ImportContactQr(_), message) => {
                    *add = AddContactState::Error(AddContactError {
                        message,
                        back: Box::new(AddContactState::EnterId(EnterId {
                            qr_path_input: qr_path,
                            ..Default::default()
                        })),
                    });
                }
                _ => {}
            }
            AddContactWorkerExit::None
        }
        AddContactState::Adding(_) => match event {
            WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
                outcome: Some(added),
                ..
            })) => AddContactWorkerExit::Added(ContactEntry::from_added(added)),
            WorkerEvent::Failed(Effect::AddContact(_), message) => {
                *add = AddContactState::Error(AddContactError {
                    message,
                    back: Box::new(AddContactState::EnterId(EnterId::default())),
                });
                AddContactWorkerExit::None
            }
            _ => AddContactWorkerExit::None,
        },
        _ => AddContactWorkerExit::None,
    }
}

/// Upserts (or, if `deleted`, removes) `entry` in `state.entries` by `pubkey` — the single place
/// `crate::screens::contact_detail`'s edits land back in this screen's list (via
/// `crate::app::App::apply_contact_update`), and also what a freshly-added contact goes through.
pub fn apply_update(state: &mut ContactsState, entry: ContactEntry, deleted: bool) {
    if deleted {
        state.entries.retain(|e| e.pubkey != entry.pubkey);
    } else if let Some(existing) = state.entries.iter_mut().find(|e| e.pubkey == entry.pubkey) {
        *existing = entry;
    } else {
        state.entries.push(entry);
    }
    let n = filtered_entries(state).len();
    if state.selected >= n {
        state.selected = n.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — degradation-unaware default (unicode on, color on) for any call site without
/// a [`RenderCtx`] handy. See [`render_with_ctx`] and `crate::theme`'s own module doc.
pub fn render(state: &ContactsState, frame: &mut Frame<'_>) {
    render_with_ctx(state, frame, &RenderCtx::default());
}

/// Pure view function — see the module doc and `crate::theme`'s own "retrofit scope" section. Also
/// applies the narrow-width contacts-collapse mechanism (task 4.26 deliverable 4,
/// [`crate::theme::contacts_pane_layout`]) to this screen's own row formatting — see [`render_list`].
pub fn render_with_ctx(state: &ContactsState, frame: &mut Frame<'_>, ctx: &RenderCtx) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Contacts");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    if let Some(add) = &state.add {
        render_add_contact(add, frame, rows[0], ctx);
    } else {
        render_list(state, frame, rows[0], ctx);
    }

    let footer_text = state
        .notice
        .clone()
        .unwrap_or_else(|| footer_hint(state, ctx));
    let footer = Paragraph::new(Line::from(Span::styled(
        footer_text,
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

fn render_list(state: &ContactsState, frame: &mut Frame<'_>, area: Rect, ctx: &RenderCtx) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);

    let filter_line = if state.filtering {
        format!("/ {}", state.filter)
    } else if !state.filter.is_empty() {
        format!("(filter: {}) — / to edit", state.filter)
    } else {
        "/ to filter".to_string()
    };
    frame.render_widget(Paragraph::new(Line::from(filter_line)), rows[0]);

    let filtered = filtered_entries(state);
    if filtered.is_empty() {
        let msg = if state.entries.is_empty() {
            "(no contacts) — press n to add one"
        } else {
            "(no matches)"
        };
        frame.render_widget(
            Paragraph::new(Line::from(msg)).wrap(Wrap { trim: false }),
            rows[1],
        );
        return;
    }

    // Task 4.26 deliverable 4: below-80-columns this screen renders its own rows in a denser,
    // unpadded format instead of the fixed-width columns it uses when there's room — see
    // `crate::theme::contacts_pane_layout`'s own doc for why this is the mechanism, not the
    // combined-layout integration itself (no such screen exists yet to collapse *within*).
    let layout_mode = contacts_pane_layout(rows[1].width);
    let lines: Vec<Line<'static>> = filtered
        .iter()
        .enumerate()
        .map(|(i, entry)| contact_row_line(entry, i == state.selected, layout_mode, ctx))
        .collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), rows[1]);
}

/// One contacts-list row: selection marker, trust glyph, label, trust label, and — per tui-
/// client.md §6 rule 2 — the truncated pubkey fingerprint, always alongside the label. `layout`
/// decides only the *formatting* (padded columns vs. dense/unpadded) — glyph + label + fingerprint are
/// always present in both, never dropped at a narrow width.
fn contact_row_line(
    entry: &ContactEntry,
    selected: bool,
    layout: ContactsPaneLayout,
    ctx: &RenderCtx,
) -> Line<'static> {
    let (glyph, label) = trust_glyph_and_label(entry.trust, ctx);
    let name = entry.display_label();
    let short = short_pubkey(&entry.pubkey);
    let blocked = if entry.user_blocked {
        "  [blocked]"
    } else {
        ""
    };
    let marker = if selected { "> " } else { "  " };
    let text = match layout {
        ContactsPaneLayout::SideBySide => {
            format!("{marker}{glyph} {name:<20} {label:<24} {short}{blocked}")
        }
        ContactsPaneLayout::Overlay => {
            format!("{marker}{glyph} {name} - {label} - {short}{blocked}")
        }
    };
    let style = if selected {
        Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
    } else {
        trust_style(entry.trust, ctx)
    };
    Line::from(Span::styled(text, style))
}

fn render_add_contact(add: &AddContactState, frame: &mut Frame<'_>, area: Rect, ctx: &RenderCtx) {
    let lines = add_contact_lines(add, ctx);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn add_contact_lines(add: &AddContactState, ctx: &RenderCtx) -> Vec<Line<'static>> {
    match add {
        AddContactState::EnterId(e) => enter_id_lines(e, ctx),
        AddContactState::ImportingQr(i) => vec![
            Line::from(format!("Importing QR from {}…", i.qr_path)),
            Line::from(""),
            Line::from("Decoding the QR image."),
        ],
        AddContactState::EnterPetname(p) => enter_petname_lines(p),
        AddContactState::Adding(_) => vec![
            Line::from("Adding contact…"),
            Line::from(""),
            Line::from("Pinning the key (trust-on-first-use) and saving it locally."),
        ],
        AddContactState::Error(err) => vec![
            Line::from(Span::styled(
                "Could not add this contact.",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(err.message.clone()),
            Line::from(""),
            Line::from("Press Enter or Esc to go back."),
        ],
    }
}

fn enter_id_lines(e: &EnterId, ctx: &RenderCtx) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Add a contact"),
        Line::from(""),
        Line::from(vec![
            Span::raw("mrd1 id: "),
            Span::styled(e.id_input.clone(), focus_style(e.focus == EnterIdFocus::Id)),
        ]),
        Line::from(vec![
            Span::raw("or QR image path: "),
            Span::styled(
                e.qr_path_input.clone(),
                focus_style(e.focus == EnterIdFocus::QrPath),
            ),
        ]),
    ];
    if let Some(err) = &e.error {
        lines.push(Line::from(""));
        let mut style = Style::default();
        if let Some(color) = color_or_none(Color::Red, ctx) {
            style = style.fg(color);
        }
        lines.push(Line::from(Span::styled(err.clone(), style)));
    }
    lines
}

fn enter_petname_lines(p: &EnterPetname) -> Vec<Line<'static>> {
    vec![
        Line::from(format!("Adding {}", p.id)),
        // The fingerprint is shown right where the petname is being chosen — the id is fixed by
        // the key, never by whatever petname gets typed next (tui-client.md §6 rule 2's spirit,
        // applied even before this contact has a row of its own to show it in).
        Line::from(format!("fingerprint: {}", short_pubkey(&p.pubkey))),
        Line::from(""),
        Line::from("Petname (optional, local only — Enter to confirm, blank to skip):"),
        Line::from(p.petname_input.clone()),
    ]
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default()
    }
}

fn footer_hint(state: &ContactsState, ctx: &RenderCtx) -> String {
    if let Some(add) = &state.add {
        match add {
            AddContactState::EnterId(e) if e.focus == EnterIdFocus::Id => {
                "Tab switch field · type id · Enter continue · Esc cancel".to_string()
            }
            AddContactState::EnterId(_) => {
                "Tab switch field · type path · Enter import · Esc cancel".to_string()
            }
            AddContactState::ImportingQr(_) | AddContactState::Adding(_) => {
                "please wait…".to_string()
            }
            AddContactState::EnterPetname(_) => {
                "type petname (optional) · Enter add · Esc back".to_string()
            }
            AddContactState::Error(_) => "Enter/Esc back".to_string(),
        }
    } else if state.filtering {
        "type to filter · Enter/Esc done".to_string()
    } else {
        let arrows = glyph(GlyphKind::ScrollHint, ctx);
        format!("{arrows}/jk move · Enter open · n add · r requests · v verify · / filter")
    }
}
