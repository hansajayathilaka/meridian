//! The real post-auth home screen (task 4.36): `Screen::Main`, the hub every other built-in screen's
//! own doc comment has been deferring live navigation to since it landed —
//! `crate::screens::contacts`'s "a future `Screen::Main`/`Preflight` step", `crate::screens::chat`'s
//! "a future task repointing `Enter`", `crate::screens::verify`'s "a future task that gives `App` a
//! real, loaded `TrustStore`", and `crate::app::Screen::Requests`'s/`Screen::Settings`'s identical
//! notes. This module is that future task, for everything **except** deciding *when* `Screen::Main`
//! is reached — that is `Preflight`'s job (task 4.37), explicitly out of this task's own scope.
//!
//! ## What `Screen::Main` actually renders — a deliberately narrower shape than tui-client.md §2's
//! mockup
//! §10 of tui-client.md is explicit that "no `Screen::Main` combines Contacts + conversation +
//! composer + status bar into one layout" and that each pane the mockup shows is a separate,
//! independently-built screen. That remains true after this task: [`render_with_ctx`] embeds the
//! already-built [`crate::screens::contacts`] pane (via
//! [`crate::screens::contacts::render_in`], task 4.36's own small additive refactor of that
//! screen's rendering entry point — a sub-`Rect`, not the whole frame) above a
//! [`crate::statusbar`] row, and nothing else. Building the full three-region mockup composite is
//! not this task's job (nor named in its own Deliverables) — this is the "real home screen" in the
//! sense of *live navigation*, not a pixel-for-pixel realization of the mockup.
//!
//! ## `MainState` — what a `LiveSession` becomes once it has somewhere to live
//! [`MainState::from_session`] consumes a [`crate::session::LiveSession`] (task 4.29) and:
//! - keeps `account`/`trust`/`chat` (the real, already-loaded
//!   [`meridian_core::account::AccountDescriptor`]/[`meridian_core::trust::TrustStore`]/
//!   [`meridian_core::chat::ChatState`]) directly on `MainState`, finally giving `App` the "real,
//!   loaded `TrustStore`" every other screen's own doc comment has been waiting on.
//! - builds the [`crate::screens::contacts::ContactsState`] this screen embeds via
//!   [`build_contact_entries`] — the join `crate::screens::contacts`'s own module doc anticipated a
//!   future `Screen::Main`/`Preflight` step performing (see that function's own doc for exactly how
//!   the join resolves the two stores' respective sources of truth).
//!
//! ## `trust` is *moved*, not borrowed, into `Screen::Chat`/`Screen::Verify` — and reclaimed back
//! `crate::screens::chat::ChatState`/`crate::screens::verify::VerifyState` both own a real
//! `TrustStore` outright (not a reference — see their own module docs for why: the composer's send
//! gate and the verify screen's mark-verified/acknowledge/block actions must call straight into
//! `TrustStore::can_send`/`mark_verified`/`acknowledge_key_change`/`set_user_blocked`, never a
//! re-derived approximation). Since `TrustStore` is deliberately move-only (`crate::session`'s own
//! module doc), opening either screen from here `std::mem::take`s `MainState::trust` (leaving a
//! trivial, harmless `TrustStore::default()` behind for the — brief, since `Screen::Main` is not
//! rendered or dispatched to while a screen is pushed on top of it — window until it pops).
//! `crate::app::App::reclaim_trust` is the other half: it moves the popped screen's own
//! (possibly-mutated) `TrustStore` back into whichever `Screen::Main` is on the stack, and refreshes
//! that one contact's [`crate::screens::contacts::ContactEntry`] row (via [`refresh_entry`]) so a
//! `Screen::Verify` mark-verified/block, for instance, doesn't leave this screen's own contacts list
//! showing a stale trust glyph — mirrors the manual "Reclaim the (unmutated by chat) TrustStore back
//! out of the popped Chat screen" idiom `apps/tui/tests/at_rest_audit.rs` already used by hand,
//! generalized and made automatic by this task.
//!
//! ## Narrowing, stated explicitly (this task's own honest-scoping discipline)
//! - **`Ctrl-R`/`r`'s request queue reflects `chat.pending_requests()` as of session load, not live
//!   arrivals during the running session.** `MainState::chat` is populated once, when
//!   `Screen::Main` is constructed, and this module never mutates it afterward — live arrivals
//!   during the session are task 4.35's `AppEvent::Inbound`/`App::pending_inbound_requests`
//!   mechanism (already built), which `crate::app::App::requests_snapshot` layers on top of this
//!   screen's own static snapshot. Accepting/rejecting a request from an opened `Screen::Requests`
//!   removes it from that screen's own in-memory list (task 4.21, unchanged); **since task 4.42 both
//!   accept and reject also reach back into `MainState::chat`** (`crate::app::App::
//!   apply_accepted_request`/`App::apply_rejected_request` replay `ChatState::accept_request`/
//!   `reject_request` in memory, matching the `sessions.bin` the worker already resealed), so neither
//!   an accepted nor a rejected request re-appears on a later `Ctrl-R`/`r` (task 4.42's own review
//!   pass closed the reject half, which its first pass had left open — see `App::
//!   apply_rejected_request`'s own doc comment).
//! - **`Screen::Chat` opened from here now actually loads its real, persisted transcript (task
//!   4.44) — but not synchronously, on the spot.** [`crate::session::LiveSession`] (task 4.29)
//!   deliberately carries no per-peer history — history lives in `crate::store::history`'s sealed,
//!   per-peer `.jsonl` files, and reading one is I/O this crate's `update` never performs directly
//!   (`docs/architecture/tui-client.md §4`). So `handle_key`'s `ContactsAction::OpenChat` arm still
//!   pushes `Screen::Chat` immediately with `entries: Vec::new()` (the screen opens instantly, same
//!   as before this task) — but now also dispatches an `Effect::LoadHistory` alongside it,
//!   `crate::app::App::apply_loaded_history` merges the real, sealed transcript in (deduped against
//!   whatever a racing live inbound may have already appended, oldest-first) once that worker round
//!   trip completes. This is true on **both** paths a chat opens: a fresh `Enter` from this screen,
//!   and a same-session re-open after `Esc` (which — unlike before this task — no longer discards
//!   the popped `ChatState`'s transcript for good, since the very next `OpenChat` re-reads it off
//!   disk rather than starting over from nothing remembered). See
//!   [`crate::app::LoadHistoryEffect`] and `crate::app::App::apply_loaded_history`'s own doc
//!   comments for the full merge/ordering reasoning, and `crate::store::history::load_or_default`
//!   (task 4.15, reused unchanged — never a second, divergent reader) for the read itself.
//! - **Fabricated `LiveSession`, by design.** Per this task's own Scope note, everything above is
//!   built and tested against a hand-built `LiveSession` — zero dependency on `Preflight` (task
//!   4.37) or a real `run_worker` existing.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use crossterm::event::KeyEvent;

use meridian_core::account::AccountDescriptor;
use meridian_core::chat::ChatState as CoreChatState;
use meridian_core::trust::{Contact, PinnedKey, TrustState, TrustStore};

use crate::app::{Effect, LoadHistoryEffect, LoadHistoryRequest, WorkerEvent};
use crate::screens::chat::ChatState;
use crate::screens::contacts::{self, ContactEntry, ContactsAction, ContactsState};
use crate::screens::verify::VerifyState;
use crate::session::LiveSession;
use crate::statusbar::{self, ConnectionState, StatusBarInfo, TransportPath};
use crate::store::contacts::{ContactRecord, ContactsDocument, PinnedKeyRecord, TrustLabel};
use crate::theme::RenderCtx;

// ---------------------------------------------------------------------------
// The join — TrustStore + ContactsDocument -> Vec<ContactEntry>
// ---------------------------------------------------------------------------

fn parse_pubkey_hex(s: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(s).ok()?;
    raw.as_slice().try_into().ok()
}

/// Joins the real, already-loaded [`TrustStore`] (task 4.3, the crypto-relevant source of truth)
/// with the TUI-local `contacts.json` cache (task 4.15, the display-only fields `TrustStore` has no
/// concept of) into the `Vec<ContactEntry>` [`ContactsState`] renders from — see this module's own
/// doc for why this is exactly the join `crate::screens::contacts`'s own module doc names as
/// belonging to "a future `Screen::Main`/`Preflight` step."
///
/// **Driven by `contacts.contacts`, not `trust.contacts()`.** [`crate::app::DeleteContactRequest`]'s
/// own doc comment is explicit that deleting a contact removes only its local `contacts.json`
/// display row, deliberately leaving the underlying `TrustStore` record (trust state, pinned-key
/// history) untouched so it can pick back up if the same pubkey is ever observed again. Iterating
/// `contacts.contacts` as the backbone (rather than `trust.contacts()`) is what makes that "removed
/// from the list" property actually hold here: a deleted contact's `contacts.json` row is gone, so
/// it stays absent from this join even though its `TrustStore` record still exists.
///
/// **That gap is closed, and the standing `TODO: confirm` with it (task 4.42).** This doc used to
/// note that a `TrustStore` contact with no matching `contacts.json` row — reachable only via
/// `Effect::AcceptRequest`'s own `TrustStore::observe` call, which never touched `contacts.json` —
/// was invisible to this join entirely, and that no design doc resolved whether an accepted
/// message-request sender should get a synthesized row. Task 4.41's exit gate then found that exact
/// hole as its blocking Defect C, and task 4.42 resolved it: **yes, it gets one, and
/// `Effect::AcceptRequest` is the only path that can ever create it.** A `MessageRequest` carries no
/// hint, so an accept-observed `Contact` has `hint == ""`, so `Contact::id_string()` fails
/// (`validate_hint` rejects an empty hint) — which makes the "show the sender's full `mrd1:` id so
/// the user re-adds them by hand" alternative structurally impossible rather than merely
/// un-implemented, and inventing a hint-less id form would contradict
/// [ADR 0001](../../../../docs/adr/0001-identity-scheme.md). So `worker::run_accept_request` now
/// upserts the row itself (`id: ""`, `hint: ""`, `conv_handle: None`), exactly as `run_add_contact`
/// does for the initiator side — see that function's own doc comment, and
/// `crate::app::App::apply_accepted_request` for the matching in-memory replay that makes it visible
/// without waiting for a restart. **The direction of the join is unchanged**, so the
/// "locally-deleted contact stays deleted" property above still holds: accept adds a *writer* behind
/// an affirmative user act, it does not let a stale `TrustStore` record resurrect a row on its own.
/// The `None` fallback below therefore stays as pure defense against an inconsistent store.
pub fn build_contact_entries(trust: &TrustStore, contacts: &ContactsDocument) -> Vec<ContactEntry> {
    contacts
        .contacts
        .iter()
        .map(|record| entry_from_record(trust, record))
        .collect()
}

fn entry_from_record(trust: &TrustStore, record: &ContactRecord) -> ContactEntry {
    let pubkey = parse_pubkey_hex(&record.pubkey).unwrap_or([0u8; 32]);
    match trust.contact(&pubkey) {
        Some(contact) => ContactEntry {
            pubkey,
            id: contact.id_string().unwrap_or_else(|_| record.id.clone()),
            hint: contact.hint.clone(),
            petname: contact.petname.clone(),
            trust: contact.state,
            user_blocked: contact.user_blocked,
            pinned_key_history: contact.pinned_key_history.clone(),
            policy_override: record.policy_override,
            added_at: record.added_at,
            last_activity_at: record.last_activity_at,
            unread: record.unread,
        },
        // Defensive fallback — should not happen for a well-formed store (a `contacts.json` row and
        // its matching `trust.bin` record are always written together, see
        // `crate::worker::upsert_contact_record`), but this join must never panic on an
        // inconsistent one.
        None => ContactEntry {
            pubkey,
            id: record.id.clone(),
            hint: record.hint.clone(),
            petname: record.petname.clone(),
            trust: from_trust_label(record.trust),
            user_blocked: false,
            pinned_key_history: record
                .pinned_key_history
                .iter()
                .map(from_pinned_key_record)
                .collect(),
            policy_override: record.policy_override,
            added_at: record.added_at,
            last_activity_at: record.last_activity_at,
            unread: record.unread,
        },
    }
}

fn from_trust_label(label: TrustLabel) -> TrustState {
    match label {
        TrustLabel::New => TrustState::New,
        TrustLabel::Pinned => TrustState::Pinned,
        TrustLabel::Verified => TrustState::Verified,
        TrustLabel::Blocked => TrustState::Blocked,
    }
}

fn from_pinned_key_record(r: &PinnedKeyRecord) -> PinnedKey {
    PinnedKey {
        pubkey: parse_pubkey_hex(&r.pubkey).unwrap_or([0u8; 32]),
        first_seen_unix: r.first_seen,
        last_seen_unix: r.last_seen,
    }
}

/// Rebuilds a single [`ContactEntry`] from a live [`Contact`], preserving the display-only fields
/// (`policy_override`/`added_at`/`last_activity_at`/`unread`) from whatever entry already existed
/// for this pubkey in `existing` — see `crate::app::App::reclaim_trust`'s own doc comment for why
/// this exists (keeping this screen's own contacts list from showing a stale trust glyph after a
/// `Screen::Chat`/`Screen::Verify` mutation is reclaimed back).
pub fn refresh_entry(contact: &Contact, existing: &[ContactEntry]) -> ContactEntry {
    let prior = existing.iter().find(|e| e.pubkey == contact.pubkey);
    ContactEntry {
        pubkey: contact.pubkey,
        id: contact
            .id_string()
            .unwrap_or_else(|_| prior.map(|p| p.id.clone()).unwrap_or_default()),
        hint: contact.hint.clone(),
        petname: contact.petname.clone(),
        trust: contact.state,
        user_blocked: contact.user_blocked,
        pinned_key_history: contact.pinned_key_history.clone(),
        policy_override: prior.and_then(|p| p.policy_override),
        added_at: prior.map(|p| p.added_at).unwrap_or(0),
        last_activity_at: prior.map(|p| p.last_activity_at).unwrap_or(0),
        unread: prior.map(|p| p.unread).unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The real post-auth home screen's state — see the module doc. `#[derive(Debug)]` is hand-rolled
/// (below), not derived: `chat` (`meridian_core::chat::ChatState`) holds ratchet/prekey key
/// material and deliberately has no `Debug` impl to derive through, same reason
/// `crate::session::LiveSession`'s own `Debug` is hand-rolled.
pub struct MainState {
    pub account: AccountDescriptor,
    pub trust: TrustStore,
    pub chat: CoreChatState,
    pub contacts: ContactsState,
}

impl std::fmt::Debug for MainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainState")
            .field("account", &self.account)
            .field("trust", &self.trust)
            .field("contacts", &self.contacts)
            .field(
                "chat",
                &"<redacted: meridian_core::chat::ChatState holds ratchet/prekey key material>",
            )
            .finish()
    }
}

impl MainState {
    /// Builds the real home screen's state from a just-loaded [`LiveSession`] (task 4.29) — see the
    /// module doc's "`MainState` — what a `LiveSession` becomes" section.
    pub fn from_session(session: LiveSession) -> Self {
        let entries = build_contact_entries(&session.trust, &session.contacts);
        Self {
            account: session.account,
            trust: session.trust,
            chat: session.chat,
            contacts: ContactsState::new(entries),
        }
    }

    /// This account's own public key, decoded from [`AccountDescriptor::pubkey`] — needed to
    /// compute a peer's safety number when opening `Screen::Verify` (mirrors
    /// `crate::worker`'s own private `account_pub_bytes` helper, duplicated here in small form
    /// since that one is private to `worker.rs`). Falls back to an all-zero key on a malformed
    /// descriptor rather than panicking — defensive; a real, worker-produced
    /// `AccountDescriptor::pubkey` is always 64 lowercase hex chars.
    fn own_pubkey(&self) -> [u8; 32] {
        parse_pubkey_hex(&self.account.pubkey).unwrap_or([0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

/// What a key event asks `App` to do — the screen-stack navigation this module can't perform
/// itself (no reach into `crate::app::App`'s screen stack), mirroring
/// [`crate::screens::contacts::ContactsAction`]'s own contract, one level up: unlike that type,
/// this one carries **fully-built** child states (`Box<ChatState>`/`Box<VerifyState>`) wherever
/// building one needs data — `trust`, `account` — only `MainState` holds.
pub enum MainAction {
    None,
    /// Push `Screen::Chat` — already fully built (`Enter`, via
    /// [`crate::screens::contacts::ContactsAction::OpenChat`]).
    OpenChat(Box<ChatState>),
    /// Push `Screen::ContactDetail` for this entry (`i`, via
    /// [`crate::screens::contacts::ContactsAction::OpenDetail`]).
    OpenContactDetail(ContactEntry),
    /// Push `Screen::Verify` — already fully built (`v`, via
    /// [`crate::screens::contacts::ContactsAction::OpenVerify`]).
    OpenVerify(Box<VerifyState>),
    /// Push `Screen::Requests` (`Ctrl-R`/`r`) — `App` builds the actual snapshot (this screen's own
    /// `chat.pending_requests()` plus whatever arrived live — see `crate::app::App::
    /// requests_snapshot`), since the *live-arrivals* half of that snapshot
    /// (`App::pending_inbound_requests`) lives on `App`, not here.
    OpenRequests,
    /// Nothing left to cancel locally — `App` should pop this screen (mirrors
    /// [`crate::screens::contacts::ContactsAction::Pop`]).
    Pop,
}

/// Handles one key event — delegates entirely to the embedded [`ContactsState`]
/// ([`contacts::handle_key`]) and translates the result into a [`MainAction`], building a real
/// `Screen::Chat`/`Screen::Verify` on the spot wherever [`ContactsAction`] itself can't (it has no
/// `trust`/`account` to build one from — see this module's own doc's "`trust` is moved, not
/// borrowed" section for why `state.trust` is `std::mem::take`n here rather than cloned).
pub fn handle_key(state: &mut MainState, key: KeyEvent) -> (Vec<Effect>, MainAction) {
    let (mut effects, action) = contacts::handle_key(&mut state.contacts, key);
    let action = match action {
        ContactsAction::None => MainAction::None,
        ContactsAction::Pop => MainAction::Pop,
        ContactsAction::OpenRequests => MainAction::OpenRequests,
        ContactsAction::OpenDetail(entry) => MainAction::OpenContactDetail(entry),
        ContactsAction::OpenChat(entry) => {
            let trust = std::mem::take(&mut state.trust);
            let peer_pubkey = entry.pubkey;
            // Task 4.44: the screen still opens instantly, with an empty transcript — no I/O in
            // `update` (`docs/architecture/tui-client.md §4`). `Effect::LoadHistory`, dispatched
            // alongside, is what actually reads `crate::store::history`'s real, sealed transcript;
            // `crate::app::App::apply_loaded_history` merges it in once the worker round trip
            // completes — see this module's own doc's "opened from here" section and that method's
            // own doc comment for the full merge/ordering reasoning.
            effects.push(Effect::LoadHistory(LoadHistoryEffect {
                request: LoadHistoryRequest { peer_pubkey },
                outcome: None,
            }));
            MainAction::OpenChat(Box::new(ChatState::new(
                peer_pubkey,
                entry.hint,
                trust,
                Vec::new(),
                entry.unread,
            )))
        }
        ContactsAction::OpenVerify(entry) => {
            let own_pubkey = state.own_pubkey();
            let trust = std::mem::take(&mut state.trust);
            MainAction::OpenVerify(Box::new(VerifyState::new(
                own_pubkey,
                entry.pubkey,
                entry.hint,
                trust,
            )))
        }
    };
    (effects, action)
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`] arriving while this screen is current — forwards to the embedded
/// [`ContactsState`]'s own [`contacts::handle_worker`] (so the add-contact/QR-import sub-flow keeps
/// working when reached through `Screen::Main`) and translates its
/// [`ContactsAction::OpenDetail`]-from-a-duplicate-guard case the same way [`handle_key`] does.
pub fn handle_worker(state: &mut MainState, event: WorkerEvent) -> (Vec<Effect>, MainAction) {
    let (effects, action) = contacts::handle_worker(&mut state.contacts, event);
    let action = match action {
        ContactsAction::OpenDetail(entry) => MainAction::OpenContactDetail(entry),
        _ => MainAction::None,
    };
    (effects, action)
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — degradation-unaware default (unicode on, color on), an honestly
/// "disconnected" status bar, for any call site without a [`RenderCtx`]/live connection handy. See
/// [`render_with_ctx`].
pub fn render(state: &MainState, frame: &mut Frame<'_>) {
    render_with_ctx(
        state,
        frame,
        &RenderCtx::default(),
        ConnectionState::Disconnected,
    );
}

/// Pure view function — see the module doc's "What `Screen::Main` actually renders" section:
/// this screen's own embedded contacts list, above a [`crate::statusbar`] row. `connection` is
/// `crate::app::App`'s own session-wide connection state (task 4.35) — not stored on `MainState`
/// itself, since it is not per-session data this screen owns, mirroring how `RenderCtx` itself is
/// resolved once in `App::render` and passed down rather than cached on any one screen.
pub fn render_with_ctx(
    state: &MainState,
    frame: &mut Frame<'_>,
    ctx: &RenderCtx,
    connection: ConnectionState,
) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    contacts::render_in(&state.contacts, frame, rows[0], ctx);

    // TODO: confirm — no live transport-path/relay-policy handle is threaded into `MainState` yet
    // (mirrors `crate::statusbar`'s own "no live data plumbed in yet" doc note); this renders the
    // real connection state (task 4.35) with the honest "unknown path / inherit policy" defaults
    // for the other two fields, never a fabricated "connected" glyph tui-client.md §6 rule 10
    // forbids.
    let info = StatusBarInfo {
        connection,
        transport: TransportPath::Unknown,
        policy: crate::config::NetworkPolicy::Inherit,
    };
    statusbar::render(frame, rows[1], &info);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::contacts::PolicyOverride;
    use meridian_core::trust::PinnedKey;

    fn account() -> AccountDescriptor {
        AccountDescriptor {
            v: 1,
            pubkey: "11".repeat(32),
            hint: "example.test".to_string(),
            store: meridian_core::account::StoreKind::Os,
            keyfile: None,
            service: Some("meridian".to_string()),
            label: "11".repeat(32),
            server: None,
        }
    }

    fn session_with_one_contact() -> LiveSession {
        let mut trust = TrustStore::default();
        let pubkey = [0x42u8; 32];
        trust.observe(pubkey, "peer.example", 1_000);
        trust.set_petname(&pubkey, Some("bob".to_string())).unwrap();

        let mut contacts = crate::store::contacts::ContactsDocument {
            v: crate::store::contacts::CURRENT_VERSION,
            contacts: Vec::new(),
        };
        contacts.contacts.push(ContactRecord {
            pubkey: hex::encode(pubkey),
            id: meridian_core::identity::to_id_string(&pubkey, "peer.example").unwrap(),
            hint: "peer.example".to_string(),
            petname: Some("bob".to_string()),
            trust: TrustLabel::Pinned,
            pinned_key_history: vec![PinnedKeyRecord {
                pubkey: hex::encode(pubkey),
                first_seen: 1_000,
                last_seen: 1_000,
            }],
            device_record_version_seen: None,
            policy_override: Some(PolicyOverride::Direct),
            added_at: 1_000,
            last_activity_at: 1_000,
            unread: 3,
            conv_handle: None,
        });

        LiveSession {
            account: account(),
            trust,
            chat: CoreChatState::default(),
            contacts,
        }
    }

    #[test]
    fn from_session_joins_trust_and_contacts_json_into_one_entry() {
        let state = MainState::from_session(session_with_one_contact());
        assert_eq!(state.contacts.entries.len(), 1);
        let entry = &state.contacts.entries[0];
        assert_eq!(entry.pubkey, [0x42u8; 32]);
        assert_eq!(entry.petname.as_deref(), Some("bob"));
        assert_eq!(entry.trust, TrustState::Pinned);
        assert_eq!(entry.unread, 3);
        assert_eq!(entry.policy_override, Some(PolicyOverride::Direct));
    }

    #[test]
    fn a_deleted_contacts_json_row_is_absent_even_if_trust_store_still_has_a_record() {
        let mut session = session_with_one_contact();
        // Simulate a prior Effect::DeleteContact: the contacts.json row is gone, the TrustStore
        // record is untouched (see Effect::DeleteContact's own doc comment).
        session.contacts.contacts.clear();
        let state = MainState::from_session(session);
        assert!(state.contacts.entries.is_empty());
        assert!(state.trust.contact(&[0x42u8; 32]).is_some());
    }

    #[test]
    fn refresh_entry_preserves_display_only_fields_from_the_prior_entry() {
        let existing = vec![ContactEntry {
            pubkey: [9u8; 32],
            id: "mrd1:deadbeef@example.test".to_string(),
            hint: "example.test".to_string(),
            petname: Some("carol".to_string()),
            trust: TrustState::Pinned,
            user_blocked: false,
            pinned_key_history: vec![PinnedKey {
                pubkey: [9u8; 32],
                first_seen_unix: 1,
                last_seen_unix: 1,
            }],
            policy_override: Some(PolicyOverride::RelayOnly),
            added_at: 42,
            last_activity_at: 43,
            unread: 7,
        }];
        let mut trust = TrustStore::default();
        trust.observe([9u8; 32], "example.test", 1);
        trust
            .set_petname(&[9u8; 32], Some("carol".to_string()))
            .unwrap();
        trust.mark_verified(&[9u8; 32]).unwrap();
        let contact = trust.contact(&[9u8; 32]).unwrap();

        let refreshed = refresh_entry(contact, &existing);
        assert_eq!(
            refreshed.trust,
            TrustState::Verified,
            "picks up the live mutation"
        );
        assert_eq!(refreshed.policy_override, Some(PolicyOverride::RelayOnly));
        assert_eq!(refreshed.added_at, 42);
        assert_eq!(refreshed.unread, 7);
    }

    #[test]
    fn enter_on_the_embedded_contacts_list_opens_a_real_chat_screen_and_takes_the_trust_store() {
        let mut state = MainState::from_session(session_with_one_contact());
        let (effects, action) = handle_key(
            &mut state,
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Enter,
                crossterm::event::KeyModifiers::NONE,
            ),
        );
        assert_eq!(
            effects.len(),
            1,
            "OpenChat must dispatch exactly one Effect::LoadHistory (task 4.44)"
        );
        match &effects[0] {
            Effect::LoadHistory(e) => assert_eq!(e.request.peer_pubkey, [0x42u8; 32]),
            other => panic!("expected Effect::LoadHistory, got {other:?}"),
        }
        match action {
            MainAction::OpenChat(chat) => {
                assert_eq!(chat.peer_pubkey, [0x42u8; 32]);
                assert!(
                    chat.entries.is_empty(),
                    "the screen still opens instantly with an empty transcript — the real, \
                     persisted history is merged in once Effect::LoadHistory completes (task 4.44), \
                     see crate::app::App::apply_loaded_history"
                );
            }
            _ => panic!("expected OpenChat"),
        }
        assert_eq!(
            state.trust.contacts().count(),
            0,
            "the TrustStore was moved into the Chat screen"
        );
    }

    #[test]
    fn i_opens_contact_detail() {
        let mut state = MainState::from_session(session_with_one_contact());
        let (effects, action) = handle_key(
            &mut state,
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char('i'),
                crossterm::event::KeyModifiers::NONE,
            ),
        );
        assert!(effects.is_empty());
        assert!(matches!(action, MainAction::OpenContactDetail(_)));
    }

    #[test]
    fn v_opens_a_real_verify_screen_with_the_right_safety_number_inputs() {
        let mut state = MainState::from_session(session_with_one_contact());
        let (effects, action) = handle_key(
            &mut state,
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char('v'),
                crossterm::event::KeyModifiers::NONE,
            ),
        );
        assert!(effects.is_empty());
        match action {
            MainAction::OpenVerify(verify) => {
                assert_eq!(verify.peer_pubkey, [0x42u8; 32]);
                assert_eq!(verify.own_pubkey, [0x11u8; 32]);
            }
            _ => panic!("expected OpenVerify"),
        }
    }

    #[test]
    fn render_works_against_a_test_backend_at_80x24_and_a_narrow_width() {
        let state = MainState::from_session(session_with_one_contact());
        for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
            let backend = ratatui::backend::TestBackend::new(w, h);
            let mut terminal = ratatui::Terminal::new(backend).expect("test backend");
            terminal.draw(|frame| render(&state, frame)).expect("draw");
        }
    }
}
