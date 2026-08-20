//! The Elm-style application core: `App` owns all state, `update` is a synchronous, pure state
//! transition, and `render` is a pure view function. **Neither ever performs I/O or awaits** — see
//! docs/architecture/tui-client.md §4. This is what makes `App::render` testable headlessly through
//! `ratatui::backend::TestBackend` (the basis for every screen-snapshot test from 4.16 onward).
//!
//! Screen content lives in [`crate::screens`] — one module per [`Screen`] variant, each owning its
//! own sub-state, `update`, and `render`; this module only dispatches to them and owns the pieces
//! that are genuinely global (quit, the screen stack).

use std::fmt;
use std::sync::Arc;

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::trust::{PinnedKey, TrustState, TrustStore};

use crate::session::LiveSession;

use crate::screens::chat::{self, ChatState};
use crate::screens::contact_detail::{self, ContactDetailState};
use crate::screens::contacts::{self, ContactEntry, ContactsState};
use crate::screens::diagnostics::DiagnosticsPane;
use crate::screens::help::{self, HelpState};
use crate::screens::main::{self, MainAction, MainState};
use crate::screens::onboarding::{self, OnboardingState};
use crate::screens::palette::{self, PaletteOutcome, PaletteState};
use crate::screens::requests::{self, RequestEntry, RequestsState};
use crate::screens::settings::{self, SettingsState};
use crate::screens::unlock::{self, UnlockState, Unlocking};
use crate::screens::verify::{self, VerifyState};
use crate::statusbar::ConnectionState;
use crate::store::contacts::PolicyOverride;
use crate::store::history::HistoryEntry;
use crate::surface::{ExtensionPane, PaletteAction, PaletteCommand, SurfaceRegistry};
use crate::theme::RenderCtx;

/// Events the runtime feeds into [`App::update`]. Produced by crossterm input, the worker-response
/// channel, or the 250ms tick — see the event-loop diagram in tui-client.md §4.
///
/// **Does not derive `Clone`** (review fix, task 4.29 Finding 1): `Worker` wraps a [`WorkerEvent`],
/// which no longer implements `Clone` (see that type's own doc comment) — nothing in this crate
/// clones a whole `AppEvent` today; each event is consumed exactly once by `App::update`.
#[derive(Debug)]
pub enum AppEvent {
    /// Fired every 250ms so the UI can animate/expire things without new input.
    Tick,
    /// A raw key event from crossterm.
    Key(KeyEvent),
    /// The terminal was resized to (columns, rows).
    Resize(u16, u16),
    /// Bracketed-paste text from crossterm.
    Paste(String),
    /// A worker task finished (or failed) executing an [`Effect`].
    ///
    /// Boxed (task 4.19): once `Effect` grew the contacts/contact-detail screens' six new
    /// I/O-requiring variants, `WorkerEvent` (which wraps a whole `Effect`) became large enough that
    /// `AppEvent`'s size gap against its zero-sized `Tick` variant tripped
    /// `clippy::large_enum_variant` — the same reason `Screen::Onboarding`/`Screen::Unlock`/
    /// `Screen::Contacts`/`Screen::ContactDetail` are all boxed already.
    Worker(Box<WorkerEvent>),
    /// A live push from the network (task 4.35) — **not** an answer to any `Effect` this crate ever
    /// dispatched, which is exactly why this is its own `AppEvent` variant rather than being squeezed
    /// into `WorkerEvent::Completed(Effect)`: nothing in `App::update` was waiting on it. Produced by
    /// `crate::worker::run_inbound_loop`'s persistent receive connection, forwarded onto the same
    /// worker→App channel every other `AppEvent` already flows through. Boxed for the same
    /// `clippy::large_enum_variant` reason as [`Self::Worker`].
    Inbound(Box<InboundEvent>),
    /// The persistent inbound connection's own connect/reconnect state (task 4.35, tui-client.md §7's
    /// `● reconnecting (n/m)` contract) — see [`crate::statusbar::ConnectionState`]. Routed into
    /// [`App::connection_status`], not into any one screen: the connection is session-wide, not
    /// per-conversation.
    ConnectionStatus(ConnectionState),
}

/// Already-decrypted content pushed live off the wire (task 4.35) — the payload of
/// [`AppEvent::Inbound`]. `crate::worker::run_inbound_loop` does all the crypto/session work
/// (`meridian_core::chat::ChatState::open_inbound`, the auto-ack) before ever constructing one of
/// these; `App::update` only ever routes already-decoded content, never touches ciphertext or a
/// `SecretStore` itself (this crate's I/O-free `update` invariant, tui-client.md §4).
#[derive(Debug, Clone)]
pub enum InboundEvent {
    /// A first-contact message request — mirrors `meridian_core::chat::ChatState::open_inbound`'s own
    /// gate exactly (task 2.10, §3.5): never auto-delivered, never auto-accepted. Routed to an already
    /// -open [`Screen::Requests`] directly, or queued in [`App`]'s own small pending-request buffer
    /// (drained into a fresh [`Screen::Requests`] the next time one opens — see
    /// [`App::handle_inbound`]) when no `Screen::Requests` is currently on the stack.
    MessageRequest(crate::screens::requests::RequestEntry),
    /// An ordinary `mrd.chat/1` text message from an already-accepted peer, already shaped as the
    /// [`HistoryEntry`] [`crate::screens::chat::insert_deduped`] (reused unchanged, exactly as that
    /// function's own doc comment anticipated) would dedup and append.
    Message {
        peer_pubkey: [u8; 32],
        entry: HistoryEntry,
    },
    /// A delivery receipt for one of our own previously-sent messages — `ack` is the acknowledged
    /// message's `mid` (hex), the same shape [`HistoryEntry::mid`] already uses.
    Receipt { peer_pubkey: [u8; 32], ack: String },
}

/// Which secret store an onboarding user chose to protect their private key with. The choice
/// itself performs no I/O — that only happens once a (future) worker executes
/// [`Effect::GenerateAccount`], via `meridian_core::identity::{FileSecretStore, OsSecretStore}`,
/// mirroring `apps/cli/src/main.rs::cmd_new`'s two branches (and its `OS_KEYSTORE_SERVICE`/default
/// keyfile location — onboarding doesn't ask the user for a custom path, only the choice of kind
/// and, for `File`, the passphrase).
#[derive(Clone, PartialEq, Eq)]
pub enum StoreChoice {
    Os,
    File { passphrase: String },
}

impl fmt::Debug for StoreChoice {
    /// Hand-rolled rather than derived: `File`'s `passphrase` must never appear in a `{:?}` dump
    /// (accidental `debug!()`/panic-message logging), even though [`Effect`] otherwise derives
    /// `Debug` freely — every type that embeds a [`StoreChoice`] inherits this redaction for free.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreChoice::Os => write!(f, "Os"),
            StoreChoice::File { .. } => write!(f, "File {{ passphrase: \"<redacted>\" }}"),
        }
    }
}

/// Inputs for onboarding's Generate sub-step (`Effect::GenerateAccount`): mint a fresh Ed25519
/// keypair via `meridian_core::identity::generate_account`, store the private seed in the chosen
/// [`StoreChoice`], and persist the non-secret `account.json` descriptor
/// (`meridian_core::account::AccountDescriptor`) — this crate's counterpart to
/// `apps/cli/src/main.rs::cmd_new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAccountRequest {
    pub store: StoreChoice,
    pub hint: String,
}

/// What generating an account actually produced. `update` cannot compute this itself — the keypair
/// is fresh randomness minted inside the worker's execution of [`Effect::GenerateAccount`] — so it
/// travels back inside the completed [`Effect`] for [`crate::screens::onboarding`] to pick up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAccount {
    /// Canonical `mrd1:…@hint` id string — public, safe to render/QR-encode.
    pub id: String,
    /// The store label (`KeyHandle::from_label`) — the public-key hex, same shape
    /// `AccountDescriptor::label` uses.
    pub label: String,
    /// Raw Ed25519 public key bytes, as `SignalingClient::connect`'s `account_pub` parameter wants
    /// them.
    pub account_pub: [u8; 32],
}

/// [`Effect::GenerateAccount`]'s payload: the request going out, and (once a worker has executed
/// it) the [`GeneratedAccount`] coming back. `outcome` is always `None` on the way out; a worker
/// populates it before wrapping this same value in `WorkerEvent::Completed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAccountEffect {
    pub request: GenerateAccountRequest,
    pub outcome: Option<GeneratedAccount>,
}

/// Inputs for onboarding's Register sub-step (`Effect::Register`): connect and authenticate to a
/// rendezvous server, optionally redeeming an invite token —
/// `meridian_core::signaling::SignalingClient::connect`, mirroring
/// `apps/cli/src/main.rs::cmd_register`'s connect half. Carries no separate outcome payload: the
/// request's own fields are everything [`Effect::PublishBundle`] needs next, and the mere fact this
/// arrived wrapped in `WorkerEvent::Completed` is the only signal `update` needs.
///
/// **Note for the worker that eventually executes this (not built by this task):** because an
/// invite token is normally single-use, the live, authenticated `SignalingClient` this effect's
/// execution produces must be the *same* connection [`Effect::PublishBundle`]'s execution publishes
/// through — re-connecting from scratch for the publish step would try to redeem the invite twice.
/// This is why this type and [`PublishBundleRequest`] both carry `account_pub: [u8; 32]` (alongside
/// `label`): it is the intended cache key for a worker to look up the `SignalingClient` opened by
/// this request's execution and reuse it for the later `PublishBundleRequest`, rather than
/// reconnecting — mirroring `apps/cli/src/main.rs::cmd_register`'s inline single-connection pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub server: String,
    pub invite: Option<String>,
    pub store: StoreChoice,
    pub label: String,
    pub account_pub: [u8; 32],
}

/// Inputs for onboarding's PublishBundle sub-step (`Effect::PublishBundle`): publish a fresh
/// prekey bundle over the already-registered session —
/// `meridian_core::signaling::SignalingClient::publish_bundle`, mirroring
/// `apps/cli/src/main.rs::cmd_register`'s publish half. Deliberately carries no `invite` field —
/// only [`RegisterRequest`]'s execution ever redeems one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBundleRequest {
    pub server: String,
    pub store: StoreChoice,
    pub label: String,
    pub account_pub: [u8; 32],
    pub otk_count: usize,
}

/// What publishing a bundle actually produced — how many one-time prekeys went out, for the
/// terminal success screen (mirrors `cmd_register`'s own "published bundle with N one-time
/// prekeys" line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedBundle {
    pub otk_count: usize,
}

/// [`Effect::PublishBundle`]'s payload — same request/outcome shape as
/// [`GenerateAccountEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBundleEffect {
    pub request: PublishBundleRequest,
    pub outcome: Option<PublishedBundle>,
}

/// [`Effect::Unlock`]'s request half (task 4.17): unwrap a passphrase-protected keyfile —
/// `meridian_core::store::FileSecretStore::new(keyfile, passphrase)` followed by an unwrap
/// attempt (e.g. `export_seed`/`use_key`), mirroring `apps/cli/src/main.rs::load_store`'s
/// `StoreKind::File` branch.
///
/// **`passphrase` is a live secret** — hand-rolled, unconditionally redacted [`fmt::Debug`], same
/// discipline as [`StoreChoice::File`]'s, since this type sits directly inside [`Effect`], which
/// derives `Debug` and is itself dumped by this crate's own `panic!("{other:?}")` test
/// fallbacks.
#[derive(Clone, PartialEq, Eq)]
pub struct UnlockRequest {
    pub keyfile: std::path::PathBuf,
    pub passphrase: String,
}

impl fmt::Debug for UnlockRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockRequest")
            .field("keyfile", &self.keyfile)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// Wraps a [`LiveSession`] as it travels inside an [`Effect`]'s own outcome field
/// ([`UnlockEffect::outcome`]/[`LoadSessionOutcome::Loaded`]) — task 4.29.
///
/// `LiveSession` deliberately implements neither `Clone` nor `PartialEq` (`TrustStore`/`ChatState`
/// are move-only, never duplicated — see `crate::session`'s own module doc), and **this type does
/// not implement `Clone` either** — deliberately, not an oversight. An earlier version of this type
/// carried a hand-rolled `Clone` impl that panicked if ever called on a populated value, justified by
/// the (then-true, but unenforced) claim that every `crate::surface::PaletteAction::Effect`
/// registered anywhere in this crate was a static, request-only value. Review fix (task 4.29,
/// Finding 1): that was a real, reproduced one-keypress crash waiting to happen — nothing in the type
/// system stopped a future call site from registering a *populated* `SessionOutcome` as a
/// `PaletteAction::Effect`, and `Screen::Help`/`Screen::Palette`'s own registry-snapshot `.clone()`
/// (fired unconditionally by the global `F1`/`Ctrl+K` keys) would reach it. `PaletteAction::Effect`
/// is now a *factory* (`Arc<dyn Fn() -> Effect + Send + Sync>` — see that type's own doc comment for
/// the full reasoning), which never needs to clone a live `Effect` at all, so this type's `Clone` need
/// is gone at the root rather than merely narrowed to "still panics, just less likely to be hit".
pub struct SessionOutcome(Option<LiveSession>);

impl SessionOutcome {
    /// Not yet resolved (the shape every outgoing request effect starts in — mirrors every other
    /// `outcome: None` construction site in this file).
    pub fn empty() -> Self {
        Self(None)
    }

    /// Resolved: a worker successfully loaded/unlocked a real [`LiveSession`].
    pub fn ready(session: LiveSession) -> Self {
        Self(Some(session))
    }

    /// Unwraps into the plain `Option<LiveSession>` shape every other consumer in this crate already
    /// pattern-matches against `Effect`'s other `outcome: Option<T>` fields with.
    pub fn into_option(self) -> Option<LiveSession> {
        self.0
    }

    pub fn as_option(&self) -> Option<&LiveSession> {
        self.0.as_ref()
    }
}

impl fmt::Debug for SessionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(_) => write!(f, "SessionOutcome(Some(LiveSession))"),
            None => write!(f, "SessionOutcome(None)"),
        }
    }
}

/// [`Effect::Unlock`]'s full payload (task 4.29 extension): the [`UnlockRequest`] going out, and
/// (once a worker has executed it) the real, loaded [`LiveSession`] coming back for the file-backed
/// path — see this task's own risk note: "a live passphrase must never cross more than one effect
/// round-trip", which is exactly why the session comes back on *this* same effect rather than a
/// second `Effect::LoadSession` dispatch. Same request/outcome shape as [`GenerateAccountEffect`],
/// just with [`SessionOutcome`] standing in for a bare `Option<LiveSession>` (see that type's own doc
/// for why).
///
/// **Does not derive `Clone`** (review fix, task 4.29 Finding 1): [`SessionOutcome`] no longer
/// implements `Clone` — see that type's own doc comment for why — so this struct, which embeds one,
/// cannot derive it either. Nothing needs it: [`crate::surface::PaletteAction::Effect`] is a factory
/// now, never a stored value to clone.
#[derive(Debug)]
pub struct UnlockEffect {
    pub request: UnlockRequest,
    pub outcome: SessionOutcome,
}

/// [`Effect::LoadSession`]'s request half (task 4.29): resolve whatever `account.json` (if any) is
/// on disk under `$MERIDIAN_HOME`, and — for an **OS-keystore-backed** account only — its associated
/// `trust.bin`/`sessions.bin`/`contacts.json` into a real [`LiveSession`].
///
/// Carries no fields at all: every input a worker needs (`$MERIDIAN_HOME`'s layout,
/// `account.json`'s own declared `StoreKind`) is read fresh from disk at dispatch time — there is
/// nothing else a caller could usefully supply here that the worker doesn't already have to
/// re-derive anyway (mirrors [`RunDoctorRequest::binary`]'s status as the *only* thing that
/// genuinely can't be re-derived over on that effect; this one has no such field).
///
/// **A file-backed account's own load never goes through this effect** — that would mean either
/// re-prompting for (or worse, re-threading) a passphrase outside [`Effect::Unlock`]'s own single
/// round trip, exactly the risk that effect's own doc comment warns against. A worker that finds
/// `account.json` declares a file-backed store here fails closed with a clear message instead of
/// silently no-op'ing or guessing a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoadSessionRequest;

/// [`Effect::LoadSession`]'s outcome (task 4.29) — deliberately **not** a bare
/// `Option<LiveSession>`-shaped `outcome` field the way most other effects in this file use, because
/// "no `account.json` on disk at all" is a legitimate, non-error result this effect must be able to
/// report distinctly from "a real account was found and loaded" — collapsing the two into the same
/// shape would leave a caller unable to tell "nothing to load yet, route to onboarding" apart from
/// "a session was loaded but happens to be freshly-empty" without inspecting the loaded
/// [`AccountDescriptor`](meridian_core::account::AccountDescriptor) itself.
///
/// **Contract, precisely (task's own "no account.json" test case):** no `account.json` at all is
/// [`LoadSessionOutcome::NoAccount`] — never a hard [`WorkerEvent::Failed`] (a pristine,
/// never-onboarded `$MERIDIAN_HOME` is not an error) and never a fabricated [`LiveSession`] (there is
/// no real [`AccountDescriptor`](meridian_core::account::AccountDescriptor) to put in one). A
/// brand-new account that *has* an `account.json` (onboarding just finished) but nothing else yet
/// sealed on disk loads through the ordinary [`LoadSessionOutcome::Loaded`] path and comes back
/// looking exactly like [`LiveSession::empty`] would have built directly — same empty
/// `TrustStore`/`ChatState`/contacts, just reached by a real (trivial) disk read here instead of a
/// caller skipping the effect entirely, which is the "no disk read needed" shortcut this task's own
/// risk note flags as available to whichever future task wires onboarding's own completion — this
/// effect's own execution stays correct either way.
///
/// **Does not derive `Clone`** — same reason as [`UnlockEffect`]: [`LoadSessionOutcome::Loaded`]
/// embeds a boxed [`SessionOutcome`], which no longer implements `Clone`.
#[derive(Debug)]
pub enum LoadSessionOutcome {
    /// No `account.json` exists yet.
    NoAccount,
    /// A real account was found; its stores were opened (or defaulted). Boxed:
    /// `clippy::large_enum_variant` flags the size gap against `NoAccount`'s zero-sized variant
    /// otherwise — the same reason several `Screen`/`Effect` variants elsewhere in this file are
    /// boxed.
    Loaded(Box<SessionOutcome>),
}

/// [`Effect::LoadSession`]'s full payload — same request/outcome shape as [`GenerateAccountEffect`].
///
/// **Does not derive `Clone`** — same reason as [`UnlockEffect`]/[`LoadSessionOutcome`]: `outcome`
/// transitively embeds a [`SessionOutcome`], which no longer implements `Clone`.
#[derive(Debug)]
pub struct LoadSessionEffect {
    pub request: LoadSessionRequest,
    pub outcome: Option<LoadSessionOutcome>,
}

/// Inputs for [`Effect::AddContact`] (task 4.19, `crate::screens::contacts`): TOFU-pin a peer's
/// already-parsed identity into `meridian_core::trust::TrustStore` (`TrustStore::observe`, then —
/// only if `petname` is `Some` — `TrustStore::set_petname`) and mirror the result into the TUI-local
/// `contacts.json` cache (`crate::store::contacts::ContactRecord`), mirroring
/// `apps/cli/src/contact.rs::cmd_add`'s exact `observe` → conditional `set_petname` sequence and its
/// two-source-only petname discipline (see that module's doc comment).
///
/// `pubkey`/`hint` are already parsed out of `id` (via `meridian_core::identity::parse_id`, called
/// synchronously by the screen — pure, no I/O — before this effect is ever dispatched), so a
/// malformed id string is rejected before any effect goes out at all, mirroring onboarding's
/// `validate_hint` gate ahead of `Effect::GenerateAccount`. `petname` came **only** from this
/// screen's own petname text field (explicit user typing) or `None` — never derived from `id`,
/// `pubkey`, or `hint` — see `crate::screens::contacts`' module doc for the full invariant this
/// mirrors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddContactRequest {
    pub id: String,
    pub pubkey: [u8; 32],
    pub hint: String,
    pub petname: Option<String>,
}

/// What adding a contact actually produced. Deliberately a small, self-contained struct (mirroring
/// [`GeneratedAccount`]'s relationship to [`Effect::GenerateAccount`]) rather than the screen's own
/// richer `crate::screens::contacts::ContactEntry` view type: `Effect` payloads stay independent of
/// any one screen's internal representation, exactly like every other effect outcome in this file.
/// `added_at` is the worker's own wall-clock read at the moment of observation (this crate's `update`
/// stays pure/deterministic — no `SystemTime::now()` call anywhere in `crate::screens`, mirroring
/// `meridian_core::trust::TrustStore::observe`'s own "time is injected, not read" discipline).
///
/// **Review fix (task 4.19, Finding 1): every field below must reflect what
/// [`TrustStore::observe`](meridian_core::trust::TrustStore::observe) *actually* produced, never an
/// assumed "this must be a fresh TOFU pin" shape.** `TrustStore::observe`'s own contract is explicit
/// that a repeat observation of an already-known pubkey leaves `state` untouched and *appends* to
/// `pinned_key_history` rather than starting a single fresh entry — and this effect's own
/// `DeleteContactRequest` design means a pubkey can absolutely already be known to `TrustStore`
/// (`Verified`, `Blocked`, `PinnedKeyChanged`, with real history) even though this TUI's local
/// `contacts.json` display row for it was deleted and is being re-added. The future worker that
/// executes [`Effect::AddContact`] must build this struct by reading straight off the real
/// [`Contact`](meridian_core::trust::Contact) `TrustStore::observe`/`set_petname` produced — via
/// `TrustStore::contact(&pubkey)` after the call — never by hard-coding `TrustState::Pinned`,
/// `user_blocked: false`, or a single freshly-stamped history entry the way an earlier version of
/// [`crate::screens::contacts::ContactEntry::from_added`] mistakenly did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedContact {
    pub pubkey: [u8; 32],
    pub id: String,
    pub hint: String,
    /// The petname **now on record** for this contact after this effect's execution — i.e. read
    /// back from `TrustStore`/`ContactRecord` after the worker's conditional `set_petname` call
    /// (mirroring `apps/cli/src/contact.rs::cmd_add`: `set_petname` only runs when
    /// [`AddContactRequest::petname`] is `Some`). **Not** a verbatim echo of the request's
    /// `petname` field: on a re-add of an already-known contact with the request's petname field
    /// left blank (`None`), `set_petname` is never called at all, so the contact's real,
    /// already-set petname (if any) survives untouched — this field must carry that real value
    /// forward, not silently report `None` and clobber the display.
    pub petname: Option<String>,
    pub added_at: u64,
    /// The real post-`observe` (and, if applicable, post-`set_petname`) [`TrustState`] — always
    /// [`TrustState::Pinned`] on a genuine first observation, but whatever the contact's actual
    /// prior state was (`Verified`/`Blocked`/`PinnedKeyChanged`/`Pinned`) on a repeat observation.
    pub trust: TrustState,
    /// The real [`Contact::user_blocked`](meridian_core::trust::Contact::user_blocked) flag —
    /// always `false` on a genuine first observation (a brand-new `Contact` is never
    /// user-blocked), but must reflect an existing local block on a repeat observation.
    pub user_blocked: bool,
    /// The real, full [`Contact::pinned_key_history`](meridian_core::trust::Contact::pinned_key_history)
    /// — a single freshly-stamped entry on a genuine first observation, but the complete
    /// (never-truncated) history on a repeat observation, including any prior keys.
    pub pinned_key_history: Vec<PinnedKey>,
}

/// [`Effect::AddContact`]'s payload — same request/outcome shape as [`GenerateAccountEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddContactEffect {
    pub request: AddContactRequest,
    pub outcome: Option<AddedContact>,
}

/// Inputs for [`Effect::ImportContactQr`] (task 4.19): decode the `mrd1:` id string carried by a QR
/// image on disk. `path` is all this screen can produce synchronously — loading and decoding an
/// image file is I/O (`image::open`) plus a codec (`image`'s PNG/etc. decoders), so unlike
/// `AddContactRequest` above, there is no parsing this effect's inputs ahead of time.
///
/// **What the future worker executing this must do** (mirrors `apps/cli/src/verify.rs::scan_and_compare`
/// exactly — the CLI's own headless QR-scan path): `image::open(&request.path)?.to_luma8()`, then
/// `meridian_core::identity::decode_luma(&img)` to recover the raw `mrd1:…` string. The worker
/// deliberately does **not** call `parse_id` itself and does **not** touch `TrustStore`/
/// `contacts.json` — decoding a QR image only ever recovers a candidate id string (`system-
/// design.md §3.1`: "a QR is a transport, not a trust anchor"); [`crate::screens::contacts`] runs it
/// through `parse_id` itself (pure) once it comes back, exactly as if the same string had been
/// pasted into the id field by hand — so QR import and manual paste converge on one code path before
/// anything is ever added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportContactQrRequest {
    pub path: std::path::PathBuf,
}

/// [`Effect::ImportContactQr`]'s payload. `outcome` is the raw decoded string (not yet validated as
/// an `mrd1:` id — see [`ImportContactQrRequest`]'s doc for why that stays the screen's job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportContactQrEffect {
    pub request: ImportContactQrRequest,
    pub outcome: Option<String>,
}

/// Inputs for [`Effect::SetPetname`] (task 4.19, contact detail's rename action): identical write
/// path to `apps/cli/src/contact.rs::cmd_rename` — `TrustStore::set_petname(pubkey, petname)`,
/// mirrored into the matching `ContactRecord.petname` in `contacts.json`. `petname` came only from
/// this screen's own rename text field — same discipline as [`AddContactRequest::petname`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPetnameRequest {
    pub pubkey: [u8; 32],
    pub petname: Option<String>,
}

/// [`Effect::SetPetname`]'s payload. No separate outcome data — the mere fact of
/// `WorkerEvent::Completed` arriving is the only signal `crate::screens::contact_detail` needs, same
/// contract as [`RegisterRequest`]/[`Effect::Unlock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPetnameEffect {
    pub request: SetPetnameRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::SetUserBlocked`] (task 4.19, contact detail's block/unblock action):
/// `TrustStore::set_user_blocked(pubkey, blocked)` — identical to `apps/cli/src/contact.rs::cmd_block`'s
/// write path (which only ever sets `true`; this screen also supports unblocking, which
/// `set_user_blocked` already accepts per its own doc comment). Deliberately does **not** touch
/// `TrustState`/`TrustState::Blocked` — see `Contact::user_blocked`'s doc in `trust.rs` for why a
/// user-initiated block is a wholly separate, independently-clearable concept from a key-change
/// block. Not mirrored into `contacts.json`'s `ContactRecord` at all: that TUI-local cache's
/// `TrustLabel` enum has no field for a user-initiated block (only the four crypto trust states) —
/// see `crate::screens::contacts`' module doc for why this screen therefore treats
/// `meridian_core::trust::TrustStore` as the sole source of truth for this flag, never
/// `ContactRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetUserBlockedRequest {
    pub pubkey: [u8; 32],
    pub blocked: bool,
}

/// [`Effect::SetUserBlocked`]'s payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetUserBlockedEffect {
    pub request: SetUserBlockedRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::SetPolicyOverride`] (task 4.19, contact detail's per-contact relay-policy
/// override): writes only `contacts.json`'s `ContactRecord.policy_override` — `TrustStore` has no
/// concept of relay policy at all (`trust.rs`'s own module doc: "`PolicyCtx` in `streams.rs` is
/// still not wired to this module"), so unlike every other effect in this group this one never
/// touches `trust.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPolicyOverrideRequest {
    pub pubkey: [u8; 32],
    pub policy_override: Option<PolicyOverride>,
}

/// [`Effect::SetPolicyOverride`]'s payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPolicyOverrideEffect {
    pub request: SetPolicyOverrideRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::DeleteContact`] (task 4.19, contact detail's delete action).
///
/// **Judgment call (no core primitive exists for this — flagged for the reviewer).**
/// `meridian_core::trust::TrustStore` has no `remove`/`forget` method (by design: TOFU pinned-key
/// history is exactly the kind of thing that should not silently vanish — see `trust.rs`'s own
/// "never truncated or reordered" note on `Contact::pinned_key_history`). Rather than adding a new
/// core-crate deletion primitive (out of this task's "no protocol logic" scope — a new
/// `TrustStore` mutation is a trust-module change that would need its own review lens, not a UI-only
/// change), **`DeleteContact` removes only the local display entry from `contacts.json`'s
/// `ContactRecord` list.** The underlying `TrustStore` record (trust state, pinned-key history,
/// verification status) is left exactly as it was: if this pubkey is ever observed again, TOFU/
/// key-change history and any outstanding warning/block state pick back up from where they were,
/// never silently reset by a "delete" that was really only ever a local list-membership action. This
/// mirrors how "delete" is a lower-stakes, purely-local operation than a security-relevant trust
/// transition in every other client here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteContactRequest {
    pub pubkey: [u8; 32],
}

/// [`Effect::DeleteContact`]'s payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteContactEffect {
    pub request: DeleteContactRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::SendMessage`] (task 4.20, `crate::screens::chat`): seal and route one
/// `mrd.chat/1` text message to `peer_pubkey`, mirroring `apps/cli/src/chat.rs::send_text`'s own
/// seal-then-`route_tolerant` path exactly. **Dispatched only after `crate::screens::chat` has
/// already consulted `meridian_core::trust::TrustStore::can_send(peer_pubkey)` and gotten
/// [`meridian_core::trust::SendGate::Ok`]** — see that module's doc for the full gate-wiring
/// rationale; this request's own fields carry no gate-bypass path of any kind.
///
/// Deliberately carries no `mid`/timestamp: minting the locally-generated 128-bit message id and
/// reading the wall clock are both the kind of impure, effect-side operation this crate's `update`
/// never performs itself (mirrors [`GenerateAccountRequest`]'s fresh-keypair minting, and
/// `crate::store::contacts`'s own `getrandom::fill`-based conversation-handle generation, which
/// likewise happens only at the storage/worker boundary, never inside a screen's pure `handle_key`).
/// The worker that executes this effect mints both and reports them back via [`SentMessage`].
///
/// **Note for the worker that eventually executes this (not built by this task):** needs the same
/// account/session context [`RegisterRequest`]/[`PublishBundleRequest`] already cache
/// (`account_pub`, the unlocked `SecretStore`/`KeyHandle`, and an established `SignalingClient` +
/// `meridian_core::chat::ChatState` session for this peer) — out of this task's scope to plumb
/// through, exactly like those two requests' own "not built by this task" notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageRequest {
    pub peer_pubkey: [u8; 32],
    pub peer_hint: String,
    pub body: String,
}

/// What sending actually produced: the worker-minted `mid` (matches
/// `crate::store::history::HistoryEntry::mid`'s shape), the worker's wall-clock read at the moment
/// of sending, and whether the peer was reachable right now — mirrors
/// `apps/cli/src/chat.rs::send_text`'s own `delivered: bool` (`route_tolerant`'s return value)
/// exactly. `delivered == false` is the pre-T07 "peer offline" case
/// ([tui-client.md §7](../../../docs/architecture/tui-client.md#7-what-the-user-sees-when-things-go-wrong)),
/// never "queued for later delivery" — see `crate::screens::chat::offline_failure_copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    pub mid: String,
    pub ts: u64,
    pub delivered: bool,
}

/// [`Effect::SendMessage`]'s payload — same request/outcome shape as [`GenerateAccountEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageEffect {
    pub request: SendMessageRequest,
    pub outcome: Option<SentMessage>,
}

/// Inputs for [`Effect::PersistHistory`] (task 4.20, `crate::screens::chat`): append `entry` to
/// `peer_pubkey`'s sealed transcript — `crate::store::history::append`/`append_at` (task 4.15),
/// mirroring how every other sealed-store write in this crate (`AddContactRequest`'s
/// `contacts.json` write, etc.) only ever happens behind an [`Effect`], never inside `update`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistHistoryRequest {
    pub peer_pubkey: [u8; 32],
    pub entry: HistoryEntry,
}

/// [`Effect::PersistHistory`]'s payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistHistoryEffect {
    pub request: PersistHistoryRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::LoadHistory`] (task 4.44, `crate::screens::main`): read `peer_pubkey`'s whole
/// sealed transcript — `crate::store::history::load_or_default` (task 4.15), the **same** reader
/// [`crate::store::export`] already uses, never a second, divergent one — off disk, the "no I/O in
/// `update`" boundary (`docs/architecture/tui-client.md §4`) this effect exists specifically to
/// respect: `crate::screens::main::handle_key`'s `ContactsAction::OpenChat` arm dispatches this
/// alongside pushing `Screen::Chat` (with `entries: Vec::new()`, same as before this task — the
/// screen still opens instantly), rather than reading the file itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadHistoryRequest {
    pub peer_pubkey: [u8; 32],
}

/// [`Effect::LoadHistory`]'s payload — `outcome` carries the loaded transcript (in file order) on
/// success, mirroring [`AcceptRequestEffect`]'s "outcome carries the real data, not just `()`" shape
/// rather than [`PersistHistoryEffect`]'s (there is genuine data to hand back here, not just a
/// completion signal).
///
/// **No redaction on `outcome`.** `Vec<HistoryEntry>` carries real, already-decrypted conversation
/// content — the same plaintext `PersistHistoryEffect`/`SendMessageEffect` already carry through this
/// exact `#[derive(Debug)]` un-redacted, per `crate::screens::chat::ChatState`'s own doc comment
/// ("nothing reachable from here is a *secret* in this crate's hand-rolled-`Debug` sense... not
/// passphrases or key material"). This type carries no `SecretStore`/`KeyHandle`/passphrase of any
/// kind — only a pubkey and message content — so there is nothing here that precedent would redact;
/// see `tests::load_history_effect_carries_no_key_material_and_is_not_redacted` (mirrors
/// `crate::session::LiveSession`'s own redaction test and
/// `run_worker_account.rs::effect_debug_never_leaks_a_passphrase`, verifying the *opposite* property
/// deliberately, since there is no secret here to hide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadHistoryEffect {
    pub request: LoadHistoryRequest,
    pub outcome: Option<Vec<HistoryEntry>>,
}

/// Inputs for [`Effect::AcceptRequest`] (task 4.21, `crate::screens::requests`): accept a pending
/// message request and TOFU-pin its sender, mirroring `apps/cli/src/chat.rs::answer_request`'s
/// accept branch **order** exactly — `meridian_core::chat::ChatState::accept_request(sender_ik)`
/// first, *then* `meridian_core::trust::TrustStore::observe(sender_ik, hint, now_unix())` (task
/// 4.7's own fix: never pin before the user decides). Both calls are pure, synchronous, in-memory
/// mutations of the real, persisted `ChatState`/`TrustStore` this crate has no live handle to yet —
/// see `crate::screens::requests`'s module doc for why that pair of calls (and re-sealing the
/// results to disk) is deferred to a future worker rather than run inside `update`, mirroring
/// [`AddContactEffect`]'s identical split.
///
/// **No `peer_hint` field, unlike [`AddContactRequest`].** `meridian_core::chat::MessageRequest`
/// (task 2.10) carries only `sender_ik`/`safety_number`/`intro` — no advisory hint, unlike
/// `apps/cli/src/chat.rs::answer_request`, which already has one in scope from the CLI's own `chat
/// run <peer>` invocation (the operator typed the peer's full `mrd1:…@hint` id to start that
/// session). A message request can arrive from a sender this client never dialed, so no hint is
/// available here to carry forward; the future worker executing this effect calls
/// `TrustStore::observe(sender_ik, "", now_unix())` — `observe`'s own contract accepts an empty
/// hint (it simply leaves `Contact::hint` empty) — which is the honest behavior, not a fabricated
/// one. `TODO: confirm` whether a later task should extend `MessageRequest`/the wire protocol to
/// carry a sender-supplied display hint; today none exists to pass through.
///
/// **Now delivers `intro` into the sender's own transcript — task 4.49 resolved the question task
/// 4.42 deliberately deferred here.** The paragraph this replaces held that doing the write inside
/// `run_accept_request` would risk two writers of the same transcript entry racing the *live* inbound
/// path, and that task 4.44's reader (`Effect::LoadHistory`/`apply_loaded_history`) needed to exist
/// before a second writer could safely be added. Both are now resolved, not merely still true:
/// - Task [4.44](../../../docs/tasks/phase-4/4.44-chat-history-load-on-open.md) landed first and
///   already gives `apply_loaded_history` dedup-by-`mid` (`crate::screens::chat::insert_deduped`'s
///   in-memory twin), so a second writer producing the same `mid` the live inbound path might also
///   produce coalesces safely rather than double-appearing.
/// - Task [4.49](../../../docs/tasks/phase-4/4.49-persist-accepted-intro-history.md) is the write
///   itself: `worker::run_accept_request` now appends the accepted
///   [`meridian_core::chat::MessageRequest`]'s `intro` — when it is
///   [`meridian_core::envelope::ChatContent::Text`] (a
///   [`meridian_core::envelope::ChatContent::Receipt`] intro, reachable only from a degenerate first
///   envelope, is skipped, not invented into a history entry) — straight into the sender's
///   `history.jsonl` via
///   `crate::store::history::append`, inline in the same worker function that already writes
///   `sessions.bin`/`trust.bin`/`contacts.json` on accept, rather than as a follow-up
///   `Effect::PersistHistory` `App` would have to dispatch after the fact (see
///   `run_accept_request`'s own doc comment for the full reasoning and the narrower partial-failure
///   window this shape introduces). This effect's own `outcome` still carries only [`AddedContact`],
///   unchanged: the history write is a fire-and-forget durability side effect of a successful accept,
///   not data `App` needs to reconcile into memory the way [`AddedContact`] itself is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequestRequest {
    pub sender_ik: [u8; 32],
}

/// [`Effect::AcceptRequest`]'s payload.
///
/// **`outcome` carries an [`AddedContact`] since task 4.42 (piece C).** It used to be `Option<()>`
/// — "the mere fact of `WorkerEvent::Completed` arriving is the only signal
/// [`crate::screens::requests`] needs", which is still true *of that screen*. What it missed is that
/// nothing re-reads `contacts.json`/`trust.bin` mid-session: `crate::screens::main::MainState` owns
/// the only live `TrustStore`/`ChatState`/contacts list, built once at session load. So the
/// `contacts.json` row and TOFU pin `worker::run_accept_request` now writes would not become visible
/// until the *next* restart unless the same mutation is replayed in memory — which is what
/// [`App::apply_accepted_request`] does with exactly the fields this outcome carries (including
/// `added_at`, the **worker-supplied** timestamp, so `App::update` never has to read a clock).
///
/// `Some(..)` on a genuine accept (or on a partial-failure retry that completed the still-owed
/// pin); `None` both on `WorkerEvent::Failed` and on a `Completed` no-op — a phantom sender with no
/// session, or a fully-completed retry — where there is genuinely no decision to replay. See
/// `worker::run_accept_request`'s own doc comment for that guard's full derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequestEffect {
    pub request: AcceptRequestRequest,
    pub outcome: Option<AddedContact>,
}

/// Inputs for [`Effect::RejectRequest`] (task 4.21, `crate::screens::requests`):
/// `meridian_core::chat::ChatState::reject_request(sender_ik)` against the real, persisted
/// `ChatState` — discards the held request *and* the already-established session behind it, with no
/// wire signal of any kind (see that method's own doc comment). **This is the one property this
/// task's own tests are built to pin at the UI layer**: rejecting must leave
/// `crate::screens::requests::RequestsState` in exactly the same shape for `sender_ik` as if it had
/// never been in the queue at all — see that module's own "leaves no trace" doc section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectRequestRequest {
    pub sender_ik: [u8; 32],
}

/// [`Effect::RejectRequest`]'s payload. Same request/outcome shape as [`AcceptRequestEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectRequestEffect {
    pub request: RejectRequestRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::MarkVerified`] (task 4.22, `crate::screens::verify`): persist a
/// [`meridian_core::trust::TrustStore::mark_verified`] transition to disk. **The pure state
/// transition itself is already applied, synchronously, in-memory** by
/// `crate::screens::verify::apply_action` — mirrors `crate::screens::chat`'s own
/// `TrustStore::acknowledge_key_change` precedent: this screen's `TrustStore` handle is already a
/// live, in-memory copy, not a display-only join like `crate::screens::contacts::ContactEntry` — so
/// this effect exists purely for a future worker to re-seal the real, persisted `trust.bin` to
/// match, the same "the screen already knows the answer, the worker's only job is durability" shape
/// [`SetPetnameEffect`]/[`SetUserBlockedEffect`] already use. `pubkey` is carried so a future
/// worker's completion/failure event can be correlated back to *this* peer specifically — see
/// `crate::screens::verify`'s module doc for why that correlation is load-bearing (the same bug
/// class tasks 4.20 and 4.21 both hit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkVerifiedRequest {
    pub pubkey: [u8; 32],
}

/// [`Effect::MarkVerified`]'s payload. No separate outcome data — same contract as
/// [`SetPetnameEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkVerifiedEffect {
    pub request: MarkVerifiedRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::AcknowledgeKeyChange`] (task 4.22, `crate::screens::verify`): persist a
/// [`meridian_core::trust::TrustStore::acknowledge_key_change`] transition to disk — same
/// already-applied-locally-then-persisted-by-a-future-worker shape as [`MarkVerifiedRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgeKeyChangeRequest {
    pub pubkey: [u8; 32],
}

/// [`Effect::AcknowledgeKeyChange`]'s payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgeKeyChangeEffect {
    pub request: AcknowledgeKeyChangeRequest,
    pub outcome: Option<()>,
}

/// Identifies exactly one editable `config.toml` field (task 4.24, `crate::screens::settings`) —
/// the settings screen's own row/cursor identity, and (via [`SettingValue::field`]) the correlation
/// key [`crate::screens::settings::handle_worker`] matches a completion/failure event back to,
/// applying the now-three-times-documented lesson from tasks 4.20/4.21/4.22: never trust an
/// `Effect::SaveSetting` completion's *shape* alone to mean "the field I'm currently waiting on
/// resolved" — see that module's own doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingField {
    ServerUrl,
    RelayPolicy,
    Theme,
    Timestamps,
    Bell,
    RetainDays,
    MaxMessagesPerConversation,
    ReconnectBackoffMs,
}

/// A new value for exactly one [`SettingField`] — both the payload [`Effect::SaveSetting`] carries
/// out to a future worker (`crate::config_write::write_setting_at`, task 4.24) and what
/// `crate::screens::settings` applies to its own in-memory [`crate::config::TuiConfig`] copy
/// (immediately, synchronously — the same "screen already knows the answer, the worker's only job
/// is durability" shape [`MarkVerifiedRequest`]/[`SetPetnameRequest`] already use, and, per that
/// module's own doc, exactly what makes "session-only" a meaningful outcome rather than a discarded
/// one: the change really did take effect for this running session even on a persist failure).
/// Deliberately carries its own field identity (via [`SettingValue::field`]) rather than a
/// free-floating `SettingField` alongside it, so the two can never drift out of sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingValue {
    ServerUrl(Option<String>),
    RelayPolicy(crate::config::NetworkPolicy),
    Theme(crate::config::Theme),
    Timestamps(crate::config::Timestamps),
    Bell(crate::config::Bell),
    RetainDays(u32),
    MaxMessagesPerConversation(u32),
    ReconnectBackoffMs(Vec<u64>),
}

impl SettingValue {
    /// The [`SettingField`] this value belongs to — see the type's own doc for why this is derived
    /// rather than stored alongside as a separate field.
    pub fn field(&self) -> SettingField {
        match self {
            SettingValue::ServerUrl(_) => SettingField::ServerUrl,
            SettingValue::RelayPolicy(_) => SettingField::RelayPolicy,
            SettingValue::Theme(_) => SettingField::Theme,
            SettingValue::Timestamps(_) => SettingField::Timestamps,
            SettingValue::Bell(_) => SettingField::Bell,
            SettingValue::RetainDays(_) => SettingField::RetainDays,
            SettingValue::MaxMessagesPerConversation(_) => SettingField::MaxMessagesPerConversation,
            SettingValue::ReconnectBackoffMs(_) => SettingField::ReconnectBackoffMs,
        }
    }

    /// Applies this value to `config` in place — the synchronous, local half of the "apply now,
    /// persist later" split described on the type's own doc comment.
    pub fn apply_to(&self, config: &mut crate::config::TuiConfig) {
        match self {
            SettingValue::ServerUrl(v) => config.account.server = v.clone(),
            SettingValue::RelayPolicy(v) => config.network.policy = *v,
            SettingValue::Theme(v) => config.ui.theme = *v,
            SettingValue::Timestamps(v) => config.ui.timestamps = *v,
            SettingValue::Bell(v) => config.ui.bell = *v,
            SettingValue::RetainDays(v) => config.history.retain_days = *v,
            SettingValue::MaxMessagesPerConversation(v) => {
                config.history.max_messages_per_conversation = *v
            }
            SettingValue::ReconnectBackoffMs(v) => config.network.reconnect_backoff_ms = v.clone(),
        }
    }
}

/// Inputs for [`Effect::SaveSetting`] (task 4.24, `crate::screens::settings`): write one field's new
/// value back into `config_path`'s on-disk `config.toml`, preserving every comment/blank line/key
/// this change doesn't touch — `crate::config_write::write_setting_at`, the comment-preserving
/// `toml_edit`-based write-back path `crate::config`'s own module doc names as "a later task's
/// concern". `config_path` travels with every request rather than being assumed
/// (`crate::config::default_config_path()`) so a future worker never has to re-derive it, mirroring
/// how [`UnlockRequest::keyfile`] carries its own path rather than assuming a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveSettingRequest {
    pub config_path: std::path::PathBuf,
    pub value: SettingValue,
}

/// [`Effect::SaveSetting`]'s payload. No separate outcome data — same contract as
/// [`SetPetnameEffect`]/[`MarkVerifiedEffect`]: the mere fact of `WorkerEvent::Completed` vs.
/// `WorkerEvent::Failed` arriving (and, on failure, its carried message) is everything
/// `crate::screens::settings` needs — see that module's doc for what each outcome does to the
/// screen's own `notice`/`last_persist` state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveSettingEffect {
    pub request: SaveSettingRequest,
    pub outcome: Option<()>,
}

/// Inputs for [`Effect::RunDoctor`] (task 4.25, `crate::screens::diagnostics`): invoke the already-
/// built `meridian doctor --json` binary as a **subprocess** and parse its captured stdout —
/// `crate::screens::diagnostics::run_doctor_binary`/`parse_doctor_json` — never a direct, in-process
/// call into `apps/cli::doctor::run`, which this crate cannot depend on (ADR 0020;
/// `tools/lint-tui-no-cli.sh`). See that module's own doc comment for the full "wrapping the existing
/// `doctor` output" design rationale this field's own doc references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDoctorRequest {
    /// The binary to invoke — `"meridian"` (resolved via `PATH`) in every real construction site
    /// today ([`crate::screens::diagnostics::DOCTOR_BINARY`]); a distinct field (rather than a bare
    /// constant baked into a future worker) so a test can substitute a bogus name to prove the
    /// binary-not-found path produces real, honest text, not something silently swallowed.
    pub binary: String,
}

/// One NAT-matrix row from `meridian doctor --json`'s output — mirrors `apps/cli/src/doctor.rs`'s own
/// per-cell JSON object shape (`nat`/`host`/`srflx`/`relay`/`path`) field-for-field, since this is
/// literally that binary's own output parsed back, not a redesigned shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCell {
    pub nat: String,
    pub host: bool,
    pub srflx: bool,
    pub relay: bool,
    pub path: String,
}

/// The full parsed report — one [`DoctorCell`] per NAT scenario `meridian doctor --json` printed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DoctorReport {
    pub cells: Vec<DoctorCell>,
}

/// [`Effect::RunDoctor`]'s payload — same request/outcome shape as [`GenerateAccountEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDoctorEffect {
    pub request: RunDoctorRequest,
    pub outcome: Option<DoctorReport>,
}

/// The only path from `update` to the network, the keystore, or disk. A worker task executes these
/// and reports the outcome back as [`WorkerEvent`] / [`AppEvent::Worker`], so a slow rendezvous can
/// never freeze the UI. `FetchBundle` is still a placeholder (no task needs it yet);
/// `SendMessage`/`PersistHistory` are task 4.20's (`crate::screens::chat`) two — see
/// [`SendMessageEffect`]/[`PersistHistoryEffect`]; `GenerateAccount`/`Register`/`PublishBundle` are
/// onboarding's (task 4.16) three I/O-requiring sub-steps; `Unlock` is the returning-user
/// counterpart (task 4.17);
/// `AddContact`/`ImportContactQr`/`SetPetname`/`SetUserBlocked`/`SetPolicyOverride`/`DeleteContact`
/// are the contacts/contact-detail screens' (task 4.19) six; `AcceptRequest`/`RejectRequest` are the
/// message-request queue's (task 4.21) two — see [`AcceptRequestEffect`]/[`RejectRequestEffect`];
/// `MarkVerified`/`AcknowledgeKeyChange` are the verify screen's (task 4.22) two new ones —
/// `SetUserBlocked` is reused as-is for that screen's own block action — see
/// [`MarkVerifiedEffect`]/[`AcknowledgeKeyChangeEffect`]; `SaveSetting` is the settings screen's
/// (task 4.24) one new one — see [`SaveSettingEffect`]; `RunDoctor` is the diagnostics screen's (task
/// 4.25) one new one — see [`RunDoctorEffect`]; `LoadSession` is task 4.29's own new one — the
/// OS-keystore/no-account-yet counterpart to `Unlock`'s now-extended file-backed path — see
/// [`LoadSessionEffect`]; `LoadHistory` is task 4.44's own new one — the read half of
/// `PersistHistory`'s write, dispatched whenever `Screen::Chat` opens (first time or a same-session
/// re-open) so the transcript reflects `crate::store::history`'s real, sealed on-disk state rather
/// than starting empty — see [`LoadHistoryEffect`] and `crate::app::App::apply_loaded_history`.
///
/// **Does not derive `PartialEq`/`Eq`** (unlike most of the payload structs above): `Unlock`/
/// `LoadSession` carry a [`SessionOutcome`], and the [`crate::session::LiveSession`] it wraps
/// deliberately implements neither (move-only — see that type's own module doc), so there is no
/// meaningful, total equality to derive here any more. The handful of call sites that used to compare
/// whole `Effect`/`Vec<Effect>` values now use `matches!` instead (see e.g.
/// `crate::app::tests::find_binding_fires_a_registered_commands_effect_without_opening_the_palette`).
///
/// **Does not derive `Clone` either** (review fix, task 4.29 Finding 1): `Unlock`/`LoadSession`
/// transitively embed a [`SessionOutcome`], which no longer implements `Clone` — see that type's own
/// doc comment. Nothing needs `Effect: Clone` any more:
/// [`crate::surface::PaletteAction::Effect`] is now a factory (`Arc<dyn Fn() -> Effect + Send +
/// Sync>`) that builds a fresh `Effect` on every trigger rather than storing and cloning one, which is
/// what made `Clone` load-bearing here in the first place — see that type's own doc comment for the
/// full before/after reasoning. A call site that genuinely needs the same request twice (e.g. a
/// same-effect retry) constructs it twice / clones the smaller request struct instead — see
/// `apps/tui/tests/run_worker_account.rs`'s `publish_bundle_retry_after_a_transient_failure_reuses_
/// the_cached_connection` for the pattern.
#[derive(Debug)]
pub enum Effect {
    SendMessage(SendMessageEffect),
    FetchBundle,
    PublishBundle(PublishBundleEffect),
    PersistHistory(PersistHistoryEffect),
    LoadHistory(LoadHistoryEffect),
    /// Boxed: `clippy::large_enum_variant` flags the size gap against the smaller variants
    /// otherwise, once [`UnlockEffect::outcome`] can carry a whole [`LiveSession`] — the same
    /// `clippy::large_enum_variant` reason [`LoadSessionOutcome::Loaded`] is boxed too.
    Unlock(Box<UnlockEffect>),
    LoadSession(LoadSessionEffect),
    GenerateAccount(GenerateAccountEffect),
    Register(RegisterRequest),
    AddContact(AddContactEffect),
    ImportContactQr(ImportContactQrEffect),
    SetPetname(SetPetnameEffect),
    SetUserBlocked(SetUserBlockedEffect),
    SetPolicyOverride(SetPolicyOverrideEffect),
    DeleteContact(DeleteContactEffect),
    AcceptRequest(AcceptRequestEffect),
    RejectRequest(RejectRequestEffect),
    MarkVerified(MarkVerifiedEffect),
    AcknowledgeKeyChange(AcknowledgeKeyChangeEffect),
    SaveSetting(SaveSettingEffect),
    RunDoctor(RunDoctorEffect),
}

/// The outcome of a worker task executing an [`Effect`], reported back as [`AppEvent::Worker`].
///
/// **Does not derive `PartialEq`/`Eq`**, for the same reason [`Effect`] itself no longer does (see
/// that type's own doc comment) — nothing in this crate compares whole `WorkerEvent` values today.
/// **Does not derive `Clone`** either, for the same reason [`Effect`] no longer does (it wraps one
/// directly) — nothing in this crate clones a whole `WorkerEvent` today.
#[derive(Debug)]
pub enum WorkerEvent {
    Completed(Effect),
    Failed(Effect, String),
}

/// A screen on the navigation stack (tui-client.md §2 for the full eventual set: Onboarding,
/// Unlock, Main, Add contact, Requests, Verify, Contact detail, Settings, Diagnostics, Help,
/// Palette). [`Screen::Onboarding`] (task 4.16) is the first real one; every other built-in screen
/// is still a stand-in until its own task lands.
///
/// **Not `Clone`/`PartialEq`/`Eq`.** [`Screen::Extension`] (task 4.18) holds a `Box<dyn
/// ExtensionPane>` trait object, which none of those three can be derived for — and nothing in
/// this crate ever actually clones or compares a `Screen` (the tests below use `matches!` and
/// stack-length assertions), so the derives were never load-bearing to begin with. `Debug` is
/// hand-rolled instead of derived for the same reason — see the `impl` below.
pub enum Screen {
    /// Stand-in screen for wherever a real screen has not landed yet (e.g. onboarding/unlock
    /// completion before task 4.36 — see [`Screen::Main`]'s own doc comment for that transition's
    /// current, real target). Still used by tests that need a bare, contentless root.
    Placeholder,
    /// The real post-auth home screen (task 4.36) — see [`crate::screens::main`]'s own module doc
    /// for the full design. Constructed from a [`crate::session::LiveSession`] via
    /// [`MainState::from_session`]; every screen it can reach
    /// (`Chat`/`ContactDetail`/`Verify`/`Requests`, plus `Settings` via the palette) is fully wired
    /// below.
    ///
    /// **Not constructed by onboarding/unlock completion, or by `App::new`, yet — deliberately out
    /// of this task's own scope, not an oversight.** `App::handle_key`'s onboarding-finished and
    /// unlock-finished branches still swap to [`Screen::Placeholder`], exactly as before this task.
    /// Deciding *when* a run reaches `Screen::Main` — at startup (`Preflight`, detecting an existing
    /// `account.json`) *and* at onboarding/unlock's own completion, both of which need a real
    /// `LiveSession` a worker round trip must produce (`Effect::LoadSession`'s already-built
    /// `NoAccount`/`Loaded` split, and the `Effect::Unlock` `SessionOutcome`-reclaim gap
    /// `crate::session`'s own module doc already flags for "whichever future task" does this wiring)
    /// — is task 4.37's job, per this task's own Scope/Out-of-scope note. This variant exists fully
    /// wired and independently reachable via [`App::push_screen`] in the meantime, exactly like
    /// every other screen in this crate before its own live-navigation task landed. Boxed for the
    /// same `clippy::large_enum_variant` reason as every other large variant here.
    Main(Box<MainState>),
    /// Take a user with no `account.json` on disk to a registered, published identity — see
    /// [`crate::screens::onboarding`]. Boxed: `OnboardingState` is far larger than `Placeholder`
    /// (it carries whichever sub-step's fields — QR text, ids, form input — are live), and
    /// `clippy::large_enum_variant` flags the resulting size gap between `Screen`'s variants
    /// otherwise.
    Onboarding(Box<OnboardingState>),
    /// Unlock a returning user's existing **file-backed** account — see [`crate::screens::unlock`].
    /// Boxed for the same `clippy::large_enum_variant` reason as [`Screen::Onboarding`].
    ///
    /// **Not constructed by [`App::new`] yet.** Deciding *whether* a run needs `Unlock` at all
    /// (account exists? file-backed vs. OS keystore?) is the `Preflight` routing decision from
    /// `docs/architecture/diagrams/tui-screen-flow.mermaid`
    /// (`Preflight --> Unlock: account exists, file-backed store`), which is out of this task's
    /// (4.17) scope and does not exist anywhere in this crate yet — `App::new` still always starts
    /// on [`Screen::Onboarding`] (see its doc comment). This variant exists so the screen itself is
    /// fully wired and independently testable/reachable via [`App::push_screen`]; a future task
    /// (Preflight) only needs to decide *when* to push it, not build the dispatch plumbing below.
    Unlock(Box<UnlockState>),
    /// Contacts pane: list + filter/search + add-contact — see [`crate::screens::contacts`].
    /// Boxed for the same `clippy::large_enum_variant` reason as [`Screen::Onboarding`].
    ///
    /// **Not constructed by [`App::new`] yet**, same caveat as [`Screen::Unlock`]: the routing
    /// decision for *when* a run reaches the contacts pane (from `Screen::Main`, once that exists —
    /// task 4.20+) is out of this task's (4.19) scope. This variant exists fully wired and
    /// independently reachable via [`App::push_screen`].
    Contacts(Box<ContactsState>),
    /// Contact detail: trust state, key history, per-contact relay-policy override, petname,
    /// block/delete — see [`crate::screens::contact_detail`]. Boxed for the same reason as the
    /// other large variants above.
    ///
    /// **Reached by pushing on top of [`Screen::Contacts`]** (`App::handle_key`'s `Contacts` arm),
    /// so `Esc` pops back to the contacts list it came from — the ordinary screen-stack pattern
    /// (tui-client.md §2), not a root screen of its own.
    ContactDetail(Box<ContactDetailState>),
    /// The main conversation screen: scrollback, composer, delivery state, restart-persistent
    /// history — see [`crate::screens::chat`]. Boxed for the same reason as the other large
    /// variants above.
    ///
    /// **Not constructed by [`App::new`] yet, and not yet reachable from [`Screen::Contacts`]'s own
    /// `Enter` handling either** — same caveat as [`Screen::Unlock`]/[`Screen::Contacts`]:
    /// [`crate::screens::contacts`]'s own module doc already documents that `Enter` opens
    /// `ContactDetail` today only because `Screen::Chat` didn't exist yet, and that repointing
    /// `Enter` at this screen (giving `ContactDetail` its own dedicated key) is deliberately left
    /// to a future navigation-integration task rather than done here, to keep this task's diff
    /// scoped to `chat.rs` plus the `Effect`/`Screen` plumbing it needs. This variant exists fully
    /// wired (`handle_key`/`handle_worker`/`render` all dispatch to it below) and independently
    /// reachable via [`App::push_screen`], exactly like `Screen::Unlock` was before its own
    /// Preflight routing landed.
    Chat(Box<ChatState>),
    /// The message-request queue: sender key, safety number, intro, accept/reject — see
    /// [`crate::screens::requests`]. Boxed for the same reason as the other large variants above.
    ///
    /// **Reachable two ways** (tui-client.md §2's own "`^R`, or the Requests section of the contacts
    /// pane"), both wired at the bottom of [`App::handle_key`]: a global `Ctrl+R` (checked
    /// unconditionally, same top-level treatment as `Ctrl+Q`), and `r` from
    /// [`Screen::Contacts`]'s own plain list-navigation mode (`crate::screens::contacts`'s newly
    /// added [`contacts::ContactsAction::OpenRequests`]). Both push with an **empty** queue today:
    /// this crate has no live `meridian_core::chat::ChatState` handle anywhere yet to snapshot
    /// `pending_requests()` from — the same "not constructed with real data yet" gap
    /// [`Screen::Unlock`]/[`Screen::Contacts`]/[`Screen::Chat`] each flagged in their own doc
    /// comments before their own Preflight/Main routing existed. A future task that gives `App` a
    /// real, loaded `ChatState` (the same Preflight step those other screens are waiting on) is what
    /// should replace `Vec::new()` at both push sites with a real snapshot.
    Requests(Box<RequestsState>),
    /// The verification screen: 60-digit safety number + QR, mark-verified, block, and the two
    /// un-softenable key-change modals — see [`crate::screens::verify`]. Boxed for the same
    /// `clippy::large_enum_variant` reason as the other large variants above.
    ///
    /// **Reached by `^V` on a selected contact** (tui-client.md §2), **not yet wired**: like
    /// [`Screen::Chat`]/[`Screen::Requests`] before their own navigation-integration tasks,
    /// `crate::screens::contacts`'s own `v` key handler still shows its task-4.19-authored "Verify
    /// is not implemented yet (task 4.22)" stand-in notice rather than pushing this screen —
    /// wiring that requires `crate::screens::contacts::ContactsState` to carry both `own_pubkey`
    /// (to compute the safety number) and a live `meridian_core::trust::TrustStore` handle, neither
    /// of which it holds today (its own module doc explains why: it works off `ContactEntry`, a
    /// display-only join, not a live `TrustStore`). That plumbing is exactly the kind of "future
    /// task that gives `App` a real, loaded `TrustStore`" [`Screen::Requests`]'s own doc comment
    /// already anticipates for itself; this variant exists fully wired
    /// (`handle_key`/`handle_worker`/`render` all dispatch to it below) and independently reachable
    /// via [`App::push_screen`] in the meantime, exactly like every other screen in this crate
    /// before its own live-navigation task landed.
    Verify(Box<VerifyState>),
    /// A form over `config.toml`'s fields — see [`crate::screens::settings`]. Boxed for the same
    /// `clippy::large_enum_variant` reason as the other large variants above.
    ///
    /// **"Reached from the command palette" (tui-client.md §2) — wired by task 4.36.** Task 4.25
    /// wired `PaletteRegistry::find_binding` into [`App::handle_key`] (see that method's own doc
    /// comment) and gave the palette ([`Screen::Palette`]) a real, generic dispatch path
    /// (`App::dispatch_palette_action`) for any *registered* command, but deliberately left the
    /// "open Settings" command unregistered — it needed a real, already-loaded
    /// [`crate::config::TuiConfig`]/`config_path` to construct a [`SettingsState`] from, and `App`
    /// had no live config anywhere yet. Task 4.36 registers `nav.settings` in
    /// `App::register_builtin_commands` now that [`Screen::Main`]'s live `LiveSession` carries that
    /// config. This variant also remains independently reachable via [`App::push_screen`], exactly
    /// like [`Screen::Verify`].
    Settings(Box<SettingsState>),
    /// The generated help overlay (task 4.25) — `F1`, built from a snapshot of
    /// [`App`]'s registered [`crate::surface::PaletteRegistry`] taken at push time. See
    /// [`crate::screens::help`]'s module doc for why the snapshot (not a live reference) and why one
    /// small section of its content is deliberately hand-written rather than generated.
    Help(Box<HelpState>),
    /// The fuzzy command palette (task 4.25) — `Ctrl+K`, same registry-snapshot construction as
    /// [`Screen::Help`]. A dedicated `Screen` variant, **not** a [`Screen::Extension`] pane, because
    /// it needs [`App::push_screen`] access to dispatch a selected command's
    /// [`crate::surface::PaletteAction::PushPane`] — which
    /// [`crate::surface::ExtensionPane::handle_key`]'s `Vec<Effect>`-only return cannot reach. See
    /// [`crate::screens::palette`]'s module doc for the full reasoning.
    Palette(Box<PaletteState>),
    /// A feature-registered pane or screen (task 4.18, `docs/architecture/tui-client.md §8`) —
    /// e.g. a transfer list (T09) or a call status panel (T10). This is the **one** `Screen`
    /// variant every future feature's pane reaches the stack through: a feature implements
    /// [`crate::surface::ExtensionPane`] and pushes `Screen::Extension(Box::new(pane))` (typically
    /// via a [`crate::surface::PaletteAction::PushPane`] factory), so adding a new feature's pane
    /// never means adding a new `Screen` variant here. Task 4.25's own
    /// [`crate::screens::diagnostics::DiagnosticsPane`] is the first real (non-test) consumer of this
    /// mechanism, registered into `App::new`'s built-in [`crate::surface::PaletteRegistry`] exactly
    /// like a future third-party feature's pane would be.
    Extension(Box<dyn crate::surface::ExtensionPane>),
}

impl fmt::Debug for Screen {
    /// Hand-rolled because [`Screen::Extension`]'s `Box<dyn ExtensionPane>` cannot derive `Debug` —
    /// it prints the pane's [`crate::surface::ExtensionPane::title`] instead of its (arbitrary,
    /// feature-owned) internal state, mirroring how [`StoreChoice`]/[`UnlockRequest`] above
    /// hand-roll `Debug` to keep a live secret out of a dump, just for a different reason (no
    /// `Debug` impl exists at all here, rather than one existing but needing redaction).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Screen::Placeholder => write!(f, "Placeholder"),
            Screen::Main(state) => f.debug_tuple("Main").field(state).finish(),
            Screen::Onboarding(state) => f.debug_tuple("Onboarding").field(state).finish(),
            Screen::Unlock(state) => f.debug_tuple("Unlock").field(state).finish(),
            Screen::Contacts(state) => f.debug_tuple("Contacts").field(state).finish(),
            Screen::ContactDetail(state) => f.debug_tuple("ContactDetail").field(state).finish(),
            Screen::Chat(state) => f.debug_tuple("Chat").field(state).finish(),
            Screen::Requests(state) => f.debug_tuple("Requests").field(state).finish(),
            Screen::Verify(state) => f.debug_tuple("Verify").field(state).finish(),
            Screen::Settings(state) => f.debug_tuple("Settings").field(state).finish(),
            Screen::Help(state) => f.debug_tuple("Help").field(state).finish(),
            Screen::Palette(state) => f.debug_tuple("Palette").field(state).finish(),
            Screen::Extension(pane) => f.debug_tuple("Extension").field(&pane.title()).finish(),
        }
    }
}

/// Registers this crate's own built-in [`crate::surface::PaletteCommand`]s into `surface` — the same
/// mechanism a future third-party feature would use (`crate::surface::SurfaceRegistry::
/// register_command`), applied here to task 4.25's `Diagnostics` screen and (task 4.36) a real
/// "open Settings" command. `App::new_with_config` is the only caller. Deliberately a free function
/// (not inlined into `App::new_with_config`) so it reads as one clearly-bounded registration step,
/// mirroring how `crate::surface`'s own doc frames registration as the one thing a feature does,
/// never a core edit.
fn register_builtin_commands(
    surface: &mut SurfaceRegistry,
    config: &crate::config::TuiConfig,
    config_path: &std::path::Path,
) {
    surface.register_command(PaletteCommand {
        id: "nav.diagnostics",
        name: "Diagnostics",
        description: "connection/transport/relay-policy diagnostics (wraps `meridian doctor`)",
        // No direct keybinding — tui-client.md §2's screen table names only "palette → Diagnostics"
        // for this screen, no global chord.
        keybinding: None,
        action: PaletteAction::PushPane(Arc::new(|| {
            Box::new(DiagnosticsPane::new()) as Box<dyn ExtensionPane>
        })),
    });

    // Task 4.36: a real, working "open Settings" command — deferred by task 4.25's own scope note
    // on `Screen::Settings`'s doc comment ("registering a working 'open Settings' command would
    // need a real, already-loaded `TuiConfig`/`config_path`... `App` has no live config anywhere
    // yet") — `App::new_with_config` always has one now. `Screen::Settings` is a first-party,
    // built-in screen (not an `ExtensionPane`), so this uses `PaletteAction::PushScreen` (task
    // 4.36's own small additive extension to that enum) rather than `PushPane`.
    let settings_config = config.clone();
    let settings_config_path = config_path.to_path_buf();
    surface.register_command(PaletteCommand {
        id: "nav.settings",
        name: "Settings",
        description: "server URL, relay policy, theme, timestamps, bell, retention (config.toml)",
        keybinding: None,
        action: PaletteAction::PushScreen(Arc::new(move || {
            Screen::Settings(Box::new(SettingsState::new(
                settings_config.clone(),
                settings_config_path.clone(),
            )))
        })),
    });
}

/// Owns all application state. Constructed once by the runtime; `update` and `render` are the only
/// two ways anything reaches or reads it.
#[derive(Debug)]
pub struct App {
    screens: Vec<Screen>,
    should_quit: bool,
    /// The registered [`crate::surface::PaletteCommand`] set this run started with (task 4.25) —
    /// seeded by [`register_builtin_commands`], extended by nothing else yet (no other feature
    /// registers into a live `App` today; see [`App::commands`]'s own doc comment). Read by
    /// [`App::handle_key`]'s global `PaletteRegistry::find_binding` dispatch step and by
    /// [`Screen::Help`]/[`Screen::Palette`]'s own construction (a snapshot taken at push time, not a
    /// live reference — see those screens' module docs).
    surface: SurfaceRegistry,
    /// The `[ui]` degradation inputs (task 4.26) — [`crate::theme::RenderCtx::from_env`] reads real
    /// `NO_COLOR` fresh on every [`App::render`] call, merged with whatever `config` this `App` was
    /// constructed with. Defaults to [`crate::config::TuiConfig::default`] (matching every screen's
    /// pre-existing hardcoded behavior) until a caller uses [`App::new_with_config`] — the same
    /// "Preflight-shaped gap" [`Screen::Unlock`]/[`Screen::Contacts`]/[`Screen::Chat`] already flag
    /// for their own not-yet-live inputs; [`crate::run`] is the one real caller that loads an actual
    /// `config.toml` and passes it through.
    config: crate::config::TuiConfig,
    /// Inbound message requests observed live (task 4.35, [`AppEvent::Inbound`]) while no
    /// `Screen::Requests` was on the stack to show them directly — drained into a fresh
    /// [`Screen::Requests`] the next time one opens (`Ctrl+R`, or the Contacts screen's own `r`),
    /// per this task's own deliverable ("surfaces on next `Ctrl-R`"). Deliberately App-level, not
    /// screen-level: unlike every other queue in this crate, there is no live
    /// `meridian_core::chat::ChatState` handle anywhere in `App` yet to snapshot
    /// `pending_requests()` from on demand (the same gap `Screen::Requests`'s own doc comment
    /// already names) — this buffer is this task's own, narrowly-scoped stand-in for that snapshot,
    /// holding only what actually arrived live during this run, not the full persisted queue.
    pending_inbound_requests: Vec<crate::screens::requests::RequestEntry>,
    /// The persistent inbound connection's own state (task 4.35) — session-wide, so it lives on
    /// `App` itself rather than inside any one `Screen`. See [`AppEvent::ConnectionStatus`].
    connection: ConnectionState,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// A fresh app starts on [`Screen::Onboarding`] unconditionally — **deliberately, still, even
    /// after task 4.37's `Preflight` routing landed.** This constructor performs no I/O (dozens of
    /// existing tests across this crate construct an `App` this way with no `account.json` of their
    /// own to check against — see this crate's own module doc's runtime-structure diagram: `update`/
    /// `render` never perform I/O, and neither does this), so it cannot itself decide whether an
    /// account already exists. [`App::new_with_route`] is the real `Preflight`-aware counterpart —
    /// [`crate::run`] is the one real caller that uses it, having already loaded `account.json` (if
    /// any) synchronously in its own setup phase and turned it into a
    /// [`crate::preflight::InitialRoute`] via [`crate::preflight::preflight_route`].
    ///
    /// Resolves [`crate::theme::RenderCtx`] against [`crate::config::TuiConfig::default`] — see
    /// [`App::new_with_config`] for the real-config counterpart.
    pub fn new() -> Self {
        Self::new_with_config(crate::config::TuiConfig::default())
    }

    /// Same as [`App::new`], but resolves [`crate::theme::RenderCtx`] (task 4.26) against a real,
    /// already-loaded `config.toml` instead of [`crate::config::TuiConfig::default`] — see
    /// [`App::config`]'s own doc comment. Still always starts on [`Screen::Onboarding`] — see
    /// [`App::new`]'s own doc comment for why that stays true even after task 4.37, and
    /// [`App::new_with_route`] for the constructor that doesn't.
    pub fn new_with_config(config: crate::config::TuiConfig) -> Self {
        // Task 4.36: needed to register a real "open Settings" command below. `default_config_path`
        // is pure (`$MERIDIAN_HOME`-relative path-joining, no disk I/O) — same discipline every
        // other call site in this crate already follows for it. Falls back to an empty path on the
        // rare failure to resolve a home directory at all; `Effect::SaveSetting`'s own dispatch is
        // where a genuinely unusable path would surface, not here.
        let config_path = crate::config::default_config_path().unwrap_or_default();
        let mut surface = SurfaceRegistry::new();
        register_builtin_commands(&mut surface, &config, &config_path);
        Self {
            screens: vec![Screen::Onboarding(Box::default())],
            should_quit: false,
            surface,
            config,
            pending_inbound_requests: Vec::new(),
            connection: ConnectionState::Disconnected,
        }
    }

    /// The `Preflight`-aware constructor (task 4.37): same construction as [`App::new_with_config`],
    /// but starts from a [`crate::preflight::InitialRoute`] decision instead of always
    /// [`Screen::Onboarding`] — see [`crate::preflight`]'s own module doc for the full routing
    /// design this implements (`docs/architecture/diagrams/tui-screen-flow.mermaid`'s `Preflight`
    /// step). Returns the initial `Vec<Effect>` the route requires the runtime to dispatch
    /// immediately alongside the constructed `App` (empty for `Onboarding`/`Unlock`; one
    /// `Effect::LoadSession` for the OS-keystore route), mirroring the shape `App::update` itself
    /// returns for every later event.
    ///
    /// [`App::new`]/[`App::new_with_config`] deliberately stay as they were (I/O-free,
    /// unconditionally `Screen::Onboarding`) rather than being redefined in terms of this
    /// constructor — the dozens of existing tests across this crate that build an `App` via those
    /// two and expect `Screen::Onboarding` (with nothing to load a real `InitialRoute` from) keep
    /// working unchanged. [`crate::run`] is the one real caller of this constructor.
    pub fn new_with_route(
        config: crate::config::TuiConfig,
        route: crate::preflight::InitialRoute,
    ) -> (Self, Vec<Effect>) {
        let mut app = Self::new_with_config(config);
        let (screen, effects) = route.into_screen_and_effects();
        *app.screens
            .last_mut()
            .expect("screens invariant: constructor above pushes exactly one") = screen;
        (app, effects)
    }

    /// Whether the runtime should stop the event loop and let the [`crate::terminal::TerminalGuard`]
    /// restore the terminal.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// The registered command set this run started with. `pub` so a test (or, in the future, a
    /// startup routine that wants to confirm what shipped built in) can inspect it without reaching
    /// into `App`'s private fields. **Not** a general "register a command into this running `App`"
    /// seam — no caller outside this module does that today (every command `App` knows about comes
    /// from [`register_builtin_commands`] at construction time); a future task that lets a live
    /// feature extend a running `App`'s registry can add a `&mut` accessor then, when something
    /// actually needs it.
    pub fn commands(&self) -> &crate::surface::PaletteRegistry {
        self.surface.commands()
    }

    /// The screen currently on top of the stack.
    pub fn current_screen(&self) -> &Screen {
        self.screens
            .last()
            .expect("screens invariant: constructor pushes one, pop_screen never empties it")
    }

    /// The persistent inbound connection's current state (task 4.35) — see
    /// [`AppEvent::ConnectionStatus`]. `pub` so a (future) status-bar-carrying screen, or a test, can
    /// read it without reaching into `App`'s private fields, mirroring [`App::commands`]'s own
    /// read-only accessor shape.
    pub fn connection_status(&self) -> ConnectionState {
        self.connection
    }

    /// How many inbound message requests are queued (task 4.35) waiting for the next
    /// `Screen::Requests` to open — see [`App::pending_inbound_requests`]'s own doc comment. `pub`
    /// for the same reason as [`App::connection_status`].
    pub fn pending_inbound_request_count(&self) -> usize {
        self.pending_inbound_requests.len()
    }

    /// Pushes a new screen on top of the stack (overlays render on top without unmounting what's
    /// beneath — tui-client.md §2).
    pub fn push_screen(&mut self, screen: Screen) {
        self.screens.push(screen);
    }

    /// Pops the top screen, unless it is the last one (there is always a root screen to render).
    /// Returns the popped screen, if any.
    pub fn pop_screen(&mut self) -> Option<Screen> {
        if self.screens.len() > 1 {
            self.screens.pop()
        } else {
            None
        }
    }

    /// The one and only state transition function. Synchronous, pure apart from mutating `self` —
    /// no I/O, no `.await`. Returns the [`Effect`]s (if any) the runtime's worker task should
    /// execute as a result of this event.
    pub fn update(&mut self, event: AppEvent) -> Vec<Effect> {
        match event {
            AppEvent::Key(key) => self.handle_key(key),
            AppEvent::Worker(worker_event) => self.handle_worker(*worker_event),
            AppEvent::Inbound(inbound) => self.handle_inbound(*inbound),
            AppEvent::ConnectionStatus(state) => {
                self.connection = state;
                Vec::new()
            }
            AppEvent::Tick | AppEvent::Resize(_, _) | AppEvent::Paste(_) => Vec::new(),
        }
    }

    /// Routes a live [`AppEvent::Inbound`] push (task 4.35) to whichever screen it's relevant to —
    /// see this crate's module doc's runtime-structure diagram and the task's own "Scope" note this
    /// mirrors exactly:
    /// - [`InboundEvent::Message`]: an open [`Screen::Chat`] for that peer appends it live (deduped
    ///   by `mid`, reusing [`chat::insert_deduped`] via [`chat::handle_inbound_message`] unchanged)
    ///   and, only for what was actually inserted, dispatches [`Effect::PersistHistory`] so it
    ///   survives a restart exactly like an outbound send already does
    ///   ([`chat::complete_send`](chat)'s identical shape). **Persisted unconditionally, even when no
    ///   matching `Screen::Chat` is open** — restart-persistent history (tui-client.md's whole point)
    ///   cannot depend on which screen happens to be on top when a message arrives; only the
    ///   *in-memory* dedup-and-append step is screen-gated.
    /// - [`InboundEvent::MessageRequest`]: an open [`Screen::Requests`] gets it appended directly
    ///   (deduped by `sender_ik`, so a resent first envelope for an already-queued sender never
    ///   double-lists); otherwise it joins [`App::pending_inbound_requests`], drained into the next
    ///   `Screen::Requests` that opens (`Ctrl+R`/Contacts' own `r`) — this task's own named
    ///   deliverable.
    /// - [`InboundEvent::Receipt`]: an open `Screen::Chat` for that peer updates the matching `Sent`
    ///   row to `Delivered` in memory; otherwise dropped (out of this task's scope — see
    ///   [`chat::apply_receipt`]'s own doc comment for why there is no disk-persistence effect for an
    ///   in-place delivery-state update today).
    fn handle_inbound(&mut self, event: InboundEvent) -> Vec<Effect> {
        match event {
            InboundEvent::Message { peer_pubkey, entry } => {
                if let Some(Screen::Chat(state)) = self.screens.last_mut() {
                    if state.peer_pubkey == peer_pubkey {
                        return chat::handle_inbound_message(state, entry);
                    }
                }
                vec![Effect::PersistHistory(PersistHistoryEffect {
                    request: PersistHistoryRequest { peer_pubkey, entry },
                    outcome: None,
                })]
            }
            InboundEvent::MessageRequest(entry) => {
                if let Some(Screen::Requests(state)) = self.screens.last_mut() {
                    if !state.entries.iter().any(|e| e.sender_ik == entry.sender_ik) {
                        state.entries.push(entry);
                    }
                } else if !self
                    .pending_inbound_requests
                    .iter()
                    .any(|e| e.sender_ik == entry.sender_ik)
                {
                    self.pending_inbound_requests.push(entry);
                }
                Vec::new()
            }
            InboundEvent::Receipt { peer_pubkey, ack } => {
                if let Some(Screen::Chat(state)) = self.screens.last_mut() {
                    if state.peer_pubkey == peer_pubkey {
                        chat::apply_receipt(state, &ack);
                    }
                }
                Vec::new()
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Vec<Effect> {
        // Global, regardless of screen: Ctrl+Q always quits.
        if key.code == KeyCode::Char('q') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return Vec::new();
        }

        // Global, regardless of screen (tui-client.md §2: "Requests | ... | `^R`, or the Requests
        // section of the contacts pane") — same top-level, unconditional treatment as `Ctrl+Q`
        // above, mirrored here since pushing a screen is never destructive (unlike quitting) so
        // there is no reason to gate it behind whichever screen happens to be current. A no-op if
        // `Screen::Requests` is already on top, so repeated `Ctrl+R` doesn't stack duplicates.
        //
        // **Task 4.35/4.36:** seeded from [`App::requests_snapshot`] — a live
        // `meridian_core::chat::ChatState::pending_requests()` read off whichever `Screen::Main` is
        // on the stack (task 4.36, "as of session load" — see `crate::screens::main`'s own module
        // doc for the precise scoping), plus whatever arrived live and is still queued in
        // [`App::pending_inbound_requests`] (task 4.35). Before a `Screen::Main` exists anywhere on
        // the stack (e.g. still mid-onboarding), this is exactly task 4.35's own original behavior:
        // `pending_inbound_requests` only. A request that arrived in an *earlier run* (before this
        // process started, and before any `Screen::Main` in this run has loaded it) is still not
        // shown here — that gap is unchanged.
        if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if !matches!(self.current_screen(), Screen::Requests(_)) {
                let entries = self.requests_snapshot();
                self.push_screen(Screen::Requests(Box::new(RequestsState::new(entries))));
            }
            return Vec::new();
        }

        // Global, regardless of screen (task 4.25, tui-client.md §3's "Global" row): `F1` opens the
        // generated help overlay. Joins `Ctrl+Q`/`Ctrl+R` above at the same unconditional tier —
        // reachable mid-onboarding, mid-edit, from any sub-mode, exactly like those two already are.
        // Idempotent (a no-op if `Screen::Help` is already on top), same discipline as `Ctrl+R`.
        if key.code == KeyCode::F(1) {
            if !matches!(self.current_screen(), Screen::Help(_)) {
                self.push_screen(Screen::Help(Box::new(HelpState::new(
                    self.surface.commands().clone(),
                ))));
            }
            return Vec::new();
        }

        // Global, regardless of screen: `Ctrl+K` opens the fuzzy command palette. Same tier and
        // idempotency discipline as `F1` above.
        if key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if !matches!(self.current_screen(), Screen::Palette(_)) {
                self.push_screen(Screen::Palette(Box::new(PaletteState::new(
                    self.surface.commands().clone(),
                ))));
            }
            return Vec::new();
        }

        // The addendum's own "real, non-optional scope": any *registered* command's keybinding fires
        // globally, without opening the palette — `crate::surface::PaletteRegistry::find_binding`'s
        // own doc comment names this exact dispatch step as orphaned before this task. Checked last
        // among the global, unconditional checks (after the four fixed chords above, which are never
        // themselves registrable commands) but still strictly before any screen-specific handling
        // below — so a registered global binding always wins over whatever a screen might otherwise
        // do with that same chord, the same precedence `Ctrl+Q`/`Ctrl+R` already have. This is a
        // deliberate, accepted trade (documented, not a bug): a future feature that registers a
        // keybinding is responsible for choosing one that doesn't collide with a screen's own
        // meaningfully-used local keys, exactly the same responsibility `Ctrl+Q`/`Ctrl+R` already
        // implicitly placed on every screen's own key handling before this task. `find_binding`
        // returns `None` for the overwhelming majority of keys — ordinary typing, screen-local
        // navigation — so this never intercepts a key with no matching registration; see
        // `App::dispatch_palette_action`'s own doc comment for what happens once one *does* match, and
        // `#[cfg(test)] mod tests` below (`a_registered_global_binding_intercepts_before_any_screens_
        // own_use_of_the_same_key`) for the ordering pinned end to end.
        if let Some(command) = self.surface.commands().find_binding(&key) {
            let action = command.action.clone();
            return self.dispatch_palette_action(action);
        }

        match self.screens.last_mut() {
            Some(Screen::Onboarding(state)) => {
                // Onboarding owns its own key handling entirely, *including* what Esc means —
                // deliberately not the generic "Esc pops the screen stack" handler below. There is
                // nothing beneath onboarding on a first run (it is always the root screen), so
                // popping it would either no-op (same outcome, misleadingly) or, if it were ever
                // pushed on top of something else, would exit onboarding by fiat rather than by
                // finishing it. Instead each onboarding sub-step decides for itself what Esc means
                // (usually "go back one sub-step to fix an answer"; a no-op at the very first
                // sub-step, ChooseStore, and during an effect that's in flight, since there's
                // nothing to cancel back to synchronously) — see
                // `crate::screens::onboarding::handle_key`.
                let (mut effects, finished) = onboarding::handle_key(state, key);
                if finished {
                    // Task 4.37: Onboarding → Main. Reaching a real `Screen::Main` needs a real
                    // `LiveSession` (task 4.29), which a freshly onboarded account doesn't have in
                    // hand yet — only `onboarding::handle_key`'s own `Success` arm ever returns
                    // `finished = true` (see that function's doc comment), and `state` here is
                    // still that same, untouched `Success` (`onboarding::handle_key`'s `Success`
                    // arm reads `key.code` but never mutates `*state`), so it's safe to read
                    // `Success::store` (task 4.37's own small addition, carried forward from
                    // `PublishingBundle::store`) to decide which effect gets there:
                    // - `StoreChoice::Os`: nothing is sealed on disk yet for this brand-new
                    //   account, so `Effect::LoadSession` reads a trivially empty (but real)
                    //   `LiveSession` straight back — see `crate::session::LiveSession::empty`'s
                    //   own doc comment, which names this exact path. The interim screen is
                    //   `Screen::Placeholder`, same "loading, briefly" role `Preflight`'s own
                    //   OS-keystore route uses (`crate::preflight::InitialRoute::LoadSession`) —
                    //   `App::handle_worker`'s new top-level `Effect::LoadSession` arm (below)
                    //   swaps it for `Screen::Main` once the effect resolves, regardless of which
                    //   of the two dispatched it.
                    // - `StoreChoice::File`: `Effect::LoadSession` deliberately refuses file-backed
                    //   accounts (`LoadSessionOutcome`'s own doc comment) — the single-round-trip
                    //   unwrap `Screen::Unlock` itself uses (`Effect::Unlock`) is the right effect
                    //   here too, reusing the passphrase already typed at `ChooseStore` rather than
                    //   re-prompting for it a second time. The interim screen reuses
                    //   `Screen::Unlock`'s own `Unlocking` sub-state (rather than inventing a new
                    //   "loading" screen) so `App::handle_worker`'s `Screen::Unlock` arm — already
                    //   updated by this same task to reclaim a `SessionOutcome` into `Screen::Main`
                    //   — is the one and only place that logic lives.
                    let OnboardingState::Success(success) = state.as_ref() else {
                        // Defensive: unreachable per `onboarding::handle_key`'s own contract (see
                        // above), but falls back to the pre-4.37 `Screen::Placeholder` stand-in
                        // rather than panicking on an invariant this module doesn't itself own.
                        *self
                            .screens
                            .last_mut()
                            .expect("screens invariant: never empty") = Screen::Placeholder;
                        return effects;
                    };
                    let (screen, initial_effects) = match &success.store {
                        StoreChoice::Os => (
                            Screen::Placeholder,
                            vec![Effect::LoadSession(LoadSessionEffect {
                                request: LoadSessionRequest,
                                outcome: None,
                            })],
                        ),
                        StoreChoice::File { passphrase } => {
                            // Same fallback discipline as `crate::preflight::preflight_route`'s own
                            // `keyfile` handling: `default_keyfile_path` only fails to resolve
                            // `$MERIDIAN_HOME` at all, which `Effect::Unlock`'s own worker-side
                            // execution would surface as an actionable error, not here.
                            let keyfile = crate::worker::default_keyfile_path().unwrap_or_default();
                            let request = UnlockRequest {
                                keyfile,
                                passphrase: passphrase.clone(),
                            };
                            let effect = Effect::Unlock(Box::new(UnlockEffect {
                                request: request.clone(),
                                outcome: SessionOutcome::empty(),
                            }));
                            let screen =
                                Screen::Unlock(Box::new(UnlockState::Unlocking(Unlocking {
                                    id: success.id.clone(),
                                    attempts: 0,
                                    request,
                                })));
                            (screen, vec![effect])
                        }
                    };
                    *self
                        .screens
                        .last_mut()
                        .expect("screens invariant: never empty") = screen;
                    effects.extend(initial_effects);
                }
                effects
            }
            Some(Screen::Unlock(state)) => {
                // Same rationale as the `Onboarding` arm above: `Unlock` owns its own key handling,
                // including Esc (a no-op — `Unlock` has nothing beneath it either, and the mermaid
                // diagram gives it no "back" transition, only retry-in-place or global quit via
                // Ctrl+Q) — see `crate::screens::unlock::handle_key`.
                //
                // `finished` is always `false` here in practice — `unlock::handle_key` only ever
                // signals completion from `handle_worker` (a submitted passphrase moves to
                // `Unlocking` and dispatches `Effect::Unlock`; the *worker's* response is what
                // decides success/failure, not this key handler) — see `App::handle_worker`'s own
                // `Screen::Unlock` arm for the real `Screen::Main` transition (task 4.37). Kept
                // here, unreachable, only for symmetry with the `Onboarding` arm above and in case a
                // future change to `unlock::handle_key` ever does signal completion synchronously.
                let (effects, finished) = unlock::handle_key(state, key);
                if finished {
                    *self
                        .screens
                        .last_mut()
                        .expect("screens invariant: never empty") = Screen::Placeholder;
                }
                effects
            }
            Some(Screen::Contacts(state)) => {
                // Same rationale as `Onboarding`/`Unlock`: the contacts pane owns its own key
                // handling, including what `Esc` means at each of its own sub-modes (cancel out of
                // the add-contact form or the filter box back to plain list navigation) — see
                // `crate::screens::contacts::handle_key`. `Some(entry)` means "open contact detail
                // for this entry", the one piece of stack navigation the screen itself can't do
                // (it has no reach into `self.screens`).
                let (effects, action) = contacts::handle_key(state, key);
                match action {
                    contacts::ContactsAction::OpenDetail(entry) => {
                        self.push_screen(Screen::ContactDetail(Box::new(ContactDetailState::new(
                            entry,
                        ))));
                    }
                    contacts::ContactsAction::Pop => {
                        self.pop_screen();
                    }
                    // Same pending-inbound-requests seeding as the global `Ctrl+R` handler above —
                    // see that handler's own doc comment (task 4.35).
                    contacts::ContactsAction::OpenRequests => {
                        let entries = std::mem::take(&mut self.pending_inbound_requests);
                        self.push_screen(Screen::Requests(Box::new(RequestsState::new(entries))));
                    }
                    // Task 4.36: `Screen::Contacts`, pushed standalone (no backing `LiveSession` —
                    // see `crate::screens::main`'s own doc), has no live `TrustStore`/history to
                    // build a real `Screen::Chat`/`Screen::Verify` from; only `Screen::Main` (which
                    // owns one) can — see `crate::screens::main::handle_key`. A no-op here.
                    contacts::ContactsAction::OpenChat(_)
                    | contacts::ContactsAction::OpenVerify(_) => {}
                    contacts::ContactsAction::None => {}
                }
                effects
            }
            Some(Screen::Main(state)) => {
                // `crate::screens::main::handle_key` embeds this screen's own contacts pane and
                // returns fully-built child screens wherever building one needs live
                // `trust`/`account` data this screen owns — see that module's own doc.
                let (effects, action) = main::handle_key(state, key);
                match action {
                    MainAction::None => {}
                    MainAction::Pop => {
                        self.pop_screen();
                    }
                    MainAction::OpenContactDetail(entry) => {
                        self.push_screen(Screen::ContactDetail(Box::new(ContactDetailState::new(
                            entry,
                        ))));
                    }
                    MainAction::OpenChat(chat_state) => {
                        self.push_screen(Screen::Chat(chat_state));
                    }
                    MainAction::OpenVerify(verify_state) => {
                        self.push_screen(Screen::Verify(verify_state));
                    }
                    MainAction::OpenRequests => {
                        let entries = self.requests_snapshot();
                        self.push_screen(Screen::Requests(Box::new(RequestsState::new(entries))));
                    }
                }
                effects
            }
            Some(Screen::ContactDetail(state)) => {
                // Unlike `Onboarding`/`Unlock`, `ContactDetail` is never the root screen (it is
                // always pushed on top of `Contacts` — see its own doc comment), so `Esc` at its
                // outermost `View` mode really does mean "pop back to Contacts", same as the
                // generic catch-all arm below — `contact_detail::handle_key` reports that via
                // `exit`. `Esc` inside a nested sub-mode (editing the petname, confirming a
                // block/delete) instead cancels back to `View` without leaving the screen —
                // `contact_detail::handle_key` owns that distinction internally, mirroring
                // onboarding's per-sub-step Esc handling.
                let (effects, exit) = contact_detail::handle_key(state, key);
                if exit {
                    if let Some(Screen::ContactDetail(popped)) = self.pop_screen() {
                        self.apply_contact_update(*popped);
                    }
                }
                effects
            }
            Some(Screen::Chat(state)) => {
                // `chat::handle_key` owns its own nested-mode `Esc` (cancelling an in-flight
                // key-change acknowledgment prompt back to normal composing, never leaving the
                // screen) exactly like `ContactDetail`'s sub-modes — see that module's doc. Only
                // the outermost `Esc` asks to pop — and (task 4.36) reconciles the `TrustStore` this
                // screen was given back into whichever `Screen::Main` it came from, refreshing that
                // one contact's own display row at the same time — see `App::reclaim_trust`'s own
                // doc comment.
                let (effects, exit) = chat::handle_key(state, key);
                if exit {
                    if let Some(Screen::Chat(popped)) = self.pop_screen() {
                        self.reclaim_trust(popped.peer_pubkey, popped.trust);
                    }
                }
                effects
            }
            Some(Screen::Requests(state)) => {
                // `requests::handle_key` owns its own nested-mode `Esc` (cancelling an in-flight
                // accept/reject confirmation back to `RequestsMode::List`, never leaving the
                // screen) exactly like `ContactDetail`'s/`Chat`'s sub-modes — see that module's
                // doc. Only the outermost `Esc` asks to pop.
                let (effects, exit) = requests::handle_key(state, key);
                if exit {
                    self.pop_screen();
                }
                effects
            }
            Some(Screen::Verify(state)) => {
                // `verify::handle_key` owns its own nested-mode `Esc` (cancelling an in-flight
                // verify/block/acknowledge confirmation back to `VerifyMode::View`, never leaving
                // the screen) exactly like `Chat`'s/`Requests`'s own sub-modes — see that module's
                // doc. Only the outermost `Esc` asks to pop; popping never touches `state.trust`, so
                // leaving this screen can never be mistaken for resolving a key-change block/warning
                // — the send gate this screen exists to resolve is computed fresh from `TrustStore`
                // wherever it's consulted (chat.rs's composer, this screen's own `gate()`), never
                // cached. (Task 4.36): on exit, reconciles the `TrustStore` this screen was given
                // back into whichever `Screen::Main` it came from — see `App::reclaim_trust`'s own
                // doc comment; a mark-verified/block/acknowledge here is exactly the kind of
                // mutation that must not leave the contacts list showing a stale trust glyph.
                let (effects, exit) = verify::handle_key(state, key);
                if exit {
                    if let Some(Screen::Verify(popped)) = self.pop_screen() {
                        self.reclaim_trust(popped.peer_pubkey, popped.trust);
                    }
                }
                effects
            }
            Some(Screen::Settings(state)) => {
                // `settings::handle_key` owns its own nested-mode `Esc` (cancelling an in-flight
                // text edit back to `SettingsMode::List`, never leaving the screen) exactly like
                // `Verify`'s/`Requests`'s own sub-modes — see that module's doc. Only the outermost
                // `Esc` asks to pop.
                let (effects, exit) = settings::handle_key(state, key);
                if exit {
                    self.pop_screen();
                }
                effects
            }
            Some(Screen::Help(state)) => {
                // `help::handle_key` has nothing to do beyond `Esc` — see that module's doc.
                let (effects, exit) = help::handle_key(state, key);
                if exit {
                    self.pop_screen();
                }
                effects
            }
            Some(Screen::Palette(state)) => {
                // `palette::handle_key` never dispatches anything itself — it reports what to do via
                // `PaletteOutcome` (see that module's own doc for why: it has no `push_screen`
                // access). Selecting a command always closes the palette, whether or not the action
                // it names was actually a screen push.
                let (effects, outcome) = palette::handle_key(state, key);
                match outcome {
                    PaletteOutcome::Close => {
                        self.pop_screen();
                        effects
                    }
                    PaletteOutcome::Run(action) => {
                        self.pop_screen();
                        let mut dispatched = self.dispatch_palette_action(action);
                        dispatched.extend(effects);
                        dispatched
                    }
                    PaletteOutcome::None => effects,
                }
            }
            Some(Screen::Extension(pane)) => {
                // `Esc` always means "back" (tui-client.md §3) and is handled generically here,
                // exactly like the catch-all arm below — an extension pane never sees an `Esc`
                // key event and therefore never needs to special-case it (see
                // `crate::surface::ExtensionPane::handle_key`'s doc comment). Every other key
                // routes to the pane.
                if key.code == KeyCode::Esc {
                    self.pop_screen();
                    Vec::new()
                } else {
                    pane.handle_key(key)
                }
            }
            _ => {
                if key.code == KeyCode::Esc {
                    self.pop_screen();
                }
                Vec::new()
            }
        }
    }

    /// Turns a selected/triggered [`PaletteAction`] into what `App` actually does — the one place
    /// that runs a [`PaletteAction`], shared by [`App::handle_key`]'s global `find_binding` dispatch
    /// step and the `Screen::Palette` arm's own `PaletteOutcome::Run` handling above, so the two
    /// dispatch paths (fire a binding directly vs. select it from the palette UI) can never diverge in
    /// what triggering a given command actually does.
    ///
    /// **Review fix (task 4.25, Finding 1): `PushPane` is idempotent, same discipline as the `F1`/
    /// `Ctrl+K`/`Ctrl+R` checks in [`App::handle_key`] above.** Without a guard, repeatedly dispatching
    /// the same palette command (e.g. `Ctrl+K` → `Enter` on `nav.diagnostics` fired several times with
    /// no `Esc` in between — reachable through ordinary use: re-opening the palette and re-selecting
    /// the same entry, or a terminal's key-repeat firing several `Enter`s) would push a fresh
    /// `Screen::Extension` on top every single time, stacking unboundedly (`pop_screen`/`push_screen`
    /// have no depth limit) and forcing the user to `Esc` once per accumulated layer to get back to the
    /// root. [`ExtensionPane`] carries no factory/command identity to compare against (unlike
    /// `Screen::Help`/`Screen::Palette`, which are distinguished by `Screen` variant alone), so this
    /// builds the candidate pane first and compares its [`ExtensionPane::title`] against the topmost
    /// screen's, mirroring the other three checks' "already on this exact screen" test as closely as
    /// this trait's surface allows — the guard is therefore keyed on pane identity (title), not on
    /// which registered command produced it, so two distinct commands that happened to build
    /// same-titled panes would also be treated as "the same pane"; no built-in command collides on
    /// title today.
    fn dispatch_palette_action(&mut self, action: PaletteAction) -> Vec<Effect> {
        match action {
            PaletteAction::Effect(factory) => vec![factory()],
            PaletteAction::PushPane(factory) => {
                let pane = factory();
                let already_open = matches!(
                    self.current_screen(),
                    Screen::Extension(current) if current.title() == pane.title()
                );
                if !already_open {
                    self.push_screen(Screen::Extension(pane));
                }
                Vec::new()
            }
            // Task 4.36: the `Screen::Settings` counterpart to `PushPane` above, for first-party
            // built-in screens rather than `ExtensionPane`s — see `PaletteAction::PushScreen`'s own
            // doc comment. Idempotent the same way: `std::mem::discriminant` compares the built
            // screen's *variant* against the current top's, which works for any `Screen` (unlike a
            // title-based check) without requiring `Screen: PartialEq` (it deliberately isn't — see
            // that type's own doc comment).
            PaletteAction::PushScreen(factory) => {
                let screen = factory();
                let already_open = std::mem::discriminant(self.current_screen())
                    == std::mem::discriminant(&screen);
                if !already_open {
                    self.push_screen(screen);
                }
                Vec::new()
            }
        }
    }

    fn handle_worker(&mut self, event: WorkerEvent) -> Vec<Effect> {
        // Task 4.37: `Effect::LoadSession` is handled here, ahead of any per-screen dispatch below
        // — unlike every other effect in this file, no *screen* owns it the way Onboarding owns
        // `GenerateAccount` or Unlock owns `Effect::Unlock`. It is dispatched from two different
        // places that don't share a screen (`crate::preflight::InitialRoute::LoadSession`, at
        // startup, before any screen has been interacted with; and `App::handle_key`'s
        // Onboarding-finished arm, for a freshly onboarded OS-keystore account), and both leave
        // `Screen::Placeholder` on top as the "loading, briefly" interim screen while it's in
        // flight — so matching on the *event* first, regardless of what's on top of the stack, is
        // the one dispatch point that covers both origins without duplicating this logic.
        let event = match event {
            WorkerEvent::Completed(Effect::LoadSession(effect)) => {
                return self.apply_load_session_outcome(effect.outcome);
            }
            // A `LoadSession` failure at this point means something genuinely went wrong reading
            // an OS-keystore account's own `trust.bin`/`sessions.bin`/`contacts.json` (corrupt
            // data, an OS keystore that became unavailable between `Preflight`'s own synchronous
            // check and this async read, …) — `docs/architecture/tui-client.md §7`'s own table has
            // no row for this exact condition, and falling back to `Screen::Onboarding` here would
            // be actively wrong (risking a second identity being generated over an account whose
            // data merely failed to *load*, not one that doesn't exist). `TODO: confirm`: no design
            // doc read for this task resolves what should happen instead (a dedicated error screen
            // is new screen content, out of this task's own "routing, not screen content" scope —
            // see the task file's own Scope note); left on `Screen::Placeholder`, visible via no
            // more feedback than today's own pre-4.37 "stuck on Generating" gap, with `Ctrl+Q`
            // still reachable to quit cleanly. Not silently absorbed: flagged here, and in this
            // task's own Status write-up, for a follow-up to resolve deliberately rather than by
            // omission.
            WorkerEvent::Failed(Effect::LoadSession(_), _) => return Vec::new(),
            // Task 4.42 (piece C): a completed `Effect::AcceptRequest` is reconciled into whichever
            // `Screen::Main` is on the stack *before* the per-screen dispatch below hands the same
            // event to `Screen::Requests` (which owns only its own queue) — matched on the event
            // first, regardless of what is on top, for the same reason `Effect::LoadSession` above
            // is: no single screen owns this consequence. The event is then handed on unchanged, so
            // `requests::handle_worker`'s own `Deciding` → `List` transition is untouched.
            WorkerEvent::Completed(Effect::AcceptRequest(effect)) => {
                if let Some(added) = effect.outcome.clone() {
                    self.apply_accepted_request(added);
                }
                WorkerEvent::Completed(Effect::AcceptRequest(effect))
            }
            // Task 4.46: a completed `Effect::AddContact` is reconciled into whichever
            // `Screen::Main` is on the stack *before* the per-screen dispatch below hands the
            // same event to whatever screen actually sits on top — matched on the event first,
            // regardless of what is on top, for the same "no single screen owns this
            // consequence" reason `AcceptRequest`/`RejectRequest`/`LoadHistory` already are (4.45's
            // own root-cause trace named the missing version of exactly this arm as the fourth
            // defect T17's exit gate found). The event is still handed on unchanged, so
            // `contacts::handle_worker`'s own `Adding` → close-the-form transition (reached via
            // `main::handle_worker`, only when `Screen::Main` happens to still be on top) runs
            // exactly as before; see `App::apply_added_contact`'s own doc comment for why this
            // arm's job is broader than that per-screen path alone.
            WorkerEvent::Completed(Effect::AddContact(effect)) => {
                if let Some(added) = effect.outcome.clone() {
                    self.apply_added_contact(added);
                }
                WorkerEvent::Completed(Effect::AddContact(effect))
            }
            // Task 4.42 review fix (Finding 3): mirrors the `AcceptRequest` arm immediately above —
            // matched on the event first, regardless of what is on top, for the same reason. Only on
            // a genuine success (`outcome: Some(())`); a `Failed`/retry-exhausted reject leaves
            // nothing to replay.
            WorkerEvent::Completed(Effect::RejectRequest(effect)) => {
                if effect.outcome.is_some() {
                    self.apply_rejected_request(effect.request.sender_ik);
                }
                WorkerEvent::Completed(Effect::RejectRequest(effect))
            }
            // Task 4.44: a completed `Effect::LoadHistory` is merged into whichever `Screen::Chat`
            // matches its peer — matched on the event first, regardless of what is on top (`Ctrl-R`
            // can push `Screen::Requests` on top of an already-open `Screen::Chat` while this is
            // still in flight, exactly the scenario `App::apply_accepted_request`'s own doc comment
            // already documents for the identical "no single screen owns this" reasoning), by
            // [`App::apply_loaded_history`]. A no-op if no matching `Screen::Chat` exists any more
            // (e.g. `Esc` already popped it) — the next `OpenChat` dispatches its own fresh
            // `Effect::LoadHistory`, so nothing already-persisted is ever lost, only briefly not
            // shown.
            WorkerEvent::Completed(Effect::LoadHistory(effect)) => {
                if let Some(loaded) = effect.outcome.clone() {
                    self.apply_loaded_history(effect.request.peer_pubkey, loaded);
                }
                WorkerEvent::Completed(Effect::LoadHistory(effect))
            }
            // A failed load leaves `Screen::Chat` exactly as it was (still empty, or whatever a live
            // inbound has already appended in the meantime) rather than losing anything already
            // shown — surfaced as a notice on the matching `Screen::Chat`, if one is still open,
            // mirroring `crate::screens::chat::handle_worker`'s own `Effect::PersistHistory` failure
            // notice.
            WorkerEvent::Failed(Effect::LoadHistory(effect), message) => {
                self.note_history_load_failure(effect.request.peer_pubkey, &message);
                WorkerEvent::Failed(Effect::LoadHistory(effect), message)
            }
            other => other,
        };
        match self.screens.last_mut() {
            Some(Screen::Onboarding(state)) => onboarding::handle_worker(state, event),
            Some(Screen::Extension(pane)) => pane.handle_worker(event),
            Some(Screen::Help(state)) => help::handle_worker(state, event),
            Some(Screen::Palette(state)) => palette::handle_worker(state, event),
            Some(Screen::Unlock(_)) => {
                // Task 4.37 (resolves task 4.29's own doc note, Finding 3 — see
                // `crate::session::LiveSession`'s module doc's "Known gap" paragraph for the
                // pre-4.37 shape of this note): a successful `Effect::Unlock` now has its
                // `SessionOutcome`/`LiveSession` reclaimed *before* falling through to
                // `unlock::handle_worker`, which — for `Completed` — did nothing but signal
                // "finished" with no further per-screen state to update; building `Screen::Main`
                // directly here, rather than delegating and then swapping to a stand-in, is that
                // reclaim point. `Failed`/irrelevant events still delegate to
                // `unlock::handle_worker` unchanged (retry-in-place, attempt count, no lockout —
                // `docs/architecture/tui-client.md §7`).
                if let WorkerEvent::Completed(Effect::Unlock(effect)) = event {
                    let UnlockEffect { outcome, .. } = *effect;
                    let screen = match outcome.into_option() {
                        Some(session) => Screen::Main(Box::new(MainState::from_session(session))),
                        // Defensive: a real worker-produced `Effect::Unlock` always populates
                        // `SessionOutcome::ready` on `Completed` (`worker::handle_unlock`'s own
                        // doc comment) — never reachable there. Reachable only from a
                        // hand-constructed test `WorkerEvent` (mirroring pre-4.37 tests that
                        // exercised this arm with `SessionOutcome::empty()`) that simulates a
                        // worker without actually running one; falls back to `Screen::Placeholder`
                        // rather than building a `Screen::Main` from nothing.
                        None => Screen::Placeholder,
                    };
                    *self
                        .screens
                        .last_mut()
                        .expect("screens invariant: never empty") = screen;
                    return Vec::new();
                }
                let Some(Screen::Unlock(state)) = self.screens.last_mut() else {
                    return Vec::new();
                };
                let (effects, finished) = unlock::handle_worker(state, event);
                if finished {
                    // Unreachable today (see above — `Completed(Effect::Unlock(_))` is fully
                    // handled above and is the only case `unlock::handle_worker` ever reports
                    // `finished = true` for), kept only for symmetry/defense-in-depth against a
                    // future change to that function's own contract.
                    *self
                        .screens
                        .last_mut()
                        .expect("screens invariant: never empty") = Screen::Placeholder;
                }
                effects
            }
            Some(Screen::Contacts(state)) => {
                // `contacts::handle_worker` (Finding 1's guard, QR-import side) can ask to open
                // Contact detail for an already-known entry — same push `handle_key`'s `Contacts`
                // arm does for `ContactsAction::OpenDetail`, just reachable from a worker event
                // instead of a key event.
                let (effects, action) = contacts::handle_worker(state, event);
                if let contacts::ContactsAction::OpenDetail(entry) = action {
                    self.push_screen(Screen::ContactDetail(Box::new(ContactDetailState::new(
                        entry,
                    ))));
                }
                effects
            }
            Some(Screen::ContactDetail(state)) => {
                let (effects, exit) = contact_detail::handle_worker(state, event);
                if exit {
                    if let Some(Screen::ContactDetail(popped)) = self.pop_screen() {
                        self.apply_contact_update(*popped);
                    }
                }
                effects
            }
            Some(Screen::Chat(state)) => chat::handle_worker(state, event),
            Some(Screen::Requests(state)) => requests::handle_worker(state, event),
            Some(Screen::Verify(state)) => verify::handle_worker(state, event),
            Some(Screen::Settings(state)) => settings::handle_worker(state, event),
            Some(Screen::Main(state)) => {
                // Same shape as the `Screen::Contacts` arm above, one level up — see
                // `crate::screens::main::handle_worker`'s own doc comment.
                let (effects, action) = main::handle_worker(state, event);
                if let MainAction::OpenContactDetail(entry) = action {
                    self.push_screen(Screen::ContactDetail(Box::new(ContactDetailState::new(
                        entry,
                    ))));
                }
                effects
            }
            _ => Vec::new(),
        }
    }

    /// Applies a completed `Effect::LoadSession`'s outcome (task 4.37) — see
    /// `App::handle_worker`'s own top-level `Effect::LoadSession` arm for why this isn't inlined
    /// there (kept as its own method for the same "one clearly-bounded step" reason
    /// `register_builtin_commands` is a free function rather than inlined into
    /// `App::new_with_config`).
    ///
    /// Scoped to fire only while `Screen::Placeholder` is genuinely still on top — both current
    /// dispatch sites leave it there as the "loading, briefly" interim screen while this effect is
    /// in flight (see `handle_worker`'s own doc comment above). Today this guard is unreachable
    /// (nothing else can be on top when this fires), but it's cheap insurance against a future
    /// second dispatch site (e.g. a "reload session" command) firing while the user has since
    /// navigated elsewhere — without it, a late completion would silently clobber whatever screen
    /// they're actually on, discarding their navigation state.
    fn apply_load_session_outcome(&mut self, outcome: Option<LoadSessionOutcome>) -> Vec<Effect> {
        if !matches!(self.screens.last(), Some(Screen::Placeholder)) {
            return Vec::new();
        }
        let screen = match outcome {
            Some(LoadSessionOutcome::Loaded(boxed)) => match (*boxed).into_option() {
                Some(session) => Screen::Main(Box::new(MainState::from_session(session))),
                // Defensive: a real worker-produced `Loaded` always carries a populated
                // `SessionOutcome::ready` (`worker::run_load_session`'s own doc comment) — never
                // reachable there; only from a hand-constructed test event.
                None => Screen::Placeholder,
            },
            // `NoAccount` should not be reachable here in a real run — this effect is only ever
            // dispatched (`crate::preflight::InitialRoute::LoadSession`, or
            // `App::handle_key`'s Onboarding-finished arm) after already confirming an
            // OS-keystore `account.json` exists. Defensive: falls back to `Screen::Onboarding`
            // rather than leaving the loading placeholder stuck forever if it somehow is (e.g. the
            // file was deleted between that synchronous check and this async worker round trip) —
            // a pristine, never-onboarded `$MERIDIAN_HOME` is exactly what `Screen::Onboarding` is
            // for.
            Some(LoadSessionOutcome::NoAccount) | None => Screen::Onboarding(Box::default()),
        };
        *self
            .screens
            .last_mut()
            .expect("screens invariant: never empty") = screen;
        Vec::new()
    }

    /// Reconciles a popped [`Screen::ContactDetail`]'s final state back into whichever
    /// [`Screen::Contacts`]/[`Screen::Main`] screen is now on top of the stack —
    /// `ContactDetail` is always pushed on top of one of the two (see [`Screen::ContactDetail`]'s
    /// doc), so this is always safe to attempt; it is simply a no-op if the new top is neither
    /// (defensive, not expected to be reachable in this crate today). `ContactsState.entries` (this
    /// screen's own, or the one `Screen::Main` embeds — task 4.36) is the single source of truth
    /// the list renders from; `ContactDetailState` only ever edits its own copy, so this is the one
    /// place those edits (or a delete) land back in the list the user returns to.
    fn apply_contact_update(&mut self, popped: ContactDetailState) {
        match self.screens.last_mut() {
            Some(Screen::Contacts(contacts)) => {
                contacts::apply_update(contacts, popped.entry, popped.deleted);
            }
            Some(Screen::Main(main)) => {
                contacts::apply_update(&mut main.contacts, popped.entry, popped.deleted);
            }
            _ => {}
        }
    }

    /// Reclaims a [`TrustStore`] moved out of a [`Screen::Main`] into a [`Screen::Chat`]/
    /// [`Screen::Verify`] push (task 4.36 — see `crate::screens::main`'s own doc for why those two
    /// screens must own a real `TrustStore` rather than borrow one) back into whichever
    /// `Screen::Main` is still on the stack once that child screen pops, and refreshes that one
    /// contact's own [`crate::screens::contacts::ContactEntry`] row in `Screen::Main`'s embedded
    /// contacts list at the same time (via [`main::refresh_entry`]) — otherwise, e.g., a
    /// mark-verified in `Screen::Verify` would leave that list showing a stale trust glyph until a
    /// future full reload. Mirrors `apps/tui/tests/at_rest_audit.rs`'s own manual "Reclaim the
    /// (unmutated by chat) TrustStore back out of the popped Chat screen" idiom, generalized and
    /// made automatic here. A no-op — the `TrustStore` is simply dropped — if no `Screen::Main`
    /// exists anywhere on the stack (e.g. this `Chat`/`Verify` was pushed directly in a test with no
    /// backing `LiveSession` to give it back to), same as before this task.
    fn reclaim_trust(&mut self, peer_pubkey: [u8; 32], trust: TrustStore) {
        for screen in &mut self.screens {
            if let Screen::Main(main) = screen {
                main.trust = trust;
                if let Some(contact) = main.trust.contact(&peer_pubkey) {
                    let refreshed = main::refresh_entry(contact, &main.contacts.entries);
                    contacts::apply_update(&mut main.contacts, refreshed, false);
                }
                return;
            }
        }
    }

    /// Replays a completed [`Effect::AcceptRequest`]'s persisted mutations into whichever
    /// [`Screen::Main`] is on the stack (task 4.42, piece C) — the in-memory half of the fix for
    /// task 4.41's Defect C.
    ///
    /// `worker::run_accept_request` has, by the time this runs, already TOFU-pinned the sender in
    /// the real `trust.bin` and written its `contacts.json` display row. But `MainState` owns the
    /// only live `TrustStore`/`ChatState`/contacts list this process has, built once by
    /// [`MainState::from_session`] at session load, and **nothing re-reads either file
    /// mid-session** — so without this, the accepted sender would only appear after a restart,
    /// reproducing the very symptom Defect C describes one restart later. All three steps replay
    /// state that is *already durable*; none of them decides anything:
    /// 1. `trust.observe(pubkey, "", added.added_at)` — the same call, with the same empty hint and
    ///    the **worker-supplied** timestamp (never `SystemTime::now()`: `App::update` and
    ///    `crate::screens` stay clock-free, mirroring `TrustStore::observe`'s own "time is
    ///    injected, not read" discipline). Without this, `v` → `Screen::Verify` → `mark_verified`
    ///    would fail `TrustError::UnknownContact` against a store that has never heard of the
    ///    sender. It produces exactly a TOFU pin — never `Verified`, never any softer gate; the
    ///    row's rendered trust state is read straight off this `TrustStore` afterwards.
    /// 2. [`contacts::apply_update`] with [`ContactEntry::from_added`] — pushes the display row when
    ///    absent (the accepted-sender case) and replaces it in place when present, so
    ///    `Screen::Main`'s embedded contacts list matches the `contacts.json` the worker just wrote.
    /// 3. `chat.accept_request(&pubkey)` — **in-memory only**, and never saved back from here (the
    ///    worker already resealed `sessions.bin`; this copy is never written to disk by `App`, so
    ///    there is no clobber risk). Without it, a request that was restored from `sessions.bin` at
    ///    session load stays in `MainState::chat`'s `pending_requests()` forever and re-appears on
    ///    the next `r`/`Ctrl-R`, because [`App::requests_snapshot`] rebuilds that list from this
    ///    exact in-memory copy.
    ///
    /// Uses the same stack walk as [`App::reclaim_trust`] to find `Screen::Main` (anywhere on the
    /// stack, not just on top — the accept always completes while `Screen::Requests` sits above it),
    /// and is likewise a no-op when there is no `Screen::Main` at all (a `Screen::Requests` pushed
    /// standalone in a test, with no backing session to reconcile into).
    ///
    /// **`Ctrl-R` is a global binding, reachable with a `Screen::Chat`/`Screen::Verify` already open
    /// on top of `Screen::Main`** (open Chat with A, `Ctrl-R` pushes `Screen::Requests` on top of
    /// that, accept a request from B): `MainState::trust` is `std::mem::take`n by whichever of those
    /// two screens is open (see `crate::screens::main`'s "moved, not borrowed" doc), leaving a
    /// placeholder `TrustStore::default()` behind on the `Main` frame itself — an `observe` call
    /// against *that* placeholder would be silently discarded when [`App::reclaim_trust`] later
    /// overwrites `main.trust` wholesale with the popped screen's own (unrelated) store. So the
    /// `trust.observe` step below is routed to wherever the live store for this `Screen::Main`
    /// actually is: the first `Screen::Chat`/`Screen::Verify` frame **above** it on the stack, if one
    /// exists (there is at most one at a time — the whole point of "moved, not cloned"), else
    /// `Screen::Main` itself. `main.chat`/`main.contacts` are never moved by that same `mem::take`
    /// (only `trust` is — see `crate::screens::main`'s "moved" doc again), so those two steps always
    /// land on the `Screen::Main` frame directly, regardless of what else is stacked above it.
    fn apply_accepted_request(&mut self, added: AddedContact) {
        let Some(main_idx) = self
            .screens
            .iter()
            .position(|s| matches!(s, Screen::Main(_)))
        else {
            return;
        };
        let live_trust_idx = self.screens[main_idx + 1..]
            .iter()
            .position(|s| matches!(s, Screen::Chat(_) | Screen::Verify(_)))
            .map(|offset| main_idx + 1 + offset);
        match live_trust_idx {
            Some(idx) => match &mut self.screens[idx] {
                Screen::Chat(chat) => {
                    chat.trust.observe(added.pubkey, "", added.added_at);
                }
                Screen::Verify(verify) => {
                    verify.trust.observe(added.pubkey, "", added.added_at);
                }
                _ => unreachable!("live_trust_idx only ever points at Chat|Verify"),
            },
            None => {
                let Some(Screen::Main(main)) = self.screens.get_mut(main_idx) else {
                    return;
                };
                main.trust.observe(added.pubkey, "", added.added_at);
            }
        }
        let Some(Screen::Main(main)) = self.screens.get_mut(main_idx) else {
            return;
        };
        main.chat.accept_request(&added.pubkey);
        contacts::apply_update(&mut main.contacts, ContactEntry::from_added(added), false);
    }

    /// Reconciles a completed [`Effect::AddContact`] into the live in-memory `TrustStore` (task
    /// 4.46 — the fourth defect 4.45's own T17 exit-gate attempt found: an initiator who adds a
    /// contact via the plain `n`-add flow could send them a first-contact message and still get
    /// `TrustError::UnknownContact` pressing `v`→`v`→`y`, because the completion never synced into
    /// `MainState::trust`). `worker::run_add_contact` has, by the time this runs, already
    /// TOFU-pinned the peer in the real `trust.bin` (and, if a petname was given, called
    /// `set_petname`) and written its `contacts.json` display row — same "replay durable state,
    /// decide nothing" character as [`App::apply_accepted_request`], whose exact `live_trust_idx`
    /// stack walk this reuses verbatim in structure (see that method's own doc comment for the
    /// full "moved, not cloned" reasoning; not re-derived here): locate `Screen::Main`, then scan
    /// above it for a `Screen::Chat`/`Screen::Verify` frame — if one exists, `MainState::trust` was
    /// `std::mem::take`n into it, so `trust.observe(added.pubkey, "", added.added_at)` routes there
    /// instead of the placeholder left on `Main`; else it routes to `Screen::Main` directly.
    ///
    /// This planning pass traced that `Screen::Chat`/`Screen::Verify` cannot actually be pushed on
    /// top of `Screen::Main` while an `Effect::AddContact` is in flight today (unlike the accepted-
    /// request case, the add-contact sub-flow is embedded in `Screen::Main` itself, not a
    /// separately pushed screen, so there is no navigation path that opens Chat/Verify while it is
    /// running) — the stack walk is reused anyway, deliberately not hand-optimized to a bare
    /// `Screen::Main`-only lookup, because reusing the general mechanism is cheap and forecloses a
    /// future navigation feature silently reintroducing this exact defect class a third time
    /// (`apply_accepted_request`'s own "not reachable today" claim already turned out false once,
    /// under 4.42's own review).
    ///
    /// **A second, closely related interleaving gap** (traced during 4.46's planning pass, fixed
    /// here rather than deferred): `Effect::AddContact` is dispatched from `Screen::Main`'s own
    /// embedded `ContactsState.add` sub-flow (`crate::screens::contacts`), not from a separately
    /// pushed screen the way `AcceptRequest` is from `Screen::Requests`. `Ctrl-R` is a genuinely
    /// global, unconditional binding checked in `App::handle_key` *before* any screen-specific key
    /// interception — reachable even while `state.contacts.add` is `Some` (mid `Adding`), pushing
    /// `Screen::Requests` on top of `Screen::Main`. When `Effect::AddContact` then completes, the
    /// per-screen fallback dispatch in `App::handle_worker` would otherwise route it to
    /// `Screen::Requests` instead of `Screen::Main` — whose own `requests::handle_worker` does not
    /// forward it anywhere — so `contacts::handle_worker`'s `AddContactState::Adding` arm (the
    /// *only* place that closes the sub-flow and calls `contacts::apply_update` for the display
    /// row) never runs: the add-contact form is stuck in `Adding` forever, and the new contact
    /// never appears in the live Contacts list for the rest of the session. Closed by doing the
    /// same `contacts::apply_update` + sub-flow reset **unconditionally** here, on whichever
    /// `Screen::Main` frame exists, regardless of what is on top of the stack. This call runs
    /// inside `App::handle_worker`'s event-first match, strictly *before* the per-screen fallback
    /// dispatch that would otherwise reach `contacts::handle_worker`'s own `Adding` arm — and since
    /// this call already resets `main.contacts.add` to `None`, that arm's own
    /// `if let Some(add) = state.add.as_mut()` guard never fires afterward. So in the ordinary
    /// non-interleaved case (`Screen::Main` still on top), `contacts::apply_update` runs exactly
    /// **once**, from here — the per-screen path is pre-empted, not raced. (`contacts::apply_update`
    /// is a plain upsert-by-pubkey and would in fact be idempotent under a genuine double call too,
    /// but no such double call actually occurs — guaranteed by construction (the reset-before-dispatch
    /// ordering above), confirmed during review by instrumenting the per-screen `Adding` arm and
    /// observing it never runs, in both
    /// `add_contact_makes_the_added_peer_reachable_for_verify` and the interleaving regression test
    /// below.)
    fn apply_added_contact(&mut self, added: AddedContact) {
        let Some(main_idx) = self
            .screens
            .iter()
            .position(|s| matches!(s, Screen::Main(_)))
        else {
            return;
        };
        let live_trust_idx = self.screens[main_idx + 1..]
            .iter()
            .position(|s| matches!(s, Screen::Chat(_) | Screen::Verify(_)))
            .map(|offset| main_idx + 1 + offset);
        match live_trust_idx {
            Some(idx) => match &mut self.screens[idx] {
                Screen::Chat(chat) => {
                    chat.trust.observe(added.pubkey, "", added.added_at);
                }
                Screen::Verify(verify) => {
                    verify.trust.observe(added.pubkey, "", added.added_at);
                }
                _ => unreachable!("live_trust_idx only ever points at Chat|Verify"),
            },
            None => {
                let Some(Screen::Main(main)) = self.screens.get_mut(main_idx) else {
                    return;
                };
                main.trust.observe(added.pubkey, "", added.added_at);
            }
        }
        let Some(Screen::Main(main)) = self.screens.get_mut(main_idx) else {
            return;
        };
        // Interleaving-gap fix (see doc comment above): unconditionally upsert the display row and
        // resolve the add-contact sub-flow out of `Adding`, regardless of whether `Screen::Main` is
        // on top of the stack right now. This resets `main.contacts.add` to `None` before the
        // per-screen fallback dispatch can reach `contacts::handle_worker`'s own `Adding` arm, so
        // that arm's own guard never fires afterward — `contacts::apply_update` runs exactly once,
        // pre-empting the per-screen path rather than racing it (also happens to be an idempotent
        // upsert-by-pubkey, so a hypothetical double call would be harmless too, but none occurs).
        contacts::apply_update(&mut main.contacts, ContactEntry::from_added(added), false);
        main.contacts.add = None;
    }

    /// Mirrors [`App::apply_accepted_request`]'s `main.chat.accept_request` step for a completed
    /// [`Effect::RejectRequest`] (task 4.42 review fix, Finding 3): replays
    /// `meridian_core::chat::ChatState::reject_request` into `MainState::chat` so a rejected request,
    /// same as an accepted one, does not reappear on a later `Ctrl-R`/`r` in the same session (see
    /// `crate::screens::main`'s own doc, "A rejected one still does" — this closes that gap).
    ///
    /// **Unlike `trust`, `MainState::chat` is never `std::mem::take`n by `Screen::Chat`/
    /// `Screen::Verify`** (only `trust` is — see those screens' own module docs), so this never needs
    /// the `live_trust_idx` routing `apply_accepted_request` does: a plain walk to the one
    /// `Screen::Main` on the stack is always correct, exactly like [`App::reclaim_trust`]'s own walk.
    fn apply_rejected_request(&mut self, sender_ik: [u8; 32]) {
        for screen in &mut self.screens {
            if let Screen::Main(main) = screen {
                main.chat.reject_request(&sender_ik);
                return;
            }
        }
    }

    /// Merges a completed [`Effect::LoadHistory`]'s `loaded` transcript into whichever
    /// [`Screen::Chat`] matches `peer_pubkey` — task 4.44's own fix for the traced gap
    /// `crate::screens::main`'s own module doc used to name: `ContactsAction::OpenChat` pushes
    /// `Screen::Chat` with `entries: Vec::new()` (unchanged — the screen still opens instantly, no
    /// I/O in `update`), and this is where the real, sealed on-disk transcript actually lands once
    /// the worker round trip that read it completes.
    ///
    /// **Merge, not overwrite — `loaded` first, then whatever is already there, deduped by `mid`.**
    /// Between the moment `Effect::LoadHistory` was dispatched and this completion arriving, a live
    /// inbound message for the same peer may already have been appended in memory
    /// (`crate::screens::chat::handle_inbound_message`, task 4.35). **Only if `Screen::Chat` is
    /// literally on top of the stack**, though — `App::handle_inbound`'s own `InboundEvent::Message`
    /// arm checks `self.screens.last_mut()`, not "is a matching `Screen::Chat` open anywhere". During
    /// the exact `Ctrl-R`-interleaving window this doc comment's next paragraph names, a live inbound
    /// arriving while `Screen::Requests` sits on top of that same `Screen::Chat` is therefore *not*
    /// captured into `chat.entries` here — it is still persisted to disk unconditionally
    /// (`App::handle_inbound`'s own doc comment), so nothing is lost or duplicated, only not yet shown;
    /// the next completed load picks it back up. That gap is 4.41's already-deferred, correctly
    /// out-of-scope "no unread indication while no matching chat is open" gap (see the deferral note
    /// on [`AcceptRequestRequest`]'s own doc comment), not a new regression introduced here.
    ///
    /// Putting `loaded` first preserves chronological order (the disk read reflects everything up to
    /// the moment it ran; anything already appended in memory happened no earlier than that read
    /// started). [`chat::insert_deduped`] (reused unchanged, never a second, divergent dedup) then
    /// folds the in-memory entries in on top, so a message that is in *both* (e.g. already flushed to
    /// disk by the time the read ran, and also separately delivered live) is kept exactly once — this
    /// is the "assert an inbound message arriving live for a peer whose history was just loaded is not
    /// double-listed" property this task's own Deliverable 4 names.
    ///
    /// Walks the **whole** stack, not just the top (`Ctrl-R` can push `Screen::Requests` on top of
    /// an already-open `Screen::Chat` while this load is still in flight) — mirrors
    /// [`App::apply_accepted_request`]'s identical stack walk. A no-op if no `Screen::Chat` for this
    /// peer exists any more (already popped via `Esc`) — see [`App::handle_worker`]'s own doc
    /// comment on the `Effect::LoadHistory` arm for why that is safe: a re-open dispatches its own
    /// fresh load.
    fn apply_loaded_history(&mut self, peer_pubkey: [u8; 32], loaded: Vec<HistoryEntry>) {
        for screen in &mut self.screens {
            if let Screen::Chat(chat) = screen {
                if chat.peer_pubkey == peer_pubkey {
                    let mut merged = loaded;
                    for entry in chat.entries.drain(..) {
                        chat::insert_deduped(&mut merged, entry);
                    }
                    chat.entries = merged;
                    return;
                }
            }
        }
    }

    /// The failure counterpart to [`App::apply_loaded_history`] — surfaces `message` as a transient
    /// notice on whichever `Screen::Chat` matches `peer_pubkey`, if one is still open, exactly like
    /// [`crate::screens::chat::handle_worker`]'s own `Effect::PersistHistory` failure arm. A no-op
    /// (nothing to surface a notice on) if that screen was already popped — the same "safe to lose,
    /// a re-open tries again" reasoning as the success path.
    fn note_history_load_failure(&mut self, peer_pubkey: [u8; 32], message: &str) {
        for screen in &mut self.screens {
            if let Screen::Chat(chat) = screen {
                if chat.peer_pubkey == peer_pubkey {
                    chat.notice = Some(format!("could not load message history: {message}"));
                    return;
                }
            }
        }
    }

    /// Builds a live pending-requests snapshot (task 4.36): entries from whichever `Screen::Main`
    /// is on the stack (its own `chat.pending_requests()`, a read-only, in-memory-only call — see
    /// `crate::screens::main`'s own doc for why this is "as of session load", not live), plus
    /// whatever arrived live and is still queued in [`App::pending_inbound_requests`] (task 4.35),
    /// deduped by `sender_ik` the same way [`App::handle_inbound`]'s own
    /// `InboundEvent::MessageRequest` arm already dedups. Shared by the global `Ctrl+R` handler and
    /// `Screen::Main`'s own `r`-in-list-mode handling (`MainAction::OpenRequests`) so the two
    /// dispatch paths can never diverge in what a fresh `Screen::Requests` shows.
    fn requests_snapshot(&mut self) -> Vec<RequestEntry> {
        let mut entries: Vec<RequestEntry> = self
            .screens
            .iter()
            .find_map(|s| match s {
                Screen::Main(main) => Some(
                    main.chat
                        .pending_requests()
                        .map(RequestEntry::from)
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        for e in std::mem::take(&mut self.pending_inbound_requests) {
            if !entries.iter().any(|x| x.sender_ik == e.sender_ik) {
                entries.push(e);
            }
        }
        entries
    }

    /// The one and only view function. Pure — no I/O, no `.await` — so it can run against a real
    /// terminal or `ratatui::backend::TestBackend` identically.
    ///
    /// **Task 4.26's one env read, and only here.** [`RenderCtx::from_env`] resolves `NO_COLOR` fresh
    /// on every call — this is this crate's one true "natural boundary" (`crate::theme`'s own module
    /// doc), never a scattered `std::env::var` call inside a screen's own nested render logic. Only
    /// the four screens that render a trust/delivery-state glyph
    /// ([`crate::screens::contacts`]/[`crate::screens::contact_detail`]/[`crate::screens::verify`]/
    /// [`crate::screens::chat`] — see `crate::theme`'s own "retrofit scope" doc section) receive it via
    /// their `render_with_ctx` entry point; every other screen keeps its pre-existing `render(state,
    /// frame)` call, documented there as out of this pass's scope.
    pub fn render(&self, frame: &mut Frame<'_>) {
        let ctx = RenderCtx::from_env(&self.config);
        match self.current_screen() {
            Screen::Onboarding(state) => onboarding::render(state, frame),
            Screen::Unlock(state) => unlock::render(state, frame),
            Screen::Contacts(state) => contacts::render_with_ctx(state, frame, &ctx),
            Screen::ContactDetail(state) => contact_detail::render_with_ctx(state, frame, &ctx),
            Screen::Chat(state) => chat::render_with_ctx(state, frame, &ctx),
            Screen::Requests(state) => requests::render(state, frame),
            Screen::Verify(state) => verify::render_with_ctx(state, frame, &ctx),
            Screen::Settings(state) => settings::render(state, frame),
            Screen::Help(state) => help::render(state, frame),
            Screen::Palette(state) => palette::render(state, frame),
            Screen::Extension(pane) => pane.render(frame),
            Screen::Placeholder => render_placeholder(frame),
            Screen::Main(state) => main::render_with_ctx(state, frame, &ctx, self.connection),
        }
    }
}

fn render_placeholder(frame: &mut Frame<'_>) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Meridian — Placeholder");
    let body = Paragraph::new(Line::from("screen content lands in later tasks"))
        .style(Style::default().add_modifier(Modifier::DIM))
        .alignment(Alignment::Center)
        .block(block);
    frame.render_widget(body, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn new_app_starts_on_onboarding() {
        let app = App::new();
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
        assert!(!app.should_quit());
    }

    /// Task 4.37: onboarding finishing for an **OS-keystore** account dispatches
    /// `Effect::LoadSession` and lands on the `Screen::Placeholder` "loading" interim screen — the
    /// same one `crate::preflight::InitialRoute::LoadSession` uses at startup — rather than the
    /// pre-4.37 bare `Screen::Placeholder`-forever stand-in.
    #[test]
    fn onboarding_success_enter_for_an_os_keystore_account_dispatches_load_session() {
        let mut app = App::new();
        *app.screens.last_mut().unwrap() =
            Screen::Onboarding(Box::new(OnboardingState::Success(onboarding::Success {
                id: "mrd1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@chat.example".into(),
                otk_count: 10,
                store: StoreChoice::Os,
            })));

        let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], Effect::LoadSession(_)));
        assert!(matches!(app.current_screen(), Screen::Placeholder));

        // ... and once that effect resolves (task 4.29's own worker-built shape), `App` lands on a
        // real `Screen::Main` — the same top-level `Effect::LoadSession` handling
        // `crate::preflight::InitialRoute::LoadSession` also relies on.
        let descriptor = meridian_core::account::AccountDescriptor {
            v: 1,
            pubkey: "d".repeat(64),
            hint: "chat.example".to_string(),
            store: meridian_core::account::StoreKind::Os,
            keyfile: None,
            service: Some("meridian".to_string()),
            label: "d".repeat(64),
            server: None,
        };
        let outcome = LoadSessionOutcome::Loaded(Box::new(SessionOutcome::ready(
            LiveSession::empty(descriptor),
        )));
        app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(
            Effect::LoadSession(LoadSessionEffect {
                request: LoadSessionRequest,
                outcome: Some(outcome),
            }),
        ))));
        assert!(matches!(app.current_screen(), Screen::Main(_)));
    }

    /// Task 4.37: onboarding finishing for a **file-backed** account dispatches `Effect::Unlock`
    /// (reusing the passphrase already typed at `ChooseStore`, never re-prompting) and lands on
    /// `Screen::Unlock`'s own `Unlocking` sub-state — the same "please wait" screen a returning
    /// user routed via `Preflight` sees, reused rather than duplicated.
    #[test]
    fn onboarding_success_enter_for_a_file_backed_account_dispatches_unlock() {
        let mut app = App::new();
        *app.screens.last_mut().unwrap() =
            Screen::Onboarding(Box::new(OnboardingState::Success(onboarding::Success {
                id: "mrd1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@chat.example".into(),
                otk_count: 10,
                store: StoreChoice::File {
                    passphrase: "correct horse battery staple".into(),
                },
            })));

        let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(effects.len(), 1);
        match &effects[0] {
            Effect::Unlock(effect) => {
                assert_eq!(effect.request.passphrase, "correct horse battery staple");
            }
            other => panic!("expected Effect::Unlock, got {other:?}"),
        }
        assert!(matches!(app.current_screen(), Screen::Unlock(_)));
    }

    #[test]
    fn ctrl_q_sets_should_quit_and_emits_no_effects() {
        let mut app = App::new();
        let effects = app.update(AppEvent::Key(key(
            KeyCode::Char('q'),
            KeyModifiers::CONTROL,
        )));
        assert!(effects.is_empty());
        assert!(app.should_quit());
    }

    #[test]
    fn plain_q_does_not_quit() {
        let mut app = App::new();
        app.update(AppEvent::Key(key(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(!app.should_quit());
    }

    #[test]
    fn esc_pops_screen_but_never_below_the_root() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        assert_eq!(app.screens.len(), 2);

        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.screens.len(), 1);

        // Popping the last screen is a no-op — there is always a root screen to render. The root
        // is onboarding at this point, so this also exercises onboarding's own "Esc at the first
        // sub-step is a no-op" rule rather than the generic pop handler, and the observable outcome
        // (stack length unchanged) is identical either way.
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.screens.len(), 1);
    }

    #[test]
    fn tick_resize_and_paste_events_are_no_ops_for_now() {
        let mut app = App::new();
        assert!(app.update(AppEvent::Tick).is_empty());
        assert!(app.update(AppEvent::Resize(80, 24)).is_empty());
        assert!(app.update(AppEvent::Paste("hi".into())).is_empty());
        assert!(!app.should_quit());
    }

    /// A worker event with nothing to do with the current screen (e.g. arriving after the screen
    /// already moved on) is silently ignored, not a panic.
    #[test]
    fn irrelevant_worker_event_on_placeholder_is_a_no_op() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        assert!(app
            .update(AppEvent::Worker(Box::new(WorkerEvent::Completed(
                Effect::FetchBundle
            ))))
            .is_empty());
    }

    /// `render` must be usable against an in-memory backend with no real terminal — the property
    /// every screen-snapshot test (4.16+) depends on.
    #[test]
    fn render_is_pure_and_works_against_test_backend() {
        let app = App::new();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    #[test]
    fn render_placeholder_works_against_test_backend() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    #[test]
    fn store_choice_debug_redacts_file_passphrase() {
        let choice = StoreChoice::File {
            passphrase: "correct horse battery staple".into(),
        };
        let debug = format!("{choice:?}");
        assert!(!debug.contains("correct horse battery staple"));
        assert!(debug.contains("redacted"));
    }

    /// Same redaction discipline as [`store_choice_debug_redacts_file_passphrase`], for
    /// [`UnlockRequest`] (task 4.17) — it sits directly inside [`Effect`]/[`WorkerEvent`], both
    /// `derive(Debug)`, so it needs the same unconditional hand-rolled redaction `StoreChoice::File`
    /// has.
    #[test]
    fn unlock_request_debug_redacts_passphrase() {
        let req = UnlockRequest {
            keyfile: std::path::PathBuf::from("/home/user/.config/meridian/account.age"),
            passphrase: "correct horse battery staple".into(),
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains("correct horse battery staple"));
        assert!(debug.contains("redacted"));
    }

    /// Deliverable 5 (task 4.44): the redaction check for `Effect::LoadHistory` — this task's own
    /// new widening of what a live process holds in memory (a peer's whole persisted transcript).
    /// Mirrors `crate::session::LiveSession`'s own redaction test and
    /// `unlock_request_debug_redacts_passphrase`/`run_worker_account.rs::
    /// effect_debug_never_leaks_a_passphrase` above/nearby in *shape* (plant a sentinel, assert on
    /// its presence/absence in `format!("{:?}", ..)`), but pins the **opposite** conclusion for the
    /// opposite reason: unlike `UnlockRequest`/`StoreChoice::File`, [`LoadHistoryRequest`]/
    /// [`LoadHistoryEffect`] carry no `SecretStore`/`KeyHandle`/passphrase of any kind — only a
    /// pubkey and already-decrypted [`HistoryEntry`] rows — so there is no secret here for a
    /// redaction to hide, and the message body sentinel below is expected to print in full,
    /// verbatim, exactly like `PersistHistoryEffect`/`SendMessageEffect` (task 4.20/4.33) already do
    /// through the same un-redacted `#[derive(Debug)]` — matching `crate::screens::chat::ChatState`'s
    /// own already-reviewed judgment call that conversation content is not a *secret* in this crate's
    /// hand-rolled-`Debug` sense, only passphrases/key material are. This test exists to make that
    /// judgment call for `LoadHistoryEffect` explicit and falsifiable, not silently assumed: if a
    /// future change ever adds a `SecretStore`/`KeyHandle`/passphrase field to this type without
    /// hand-rolling `Debug` for it (the `StoreChoice::File`/`UnlockRequest` precedent), this is the
    /// test that should start failing to catch it.
    #[test]
    fn load_history_effect_carries_no_key_material_and_is_not_redacted() {
        let key_sentinel = "SENTINEL-DO-NOT-LEAK-KEY-MATERIAL-4f9c";
        let body_sentinel = "SENTINEL-CONVERSATION-BODY-are-you-free-tonight";
        let effect = Effect::LoadHistory(LoadHistoryEffect {
            request: LoadHistoryRequest {
                peer_pubkey: [0x42u8; 32],
            },
            outcome: Some(vec![HistoryEntry {
                v: crate::store::history::CURRENT_VERSION,
                mid: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                dir: crate::store::history::Direction::In,
                ts: 1_760_000_000,
                stream: "mrd.chat/1".to_string(),
                body: body_sentinel.to_string(),
                state: crate::store::history::MessageState::Received,
            }]),
        });
        let dump = format!("{effect:?}");
        assert!(
            !dump.contains(key_sentinel),
            "sanity: the sentinel we're checking for absence of was never planted anywhere \
             reachable — this type structurally has no SecretStore/KeyHandle/passphrase field, so \
             there is nothing to redact"
        );
        assert!(
            dump.contains(body_sentinel),
            "message body content is deliberately NOT redacted (matches ChatState's own reviewed \
             precedent, task 4.20) — a silently-redacted transcript would be a debugging footgun, \
             not a security improvement, since it is not a passphrase or key material: {dump}"
        );
    }

    fn unlock_state() -> UnlockState {
        UnlockState::new(
            std::path::PathBuf::from("/home/user/.config/meridian/account.age"),
            "mrd1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@chat.example".into(),
        )
    }

    /// `Screen::Unlock` is fully dispatched at the `App` level (task 4.17): a submitted passphrase
    /// dispatches `Effect::Unlock`. **Defensive-fallback case (task 4.37):** the effect echoed back
    /// here is the exact one `unlock::handle_key` itself built — `SessionOutcome::empty()` — which
    /// is what this test object looks like before a real worker ever touches it; a real worker
    /// (`worker::handle_unlock`) always populates `SessionOutcome::ready(..)` on `Completed`, so
    /// this exercises `App::handle_worker`'s own defensive "no real outcome" fallback to
    /// `Screen::Placeholder`, not the ordinary success path — see
    /// `unlock_screen_completes_to_main_on_worker_success_with_a_real_session` below for that one.
    #[test]
    fn unlock_screen_worker_completion_with_an_empty_outcome_falls_back_to_placeholder() {
        let mut app = App::new();
        *app.screens.last_mut().unwrap() = Screen::Unlock(Box::new(unlock_state()));

        for c in "hunter2".chars() {
            app.update(AppEvent::Key(key(KeyCode::Char(c), KeyModifiers::NONE)));
        }
        let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(effects.len(), 1);
        let effect = effects.into_iter().next().unwrap();
        assert!(matches!(app.current_screen(), Screen::Unlock(_)));

        app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(effect))));
        assert!(matches!(app.current_screen(), Screen::Placeholder));
    }

    /// The real success path (task 4.37): a `WorkerEvent::Completed(Effect::Unlock(_))` carrying a
    /// real, populated `SessionOutcome` (exactly what `worker::handle_unlock` builds — see that
    /// function's own doc comment) reclaims the `LiveSession` and lands on `Screen::Main`, built via
    /// `MainState::from_session` — the reclaim point `crate::session::LiveSession`'s own module doc
    /// flagged as missing before this task.
    #[test]
    fn unlock_screen_completes_to_main_on_worker_success_with_a_real_session() {
        let mut app = App::new();
        *app.screens.last_mut().unwrap() = Screen::Unlock(Box::new(unlock_state()));

        let request = UnlockRequest {
            keyfile: std::path::PathBuf::from("/home/user/.config/meridian/account.key"),
            passphrase: "hunter2".into(),
        };
        let descriptor = meridian_core::account::AccountDescriptor {
            v: 1,
            pubkey: "c".repeat(64),
            hint: "chat.example".to_string(),
            store: meridian_core::account::StoreKind::File,
            keyfile: Some(request.keyfile.clone()),
            service: None,
            label: "c".repeat(64),
            server: None,
        };
        let effect = Effect::Unlock(Box::new(UnlockEffect {
            request,
            outcome: SessionOutcome::ready(LiveSession::empty(descriptor)),
        }));

        app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(effect))));
        assert!(matches!(app.current_screen(), Screen::Main(_)));
    }

    /// `render` must work for `Screen::Unlock` too, against an in-memory backend — same property
    /// `render_is_pure_and_works_against_test_backend` checks for the default `Onboarding` root.
    #[test]
    fn render_unlock_screen_works_against_test_backend() {
        let mut app = App::new();
        app.push_screen(Screen::Unlock(Box::new(unlock_state())));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    // -----------------------------------------------------------------------
    // Contacts / ContactDetail dispatch (task 4.19) — the App-level plumbing
    // `apps/tui/tests/screens_contacts.rs` doesn't cover, since that file drives
    // `crate::screens::contacts`/`contact_detail` directly rather than through `App`.
    // -----------------------------------------------------------------------

    #[test]
    fn contacts_screen_i_pushes_detail_and_esc_reconciles_edits_back_into_the_list() {
        let mut app = App::new();
        let entry = crate::screens::contacts::ContactEntry {
            pubkey: [3u8; 32],
            id: "mrd1:contact-03@example.test".into(),
            hint: "example.test".into(),
            petname: Some("carol".into()),
            trust: meridian_core::trust::TrustState::Pinned,
            user_blocked: false,
            pinned_key_history: Vec::new(),
            policy_override: None,
            added_at: 0,
            last_activity_at: 0,
            unread: 0,
        };
        *app.screens.last_mut().unwrap() =
            Screen::Contacts(Box::new(ContactsState::new(vec![entry])));

        // Task 4.36: `Enter` now opens `Screen::Chat` (see the dedicated test below) — `i` is
        // `Screen::ContactDetail`'s own new dedicated key.
        app.update(AppEvent::Key(key(KeyCode::Char('i'), KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::ContactDetail(_)));

        // Rename to "Carol V." through the detail screen, completing the effect exactly as a
        // future worker would.
        app.update(AppEvent::Key(key(KeyCode::Char('p'), KeyModifiers::NONE)));
        for _ in 0..5 {
            app.update(AppEvent::Key(key(KeyCode::Backspace, KeyModifiers::NONE)));
        }
        for c in "Carol V.".chars() {
            app.update(AppEvent::Key(key(KeyCode::Char(c), KeyModifiers::NONE)));
        }
        let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(effects.len(), 1);
        let effect = effects.into_iter().next().unwrap();
        app.update(AppEvent::Worker(Box::new(WorkerEvent::Completed(effect))));

        // Still on the detail screen (a successful rename doesn't exit) — Esc now pops back.
        assert!(matches!(app.current_screen(), Screen::ContactDetail(_)));
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));

        match app.current_screen() {
            Screen::Contacts(contacts) => {
                assert_eq!(contacts.entries.len(), 1);
                assert_eq!(contacts.entries[0].petname.as_deref(), Some("Carol V."));
            }
            other => panic!("expected Contacts, got {other:?}"),
        }
    }

    /// A standalone `Screen::Contacts` (no backing `Screen::Main`/`LiveSession` — see
    /// `crate::screens::main`'s own module doc) has no live `TrustStore`/history to build a real
    /// `Screen::Chat`/`Screen::Verify` from; task 4.36's `App::handle_key` treats `OpenChat`/
    /// `OpenVerify` as a no-op there rather than fabricating one.
    #[test]
    fn contacts_screen_enter_and_v_are_no_ops_without_a_live_trust_store() {
        let mut app = App::new();
        let entry = crate::screens::contacts::ContactEntry {
            pubkey: [4u8; 32],
            id: "mrd1:contact-04@example.test".into(),
            hint: "example.test".into(),
            petname: Some("dave".into()),
            trust: meridian_core::trust::TrustState::Pinned,
            user_blocked: false,
            pinned_key_history: Vec::new(),
            policy_override: None,
            added_at: 0,
            last_activity_at: 0,
            unread: 0,
        };
        *app.screens.last_mut().unwrap() =
            Screen::Contacts(Box::new(ContactsState::new(vec![entry])));

        app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Contacts(_)));
        assert_eq!(app.screens.len(), 1);

        app.update(AppEvent::Key(key(KeyCode::Char('v'), KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Contacts(_)));
        assert_eq!(app.screens.len(), 1);
    }

    #[test]
    fn contacts_screen_esc_in_plain_list_mode_pops_the_screen() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        app.push_screen(Screen::Contacts(Box::new(ContactsState::new(Vec::new()))));
        assert_eq!(app.screens.len(), 3);

        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Placeholder));
    }

    #[test]
    fn render_contacts_and_contact_detail_screens_work_against_test_backend() {
        let mut app = App::new();
        app.push_screen(Screen::Contacts(Box::new(ContactsState::new(Vec::new()))));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");

        let entry = crate::screens::contacts::ContactEntry {
            pubkey: [4u8; 32],
            id: "mrd1:contact-04@example.test".into(),
            hint: "example.test".into(),
            petname: None,
            trust: meridian_core::trust::TrustState::Verified,
            user_blocked: false,
            pinned_key_history: Vec::new(),
            policy_override: None,
            added_at: 0,
            last_activity_at: 0,
            unread: 0,
        };
        app.push_screen(Screen::ContactDetail(Box::new(ContactDetailState::new(
            entry,
        ))));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    // -----------------------------------------------------------------------
    // Requests dispatch (task 4.21) — the App-level plumbing
    // `apps/tui/tests/screens_requests.rs` doesn't cover, since that file drives
    // `crate::screens::requests` directly rather than through `App`.
    // -----------------------------------------------------------------------

    #[test]
    fn ctrl_r_pushes_the_requests_screen_from_anywhere_and_is_idempotent() {
        let mut app = App::new();
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));

        let effects = app.update(AppEvent::Key(key(
            KeyCode::Char('r'),
            KeyModifiers::CONTROL,
        )));
        assert!(effects.is_empty());
        assert!(matches!(app.current_screen(), Screen::Requests(_)));
        assert_eq!(app.screens.len(), 2);

        // Pressing it again while already on Requests doesn't stack a duplicate.
        app.update(AppEvent::Key(key(
            KeyCode::Char('r'),
            KeyModifiers::CONTROL,
        )));
        assert_eq!(app.screens.len(), 2);
    }

    #[test]
    fn plain_r_does_not_trigger_the_requests_screen_globally() {
        let mut app = App::new();
        app.push_screen(Screen::Placeholder);
        app.update(AppEvent::Key(key(KeyCode::Char('r'), KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Placeholder));
    }

    #[test]
    fn contacts_screen_r_opens_requests_and_esc_pops_back_to_contacts() {
        let mut app = App::new();
        *app.screens.last_mut().unwrap() =
            Screen::Contacts(Box::new(ContactsState::new(Vec::new())));

        let effects = app.update(AppEvent::Key(key(KeyCode::Char('r'), KeyModifiers::NONE)));
        assert!(effects.is_empty());
        assert!(matches!(app.current_screen(), Screen::Requests(_)));

        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Contacts(_)));
    }

    #[test]
    fn render_requests_screen_works_against_test_backend() {
        let mut app = App::new();
        app.push_screen(Screen::Requests(Box::new(
            crate::screens::requests::RequestsState::new(Vec::new()),
        )));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }

    // -----------------------------------------------------------------------
    // Help / Palette / global dispatch wiring (task 4.25) — the App-level plumbing
    // `apps/tui/tests/screens_help_palette.rs` doesn't cover, since that file drives
    // `crate::screens::help`/`crate::screens::palette` directly and only exercises `App`'s *built-in*
    // registered set (never a synthetic keybinding — `App` has no public seam to inject one). The
    // ordering-regression coverage below needs private `App` access this external test file doesn't
    // have, via the `#[cfg(test)]`-only `register_test_command` seam just below.
    // -----------------------------------------------------------------------

    impl App {
        /// Test-only seam for exercising [`App::handle_key`]'s global `PaletteRegistry::find_binding`
        /// dispatch step against a synthetic command with a real keybinding.
        /// [`register_builtin_commands`] deliberately ships no keybinding-bearing command yet
        /// (`Diagnostics` is palette-only, per tui-client.md's own screen table), so this is the only
        /// way to prove the *mechanism* fires correctly without waiting for a real future feature to
        /// register one. `#[cfg(test)]`-gated: no public API surface added for production callers.
        fn register_test_command(&mut self, command: PaletteCommand) {
            self.surface.register_command(command);
        }
    }

    #[test]
    fn f1_opens_help_and_is_idempotent() {
        let mut app = App::new();
        let effects = app.update(AppEvent::Key(key(KeyCode::F(1), KeyModifiers::NONE)));
        assert!(effects.is_empty());
        assert!(matches!(app.current_screen(), Screen::Help(_)));
        assert_eq!(app.screens.len(), 2);

        app.update(AppEvent::Key(key(KeyCode::F(1), KeyModifiers::NONE)));
        assert_eq!(
            app.screens.len(),
            2,
            "F1 while already on Help must not stack a duplicate"
        );
    }

    #[test]
    fn esc_from_help_pops_back() {
        let mut app = App::new();
        app.update(AppEvent::Key(key(KeyCode::F(1), KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Help(_)));
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
    }

    #[test]
    fn ctrl_k_opens_palette_and_is_idempotent() {
        let mut app = App::new();
        let effects = app.update(AppEvent::Key(key(
            KeyCode::Char('k'),
            KeyModifiers::CONTROL,
        )));
        assert!(effects.is_empty());
        assert!(matches!(app.current_screen(), Screen::Palette(_)));
        assert_eq!(app.screens.len(), 2);

        app.update(AppEvent::Key(key(
            KeyCode::Char('k'),
            KeyModifiers::CONTROL,
        )));
        assert_eq!(
            app.screens.len(),
            2,
            "Ctrl+K while already on Palette must not stack a duplicate"
        );
    }

    #[test]
    fn plain_k_does_not_open_the_palette() {
        let mut app = App::new();
        app.update(AppEvent::Key(key(KeyCode::Char('k'), KeyModifiers::NONE)));
        assert!(!matches!(app.current_screen(), Screen::Palette(_)));
    }

    #[test]
    fn esc_from_palette_pops_back_without_dispatching_anything() {
        let mut app = App::new();
        app.update(AppEvent::Key(key(
            KeyCode::Char('k'),
            KeyModifiers::CONTROL,
        )));
        let effects = app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(effects.is_empty());
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
    }

    /// The built-in `Diagnostics` command (registered by `register_builtin_commands`) must be
    /// reachable end to end: `Ctrl+K` opens the palette showing it, `Enter` selects the only entry
    /// and dispatches its `PaletteAction::PushPane`, landing on `Screen::Extension` (the
    /// `DiagnosticsPane`) with the palette itself closed.
    #[test]
    fn built_in_diagnostics_command_is_reachable_end_to_end_from_the_palette() {
        let mut app = App::new();
        assert_eq!(
            app.commands().iter().count(),
            2,
            "the built-in Diagnostics command, plus task 4.36's Settings command"
        );

        app.update(AppEvent::Key(key(
            KeyCode::Char('k'),
            KeyModifiers::CONTROL,
        )));
        assert!(matches!(app.current_screen(), Screen::Palette(_)));

        let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(effects.is_empty(), "PushPane dispatches no worker Effect");
        assert!(matches!(app.current_screen(), Screen::Extension(_)));
        // The palette itself is gone, not left underneath as a second stacked screen.
        assert_eq!(app.screens.len(), 2);

        // The pane pops on Esc like any other extension pane, back to the root.
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
    }

    /// Review fix (task 4.25, Finding 1): repeated dispatch of the same palette command must not
    /// stack duplicate `Screen::Extension` panes. Drives `Ctrl+K` → `Enter` on the built-in
    /// `Diagnostics` command twice in a row with no `Esc` in between — reproducing "re-open the
    /// palette and re-select the same entry" (or a terminal's key-repeat firing several `Enter`s) —
    /// and asserts the screen stack is the same shape/depth after the second dispatch as after the
    /// first.
    #[test]
    fn repeated_palette_dispatch_of_the_same_command_does_not_stack_duplicate_panes() {
        let mut app = App::new();

        // First round: Ctrl+K, Enter → lands on Screen::Extension, palette closed.
        app.update(AppEvent::Key(key(
            KeyCode::Char('k'),
            KeyModifiers::CONTROL,
        )));
        app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Extension(_)));
        assert_eq!(app.screens.len(), 2);

        // Second round, no Esc in between: re-open the palette and re-select the same entry.
        app.update(AppEvent::Key(key(
            KeyCode::Char('k'),
            KeyModifiers::CONTROL,
        )));
        let effects = app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(effects.is_empty());
        assert!(matches!(app.current_screen(), Screen::Extension(_)));
        assert_eq!(
            app.screens.len(),
            2,
            "re-selecting the same palette command must not stack a second Extension pane"
        );

        // A single Esc returns all the way to the root — proof there was only ever one layer.
        app.update(AppEvent::Key(key(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
    }

    /// `Ctrl+Q` and `Ctrl+R` (pre-existing global keys) must keep working unchanged now that `F1`,
    /// `Ctrl+K`, and the `find_binding` dispatch step sit alongside them — this is the ordering
    /// regression the task's own constraints call out by name. (`ctrl_q_sets_should_quit_and_emits_
    /// no_effects`/`ctrl_r_pushes_the_requests_screen_from_anywhere_and_is_idempotent` above already
    /// re-run unmodified as part of this same test module, since this task's new checks were inserted
    /// *after* both existing ones, not reordered ahead of them; this test additionally proves the two
    /// still work with a *registered* command present, in case a registration ever shadowed them.)
    #[test]
    fn ctrl_q_and_ctrl_r_still_work_with_a_registered_command_present() {
        let mut app = App::new();
        app.register_test_command(PaletteCommand {
            id: "test.unrelated",
            name: "Unrelated",
            description: "synthetic, bound to a key nothing else uses",
            keybinding: Some(crate::surface::KeyBinding::new(
                KeyCode::Char('z'),
                KeyModifiers::CONTROL,
            )),
            action: PaletteAction::Effect(Arc::new(|| Effect::FetchBundle)),
        });

        app.update(AppEvent::Key(key(
            KeyCode::Char('r'),
            KeyModifiers::CONTROL,
        )));
        assert!(matches!(app.current_screen(), Screen::Requests(_)));

        let effects = app.update(AppEvent::Key(key(
            KeyCode::Char('q'),
            KeyModifiers::CONTROL,
        )));
        assert!(effects.is_empty());
        assert!(app.should_quit());
    }

    /// The addendum's core ask: a registered command's keybinding fires globally — the effect it
    /// names is returned directly from `update`, without opening the palette at all.
    #[test]
    fn find_binding_fires_a_registered_commands_effect_without_opening_the_palette() {
        let mut app = App::new();
        app.register_test_command(PaletteCommand {
            id: "test.ping",
            name: "Ping",
            description: "synthetic",
            keybinding: Some(crate::surface::KeyBinding::new(
                KeyCode::Char('p'),
                KeyModifiers::CONTROL | KeyModifiers::ALT,
            )),
            action: PaletteAction::Effect(Arc::new(|| Effect::FetchBundle)),
        });

        let effects = app.update(AppEvent::Key(key(
            KeyCode::Char('p'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
        )));
        assert!(
            matches!(effects.as_slice(), [Effect::FetchBundle]),
            "expected [Effect::FetchBundle], got {effects:?}"
        );
        // No palette was opened — still on the root screen.
        assert!(matches!(app.current_screen(), Screen::Onboarding(_)));
        assert_eq!(app.screens.len(), 1);
    }

    /// The documented, accepted precedence: a registered global binding intercepts *before* a
    /// screen's own use of the identical chord — here, plain `j` (Settings' "move selection down"
    /// vim binding). Not a bug: `App::handle_key`'s own doc comment names this ordering explicitly, as
    /// does `crate::surface::PaletteRegistry::find_binding`'s. A real future feature registering a
    /// binding is responsible for avoiding a collision like this one if it wants both to work.
    #[test]
    fn a_registered_global_binding_intercepts_before_a_screens_own_use_of_the_same_key() {
        let mut app = App::new();
        app.register_test_command(PaletteCommand {
            id: "test.intercept",
            name: "Test intercept",
            description: "synthetic, deliberately colliding with Settings' own 'j' binding",
            keybinding: Some(crate::surface::KeyBinding::new(
                KeyCode::Char('j'),
                KeyModifiers::NONE,
            )),
            action: PaletteAction::Effect(Arc::new(|| Effect::FetchBundle)),
        });
        *app.screens.last_mut().unwrap() = Screen::Settings(Box::new(SettingsState::new(
            crate::config::TuiConfig::default(),
            std::path::PathBuf::from("/nonexistent/config.toml"),
        )));

        let effects = app.update(AppEvent::Key(key(KeyCode::Char('j'), KeyModifiers::NONE)));
        assert!(
            matches!(effects.as_slice(), [Effect::FetchBundle]),
            "expected [Effect::FetchBundle], got {effects:?}"
        );
        match app.current_screen() {
            // Settings' own selection cursor did not move — it would have, absent the interception.
            Screen::Settings(state) => assert_eq!(state.selected, 0),
            other => panic!("expected Settings, got {other:?}"),
        }
    }

    /// The mirror image of the previous test: with **no** registration on a given chord,
    /// `find_binding` returns `None` and every screen's own key handling is completely unaffected —
    /// the property that makes the new global check safe to run unconditionally ahead of every
    /// screen's own match arm.
    #[test]
    fn an_unregistered_key_reaches_screen_specific_handling_normally() {
        let mut app = App::new();
        *app.screens.last_mut().unwrap() = Screen::Settings(Box::new(SettingsState::new(
            crate::config::TuiConfig::default(),
            std::path::PathBuf::from("/nonexistent/config.toml"),
        )));

        app.update(AppEvent::Key(key(KeyCode::Char('j'), KeyModifiers::NONE)));
        match app.current_screen() {
            Screen::Settings(state) => assert_eq!(state.selected, 1, "moved down normally"),
            other => panic!("expected Settings, got {other:?}"),
        }
    }

    #[test]
    fn render_help_and_palette_screens_work_against_test_backend() {
        let mut app = App::new();
        app.push_screen(Screen::Help(Box::new(HelpState::new(
            app.commands().clone(),
        ))));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");

        let mut app = App::new();
        app.push_screen(Screen::Palette(Box::new(PaletteState::new(
            app.commands().clone(),
        ))));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal.draw(|frame| app.render(frame)).expect("draw");
    }
}
