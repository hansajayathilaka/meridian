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

use meridian_core::trust::{PinnedKey, TrustState};

use crate::session::LiveSession;

use crate::screens::chat::{self, ChatState};
use crate::screens::contact_detail::{self, ContactDetailState};
use crate::screens::contacts::{self, ContactsState};
use crate::screens::diagnostics::DiagnosticsPane;
use crate::screens::help::{self, HelpState};
use crate::screens::onboarding::{self, OnboardingState};
use crate::screens::palette::{self, PaletteOutcome, PaletteState};
use crate::screens::requests::{self, RequestsState};
use crate::screens::settings::{self, SettingsState};
use crate::screens::unlock::{self, UnlockState};
use crate::screens::verify::{self, VerifyState};
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
/// **Does not itself deliver `intro` into a conversation transcript.** Mirrors
/// `crate::screens::chat`'s own "no receive-path wiring" scope note: there is no
/// `Effect`/history-append plumbing in this crate yet for an inbound message arriving outside an
/// active `Screen::Chat` session. A future task that wires `Screen::Requests` → `Screen::Chat`
/// navigation is also what should decide how the accepted `intro` reaches that peer's transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequestRequest {
    pub sender_ik: [u8; 32],
}

/// [`Effect::AcceptRequest`]'s payload. No separate outcome data — same contract as
/// [`SetPetnameEffect`]/[`RegisterRequest`]: the mere fact of `WorkerEvent::Completed` arriving is
/// the only signal [`crate::screens::requests`] needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequestEffect {
    pub request: AcceptRequestRequest,
    pub outcome: Option<()>,
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
/// [`LoadSessionEffect`].
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
    /// Stand-in root screen until real screens land — also onboarding's own completion target: a
    /// future task (4.19/4.20+) swaps this for `Screen::Main` without redesigning the onboarding
    /// flow that transitions into it (see [`App::handle_key`]'s onboarding-finished branch).
    Placeholder,
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
    /// **"Reached from the command palette" (tui-client.md §2), still not wired — a deliberate,
    /// documented scope boundary of task 4.25, not an oversight.** Task 4.25 wires
    /// `PaletteRegistry::find_binding` into [`App::handle_key`] (see that method's own doc comment)
    /// and gives the palette ([`Screen::Palette`]) a real, generic dispatch path
    /// (`App::dispatch_palette_action`) for any *registered* command — but registering a working
    /// "open Settings" command would need a real, already-loaded [`crate::config::TuiConfig`]/
    /// `config_path` to construct a [`SettingsState`] from, and `App` has no live config anywhere
    /// yet (the same `Preflight`-shaped gap [`Screen::Unlock`]/[`Screen::Contacts`]/[`Screen::Chat`]
    /// all flag in their own doc comments — task 4.25 is a discoverability task, not the task that
    /// threads a real config into `App`). This variant exists fully wired
    /// (`handle_key`/`handle_worker`/`render` all dispatch to it below) and independently reachable
    /// via [`App::push_screen`], exactly like [`Screen::Verify`] before its own navigation task; only
    /// the palette-registration step is left for whichever future task gives `App` that real config.
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
/// register_command`), applied here to this task's own `Diagnostics` screen. `App::new` is the only
/// caller. Deliberately a free function (not inlined into `App::new`) so it reads as one clearly-
/// bounded registration step, mirroring how `crate::surface`'s own doc frames registration as the one
/// thing a feature does, never a core edit.
fn register_builtin_commands(surface: &mut SurfaceRegistry) {
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
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// A fresh app starts on [`Screen::Onboarding`] — this crate has no way (yet) to detect an
    /// existing `account.json` and route to [`Screen::Unlock`] or straight to `Main` instead (the
    /// `Preflight` step from `docs/architecture/diagrams/tui-screen-flow.mermaid`, still
    /// unbuilt) — so every run starts a new user from the top of the onboarding flow. `Screen::
    /// Unlock` itself exists and is fully wired (task 4.17); only the decision to construct and
    /// push it here is missing.
    ///
    /// Resolves [`crate::theme::RenderCtx`] against [`crate::config::TuiConfig::default`] — see
    /// [`App::new_with_config`] for the real-config counterpart.
    pub fn new() -> Self {
        Self::new_with_config(crate::config::TuiConfig::default())
    }

    /// Same as [`App::new`], but resolves [`crate::theme::RenderCtx`] (task 4.26) against a real,
    /// already-loaded `config.toml` instead of [`crate::config::TuiConfig::default`] — see
    /// [`App::config`]'s own doc comment.
    pub fn new_with_config(config: crate::config::TuiConfig) -> Self {
        let mut surface = SurfaceRegistry::new();
        register_builtin_commands(&mut surface);
        Self {
            screens: vec![Screen::Onboarding(Box::default())],
            should_quit: false,
            surface,
            config,
        }
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
            AppEvent::Tick | AppEvent::Resize(_, _) | AppEvent::Paste(_) => Vec::new(),
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
        // `Screen::Requests` is already on top, so repeated `Ctrl+R` doesn't stack duplicates — see
        // `Screen::Requests`'s own doc comment for why this pushes an empty queue today.
        if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if !matches!(self.current_screen(), Screen::Requests(_)) {
                self.push_screen(Screen::Requests(Box::new(RequestsState::new(Vec::new()))));
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
                let (effects, finished) = onboarding::handle_key(state, key);
                if finished {
                    // Onboarding → Main on completion. `Screen::Main` doesn't exist yet (lands in
                    // a later task, 4.19/4.20+); `Screen::Placeholder` stands in for it so that
                    // future task only has to change the line below, not this flow.
                    *self
                        .screens
                        .last_mut()
                        .expect("screens invariant: never empty") = Screen::Placeholder;
                }
                effects
            }
            Some(Screen::Unlock(state)) => {
                // Same rationale as the `Onboarding` arm above: `Unlock` owns its own key handling,
                // including Esc (a no-op — `Unlock` has nothing beneath it either, and the mermaid
                // diagram gives it no "back" transition, only retry-in-place or global quit via
                // Ctrl+Q) — see `crate::screens::unlock::handle_key`.
                let (effects, finished) = unlock::handle_key(state, key);
                if finished {
                    // Unlock → Main on a passphrase accepted. Same `Screen::Placeholder` stand-in
                    // as onboarding's completion, pending `Screen::Main` (4.19/4.20+).
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
                    // Same "empty until a future Preflight loads real data" caveat as the global
                    // `Ctrl+R` handler above — see `Screen::Requests`'s own doc comment.
                    contacts::ContactsAction::OpenRequests => {
                        self.push_screen(Screen::Requests(Box::new(
                            RequestsState::new(Vec::new()),
                        )));
                    }
                    contacts::ContactsAction::None => {}
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
                // the outermost `Esc` asks to pop, and (unlike `ContactDetail`) there is nothing to
                // reconcile back into a screen beneath it yet (see `Screen::Chat`'s own doc on why
                // navigation wiring is deferred).
                let (effects, exit) = chat::handle_key(state, key);
                if exit {
                    self.pop_screen();
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
                // cached.
                let (effects, exit) = verify::handle_key(state, key);
                if exit {
                    self.pop_screen();
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
        }
    }

    fn handle_worker(&mut self, event: WorkerEvent) -> Vec<Effect> {
        match self.screens.last_mut() {
            Some(Screen::Onboarding(state)) => onboarding::handle_worker(state, event),
            Some(Screen::Extension(pane)) => pane.handle_worker(event),
            Some(Screen::Help(state)) => help::handle_worker(state, event),
            Some(Screen::Palette(state)) => palette::handle_worker(state, event),
            Some(Screen::Unlock(state)) => {
                // **Known gap, flagged for 4.36/4.37 (task 4.29's own doc note, Finding 3):** this
                // delegates the *whole* `WorkerEvent` to `unlock::handle_worker` without first
                // reclaiming the `SessionOutcome`/`LiveSession` a successful file-backed
                // `Effect::Unlock` now carries (see `crate::app::UnlockEffect`/
                // `crate::session::LiveSession`) — so today a real, freshly-loaded `LiveSession` is
                // built and then discarded unread on every successful unlock. Not a defect in *this*
                // task (4.29's own scope explicitly excludes wiring `App` to hold
                // `Option<LiveSession>` — see the task file's Scope/Out section), but whichever future
                // task does that wiring must change *this arm itself* to extract the outcome before
                // delegating, not just add navigation elsewhere — there is no other reclaim point on
                // this path today.
                let (effects, finished) = unlock::handle_worker(state, event);
                if finished {
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
            _ => Vec::new(),
        }
    }

    /// Reconciles a popped [`Screen::ContactDetail`]'s final state back into the
    /// [`Screen::Contacts`] screen now on top of the stack — `ContactDetail` is always pushed on
    /// top of `Contacts` (see [`Screen::ContactDetail`]'s doc), so this is always safe to attempt;
    /// it is simply a no-op if, for whatever reason, the new top is not `Contacts` (defensive, not
    /// expected to be reachable in this crate today). `ContactsState.entries` is the single source
    /// of truth the list renders from; `ContactDetailState` only ever edits its own copy, so this is
    /// the one place those edits (or a delete) land back in the list the user returns to.
    fn apply_contact_update(&mut self, popped: ContactDetailState) {
        if let Some(Screen::Contacts(contacts)) = self.screens.last_mut() {
            contacts::apply_update(contacts, popped.entry, popped.deleted);
        }
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

    fn unlock_state() -> UnlockState {
        UnlockState::new(
            std::path::PathBuf::from("/home/user/.config/meridian/account.age"),
            "mrd1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@chat.example".into(),
        )
    }

    /// `Screen::Unlock` is fully dispatched at the `App` level (task 4.17): a submitted passphrase
    /// dispatches `Effect::Unlock`, and a `WorkerEvent::Completed(Effect::Unlock(_))` swaps the
    /// screen to `Screen::Placeholder` — the same completion mechanism `App::handle_key`'s
    /// `Onboarding` arm uses, exercised here through `handle_worker` instead since Unlock signals
    /// success directly from a worker event rather than via a confirmation keypress.
    #[test]
    fn unlock_screen_completes_to_placeholder_on_worker_success() {
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
    fn contacts_screen_enter_pushes_detail_and_esc_reconciles_edits_back_into_the_list() {
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

        app.update(AppEvent::Key(key(KeyCode::Enter, KeyModifiers::NONE)));
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
            1,
            "exactly the built-in Diagnostics command"
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
