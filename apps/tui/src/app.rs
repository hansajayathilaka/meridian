//! The Elm-style application core: `App` owns all state, `update` is a synchronous, pure state
//! transition, and `render` is a pure view function. **Neither ever performs I/O or awaits** — see
//! docs/architecture/tui-client.md §4. This is what makes `App::render` testable headlessly through
//! `ratatui::backend::TestBackend` (the basis for every screen-snapshot test from 4.16 onward).
//!
//! Screen content lives in [`crate::screens`] — one module per [`Screen`] variant, each owning its
//! own sub-state, `update`, and `render`; this module only dispatches to them and owns the pieces
//! that are genuinely global (quit, the screen stack).

use std::fmt;

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::trust::{PinnedKey, TrustState};

use crate::screens::chat::{self, ChatState};
use crate::screens::contact_detail::{self, ContactDetailState};
use crate::screens::contacts::{self, ContactsState};
use crate::screens::onboarding::{self, OnboardingState};
use crate::screens::requests::{self, RequestsState};
use crate::screens::unlock::{self, UnlockState};
use crate::screens::verify::{self, VerifyState};
use crate::store::contacts::PolicyOverride;
use crate::store::history::HistoryEntry;

/// Events the runtime feeds into [`App::update`]. Produced by crossterm input, the worker-response
/// channel, or the 250ms tick — see the event-loop diagram in tui-client.md §4.
#[derive(Debug, Clone)]
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

/// [`Effect::Unlock`]'s payload (task 4.17): unwrap a passphrase-protected keyfile —
/// `meridian_core::store::FileSecretStore::new(keyfile, passphrase)` followed by an unwrap
/// attempt (e.g. `export_seed`/`use_key`), mirroring `apps/cli/src/main.rs::load_store`'s
/// `StoreKind::File` branch. Carries no separate outcome payload, same as [`RegisterRequest`]: a
/// wrong passphrase surfaces as `meridian_core::store::StoreError::Unwrap` inside
/// `WorkerEvent::Failed`'s message, and the mere fact of `WorkerEvent::Completed` arriving is the
/// only signal [`crate::screens::unlock`] needs — there is no extra data to carry forward into
/// `Screen::Main` from this pure-UI layer (the unlocked store itself is a worker-side concern).
///
/// **`passphrase` is a live secret** — hand-rolled, unconditionally redacted [`fmt::Debug`], same
/// discipline as [`StoreChoice::File`]'s, since this type sits directly inside [`Effect`], which
/// `#[derive(Debug)]`s and is itself dumped by this crate's own `panic!("{other:?}")` test
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
/// [`MarkVerifiedEffect`]/[`AcknowledgeKeyChangeEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    SendMessage(SendMessageEffect),
    FetchBundle,
    PublishBundle(PublishBundleEffect),
    PersistHistory(PersistHistoryEffect),
    Unlock(UnlockRequest),
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
}

/// The outcome of a worker task executing an [`Effect`], reported back as [`AppEvent::Worker`].
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A feature-registered pane or screen (task 4.18, `docs/architecture/tui-client.md §8`) —
    /// e.g. a transfer list (T09) or a call status panel (T10). This is the **one** `Screen`
    /// variant every future feature's pane reaches the stack through: a feature implements
    /// [`crate::surface::ExtensionPane`] and pushes `Screen::Extension(Box::new(pane))` (typically
    /// via a [`crate::surface::PaletteAction::PushPane`] factory), so adding a new feature's pane
    /// never means adding a new `Screen` variant here.
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
            Screen::Extension(pane) => f.debug_tuple("Extension").field(&pane.title()).finish(),
        }
    }
}

/// Owns all application state. Constructed once by the runtime; `update` and `render` are the only
/// two ways anything reaches or reads it.
#[derive(Debug)]
pub struct App {
    screens: Vec<Screen>,
    should_quit: bool,
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
    pub fn new() -> Self {
        Self {
            screens: vec![Screen::Onboarding(Box::default())],
            should_quit: false,
        }
    }

    /// Whether the runtime should stop the event loop and let the [`crate::terminal::TerminalGuard`]
    /// restore the terminal.
    pub fn should_quit(&self) -> bool {
        self.should_quit
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

    fn handle_worker(&mut self, event: WorkerEvent) -> Vec<Effect> {
        match self.screens.last_mut() {
            Some(Screen::Onboarding(state)) => onboarding::handle_worker(state, event),
            Some(Screen::Extension(pane)) => pane.handle_worker(event),
            Some(Screen::Unlock(state)) => {
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
    pub fn render(&self, frame: &mut Frame<'_>) {
        match self.current_screen() {
            Screen::Onboarding(state) => onboarding::render(state, frame),
            Screen::Unlock(state) => unlock::render(state, frame),
            Screen::Contacts(state) => contacts::render(state, frame),
            Screen::ContactDetail(state) => contact_detail::render(state, frame),
            Screen::Chat(state) => chat::render(state, frame),
            Screen::Requests(state) => requests::render(state, frame),
            Screen::Verify(state) => verify::render(state, frame),
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
}
