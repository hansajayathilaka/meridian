//! The real per-[`Effect`] execution this crate's worker task runs (task 4.30, extended by task
//! 4.29) — the network/store/crypto half of the account-lifecycle sub-steps
//! `crate::screens::onboarding`/`crate::screens::unlock` only ever *describe*. [`dispatch`] is the
//! single entry point `crate::run_worker`'s event loop calls for every [`Effect`] it receives;
//! internally it fans out to one function per effect group (`handle_generate_account`/
//! `handle_register`/`handle_publish_bundle`/`handle_unlock`/`handle_load_session` below), so later
//! gap-closure tasks (4.31–4.34) extend the same `match` with their own groups rather than inlining
//! everything into one growing function.
//!
//! Every [`Effect`] variant this module does not yet own (chat/settings/…) falls through
//! `dispatch`'s final arm, which preserves this crate's original task-4.11 placeholder behavior —
//! echoing the effect straight back as [`WorkerEvent::Completed`] — so screens whose real execution
//! hasn't landed yet keep behaving exactly as they did before this task, out of this task's scope
//! per its own task file.
//!
//! Mirrors `apps/cli/src/main.rs::cmd_new`/`cmd_register`'s exact call sequence
//! (`generate_account` → `AccountDescriptor::save`; `SignalingClient::connect` →
//! `publish_bundle`), never inventing a different one.

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

use meridian_core::account::{self, AccountDescriptor, StoreKind};
use meridian_core::chat::{ChatError, ChatState as CoreChatState};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    generate_account, FileSecretStore, KeyHandle, MemorySecretStore, OsSecretStore, SecretStore,
};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_core::trust::{Contact, PinnedKey, TrustState, TrustStore};

use crate::app::{
    AcceptRequestEffect, AcceptRequestRequest, AcknowledgeKeyChangeEffect,
    AcknowledgeKeyChangeRequest, AddContactEffect, AddContactRequest, AddedContact,
    DeleteContactEffect, DeleteContactRequest, Effect, GenerateAccountEffect,
    GenerateAccountRequest, GeneratedAccount, ImportContactQrEffect, ImportContactQrRequest,
    LoadHistoryEffect, LoadHistoryRequest, LoadSessionEffect, LoadSessionOutcome,
    MarkVerifiedEffect, MarkVerifiedRequest, PersistHistoryEffect, PersistHistoryRequest,
    PublishBundleEffect, PublishedBundle, RegisterRequest, RejectRequestEffect,
    RejectRequestRequest, RunDoctorEffect, SaveSettingEffect, SendMessageEffect,
    SendMessageRequest, SentMessage, SessionOutcome, SetPetnameEffect, SetPetnameRequest,
    SetPolicyOverrideEffect, SetPolicyOverrideRequest, SetUserBlockedEffect, SetUserBlockedRequest,
    StoreChoice, UnlockEffect, UnlockRequest, WorkerEvent,
};
use crate::session::LiveSession;
use crate::store::contacts::{ContactRecord, ContactsDocument, PinnedKeyRecord, TrustLabel};

/// The exact keychain "service" string `apps/cli/src/main.rs::OS_KEYSTORE_SERVICE` uses. Must stay
/// identical between clients: an account minted with `--store os` by the CLI (or by this worker's
/// own [`handle_generate_account`]) has to be readable by whichever client opens it next — the
/// keychain entry is looked up by `(service, label)`, and `service` is this constant.
const OS_KEYSTORE_SERVICE: &str = "meridian";

// ---------------------------------------------------------------------------
// SignalingClient reuse across Register -> PublishBundle
// ---------------------------------------------------------------------------

/// Caches the one live [`SignalingClient`] a `Register` effect's execution opens (plus the
/// already-unwrapped [`SecretStore`] it authenticated with — see the "store reuse" note below), so
/// the following `PublishBundle` effect's execution reuses that exact connection instead of
/// reconnecting — see [`RegisterRequest`]'s own doc comment in `crate::app` for why reconnecting
/// risks a double invite redemption. Mirrors `apps/cli/src/main.rs::cmd_register`'s inline
/// single-connection pattern (`connect` once, reuse the same `client`/`store` locals for
/// `publish_bundle`), just spread across two separately-dispatched `Effect`s instead of one function
/// body.
///
/// Scoped to a single running worker task — i.e. one `meridian tui` process's whole lifetime, not
/// persisted anywhere, and never shared across processes. `crate::run_worker` constructs exactly one
/// of these before its event loop starts and threads it through every [`dispatch`] call for the
/// life of that task.
///
/// Single-slot, keyed by `account_pub`: a fresh `Register` overwrites whatever was cached (the
/// previous attempt's connection, if any, is simply dropped — closing the underlying socket without
/// a graceful WS close handshake, the same "let it drop" behavior `cmd_register` itself falls back
/// to on its own error path).
///
/// **`PublishBundle` only removes the cached entry once its own publish call actually succeeds** —
/// [`handle_publish_bundle`] borrows it via [`OnboardingSession::borrow_mut`] for the call itself and
/// only reaches for [`OnboardingSession::take`] in its `Ok` arm. A *failed* `PublishBundle` therefore
/// leaves the same still-open connection cached: `crate::screens::onboarding`'s `Failed` state
/// re-dispatches the identical effect on Enter/`r`, and that retry lands on this same connection,
/// giving it a real chance to succeed instead of only ever reproducing a "no active session" masking
/// message (the failure mode this exists to avoid — an eager `take()` before the fallible publish
/// call would silently discard the cache on the very first transient error). Only a `PublishBundle`
/// dispatched with **nothing at all** cached under its `account_pub` (most commonly one with no
/// preceding `Register` in this session) hits that fails-closed error path — deliberately, since the
/// alternative there (silently opening a fresh connection) is exactly the "reconnecting between
/// them" the design explicitly rules out. The user's way out of a `PublishBundle` that keeps failing
/// for a non-transient reason is `Esc` (onboarding's own `Failed::back`), which returns to
/// `ShowIdentity` and, on re-submission, dispatches a fresh `Register` — recaching a fresh connection
/// (and store) before `PublishBundle` runs again.
#[derive(Default)]
pub struct OnboardingSession {
    pending: Option<PendingConnection>,
    /// **Task 4.40** (closing task 4.38's Defect B): the already-unwrapped `SecretStore`/`KeyHandle`
    /// pair for a **file-backed** account's live session, populated exactly once — by
    /// [`handle_unlock`]'s own success path — and read thereafter by every contacts/trust/chat
    /// handler's [`open_account_store`] call. See that function's own doc comment for the full
    /// design and the `inbound_handoff`/`run_inbound_loop` (task 4.35) security precedent this
    /// generalizes; see this task's own Status section (`docs/tasks/phase-4/
    /// 4.40-file-backed-live-session-store.md`) for the architect + security-reviewer consult that
    /// cleared extending this process's key-material residency to the whole session lifetime.
    ///
    /// **Deliberately a distinct field from `pending`** (binding modification 1 of that consult):
    /// `pending`'s own invalidation is retry-driven (a fresh `Register` overwrites it; a *successful*
    /// `PublishBundle` removes it — see [`PendingConnection`]'s own doc comment), while this field is
    /// populate-once-and-keep-forever for the rest of the process's life. Folding the two together
    /// would blur two genuinely different lifecycles into one shared invalidation rule that fits
    /// neither.
    ///
    /// **`StoreKind::File`-only** (binding modification 3): the OS-keystore path never reads or
    /// writes this field — see [`open_account_store`]'s own doc comment for why (already cheap to
    /// re-derive per dispatch, so there is no residency cost worth caching away there).
    ///
    /// **Single-writer discipline** (binding modification 2): only [`handle_unlock`]'s success path
    /// ever calls [`OnboardingSession::set_live_store`]; every other handler in this module only
    /// ever reads it, via [`OnboardingSession::live_store`].
    ///
    /// **Known duplication, named on purpose, not fixed here** (binding modification 5): once this
    /// is populated, a live file-backed session holds *two* independent `FileSecretStore` instances
    /// resident in this one process — this one, and a second, separately-constructed one inside
    /// [`run_inbound_loop`]'s own [`InboundHandoff`] (built by [`inbound_handoff`], from the very
    /// same `UnlockRequest`, task 4.35). Not a new exposure class (same process, same trust
    /// boundary — see this task's Status section), but a future reader should not assume there is
    /// only one copy of the passphrase-derived key material resident. `TODO: confirm`: unifying the
    /// two (e.g. behind one shared `Arc<dyn SecretStore>`) is a larger refactor than this task's own
    /// scope — left for a future task to decide, not implemented here.
    live_store: Option<(Box<dyn SecretStore>, KeyHandle)>,
}

struct PendingConnection {
    account_pub: [u8; 32],
    client: SignalingClient,
    /// The already-unwrapped store [`handle_register`] authenticated with, cached so
    /// [`handle_publish_bundle`] does not pay a second, redundant scrypt unwrap for the same
    /// passphrase keyfile — see [`open_store_for_bulk_signing`]'s own doc comment.
    store: Box<dyn SecretStore>,
}

impl std::fmt::Debug for OnboardingSession {
    /// Hand-rolled, same reason and same shape as [`crate::session::LiveSession`]'s own `Debug`
    /// impl: both `pending`'s [`PendingConnection::store`] and this struct's own `live_store` hold
    /// live, passphrase-derived key material behind `Box<dyn SecretStore>`, which has no `Debug`
    /// supertrait to derive through at all — `#[derive(Debug)]` on this struct would not compile
    /// (a compile-time guarantee that a naive derive can never leak the store's contents, not just
    /// discipline). This hand-rolled impl exists only so the struct can be `{:?}`-formatted at all
    /// (e.g. in a future diagnostic log line) without ever reaching into either store field for
    /// real — both are shown as a fixed, static redaction marker, never the store's own state.
    /// [`worker::tests::onboarding_session_debug_never_leaks_the_live_store`] (task 4.40, binding
    /// modification 6) pins this down with a real assertion, mirroring `LiveSession`'s own
    /// `debug_never_leaks_chat_session_internals` test exactly.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnboardingSession")
            .field(
                "pending",
                &self.pending.as_ref().map(|p| {
                    format!(
                        "PendingConnection {{ account_pub: {}, store: <redacted> }}",
                        hex::encode(p.account_pub)
                    )
                }),
            )
            .field(
                "live_store",
                &self
                    .live_store
                    .as_ref()
                    .map(|_| "<redacted: file-backed live-session SecretStore/KeyHandle>"),
            )
            .finish()
    }
}

impl OnboardingSession {
    fn cache(
        &mut self,
        account_pub: [u8; 32],
        client: SignalingClient,
        store: Box<dyn SecretStore>,
    ) {
        self.pending = Some(PendingConnection {
            account_pub,
            client,
            store,
        });
    }

    /// **Task 4.40, binding modification 2 (single-writer discipline):** the *only* place in this
    /// module that ever populates [`OnboardingSession::live_store`] — called exactly once, from
    /// [`handle_unlock`]'s own success path, for a `StoreKind::File` account only (guaranteed by
    /// [`run_unlock`]'s own guard, which rejects an OS-keystore `account.json` before this is ever
    /// reached). Every other handler in this module only ever reads the cache back via
    /// [`OnboardingSession::live_store`] — never writes it.
    fn set_live_store(&mut self, store: Box<dyn SecretStore>, handle: KeyHandle) {
        self.live_store = Some((store, handle));
    }

    /// **Task 4.40, binding modification 4:** borrows (never consumes) the cached file-backed
    /// store/handle populated at `Unlock` time, if any — the read half every contacts/trust/chat
    /// handler's [`open_account_store`] call goes through. `None` when no file-backed account has
    /// ever successfully unlocked in this session yet (e.g. an OS-keystore session, which never
    /// populates this field at all, or a stray dispatch that somehow raced ahead of a successful
    /// `Unlock` — should not happen through ordinary navigation, since `Screen::Main` is
    /// unreachable without one, but this accessor does not assume that invariant holds elsewhere).
    fn live_store(&self) -> Option<(&dyn SecretStore, &KeyHandle)> {
        self.live_store
            .as_ref()
            .map(|(store, handle)| (store.as_ref(), handle))
    }

    /// Borrows (never consumes) the cached client + store for `account_pub`, so a fallible operation
    /// against them — [`handle_publish_bundle`]'s `publish_bundle` call — leaves the cache intact on
    /// failure and available for a same-effect retry. A mismatched or absent entry is `None`.
    fn borrow_mut(
        &mut self,
        account_pub: [u8; 32],
    ) -> Option<(&mut SignalingClient, &dyn SecretStore)> {
        match &mut self.pending {
            Some(p) if p.account_pub == account_pub => Some((&mut p.client, p.store.as_ref())),
            _ => None,
        }
    }

    /// Removes and returns the cached client, but only if it was opened for `account_pub` — a
    /// mismatched or absent entry is `None`, never a stale connection for the wrong account. Called
    /// only once [`handle_publish_bundle`]'s own publish call has actually succeeded — see this
    /// type's own doc comment for why removal is deferred that long.
    fn take(&mut self, account_pub: [u8; 32]) -> Option<SignalingClient> {
        match &self.pending {
            Some(p) if p.account_pub == account_pub => self.pending.take().map(|p| p.client),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Executes one [`Effect`] for real and returns the [`WorkerEvent`] to report back. The single entry
/// point `crate::run_worker`'s loop calls, and the same entry point this module's own tests dispatch
/// against directly (no live screen stack, no channel plumbing required).
pub async fn dispatch(effect: Effect, session: &mut OnboardingSession) -> WorkerEvent {
    match effect {
        Effect::GenerateAccount(e) => handle_generate_account(e).await,
        Effect::Register(request) => handle_register(request, session).await,
        Effect::PublishBundle(e) => handle_publish_bundle(e, session).await,
        Effect::Unlock(effect) => handle_unlock(*effect, session).await,
        Effect::LoadSession(effect) => handle_load_session(effect).await,
        // Task 4.31: contacts / contact-detail persistence. Each of these (task 4.40) now also
        // reads `session`'s file-backed live-store cache via `open_account_store` — see
        // `OnboardingSession::live_store`'s own doc comment. `session: &mut OnboardingSession` is
        // implicitly reborrowed as `&OnboardingSession` here (a standard coercion at a function-call
        // argument site): none of these twelve handlers ever need to *write* the cache, only
        // `handle_unlock` above does.
        Effect::AddContact(effect) => handle_add_contact(effect, session).await,
        Effect::ImportContactQr(effect) => handle_import_contact_qr(effect).await,
        Effect::SetPetname(effect) => handle_set_petname(effect, session).await,
        Effect::SetUserBlocked(effect) => handle_set_user_blocked(effect, session).await,
        Effect::SetPolicyOverride(effect) => handle_set_policy_override(effect, session).await,
        Effect::DeleteContact(effect) => handle_delete_contact(effect, session).await,
        // Task 4.32: message-request-queue / verify-screen trust persistence.
        Effect::AcceptRequest(effect) => handle_accept_request(effect, session).await,
        Effect::RejectRequest(effect) => handle_reject_request(effect, session).await,
        Effect::MarkVerified(effect) => handle_mark_verified(effect, session).await,
        Effect::AcknowledgeKeyChange(effect) => {
            handle_acknowledge_key_change(effect, session).await
        }
        // Task 4.33: outbound chat (the send half of the T17 demo's "both sides chat" step).
        Effect::SendMessage(effect) => handle_send_message(effect, session).await,
        Effect::PersistHistory(effect) => handle_persist_history(effect, session).await,
        // Task 4.44: the read half of `PersistHistory` above — dispatched whenever `Screen::Chat`
        // opens (`crate::screens::main::handle_key`'s `OpenChat` arm), so the transcript reflects
        // this exact same `crate::store::history` file rather than starting empty.
        Effect::LoadHistory(effect) => handle_load_history(effect, session).await,
        // Task 4.34: settings write-back / diagnostics — both already-built, already-reviewed
        // functions (`crate::config_write::write_setting_at` from task 4.24,
        // `crate::screens::diagnostics::run_doctor_binary` from task 4.25); this task is purely
        // wiring, not new logic.
        Effect::SaveSetting(effect) => handle_save_setting(effect).await,
        Effect::RunDoctor(effect) => handle_run_doctor(effect).await,
        // Effect::FetchBundle is the only variant still falling through here: a placeholder no task
        // has claimed yet (see `crate::app::Effect::FetchBundle`'s own doc comment). Task 4.35's
        // inbound-delivery work is a separate `AppEvent::Inbound` push path, not a `dispatch` arm, so
        // it does not touch or reduce this catch-all. Preserves task 4.11's original placeholder
        // behavior so any future unhandled variant is unaffected by this change.
        other => WorkerEvent::Completed(other),
    }
}

// ---------------------------------------------------------------------------
// GenerateAccount
// ---------------------------------------------------------------------------

async fn handle_generate_account(effect: GenerateAccountEffect) -> WorkerEvent {
    let GenerateAccountEffect { request, .. } = effect;
    match run_generate_account(&request) {
        Ok(account) => WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            request,
            outcome: Some(account),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::GenerateAccount(GenerateAccountEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mints a fresh Ed25519 keypair via `meridian_core::identity::generate_account`, stores the private
/// seed in the chosen [`StoreChoice`], and persists the non-secret `account.json` descriptor —
/// exactly [`GenerateAccountRequest`]'s own doc comment, exactly `apps/cli/src/main.rs::cmd_new`'s
/// two branches (`OS_KEYSTORE_SERVICE` for the OS branch; [`default_keyfile_path`] stands in for
/// `cmd_new`'s `--out` for the File branch, since onboarding never asks for a custom path).
fn run_generate_account(request: &GenerateAccountRequest) -> Result<GeneratedAccount, String> {
    let account = match &request.store {
        StoreChoice::Os => {
            init_os_keystore()?;
            let os = OsSecretStore::new(OS_KEYSTORE_SERVICE);
            let account = generate_account(&os, &request.hint).map_err(|e| e.to_string())?;
            AccountDescriptor::new_os(&account, OS_KEYSTORE_SERVICE).save()?;
            account
        }
        StoreChoice::File { passphrase } => {
            let keyfile = default_keyfile_path()?;
            let fs = FileSecretStore::new(&keyfile, passphrase.clone());
            let account = generate_account(&fs, &request.hint).map_err(|e| e.to_string())?;
            AccountDescriptor::new_file(&account, &keyfile).save()?;
            account
        }
    };
    Ok(GeneratedAccount {
        id: account.to_id_string(),
        label: hex::encode(account.public_key().as_bytes()),
        account_pub: *account.public_key().as_bytes(),
    })
}

/// The default keyfile location for a **new** file-backed account minted by onboarding
/// (`StoreChoice::File`'s branch of [`run_generate_account`]) and read back by the `Register`/
/// `PublishBundle` steps that follow it in the same onboarding run. Onboarding never asks the user
/// for a custom path ([`StoreChoice`]'s own doc comment in `crate::app`), so this worker has to pick
/// one itself. Placed next to `account.json` under `$MERIDIAN_HOME` (`account.key`) — alongside
/// `sessions.bin`/`trust.bin` — rather than mirroring `apps/cli/src/main.rs::cmd_new`'s own
/// cwd-relative `--out` default (`meridian.key`): a `meridian tui` session can be launched from any
/// working directory, so a cwd-relative default would be fragile here in a way it is not for the
/// CLI's own scripted/demo invocations.
///
/// TODO: confirm — the design (tui-client.md §5, [`GenerateAccountRequest`]'s own doc comment) names
/// `OS_KEYSTORE_SERVICE` explicitly as the thing to mirror for the OS-keystore branch, but is silent
/// on an exact filename/location for the File-store branch; this is a considered default, not a
/// documented one.
///
/// `pub(crate)` (task 4.37, not a functional change): `crate::app::App::handle_key`'s
/// Onboarding-finished arm needs this exact same path to build the `Effect::Unlock` a freshly
/// onboarded file-backed account dispatches to reach `Screen::Main` — reusing this function rather
/// than re-deriving the same `"account.key"` suffix a second time in `app.rs` is what keeps the two
/// call sites from silently drifting apart.
pub(crate) fn default_keyfile_path() -> Result<PathBuf, String> {
    Ok(account::config_dir()?.join("account.key"))
}

/// Installs the platform credential store the same way `apps/cli/src/main.rs::init_os_keystore`
/// does: constructing any `keyring` (v1 wrapper) `Entry` registers the real platform backend into
/// `keyring-core`, which `meridian_core::identity::OsSecretStore` then uses. Fails clearly on
/// headless systems with no Keychain/DPAPI/Secret Service, naming the passphrase-keyfile fallback.
fn init_os_keystore() -> Result<(), String> {
    keyring::Entry::new(OS_KEYSTORE_SERVICE, "__probe__").map_err(|e| {
        format!("OS keystore unavailable ({e}). Use a passphrase-wrapped keyfile instead.")
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

async fn handle_register(request: RegisterRequest, session: &mut OnboardingSession) -> WorkerEvent {
    // Opens via `open_store_for_bulk_signing` rather than `open_store` directly: for a passphrase
    // keyfile this pays the one scrypt unwrap the connect-time auth signature needs *and* produces
    // the exact `MemorySecretStore` `handle_publish_bundle` will go on to sign the bundle's 1 +
    // `otk_count` signatures with, cached below alongside the connection so that second step never
    // re-unwraps the same keyfile a second time — see `OnboardingSession`'s own doc comment.
    let store = match open_store_for_bulk_signing(&request.store, &request.label) {
        Ok(store) => store,
        Err(message) => return WorkerEvent::Failed(Effect::Register(request), message),
    };
    let handle = KeyHandle::from_label(&request.label);
    let account_pub = request.account_pub;
    match SignalingClient::connect(
        &request.server,
        store.as_ref(),
        &handle,
        account_pub,
        request.invite.clone(),
        1,
    )
    .await
    {
        Ok(client) => {
            // Persist the server this account just registered with onto `account.json` — closing
            // the gap `resolve_server`'s own doc comment used to describe as an open TODO: a later
            // `SendMessage` (or any other chat effect) reads this back when `config.toml` carries
            // no `[account] server` override, matching tui-client.md §5's documented "default: the
            // value used at registration" contract exactly. `run_generate_account` already wrote
            // this same descriptor (with `server: None`) earlier in onboarding, so this is a
            // load-mutate-save upgrade in place, not a fresh write.
            if let Err(message) = persist_registered_server(&request.server) {
                return WorkerEvent::Failed(Effect::Register(request), message);
            }
            session.cache(account_pub, client, store);
            WorkerEvent::Completed(Effect::Register(request))
        }
        Err(e) => WorkerEvent::Failed(Effect::Register(request), e.to_string()),
    }
}

/// Loads the current `account.json`, sets its `server` field to `server`, and re-saves it — the
/// exact load-mutate-save upgrade [`AccountDescriptor::server`]'s own doc comment describes.
/// Failure here (e.g. `account.json` went missing between `GenerateAccount` and `Register`, which
/// should never happen in a normal onboarding run but is not this function's job to rule out) is
/// reported as a real `Register` failure rather than silently dropped: without this write,
/// `resolve_server` has no fallback and every later send fails closed anyway, so surfacing it now
/// — while the user is still on the registration step and can retry — is strictly more useful than
/// deferring the same failure to their first `SendMessage`.
fn persist_registered_server(server: &str) -> Result<(), String> {
    let mut descriptor = AccountDescriptor::load()?;
    descriptor.server = Some(server.to_string());
    descriptor.save()
}

// ---------------------------------------------------------------------------
// PublishBundle
// ---------------------------------------------------------------------------

async fn handle_publish_bundle(
    effect: PublishBundleEffect,
    session: &mut OnboardingSession,
) -> WorkerEvent {
    let PublishBundleEffect { request, .. } = effect;
    let handle = KeyHandle::from_label(&request.label);

    // Borrowed, not taken: on a failed `publish_bundle` call below this leaves the connection (and
    // its already-unwrapped store) cached, so a same-effect retry reuses it instead of hitting the
    // "no active session" masking message on every attempt — see `OnboardingSession`'s own doc
    // comment for why removal is deferred to the `Ok` arm below.
    let Some((client, store)) = session.borrow_mut(request.account_pub) else {
        // See `OnboardingSession`'s own doc comment: never silently open a second connection here —
        // that's exactly the "reconnecting between them" the design rules out.
        let message =
            "no active registration session for this account — go back and register again"
                .to_string();
        return WorkerEvent::Failed(
            Effect::PublishBundle(PublishBundleEffect {
                request,
                outcome: None,
            }),
            message,
        );
    };

    match client
        .publish_bundle(store, &handle, request.otk_count)
        .await
    {
        Ok(generated) => {
            let otk_count = generated.bundle.otk_count();
            // Only now — the publish actually succeeded — is it safe to remove the cached entry.
            // Best-effort graceful close, mirroring `cmd_register`'s own `let _ = client.close()`.
            if let Some(client) = session.take(request.account_pub) {
                let _ = client.close().await;
            }
            WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
                request,
                outcome: Some(PublishedBundle { otk_count }),
            }))
        }
        // Deliberately does NOT remove the cached connection: it stays available, still open, for a
        // same-effect retry (`crate::screens::onboarding`'s `Failed::retry`) to reuse — see
        // `OnboardingSession`'s own doc comment. This differs from `cmd_register`'s own error path
        // (which simply drops `client`, closing the socket without a graceful WS handshake) because
        // the CLI has no retry affordance to preserve a connection for; the TUI does.
        Err(e) => WorkerEvent::Failed(
            Effect::PublishBundle(PublishBundleEffect {
                request,
                outcome: None,
            }),
            e.to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Unlock (task 4.29: now also loads the real LiveSession, in the same round trip)
// ---------------------------------------------------------------------------

/// Unwraps a passphrase-protected keyfile and, on success, loads the real [`LiveSession`] behind it
/// — `trust.bin`/`sessions.bin`/`contacts.json`, exactly like [`handle_load_session`]'s OS-keystore
/// path, just against a [`FileSecretStore`] instead of an [`OsSecretStore`]. Both the passphrase
/// verification *and* the session load happen in this one dispatch, never split across two effect
/// round trips — see [`UnlockEffect`]'s own doc comment for why.
///
/// **Task 4.40 (binding modification 2 — single-writer discipline):** on success, this is the one
/// and only place in this module that ever calls [`OnboardingSession::set_live_store`], caching the
/// exact `FileSecretStore`/`KeyHandle` pair [`run_unlock`] just built and verified so every
/// contacts/trust/chat handler's later [`open_account_store`] call can borrow it back instead of
/// failing closed — see that function's own doc comment for the full design.
async fn handle_unlock(effect: UnlockEffect, session: &mut OnboardingSession) -> WorkerEvent {
    let UnlockEffect { request, .. } = effect;
    match run_unlock(&request) {
        Ok((live_session, store, handle)) => {
            session.set_live_store(store, handle);
            WorkerEvent::Completed(Effect::Unlock(Box::new(UnlockEffect {
                request,
                outcome: SessionOutcome::ready(live_session),
            })))
        }
        Err(message) => WorkerEvent::Failed(
            Effect::Unlock(Box::new(UnlockEffect {
                request,
                outcome: SessionOutcome::empty(),
            })),
            message,
        ),
    }
}

/// Returns the loaded [`LiveSession`] alongside the already-unwrapped `store`/`handle` pair that
/// loaded it — task 4.40 widened this return shape (previously just `Result<LiveSession, String>`)
/// so [`handle_unlock`] can cache that exact pair on [`OnboardingSession`] without paying a second,
/// redundant passphrase unwrap to reconstruct it.
fn run_unlock(
    request: &UnlockRequest,
) -> Result<(LiveSession, Box<dyn SecretStore>, KeyHandle), String> {
    // Review fix (task 4.29, Finding 4): the symmetric guard to `run_load_session`'s own
    // `StoreKind::File => Err(...)` arm below — checked first, and against the real on-disk
    // `account.json`, not the caller-supplied keyfile, so an OS-keystore account is rejected with a
    // clear, actionable message *before* `FileSecretStore::export_seed` ever runs against it. Without
    // this guard, misusing `Effect::Unlock` on an OS-keystore account still fails closed today (an
    // AEAD failure against the wrong/nonexistent keyfile, never a silent success or wrong-account
    // leak), but with a confusing "corrupt trust.bin"-shaped error instead of a message that actually
    // names the fix. It also guarantees (task 4.40) that `OnboardingSession::set_live_store` is only
    // ever reached for a genuinely `StoreKind::File` account.
    let descriptor = AccountDescriptor::load()?;
    if descriptor.store != StoreKind::File {
        return Err(
            "this account is OS-keystore-backed — load it via Effect::LoadSession, not \
             Effect::Unlock"
                .to_string(),
        );
    }
    let fs = FileSecretStore::new(&request.keyfile, request.passphrase.clone());
    // Verify the passphrase first, exactly as task 4.30 already did — a wrong passphrase must
    // surface as *that*, not as a confusing "corrupt trust.bin" error from the loads below.
    fs.export_seed().map_err(|e| e.to_string())?;
    let handle = KeyHandle::from_label(&descriptor.label);
    let live_session = load_live_session(descriptor, &fs, &handle)?;
    Ok((live_session, Box::new(fs), handle))
}

// ---------------------------------------------------------------------------
// LoadSession (task 4.29): the OS-keystore / no-account-yet counterpart to Unlock
// ---------------------------------------------------------------------------

async fn handle_load_session(effect: LoadSessionEffect) -> WorkerEvent {
    let LoadSessionEffect { request, .. } = effect;
    match run_load_session() {
        Ok(outcome) => WorkerEvent::Completed(Effect::LoadSession(LoadSessionEffect {
            request,
            outcome: Some(outcome),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::LoadSession(LoadSessionEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// The real resolution behind [`Effect::LoadSession`] — see that effect's own request/outcome doc
/// comments in `crate::app` for the full contract this implements.
fn run_load_session() -> Result<LoadSessionOutcome, String> {
    // Checked directly against the filesystem (never via `AccountDescriptor::load()`'s own error
    // string, which conflates "not found" with "found but unparseable") so a genuinely corrupt
    // `account.json` still fails closed as a hard error below, rather than being silently
    // mistaken for the legitimate "never onboarded yet" case.
    let account_json = account::config_dir()?.join("account.json");
    if !account_json.exists() {
        return Ok(LoadSessionOutcome::NoAccount);
    }
    let descriptor = AccountDescriptor::load()?;
    match descriptor.store {
        StoreKind::Os => {
            init_os_keystore()?;
            let service = descriptor
                .service
                .clone()
                .unwrap_or_else(|| OS_KEYSTORE_SERVICE.to_string());
            let os = OsSecretStore::new(&service);
            let handle = KeyHandle::from_label(&descriptor.label);
            let session = load_live_session(descriptor, &os, &handle)?;
            Ok(LoadSessionOutcome::Loaded(Box::new(SessionOutcome::ready(
                session,
            ))))
        }
        // Never reached through ordinary navigation — a file-backed account routes through
        // `Effect::Unlock` instead, which is the only path that ever has the live passphrase this
        // store needs (see `UnlockEffect`'s own doc comment). Fails closed with a clear message
        // rather than silently no-op'ing or, worse, prompting/guessing a passphrase here.
        StoreKind::File => Err(
            "this account is passphrase-protected — unlock it via Effect::Unlock, not \
             Effect::LoadSession"
                .to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Contacts / contact-detail persistence (task 4.31)
//
// Every handler below follows the same load-fresh-from-disk -> apply-the-real-mutation ->
// reseal/save -> report round trip `at_rest_audit.rs`'s own "harness-as-worker" section had to
// hand-roll before this task existed (task 4.27's own prior art, named by this task's own file) —
// `TrustStore::observe` -> conditional `set_petname` -> re-read the real post-mutation `Contact` ->
// `seal_at_rest`, never a held-open session (see `open_account_store`'s own doc comment for why
// each dispatch re-derives its `SecretStore`/`KeyHandle` rather than reusing one cached across
// calls, unlike `OnboardingSession`).
// ---------------------------------------------------------------------------

/// Either a freshly-constructed, owned `SecretStore` (the `StoreKind::Os` branch — nothing to
/// borrow from, since it is rebuilt fresh on every call) or a borrow into
/// [`OnboardingSession::live_store`] (the `StoreKind::File` branch — task 4.40). [`open_account_store`]
/// returns one of these rather than a bare `(Box<dyn SecretStore>, KeyHandle)` precisely so the
/// file-backed branch can hand back **borrowed** data (binding modification 4 of this task's own
/// consult) instead of forcing every caller to either move the cached store out of `session` (which
/// would leave a *later* dispatch with nothing cached at all) or pay a fresh, redundant unwrap just
/// to hand back an owned copy.
enum AccountStore<'a> {
    Owned(Box<dyn SecretStore>, KeyHandle),
    Cached(&'a dyn SecretStore, &'a KeyHandle),
}

impl AccountStore<'_> {
    /// The one thing every call site actually wants: a borrowed `(&dyn SecretStore, &KeyHandle)`
    /// pair, regardless of which branch produced it.
    fn parts(&self) -> (&dyn SecretStore, &KeyHandle) {
        match self {
            AccountStore::Owned(store, handle) => (store.as_ref(), handle),
            AccountStore::Cached(store, handle) => (*store, *handle),
        }
    }
}

/// Resolves the `SecretStore`/`KeyHandle` pair every handler below needs, from the real,
/// already-onboarded `account.json` — never from a request field (none of
/// [`AddContactRequest`]/[`SetPetnameRequest`]/[`SetUserBlockedRequest`]/
/// [`SetPolicyOverrideRequest`]/[`DeleteContactRequest`]/[`SendMessageRequest`]/
/// [`PersistHistoryRequest`] carries one; see `crate::app`'s own doc comments on each), plus
/// `session`'s own file-backed live-store cache (task 4.40).
///
/// **`StoreKind::Os`.** Mirrors [`run_load_session`]'s own `StoreKind::Os` branch exactly
/// (`init_os_keystore` -> `OsSecretStore::new(service)` -> `KeyHandle::from_label`) — the OS
/// keystore needs no additional secret from this call site, so a fresh [`OsSecretStore`] is
/// (re-)constructed on every single effect dispatch with no state carried between them: cheap (no
/// KDF, no passphrase to hold onto), so — per this task's own binding modification 3 — there is no
/// residency cost worth caching away here, and this branch stays byte-for-byte unchanged from
/// before task 4.40.
///
/// **`StoreKind::File`.** Task 4.40, closing the gap this function's own doc comment used to name
/// as an open `TODO: confirm` (first flagged by task 4.37's own review, reproduced live end to end
/// by task 4.38's Defect B): borrows the already-unwrapped store/handle
/// [`handle_unlock`]'s success path cached on `session.live_store` the moment this account's
/// passphrase was last verified, rather than re-deriving one (which this branch has no passphrase
/// in scope to do — none of this module's contacts/trust/chat requests carry one; see the doc
/// comments this paragraph opened with). Fails closed, with a message naming the real gap, only
/// when nothing is cached yet — an OS-keystore session (which never populates this field at all) or
/// a dispatch that somehow reached a contacts/trust/chat effect before any successful `Unlock` in
/// this process (should not happen through ordinary navigation, since `Screen::Main` is
/// unreachable without one).
///
/// **Security rationale for resident, already-unwrapped key material for the rest of the process's
/// life:** not a new residency extension — task 4.40's own architect + security-reviewer consult
/// (this task's own Status section, `docs/tasks/phase-4/4.40-file-backed-live-session-store.md`)
/// found this pattern was already shipped and already accepted: [`run_inbound_loop`]'s own
/// [`InboundHandoff`] (built by [`inbound_handoff`], task 4.35) already constructs an independent,
/// passphrase-holding `FileSecretStore` for every file-backed account that reaches `Screen::Main`
/// and keeps it resident, unconditionally, for the rest of the process's life. This cache is a
/// second, narrower, better-scoped occurrence of that same pattern — not a wholly new exposure
/// class (see `OnboardingSession::live_store`'s own doc comment for the resulting, deliberately
/// named two-copies duplication).
fn open_account_store(session: &OnboardingSession) -> Result<AccountStore<'_>, String> {
    let descriptor = AccountDescriptor::load()?;
    match descriptor.store {
        StoreKind::Os => {
            init_os_keystore()?;
            let service = descriptor
                .service
                .clone()
                .unwrap_or_else(|| OS_KEYSTORE_SERVICE.to_string());
            let handle = KeyHandle::from_label(&descriptor.label);
            Ok(AccountStore::Owned(
                Box::new(OsSecretStore::new(&service)),
                handle,
            ))
        }
        StoreKind::File => session
            .live_store()
            .map(|(store, handle)| AccountStore::Cached(store, handle))
            .ok_or_else(|| {
                "this account is passphrase-protected and has not been unlocked in this session \
                 yet — send Effect::Unlock first"
                    .to_string()
            }),
    }
}

/// [`AccountDescriptor::pubkey`] as raw bytes — mirrors `apps/cli/src/main.rs::account_pub_bytes`
/// exactly. [`open_account_store`] resolves the `SecretStore`/`KeyHandle` pair from the same
/// descriptor but has no reason to also decode `pubkey`; [`run_send_message`] is the one caller in
/// this module that needs the raw `account_pub` too (as `ChatState::seal_outbound`'s `our_ik` and
/// `SignalingClient::connect`'s own `account_pub` argument), so it is a separate, small helper
/// rather than widening [`open_account_store`]'s return shape for every other caller.
fn account_pub_bytes(descriptor: &AccountDescriptor) -> Result<[u8; 32], String> {
    let raw = hex::decode(&descriptor.pubkey).map_err(|_| "descriptor pubkey is not valid hex")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| "descriptor pubkey is not 32 bytes".to_string())
}

/// This module's own wall-clock read (mirrors `apps/cli/src/main.rs::now_unix` exactly) — the one
/// place in this crate that reads it for the contacts-group effects, keeping `crate::screens`
/// itself pure/deterministic per this crate's Elm-architecture split (see [`AddedContact`]'s own
/// doc comment in `crate::app`: "this crate's `update` stays pure/deterministic — no
/// `SystemTime::now()` call anywhere in `crate::screens`").
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seals and writes `trust` to `trust.bin` — mirrors `apps/cli/src/contact.rs::save_trust` exactly
/// (same parent-dir creation, same error shape).
fn save_trust(
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let path = account::trust_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let sealed = trust
        .seal_at_rest(store, handle)
        .map_err(|e| format!("sealing trust store: {e}"))?;
    std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// [`TrustState`] -> `contacts.json`'s [`TrustLabel`] — mirrors `tests/at_rest_audit.rs`'s own
/// `to_trust_label` exactly (same `PinnedKeyChanged -> Pinned` approximation, since `TrustLabel`'s
/// four-value enum structurally cannot represent it — see `crate::screens::contacts`' module doc).
fn to_trust_label(state: TrustState) -> TrustLabel {
    match state {
        TrustState::New => TrustLabel::New,
        TrustState::Pinned => TrustLabel::Pinned,
        TrustState::Verified => TrustLabel::Verified,
        TrustState::Blocked => TrustLabel::Blocked,
        TrustState::PinnedKeyChanged => TrustLabel::Pinned,
    }
}

/// [`PinnedKey`] history -> `contacts.json`'s [`PinnedKeyRecord`] history — mirrors
/// `tests/at_rest_audit.rs`'s own `to_pinned_key_records` exactly.
fn to_pinned_key_records(history: &[PinnedKey]) -> Vec<PinnedKeyRecord> {
    history
        .iter()
        .map(|k| PinnedKeyRecord {
            pubkey: hex::encode(k.pubkey),
            first_seen: k.first_seen_unix,
            last_seen: k.last_seen_unix,
        })
        .collect()
}

/// Upserts `contact`'s display row into `doc`, keyed by pubkey hex (`contacts.json`'s primary
/// key — see `crate::store::contacts`'s own module doc). On a re-add of an already-known pubkey
/// whose `contacts.json` row still exists, this updates the row's `TrustStore`-owned fields
/// (`id`/`hint`/`petname`/`trust`/`pinned_key_history`) in place and bumps `last_activity_at`, but
/// leaves the row's purely-local fields (`added_at`, `policy_override`, `conv_handle`, `unread`)
/// untouched — `TrustStore::observe` has no bearing on any of them, and clobbering a real per-contact
/// policy override or unread count on a mere re-observe would be a worse regression than leaving
/// them be. `TODO: confirm`: no doc this task read pins down re-add semantics for these four fields
/// specifically; this is a considered, conservative default, not a documented one.
///
/// **Task 4.42 added a second caller, [`run_accept_request`], and that `TODO: confirm` now covers it
/// too — with its meaning unchanged.** The accept path reaches the "already has a row" branch only
/// when the sender was already a known contact (possible: `ChatState::open_inbound` gates on "no
/// established session", not on "unknown key"), and it wants exactly the same conservative
/// treatment: refresh what `TrustStore` owns, leave `added_at`/`policy_override`/`conv_handle`/
/// `unread` alone. Nothing about the note is weakened or re-scoped by that second caller; it is
/// still an undocumented-by-design default awaiting a real answer.
fn upsert_contact_record(doc: &mut ContactsDocument, id: &str, contact: &Contact, now: u64) {
    let pubkey_hex = hex::encode(contact.pubkey);
    if let Some(existing) = doc.contacts.iter_mut().find(|c| c.pubkey == pubkey_hex) {
        existing.id = id.to_string();
        existing.hint = contact.hint.clone();
        existing.petname = contact.petname.clone();
        existing.trust = to_trust_label(contact.state);
        existing.pinned_key_history = to_pinned_key_records(&contact.pinned_key_history);
        existing.last_activity_at = now;
    } else {
        doc.contacts.push(ContactRecord {
            pubkey: pubkey_hex,
            id: id.to_string(),
            hint: contact.hint.clone(),
            petname: contact.petname.clone(),
            trust: to_trust_label(contact.state),
            pinned_key_history: to_pinned_key_records(&contact.pinned_key_history),
            device_record_version_seen: None,
            policy_override: None,
            added_at: now,
            last_activity_at: now,
            unread: 0,
            conv_handle: None,
        });
    }
}

// --- AddContact --------------------------------------------------------------------------------

async fn handle_add_contact(effect: AddContactEffect, session: &OnboardingSession) -> WorkerEvent {
    let AddContactEffect { request, .. } = effect;
    match run_add_contact(&request, session) {
        Ok(added) => WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            request,
            outcome: Some(added),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::AddContact(AddContactEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mirrors `apps/cli/src/contact.rs::cmd_add`'s exact call sequence: `TrustStore::observe`
/// unconditionally, then `TrustStore::set_petname` only if [`AddContactRequest::petname`] is
/// `Some` — never derived from `id`/`pubkey`/`hint` (see that request's own doc comment in
/// `crate::app`). [`AddedContact`] is built from the real post-mutation [`Contact`] read back via
/// `TrustStore::contact`, never an assumed fresh-TOFU shape — the task 4.19 Finding 1 fix
/// [`AddedContact`]'s own doc comment requires.
fn run_add_contact(
    request: &AddContactRequest,
    session: &OnboardingSession,
) -> Result<AddedContact, String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let now = now_unix();

    let mut trust = load_trust(store, handle)?;
    trust.observe(request.pubkey, &request.hint, now);
    if let Some(petname) = request.petname.clone() {
        trust
            .set_petname(&request.pubkey, Some(petname))
            .map_err(|e| e.to_string())?;
    }
    let contact = trust
        .contact(&request.pubkey)
        .cloned()
        .expect("just observed above — always present");
    save_trust(&trust, store, handle)?;

    let mut doc =
        crate::store::contacts::load_or_default(store, handle).map_err(|e| e.to_string())?;
    upsert_contact_record(&mut doc, &request.id, &contact, now);
    crate::store::contacts::save(&doc, store, handle).map_err(|e| e.to_string())?;

    Ok(AddedContact {
        pubkey: request.pubkey,
        id: request.id.clone(),
        hint: contact.hint,
        petname: contact.petname,
        added_at: now,
        trust: contact.state,
        user_blocked: contact.user_blocked,
        pinned_key_history: contact.pinned_key_history,
    })
}

// --- ImportContactQr ----------------------------------------------------------------------------

async fn handle_import_contact_qr(effect: ImportContactQrEffect) -> WorkerEvent {
    let ImportContactQrEffect { request, .. } = effect;
    match run_import_contact_qr(&request) {
        Ok(decoded) => WorkerEvent::Completed(Effect::ImportContactQr(ImportContactQrEffect {
            request,
            outcome: Some(decoded),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::ImportContactQr(ImportContactQrEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mirrors `apps/cli/src/verify.rs::scan_and_compare`'s own headless QR-scan path exactly, per
/// [`ImportContactQrEffect`]'s own doc comment in `crate::app`: `image::open` + `to_luma8()`, then
/// `meridian_core::identity::decode_luma` to recover the raw `mrd1:…` candidate string. Never calls
/// `parse_id` and never touches `TrustStore`/`contacts.json` itself — that is
/// `crate::screens::contacts`' own job, treating the decoded string exactly like a pasted one.
fn run_import_contact_qr(request: &ImportContactQrRequest) -> Result<String, String> {
    let img = image::open(&request.path)
        .map_err(|e| e.to_string())?
        .to_luma8();
    meridian_core::identity::decode_luma(&img).map_err(|e| e.to_string())
}

// --- SetPetname ----------------------------------------------------------------------------------

async fn handle_set_petname(effect: SetPetnameEffect, session: &OnboardingSession) -> WorkerEvent {
    let SetPetnameEffect { request, .. } = effect;
    match run_set_petname(&request, session) {
        Ok(()) => WorkerEvent::Completed(Effect::SetPetname(SetPetnameEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::SetPetname(SetPetnameEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mirrors `apps/cli/src/contact.rs::cmd_rename`'s write path: `TrustStore::set_petname`, then the
/// matching `contacts.json` `ContactRecord.petname` — both writes, per [`SetPetnameEffect`]'s own
/// doc comment in `crate::app`, unlike [`SetUserBlockedEffect`] (`trust.bin` only).
fn run_set_petname(request: &SetPetnameRequest, session: &OnboardingSession) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();

    let mut trust = load_trust(store, handle)?;
    trust
        .set_petname(&request.pubkey, request.petname.clone())
        .map_err(|e| e.to_string())?;
    let petname = trust
        .contact(&request.pubkey)
        .expect("set_petname succeeded — contact exists")
        .petname
        .clone();
    save_trust(&trust, store, handle)?;

    let mut doc =
        crate::store::contacts::load_or_default(store, handle).map_err(|e| e.to_string())?;
    let pubkey_hex = hex::encode(request.pubkey);
    if let Some(record) = doc.contacts.iter_mut().find(|c| c.pubkey == pubkey_hex) {
        record.petname = petname;
        crate::store::contacts::save(&doc, store, handle).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// --- SetUserBlocked --------------------------------------------------------------------------------

async fn handle_set_user_blocked(
    effect: SetUserBlockedEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let SetUserBlockedEffect { request, .. } = effect;
    match run_set_user_blocked(&request, session) {
        Ok(()) => WorkerEvent::Completed(Effect::SetUserBlocked(SetUserBlockedEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::SetUserBlocked(SetUserBlockedEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mirrors `apps/cli/src/contact.rs::cmd_block`'s write path: `TrustStore::set_user_blocked` only
/// — deliberately never mirrored into `contacts.json` (see [`SetUserBlockedEffect`]'s own doc
/// comment in `crate::app`: that document's `TrustLabel` enum has no field for a user-initiated
/// block).
fn run_set_user_blocked(
    request: &SetUserBlockedRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let mut trust = load_trust(store, handle)?;
    trust
        .set_user_blocked(&request.pubkey, request.blocked)
        .map_err(|e| e.to_string())?;
    save_trust(&trust, store, handle)
}

// --- SetPolicyOverride -----------------------------------------------------------------------------

async fn handle_set_policy_override(
    effect: SetPolicyOverrideEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let SetPolicyOverrideEffect { request, .. } = effect;
    match run_set_policy_override(&request, session) {
        Ok(()) => WorkerEvent::Completed(Effect::SetPolicyOverride(SetPolicyOverrideEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::SetPolicyOverride(SetPolicyOverrideEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Writes only `contacts.json`'s `ContactRecord.policy_override` — `TrustStore` has no concept of
/// relay policy at all, per [`SetPolicyOverrideEffect`]'s own doc comment in `crate::app`.
fn run_set_policy_override(
    request: &SetPolicyOverrideRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let mut doc =
        crate::store::contacts::load_or_default(store, handle).map_err(|e| e.to_string())?;
    let pubkey_hex = hex::encode(request.pubkey);
    let record = doc
        .contacts
        .iter_mut()
        .find(|c| c.pubkey == pubkey_hex)
        .ok_or_else(|| "no contact recorded for this pubkey — add it first".to_string())?;
    record.policy_override = request.policy_override;
    crate::store::contacts::save(&doc, store, handle).map_err(|e| e.to_string())
}

// --- DeleteContact ---------------------------------------------------------------------------------

async fn handle_delete_contact(
    effect: DeleteContactEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let DeleteContactEffect { request, .. } = effect;
    match run_delete_contact(&request, session) {
        Ok(()) => WorkerEvent::Completed(Effect::DeleteContact(DeleteContactEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::DeleteContact(DeleteContactEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Removes only the local `contacts.json` display row — never touches `TrustStore`/`trust.bin`, per
/// [`DeleteContactEffect`]'s own doc comment in `crate::app` (a deliberate, already-reviewed
/// judgment call: no core primitive exists to forget TOFU pinned-key history, by design). Deleting
/// an already-absent row is a no-op, not an error — idempotent, matching "delete" being a
/// lower-stakes, purely-local list-membership action.
fn run_delete_contact(
    request: &DeleteContactRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let mut doc =
        crate::store::contacts::load_or_default(store, handle).map_err(|e| e.to_string())?;
    let pubkey_hex = hex::encode(request.pubkey);
    doc.contacts.retain(|c| c.pubkey != pubkey_hex);
    crate::store::contacts::save(&doc, store, handle).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Message-request queue / verify-screen trust persistence (task 4.32)
//
// Every handler below shares the shape this task's own file names: the screen has already computed
// the answer, synchronously, in-memory (`crate::screens::requests`'s confirm step;
// `crate::screens::verify::apply_action`) — these handlers exist purely to make that already-decided
// answer durable. None of them re-derives or second-guesses the decision: `run_mark_verified`/
// `run_acknowledge_key_change` propagate `TrustStore`'s own `Result` faithfully (including
// `TrustError::NotAcknowledgeable`) rather than treating a refusal as success, and
// `run_accept_request`/`run_reject_request` replay `ChatState::accept_request`/`reject_request`
// exactly as `apps/cli/src/chat.rs::answer_request` does — same calls, same order, just reloaded
// fresh from disk and resealed rather than applied to an already-open in-memory value.
//
// **Task 4.42 amends the scope note that used to end this paragraph** ("Only `trust.bin`/
// `sessions.bin` are touched here — never `contacts.json`"). That is still true of
// `run_reject_request`/`run_mark_verified`/`run_acknowledge_key_change`, but no longer of
// [`run_accept_request`], which now also writes the accepted sender's `contacts.json` display row —
// see that function's own doc comment for why it *has* to be the one that does (task 4.41's Defect
// C: `Contact::id_string()` fails for an accept-observed sender, so no other code path in this crate
// can ever create that row).
//
// **Task 4.49 extends this further:** [`run_accept_request`] now also appends the accepted sender's
// intro to `history.jsonl` on a genuine accept — see that function's own doc comment for the fourth
// write and the narrower partial-failure window it introduces.
// ---------------------------------------------------------------------------

// --- AcceptRequest -------------------------------------------------------------------------------

async fn handle_accept_request(
    effect: AcceptRequestEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let AcceptRequestEffect { request, .. } = effect;
    match run_accept_request(&request, session).await {
        Ok(outcome) => WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            request,
            outcome,
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::AcceptRequest(AcceptRequestEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mirrors `apps/cli/src/chat.rs::answer_request`'s accept branch exactly, and in the same order
/// (task 4.7's own fix, named again by [`AcceptRequestRequest`]'s own doc comment in `crate::app`):
/// `ChatState::accept_request(sender_ik)` first — resealing `sessions.bin` immediately — and only
/// *then* `TrustStore::observe(sender_ik, "", now_unix())` to TOFU-pin the sender, resealing
/// `trust.bin` separately. The empty hint mirrors `AcceptRequestRequest`'s own doc comment exactly:
/// `MessageRequest` carries no advisory hint for this worker to pass through.
///
/// If `accept_request` finds no pending request for `sender_ik` (e.g. this effect is a stale retry
/// of one that already completed), that mirrors `answer_request`'s own `if let Some(req) = ...`
/// guard: nothing to accept, so `TrustStore::observe` is never reached either — no unrelated pin
/// created for a decision that was never actually made against a real pending request.
///
/// **Review fix (partial-failure idempotency):** this writes two separate sealed files
/// (`sessions.bin` then `trust.bin`), not one atomic transaction. If `save_chat` above succeeds but
/// the pin step's own `save_trust` then fails (disk I/O error, permission change, …), the whole
/// function still returns `Err` and the UI can retry the identical effect — but on that retry
/// `chat.accept_request(sender_ik)` now returns `None` (already removed from `pending_requests` by
/// the first, partially-successful attempt), so a naive `if accepted { … }` guard would skip the pin
/// forever, leaving a live, delivering session with no `TrustStore` record at all. The correct signal
/// for "does this sender still need pinning" is not "did `accept_request` just now return `Some`" but
/// "does `TrustStore` already have a `Contact` record for `sender_ik`" — so the pin step also runs on
/// a retry that finds the trust side still outstanding (`trust.contact(sender_ik).is_none()`).
///
/// That signal alone is not quite sufficient, though: a **phantom** `sender_ik` that was never
/// accepted at all (no pending request ever existed, so `chat.has_session` is also false) would
/// equally read `accepted == false` and `trust.contact(..).is_none()` — indistinguishable from the
/// genuine partial-failure retry by `trust.contact` alone, and pinning it would recreate exactly the
/// "unrelated pin for a decision never actually made" bug this function's own doc comment (above)
/// already guards against for that case. `chat.has_session(sender_ik)` disambiguates the two: it is
/// true only once a request for `sender_ik` was genuinely accepted (accept never touches the session
/// map — the crypto session was already established when the request was gated, well before
/// `accept_request` ever runs — so it stays true across a same-effect retry), and false for a sender
/// who was never accepted at all. So the pin step runs when **either** `accepted` is true (a genuine
/// first-time accept), **or** the trust side is still outstanding for a sender who *was* genuinely
/// accepted (`chat.has_session(sender_ik) && trust.contact(sender_ik).is_none()`) — a fully-completed
/// retry (both saves already succeeded once) has an existing `Contact` record and takes no action, and
/// a phantom/never-accepted sender has no session and likewise takes no action, exactly as today.
///
/// **Task 4.35:** holds [`chat_state_lock`] for the whole load-mutate-save `sessions.bin` sequence,
/// same as [`run_reject_request`]/[`run_send_message`] — see that function's own doc comment for why
/// (`sessions.bin` is a single serialized document covering every peer's session, and the persistent
/// inbound receive loop touches the same file concurrently on its own tokio task).
///
/// **Task 4.42 (Shape A — the fix for task 4.41's Defect C):** on the same `accepted ||
/// pin_still_owed` branch, this now *also* upserts and saves the sender's `contacts.json` display
/// row, through [`crate::store::contacts::save`] (sealed via `at_rest::seal`, per ADR 0021) —
/// exactly the pair of writes [`run_add_contact`] already performs for the initiator side, in the
/// same order (`trust.bin` first, the display cache second: the crypto-relevant source of truth is
/// never allowed to lag behind the display row that asserts it). Accept is the responder-side twin
/// of add, and this is the **only** code path that can ever create that row: `TrustStore::observe`
/// here passes an empty hint (see above), so the resulting `Contact::id_string()` fails
/// (`validate_hint` rejects an empty hint) and the "re-add the sender by hand via the contacts
/// screen" workaround is structurally impossible, not merely un-implemented — see task 4.42's own
/// file. Without the row, `crate::screens::main::build_contact_entries`' `contacts.json`-driven join
/// leaves an accepted sender invisible in the live UI forever.
///
/// The synthesized row therefore carries `id: ""` and `hint: ""` for a genuinely first-contact
/// sender. **No hint-less `mrd1:` id form is invented** for it (that would touch the wire-critical,
/// conformance-vectored `meridian-identity` crate and contradict [ADR 0001]'s self-certifying-key +
/// routing-hint identity); `crate::screens::contacts::ContactEntry::display_label`'s existing
/// petname → hint → `short_pubkey` fallback renders the row as the same fingerprint the Requests
/// pane showed. `conv_handle` stays `None` until a conversation is first opened
/// ([`ContactRecord::conv_handle_or_mint`](crate::store::contacts::ContactRecord::conv_handle_or_mint)),
/// and no schema change is involved. The `id` passed to [`upsert_contact_record`] is
/// `contact.id_string().unwrap_or_default()`, not a hard-coded `""`: for the (rare, but reachable)
/// case of a sender who is *already* a known contact with a real hint — `ChatState::open_inbound`
/// gates on "no established session", not on "unknown key", so an added-but-never-messaged contact's
/// first inbound message is still a message request — that reads back the contact's real canonical
/// id rather than blanking the existing row's. [`upsert_contact_record`]'s own `TODO: confirm` about
/// re-add semantics for `added_at`/`policy_override`/`conv_handle`/`unread` applies verbatim to that
/// accept-side re-observe too: those four purely-local fields are left untouched on an existing row,
/// for exactly the reasons stated there, and this task did not find a design doc resolving them
/// either.
///
/// **Retry idempotency, unchanged in shape:** the row write sits behind the *same* `accepted ||
/// pin_still_owed` guard as the pin, so a same-effect retry can never create a display row for a
/// sender with no session (the phantom-sender case the guard's own derivation above covers), and a
/// fully-completed retry still takes no action at all. One residual, narrower-than-the-pin window
/// remains: if `save_trust` succeeds and `contacts::save` then fails, this returns `Err`, and the
/// retry finds `accepted == false` and `pin_still_owed == false` (the pin *is* complete) and so
/// writes no row. Widening the guard with a third "the row is missing" disjunct is deliberately
/// **not** done — it would resurrect a display row the user had since locally deleted
/// (`crate::app::DeleteContactRequest`'s "deleting removes only the local row, the `TrustStore`
/// record survives" invariant), which is exactly the direction-of-the-join property task 4.42's own
/// file protects. `TODO: confirm`: no design doc read for this task resolves how a display row lost
/// to that specific partial failure should be recovered. Recommended direction for a dedicated
/// follow-up task (out of this task's own scope — new diagnostics/UI surface, not a `run_worker`
/// change alone): a diagnostics-surfaced repair action that rebuilds *only* the display rows missing
/// from `contacts.json` for a `trust.bin` contact — driven from `chat.has_session`/`trust.contact`
/// the same way this guard is, so it stays explicitly distinct from, and can never resurrect, the
/// legitimate delete-tombstone case (`crate::app::DeleteContactRequest`'s row-deleted-but-`TrustStore`
/// -record-survives case above) — never a blanket "resync contacts.json from trust.bin" that would
/// conflate the two. Left unimplemented here; flagged for that follow-up rather than absorbed
/// silently or rushed into this task's own diff.
///
/// Returns the [`AddedContact`] the accept produced, so `crate::app::App` can replay the same
/// mutation into the live, already-open `Screen::Main` (task 4.42, piece C) instead of only fixing
/// the next restart — built from the real post-`observe` [`Contact`] read back via
/// `TrustStore::contact`, never an assumed fresh-TOFU shape, exactly as [`run_add_contact`] does
/// (the task 4.19 Finding 1 rule). `Ok(None)` is the honest "this dispatch decided nothing" answer
/// for the no-op/fully-completed-retry cases: the effect still *completes* (nothing failed), it just
/// carries no contact for `App` to apply.
///
/// **Task 4.49 (the fix for 4.48's fifth defect):** on the same genuine-accept branch, this now also
/// writes a fourth sealed document: the [`meridian_core::chat::MessageRequest::intro`] this accept
/// just took, appended into the sender's own `history.jsonl` via [`crate::store::history::append`] —
/// the same writer, same call shape, [`run_persist_history`] already uses. This is placed *after*
/// the `trust.bin`/`contacts.json` writes above succeed, and reads `request_taken` (the real
/// `Option<MessageRequest>` `chat.accept_request` returned), never re-deriving it from `accepted`
/// alone — the `pin_still_owed`-only retry branch has no `MessageRequest` to source content from
/// (`chat.accept_request` already returned `None` there; see the partial-failure doc comment above),
/// so the history write is skipped on that branch, not attempted with a fabricated body. The
/// `HistoryEntry` built mirrors `process_inbound_delivery`'s own ordinary-inbound-Text construction
/// field-for-field, except `ts`, which reuses this function's own `now` (accept-time, not
/// original-request-arrival-time — `MessageRequest` carries no arrival timestamp to source a more
/// precise one from; a deliberate, stated approximation, not a `TODO`). A `ChatContent::Receipt`
/// intro (reachable only from a degenerate/adversarial first envelope — see `intro_summary`'s own
/// "not a text message" precedent) is skipped entirely: no history entry is invented for it, and it
/// is not treated as an error.
///
/// **A narrower partial-failure window, named rather than fixed.** This fourth write is gated on
/// `accepted` only (via `request_taken`, which is `Some` exactly when `accepted` is true), sitting
/// after `save_trust`/`contacts::save` have already succeeded. If `history::append` itself then
/// fails, the function returns `Err`, and a client retry finds `accepted == false && pin_still_owed
/// == false` (the pin is already complete) — the same early `Ok(None)` return the guard above
/// already takes for a fully-completed retry — so the retry never re-attempts the history write: the
/// peer stays durably trusted and reachable, but the intro is then permanently missing. This is
/// **not** fixed by widening the guard, for the same "do not resurrect a case that should not
/// self-heal automatically" reason the `contacts.json`-row-missing case above is not fixed either —
/// it is a narrower analog of that same already-tracked repair-action follow-up, not a third,
/// freestanding partial-failure task.
///
/// [ADR 0001]: ../../../docs/adr/0001-identity-scheme.md
async fn run_accept_request(
    request: &AcceptRequestRequest,
    session: &OnboardingSession,
) -> Result<Option<AddedContact>, String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let _chat_guard = chat_state_lock().lock().await;

    let mut chat = load_chat(store, handle)?;
    let request_taken = chat.accept_request(&request.sender_ik);
    let accepted = request_taken.is_some();
    let has_session = chat.has_session(&request.sender_ik);
    save_chat(&chat, store, handle)?;

    let mut trust = load_trust(store, handle)?;
    let pin_still_owed = has_session && trust.contact(&request.sender_ik).is_none();
    if !(accepted || pin_still_owed) {
        return Ok(None);
    }

    let now = now_unix();
    trust.observe(request.sender_ik, "", now);
    let contact = trust
        .contact(&request.sender_ik)
        .cloned()
        .expect("just observed above — always present");
    save_trust(&trust, store, handle)?;

    let id = contact.id_string().unwrap_or_default();
    let mut doc =
        crate::store::contacts::load_or_default(store, handle).map_err(|e| e.to_string())?;
    upsert_contact_record(&mut doc, &id, &contact, now);
    crate::store::contacts::save(&doc, store, handle).map_err(|e| e.to_string())?;

    // Task 4.49: persist the intro into the sender's own `history.jsonl`, on the genuine fresh-accept
    // branch only (`request_taken`, not the `pin_still_owed`-only retry branch — a retry finds
    // `chat.accept_request` already returned `None`, so there is no `MessageRequest` to source a body
    // from; that branch's intro was, if ever, written by the first, partially-successful attempt).
    // Mirrors the ordinary inbound-Text handler's own `HistoryEntry` construction
    // (`process_inbound_delivery`) field-for-field, except `ts`, which reuses the `now` already
    // computed above for `trust.observe` — see this function's own doc comment for why. A
    // `ChatContent::Receipt` intro (degenerate, not normal — see the doc comment) is skipped, never
    // errored or invented into a receipt-shaped entry.
    if let Some(taken) = request_taken {
        if let ChatContent::Text { id, body } = taken.intro {
            let entry = crate::store::history::HistoryEntry {
                v: crate::store::history::CURRENT_VERSION,
                mid: hex::encode(id),
                dir: crate::store::history::Direction::In,
                ts: now,
                stream: "mrd.chat/1".to_string(),
                body,
                state: crate::store::history::MessageState::Received,
            };
            crate::store::history::append(&hex::encode(request.sender_ik), &entry, store, handle)
                .map_err(|e| e.to_string())?;
        }
    }

    Ok(Some(AddedContact {
        pubkey: request.sender_ik,
        id,
        hint: contact.hint,
        petname: contact.petname,
        added_at: now,
        trust: contact.state,
        user_blocked: contact.user_blocked,
        pinned_key_history: contact.pinned_key_history,
    }))
}

// --- RejectRequest -------------------------------------------------------------------------------

async fn handle_reject_request(
    effect: RejectRequestEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let RejectRequestEffect { request, .. } = effect;
    match run_reject_request(&request, session).await {
        Ok(()) => WorkerEvent::Completed(Effect::RejectRequest(RejectRequestEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::RejectRequest(RejectRequestEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Mirrors `apps/cli/src/chat.rs::answer_request`'s reject branch exactly:
/// `ChatState::reject_request(sender_ik)` only — no `TrustStore` interaction of any kind, per
/// [`RejectRequestRequest`]'s own doc comment ("leaves no trace"). `reject_request` discards both the
/// held [`meridian_core::chat::MessageRequest`] *and* the already-established session behind it
/// (ratchet/X3DH material zeroized), so once `sessions.bin` is resealed here, a fresh
/// `TrustStore::open_at_rest`/`ChatState::open_at_rest` reload sees exactly the same state for
/// `sender_ik` as if it had never been contacted at all — the property this task's own tests
/// (`reject_leaves_no_trace_*` below) pin via a real before/after comparison, not just a successful
/// return.
///
/// **Task 4.35:** holds [`chat_state_lock`] for the whole load-mutate-save sequence — see
/// [`run_accept_request`]'s own doc comment for why.
async fn run_reject_request(
    request: &RejectRequestRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let _chat_guard = chat_state_lock().lock().await;
    let mut chat = load_chat(store, handle)?;
    chat.reject_request(&request.sender_ik);
    save_chat(&chat, store, handle)
}

// --- MarkVerified --------------------------------------------------------------------------------

async fn handle_mark_verified(
    effect: MarkVerifiedEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let MarkVerifiedEffect { request, .. } = effect;
    match run_mark_verified(&request, session) {
        Ok(()) => WorkerEvent::Completed(Effect::MarkVerified(MarkVerifiedEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::MarkVerified(MarkVerifiedEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Replays `crate::screens::verify::apply_action`'s already-applied-in-memory
/// [`TrustStore::mark_verified`] call against the real, persisted `trust.bin` — never re-deciding
/// whether verification was warranted (that judgment call already happened, out of band, before the
/// screen dispatched this effect). Faithfully propagates [`TrustError::UnknownContact`] (e.g. a
/// concurrently-deleted contact) as a real [`WorkerEvent::Failed`], never swallowed into a silent
/// success.
fn run_mark_verified(
    request: &MarkVerifiedRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let mut trust = load_trust(store, handle)?;
    trust
        .mark_verified(&request.pubkey)
        .map_err(|e| e.to_string())?;
    save_trust(&trust, store, handle)
}

// --- AcknowledgeKeyChange -------------------------------------------------------------------------

async fn handle_acknowledge_key_change(
    effect: AcknowledgeKeyChangeEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let AcknowledgeKeyChangeEffect { request, .. } = effect;
    match run_acknowledge_key_change(&request, session) {
        Ok(()) => {
            WorkerEvent::Completed(Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
                request,
                outcome: Some(()),
            }))
        }
        Err(message) => WorkerEvent::Failed(
            Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Replays `crate::screens::verify::apply_action`'s already-applied-in-memory
/// [`TrustStore::acknowledge_key_change`] call against the real, persisted `trust.bin`. **Never
/// softens [`TrustError::NotAcknowledgeable`]** — if the real, freshly-reloaded `trust.bin` disagrees
/// with the screen's in-memory copy (the contact is not currently `PinnedKeyChanged`, most
/// importantly because it is `Blocked`, or because `escalate_pinned_key_change` force-transitioned it
/// to `Blocked` on this very call), that refusal is propagated verbatim as [`WorkerEvent::Failed`],
/// exactly the "no bypass" invariant [`TrustStore::acknowledge_key_change`]'s own doc comment
/// requires (tasks 4.4/4.23) — this worker has no authority to retry it as a `mark_verified` or any
/// other weaker substitute.
///
/// **Review fix (persistence gap):** `TrustStore::acknowledge_key_change`'s own escalation branch
/// mutates `contact.state` to [`TrustState::Blocked`] *and then* returns
/// `Err(TrustError::NotAcknowledgeable)` — a real, in-memory state change riding along on an `Err`
/// path. A naive `?` immediately after the call (as this function used to have) would propagate that
/// `Err` before ever reaching [`save_trust`], silently discarding the force-block instead of sealing
/// it into `trust.bin` — exactly the retroactive-escalation bypass that method's own doc comment says
/// must never happen (a later plain acknowledge, with escalation off again, would still succeed and
/// silently re-pin). So the real [`TrustState`] is snapshotted both before and after the call, and
/// [`save_trust`] runs whenever it actually changed — on **either** outcome, not just `Ok` — while the
/// already-covered "no mutation at all" case (a contact that is not `PinnedKeyChanged` and not under
/// escalation, e.g. already `Verified`/`Pinned`) still takes no save at all: `trust.bin` stays
/// byte-for-byte untouched, never even resealed-and-rewritten-identically.
fn run_acknowledge_key_change(
    request: &AcknowledgeKeyChangeRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let mut trust = load_trust(store, handle)?;
    let state_before = trust.contact(&request.pubkey).map(|c| c.state);
    let result = trust.acknowledge_key_change(&request.pubkey);
    let state_after = trust.contact(&request.pubkey).map(|c| c.state);
    if state_before != state_after {
        save_trust(&trust, store, handle)?;
    }
    result.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Outbound chat: SendMessage / PersistHistory (task 4.33)
//
// The send half of the T17 demo's "both sides chat" step — the receive path (a persistent
// connection, unlike this one) is task 4.35's, materially different mechanism, not this module's
// concern yet. Mirrors `apps/cli/src/chat.rs::send_text`'s exact seal-then-`route_tolerant`
// sequence, including its first-send session establishment (`fetch_with_retry` +
// `start_initiator_session`, gated on `initiator && !has_session` exactly like
// `apps/cli/src/chat.rs::run`) — see this task's own file for why that mirroring is load-bearing
// rather than a stylistic choice. **Deliberately opens and closes its own `SignalingClient`
// connection per dispatch**, unlike `OnboardingSession`'s held-open `Register` -> `PublishBundle`
// connection: this task's own file calls that out as a documented v1 simplification (avoids
// coupling to 4.35's persistent-connection design for the receive path), not a correctness gap.
//
// **`SendGate` is never consulted here.** `crate::screens::chat`'s own module doc names
// `dispatch_gated_send` as the *only* place in this whole crate that ever constructs
// `Effect::SendMessage`, and it does so only after `meridian_core::trust::TrustStore::can_send`
// already returned `SendGate::Ok` — this module has no `TrustStore` handle in scope anywhere below
// and must never acquire one just to re-derive that same decision (this task's own binding
// constraint: a second, possibly-drifting gate check here is exactly the class of defect the
// un-softenable key-change UI exists to prevent).
// ---------------------------------------------------------------------------

async fn handle_send_message(
    effect: SendMessageEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let SendMessageEffect { request, .. } = effect;
    match run_send_message(&request, session).await {
        Ok(sent) => WorkerEvent::Completed(Effect::SendMessage(SendMessageEffect {
            request,
            outcome: Some(sent),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::SendMessage(SendMessageEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Resolves the rendezvous server URL a chat effect should connect to. Unlike
/// [`RegisterRequest`]/`PublishBundleRequest` (onboarding-time effects the user types a server
/// into directly), [`SendMessageRequest`] carries no server field of its own — see that request's
/// own doc comment in `crate::app`. tui-client.md §5's `config.toml` template documents
/// `[account] server` as defaulting to "the value used at registration" — now a real fallback,
/// not just documented copy: [`handle_register`] persists that value onto `account.json`'s
/// [`AccountDescriptor::server`] the moment registration succeeds, and this function reads it back
/// whenever `config.toml` carries no override, matching the contract exactly.
///
/// Fails closed with an actionable message only when genuinely neither source has a value — an
/// `account.json` written before this field existed, or a file-backed/imported account that was
/// never registered through this worker (e.g. registered once through `meridian-cli` instead,
/// which has no equivalent persistence step of its own — see this module's own review notes).
///
/// Takes the caller's already-loaded [`AccountDescriptor`] rather than loading its own — the one
/// caller ([`run_send_message`]) already paid for `AccountDescriptor::load()` a few lines above
/// (to derive `account_pub`), so re-reading `account.json` here a second time would be a pointless
/// duplicate disk hit for the same file in the same call.
fn resolve_server(descriptor: &AccountDescriptor) -> Result<String, String> {
    let config = crate::config::load(&[]).map_err(|e| format!("loading config: {e}"))?;
    if let Some(server) = config.account.server {
        return Ok(server);
    }
    descriptor.server.clone().ok_or_else(|| {
        "no rendezvous server configured — set [account] server in config.toml before sending a \
         message"
            .to_string()
    })
}

/// Mirrors `apps/cli/src/chat.rs::send_text`'s exact seal-then-route sequence, plus the
/// first-send session establishment `apps/cli/src/chat.rs::run` performs before ever reaching
/// `send_text` — see this task's own file's "Required reading" list for both call sites this
/// mirrors line-for-line rather than reinvents.
///
/// **Mints `mid`/timestamp here, never in `crate::screens::chat`'s pure `update`** — exactly
/// [`SendMessageRequest`]'s own doc comment requires ([`getrandom::fill`] for the 128-bit id,
/// matching `crate::store::history::HistoryEntry::mid`'s shape; [`now_unix`] for the wall clock).
///
/// **Persistence ordering (review-anticipated).** `sessions.bin` is resealed and written twice on
/// the first-send path: once immediately after `start_initiator_session` succeeds (mirrors
/// `apps/cli/src/chat.rs::run`'s own `save_state` call right after establishing the session, line
/// 148 — a genuinely-established session must survive even if the seal/route step below then fails
/// for an unrelated reason), and again immediately after `seal_outbound` succeeds — **before**
/// `route_tolerant` is even attempted. `seal_outbound` already advanced the local ratchet chain the
/// moment it returned `Ok`, regardless of whether the peer is reachable right now, so that advance
/// is persisted unconditionally — never reused or replayed by a later retry — independent of the
/// delivery outcome `route_tolerant` reports next.
///
/// This is a deliberate **tightening** beyond the CLI's own ordering, not parity with it: the CLI's
/// outer loop (`apps/cli/src/chat.rs::run`, lines 180-212) only calls its own loop-body
/// `save_state` *after* the whole per-message call (`send_gated`, including the `route_tolerant`-
/// equivalent network round trip) has already returned — so the CLI's crash window spans the full
/// network call, while this worker's window is only the in-memory, synchronous ratchet advance
/// itself. A future reader comparing the two call sites should read this as the worker doing
/// strictly better, not as the two behaving identically.
///
/// **Task 4.35:** holds [`chat_state_lock`] for this whole function, including its network calls —
/// coarser than strictly necessary (only the disk load/mutate/save steps actually race with
/// `run_inbound_loop`'s own concurrent `sessions.bin` access), but a deliberate, documented v1
/// choice: this function only ever loads `chat` once at the top and mutates the same in-memory copy
/// across both save points, so releasing the lock in between would still let the persistent receive
/// loop's own save silently clobber whichever of the two writers finishes second. Holding it for the
/// whole call is the simplest way to make that impossible without restructuring this already-
/// reviewed function's control flow; a future task can narrow it if outbound-send/inbound-receive
/// contention ever becomes a real throughput problem.
async fn run_send_message(
    request: &SendMessageRequest,
    session: &OnboardingSession,
) -> Result<SentMessage, String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let _chat_guard = chat_state_lock().lock().await;
    let descriptor = AccountDescriptor::load()?;
    let account_pub = account_pub_bytes(&descriptor)?;
    let server = resolve_server(&descriptor)?;
    let peer_label =
        meridian_core::identity::to_id_string(&request.peer_pubkey, &request.peer_hint)
            .unwrap_or_else(|_| hex::encode(request.peer_pubkey));

    let mut chat = load_chat(store, handle)?;

    let mut client = SignalingClient::connect(&server, store, handle, account_pub, None, 1)
        .await
        .map_err(|e| format!("connecting to {server}: {e}"))?;

    // Role decided by key order (mirrors `apps/cli/src/chat.rs::run` exactly), so two peers who
    // both reach out establish exactly one X3DH session rather than racing two. A non-initiator
    // with no session yet has nothing to initiate here: `seal_outbound` below fails closed with
    // `ChatError::NoSession` in that case, exactly as the CLI's own loop simply buffers pending
    // text (`pending.push(text)`) rather than sending until a responder session arrives via an
    // inbound receive — this worker has no receive path to wait on (that's task 4.35), so it
    // reports the failure immediately instead of buffering silently.
    let initiator = account_pub.as_slice() <= request.peer_pubkey.as_slice();
    if initiator && !chat.has_session(&request.peer_pubkey) {
        let peer_bundle = fetch_with_retry(
            &mut client,
            request.peer_pubkey,
            &request.peer_hint,
            &peer_label,
        )
        .await?;
        chat.start_initiator_session(
            store,
            handle,
            &account_pub,
            &request.peer_pubkey,
            &peer_bundle.spk,
            peer_bundle.otks.first().copied(),
        )
        .map_err(|e| format!("establishing session: {e}"))?;
        save_chat(&chat, store, handle)?;
    }

    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    let blob = chat
        .seal_outbound(
            store,
            handle,
            &account_pub,
            &request.peer_pubkey,
            &ChatContent::Text {
                id,
                body: request.body.clone(),
            },
        )
        .map_err(|e| format!("sealing message: {e}"))?;
    save_chat(&chat, store, handle)?;

    let delivered = route_tolerant(
        &mut client,
        request.peer_pubkey,
        &request.peer_hint,
        blob,
        &peer_label,
    )
    .await;
    let _ = client.close().await;
    let delivered = delivered?;

    Ok(SentMessage {
        mid: hex::encode(id),
        ts: now_unix(),
        delivered,
    })
}

/// Sanitizes a routing hint before it is ever wrapped in `Some(..)` for
/// `SignalingClient::fetch_bundle`/`route_with_hint`: an empty-but-present hint must never be
/// forwarded as `Some(String::new())`. `meridian-rendezvous`'s own routing rule
/// (`handle_route`/`handle_fetch`, `apps/rendezvous/src/ws.rs`) treats *any* `Some` hint that
/// doesn't case-insensitively match its own domain as a foreign-server federation target — an
/// empty string never matches a real domain, so passing it through verbatim misroutes as a
/// federation attempt instead of a local delivery. A blank hint is exactly what
/// `run_accept_request` pins for a first-contact sender (`TrustStore::observe`'s own
/// "`MessageRequest` carries no advisory hint" contract), so this is not a hypothetical input —
/// every call site that builds a routing hint (auto-ack in [`process_inbound_delivery`],
/// [`fetch_with_retry`], [`route_tolerant`]) must run its hint through here so this class of bug
/// cannot recur at a fourth call site either.
fn sanitize_routing_hint(hint: &str) -> Option<String> {
    if hint.is_empty() {
        None
    } else {
        Some(hint.to_string())
    }
}

/// Fetch + verify the peer's bundle, retrying while the peer has not published yet — mirrors
/// `apps/cli/src/chat.rs::fetch_with_retry` exactly (same 40-attempt/250ms-backoff bound), minus
/// its `eprintln!` progress lines: this worker's [`WorkerEvent`] has only `Completed`/`Failed`, no
/// interim-progress variant to report through.
async fn fetch_with_retry(
    client: &mut SignalingClient,
    peer_ik: [u8; 32],
    peer_hint: &str,
    peer_label: &str,
) -> Result<meridian_core::proto::PrekeyBundle, String> {
    use meridian_core::signaling::SignalError;
    // Set once a `not_found_at_hint` is observed, so the final message — if every attempt
    // exhausts — can name the reachability-specific outcome instead of the generic "did not
    // publish" text used for a purely local `not_found`.
    let mut stale_hint = false;
    for _ in 0..40u32 {
        match client
            .fetch_bundle(peer_ik, sanitize_routing_hint(peer_hint), false)
            .await
        {
            Ok(bundle) => return Ok(bundle),
            // "not_found" (local): no bundle here yet — retry, the peer may publish soon.
            Err(SignalError::Server(e)) if e.code == "not_found" => {
                stale_hint = false;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            // `not_found_at_hint`: the hinted org doesn't hold this account — retry the same
            // bounded number of times as the local case, but report the distinct "unreachable at
            // hint" outcome below if every attempt exhausts this way (never a security warning).
            Err(SignalError::NotFoundAtHint { .. }) => {
                stale_hint = true;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            // `fed_denied`/`fed_unreachable` (and anything else): definitive policy/connectivity
            // outcomes, never retried.
            Err(e) => return Err(federation_error_line(&e, peer_label, "fetching")),
        }
    }
    if stale_hint {
        Err(format!(
            "{peer_label} unreachable at hint {peer_hint}: no account found there after \
             retrying — the hint may be stale (the peer may have re-registered elsewhere); this \
             is a reachability issue, never a security warning"
        ))
    } else {
        Err(format!("{peer_label} did not publish a bundle in time"))
    }
}

/// Render a definitive (non-retried) fetch/route failure as one diagnosable line — mirrors
/// `apps/cli/src/chat.rs::federation_error_line` exactly.
fn federation_error_line(
    e: &meridian_core::signaling::SignalError,
    peer_label: &str,
    action: &str,
) -> String {
    use meridian_core::signaling::SignalError;
    match e {
        SignalError::FedDenied { hint, detail } => format!(
            "federation denied: {hint} is not accepting requests for {peer_label} ({detail}) — \
             a policy outcome, not a security warning"
        ),
        SignalError::FedUnreachable { hint, detail } => format!(
            "{peer_label} unreachable at hint {hint}: could not reach that server ({detail})"
        ),
        other => format!("{action} {peer_label}: {other}"),
    }
}

/// Route a blob, treating a `not_connected` server reply as "not delivered" rather than a fatal
/// error — mirrors `apps/cli/src/chat.rs::route_tolerant` exactly: a momentarily-offline peer must
/// not be reported as a harder failure than it is (offline delivery is the T07 mailbox, out of
/// scope for this whole phase — see [`SentMessage`]'s own doc comment on what `delivered: false`
/// must never imply).
async fn route_tolerant(
    client: &mut SignalingClient,
    to: [u8; 32],
    hint: &str,
    blob: Vec<u8>,
    peer_label: &str,
) -> Result<bool, String> {
    use meridian_core::proto::error_codes::NOT_CONNECTED;
    use meridian_core::signaling::SignalError;
    match client
        .route_with_hint(to, sanitize_routing_hint(hint), blob)
        .await
    {
        Ok(delivered) => Ok(delivered),
        Err(SignalError::Server(e)) if e.code == NOT_CONNECTED => Ok(false),
        Err(e) => Err(federation_error_line(&e, peer_label, "routing message to")),
    }
}

// ---------------------------------------------------------------------------
// PersistHistory (task 4.33)
// ---------------------------------------------------------------------------

async fn handle_persist_history(
    effect: PersistHistoryEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let PersistHistoryEffect { request, .. } = effect;
    match run_persist_history(&request, session) {
        Ok(()) => WorkerEvent::Completed(Effect::PersistHistory(PersistHistoryEffect {
            request,
            outcome: Some(()),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::PersistHistory(PersistHistoryEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Appends `request.entry` to `request.peer_pubkey`'s sealed transcript — `crate::store::history::
/// append` (task 4.15), fresh `SecretStore`/`KeyHandle` via [`open_account_store`] like every other
/// handler in this module, never a request field (see [`PersistHistoryRequest`]'s own doc comment
/// in `crate::app`). The screen already deduped by `mid` before dispatching this effect
/// (`crate::screens::chat::insert_deduped`), so this appends unconditionally rather than
/// re-deriving that decision here.
fn run_persist_history(
    request: &PersistHistoryRequest,
    session: &OnboardingSession,
) -> Result<(), String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let peer_pubkey_hex = hex::encode(request.peer_pubkey);
    crate::store::history::append(&peer_pubkey_hex, &request.entry, store, handle)
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// LoadHistory (task 4.44) — the read half of PersistHistory above
// ---------------------------------------------------------------------------

async fn handle_load_history(
    effect: LoadHistoryEffect,
    session: &OnboardingSession,
) -> WorkerEvent {
    let LoadHistoryEffect { request, .. } = effect;
    match run_load_history(&request, session) {
        Ok(entries) => WorkerEvent::Completed(Effect::LoadHistory(LoadHistoryEffect {
            request,
            outcome: Some(entries),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::LoadHistory(LoadHistoryEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

/// Reads `request.peer_pubkey`'s whole sealed transcript — `crate::store::history::load_or_default`
/// (task 4.15), the **same** reader `crate::store::export` already uses, fresh `SecretStore`/
/// `KeyHandle` via [`open_account_store`] like every other handler in this module, never a request
/// field (mirrors [`run_persist_history`] exactly). Returns an empty transcript, not an error, if no
/// `history/<peer>.jsonl` exists yet for this peer — `load_or_default`'s own contract (a peer with no
/// prior conversation is not a failure).
fn run_load_history(
    request: &LoadHistoryRequest,
    session: &OnboardingSession,
) -> Result<Vec<crate::store::history::HistoryEntry>, String> {
    let account_store = open_account_store(session)?;
    let (store, handle) = account_store.parts();
    let peer_pubkey_hex = hex::encode(request.peer_pubkey);
    crate::store::history::load_or_default(&peer_pubkey_hex, store, handle)
        .map_err(|e| e.to_string())
}

/// Seals and writes `chat` to `sessions.bin` — mirrors [`save_trust`] (and
/// `apps/cli/src/chat.rs::save_state`) exactly.
fn save_chat(
    chat: &CoreChatState,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let path = account::sessions_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let sealed = chat
        .seal_at_rest(store, handle)
        .map_err(|e| format!("sealing session store: {e}"))?;
    std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Inbound delivery stream (task 4.35)
//
// The receive half of the T17 demo's "both sides chat" step — materially different from every
// other `Effect` this module executes: it is not dispatched by a screen at all. `crate::run_worker`
// spawns exactly one [`run_inbound_loop`] per session, immediately after a successful
// `Effect::LoadSession`/`Effect::Unlock` (see [`inbound_handoff`]), and holds it open — one
// persistent `SignalingClient`, never reconnected per message — for the rest of the process's life,
// forwarding decoded content onto the same worker→App channel as `crate::app::AppEvent::Inbound`.
//
// **Auto-ack, never gated by `SendGate`.** Mirrors `apps/cli/src/chat.rs::deliver_content`'s own
// auto-acknowledge exactly: a `ChatContent::Receipt` reply to an already-decrypted
// `ChatContent::Text` only ever acknowledges content the local user has already seen — it sends no
// new user-composed content, so withholding it behind `meridian_core::trust::TrustStore::can_send`
// would protect nothing an attacker doesn't already have and would just break the protocol's own
// liveness. [`process_inbound_delivery`] is the **only** place in this crate that ever constructs a
// `ChatContent::Receipt` reply, and it has no `TrustStore` handle in scope anywhere below to have
// gated it with even if it wanted to — the exemption is structural, not a bypassed check, and it is
// scoped exactly to this one reply-to-already-decrypted-`Text` case (see `run_worker_chat.rs`'s own
// "SendGate never consulted" precedent for the outbound side, and `tests/inbound_delivery.rs`'s own
// falsifiable version of this exact claim for the inbound side).
//
// **Adversarial input, never trusted.** Every envelope this loop decrypts came off the wire from
// whoever the rendezvous server claims routed it — `meridian_core::chat::ChatState::open_inbound`
// already verifies the envelope's signature and session state before this function ever sees a
// decoded `ChatContent`; anything that fails that (bad signature, sender mismatch, unknown prekey,
// no session, a ratchet desync, a malformed/truncated blob) is dropped, logged, and never crashes
// this loop or the app — mirrors `apps/cli/src/chat.rs::handle_inbound`'s own reject-loudly-never-
// trust catch-all exactly. Automatic desync recovery (task 4.9's receiver-side re-handshake) is
// deliberately **not** wired into this loop — out of this task's scope; a repeated desync from the
// same peer is simply dropped here, same as any other rejection, until a future task decides this
// loop should call `meridian_core::desync::attempt_recovery` too.
// ---------------------------------------------------------------------------

/// Serializes every load-mutate-save touch of `sessions.bin` across this worker task's two
/// concurrent consumers: the ordinary effect-dispatch loop (`run_send_message`/`run_accept_request`/
/// `run_reject_request`, all in this module) and [`run_inbound_loop`]'s own tokio task. Without this,
/// a `sessions.bin` write from one side could silently clobber a concurrent write from the other —
/// `sessions.bin` is a single serialized document covering every peer's session, not one file per
/// peer, so even two writes touching *different* peers' sessions still race on the same underlying
/// file. A plain `tokio::sync::Mutex` (never a blocking `std::sync::Mutex`, which `clippy::
/// await_holding_lock` correctly flags — [`run_send_message`] holds this guard across real network
/// `.await` points) behind a `OnceLock` so every call site in this module reaches the *same* lock
/// without threading a parameter through every function signature that already exists (this task's
/// own minimal-diff choice — see this module's own doc comment for why widening [`dispatch`]'s
/// signature was avoided).
fn chat_state_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// What [`crate::run_worker`] needs to spawn [`run_inbound_loop`] — see [`inbound_handoff`]'s own
/// doc comment for exactly when and how this is built.
///
/// **Deliberately carries two stores** (task 4.43), one per consumer, because their cost profiles
/// are opposites: `store` signs once per delivered envelope for the whole session, while
/// `bulk_signing_store` signs `1 + DEFAULT_OTK_COUNT` = 101 times in one burst and is then dropped.
/// See each field's own doc comment. This type deliberately has **no `Debug` impl at all**:
/// `Box<dyn SecretStore>` has no `Debug` supertrait, so a `#[derive(Debug)]` here would not compile
/// — a compile-time guarantee that neither store can ever be `{:?}`-dumped, stronger than the
/// hand-rolled redaction [`OnboardingSession`] needs (that type *is* `Debug`-reachable and so has
/// to redact by hand). Never log, `Debug`-print, or persist either field or the material it holds.
pub struct InboundHandoff {
    /// The **per-delivery** store [`run_inbound_loop`] is handed and keeps for the rest of the
    /// process's life. For a file-backed account this is the raw `FileSecretStore` — one age/scrypt
    /// unwrap per `use_key`/`derive_key`, which is the right trade for a loop that signs once per
    /// received envelope and would otherwise hold a raw seed resident forever. Unchanged by task
    /// 4.43: `run_inbound_loop`'s behavior is byte-for-byte as task 4.35 shipped it.
    pub store: Box<dyn SecretStore>,
    /// The **bulk-signing** store [`crate::run_worker`] hands to [`republish_bundle`] — the one
    /// call in this path that signs 101 times (1 SPK + `DEFAULT_OTK_COUNT` OTKs) plus the
    /// connect-time auth signature and `load_chat`/`save_chat`'s at-rest `derive_key`.
    ///
    /// - **File-backed** (`Effect::Unlock`): a [`MemorySecretStore`] whose seed was unwrapped
    ///   **once**, here, by [`unwrap_keyfile_for_bulk_signing`] — the exact mechanism onboarding's
    ///   own `Register`/`PublishBundle` pair already uses via [`open_store_for_bulk_signing`], and
    ///   the reason the 101-signature burst that took ~190 s through `store` above now costs
    ///   **~0.052 s** (O(1) scrypt vs. O(101); task 4.39 recorded the defect, task 4.41 measured it
    ///   live, task 4.43 closes it).
    /// - **OS-keystore** (`Effect::LoadSession`): a second [`OsSecretStore`] — free to construct,
    ///   no KDF per op, so the call site needs no branch.
    ///
    /// **Where a file-backed session start's remaining time actually goes (measured, task 4.43).**
    /// After the fix, completed-`Effect::Unlock` → `run_inbound_loop` spawn is ~1.45-1.92 s, and
    /// [`republish_bundle`] itself is only ~0.052 s of that — **~97% is the single age/scrypt
    /// unwrap this field's own construction performs** (`unwrap_keyfile_for_bulk_signing`, ~1.4-1.6 s
    /// at the shipped scrypt parameters). That one unwrap is the irreducible floor for a
    /// passphrase-wrapped keyfile — it is what scrypt is *for* — so a file-backed session start
    /// stays ~1.5-2 s regardless of what happens to the republish. A later task chasing residual
    /// file-backed latency (task 4.45) should not attribute it to the republish path.
    ///
    /// **Residency bound (load-bearing, not incidental).** For the file-backed case this is the
    /// only place in the process holding the *raw seed* rather than the passphrase, and
    /// [`crate::run_worker`] **drops it before spawning [`run_inbound_loop`]** — so `MemorySecretStore`'s
    /// `Zeroizing<Vec<u8>>` is zeroized at republish completion, not at process exit. Per the
    /// measurement above that is a residency of **~50 ms**, not the ~2 s the session start takes:
    /// the expensive part of that window is the unwrap that happens *before* this store exists.
    /// That bound is what makes this change a *reduction* in exposure (the same seed was previously
    /// materialized 101 times across ~190 s by `FileSecretStore::decrypt_seed`), and it is what
    /// task 4.43's own security rationale rests on — a future caller that keeps this alive longer,
    /// or hands it to `run_inbound_loop`, is making a materially different decision that needs its
    /// own security sign-off (that task's "The boundary").
    pub bulk_signing_store: Box<dyn SecretStore>,
    pub handle: KeyHandle,
    pub account_pub: [u8; 32],
    pub server: String,
}

/// Peeks (never consumes) a [`WorkerEvent`] fresh off [`dispatch`] and, only on a **successful**
/// `Effect::LoadSession`/`Effect::Unlock` that actually produced a live session, independently
/// re-derives the `SecretStore`/`KeyHandle`/`account_pub`/`server` [`crate::run_worker`] needs to
/// spawn the one persistent inbound loop for this session — the architect-approved lifecycle task
/// 4.35's own file names: "opened once at session-load time, held inside the worker task, never
/// re-derived per effect."
///
/// **Never touches the [`crate::session::LiveSession`] the successful effect actually carries** —
/// `crate::app::SessionOutcome` has no `Clone` (by design — see that type's own doc comment), and
/// `crate::run_worker`'s loop still has to forward the *whole*, unread `WorkerEvent` on to `App`
/// afterward exactly as task 4.29 left it (`crate::session`'s own "known gap" doc note: `App` does
/// not yet reclaim a `LiveSession` from this event at all — that reclaim is 4.36/4.37's job, not this
/// one's). Instead this re-derives its own, independent `SecretStore`: cheap for the OS-keystore
/// branch (no KDF), and for the file-backed branch reads the still-in-scope
/// `request.keyfile`/`request.passphrase` the very `WorkerEvent` being peeked already carries — never
/// persisted anywhere, never sent anywhere else, never crossing more than this one already-completed
/// round trip (this *is* that same round trip, just read a second time — [`UnlockRequest`]'s own "a
/// live passphrase must never cross more than one effect round trip" invariant is about not starting
/// a *new* round trip for it, which this does not).
///
/// Returns `None` (never a panic, never a fabricated handoff) for every other `WorkerEvent`, for a
/// failed load/unlock, for an OS-keystore/file-backed account this process cannot re-derive a store
/// for, or when [`resolve_server`] cannot resolve a rendezvous server yet (an account loaded/unlocked
/// but never registered through this or any worker that persisted `account.json`'s `server` field —
/// see that function's own doc comment). `TODO: confirm`: this last case means the persistent inbound
/// loop silently never starts rather than surfacing an error anywhere the user can see — no design
/// doc this task read specifies whether that should instead be a visible, named failure (e.g. a
/// dedicated `WorkerEvent`); flagged, not resolved, here.
pub fn inbound_handoff(event: &WorkerEvent) -> Option<InboundHandoff> {
    match event {
        WorkerEvent::Completed(Effect::LoadSession(LoadSessionEffect {
            outcome: Some(LoadSessionOutcome::Loaded(boxed)),
            ..
        })) if boxed.as_option().is_some() => {
            let descriptor = AccountDescriptor::load().ok()?;
            if descriptor.store != StoreKind::Os {
                return None;
            }
            init_os_keystore().ok()?;
            let service = descriptor
                .service
                .clone()
                .unwrap_or_else(|| OS_KEYSTORE_SERVICE.to_string());
            let handle = KeyHandle::from_label(&descriptor.label);
            let account_pub = account_pub_bytes(&descriptor).ok()?;
            let server = resolve_server(&descriptor).ok()?;
            Some(InboundHandoff {
                store: Box::new(OsSecretStore::new(&service)),
                // Task 4.43: a second, independent `OsSecretStore` for `republish_bundle`'s own
                // bulk signing. Free (no KDF, no passphrase held), so this branch needs no
                // unwrap-once treatment and is otherwise byte-for-byte unchanged.
                bulk_signing_store: Box::new(OsSecretStore::new(&service)),
                handle,
                account_pub,
                server,
            })
        }
        WorkerEvent::Completed(Effect::Unlock(boxed)) if boxed.outcome.as_option().is_some() => {
            let descriptor = AccountDescriptor::load().ok()?;
            let fs = FileSecretStore::new(&boxed.request.keyfile, boxed.request.passphrase.clone());
            let handle = KeyHandle::from_label(&descriptor.label);
            // Task 4.43: the one-time seed unwrap for `republish_bundle`'s 101 signatures, done
            // *here* because this is the last place the concrete `FileSecretStore` (and so the
            // inherent, deliberately-not-on-`SecretStore` `export_seed`) is still in scope — see
            // `InboundHandoff::bulk_signing_store`. Keyed by `descriptor.label`, the exact label
            // `handle` above carries, since `MemorySecretStore` looks up by label. Reads the same
            // already-completed round trip's `request.keyfile`/`request.passphrase` this function
            // already reads (see this function's own doc comment) — the passphrase is not threaded
            // any further down, and in particular never into `republish_bundle`.
            //
            // `None` on failure, like every other step here: an unwrap failure means this process
            // cannot decrypt the keyfile at all, so `store` above could not sign a delivery either
            // — a handoff built anyway would be a handoff that cannot work. (Unreachable in
            // practice: `run_unlock` already ran `export_seed` successfully against this exact
            // keyfile/passphrase moments earlier, in the very round trip being peeked.)
            let bulk_signing_store = unwrap_keyfile_for_bulk_signing(
                &boxed.request.keyfile,
                &boxed.request.passphrase,
                &descriptor.label,
            )
            .ok()?;
            let account_pub = account_pub_bytes(&descriptor).ok()?;
            let server = resolve_server(&descriptor).ok()?;
            Some(InboundHandoff {
                store: Box::new(fs),
                bulk_signing_store,
                handle,
                account_pub,
                server,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Prekey bundle republish + vault persistence (task 4.39, closing task 4.38's Defect A)
// ---------------------------------------------------------------------------

/// Republishes a fresh prekey bundle for this session and persists its secret scalars into
/// `sessions.bin`'s `PrekeyVault` — mirroring `apps/cli/src/chat.rs::run`'s exact connect ->
/// `publish_bundle` -> `state.vault.set_bundle(...)` -> save sequence, not a new one. Closes task
/// 4.38's Defect A: `crate::screens::onboarding`'s own `handle_publish_bundle` publishes a bundle
/// but never records the matching secrets anywhere a later `ChatState::open_inbound` could find
/// them, so — until now — no `meridian-tui` session ever had a code path that made a peer's
/// first-contact message decryptable at all; every genuine first envelope hit
/// `ChatError::UnknownPrekey` and was silently dropped (`worker::process_inbound_delivery`'s own
/// catch-all).
///
/// **Call site, deliberately separate from [`inbound_handoff`].** `crate::run_worker` calls this
/// once, immediately before `tokio::spawn(run_inbound_loop(..))`, guarded by the same one-shot
/// `inbound_started` flag that already ensures `run_inbound_loop` itself only spawns once per
/// session — so this also runs exactly once per session. It is its own async function, never
/// folded into [`inbound_handoff`], because that function is synchronous and documented as "never
/// a new round trip" (task 4.35) — widening its contract to cover a network round trip would break
/// that invariant for every other caller of `inbound_handoff` (today, only `crate::run_worker`,
/// but the doc comment's promise is about the function's own contract, not just its one caller).
///
/// Takes `store`/`handle`/`account_pub`/`server` by reference/value directly (the same shape
/// [`InboundHandoff`] carries) rather than an `&InboundHandoff`, so `crate::run_worker` can borrow
/// the store/handle for this call and *then* still move the rest of the `handoff` into
/// `run_inbound_loop` right after — see that call site's own comment.
///
/// **`store` must be a bulk-signing store — pass [`InboundHandoff::bulk_signing_store`], never
/// [`InboundHandoff::store`] (task 4.43).** This function performs `1 + DEFAULT_OTK_COUNT` = 101
/// real signatures, plus the connect-time auth signature and `load_chat`/`save_chat`'s at-rest
/// `derive_key`. A raw `FileSecretStore` runs a full age/scrypt unwrap on *every one* of those
/// calls, which is why a file-backed session start measured **194.5 s** here (and 188 s live in
/// task 4.41) before this task; an unwrap-once [`MemorySecretStore`] makes the same work O(1)
/// scrypt. Both stores derive from the same Ed25519 seed and
/// `derive_key_from_seed(seed, info)` is identical for both, so the resealed `sessions.bin` stays
/// readable by every other handler's `FileSecretStore` path — a store swap, not a format change.
/// `crate::run_worker` drops the bulk store immediately after this call returns, before
/// `run_inbound_loop` is spawned; nothing here retains it.
///
/// **Failure UX (`TODO: confirm` — no design doc this task read specifies visible-status vs.
/// log-only for a failed republish):** logged to stderr and otherwise swallowed by the caller,
/// which spawns `run_inbound_loop` regardless of the `Result` this returns. A transient failure
/// here (e.g. a momentary network hiccup right at session start) must not block the persistent
/// receive loop from starting at all — the loop still serves already-established sessions and
/// ordinary replies just fine without a fresh bundle; only a *new* first-contact peer is affected,
/// and onboarding's own bundle (unpersisted secrets aside) is still live on the server in this
/// failure case, not absent. This task's own file explicitly rules out inventing a new screen or
/// `Effect` to surface this more richly, so a swallowed, logged failure is the considered choice
/// here, not an oversight.
pub async fn republish_bundle(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: [u8; 32],
    server: &str,
) -> Result<(), String> {
    let mut client = SignalingClient::connect(server, store, handle, account_pub, None, 1)
        .await
        .map_err(|e| format!("connecting to {server}: {e}"))?;

    let generated = client
        .publish_bundle(store, handle, DEFAULT_OTK_COUNT)
        .await
        .map_err(|e| format!("publishing bundle: {e}"));
    // Best-effort graceful close either way — mirrors `handle_publish_bundle`'s own
    // `let _ = client.close().await` on its success path; this one-shot connection is never reused
    // across calls (unlike `OnboardingSession`'s cached `Register` -> `PublishBundle` connection),
    // so there is nothing to keep open regardless of outcome.
    let generated = match generated {
        Ok(g) => g,
        Err(e) => {
            let _ = client.close().await;
            return Err(e);
        }
    };

    let otks: Vec<([u8; 32], [u8; 32])> = generated
        .bundle
        .otks
        .iter()
        .zip(generated.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();

    // Task 4.35: hold `chat_state_lock` for the whole load-mutate-save `sessions.bin` sequence,
    // same as every other handler in this module that touches it — `run_inbound_loop`'s own task
    // may be racing this exact file (it is not spawned until *after* this call returns, per
    // `crate::run_worker`'s own ordering, but a defensive same-lock discipline here costs nothing
    // and keeps this function correct even if a future caller ever changes that ordering).
    let result = {
        let _chat_guard = chat_state_lock().lock().await;
        match load_chat(store, handle) {
            Ok(mut chat) => {
                chat.vault.set_bundle(
                    generated.bundle.spk,
                    *generated.spk_secret,
                    otks,
                    now_unix(),
                );
                save_chat(&chat, store, handle)
            }
            Err(e) => Err(e),
        }
    };

    let _ = client.close().await;
    result
}

/// The persistent inbound-delivery loop itself (task 4.35) — see this section's own module doc for
/// the full design. Reconnects with backoff (`backoff_ms`, `config.toml`'s
/// `[network] reconnect_backoff_ms`) on any connection-level failure, surfacing
/// `crate::app::AppEvent::ConnectionStatus` transitions along the way (tui-client.md §7's
/// `● reconnecting (n/m)` contract) — the architect's own condition for approving this task: this
/// loop must never go silently deaf for the rest of the session after its first drop. Returns only
/// when `replies` itself fails to send (the app side hung up, e.g. `meridian tui` exited) — every
/// other failure just reconnects, forever, at the last configured backoff step once `backoff_ms` is
/// exhausted.
pub async fn run_inbound_loop(
    store: Box<dyn SecretStore>,
    handle: KeyHandle,
    account_pub: [u8; 32],
    server: String,
    backoff_ms: Vec<u64>,
    replies: mpsc::UnboundedSender<crate::app::AppEvent>,
) {
    use crate::app::AppEvent;
    use crate::statusbar::ConnectionState;

    let backoff: Vec<u64> = if backoff_ms.is_empty() {
        vec![500, 1000, 2000, 5000, 15000]
    } else {
        backoff_ms
    };
    let mut attempt: u32 = 0;

    loop {
        match SignalingClient::connect(&server, store.as_ref(), &handle, account_pub, None, 1).await
        {
            Ok(mut client) => {
                attempt = 0;
                if replies
                    .send(AppEvent::ConnectionStatus(ConnectionState::Connected))
                    .is_err()
                {
                    return;
                }
                // A connection-level failure (the socket dropped, the server went away, a framing
                // error) simply ends this `while let`, falling through to the reconnect logic below
                // — never crashes this loop, mirrors every other network call site in this module.
                while let Ok(deliver) = client.next_deliver().await {
                    if let Some(event) = process_inbound_delivery(
                        store.as_ref(),
                        &handle,
                        &account_pub,
                        &mut client,
                        &deliver,
                    )
                    .await
                    {
                        if replies.send(AppEvent::Inbound(Box::new(event))).is_err() {
                            return;
                        }
                    }
                }
            }
            // Could not even connect this attempt — same reconnect handling as a mid-session drop.
            Err(_e) => {}
        }

        let idx = (attempt as usize).min(backoff.len() - 1);
        let delay_ms = backoff[idx];
        attempt = attempt.saturating_add(1);
        let shown_attempt = attempt.min(backoff.len() as u32);
        if replies
            .send(AppEvent::ConnectionStatus(ConnectionState::Reconnecting {
                attempt: shown_attempt,
                max: backoff.len() as u32,
            }))
            .is_err()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
}

/// Decrypts one delivered envelope and turns it into (at most) one [`crate::app::InboundEvent`] —
/// [`run_inbound_loop`]'s own per-message body, factored out so it can be exercised directly by
/// `tests/inbound_delivery.rs` without spinning up the whole reconnect loop. Always holds
/// [`chat_state_lock`] for the whole load-open-save sequence (see that function's own doc comment),
/// and always attempts [`save_chat`] before returning — a `sessions.bin` mutation
/// (`open_inbound`/`open_inbound_gated` installing a session, consuming a one-time prekey, queuing a
/// message request, advancing a ratchet chain) must survive even when the specific content is
/// ultimately not forwarded to `App` (e.g. a `ChatError::RequestPending` re-send, or a `Receipt`).
async fn process_inbound_delivery(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    account_pub: &[u8; 32],
    client: &mut SignalingClient,
    deliver: &meridian_core::proto::Deliver,
) -> Option<crate::app::InboundEvent> {
    use crate::app::InboundEvent;
    use crate::store::history::{Direction as HistDirection, HistoryEntry, MessageState};

    let _chat_guard = chat_state_lock().lock().await;

    // A `sessions.bin` that fails to load (corrupt, wrong key) is a hard local problem, not
    // something this envelope caused — drop this one delivery rather than crash the loop; the next
    // successful delivery gets exactly the same chance. Mirrors every other handler's fail-closed
    // `load_chat`/`load_trust` contract in this module.
    let mut chat = match load_chat(store, handle) {
        Ok(chat) => chat,
        Err(e) => {
            eprintln!("meridian tui: could not load sessions.bin for an inbound envelope: {e}");
            return None;
        }
    };
    chat.expire_previous_generation(now_unix());

    let event = match chat.open_inbound(
        store,
        handle,
        account_pub,
        &deliver.from,
        deliver.blob.as_bytes(),
    ) {
        Ok(ChatContent::Text { id, body }) => {
            // Auto-ack (never gated by `SendGate` — see this section's own module doc). Best-effort:
            // a failed seal or a failed route must not stop the message itself from being delivered
            // to the user, so neither is treated as fatal to this whole delivery.
            if let Ok(receipt_blob) = chat.seal_outbound(
                store,
                handle,
                account_pub,
                &deliver.from,
                &ChatContent::Receipt { ack: id },
            ) {
                // Runs the looked-up hint through the same [`sanitize_routing_hint`] every other
                // routing-hint call site uses — see that function's own doc comment for why an
                // empty-but-present hint must never be forwarded verbatim.
                let hint = load_trust(store, handle)
                    .ok()
                    .and_then(|t| t.contact(&deliver.from).map(|c| c.hint.clone()))
                    .and_then(|h| sanitize_routing_hint(&h));
                let _ = client
                    .route_with_hint(deliver.from, hint, receipt_blob)
                    .await;
            }
            Some(InboundEvent::Message {
                peer_pubkey: deliver.from,
                entry: HistoryEntry {
                    v: crate::store::history::CURRENT_VERSION,
                    mid: hex::encode(id),
                    dir: HistDirection::In,
                    ts: now_unix(),
                    stream: "mrd.chat/1".to_string(),
                    body,
                    state: MessageState::Received,
                },
            })
        }
        Ok(ChatContent::Receipt { ack }) => Some(InboundEvent::Receipt {
            peer_pubkey: deliver.from,
            ack: hex::encode(ack),
        }),
        // First contact (task 2.10, §3.5) — gated, never auto-delivered. `open_inbound` already
        // installed the pending request into `chat` itself; read it back to build the display copy.
        Err(ChatError::MessageRequest) => chat.pending_request(&deliver.from).map(|req| {
            InboundEvent::MessageRequest(crate::screens::requests::RequestEntry::from(req))
        }),
        // Everything else — `RequestPending`, `Desync`, `BadSignature`, `SenderMismatch`,
        // `UnknownPrekey`, `NoSession`, a codec/crypto/store error — dropped, logged, never trusted.
        // Mirrors `apps/cli/src/chat.rs::handle_inbound`'s own reject-loudly-never-trust catch-all
        // exactly (this section's own module doc). Automatic desync recovery is deliberately not
        // wired into this loop — out of this task's scope.
        Err(e) => {
            eprintln!("meridian tui: dropped an inbound envelope: {e}");
            None
        }
    };

    if let Err(e) = save_chat(&chat, store, handle) {
        eprintln!("meridian tui: could not persist sessions.bin after an inbound envelope: {e}");
    }

    event
}

// ---------------------------------------------------------------------------
// Settings write-back / diagnostics (task 4.34)
//
// Both handlers below are pure wiring onto already-built, already-reviewed functions — see this
// task's own file. Neither derives a `SecretStore`/`KeyHandle` via `open_account_store` the way
// every contacts/chat handler above does: both `SaveSettingRequest`/`RunDoctorRequest` carry every
// input their underlying function needs directly (`config_path`/`value`; `binary`), exactly like
// `UnlockRequest::keyfile` — see those requests' own doc comments in `crate::app`.
// ---------------------------------------------------------------------------

// --- SaveSetting -----------------------------------------------------------------------------

async fn handle_save_setting(effect: SaveSettingEffect) -> WorkerEvent {
    let SaveSettingEffect { request, .. } = effect;
    match crate::config_write::write_setting_at(&request.config_path, &request.value) {
        Ok(()) => WorkerEvent::Completed(Effect::SaveSetting(SaveSettingEffect {
            request,
            outcome: Some(()),
        })),
        // `ConfigWriteError` (`NoFile`/`Malformed`/`NotATable`/`Io`) is surfaced verbatim via its
        // own `Display` impl — every one of those variants is already an honest, named refusal
        // (see `crate::config_write`'s own module doc), never a silent no-op; this handler adds no
        // softening on top.
        Err(e) => WorkerEvent::Failed(
            Effect::SaveSetting(SaveSettingEffect {
                request,
                outcome: None,
            }),
            e.to_string(),
        ),
    }
}

// --- RunDoctor ---------------------------------------------------------------------------------

/// **Not this crate's protocol logic** — mirrors `crate::screens::diagnostics`'s own module doc:
/// invokes the already-built `meridian doctor --json` binary as a subprocess and treats its
/// captured stdout as opaque data (`run_doctor_binary` already parses it internally via
/// `parse_doctor_json`, so this handler has nothing left to do beyond propagating that one
/// `Result` faithfully). A missing binary on `PATH`, a non-zero exit, or an unparseable line are
/// each an honest, named `Err(String)` already — see that function's own doc comment for exactly
/// which message each produces — never a silent no-op or a fabricated empty report.
async fn handle_run_doctor(effect: RunDoctorEffect) -> WorkerEvent {
    let RunDoctorEffect { request, .. } = effect;
    match crate::screens::diagnostics::run_doctor_binary(&request.binary) {
        Ok(report) => WorkerEvent::Completed(Effect::RunDoctor(RunDoctorEffect {
            request,
            outcome: Some(report),
        })),
        Err(message) => WorkerEvent::Failed(
            Effect::RunDoctor(RunDoctorEffect {
                request,
                outcome: None,
            }),
            message,
        ),
    }
}

// ---------------------------------------------------------------------------
// Shared sealed-store loading — used by both `handle_unlock` and `handle_load_session`, which
// differ only in how `store`/`handle` were obtained (a live passphrase vs. the OS keystore), never
// in how the sealed state itself is opened.
// ---------------------------------------------------------------------------

/// Loads `trust.bin`/`sessions.bin`/`contacts.json` for an already-resolved `store`/`handle` pair
/// into a real [`LiveSession`]. Every one of the three sealed/cached stores defaults (never errors)
/// when its file is simply absent — the legitimate "nothing sealed here yet" case, exactly
/// [`TrustStore::open_at_rest`]/`ChatState::open_at_rest`'s own callers already handle at
/// `apps/core/src/account.rs`'s paths elsewhere in this crate (`crate::store::contacts::
/// load_or_default_at`'s identical "`NotFound` -> default, anything else -> error" shape) — but a
/// file that exists and fails to open (wrong key, corrupt bytes) is a hard error, never silently
/// swallowed into a fresh/empty store: that would erase real TOFU pinned-key history / ratchet
/// state, exactly the failure mode `TrustStore::open_at_rest`'s own doc comment calls out (ADR 0021
/// condition 5b).
fn load_live_session(
    descriptor: AccountDescriptor,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<LiveSession, String> {
    let trust = load_trust(store, handle)?;
    let chat = load_chat(store, handle)?;
    let contacts =
        crate::store::contacts::load_or_default(store, handle).map_err(|e| e.to_string())?;
    Ok(LiveSession {
        account: descriptor,
        trust,
        chat,
        contacts,
    })
}

fn load_trust(store: &dyn SecretStore, handle: &KeyHandle) -> Result<TrustStore, String> {
    let path = account::trust_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => TrustStore::open_at_rest(store, handle, &bytes).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn load_chat(store: &dyn SecretStore, handle: &KeyHandle) -> Result<CoreChatState, String> {
    let path = account::sessions_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => CoreChatState::open_at_rest(store, handle, &bytes).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CoreChatState::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// Store construction
// ---------------------------------------------------------------------------

/// Opens a secret store for one-off use — mirrors `apps/cli/src/main.rs::cmd_new`'s direct
/// `FileSecretStore`/`OsSecretStore` construction. **Not** for bulk signing (repeatedly re-deriving
/// a passphrase-wrapped seed via scrypt is expensive); see [`open_store_for_bulk_signing`], which
/// [`handle_register`] actually calls (even for its own single connect-time signature, since the
/// same unwrapped store is cached for [`handle_publish_bundle`]'s later bulk signing) and which
/// delegates back to this function only for the OS-keystore branch, which has no such cost to avoid.
fn open_store(store: &StoreChoice) -> Result<Box<dyn SecretStore>, String> {
    match store {
        StoreChoice::Os => {
            init_os_keystore()?;
            Ok(Box::new(OsSecretStore::new(OS_KEYSTORE_SERVICE)))
        }
        StoreChoice::File { passphrase } => {
            let keyfile = default_keyfile_path()?;
            Ok(Box::new(FileSecretStore::new(&keyfile, passphrase.clone())))
        }
    }
}

/// Opens a secret store for bulk signing — publishing a bundle signs `1 + otk_count` times
/// (`DEFAULT_OTK_COUNT` = 100). Mirrors `apps/cli/src/main.rs::load_store`'s own doc comment
/// exactly: for a passphrase keyfile, unwrap the scrypt-wrapped seed **once** into a
/// `MemorySecretStore` rather than re-running scrypt key derivation on every signature (which would
/// take minutes for 100 prekeys) — O(1) scrypt work instead of O(prekeys). The OS-keystore branch
/// needs no such optimization (it signs per-op with no KDF), so it delegates straight to
/// [`open_store`].
///
/// [`handle_register`] calls this (not [`open_store`] directly) for its own single connect-time
/// signature too, and caches the resulting store in [`OnboardingSession`] for [`handle_publish_bundle`]
/// to reuse — exactly `apps/cli/src/main.rs::load_store`'s own call pattern (`cmd_register` unwraps
/// once via `load_store` and reuses that one object for both the connect signature and every
/// `publish_bundle` signature), rather than this worker paying a second, redundant scrypt unwrap for
/// the same keyfile across its two separately-dispatched effects.
fn open_store_for_bulk_signing(
    store: &StoreChoice,
    label: &str,
) -> Result<Box<dyn SecretStore>, String> {
    match store {
        StoreChoice::Os => open_store(store),
        // Onboarding never asks for a custom keyfile path (see `default_keyfile_path`'s own doc
        // comment), so this branch resolves the default one and delegates — one implementation of
        // the unwrap-once dance, shared with `inbound_handoff`, never two copies that could drift.
        StoreChoice::File { passphrase } => {
            let keyfile = default_keyfile_path()?;
            unwrap_keyfile_for_bulk_signing(&keyfile, passphrase, label)
        }
    }
}

/// The unwrap-**once** core of [`open_store_for_bulk_signing`]'s `StoreChoice::File` branch, split
/// out (task 4.43) so the one other call site that needs exactly this — [`inbound_handoff`]'s own
/// `Effect::Unlock` arm, which holds a caller-supplied `request.keyfile` rather than
/// [`default_keyfile_path`]'s default — shares this implementation instead of copying it.
///
/// Reads the age/scrypt keyfile at `keyfile` with `passphrase`, extracts the seed **once**
/// (`FileSecretStore::export_seed`), and hands back a [`MemorySecretStore`] holding it under
/// `label`. Every subsequent `use_key`/`derive_key` is then a `HashMap` lookup plus the op — O(1)
/// scrypt work for the whole caller, instead of the O(n) `FileSecretStore` pays (its `use_key` and
/// `derive_key` each call `decrypt_seed()` — a full age/scrypt unwrap — on *every single call*).
///
/// **Key residency, deliberately bounded by the caller.** The returned store holds the raw seed in
/// a `Zeroizing<Vec<u8>>`, zeroized the moment it drops — so how long that material stays resident
/// is exactly how long the caller keeps the box. Both callers keep it for one bounded burst of
/// work: onboarding's `Register` -> `PublishBundle` pair (via [`OnboardingSession`]'s cache) and
/// [`crate::run_worker`]'s single [`republish_bundle`] call, which drops it *before* spawning
/// [`run_inbound_loop`] (task 4.43's own security bound — see [`InboundHandoff::bulk_signing_store`]).
/// Never log, `Debug`-print, or persist the returned store or the seed it wraps.
///
/// `label` must be the same label the caller's [`KeyHandle`] carries: `MemorySecretStore::store`
/// keys by label, and its `use_key`/`derive_key` look up by `h.label` — a mismatch fails closed
/// with `StoreError::NotFound`, never a wrong-key signature.
fn unwrap_keyfile_for_bulk_signing(
    keyfile: &Path,
    passphrase: &str,
    label: &str,
) -> Result<Box<dyn SecretStore>, String> {
    let fs = FileSecretStore::new(keyfile, passphrase);
    let seed = fs.export_seed().map_err(|e| e.to_string())?;
    let mem = MemorySecretStore::new();
    mem.store(label, seed.as_slice())
        .map_err(|e| e.to_string())?;
    Ok(Box::new(mem))
}

// ---------------------------------------------------------------------------
// Unit tests for the shared sealed-store loading logic (task 4.29).
//
// `load_trust`/`load_chat`/`load_live_session`/`run_load_session` are private to this module, so
// their own defaulting/fail-closed contracts are proven here directly, against a `MemorySecretStore`
// (no real keystore access, no scrypt cost) rather than through `dispatch`'s public surface — the
// `StoreChoice::Os`-shaped end-to-end path is deliberately not exercised anywhere in this crate's
// test suite (see `apps/tui/tests/run_worker_account.rs`'s own module doc: "needs a real platform
// credential store ... which a headless CI runner does not have"); this module's own `MemorySecretStore`
// stands in for exactly the part of that path (`load_live_session` and everything it calls) that is
// actually shared with the `OsSecretStore`-backed branch — the only thing genuinely untestable
// headlessly is the `keyring`-backed `OsSecretStore::new`/`init_os_keystore` glue itself, which this
// module's own `run_load_session` keeps to a thin, single, easily-audited branch (see that function's
// body) precisely so the untestable surface stays that small.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::identity::generate_account;
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        prev_home: Option<String>,
    }

    impl EnvGuard {
        fn set(dir: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev_home = std::env::var("MERIDIAN_HOME").ok();
            // SAFETY: serialized by ENV_LOCK, the only place in this test module touching this var.
            unsafe {
                std::env::set_var("MERIDIAN_HOME", dir);
            }
            Self {
                _lock: lock,
                prev_home,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: see `EnvGuard::set`.
            unsafe {
                match &self.prev_home {
                    Some(v) => std::env::set_var("MERIDIAN_HOME", v),
                    None => std::env::remove_var("MERIDIAN_HOME"),
                }
            }
        }
    }

    fn store_and_handle() -> (MemorySecretStore, KeyHandle) {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, "example.org").expect("generate_account");
        (store, account.handle().clone())
    }

    fn dummy_descriptor() -> AccountDescriptor {
        AccountDescriptor {
            v: 1,
            pubkey: "a".repeat(64),
            hint: "example.org".to_string(),
            store: StoreKind::Os,
            keyfile: None,
            service: Some(OS_KEYSTORE_SERVICE.to_string()),
            label: "a".repeat(64),
            server: None,
        }
    }

    fn dummy_file_descriptor(keyfile: &Path) -> AccountDescriptor {
        AccountDescriptor {
            v: 1,
            pubkey: "b".repeat(64),
            hint: "example.org".to_string(),
            store: StoreKind::File,
            keyfile: Some(keyfile.to_path_buf()),
            service: None,
            label: "b".repeat(64),
            server: None,
        }
    }

    // -----------------------------------------------------------------------------------------
    // Task 4.40 — `OnboardingSession::live_store` (binding modifications 6 and 7)
    // -----------------------------------------------------------------------------------------

    /// Binding modification 6: the host struct (`OnboardingSession`), not just `Box<dyn
    /// SecretStore>` itself, must never leak the cached store's real contents through `Debug` —
    /// mirrors `crate::session::LiveSession`'s own `debug_never_leaks_chat_session_internals` test
    /// exactly, just against the field this task added.
    #[test]
    fn onboarding_session_debug_never_leaks_the_live_store() {
        let store: Box<dyn SecretStore> = Box::new(MemorySecretStore::new());
        let handle = KeyHandle::from_label("deadbeef");
        let mut session = OnboardingSession::default();
        session.set_live_store(store, handle);

        let dump = format!("{session:?}");
        assert!(dump.contains("redacted"), "dump: {dump}");
        // Never shows any real `SecretStore` implementor's name/state — only the fixed marker.
        assert!(!dump.contains("MemorySecretStore"));
        assert!(!dump.contains("FileSecretStore"));
    }

    /// A `SecretStore` double whose sole job is proving *how many times it was constructed* — the
    /// correct proxy (see this test's own doc comment below) for "no second `FileSecretStore`
    /// construction / no second `Effect::Unlock` passphrase round-trip" (not "no second scrypt/
    /// age-decrypt" — that KDF cost is paid on every legitimate `use_key`/`derive_key` call
    /// regardless of caching, per `use_key`'s own doc comment below; what this cache actually saves
    /// is the round trip, not the per-call KDF work), binding modification 7's own required negative
    /// assertion. Delegates every real trait method
    /// to a wrapped [`MemorySecretStore`] so a session built around this double can still do real,
    /// successful sealed-store round trips (`load_trust`/`save_trust`/…) — this is not a stub that
    /// merely compiles, it is a store the twelve handlers can genuinely operate against.
    struct CountingStore {
        inner: MemorySecretStore,
    }

    impl CountingStore {
        /// Increments `constructions` once, here, at construction time — mirroring exactly where a
        /// real `FileSecretStore`'s own one-time passphrase-verification cost
        /// (`FileSecretStore::export_seed`, called once by [`run_unlock`]) is actually paid in
        /// production. `use_key`/`derive_key` are deliberately **not** instrumented: real sealed-
        /// store operations (`seal_at_rest`/`open_at_rest`) call those on *every* dispatch
        /// regardless of caching — that is expected, unavoidable work, not the regression this test
        /// exists to catch. Counting constructions is the one observable that actually
        /// distinguishes "the same cached store object is reused across dispatches" (this task's
        /// fix) from "a fresh store was silently rebuilt — and its passphrase silently
        /// re-verified — on every dispatch" (the regression this test rules out).
        ///
        /// Takes an already-seeded `inner` (rather than building an empty one) so the twelve
        /// handlers this test drives against it can do real, successful sealed-store round trips —
        /// `derive_key`/`use_key` both fail closed against a label with nothing stored under it.
        fn new(
            inner: MemorySecretStore,
            constructions: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ) -> Self {
            constructions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Self { inner }
        }
    }

    impl SecretStore for CountingStore {
        fn store(
            &self,
            label: &str,
            secret: &[u8],
        ) -> std::result::Result<KeyHandle, meridian_core::identity::StoreError> {
            self.inner.store(label, secret)
        }

        fn use_key(
            &self,
            h: &KeyHandle,
            op: meridian_core::identity::SignOrDh,
            input: &[u8],
        ) -> std::result::Result<Vec<u8>, meridian_core::identity::StoreError> {
            self.inner.use_key(h, op, input)
        }

        fn nonextractable(&self) -> bool {
            self.inner.nonextractable()
        }

        fn derive_key(
            &self,
            h: &KeyHandle,
            info: &[u8],
        ) -> std::result::Result<[u8; 32], meridian_core::identity::StoreError> {
            self.inner.derive_key(h, info)
        }
    }

    /// Binding modification 7: proves a **second, later dispatch reuses the cache** — a real
    /// negative assertion (an instrumented, construction-counting `SecretStore` double), not just
    /// "the operation succeeded twice." Populates `session.live_store` directly (bypassing a real
    /// `Effect::Unlock` round trip, which always constructs its own genuine `FileSecretStore` and
    /// therefore could never observe this) and drives two *different* handler dispatches
    /// (`run_add_contact` then `run_set_petname`) against the same `session` — both must succeed,
    /// and [`CountingStore::new`] must never have run a second time.
    #[test]
    fn open_account_store_reuses_the_cached_file_backed_store_never_rebuilding_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let keyfile = tmp.path().join("account.key");
        let seeded = MemorySecretStore::new();
        let account = generate_account(&seeded, "example.org").expect("generate_account");
        dummy_file_descriptor(&keyfile)
            .save()
            .expect("save account.json");

        let constructions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handle = account.handle().clone();
        let mut session = OnboardingSession::default();
        session.set_live_store(Box::new(CountingStore::new(seeded, &constructions)), handle);
        assert_eq!(
            constructions.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "constructed exactly once, simulating handle_unlock's own single populate-time build"
        );

        let add_request = AddContactRequest {
            id: "peer".to_string(),
            pubkey: [9u8; 32],
            hint: "peer.example".to_string(),
            petname: None,
        };
        run_add_contact(&add_request, &session).expect("run_add_contact against the cached store");
        assert_eq!(
            constructions.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the first later dispatch must reuse the cache, never rebuild the store"
        );

        let petname_request = SetPetnameRequest {
            pubkey: [9u8; 32],
            petname: Some("bff".to_string()),
        };
        run_set_petname(&petname_request, &session)
            .expect("run_set_petname against the same cached store");
        assert_eq!(
            constructions.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a second, later dispatch of a *different* handler must still reuse the same cache"
        );
    }

    #[test]
    fn load_trust_defaults_to_empty_when_trust_bin_is_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let (store, handle) = store_and_handle();

        let trust = load_trust(&store, &handle).expect("no trust.bin yet -> default, not error");
        assert_eq!(trust.contacts().count(), 0);
    }

    #[test]
    fn load_trust_fails_closed_on_corrupt_bytes_never_silently_reinitializes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let (store, handle) = store_and_handle();

        let path = account::trust_path().expect("trust_path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a real sealed trust store").unwrap();

        let err = load_trust(&store, &handle).expect_err("corrupt trust.bin must be a hard error");
        assert!(!err.is_empty());
    }

    #[test]
    fn load_trust_fails_closed_under_the_wrong_key() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let (store, handle) = store_and_handle();
        let mut trust = TrustStore::default();
        trust.observe([7u8; 32], "peer.example", 1_760_000_000);
        let sealed = trust.seal_at_rest(&store, &handle).expect("seal trust.bin");
        let path = account::trust_path().expect("trust_path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, sealed).unwrap();

        // A different account's store/handle must never open it.
        let (wrong_store, wrong_handle) = store_and_handle();
        let err = load_trust(&wrong_store, &wrong_handle)
            .expect_err("trust.bin sealed under a different key must fail closed");
        assert!(!err.is_empty());
    }

    #[test]
    fn load_chat_defaults_to_empty_when_sessions_bin_is_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let (store, handle) = store_and_handle();

        let chat = load_chat(&store, &handle).expect("no sessions.bin yet -> default, not error");
        assert!(!chat.has_session(&[0u8; 32]));
    }

    #[test]
    fn load_chat_fails_closed_on_corrupt_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let (store, handle) = store_and_handle();

        let path = account::sessions_path().expect("sessions_path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a real sealed chat state").unwrap();

        match load_chat(&store, &handle) {
            Err(err) => assert!(!err.is_empty()),
            Ok(_) => panic!("corrupt sessions.bin must be a hard error, not a silent default"),
        }
    }

    #[test]
    fn load_live_session_round_trips_real_sealed_trust_and_contacts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let (store, handle) = store_and_handle();

        let mut trust = TrustStore::default();
        trust.observe([9u8; 32], "peer.example", 1_760_000_000);
        let trust_sealed = trust.seal_at_rest(&store, &handle).expect("seal trust.bin");
        let trust_path = account::trust_path().expect("trust_path");
        std::fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
        std::fs::write(&trust_path, trust_sealed).unwrap();

        let doc = crate::store::contacts::ContactsDocument {
            v: crate::store::contacts::CURRENT_VERSION,
            contacts: Vec::new(),
        };
        crate::store::contacts::save(&doc, &store, &handle).expect("save contacts.json");

        let session =
            load_live_session(dummy_descriptor(), &store, &handle).expect("load_live_session");
        assert_eq!(session.trust.contacts().count(), 1);
        assert!(session.trust.contact(&[9u8; 32]).is_some());
        assert!(!session.chat.has_session(&[0u8; 32]));
        assert!(session.contacts.contacts.is_empty());
    }

    #[test]
    fn run_load_session_returns_no_account_when_account_json_is_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());

        match run_load_session().expect("a pristine MERIDIAN_HOME is not an error") {
            LoadSessionOutcome::NoAccount => {}
            other => panic!("expected NoAccount, got {other:?}"),
        }
    }

    #[test]
    fn run_load_session_fails_closed_for_a_file_backed_account_never_touching_the_os_keystore() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        let keyfile = tmp.path().join("account.key");
        let fs = FileSecretStore::new(&keyfile, "does-not-matter");
        let account = generate_account(&fs, "example.org").expect("generate_account");
        AccountDescriptor::new_file(&account, &keyfile)
            .save()
            .expect("save account.json");

        let err = run_load_session()
            .expect_err("a file-backed account.json must never load through LoadSession");
        assert!(err.contains("Unlock"));
    }

    /// Review fix (task 4.29, Finding 4): the symmetric guard on `run_unlock`, mirroring the test
    /// immediately above (`run_load_session_fails_closed_for_a_file_backed_account_never_touching_
    /// the_os_keystore`) exactly, just for the opposite direction — an OS-keystore `account.json`
    /// must never unlock through `Effect::Unlock`, and the failure must name the actual fix
    /// (`Effect::LoadSession`), not surface as a confusing keyfile/AEAD error.
    #[test]
    fn run_unlock_fails_closed_for_an_os_keystore_account_never_touching_the_keyfile() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(tmp.path());
        dummy_descriptor().save().expect("save account.json");

        // A keyfile path that doesn't even exist on disk — proves the guard fires before any
        // `FileSecretStore` operation is attempted against it.
        let request = UnlockRequest {
            keyfile: tmp.path().join("nonexistent.key"),
            passphrase: "does-not-matter".to_string(),
        };
        // `run_unlock`'s `Ok` type widened (task 4.40) to `(LiveSession, Box<dyn SecretStore>,
        // KeyHandle)`, which — deliberately, `Box<dyn SecretStore>` has no `Debug` supertrait at
        // all (see `OnboardingSession`'s own hand-rolled `Debug` impl for why) — no longer
        // implements `Debug` itself, so `Result::expect_err` (which requires `T: Debug`) no longer
        // compiles here. A plain `match` proves the same thing without that bound.
        match run_unlock(&request) {
            Err(err) => assert!(err.contains("LoadSession")),
            Ok(_) => panic!("an OS-keystore account.json must never unlock through Effect::Unlock"),
        }
    }
}
