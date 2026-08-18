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

use std::path::PathBuf;

use tokio::sync::mpsc;

use meridian_core::account::{self, AccountDescriptor, StoreKind};
use meridian_core::chat::{ChatError, ChatState as CoreChatState};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    generate_account, FileSecretStore, KeyHandle, MemorySecretStore, OsSecretStore, SecretStore,
};
use meridian_core::signaling::SignalingClient;
use meridian_core::trust::{Contact, PinnedKey, TrustState, TrustStore};

use crate::app::{
    AcceptRequestEffect, AcceptRequestRequest, AcknowledgeKeyChangeEffect,
    AcknowledgeKeyChangeRequest, AddContactEffect, AddContactRequest, AddedContact,
    DeleteContactEffect, DeleteContactRequest, Effect, GenerateAccountEffect,
    GenerateAccountRequest, GeneratedAccount, ImportContactQrEffect, ImportContactQrRequest,
    LoadSessionEffect, LoadSessionOutcome, MarkVerifiedEffect, MarkVerifiedRequest,
    PersistHistoryEffect, PersistHistoryRequest, PublishBundleEffect, PublishedBundle,
    RegisterRequest, RejectRequestEffect, RejectRequestRequest, RunDoctorEffect, SaveSettingEffect,
    SendMessageEffect, SendMessageRequest, SentMessage, SessionOutcome, SetPetnameEffect,
    SetPetnameRequest, SetPolicyOverrideEffect, SetPolicyOverrideRequest, SetUserBlockedEffect,
    SetUserBlockedRequest, StoreChoice, UnlockEffect, UnlockRequest, WorkerEvent,
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
}

struct PendingConnection {
    account_pub: [u8; 32],
    client: SignalingClient,
    /// The already-unwrapped store [`handle_register`] authenticated with, cached so
    /// [`handle_publish_bundle`] does not pay a second, redundant scrypt unwrap for the same
    /// passphrase keyfile — see [`open_store_for_bulk_signing`]'s own doc comment.
    store: Box<dyn SecretStore>,
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
        Effect::Unlock(effect) => handle_unlock(*effect).await,
        Effect::LoadSession(effect) => handle_load_session(effect).await,
        // Task 4.31: contacts / contact-detail persistence.
        Effect::AddContact(effect) => handle_add_contact(effect).await,
        Effect::ImportContactQr(effect) => handle_import_contact_qr(effect).await,
        Effect::SetPetname(effect) => handle_set_petname(effect).await,
        Effect::SetUserBlocked(effect) => handle_set_user_blocked(effect).await,
        Effect::SetPolicyOverride(effect) => handle_set_policy_override(effect).await,
        Effect::DeleteContact(effect) => handle_delete_contact(effect).await,
        // Task 4.32: message-request-queue / verify-screen trust persistence.
        Effect::AcceptRequest(effect) => handle_accept_request(effect).await,
        Effect::RejectRequest(effect) => handle_reject_request(effect).await,
        Effect::MarkVerified(effect) => handle_mark_verified(effect).await,
        Effect::AcknowledgeKeyChange(effect) => handle_acknowledge_key_change(effect).await,
        // Task 4.33: outbound chat (the send half of the T17 demo's "both sides chat" step).
        Effect::SendMessage(effect) => handle_send_message(effect).await,
        Effect::PersistHistory(effect) => handle_persist_history(effect).await,
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
fn default_keyfile_path() -> Result<PathBuf, String> {
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
async fn handle_unlock(effect: UnlockEffect) -> WorkerEvent {
    let UnlockEffect { request, .. } = effect;
    match run_unlock(&request) {
        Ok(session) => WorkerEvent::Completed(Effect::Unlock(Box::new(UnlockEffect {
            request,
            outcome: SessionOutcome::ready(session),
        }))),
        Err(message) => WorkerEvent::Failed(
            Effect::Unlock(Box::new(UnlockEffect {
                request,
                outcome: SessionOutcome::empty(),
            })),
            message,
        ),
    }
}

fn run_unlock(request: &UnlockRequest) -> Result<LiveSession, String> {
    // Review fix (task 4.29, Finding 4): the symmetric guard to `run_load_session`'s own
    // `StoreKind::File => Err(...)` arm below — checked first, and against the real on-disk
    // `account.json`, not the caller-supplied keyfile, so an OS-keystore account is rejected with a
    // clear, actionable message *before* `FileSecretStore::export_seed` ever runs against it. Without
    // this guard, misusing `Effect::Unlock` on an OS-keystore account still fails closed today (an
    // AEAD failure against the wrong/nonexistent keyfile, never a silent success or wrong-account
    // leak), but with a confusing "corrupt trust.bin"-shaped error instead of a message that actually
    // names the fix.
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
    load_live_session(descriptor, &fs, &handle)
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

/// Resolves the `SecretStore`/`KeyHandle` pair every handler below needs, fresh from the real,
/// already-onboarded `account.json` — never from a request field (none of
/// [`AddContactRequest`]/[`SetPetnameRequest`]/[`SetUserBlockedRequest`]/
/// [`SetPolicyOverrideRequest`]/[`DeleteContactRequest`]/[`SendMessageRequest`]/
/// [`PersistHistoryRequest`] carries one; see `crate::app`'s own doc comments on each).
///
/// **`StoreKind::Os` only, today.** Mirrors [`run_load_session`]'s own `StoreKind::Os` branch
/// exactly (`init_os_keystore` -> `OsSecretStore::new(service)` -> `KeyHandle::from_label`) — the
/// OS keystore needs no additional secret from this call site, so a fresh [`OsSecretStore`] can be
/// (re-)constructed on every single effect dispatch with no state carried between them, exactly
/// this task's own "single, complete disk round-trip" scope.
///
/// **`StoreKind::File` fails closed here**, with a message naming the real gap rather than
/// attempting (and failing more confusingly) a `FileSecretStore` operation with no passphrase:
/// unlike [`run_unlock`], none of this module's six contacts-group requests carry one, and unlike
/// [`OnboardingSession`], `crate::app::App` has no `Option<LiveSession>` field yet to have cached
/// an already-unwrapped store in from a prior `Effect::Unlock` — [`crate::session::LiveSession`]'s
/// own module doc names this exact "known gap" (`App` discarding the `LiveSession` a successful
/// file-backed `Effect::Unlock` already builds) and defers wiring it to a later task (4.36/4.37).
/// `TODO: confirm`: once that wiring lands, this function (or its caller) is the natural place to
/// thread the already-unlocked store through instead of re-deriving one per effect for the
/// file-backed case — not invented here, since no design doc this task read specifies it.
fn open_account_store() -> Result<(Box<dyn SecretStore>, KeyHandle), String> {
    let descriptor = AccountDescriptor::load()?;
    match descriptor.store {
        StoreKind::Os => {
            init_os_keystore()?;
            let service = descriptor
                .service
                .clone()
                .unwrap_or_else(|| OS_KEYSTORE_SERVICE.to_string());
            let handle = KeyHandle::from_label(&descriptor.label);
            Ok((Box::new(OsSecretStore::new(&service)), handle))
        }
        StoreKind::File => Err(
            "this account is passphrase-protected — this action from a live TUI session isn't \
             supported yet for file-backed accounts (no cached, already-unlocked store to reuse); \
             use the CLI instead"
                .to_string(),
        ),
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

async fn handle_add_contact(effect: AddContactEffect) -> WorkerEvent {
    let AddContactEffect { request, .. } = effect;
    match run_add_contact(&request) {
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
fn run_add_contact(request: &AddContactRequest) -> Result<AddedContact, String> {
    let (store, handle) = open_account_store()?;
    let now = now_unix();

    let mut trust = load_trust(store.as_ref(), &handle)?;
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
    save_trust(&trust, store.as_ref(), &handle)?;

    let mut doc = crate::store::contacts::load_or_default(store.as_ref(), &handle)
        .map_err(|e| e.to_string())?;
    upsert_contact_record(&mut doc, &request.id, &contact, now);
    crate::store::contacts::save(&doc, store.as_ref(), &handle).map_err(|e| e.to_string())?;

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

async fn handle_set_petname(effect: SetPetnameEffect) -> WorkerEvent {
    let SetPetnameEffect { request, .. } = effect;
    match run_set_petname(&request) {
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
fn run_set_petname(request: &SetPetnameRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;

    let mut trust = load_trust(store.as_ref(), &handle)?;
    trust
        .set_petname(&request.pubkey, request.petname.clone())
        .map_err(|e| e.to_string())?;
    let petname = trust
        .contact(&request.pubkey)
        .expect("set_petname succeeded — contact exists")
        .petname
        .clone();
    save_trust(&trust, store.as_ref(), &handle)?;

    let mut doc = crate::store::contacts::load_or_default(store.as_ref(), &handle)
        .map_err(|e| e.to_string())?;
    let pubkey_hex = hex::encode(request.pubkey);
    if let Some(record) = doc.contacts.iter_mut().find(|c| c.pubkey == pubkey_hex) {
        record.petname = petname;
        crate::store::contacts::save(&doc, store.as_ref(), &handle).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// --- SetUserBlocked --------------------------------------------------------------------------------

async fn handle_set_user_blocked(effect: SetUserBlockedEffect) -> WorkerEvent {
    let SetUserBlockedEffect { request, .. } = effect;
    match run_set_user_blocked(&request) {
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
fn run_set_user_blocked(request: &SetUserBlockedRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let mut trust = load_trust(store.as_ref(), &handle)?;
    trust
        .set_user_blocked(&request.pubkey, request.blocked)
        .map_err(|e| e.to_string())?;
    save_trust(&trust, store.as_ref(), &handle)
}

// --- SetPolicyOverride -----------------------------------------------------------------------------

async fn handle_set_policy_override(effect: SetPolicyOverrideEffect) -> WorkerEvent {
    let SetPolicyOverrideEffect { request, .. } = effect;
    match run_set_policy_override(&request) {
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
fn run_set_policy_override(request: &SetPolicyOverrideRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let mut doc = crate::store::contacts::load_or_default(store.as_ref(), &handle)
        .map_err(|e| e.to_string())?;
    let pubkey_hex = hex::encode(request.pubkey);
    let record = doc
        .contacts
        .iter_mut()
        .find(|c| c.pubkey == pubkey_hex)
        .ok_or_else(|| "no contact recorded for this pubkey — add it first".to_string())?;
    record.policy_override = request.policy_override;
    crate::store::contacts::save(&doc, store.as_ref(), &handle).map_err(|e| e.to_string())
}

// --- DeleteContact ---------------------------------------------------------------------------------

async fn handle_delete_contact(effect: DeleteContactEffect) -> WorkerEvent {
    let DeleteContactEffect { request, .. } = effect;
    match run_delete_contact(&request) {
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
fn run_delete_contact(request: &DeleteContactRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let mut doc = crate::store::contacts::load_or_default(store.as_ref(), &handle)
        .map_err(|e| e.to_string())?;
    let pubkey_hex = hex::encode(request.pubkey);
    doc.contacts.retain(|c| c.pubkey != pubkey_hex);
    crate::store::contacts::save(&doc, store.as_ref(), &handle).map_err(|e| e.to_string())
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
// fresh from disk and resealed rather than applied to an already-open in-memory value. Only
// `trust.bin`/`sessions.bin` are touched here — never `contacts.json` (this task's own scope note;
// `crate::screens::requests`'s and `crate::screens::verify`'s own module docs name no
// `contacts.json` interaction for any of these four effects, unlike `handle_add_contact`/
// `handle_set_petname` above).
// ---------------------------------------------------------------------------

// --- AcceptRequest -------------------------------------------------------------------------------

async fn handle_accept_request(effect: AcceptRequestEffect) -> WorkerEvent {
    let AcceptRequestEffect { request, .. } = effect;
    match run_accept_request(&request).await {
        Ok(()) => WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            request,
            outcome: Some(()),
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
async fn run_accept_request(request: &AcceptRequestRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let _chat_guard = chat_state_lock().lock().await;

    let mut chat = load_chat(store.as_ref(), &handle)?;
    let accepted = chat.accept_request(&request.sender_ik).is_some();
    let has_session = chat.has_session(&request.sender_ik);
    save_chat(&chat, store.as_ref(), &handle)?;

    let mut trust = load_trust(store.as_ref(), &handle)?;
    let pin_still_owed = has_session && trust.contact(&request.sender_ik).is_none();
    if accepted || pin_still_owed {
        trust.observe(request.sender_ik, "", now_unix());
        save_trust(&trust, store.as_ref(), &handle)?;
    }
    Ok(())
}

// --- RejectRequest -------------------------------------------------------------------------------

async fn handle_reject_request(effect: RejectRequestEffect) -> WorkerEvent {
    let RejectRequestEffect { request, .. } = effect;
    match run_reject_request(&request).await {
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
async fn run_reject_request(request: &RejectRequestRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let _chat_guard = chat_state_lock().lock().await;
    let mut chat = load_chat(store.as_ref(), &handle)?;
    chat.reject_request(&request.sender_ik);
    save_chat(&chat, store.as_ref(), &handle)
}

// --- MarkVerified --------------------------------------------------------------------------------

async fn handle_mark_verified(effect: MarkVerifiedEffect) -> WorkerEvent {
    let MarkVerifiedEffect { request, .. } = effect;
    match run_mark_verified(&request) {
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
fn run_mark_verified(request: &MarkVerifiedRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let mut trust = load_trust(store.as_ref(), &handle)?;
    trust
        .mark_verified(&request.pubkey)
        .map_err(|e| e.to_string())?;
    save_trust(&trust, store.as_ref(), &handle)
}

// --- AcknowledgeKeyChange -------------------------------------------------------------------------

async fn handle_acknowledge_key_change(effect: AcknowledgeKeyChangeEffect) -> WorkerEvent {
    let AcknowledgeKeyChangeEffect { request, .. } = effect;
    match run_acknowledge_key_change(&request) {
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
fn run_acknowledge_key_change(request: &AcknowledgeKeyChangeRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let mut trust = load_trust(store.as_ref(), &handle)?;
    let state_before = trust.contact(&request.pubkey).map(|c| c.state);
    let result = trust.acknowledge_key_change(&request.pubkey);
    let state_after = trust.contact(&request.pubkey).map(|c| c.state);
    if state_before != state_after {
        save_trust(&trust, store.as_ref(), &handle)?;
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

async fn handle_send_message(effect: SendMessageEffect) -> WorkerEvent {
    let SendMessageEffect { request, .. } = effect;
    match run_send_message(&request).await {
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
async fn run_send_message(request: &SendMessageRequest) -> Result<SentMessage, String> {
    let (store, handle) = open_account_store()?;
    let _chat_guard = chat_state_lock().lock().await;
    let descriptor = AccountDescriptor::load()?;
    let account_pub = account_pub_bytes(&descriptor)?;
    let server = resolve_server(&descriptor)?;
    let peer_label =
        meridian_core::identity::to_id_string(&request.peer_pubkey, &request.peer_hint)
            .unwrap_or_else(|_| hex::encode(request.peer_pubkey));

    let mut chat = load_chat(store.as_ref(), &handle)?;

    let mut client =
        SignalingClient::connect(&server, store.as_ref(), &handle, account_pub, None, 1)
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
            store.as_ref(),
            &handle,
            &account_pub,
            &request.peer_pubkey,
            &peer_bundle.spk,
            peer_bundle.otks.first().copied(),
        )
        .map_err(|e| format!("establishing session: {e}"))?;
        save_chat(&chat, store.as_ref(), &handle)?;
    }

    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    let blob = chat
        .seal_outbound(
            store.as_ref(),
            &handle,
            &account_pub,
            &request.peer_pubkey,
            &ChatContent::Text {
                id,
                body: request.body.clone(),
            },
        )
        .map_err(|e| format!("sealing message: {e}"))?;
    save_chat(&chat, store.as_ref(), &handle)?;

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

async fn handle_persist_history(effect: PersistHistoryEffect) -> WorkerEvent {
    let PersistHistoryEffect { request, .. } = effect;
    match run_persist_history(&request) {
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
fn run_persist_history(request: &PersistHistoryRequest) -> Result<(), String> {
    let (store, handle) = open_account_store()?;
    let peer_pubkey_hex = hex::encode(request.peer_pubkey);
    crate::store::history::append(&peer_pubkey_hex, &request.entry, store.as_ref(), &handle)
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
pub struct InboundHandoff {
    pub store: Box<dyn SecretStore>,
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
                handle,
                account_pub,
                server,
            })
        }
        WorkerEvent::Completed(Effect::Unlock(boxed)) if boxed.outcome.as_option().is_some() => {
            let descriptor = AccountDescriptor::load().ok()?;
            let fs = FileSecretStore::new(&boxed.request.keyfile, boxed.request.passphrase.clone());
            let handle = KeyHandle::from_label(&descriptor.label);
            let account_pub = account_pub_bytes(&descriptor).ok()?;
            let server = resolve_server(&descriptor).ok()?;
            Some(InboundHandoff {
                store: Box::new(fs),
                handle,
                account_pub,
                server,
            })
        }
        _ => None,
    }
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
        StoreChoice::File { passphrase } => {
            let keyfile = default_keyfile_path()?;
            let fs = FileSecretStore::new(&keyfile, passphrase.clone());
            let seed = fs.export_seed().map_err(|e| e.to_string())?;
            let mem = MemorySecretStore::new();
            mem.store(label, seed.as_slice())
                .map_err(|e| e.to_string())?;
            Ok(Box::new(mem))
        }
    }
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
        let err = run_unlock(&request)
            .expect_err("an OS-keystore account.json must never unlock through Effect::Unlock");
        assert!(err.contains("LoadSession"));
    }
}
