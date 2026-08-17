//! The real per-[`Effect`] execution this crate's worker task runs (task 4.30, extended by task
//! 4.29) — the network/store/crypto half of the account-lifecycle sub-steps
//! `crate::screens::onboarding`/`crate::screens::unlock` only ever *describe*. [`dispatch`] is the
//! single entry point `crate::run_worker`'s event loop calls for every [`Effect`] it receives;
//! internally it fans out to one function per effect group (`handle_generate_account`/
//! `handle_register`/`handle_publish_bundle`/`handle_unlock`/`handle_load_session` below), so later
//! gap-closure tasks (4.31–4.34) extend the same `match` with their own groups rather than inlining
//! everything into one growing function.
//!
//! Every [`Effect`] variant this module does not yet own (contacts/trust/settings/chat/…) falls
//! through `dispatch`'s final arm, which preserves this crate's original task-4.11 placeholder
//! behavior — echoing the effect straight back as [`WorkerEvent::Completed`] — so screens whose real
//! execution hasn't landed yet keep behaving exactly as they did before this task, out of this
//! task's scope per its own task file.
//!
//! Mirrors `apps/cli/src/main.rs::cmd_new`/`cmd_register`'s exact call sequence
//! (`generate_account` → `AccountDescriptor::save`; `SignalingClient::connect` →
//! `publish_bundle`), never inventing a different one.

use std::path::PathBuf;

use meridian_core::account::{self, AccountDescriptor, StoreKind};
use meridian_core::chat::ChatState as CoreChatState;
use meridian_core::identity::{
    generate_account, FileSecretStore, KeyHandle, MemorySecretStore, OsSecretStore, SecretStore,
};
use meridian_core::signaling::SignalingClient;
use meridian_core::trust::TrustStore;

use crate::app::{
    Effect, GenerateAccountEffect, GenerateAccountRequest, GeneratedAccount, LoadSessionEffect,
    LoadSessionOutcome, PublishBundleEffect, PublishedBundle, RegisterRequest, SessionOutcome,
    StoreChoice, UnlockEffect, UnlockRequest, WorkerEvent,
};
use crate::session::LiveSession;

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
        // Not this task's scope (contacts/trust/settings/chat/diagnostics/… — see later
        // gap-closure tasks 4.31-4.34). Preserves task 4.11's original placeholder behavior so
        // screens whose real execution hasn't landed yet are unaffected by this change.
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
            session.cache(account_pub, client, store);
            WorkerEvent::Completed(Effect::Register(request))
        }
        Err(e) => WorkerEvent::Failed(Effect::Register(request), e.to_string()),
    }
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
