//! The real per-[`Effect`] execution this crate's worker task runs (task 4.30) — the network/
//! store/crypto half of the account-lifecycle sub-steps `crate::screens::onboarding`/
//! `crate::screens::unlock` only ever *describe*. [`dispatch`] is the single entry point
//! `crate::run_worker`'s event loop calls for every [`Effect`] it receives; internally it fans out
//! to one function per effect group (`handle_generate_account`/`handle_register`/
//! `handle_publish_bundle`/`handle_unlock` below), so later gap-closure tasks (4.31–4.34) extend the
//! same `match` with their own groups rather than inlining everything into one growing function.
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

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::identity::{
    generate_account, FileSecretStore, KeyHandle, MemorySecretStore, OsSecretStore, SecretStore,
};
use meridian_core::signaling::SignalingClient;

use crate::app::{
    Effect, GenerateAccountEffect, GenerateAccountRequest, GeneratedAccount, PublishBundleEffect,
    PublishedBundle, RegisterRequest, StoreChoice, UnlockRequest, WorkerEvent,
};

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
        Effect::Unlock(request) => handle_unlock(request).await,
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
// Unlock
// ---------------------------------------------------------------------------

async fn handle_unlock(request: UnlockRequest) -> WorkerEvent {
    let fs = FileSecretStore::new(&request.keyfile, request.passphrase.clone());
    match fs.export_seed() {
        Ok(_seed) => WorkerEvent::Completed(Effect::Unlock(request)),
        Err(e) => WorkerEvent::Failed(Effect::Unlock(request), e.to_string()),
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
