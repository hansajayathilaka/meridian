//! `Preflight` (task 4.37): the routing decision named in
//! `docs/architecture/diagrams/tui-screen-flow.mermaid`
//! (`Preflight --> Onboarding: no account.json`, `Preflight --> Unlock: account exists, file-backed
//! store`, `Preflight --> Main: account exists, OS keystore`) that this crate never had — `App::new`
//! unconditionally started every run on [`crate::app::Screen::Onboarding`] before this task, and
//! onboarding's/unlock's own completion swapped to a bare `Screen::Placeholder`, never a real
//! `Screen::Main` (task 4.36), because no live-navigation wiring connected the two.
//!
//! ## The split: pure decision vs. its (still-I/O-free) application
//! [`preflight_route`] is the pure decision half (this task's own Deliverable 1) — it performs no
//! I/O itself, taking whatever `Option<AccountDescriptor>` its caller already loaded synchronously.
//! This mirrors [`crate::run`]'s own pre-existing precedent: that function already does synchronous
//! `config.toml` I/O in its own setup phase, before ever constructing an `App` — loading
//! `account.json` (if any) the same way, in the same phase, is the same pattern applied to one more
//! file, not a new one. [`crate::run`] is the one real (I/O-performing) caller; every test in this
//! module exercises the routing decision itself without touching `$MERIDIAN_HOME` at all.
//!
//! [`InitialRoute::into_screen_and_effects`] is the second, still-I/O-free half: turning a decision
//! into the concrete `(Screen, Vec<Effect>)` [`crate::app::App::new_with_route`] applies to a freshly
//! constructed `App` — building an `Effect`/a `Screen`'s initial state is ordinary, pure value
//! construction (exactly like every `Effect` this crate's own `handle_key`/`handle_worker` functions
//! already build), never a disk read in its own right.
//!
//! ## Why the OS-keystore route doesn't land on `Screen::Main` immediately
//! Reaching `Screen::Main` needs a real, loaded `TrustStore`/`ChatState`/contacts —
//! [`crate::session::LiveSession`] (task 4.29) — and building one is exactly what
//! [`crate::app::Effect::LoadSession`]'s worker execution already does, asynchronously, off the
//! actual `trust.bin`/`sessions.bin`/`contacts.json` on disk. So the OS-keystore route starts the
//! run on [`crate::app::Screen::Placeholder`] (the same "loading, briefly" role `crate::screens::
//! unlock::UnlockState::Unlocking` already plays for the file-backed path — see this task's own
//! `App::handle_key` changes for how a freshly onboarded file-backed account reuses that exact
//! sub-state rather than `Placeholder`) with `Effect::LoadSession` queued as the very first effect
//! the runtime dispatches; `crate::app::App::handle_worker`'s own new top-level arm (ahead of any
//! per-screen dispatch — see that function's own doc comment) swaps the placeholder for a real
//! `Screen::Main` once the effect resolves.
//!
//! ## The file-backed route
//! [`InitialRoute::Unlock`] carries an already-built [`crate::screens::unlock::UnlockState`]
//! (`UnlockState::new`, pure — no I/O) rather than the raw `AccountDescriptor` fields, so
//! `App::new_with_route` never has to know `crate::screens::unlock`'s own internal shape.

use meridian_core::account::{AccountDescriptor, StoreKind};

use crate::app::{Effect, LoadSessionEffect, LoadSessionRequest, Screen};
use crate::screens::unlock::UnlockState;

/// The `Preflight` decision (task 4.37's own Deliverable 1) — see the module doc.
#[derive(Debug)]
pub enum InitialRoute {
    /// No `account.json` on disk — a brand-new run, unchanged from this crate's pre-4.37 behavior
    /// (`App::new`'s own doc comment before this task: "a fresh app starts on `Screen::Onboarding`").
    Onboarding,
    /// A file-backed account exists — needs a passphrase before anything else can load. Carries the
    /// already-built [`UnlockState`] (pure construction, no I/O — see [`UnlockState::new`]) rather
    /// than the raw descriptor fields.
    Unlock(Box<UnlockState>),
    /// An OS-keystore account exists — no interactive step needed, but a real `LiveSession` still
    /// has to be loaded off disk asynchronously (`Effect::LoadSession`) before `Screen::Main` can be
    /// built — see the module doc's "why the OS-keystore route doesn't land on `Screen::Main`
    /// immediately" section.
    LoadSession,
}

impl InitialRoute {
    /// Converts this decision into the concrete `(Screen, Vec<Effect>)`
    /// [`crate::app::App::new_with_route`] applies to a freshly constructed `App` — see that
    /// function's own doc comment for why this split (pure decision vs. its application) exists.
    /// Still entirely I/O-free: ordinary value construction, exactly like every `Effect`
    /// `App::handle_key`/`App::handle_worker` already build.
    pub fn into_screen_and_effects(self) -> (Screen, Vec<Effect>) {
        match self {
            InitialRoute::Onboarding => (Screen::Onboarding(Box::default()), Vec::new()),
            InitialRoute::Unlock(state) => (Screen::Unlock(state), Vec::new()),
            InitialRoute::LoadSession => (
                Screen::Placeholder,
                vec![Effect::LoadSession(LoadSessionEffect {
                    request: LoadSessionRequest,
                    outcome: None,
                })],
            ),
        }
    }
}

/// The pure `Preflight` decision function (task 4.37's own Deliverable 1) — see the module doc.
/// Takes whatever `account.json` (if any) its caller already loaded synchronously; performs no I/O
/// itself, so it is testable in complete isolation from `$MERIDIAN_HOME` — every test below does
/// exactly that.
pub fn preflight_route(account: Option<AccountDescriptor>) -> InitialRoute {
    match account {
        None => InitialRoute::Onboarding,
        Some(descriptor) => match descriptor.store {
            StoreKind::File => {
                // A file-backed descriptor always carries `keyfile: Some(..)` — see
                // `AccountDescriptor::new_file`/`new_from_parts`. Falls back to an empty path
                // defensively rather than panicking on a hand-corrupted descriptor;
                // `Effect::Unlock`'s own worker-side `FileSecretStore::new` (task 4.17/4.29) is
                // where a genuinely unusable path would surface as an actionable error, not here —
                // same discipline `crate::app::App::new_with_config`'s own `config_path` fallback
                // already uses for the equivalent "rare, defensive, surfaced downstream instead"
                // case.
                let keyfile = descriptor.keyfile.clone().unwrap_or_default();
                // `id_string()` only fails on a malformed pubkey/hint — falls back to the raw hex
                // pubkey so the Unlock screen still has *something* identifying to show, same
                // defensive discipline as `keyfile` above, rather than panicking on a
                // hand-corrupted descriptor.
                let id = descriptor
                    .id_string()
                    .unwrap_or_else(|_| descriptor.pubkey.clone());
                InitialRoute::Unlock(Box::new(UnlockState::new(keyfile, id)))
            }
            StoreKind::Os => InitialRoute::LoadSession,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os_descriptor() -> AccountDescriptor {
        AccountDescriptor {
            v: 1,
            pubkey: "a".repeat(64),
            hint: "example.org".to_string(),
            store: StoreKind::Os,
            keyfile: None,
            service: Some("meridian".to_string()),
            label: "a".repeat(64),
            server: None,
        }
    }

    fn file_descriptor() -> AccountDescriptor {
        AccountDescriptor {
            v: 1,
            pubkey: "b".repeat(64),
            hint: "example.org".to_string(),
            store: StoreKind::File,
            keyfile: Some(std::path::PathBuf::from(
                "/home/user/.config/meridian/account.key",
            )),
            service: None,
            label: "b".repeat(64),
            server: None,
        }
    }

    // (a) — no account.json at all → Onboarding. This is the *regression* case (task's own
    // Deliverable 4a): must stay identical to this crate's pre-4.37 unconditional default.
    #[test]
    fn no_account_routes_to_onboarding() {
        assert!(matches!(preflight_route(None), InitialRoute::Onboarding));
    }

    // (b) — an existing file-backed account → Unlock, carrying the real keyfile/id.
    #[test]
    fn file_backed_account_routes_to_unlock() {
        let descriptor = file_descriptor();
        let expected_id = descriptor.id_string().unwrap();
        match preflight_route(Some(descriptor)) {
            InitialRoute::Unlock(state) => match *state {
                UnlockState::Entering(e) => {
                    assert_eq!(
                        e.keyfile,
                        std::path::PathBuf::from("/home/user/.config/meridian/account.key")
                    );
                    assert_eq!(e.id, expected_id);
                    assert_eq!(e.attempts, 0);
                }
                other => panic!("expected UnlockState::Entering, got {other:?}"),
            },
            other => panic!("expected InitialRoute::Unlock, got {other:?}"),
        }
    }

    // (c) — an existing OS-keystore account → LoadSession (straight to Main once the effect
    // resolves — see `crate::app`'s own tests for the worker-completion half of this).
    #[test]
    fn os_keystore_account_routes_to_load_session() {
        assert!(matches!(
            preflight_route(Some(os_descriptor())),
            InitialRoute::LoadSession
        ));
    }

    #[test]
    fn onboarding_route_converts_to_the_onboarding_screen_with_no_effects() {
        let (screen, effects) = InitialRoute::Onboarding.into_screen_and_effects();
        assert!(matches!(screen, Screen::Onboarding(_)));
        assert!(effects.is_empty());
    }

    #[test]
    fn unlock_route_converts_to_the_unlock_screen_with_no_effects() {
        let descriptor = file_descriptor();
        let route = preflight_route(Some(descriptor));
        let (screen, effects) = route.into_screen_and_effects();
        assert!(matches!(screen, Screen::Unlock(_)));
        assert!(effects.is_empty());
    }

    #[test]
    fn load_session_route_converts_to_a_placeholder_with_exactly_one_load_session_effect() {
        let (screen, effects) = InitialRoute::LoadSession.into_screen_and_effects();
        assert!(matches!(screen, Screen::Placeholder));
        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], Effect::LoadSession(_)));
    }

    #[test]
    fn a_malformed_file_descriptor_falls_back_defensively_instead_of_panicking() {
        let mut descriptor = file_descriptor();
        descriptor.keyfile = None;
        descriptor.pubkey = "not hex".to_string();
        match preflight_route(Some(descriptor)) {
            InitialRoute::Unlock(state) => match *state {
                UnlockState::Entering(e) => {
                    assert_eq!(e.keyfile, std::path::PathBuf::new());
                    assert_eq!(e.id, "not hex");
                }
                other => panic!("expected UnlockState::Entering, got {other:?}"),
            },
            other => panic!("expected InitialRoute::Unlock, got {other:?}"),
        }
    }
}
