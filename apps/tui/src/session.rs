//! [`LiveSession`] (task 4.29): the real, owned, in-memory bundle of everything a screen needs once
//! an account is unlocked — the "future task that gives `App` a real, loaded `TrustStore`"/
//! `ChatState`/config gap every one of `crate::app::Screen::Chat`/`Screen::Requests`/
//! `Screen::Verify`'s own doc comments have been flagging since their own tasks landed.
//!
//! ## Field set, and why each one is here (not copied blindly from the task file's own draft list)
//! - [`LiveSession::account`] — the non-secret [`AccountDescriptor`]: every screen that renders "who
//!   am I" (the id string, `own_pubkey` for a safety-number computation — see
//!   `crate::screens::verify::VerifyState::new`'s own `own_pubkey` parameter) needs this, and it is
//!   also the thing a (future) worker re-derives its `SecretStore`/`KeyHandle` from on every other
//!   effect this crate dispatches once "logged in" — see `crate::worker`'s own account-resolution
//!   helpers.
//! - [`LiveSession::trust`] — the real [`TrustStore`]: `Screen::Requests`/`Screen::Verify`/
//!   `Screen::Chat` (`crate::screens::chat::ChatState::trust`) each already document that they are
//!   "waiting on" exactly this — a live, mutable, at-rest-backed trust store, not the TUI's own
//!   display-only `ContactEntry` join.
//! - [`LiveSession::chat`] — the real `meridian_core::chat::ChatState` (sessions.bin: the prekey
//!   vault plus every established ratchet session and pending message-request queue) —
//!   [`crate::app::AcceptRequestRequest`]/[`crate::app::SendMessageRequest`]'s own doc comments both
//!   name this exact type as the "account/session context" their own future workers (4.33/4.35) will
//!   need; this task is what actually loads it off disk for them to reach.
//! - [`LiveSession::contacts`] — the TUI-local `contacts.json` cache
//!   ([`crate::store::contacts::ContactsDocument`]): `crate::screens::contacts::ContactsState`/
//!   `crate::screens::chat`'s own history-reopening path both work off this display-oriented join
//!   (petname, unread count, `conv_handle`), not `TrustStore` directly — see
//!   `crate::store::contacts`'s own module doc for why the two stores deliberately stay separate.
//!
//! **Deliberately excludes `state.json`** ([`crate::store::state::StateDocument`]): unlike the four
//! fields above, `state.json` needs no [`meridian_core::identity::SecretStore`]/`KeyHandle` to read
//! at all (task 4.15's own module doc: "deliberately unsealed plaintext UI state") — bundling it
//! into the one type that exists specifically to carry *unlock-gated* state would blur that
//! distinction for no benefit, and no `Screen::*` doc comment names it as something this type is
//! blocking on the way `trust`/`chat`/`contacts` are. `TODO: confirm`: a later task may still decide
//! `state.json`'s own load belongs alongside this bundle for convenience (one fewer place a future
//! `Preflight` step has to remember to read from) — flagged, not resolved, here.
//!
//! ## Ownership: move-only, by design
//! [`TrustStore`] and `meridian_core::chat::ChatState` are deliberately **not** `Clone` (see their
//! own module docs — a `TrustStore`/`ChatState` clone would let two in-memory copies of the same
//! sealed-at-rest state silently diverge, one of them stale). [`LiveSession`] therefore does not
//! derive `Clone`/`PartialEq`/`Eq` either — the architect-blessed shape this task's own goal names:
//! a live session moves via `Option::take` between whichever code owns it and whichever screen is on
//! top of the stack (`crate::app::Screen::Chat`'s own `trust: TrustStore` field, populated the same
//! way, already establishes this exact pattern — see `apps/tui/tests/at_rest_audit.rs`'s "Reclaim the
//! (unmutated by chat) TrustStore back out of the popped Chat screen" step for a live example of the
//! reclaim-by-move idiom this type is meant to feed). Wiring `App` itself to hold `Option<LiveSession>`
//! and thread it through screen pushes/pops is out of this task's own scope (4.36/4.37's job — see
//! the task file's own Scope/Out section); this module only builds the type and the loading path that
//! will feed it.
//!
//! **Known gap, flagged here for discoverability (review finding, task 4.29):** because `App` has no
//! `Option<LiveSession>` field yet, `crate::app::App::handle_worker`'s `Screen::Unlock` arm today
//! delegates the *whole* `WorkerEvent` to `crate::screens::unlock::handle_worker` without first
//! extracting the [`crate::app::SessionOutcome`] a successful file-backed `Effect::Unlock` now
//! carries — so a real, freshly-built [`LiveSession`] is constructed and then discarded unread on
//! every successful unlock today. Whichever future task (4.36/4.37) wires `App` to hold
//! `Option<LiveSession>` must change **that arm itself**, not just add navigation elsewhere — see its
//! own doc comment in `app.rs` for the precise reclaim point that does not exist yet.

use meridian_core::account::AccountDescriptor;
use meridian_core::chat::ChatState;
use meridian_core::trust::TrustStore;

use crate::store::contacts::ContactsDocument;

/// The real, owned, in-memory session state a screen needs once an account is loaded/unlocked — see
/// the module doc for the exact field set and reasoning, and [`crate::app::Effect::LoadSession`]/
/// [`crate::app::Effect::Unlock`] for how one of these actually gets built.
pub struct LiveSession {
    pub account: AccountDescriptor,
    pub trust: TrustStore,
    pub chat: ChatState,
    pub contacts: ContactsDocument,
}

impl LiveSession {
    /// A brand-new account's trivially empty session: no `trust.bin`/`sessions.bin`/`contacts.json`
    /// has ever been sealed for it, so every one of those defaults exactly like their own
    /// `open_at_rest`/`load_or_default` would for a first-ever read (`TrustStore::default()`,
    /// `ChatState::default()`, an empty-but-versioned [`ContactsDocument`] — mirroring
    /// `crate::store::contacts::load_or_default_at`'s own "file not found" branch rather than that
    /// type's derived `Default` impl, which would leave `v: 0` instead of the real current schema
    /// version). Named for onboarding's own completion path (this task's own risk note: "a
    /// brand-new account's `LiveSession` is trivially empty/default — no disk read needed") — a
    /// future navigation task can call this directly once onboarding finishes, without dispatching
    /// any `Effect` at all, since there is genuinely nothing on disk yet to read.
    pub fn empty(account: AccountDescriptor) -> Self {
        Self {
            account,
            trust: TrustStore::default(),
            chat: ChatState::default(),
            contacts: ContactsDocument {
                v: crate::store::contacts::CURRENT_VERSION,
                contacts: Vec::new(),
            },
        }
    }
}

impl std::fmt::Debug for LiveSession {
    /// Hand-rolled, same reason as `crate::app::UnlockRequest`/`crate::app::Screen`: `chat`'s own
    /// type (`meridian_core::chat::ChatState`) holds ratchet/prekey secret material and deliberately
    /// has **no** `Debug` impl at all to derive through (see that type's own module doc: unlike
    /// `TrustStore`, "every field reachable from here is already-public contact metadata... never key
    /// material" does not hold for `ChatState`). `account`/`trust`/`contacts` are all already safe to
    /// derive `Debug` for on their own (public account metadata, contact metadata, and the TUI's own
    /// display cache respectively), so they are shown as-is.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveSession")
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

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::account::StoreKind;

    fn descriptor() -> AccountDescriptor {
        AccountDescriptor {
            v: 1,
            pubkey: "a".repeat(64),
            hint: "example.org".to_string(),
            store: StoreKind::Os,
            keyfile: None,
            service: Some("meridian".to_string()),
            label: "a".repeat(64),
        }
    }

    #[test]
    fn empty_session_has_default_empty_stores_but_the_real_current_contacts_version() {
        let session = LiveSession::empty(descriptor());
        assert_eq!(session.trust.contacts().count(), 0);
        assert!(!session.chat.has_session(&[0u8; 32]));
        assert_eq!(session.contacts.v, crate::store::contacts::CURRENT_VERSION);
        assert!(session.contacts.contacts.is_empty());
    }

    #[test]
    fn debug_never_leaks_chat_session_internals() {
        let session = LiveSession::empty(descriptor());
        let dump = format!("{session:?}");
        assert!(dump.contains("redacted"));
        assert!(!dump.contains("ChatState {"));
    }
}
