//! Guarded receiver-side desync recovery (task 4.9, following through on task 1.18's deferred
//! "dangerous half" — see [`crate::chat::ChatError::Desync`]'s doc comment and
//! `docs/api/messaging-envelope-v1.md` §3 "Desync recovery" for the full design).
//!
//! Deliberately still I/O-free, matching `chat.rs`'s own module doc (`meridian-core` never touches
//! the network): the actual bundle fetch happens CLI-side
//! (`apps/cli/src/chat.rs`'s `maybe_attempt_recovery`), mirroring
//! `fetch_with_retry`/`start_initiator_session`'s existing pattern for original first contact. What
//! lives here is the decision + state-mutation glue once the caller already has a freshly fetched,
//! signature-verified bundle in hand:
//! - [`crate::chat::ChatState::recovery_recommended`] / [`crate::chat::DESYNC_RECOVERY_THRESHOLD`]
//!   (in `chat.rs`) decide *whether* recovery should even be considered (repeated, never
//!   first-occurrence, `Desync` — see that constant's doc for the threshold reasoning);
//! - [`crate::desync::attempt_recovery`] here decides *whether it is actually allowed to proceed* (task 4.4's
//!   [`crate::trust::TrustStore::can_send`] gate) and, if so, performs the forced session
//!   replacement via [`crate::chat::ChatState::replace_session_as_initiator`] — the one explicit,
//!   clearly-named surface for that, never a side effect of the ordinary
//!   `start_initiator_session` callers already use.

use meridian_identity::{KeyHandle, SecretStore};

use crate::chat::{ChatError, ChatState};
use crate::trust::{SendGate, TrustError, TrustStore};

/// Errors from [`attempt_recovery`]: either the underlying chat/session machinery, or the trust
/// store. Kept distinct from [`ChatError`] (rather than folding trust errors into it) so `chat.rs`'s
/// own error type does not have to know about `trust.rs` — only this orchestration module, which
/// already depends on both, does.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("chat error: {0}")]
    Chat(#[from] ChatError),
    #[error("trust error: {0}")]
    Trust(#[from] TrustError),
}

/// The outcome of an [`attempt_recovery`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The forced re-handshake was performed: the (presumed-stale) session with the target identity
    /// was discarded and replaced with a fresh initiator session.
    Recovered,
    /// Refused: [`TrustStore::can_send`] for the identity this recovery would actually target was
    /// not [`SendGate::Ok`]. No session was touched, no OTK was consumed.
    Gated(SendGate),
    /// The fetched bundle was genuinely signed by a **different** identity key than `peer_ik` — an
    /// ordinary key-change event, routed through [`TrustStore::observe_key_change`] exactly like any
    /// other key-change discovery — but `observe_key_change` refused it as
    /// [`TrustError::ConflictingContact`] (the new key already names a different,
    /// independently-known contact). No session was touched.
    KeyChangeConflict,
    /// (review fixup) The fetched bundle was signed by a different key than `peer_ik`, and
    /// `observe_key_change` reports [`TrustError::UnknownContact`] — there is no prior contact
    /// record for `peer_ik` at all to migrate. Carries the surfaced key (the bundle's actual signer)
    /// for the caller's own follow-up.
    ///
    /// **This never auto-completes.** Earlier behavior silently TOFU-pinned the surfaced key *and*
    /// proceeded to establish a live session in the same call whenever `can_send` read `Ok` for it —
    /// with no message-request gate and no distinguishing notice, weaker than ordinary first contact
    /// (which is always either receiver-gated via [`crate::chat::MessageRequest`] or an explicit
    /// sender-initiated [`crate::chat::ChatState::start_initiator_session`] call). This variant
    /// requires the caller to take an explicit follow-up action instead — e.g. treat the surfaced
    /// key as a brand-new contact through the ordinary first-contact UX, or refuse it — never
    /// silently completing a session on the caller's behalf. No session was touched and no trust
    /// state was written by `attempt_recovery` itself when this is returned.
    ///
    /// Should not happen in practice today: repeated `Desync` firing at all requires a session to
    /// have already existed for `peer_ik`, and every path that installs a session also calls
    /// [`TrustStore::observe`]/`observe_key_change` on it — but reachable in principle, so handled
    /// rather than assumed impossible.
    UnknownIdentitySurfaced([u8; 32]),
}

/// Attempt the guarded recovery for `peer_ik`, given a bundle the caller has **already fetched and
/// signature-verified** (same contract `apps/cli/src/chat.rs`'s `fetch_with_retry` already provides
/// for `ChatState::start_initiator_session`'s original first-contact call).
///
/// Resets `peer_ik`'s desync counter as its very first action
/// ([`ChatState::note_recovery_attempted`]) — see [`crate::chat::DESYNC_RECOVERY_THRESHOLD`]'s doc
/// for why an *attempted* recovery is rate-limited whatever its outcome, not only on success: a
/// caller that decides to call this at all (i.e. already crossed the threshold) should not have the
/// very next `Desync` immediately re-trigger another attempt, whether this one succeeded, was
/// gated, or hit a key-change conflict.
///
/// **`bundle_owner_ik` vs. `peer_ik` — the key-change guard (design requirement 3).** These are
/// passed *separately*, rather than this function assuming the fetched bundle is for `peer_ik`,
/// specifically so its *contract* can never bypass task 4.4's key-change gate "because a recovery
/// flow is already in progress" — see the module doc. In the one caller that exists today
/// (`apps/cli/src/chat.rs`, via `SignalingClient::fetch_bundle(peer_ik, ...)`),
/// `meridian_signaling::verify_bundle`'s exact-key pinning (bundle signatures MUST verify under the
/// *exact requested* key) makes `bundle_owner_ik != peer_ik` structurally unreachable in practice —
/// a genuine substitution attempt fails closed as `SignalError::BundleVerification` before this
/// function is ever called (see `fetch_with_retry`'s generic, non-retried error arm). This parameter
/// — and the branch below — exist anyway so (a) a future fetch strategy that *can* resolve to a
/// different key (a hint/directory-based lookup, or T13 multi-device's device-list-change case,
/// which `trust.rs`'s own module doc already anticipates reusing this exact machinery for) inherits
/// the same guard automatically rather than needing a second implementation of it, and (b) this
/// function's key-change handling is directly testable in isolation from the network layer (this
/// crate stays I/O-free — see `chat.rs`'s module doc).
///
/// **The `UnknownContact` degrade path (review fixup).** If a key change is surfaced and
/// `observe_key_change` reports [`TrustError::UnknownContact`] (no prior record for `peer_ik` to
/// migrate — should not happen in practice, since a session must already have existed for repeated
/// `Desync` to have fired, and every path that installs a session also calls
/// `TrustStore::observe`/`observe_key_change` on it, but handled rather than assumed impossible),
/// this function returns [`RecoveryOutcome::UnknownIdentitySurfaced`] **without** touching `trust`
/// or `chat` any further. Earlier behavior silently TOFU-pinned the surfaced key via
/// [`TrustStore::observe`] *and then proceeded, in the same call*, to establish a live session if
/// `can_send` happened to read `Ok` for it — with no message-request gate and no distinguishing
/// notice, which is a materially weaker invariant than ordinary first contact (always either
/// receiver-gated via [`crate::chat::MessageRequest`] or explicit sender-initiated
/// [`crate::chat::ChatState::start_initiator_session`]). See [`RecoveryOutcome::UnknownIdentitySurfaced`]'s
/// own doc for what a caller should do instead.
#[allow(clippy::too_many_arguments)]
pub fn attempt_recovery(
    chat: &mut ChatState,
    trust: &mut TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: &[u8; 32],
    peer_ik: &[u8; 32],
    bundle_owner_ik: &[u8; 32],
    peer_spk: &[u8; 32],
    peer_opk: Option<[u8; 32]>,
    hint: &str,
    now_unix: u64,
) -> Result<RecoveryOutcome, RecoveryError> {
    chat.note_recovery_attempted(peer_ik);

    let target_ik = if bundle_owner_ik == peer_ik {
        *peer_ik
    } else {
        // A surfaced key change: never silently accepted, and never treated any differently than
        // an ordinary key-change discovery just because a recovery flow is in progress.
        match trust.observe_key_change(peer_ik, *bundle_owner_ik, hint, now_unix) {
            Ok(_) => {}
            Err(TrustError::UnknownContact) => {
                // (review fixup) No silent TOFU-pin-and-proceed here — see this function's doc
                // comment and `RecoveryOutcome::UnknownIdentitySurfaced`'s own doc. Nothing in
                // `trust` or `chat` is touched; the caller must take an explicit follow-up action.
                return Ok(RecoveryOutcome::UnknownIdentitySurfaced(*bundle_owner_ik));
            }
            Err(TrustError::ConflictingContact) => {
                return Ok(RecoveryOutcome::KeyChangeConflict);
            }
            Err(e) => return Err(e.into()),
        }
        *bundle_owner_ik
    };

    match trust.can_send(&target_ik) {
        SendGate::Ok => {
            chat.replace_session_as_initiator(
                store, handle, our_ik, &target_ik, peer_spk, peer_opk,
            )?;
            Ok(RecoveryOutcome::Recovered)
        }
        gate => Ok(RecoveryOutcome::Gated(gate)),
    }
}
