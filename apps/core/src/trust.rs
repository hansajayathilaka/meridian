//! Trust module + contact store (T08 core layer, task 4.3): the client-agnostic
//! `new → pinned (TOFU) → verified` state machine — plus `blocked` — described in
//! `docs/architecture/features/08-verification-trust.md`.
//!
//! Every client (CLI today, TUI this phase, browser/mobile later) consumes the same
//! [`TrustStore`] rather than growing its own ad hoc contact list — the same reason `chat.rs`'s
//! `ChatState` lives here rather than in a shim.
//!
//! **Scope, precisely.** This task lands *state + persistence only*:
//! - TOFU-pin on first contact ([`TrustStore::observe`]): a brand-new contact is recorded
//!   directly as [`TrustState::Pinned`] the first time it is observed (never persisted as `New` —
//!   see that variant's doc for why).
//! - The human-verified transition ([`TrustStore::mark_verified`]), run after an out-of-band
//!   safety-number compare (tasks 4.4/4.5, not implemented here).
//! - Sealed-at-rest persistence, following `chat.rs`'s `ChatState` pattern exactly: CBOR-encoded,
//!   then [`meridian_crypto::at_rest`]-sealed under a key derived from the account's
//!   [`SecretStore`] handle via the *same* [`at_rest::STORE_KEY_INFO`] label `sessions.bin`
//!   already uses (ADR 0021 — every client-local sealed store shares one key derivation, not a
//!   per-store domain-separation label), with the same fail-closed-on-AEAD-failure behavior: a
//!   corrupt/tampered/wrong-key blob is a hard error, never silently reinitialized (ADR 0021
//!   condition 5b — reinitializing would erase the pinned-key history that is the whole point of
//!   TOFU).
//!
//! **Task 4.4 adds key-change handling** on top of the above: [`TrustStore::observe_key_change`]
//! (detection) and [`TrustStore::can_send`]/[`SendGate`] (the un-softenable send gate). See those
//! items' doc comments and the design note below for the detection mechanism and why it looks the
//! way it does. `PolicyCtx` in `streams.rs` is still not wired to this module — that remains a
//! later task (nothing here changes stream-open policy, only the outbound chat send path in
//! `apps/cli/src/chat.rs`).
//!
//! ## Key-change detection design (task 4.4)
//!
//! [`TrustStore`] is keyed by the peer's **current** identity key ([`Contact::pubkey`]'s own doc:
//! "also the `TrustStore` map key"). That key *is* the cryptographic principal
//! ([`meridian_identity::same_principal`] is key-only, hint-ignored) — so, by construction, this
//! store can never *derive* "this new key belongs to the same human as that old key" from the raw
//! key material alone. Two different keys are, cryptographically, two different principals, full
//! stop; that is exactly *why* a key change needs a human-verifiable safety-number check rather
//! than being silently reconciled by software.
//!
//! So "key change" is not something [`TrustStore`] discovers by itself from an [`observe`](TrustStore::observe)
//! call with a never-before-seen key — that path is (correctly, per 4.3's design) indistinguishable
//! from a brand-new contact, and stays exactly as narrow as 4.3 left it. Instead,
//! [`observe_key_change`](TrustStore::observe_key_change) takes the correlation as an **explicit
//! parameter**: the caller supplies both `previous_pubkey` (the identity this contact was already
//! pinned/verified under) and `new_pubkey` (what it is now presenting). This mirrors how the
//! feature actually works end to end: the *routing/session layer* is the thing that has a reason to
//! believe a new key is a continuation of an existing conversation — e.g., a contact address book
//! entry resolving to a different key than last time, an X3DH responder session opening under a key
//! that doesn't match what a directory/attestation record expects, or (T13, later) an account's
//! device list gaining a new signing key. `TrustStore` never guesses this from a hint or a routing
//! label; `hint`/`@domain` values are shared by many principals at one org and are explicitly
//! "never authoritative on its own for principal identity" (see [`Contact::hint`]'s doc) — good
//! enough for display, not for silently deciding two keys are the same person.
//!
//! This also keeps the design open for the explicitly-deferred extension noted in the task file:
//! device-list-change detection (T13) can reuse the exact same `observe_key_change`/[`SendGate`]
//! machinery — a newly-observed device-signed key is just another `new_pubkey` claiming continuity
//! with an existing, already-trusted `previous_pubkey` — without any structural change here.

use std::collections::BTreeMap;

use meridian_crypto::at_rest;
use meridian_identity::{IdError, KeyHandle, SecretStore};
use serde::{Deserialize, Serialize};

/// Bound a single [`Contact::hint`]'s contribution to [`TrustStore`]'s at-rest size, mirroring
/// `chat.rs`'s `MAX_INTRO_LEN` bound on pending-request intros. Nothing calls
/// [`TrustStore::observe`] yet, but once inbound routing hints (attacker-influenced) feed it
/// (task 4.4/4.7), a hostile peer re-observing with an unbounded hint string could otherwise grow
/// one contact's footprint without limit. Truncated, not rejected — an oversized-but-still-usable
/// hint is preferable to silently dropping the observation.
pub const MAX_HINT_LEN: usize = 253; // max DNS name length; generous for any real `@domain` hint.

/// Errors from the trust store.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("crypto error: {0}")]
    Crypto(#[from] meridian_crypto::CryptoError),
    #[error("keystore error: {0}")]
    Store(#[from] meridian_store::StoreError),
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    /// [`TrustStore::mark_verified`] was called for a key this store has never
    /// [`observe`](TrustStore::observe)d — there is no contact record to transition.
    #[error("no contact recorded for this key")]
    UnknownContact,
    /// (task 4.4) [`TrustStore::observe_key_change`] was asked to migrate `previous_pubkey`'s
    /// contact record onto `new_pubkey`, but `new_pubkey` already names a **different**,
    /// independently-known contact. Refused rather than merged: silently folding two contact
    /// records into one on a caller's say-so would let a claimed "key change" quietly overwrite an
    /// unrelated (possibly already-verified) contact's trust state.
    #[error("the claimed new key already belongs to a different known contact")]
    ConflictingContact,
    /// (task 4.4) [`TrustStore::acknowledge_key_change`] was called for a contact that is not
    /// currently in [`TrustState::PinnedKeyChanged`] — most importantly, this is the hard error a
    /// caller gets back if it tries to "acknowledge" a [`TrustState::Blocked`] (verified-contact
    /// key change) contact. There is deliberately **no** code path that clears `Blocked` other than
    /// [`TrustStore::mark_verified`] (docs/security/verification-ux.md: "Do not provide a one-tap
    /// 'trust anyway' / dismiss that silently re-pins without verification").
    #[error("this contact has no pending pinned-key-change warning to acknowledge")]
    NotAcknowledgeable,
}

/// The trust lifecycle for one contact (feature spec 08, "contact store states
/// `new → pinned (TOFU) → verified`", plus `blocked`).
///
/// `New` is intentionally never written to a [`Contact`]'s `state` field by this module: TOFU
/// pinning ([`TrustStore::observe`]) takes a peer straight to `Pinned` the instant it is first
/// observed, so `New` only ever describes the *absence* of a contact record — what
/// [`TrustStore::trust_state`] returns for a key it has never seen. It is kept as an explicit enum
/// value (rather than folding "no record" into `Option::None` at every call site) because the
/// public API contract (`docs/api/core-api-contracts.md`) specifies `trust_state` as a total
/// function returning `TrustState`, never `Option<TrustState>`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    /// No contact record exists yet for this key.
    #[default]
    New,
    /// Trust-on-first-use: the key was pinned automatically on first observation, unverified.
    Pinned,
    /// The user compared safety numbers out-of-band (§4.4/4.5) and confirmed the match.
    Verified,
    /// (task 4.4) A **verified** contact's key changed. Hard stop: [`TrustStore::can_send`] returns
    /// [`SendGate::Blocked`] and nothing except [`TrustStore::mark_verified`] (a genuine
    /// out-of-band re-verification) clears it — see [`TrustError::NotAcknowledgeable`].
    Blocked,
    /// (task 4.4) A **pinned** (TOFU, not verified) contact's key changed. Prominent,
    /// blocking-until-acknowledged warning: [`TrustStore::can_send`] returns [`SendGate::Warn`];
    /// [`TrustStore::acknowledge_key_change`] re-pins (returns to [`TrustState::Pinned`]) without
    /// requiring a safety-number compare, exactly as verification-ux.md specifies for the pinned
    /// case (unlike the verified case, where only re-verification clears the block). Org policy MAY
    /// escalate this straight to [`TrustState::Blocked`] instead — see
    /// [`TrustStore::set_escalate_pinned_key_change`].
    PinnedKeyChanged,
}

/// One key ever pinned for a contact, with the window it was observed in.
///
/// History (not just the current key) is retained so a future key-change check (task 4.4) can
/// tell "this is a key we've pinned before, just not the most recent one" from "this key has
/// never been seen for this contact" — the distinction the feature spec's blocking semantics need.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinnedKey {
    #[serde(with = "b32")]
    pub pubkey: [u8; 32],
    /// Unix seconds this key was first observed.
    pub first_seen_unix: u64,
    /// Unix seconds this key was most recently observed. Updated on every matching
    /// [`TrustStore::observe`] call.
    pub last_seen_unix: u64,
}

/// A contact record: the peer's current identity key, an advisory id/hint, its trust state, and
/// the full history of keys ever pinned for it (naming mirrors ADR 0021's `pinned_key_history` —
/// this module is the source of truth any client-local mirror, e.g. the TUI's `contacts.json`
/// (task 4.15), is built from).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// The peer's current Ed25519 identity key — also the [`TrustStore`] map key.
    #[serde(with = "b32")]
    pub pubkey: [u8; 32],
    /// Advisory routing hint (`@domain`), as last observed. Never authoritative on its own for
    /// principal identity — see [`meridian_identity::same_principal`].
    pub hint: String,
    pub state: TrustState,
    /// Every key ever pinned for this contact, oldest first. Never truncated or reordered by this
    /// module.
    pub pinned_key_history: Vec<PinnedKey>,
}

impl Contact {
    /// Canonical `mrd1:…@hint` string for this contact.
    pub fn id_string(&self) -> Result<String, IdError> {
        meridian_identity::to_id_string(&self.pubkey, &self.hint)
    }
}

/// The full persistable trust state: every known contact, keyed by identity key.
///
/// Unlike `chat.rs`'s `ChatState` (which deliberately does **not** derive `Debug`, since its
/// `Session`s hold ratchet secrets), every field reachable from here is already-public contact
/// metadata — a public key, an advisory hint, and observation timestamps, never key material — so
/// `Debug` is safe to derive and useful for test assertions/diagnostics.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    contacts: BTreeMap<[u8; 32], Contact>,
    /// (task 4.4) See [`TrustStore::set_escalate_pinned_key_change`]. `#[serde(default)]` so a
    /// store sealed before this task still opens (mirrors `chat.rs`'s `PrekeyVault::previous`
    /// precedent, task 1.31) — a pre-4.4 store correctly defaults to the non-escalated,
    /// warn-not-block behavior.
    #[serde(default)]
    escalate_pinned_key_change: bool,
}

/// (task 4.4) The outcome of consulting [`TrustStore::can_send`] — the un-softenable send gate
/// every client must consult before sending, and must not bypass. See
/// `docs/security/verification-ux.md` for the normative source of the `Warn`/`Blocked` wording's
/// intent; [`blocked_reason`]/[`warn_reason`] are what actually produce it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendGate {
    /// Nothing to warn about — send normally.
    Ok,
    /// A pinned (TOFU) contact's key changed. Prominent, blocking-until-acknowledged warning; not
    /// a hard stop. The peer's petname/hint-derived label is already folded into the message.
    Warn(String),
    /// A verified contact's key changed (or org policy escalated a pinned one). Hard stop — no
    /// bypass; only re-verification ([`TrustStore::mark_verified`]) clears it.
    Blocked(String),
}

impl TrustStore {
    /// The trust state for `pubkey` — [`TrustState::New`] if no contact record exists. This is
    /// the `trust_state` surface from `docs/api/core-api-contracts.md`.
    pub fn trust_state(&self, pubkey: &[u8; 32]) -> TrustState {
        self.contacts
            .get(pubkey)
            .map(|c| c.state)
            .unwrap_or_default()
    }

    /// The full contact record for `pubkey`, if one exists.
    pub fn contact(&self, pubkey: &[u8; 32]) -> Option<&Contact> {
        self.contacts.get(pubkey)
    }

    /// All known contacts (`BTreeMap`/key order — stable, not observation order, which this
    /// clock-free crate has no independent way to record beyond the caller-supplied timestamps
    /// already on each [`PinnedKey`]).
    pub fn contacts(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.values()
    }

    /// Record an observation of `pubkey` under `hint`, TOFU-pinning it if this is the first time
    /// this store has ever seen it (feature spec 08: "new → pinned (TOFU)").
    ///
    /// `now_unix` is the caller's wall clock in unix seconds — this crate is deliberately
    /// clock-free (it compiles to wasm32, where `std::time::SystemTime::now()` is unavailable;
    /// see `chat.rs`'s `PrekeyVault::set_bundle` for the identical constraint), so time is
    /// injected rather than read here.
    ///
    /// **Behavior, precisely (and why it stops here).**
    /// - No record yet for `pubkey`: create one directly in [`TrustState::Pinned`] (never a
    ///   persisted `New` step — see [`TrustState`]'s doc), with a single [`PinnedKey`] history
    ///   entry stamped `first_seen_unix == last_seen_unix == now_unix`.
    /// - A record already exists for exactly this `pubkey` (this method is keyed by `pubkey`
    ///   itself, so this is the only case it can reach for a repeat call): refresh
    ///   `last_seen_unix` on the matching history entry (or add one, defensively, if that
    ///   invariant were ever violated) and update `hint`. The trust state itself is left
    ///   untouched — repeated observation of the *same* key never changes `Pinned`/`Verified`/
    ///   `Blocked` on its own.
    ///
    /// **What this deliberately does *not* do.** This method never detects a key change. Because
    /// [`TrustStore`] is keyed by `pubkey`, a `pubkey` this store has never seen before is *always*
    /// treated as a brand-new contact (straight to `Pinned`) — even if, unbeknownst to this method,
    /// it is really the same human presenting a new key. Callers that have an actual reason to
    /// believe two keys belong to the same contact (task 4.4) must say so explicitly via
    /// [`observe_key_change`](Self::observe_key_change) instead of calling this method with the new
    /// key — see that method's doc and the module-level "Key-change detection design" note for why
    /// this store cannot and does not infer that correlation on its own.
    ///
    /// `hint` is truncated to [`MAX_HINT_LEN`] bytes (at a UTF-8 boundary) before being stored —
    /// this module does not otherwise validate it (e.g. via `meridian_identity::validate_hint`),
    /// so a caller feeding an inbound routing hint should validate/normalize it first if it needs
    /// [`Contact::id_string`] to succeed later.
    ///
    /// Returns the resulting [`TrustState`] (always [`TrustState::Pinned`] on first observation;
    /// the contact's current state otherwise).
    pub fn observe(&mut self, pubkey: [u8; 32], hint: &str, now_unix: u64) -> TrustState {
        if let Some(contact) = self.contacts.get_mut(&pubkey) {
            match contact
                .pinned_key_history
                .iter_mut()
                .find(|k| k.pubkey == pubkey)
            {
                Some(entry) => entry.last_seen_unix = now_unix,
                None => contact.pinned_key_history.push(PinnedKey {
                    pubkey,
                    first_seen_unix: now_unix,
                    last_seen_unix: now_unix,
                }),
            }
            if !hint.is_empty() {
                contact.hint = bounded_hint(hint);
            }
            return contact.state;
        }

        self.contacts.insert(
            pubkey,
            Contact {
                pubkey,
                hint: bounded_hint(hint),
                state: TrustState::Pinned,
                pinned_key_history: vec![PinnedKey {
                    pubkey,
                    first_seen_unix: now_unix,
                    last_seen_unix: now_unix,
                }],
            },
        );
        TrustState::Pinned
    }

    /// Transition a known contact to [`TrustState::Verified`], after an out-of-band safety-number
    /// compare (§4.4/4.5's QR/numeric flow — not implemented here). The `mark_verified` surface
    /// from `docs/api/core-api-contracts.md`.
    ///
    /// Errs [`TrustError::UnknownContact`] if `pubkey` has never been [`observe`](Self::observe)d
    /// — there is no contact record to verify. **This is the only path (task 4.4) that clears
    /// [`TrustState::Blocked`]** — a verified contact's key change stays hard-blocked until the
    /// user actually re-runs a genuine out-of-band safety-number compare and this method is called
    /// as its result; there is deliberately no other way to reach `Verified` from `Blocked`. It also
    /// clears [`TrustState::PinnedKeyChanged`] (verifying is always at least as strong as
    /// acknowledging), and transitions the ordinary `Pinned` case exactly as before 4.4.
    pub fn mark_verified(&mut self, pubkey: &[u8; 32]) -> Result<(), TrustError> {
        let contact = self
            .contacts
            .get_mut(pubkey)
            .ok_or(TrustError::UnknownContact)?;
        contact.state = TrustState::Verified;
        Ok(())
    }

    /// (task 4.4) Record a **claimed key change**: `new_pubkey` claims to be a continuation of the
    /// contact currently on record under `previous_pubkey`. See the module-level "Key-change
    /// detection design" note for why this correlation is always an explicit caller-supplied
    /// parameter rather than something this store infers from `new_pubkey` alone.
    ///
    /// **State transition, precisely** (verification-ux.md's normative block/warn semantics):
    /// - Prior state [`Verified`](TrustState::Verified) → [`Blocked`](TrustState::Blocked). Hard
    ///   stop; only [`mark_verified`](Self::mark_verified) clears it.
    /// - Prior state [`Pinned`](TrustState::Pinned) → [`PinnedKeyChanged`](TrustState::PinnedKeyChanged)
    ///   (prominent, blocking-until-acknowledged warning; [`acknowledge_key_change`](Self::acknowledge_key_change)
    ///   re-pins) — or straight to [`Blocked`](TrustState::Blocked) if
    ///   [`escalate_pinned_key_change`](Self::escalate_pinned_key_change) is set (org policy MAY
    ///   escalate the pinned case to the same hard block as verified).
    /// - Prior state [`Blocked`](TrustState::Blocked) or [`PinnedKeyChanged`](TrustState::PinnedKeyChanged)
    ///   (already mid-incident): stays at least as strict — a further key change never *relaxes*
    ///   the state, and re-applies the escalation setting (so turning escalation on tightens an
    ///   in-flight `PinnedKeyChanged` to `Blocked` on the next observed change).
    /// - [`New`](TrustState::New) is unreachable here (never persisted on a real `Contact` — see
    ///   [`TrustState`]'s doc) but is handled fail-closed (→ `Blocked`) rather than treated as
    ///   unreachable code, on the general principle that an impossible state should never be the
    ///   one case that accidentally under-protects.
    ///
    /// If `new_pubkey` is identical to `previous_pubkey`'s current key, this is not actually a
    /// change (a caller mis-supplying the same key twice, or re-confirming); it behaves exactly
    /// like a repeat [`observe`](Self::observe) call and leaves the trust state untouched.
    ///
    /// **Errors.** [`TrustError::UnknownContact`] if `previous_pubkey` has no contact record at
    /// all. [`TrustError::ConflictingContact`] if `new_pubkey` already names a *different* known
    /// contact — see that variant's doc for why this is refused rather than merged.
    ///
    /// On success, the contact record is **migrated**: it is removed from `previous_pubkey` and
    /// re-inserted keyed by `new_pubkey` (which becomes the new [`Contact::pubkey`] / current
    /// identity key — same "map key is the current identity key" convention [`observe`](Self::observe)
    /// already follows), with a new [`PinnedKey`] history entry appended for `new_pubkey` (the full
    /// history, including `previous_pubkey`'s entries, is preserved — never truncated). `hint` is
    /// bounded exactly as [`observe`](Self::observe) bounds it, and only overwrites the stored hint
    /// if non-empty.
    pub fn observe_key_change(
        &mut self,
        previous_pubkey: &[u8; 32],
        new_pubkey: [u8; 32],
        hint: &str,
        now_unix: u64,
    ) -> Result<TrustState, TrustError> {
        if !self.contacts.contains_key(previous_pubkey) {
            return Err(TrustError::UnknownContact);
        }
        if new_pubkey == *previous_pubkey {
            // Not actually a change — behave exactly like a plain repeat observation, touching
            // nothing about the trust state.
            return Ok(self.observe(new_pubkey, hint, now_unix));
        }
        if let Some(existing) = self.contacts.get(&new_pubkey) {
            if &existing.pubkey != previous_pubkey {
                return Err(TrustError::ConflictingContact);
            }
        }

        let mut contact = self
            .contacts
            .remove(previous_pubkey)
            .expect("checked contains_key above");
        let new_state = escalated_state(contact.state, self.escalate_pinned_key_change);

        contact.pubkey = new_pubkey;
        if !hint.is_empty() {
            contact.hint = bounded_hint(hint);
        }
        contact.state = new_state;
        match contact
            .pinned_key_history
            .iter_mut()
            .find(|k| k.pubkey == new_pubkey)
        {
            Some(entry) => entry.last_seen_unix = now_unix,
            None => contact.pinned_key_history.push(PinnedKey {
                pubkey: new_pubkey,
                first_seen_unix: now_unix,
                last_seen_unix: now_unix,
            }),
        }
        self.contacts.insert(new_pubkey, contact);
        Ok(new_state)
    }

    /// (task 4.4) Acknowledge a [`TrustState::PinnedKeyChanged`] warning, re-pinning the new key
    /// (transitions to [`TrustState::Pinned`]) **without** requiring a safety-number compare —
    /// exactly what verification-ux.md specifies for the pinned (not-yet-verified) case:
    /// "Acknowledgement re-pins."
    ///
    /// **This can never clear [`TrustState::Blocked`].** If `pubkey`'s contact is not currently in
    /// `PinnedKeyChanged` — most importantly, if it is `Blocked` — this returns
    /// [`TrustError::NotAcknowledgeable`] and changes nothing. That is the load-bearing half of the
    /// "no bypass" invariant: a verified contact's key-change block has exactly one way out
    /// ([`mark_verified`](Self::mark_verified), which requires an actual out-of-band re-verification),
    /// never a one-tap "acknowledge"/dismiss.
    ///
    /// **Escalation applies retroactively to an already-in-flight warning, not just future ones.**
    /// If [`escalate_pinned_key_change`](Self::escalate_pinned_key_change) is `true` at the moment
    /// of the call, a contact sitting in `PinnedKeyChanged` from *before* escalation was turned on
    /// is force-transitioned to [`TrustState::Blocked`] instead of being re-pinned, and this
    /// returns [`TrustError::NotAcknowledgeable`] (there is no longer anything a plain
    /// acknowledgment can clear — only [`mark_verified`](Self::mark_verified) can now). Without
    /// this check, an org flipping escalation on as an incident response (e.g. "we suspect an
    /// active MITM, force hard-block") could be silently defeated by a user acknowledging a
    /// still-outstanding warning in the gap before the next observed key change — exactly the
    /// bypass `set_escalate_pinned_key_change`'s escalation exists to prevent.
    pub fn acknowledge_key_change(&mut self, pubkey: &[u8; 32]) -> Result<(), TrustError> {
        let escalate = self.escalate_pinned_key_change;
        let contact = self
            .contacts
            .get_mut(pubkey)
            .ok_or(TrustError::UnknownContact)?;
        if contact.state != TrustState::PinnedKeyChanged {
            return Err(TrustError::NotAcknowledgeable);
        }
        if escalate {
            contact.state = TrustState::Blocked;
            return Err(TrustError::NotAcknowledgeable);
        }
        contact.state = TrustState::Pinned;
        Ok(())
    }

    /// (task 4.4) The send gate for `pubkey` — the surface every client (CLI today, TUI's modal in
    /// 4.22 later) must consult before sending, and must not bypass. `pubkey` with no contact
    /// record at all (never [`observe`](Self::observe)d) reads [`SendGate::Ok`] — nothing to gate
    /// yet; TOFU pinning happens on `observe`, not here.
    ///
    /// The `reason` strings carried by [`SendGate::Warn`]/[`SendGate::Blocked`] preserve, in
    /// meaning, verification-ux.md's canonical intent text: the benign explanation, the
    /// interception possibility, that sends are paused, and that Verify is the way forward — never
    /// softened into pure reassurance (see [`blocked_reason`]/[`warn_reason`]).
    pub fn can_send(&self, pubkey: &[u8; 32]) -> SendGate {
        let Some(contact) = self.contacts.get(pubkey) else {
            return SendGate::Ok;
        };
        let label = contact_label(contact);
        match contact.state {
            TrustState::Blocked => SendGate::Blocked(blocked_reason(&label)),
            TrustState::PinnedKeyChanged => SendGate::Warn(warn_reason(&label)),
            TrustState::New | TrustState::Pinned | TrustState::Verified => SendGate::Ok,
        }
    }

    /// (task 4.4) Org-configurable escalation: when set, a **pinned** contact's key change
    /// produces the same [`TrustState::Blocked`] hard stop as a verified contact's, instead of
    /// [`TrustState::PinnedKeyChanged`]'s warn-and-acknowledge (verification-ux.md: "org policy MAY
    /// escalate this to the same hard block as verified"). Defaults to `false` — plain TOFU-warn
    /// behavior — and is itself part of the persisted, sealed-at-rest store (so the org policy in
    /// effect when a contact's state was last touched is what gets restored, not silently reset to
    /// the default on reload).
    pub fn set_escalate_pinned_key_change(&mut self, escalate: bool) {
        self.escalate_pinned_key_change = escalate;
    }

    /// The current escalation setting — see [`set_escalate_pinned_key_change`](Self::set_escalate_pinned_key_change).
    pub fn escalate_pinned_key_change(&self) -> bool {
        self.escalate_pinned_key_change
    }

    /// Serialize and seal the whole store under a key derived from the account key in `store` —
    /// identical mechanism to `chat.rs`'s `ChatState::seal_at_rest` (ADR 0021: one key derivation,
    /// shared by every client-local sealed store).
    pub fn seal_at_rest(
        &self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
    ) -> Result<Vec<u8>, TrustError> {
        let mut plaintext = Vec::new();
        ciborium::into_writer(self, &mut plaintext)
            .map_err(|e| meridian_proto::CodecError::Encode(e.to_string()))?;
        let key = store_key(store, handle)?;
        Ok(at_rest::seal(&key, &plaintext)?)
    }

    /// Open a store previously produced by [`seal_at_rest`](Self::seal_at_rest).
    ///
    /// Fails closed on any AEAD/decode error (ADR 0021 condition 5b): callers must not treat a
    /// decrypt failure as "no contacts yet" the way a genuinely missing file legitimately falls
    /// back to a fresh/default store — see that condition's rationale (a silent reinitialize here
    /// would erase the pinned-key history TOFU depends on).
    pub fn open_at_rest(
        store: &dyn SecretStore,
        handle: &KeyHandle,
        sealed: &[u8],
    ) -> Result<Self, TrustError> {
        let key = store_key(store, handle)?;
        let plaintext = at_rest::open(&key, sealed)?;
        let state: Self = ciborium::from_reader(&plaintext[..])
            .map_err(|e| meridian_proto::CodecError::Decode(e.to_string()))?;
        Ok(state)
    }
}

/// Truncate `hint` to [`MAX_HINT_LEN`] bytes at a UTF-8 char boundary.
fn bounded_hint(hint: &str) -> String {
    if hint.len() <= MAX_HINT_LEN {
        return hint.to_string();
    }
    let mut end = MAX_HINT_LEN;
    while !hint.is_char_boundary(end) {
        end -= 1;
    }
    hint[..end].to_string()
}

/// (task 4.4) The next [`TrustState`] a contact currently at `prior_state` reaches after
/// [`TrustStore::observe_key_change`] records a genuine key change, given whether org policy
/// escalates the pinned case (`escalate`). See [`TrustStore::observe_key_change`]'s doc for the
/// full transition table this implements; kept as a free function so the table itself — the part a
/// reviewer most needs to check against verification-ux.md — is easy to read in one place.
fn escalated_state(prior_state: TrustState, escalate: bool) -> TrustState {
    match prior_state {
        TrustState::Verified => TrustState::Blocked,
        TrustState::Pinned | TrustState::PinnedKeyChanged => {
            if escalate {
                TrustState::Blocked
            } else {
                TrustState::PinnedKeyChanged
            }
        }
        // Already blocked: a further claimed key change never relaxes it. Only `mark_verified`
        // (a genuine re-verification) gets a contact out of `Blocked` — see that method's doc.
        TrustState::Blocked => TrustState::Blocked,
        // Never persisted on a real `Contact` (see `TrustState::New`'s doc) — unreachable in
        // practice, but fails closed (strongest protection) rather than being treated as
        // impossible-so-it-doesn't-matter.
        TrustState::New => TrustState::Blocked,
    }
}

/// The best available human-facing label for `contact` in a [`SendGate`] message. Petname
/// assignment (feature spec 08 §3.1: "display names are never taken from the wire") has not landed
/// yet as of this task — `TODO: confirm` once it does, this should prefer the local petname over
/// the advisory hint. Until then, falls back to the hint, and — if even that is empty — a short,
/// unambiguous key-derived label so a warning/block message is never left without an identifiable
/// subject.
fn contact_label(contact: &Contact) -> String {
    if !contact.hint.is_empty() {
        contact.hint.clone()
    } else {
        format!("contact {}", &hex::encode(contact.pubkey)[..12])
    }
}

/// Canonical wording for [`SendGate::Blocked`] — a **verified** contact's key change
/// (docs/security/verification-ux.md, "Key change on a VERIFIED contact — BLOCK"). Preserves, in
/// meaning: the benign explanation, the interception possibility (hard prohibition #2: never imply
/// the change is definitely benign without also stating this), that sends are paused/blocked (not
/// a warning-with-continue — hard prohibition #3), and that Verify is the way forward. Deliberately
/// contains no "trust anyway" / dismiss wording anywhere (hard prohibition #1) — there isn't one,
/// because [`TrustStore::acknowledge_key_change`] cannot clear this state at all.
///
/// `TODO: confirm` final user-facing copy with design/UX (verification-ux.md's own note): this is
/// the canonical *intent*, not necessarily the last word on phrasing.
fn blocked_reason(label: &str) -> String {
    format!(
        "The safety number for {label} has changed. This can happen if they reinstalled or \
         switched devices — but it can also mean someone is intercepting your messages. Sends to \
         {label} are blocked until you verify the new safety number with them through a channel \
         you trust. Verify the new safety number to resume, or leave this contact blocked — there \
         is no way to send without doing one of those."
    )
}

/// Canonical wording for [`SendGate::Warn`] — a **pinned** (TOFU, not yet verified) contact's key
/// change (docs/security/verification-ux.md, "Key change on a PINNED contact — PROMINENT
/// WARNING"). Same substance as [`blocked_reason`] (benign explanation + interception possibility +
/// paused sends + Verify) but for the warn-not-block case: acknowledging (without verifying) is
/// possible here, via [`TrustStore::acknowledge_key_change`], and this message says so — the
/// distinction that keeps this from being a disguised bypass rather than an honestly weaker gate.
///
/// `TODO: confirm` final user-facing copy with design/UX (same note as [`blocked_reason`]).
fn warn_reason(label: &str) -> String {
    format!(
        "The safety number for {label} has changed. This can happen if they reinstalled or \
         switched devices — but it can also mean someone is intercepting your messages. Sends to \
         {label} are paused until you either verify the new safety number with them through a \
         channel you trust, or explicitly acknowledge this warning (which re-pins the new key \
         without verifying it — verify first if anything you're about to send is sensitive)."
    )
}

fn store_key(store: &dyn SecretStore, handle: &KeyHandle) -> Result<[u8; 32], TrustError> {
    // Derive directly through the store (private key never leaves it) — same call as `chat.rs`'s
    // `store_key`, deliberately the same label (ADR 0021): one derivation per account, shared by
    // every client-local sealed store rather than a bespoke domain-separation string per store.
    Ok(store.derive_key(handle, at_rest::STORE_KEY_INFO)?)
}

// Local byte-string serde helper (kept private to this module; mirrors `chat.rs`'s `b32`, which
// is likewise crate-module-private — there is no shared helper today).
mod b32 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = serde_bytes_vec(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
    fn serde_bytes_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}
