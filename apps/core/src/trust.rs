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
//! **Explicitly out of scope here** (see the task file): key-change *detection* — a contact whose
//! claimed key differs from what is already pinned/verified for that identity — and the
//! resulting warn/block semantics land in task 4.4. [`TrustStore::observe`] therefore only ever
//! reasons about the *matching*-key case; see its doc comment for the precise (deliberately
//! narrow) behavior on repeat observation. `PolicyCtx` in `streams.rs` already anticipates this
//! module's arrival in its own doc comment ("T08 grows the trust surface") but is **not** wired to
//! it here — that hook-up is task 4.4's job.

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
    /// Blocked pending re-verification. No path in this task sets this state — it lands with
    /// task 4.4's key-change handling.
    Blocked,
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
    /// **What this deliberately does *not* do.** Detecting that a peer previously known under one
    /// key is now presenting a *different* one — and reacting with a warn/block decision — is
    /// task 4.4's job. Because [`TrustStore`] is keyed by `pubkey`, a different key for "the same
    /// human" is, from this store's point of view alone, simply a different map entry with no
    /// link back to the old one; correlating the two identities and deciding what to do about it
    /// is exactly the surface 4.4 adds. Callers must not treat this method as key-change-safe
    /// until that lands.
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
    /// — there is no contact record to verify. Any existing state (`Pinned`, or in principle
    /// `Blocked` once task 4.4 can set it) transitions to `Verified`; this module does not yet
    /// gate that decision on the prior state — that policy question also belongs to 4.4.
    pub fn mark_verified(&mut self, pubkey: &[u8; 32]) -> Result<(), TrustError> {
        let contact = self
            .contacts
            .get_mut(pubkey)
            .ok_or(TrustError::UnknownContact)?;
        contact.state = TrustState::Verified;
        Ok(())
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
