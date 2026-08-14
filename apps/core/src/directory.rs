//! Org directory-attestation ingest (T08, task 4.8): client-side ingest of a signed, org-issued
//! HR-name -> account-key mapping, offered to a user as a **display-name suggestion with recorded
//! provenance** — never a substitute for out-of-band verification and never a key authority
//! (`docs/architecture/system-design.md` §3.5).
//!
//! **This module implements a settled, already-reviewed schema verbatim.** The full schema, the
//! precise signed-byte-sequence definition, and the "provenance-not-authority boundary" this
//! module exists to enforce are specified in
//! [`docs/security/directory-attestation.md`](../../../docs/security/directory-attestation.md) —
//! architect+security-reviewer-approved after a revision pass. Do not redesign it here.
//!
//! # The provenance-not-authority boundary (structural, not just tested)
//!
//! [`DirectoryStore`] is the **only** type this module defines that holds mutable state, and its
//! one field is `suggestions: BTreeMap<[u8; 32], Vec<DirectorySuggestion>>` — nothing else. This
//! module never imports [`crate::trust::Contact`] or [`crate::trust::TrustState`], and
//! [`DirectoryStore`] never holds a reference to a [`crate::trust::TrustStore`]. So
//! [`DirectoryStore::ingest_directory`] is not merely *written* to avoid calling
//! `observe`/`set_petname`/`mark_verified`/`set_user_blocked` — it has **no way to reach** those
//! methods or the `Contact`/`TrustState` types they operate on: they are simply not in scope, and
//! there is no field here from which a `TrustStore` could even be obtained. `TrustStore` (in
//! `trust.rs`) embeds a `DirectoryStore` field purely for at-rest persistence (so directory
//! suggestions ride the same sealed blob as contacts) and exposes thin one-line pass-through
//! methods with the same names/signatures — but the actual ingest logic lives entirely in this
//! module, over a type that is structurally incapable of touching contact/trust state.
//!
//! An attestation for a key this client has never [`observe`](crate::trust::TrustStore::observe)d
//! still gets a [`DirectorySuggestion`] recorded (unmatched entries are held, not dropped — see
//! the schema doc's "Unmatched entries are held, not dropped" section) — that is exactly why this
//! module cannot and does not consult `TrustStore::contacts` at all; ingest never needs to know
//! whether a key is already a contact.

use std::collections::BTreeMap;

use meridian_identity::{verify, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// Format version. A bump changes the signed-artifact bytes.
pub const DIRECTORY_VERSION: u16 = 1;

/// Upper bound on entries in one artifact — bounds ingest cost and at-rest storage growth from a
/// single import (mirrors `chat.rs`'s `MAX_PENDING_REQUESTS`/`trust.rs`'s `MAX_HINT_LEN` precedent
/// of capping attacker- or bulk-import-controlled collection sizes). A larger enterprise splits
/// across multiple `.mrdir` files/imports rather than needing a bigger single-file cap.
pub const MAX_DIRECTORY_ENTRIES: usize = 10_000;

/// Bound one entry's `hr_name` — hostile-input-facing content (an org's directory, or a
/// compromised org signing key, is the same threat class as `Contact::hint`, not the
/// user-typed-only `Contact::petname` — see `trust.rs`'s `MAX_HINT_LEN` vs. `MAX_PETNAME_LEN`
/// distinction). Reuses `trust.rs`'s `MAX_HINT_LEN` value (253) for the same reasoning; truncated
/// at ingest, at a UTF-8 boundary, never rejected — same style as `bounded_hint`/`bounded_petname`.
pub const MAX_HR_NAME_LEN: usize = 253;

/// Total cap on suggestions held across ALL imports, not just one artifact —
/// [`MAX_DIRECTORY_ENTRIES`] alone only bounds a single artifact's contribution; repeated
/// re-imports or several distinct `.mrdir` files pinned to one (or a compromised)
/// `org_signing_pub` could otherwise grow the suggestions map unboundedly. Mirrors `chat.rs`'s
/// `MAX_PENDING_REQUESTS` + `evict_oldest_pending` pattern exactly: the globally oldest
/// `attested_at` entry is evicted first once this cap is hit.
pub const MAX_TOTAL_DIRECTORY_SUGGESTIONS: usize = 50_000;

/// Errors from [`DirectoryStore::ingest_directory`]. Every variant means the **whole** artifact was
/// rejected — nothing partial is ever stored on an error return.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    /// The artifact's self-claimed `org_signing_pub` does not match the caller-supplied
    /// `expected_org_signing_pub` trust anchor. Checked and rejected **before** signature
    /// verification: an artifact proves nothing about who signed it by simply claiming a key —
    /// the caller-pinned key (mirrors `federation_map.toml`'s `pinned_identity`, ADR 0017) is the
    /// only thing that makes the signature check meaningful at all.
    #[error("artifact's org_signing_pub does not match the caller-supplied trust anchor")]
    OrgKeyMismatch,
    /// `org_signing_pub` does not decode to a valid Ed25519 point.
    #[error("artifact's org_signing_pub is not a valid Ed25519 key")]
    BadSigningKey,
    /// `sig` does not verify over the reconstructed [`DirectoryAttestationSignable`] under
    /// `org_signing_pub`.
    #[error("artifact signature does not verify")]
    BadSignature,
    /// `entries.len() > MAX_DIRECTORY_ENTRIES`.
    #[error("artifact has {0} entries, exceeding the per-import cap of {MAX_DIRECTORY_ENTRIES}")]
    TooManyEntries(usize),
}

/// One entry in a [`DirectoryAttestation`]: an account key and the HR name the issuing org
/// attests for it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// The account key this entry names.
    #[serde(with = "meridian_proto::bytes::b32")]
    pub account_pub: [u8; 32],
    /// e.g. "Dana Smith, Finance" — bounded by [`MAX_HR_NAME_LEN`] at ingest.
    pub hr_name: String,
}

/// The exact byte sequence [`DirectoryAttestation::sig`] is computed and verified over: every
/// field of [`DirectoryAttestation`] except `sig` itself, as its own concrete type — not "the
/// struct minus a field" as a loose instruction, which would leave two independent
/// implementations (native, WASM, a future mobile-via-UniFFI client) free to diverge on exactly
/// what bytes get signed. CBOR-encoded via `ciborium::into_writer`, full stop — see
/// [`docs/security/directory-attestation.md`](../../../docs/security/directory-attestation.md)'s
/// own doc comment for this type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAttestationSignable {
    pub v: u16,
    pub org_domain: String,
    #[serde(with = "meridian_proto::bytes::b32")]
    pub org_signing_pub: [u8; 32],
    pub issued_at: u64,
    pub entries: Vec<DirectoryEntry>,
}

impl DirectoryAttestationSignable {
    /// CBOR-encode this type — exactly the byte sequence [`DirectoryAttestation::sig`] is
    /// signed/verified over. `pub` so a future attestation-issuing tool (org-side, out of this
    /// task's scope) and this module's own tests can produce the same bytes this module verifies.
    pub fn to_cbor(&self) -> Result<Vec<u8>, DirectoryError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| meridian_proto::CodecError::Encode(e.to_string()))?;
        Ok(buf)
    }
}

/// The full signed directory-attestation artifact — one org's signed HR-name → account-key
/// mapping. Never a wire type (never crosses the rendezvous c2s/s2s connection); distributed
/// out-of-band and ingested via `meridian directory import`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAttestation {
    pub v: u16,
    /// The issuing org's hint domain, e.g. "org-a.test" — display only, never the trust anchor
    /// (that is the caller-supplied `expected_org_signing_pub`, see [`DirectoryError::OrgKeyMismatch`]).
    pub org_domain: String,
    /// Ed25519 public key this artifact is signed under.
    #[serde(with = "meridian_proto::bytes::b32")]
    pub org_signing_pub: [u8; 32],
    /// Unix seconds, org's clock.
    pub issued_at: u64,
    pub entries: Vec<DirectoryEntry>,
    /// Ed25519(`org_signing_pub`) over the CBOR encoding of the [`DirectoryAttestationSignable`]
    /// built from every field above.
    #[serde(with = "meridian_proto::bytes::b64")]
    pub sig: [u8; 64],
}

impl DirectoryAttestation {
    /// Decode a `.mrdir` artifact's raw CBOR bytes (as read from disk by `meridian directory
    /// import`) into a [`DirectoryAttestation`]. Malformed/hostile input decodes to a clean
    /// [`DirectoryError::Codec`] — never a panic.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DirectoryError> {
        ciborium::from_reader(bytes)
            .map_err(|e| meridian_proto::CodecError::Decode(e.to_string()).into())
    }

    /// The [`DirectoryAttestationSignable`] this artifact's `sig` is computed/verified over.
    pub fn signable(&self) -> DirectoryAttestationSignable {
        DirectoryAttestationSignable {
            v: self.v,
            org_domain: self.org_domain.clone(),
            org_signing_pub: self.org_signing_pub,
            issued_at: self.issued_at,
            entries: self.entries.clone(),
        }
    }
}

/// A suggested display name for `account_pub`, with the provenance that produced it — **distinct
/// from, and never merged into, [`crate::trust::Contact::petname`]** (the provenance-not-authority
/// boundary; see this module's own doc comment).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySuggestion {
    /// Bounded by [`MAX_HR_NAME_LEN`], truncate-not-reject.
    pub hr_name: String,
    /// Display only — never the match key (see `org_signing_pub` below).
    pub org_domain: String,
    /// The match key: which attesting org this suggestion is from. A single `account_pub` can
    /// carry one suggestion per distinct `org_signing_pub`, never collapsed to one.
    #[serde(with = "meridian_proto::bytes::b32")]
    pub org_signing_pub: [u8; 32],
    /// The artifact's `issued_at` — not local ingest time.
    pub attested_at: u64,
}

/// The suggestions store: every [`DirectorySuggestion`] ever ingested, multi-valued per
/// `account_pub` (one slot per distinct attesting `org_signing_pub`, never collapsed). See this
/// module's doc comment for why this type — and not [`crate::trust::TrustStore`] — is the one that
/// actually performs ingest: it has no way to reach `Contact`/`TrustState` at all.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DirectoryStore {
    suggestions: BTreeMap<[u8; 32], Vec<DirectorySuggestion>>,
    /// Running total of suggestions across every key's `Vec`, maintained in lockstep with
    /// `suggestions` by [`upsert`](Self::upsert)/[`evict_oldest`](Self::evict_oldest) — avoids an
    /// O(n) rescan of the whole map on every ingested entry (which would make a large ingest
    /// quadratic). `#[serde(default)]` so a store sealed before this task still opens;
    /// [`reconcile_total`](Self::reconcile_total) repairs it defensively after every
    /// `open_at_rest`, the same "trust the persisted value, but repair on load" pattern as
    /// `chat.rs`'s `request_order`/`reconcile_request_order`.
    #[serde(default)]
    total: usize,
}

impl DirectoryStore {
    /// Verify and ingest `artifact`, upserting one [`DirectorySuggestion`] per entry.
    ///
    /// `expected_org_signing_pub` is the caller-supplied trust anchor (never the artifact's own
    /// self-claimed key alone) — see [`DirectoryError::OrgKeyMismatch`]. Rejects the **whole**
    /// artifact (nothing stored) on: a key mismatch, a malformed `org_signing_pub`, a signature
    /// that doesn't verify, or `entries.len() > MAX_DIRECTORY_ENTRIES`.
    ///
    /// On success: for each entry, a suggestion from the same `org_signing_pub` already on record
    /// for that `account_pub` is replaced only if the new `issued_at` (this artifact's, applied to
    /// every entry) is strictly later — never regressed to an older attestation; a suggestion from
    /// a *different* `org_signing_pub` is pushed alongside, never overwritten. Once the running
    /// total across every key's `Vec` would exceed [`MAX_TOTAL_DIRECTORY_SUGGESTIONS`], the
    /// globally oldest `attested_at` entry anywhere in the map is evicted before the new one is
    /// inserted (mirrors `chat.rs`'s `MAX_PENDING_REQUESTS`/`evict_oldest_pending`).
    ///
    /// Returns the count of entries ingested (for CLI/TUI feedback).
    pub fn ingest_directory(
        &mut self,
        artifact: &DirectoryAttestation,
        expected_org_signing_pub: &[u8; 32],
    ) -> Result<usize, DirectoryError> {
        if artifact.org_signing_pub != *expected_org_signing_pub {
            return Err(DirectoryError::OrgKeyMismatch);
        }
        if artifact.entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(DirectoryError::TooManyEntries(artifact.entries.len()));
        }
        let pk = PublicKey::from_bytes(artifact.org_signing_pub)
            .map_err(|_| DirectoryError::BadSigningKey)?;

        let msg = artifact.signable().to_cbor()?;
        let sig = Signature::from_bytes(artifact.sig);
        if !verify(&pk, &msg, &sig) {
            return Err(DirectoryError::BadSignature);
        }

        let mut ingested = 0usize;
        for entry in &artifact.entries {
            let suggestion = DirectorySuggestion {
                hr_name: bounded_hr_name(&entry.hr_name),
                org_domain: artifact.org_domain.clone(),
                org_signing_pub: artifact.org_signing_pub,
                attested_at: artifact.issued_at,
            };
            self.upsert(entry.account_pub, suggestion);
            ingested += 1;
        }
        Ok(ingested)
    }

    /// Every suggestion on record for `account_pub` — zero or more, in no particular order beyond
    /// the map's own (insertion-order-ish, see [`upsert`](Self::upsert)) `Vec` order. Read-only.
    pub fn suggestions(
        &self,
        account_pub: &[u8; 32],
    ) -> impl Iterator<Item = &DirectorySuggestion> {
        self.suggestions.get(account_pub).into_iter().flatten()
    }

    /// Recompute `total` from `suggestions` directly — called by
    /// [`TrustStore::open_at_rest`](crate::trust::TrustStore::open_at_rest) right after
    /// deserializing, so a store sealed before this task (`total` defaults to 0 via
    /// `#[serde(default)]` regardless of how many suggestions it actually holds) — or any other
    /// way the two could have desynced — can't leave [`ingest_directory`](Self::ingest_directory)'s
    /// cap check looking at a stale count.
    pub(crate) fn reconcile_total(&mut self) {
        self.total = self.suggestions.values().map(Vec::len).sum();
    }

    /// Upsert one suggestion for `account_pub`: replace-in-place (only if strictly newer) for a
    /// repeat `org_signing_pub`, push-alongside for a new one — evicting the globally oldest entry
    /// first if the push would take the running total to (or past) [`MAX_TOTAL_DIRECTORY_SUGGESTIONS`].
    fn upsert(&mut self, account_pub: [u8; 32], suggestion: DirectorySuggestion) {
        if let Some(list) = self.suggestions.get_mut(&account_pub) {
            if let Some(existing) = list
                .iter_mut()
                .find(|s| s.org_signing_pub == suggestion.org_signing_pub)
            {
                if suggestion.attested_at > existing.attested_at {
                    *existing = suggestion;
                }
                return;
            }
        }
        if self.total >= MAX_TOTAL_DIRECTORY_SUGGESTIONS {
            self.evict_oldest();
        }
        self.suggestions
            .entry(account_pub)
            .or_default()
            .push(suggestion);
        self.total += 1;
    }

    /// Drop the single suggestion with the globally smallest `attested_at` anywhere in the map
    /// (mirrors `chat.rs`'s `evict_oldest_pending`, applied to this map instead).
    fn evict_oldest(&mut self) {
        let mut oldest: Option<([u8; 32], usize, u64)> = None;
        for (key, list) in self.suggestions.iter() {
            for (idx, s) in list.iter().enumerate() {
                let is_older = match oldest {
                    Some((_, _, t)) => s.attested_at < t,
                    None => true,
                };
                if is_older {
                    oldest = Some((*key, idx, s.attested_at));
                }
            }
        }
        if let Some((key, idx, _)) = oldest {
            if let Some(list) = self.suggestions.get_mut(&key) {
                list.remove(idx);
                if list.is_empty() {
                    self.suggestions.remove(&key);
                }
                self.total = self.total.saturating_sub(1);
            }
        }
    }
}

/// Truncate `hr_name` to [`MAX_HR_NAME_LEN`] bytes at a UTF-8 char boundary — shares `trust.rs`'s
/// `truncate_utf8` implementation rather than duplicating the truncation loop (the same helper
/// `bounded_hint`/`bounded_petname` are built on).
fn bounded_hr_name(hr_name: &str) -> String {
    crate::trust::truncate_utf8(hr_name, MAX_HR_NAME_LEN)
}

#[cfg(test)]
mod bound_tests {
    use super::{bounded_hr_name, MAX_HR_NAME_LEN};

    #[test]
    fn bounded_hr_name_truncates_at_a_utf8_boundary_not_mid_character() {
        let hr_name: String = "a".repeat(MAX_HR_NAME_LEN - 2) + "💥💥💥";
        assert!(hr_name.len() > MAX_HR_NAME_LEN);

        let truncated = bounded_hr_name(&hr_name);
        assert!(truncated.len() <= MAX_HR_NAME_LEN);
        assert!(truncated.chars().count() > 0);
        assert!(hr_name.starts_with(&truncated));
    }

    #[test]
    fn bounded_hr_name_under_the_limit_is_unchanged() {
        assert_eq!(
            bounded_hr_name("Dana Smith, Finance"),
            "Dana Smith, Finance"
        );
    }
}
