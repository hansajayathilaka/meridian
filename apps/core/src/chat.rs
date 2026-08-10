//! Chat session manager (T03): the transport-agnostic glue that turns `mrd.chat/1` payloads into
//! signed, ratchet-encrypted [`MessageEnvelope`]s and back, and owns the persistable session state.
//!
//! This is deliberately I/O-free: it does not touch the network. The CLI (or any shim) fetches
//! bundles + routes/delivers opaque blobs via [`meridian_signaling`], and calls in here to
//! seal/open the content. That separation is the point of §4.3: the *same* ratcheted envelopes
//! ride the relay today and P2P/mailbox later, unchanged.
//!
//! Security: every inbound envelope is signature-verified under the sender's claimed identity key
//! **before** its payload is decrypted (crypto-protocols rule 4), and the claimed key is checked
//! against the routing `from`. The whole state is sealed at rest under a keystore-derived key.

use std::collections::BTreeMap;

use meridian_crypto::{at_rest, PrekeyMaterial, Session};
use meridian_envelope::{ChatContent, MessageEnvelope, Prekey};
use meridian_identity::{sign, verify, KeyHandle, PublicKey, SecretStore, Signature};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Errors from the chat session manager.
#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("crypto error: {0}")]
    Crypto(#[from] meridian_crypto::CryptoError),
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    #[error("keystore error: {0}")]
    Store(#[from] meridian_store::StoreError),
    /// The envelope's signature did not verify under its claimed sender key — reject, never
    /// downgrade (anonymity-and-retention "must never" #5).
    #[error("envelope signature verification failed")]
    BadSignature,
    /// The sender key inside the envelope did not match the routing `from`.
    #[error("envelope sender does not match routing origin")]
    SenderMismatch,
    /// A prekey message referenced a signed/one-time prekey we do not hold the secret for.
    #[error("no matching prekey secret for incoming session")]
    UnknownPrekey,
    /// A first message from an unknown peer arrived without the X3DH preamble.
    #[error("no session and no prekey preamble to establish one")]
    NoSession,
    /// The envelope's ratchet header opened under **neither** header key, so this session cannot
    /// advance: either the peer has lost its ratchet state (a genuine desync — restored backup,
    /// wiped session store) or the input is hostile. Distinguished from the general
    /// [`Crypto`](ChatError::Crypto) case purely so callers can *report* desync diagnosably; it is a
    /// hard rejection like any other, and callers MUST NOT react to it by resetting or re-keying the
    /// session (task 1.18 — doing so would hand an active attacker a session-reset,
    /// skipped-key-destruction, and prekey-depletion oracle). Recovery is driven only by the peer
    /// that knows it lost state; see `docs/api/messaging-envelope-v1.md` §3 "Desync recovery".
    #[error("ratchet desync: header undecryptable under either header key")]
    Desync,
    /// (task 2.10) A first-contact envelope from a sender [`ChatState`] has never seen before was
    /// verified and decrypted successfully, but is being held in the segregated message-request
    /// state ([`ChatState::pending_requests`]) rather than delivered — system-design.md §3.5. Not a
    /// failure: reused `Result`'s error channel the same way [`Desync`](ChatError::Desync) does, so
    /// `open_inbound`'s signature doesn't have to widen for a non-fatal, but distinguishable,
    /// routing outcome. Callers should look up the held [`MessageRequest`] via
    /// [`ChatState::pending_request`] rather than treat this like an ordinary rejection.
    #[error("first contact from this sender is now a pending message request")]
    MessageRequest,
    /// (task 2.10) An envelope arrived from a sender who already has an undecided pending message
    /// request. It is refused outright — **never** merged into the existing request — until the
    /// user calls [`ChatState::accept_request`] or [`ChatState::reject_request`]. The original
    /// intro captured by the first envelope is untouched.
    #[error("sender has a pending message request awaiting accept/reject")]
    RequestPending,
}

/// How long a *superseded* prekey generation stays usable after a republish, in seconds (task 1.31).
///
/// Every `session connect` / `chat` invocation republishes a fresh bundle, so a peer whose fetch
/// landed on the bundle that was current a moment ago would otherwise hit a hard
/// [`ChatError::UnknownPrekey`] on its X3DH init (a reconnect race, not a hostile input). 60 seconds
/// comfortably covers that race — fetch → X3DH → route → deliver is single-digit seconds even over a
/// relayed path with retries — while staying far below any real prekey-rotation period, so the
/// window in which a compromise of the *old* secrets could still open a session stays negligible.
/// Forward secrecy is bounded on both axes: at most **one** prior generation is ever retained
/// (see [`PrekeyVault::set_bundle`]) and it is dropped + zeroized once this window passes (see
/// [`PrekeyVault::expire_previous_generation`]).
pub const PREV_GENERATION_GRACE_SECS: u64 = 60;

/// Hard cap on the number of undecided [`MessageRequest`]s [`ChatState`] will hold at once (task
/// 3.10 / review finding F5).
///
/// OTK-free X3DH is legal (`used_opk: None`), so a first-contact envelope costs its sender
/// nothing but a fresh identity key — nothing upstream of this bounds how many distinct strangers
/// can each land a `Session` + `MessageRequest` in the sealed-at-rest `ChatState`, which is
/// rewritten on every save. Once the cap is reached, the *oldest still-undecided* request is
/// evicted (its `Session` dropped with it, see [`evict_oldest_pending`]) to admit the new one.
///
/// `TODO: confirm`: no design doc (system-design.md §3.5, `docs/architecture/features/06-cross-org-federation.md`)
/// gives a numeric depth for the request queue. 256 was chosen to stay generous for a legitimate
/// user fielding many simultaneous strangers (e.g. an ID posted publicly) — two orders of
/// magnitude above the ~5 concurrent unread requests a real inbox is ever likely to hold — while
/// still bounding `ChatState`'s pending-request footprint to a small, fixed multiple of one
/// session's size regardless of flood volume. See this task's Outcome section
/// (`docs/tasks/phase-3/3.10-message-request-flood-bound.md`) for the full reasoning.
pub const MAX_PENDING_REQUESTS: usize = 256;

/// Hard cap, in encoded `mrd.chat/1` bytes, on the payload retained as a pending request's
/// [`MessageRequest::intro`] (task 3.10 / review finding F5).
///
/// Bounds a single request's contribution to `ChatState`'s at-rest size independently of
/// [`MAX_PENDING_REQUESTS`], so a handful of maximally-padded intros can't dominate the queue's
/// footprint even below the count cap. An oversized intro is *truncated*, not dropped: dropping
/// it would leave [`ChatError::MessageRequest`] returned with no corresponding entry in
/// `pending_requests`, breaking the invariant every caller (`apps/cli`) relies on that the error
/// always means "look this sender up, they're queued".
///
/// `TODO: confirm`: no design doc bounds §3.5's "a short encrypted intro" numerically. 4 KiB is
/// generous for a genuine one-line/one-paragraph greeting (an order of magnitude past a typical
/// chat message) while keeping a single request's worst-case storage contribution well under
/// `apps/rendezvous/src/federation/link.rs`'s `MAX_FRAME_LEN` (1 MiB, the wire ceiling a single
/// envelope is bound by upstream of this). See this task's Outcome section for the full
/// reasoning.
pub const MAX_INTRO_LEN: usize = 4096;

/// One published one-time prekey's key pair (public + X25519 secret).
///
/// The secret is zeroized on drop (matching `meridian-crypto`'s `DoubleRatchet` style), so removing
/// an OTK from a generation — on consumption, expiry, or rotation — clears its key material.
#[derive(Clone, Serialize, Deserialize)]
struct Otk {
    #[serde(with = "b32")]
    public: [u8; 32],
    #[serde(with = "b32")]
    secret: [u8; 32],
}

impl Drop for Otk {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The single retained *previous* prekey generation: the secrets behind the bundle that the most
/// recent [`PrekeyVault::set_bundle`] superseded, plus the absolute unix second at which they stop
/// being accepted. The expiry is stored absolute (not as a duration) precisely so it survives the
/// at-rest seal/open round-trip unchanged.
#[derive(Clone, Serialize, Deserialize)]
struct PrevGeneration {
    #[serde(with = "opt_b32", default)]
    spk_public: Option<[u8; 32]>,
    #[serde(with = "opt_b32", default)]
    spk_secret: Option<[u8; 32]>,
    #[serde(default)]
    otks: Vec<Otk>,
    #[serde(default)]
    expires_at_unix: u64,
}

impl PrevGeneration {
    /// Zeroize every secret-bearing field in place. Shared by [`Drop::drop`] and mirrors
    /// `meridian_crypto`'s ratchet convention.
    fn zeroize_secrets(&mut self) {
        if let Some(mut s) = self.spk_secret.take() {
            s.zeroize();
        }
        // Each `Otk`'s own `Drop` clears its secret too; do it here as well so an in-place
        // zeroize (without a drop) leaves nothing behind.
        for o in &mut self.otks {
            o.secret.zeroize();
        }
        self.otks.clear();
    }
}

impl Drop for PrevGeneration {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

/// The local secrets behind this account's *published* prekey bundle — needed to answer incoming
/// X3DH handshakes. One-time prekeys are consumed (removed) on first use.
///
/// A republish rotates the current generation into a single "previous" slot for
/// [`PREV_GENERATION_GRACE_SECS`] so a peer that fetched the just-superseded bundle can still
/// complete X3DH (task 1.31's reconnect race). One-time prekeys stay single-use *across* both
/// generations.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PrekeyVault {
    #[serde(with = "opt_b32", default)]
    spk_public: Option<[u8; 32]>,
    #[serde(with = "opt_b32", default)]
    spk_secret: Option<[u8; 32]>,
    otks: Vec<Otk>,
    /// At most one superseded generation, retained for a bounded window. `serde(default)` so a
    /// state sealed before 1.31 still opens.
    #[serde(default)]
    previous: Option<PrevGeneration>,
}

impl PrekeyVault {
    /// Record the secrets for a freshly published bundle, rotating the outgoing generation into the
    /// bounded-lifetime "previous" slot.
    ///
    /// `now_unix` is the caller's wall clock in unix seconds: this crate is deliberately clock-free
    /// (it compiles to wasm32, where `std::time::SystemTime::now()` is unavailable), so time is
    /// injected rather than read here. The previous generation's expiry is recorded as
    /// `now_unix + PREV_GENERATION_GRACE_SECS` and enforced by
    /// [`expire_previous_generation`](Self::expire_previous_generation).
    ///
    /// Retention is hard-bounded to **one** generation: this replaces (and therefore zeroizes)
    /// whatever was in the previous slot, so a chain of republishes can never accumulate a tail of
    /// live prekey secrets.
    pub fn set_bundle(
        &mut self,
        spk_public: [u8; 32],
        spk_secret: [u8; 32],
        otks: impl IntoIterator<Item = ([u8; 32], [u8; 32])>,
        now_unix: u64,
    ) {
        let prior_public = self.spk_public.take();
        let prior_secret = self.spk_secret.take();
        let prior_otks = std::mem::take(&mut self.otks);
        // Assigning here drops the old `previous` (zeroizing it via `PrevGeneration::drop`).
        self.previous = match (prior_public, prior_secret) {
            (Some(p), Some(s)) => Some(PrevGeneration {
                spk_public: Some(p),
                spk_secret: Some(s),
                otks: prior_otks,
                expires_at_unix: now_unix.saturating_add(PREV_GENERATION_GRACE_SECS),
            }),
            // Nothing was published before (first-ever publish): nothing to retain, and any
            // older previous generation is dropped rather than carried forward.
            _ => None,
        };
        self.spk_public = Some(spk_public);
        self.spk_secret = Some(spk_secret);
        self.otks = otks
            .into_iter()
            .map(|(public, secret)| Otk { public, secret })
            .collect();
    }

    /// Drop + zeroize the retained previous generation once its grace window has passed.
    ///
    /// Time is supplied by the caller for the same reason as in [`set_bundle`](Self::set_bundle).
    /// Callers that answer incoming X3DH handshakes should call this (with a real wall clock)
    /// before opening inbound blobs, so a superseded generation fails closed with
    /// [`ChatError::UnknownPrekey`] once expired instead of being silently accepted.
    pub fn expire_previous_generation(&mut self, now_unix: u64) {
        let expired = self
            .previous
            .as_ref()
            .map(|p| now_unix >= p.expires_at_unix)
            .unwrap_or(false);
        if expired {
            self.previous = None;
        }
    }

    fn spk_secret_for(&self, spk_public: &[u8; 32]) -> Option<[u8; 32]> {
        // Exact match on the requested SPK only — never substitute a different one.
        if let (Some(p), Some(s)) = (self.spk_public, self.spk_secret) {
            if &p == spk_public {
                return Some(s);
            }
        }
        // Grace window: a fetch that landed on the just-superseded bundle must still complete.
        let prev = self.previous.as_ref()?;
        match (prev.spk_public, prev.spk_secret) {
            (Some(p), Some(s)) if &p == spk_public => Some(s),
            _ => None,
        }
    }

    /// Consume the secret for `opk_public`, whichever generation holds it.
    ///
    /// Single-use is enforced *across* generations: the OTK is removed from the current generation
    /// **and** from the retained previous one, so one published one-time prekey can never establish
    /// two sessions (a second attempt with the same public returns `None` →
    /// [`ChatError::UnknownPrekey`]).
    fn take_otk_secret(&mut self, opk_public: &[u8; 32]) -> Option<[u8; 32]> {
        let from_current = take_otk(&mut self.otks, opk_public);
        let from_prev = self
            .previous
            .as_mut()
            .and_then(|p| take_otk(&mut p.otks, opk_public));
        from_current.or(from_prev)
    }
}

/// Remove **every** entry matching `opk_public` from `otks`, returning the first secret found.
/// Removing all matches (rather than just the first) is what makes single-use robust even if the
/// same public somehow appears twice; each removed [`Otk`] zeroizes its own copy on drop.
fn take_otk(otks: &mut Vec<Otk>, opk_public: &[u8; 32]) -> Option<[u8; 32]> {
    let mut found = None;
    let mut i = 0;
    while i < otks.len() {
        if &otks[i].public == opk_public {
            let otk = otks.remove(i);
            if found.is_none() {
                found = Some(otk.secret);
            }
        } else {
            i += 1;
        }
    }
    found
}

/// A first-contact envelope held in the segregated "message request" state (task 2.10,
/// system-design.md §3.5) instead of being delivered as an ordinary message, pending the user's
/// accept/reject decision.
///
/// **What "gated" means here, precisely.** By the time a [`MessageRequest`] exists, the crypto
/// underneath it is *done*: the envelope's signature verified, X3DH ran (or the existing ratchet
/// advanced), and a live [`Session`] is already installed in [`ChatState`]'s session map — see the
/// gate in [`ChatState::open_inbound`]. What is held back is *delivery/display*, not
/// authentication: the sender really does hold the private key behind `sender_ik`. The user is
/// simply being asked whether they want to talk to that (now cryptographically confirmed) key.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageRequest {
    /// The sender's account identity key. Duplicated here (it is also the key in
    /// [`ChatState::pending_requests`]) so a [`MessageRequest`] handed to a caller by value/ref
    /// remains self-describing.
    #[serde(with = "b32")]
    pub sender_ik: [u8; 32],
    /// The safety number for the (already-established, not-yet-trusted) session, computed exactly
    /// as an accepted contact's would be (§4.4) — shown next to the intro so the user can eyeball
    /// it *before* deciding, not after.
    pub safety_number: String,
    /// The decrypted first payload — system-design.md §3.5's "a short encrypted intro".
    pub intro: ChatContent,
}

/// The full persistable chat state: the prekey vault + all live sessions, keyed by peer identity,
/// plus (task 2.10) the segregated message-request queue for senders not yet accepted.
#[derive(Default, Serialize, Deserialize)]
pub struct ChatState {
    pub vault: PrekeyVault,
    sessions: BTreeMap<[u8; 32], Session>,
    /// First-contact envelopes awaiting an accept/reject decision (task 2.10), keyed by sender
    /// identity key. Part of the same struct (rather than a separate store) specifically so it
    /// rides `seal_at_rest`/`open_at_rest` unchanged — the task's "persistence inside the
    /// sealed-at-rest `ChatState`" requirement. `#[serde(default)]` so state sealed before this
    /// task still opens (mirrors `PrekeyVault::previous`'s precedent, task 1.31).
    #[serde(default)]
    pending_requests: BTreeMap<[u8; 32], MessageRequest>,
    /// Arrival order (oldest first) of the sender keys currently present in `pending_requests`
    /// (task 3.10 / review finding F5). This crate is deliberately clock-free (it compiles to
    /// wasm32, where `std::time::SystemTime::now()` is unavailable — see
    /// [`PrekeyVault::set_bundle`]'s doc comment for the same constraint), so eviction order is
    /// tracked as a plain insertion sequence rather than by timestamp.
    ///
    /// Maintained in lockstep with `pending_requests` by every path that adds or removes an
    /// entry — [`insert_pending_request`](Self::insert_pending_request),
    /// [`accept_request`](Self::accept_request), [`reject_request`](Self::reject_request), and
    /// [`evict_oldest_pending`](Self::evict_oldest_pending) — which is what makes the "only a
    /// genuinely undecided request is evictable" invariant hold: a request that has been accepted
    /// or rejected is removed from both collections in the same call, so it can never be the
    /// target `evict_oldest_pending` picks. `#[serde(default)]` for the same at-rest-compat
    /// reason as `pending_requests` itself; [`open_at_rest`](Self::open_at_rest) reconciles it
    /// against `pending_requests` right after deserializing (see
    /// [`reconcile_request_order`](Self::reconcile_request_order)) so a state sealed before this
    /// task — or any other future desync — can't leave the two out of step.
    #[serde(default)]
    request_order: Vec<[u8; 32]>,
}

impl ChatState {
    /// Whether a session with `peer_ik` already exists.
    pub fn has_session(&self, peer_ik: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_ik)
    }

    /// Insert an initiator session established elsewhere (after fetch+verify+X3DH).
    pub fn insert_session(&mut self, session: Session) {
        self.sessions.insert(session.peer_ik, session);
    }

    /// Establish an **initiator** session against a peer's already-verified bundle keys and store
    /// it. Idempotent per peer: a second call is a no-op so re-opening a chat keeps the live
    /// ratchet (no re-handshake). `peer_spk`/`peer_opk` come from the fetched, signature-verified
    /// bundle (caller MUST have verified it under `peer_ik`).
    pub fn start_initiator_session(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        peer_spk: &[u8; 32],
        peer_opk: Option<[u8; 32]>,
    ) -> Result<(), ChatError> {
        if self.sessions.contains_key(peer_ik) {
            return Ok(());
        }
        let (session, _material) =
            Session::initiate(store, handle, our_ik, peer_ik, peer_spk, peer_opk)?;
        self.sessions.insert(*peer_ik, session);
        Ok(())
    }

    /// Safety number for a peer session, if present.
    pub fn safety_number(&self, our_ik: &[u8; 32], peer_ik: &[u8; 32]) -> Option<String> {
        self.sessions.get(peer_ik).map(|s| s.safety_number(our_ik))
    }

    // -- task 2.10: message-request queue ------------------------------------------------------

    /// Iterate the pending message requests (sender key first, `BTreeMap` order — stable, not
    /// arrival order, which this crate has no clock to record).
    pub fn pending_requests(&self) -> impl Iterator<Item = &MessageRequest> {
        self.pending_requests.values()
    }

    /// The pending request from `sender_ik`, if any.
    pub fn pending_request(&self, sender_ik: &[u8; 32]) -> Option<&MessageRequest> {
        self.pending_requests.get(sender_ik)
    }

    /// Accept a pending message request: removes it from the gate so subsequent envelopes from
    /// `sender_ik` deliver as ordinary messages (see the gate in [`open_inbound`](Self::open_inbound)),
    /// and returns the [`MessageRequest`] that was being held — including its `intro`, which the
    /// caller should now present exactly like any other freshly-received [`ChatContent`].
    ///
    /// The crypto session behind the request was already fully established when it was gated
    /// (signature verified, X3DH complete); accepting is pure local bookkeeping and re-verifies
    /// nothing.
    pub fn accept_request(&mut self, sender_ik: &[u8; 32]) -> Option<MessageRequest> {
        let out = self.pending_requests.remove(sender_ik);
        if out.is_some() {
            // (task 3.10) Removed from `request_order` in the same call that decides the
            // request, so an accepted request is never again reachable from
            // `evict_oldest_pending` — it simply isn't in either collection anymore.
            self.request_order.retain(|k| k != sender_ik);
        }
        out
    }

    /// Reject a pending message request: discards it *and* the (already-established) session
    /// behind it, without sending anything back to the sender. Returns whether a request actually
    /// existed for `sender_ik` (so callers can tell a real rejection from a no-op).
    ///
    /// **Security note (does not leak whether the key is known).** This method is pure local
    /// bookkeeping: it never sends an envelope, receipt, or any other wire-visible signal, so a
    /// sender who gets rejected observes nothing different from a sender whose envelope was lost,
    /// dropped by a relay, or never delivered for any other reason — there is no protocol-level
    /// "rejected" message for a probing sender to fingerprint. That is a *client-side* answer to
    /// the task's "does not leak" requirement; it says nothing about server-side traffic-analysis
    /// resistance, which is out of this task's scope (§3.5 rate limits / contact tokens are T08/T14).
    ///
    /// The session is dropped (not just the request), zeroizing its ratchet/X3DH key material — an
    /// unaccepted contact's session secrets are not worth retaining. Consequence: if this sender is
    /// heard from again, their next envelope either re-runs X3DH from scratch (if it still carries
    /// a usable prekey preamble) and lands back in `pending_requests` as a new first-contact
    /// request, or — if it was a bare ratchet continuation with no preamble, or referenced an
    /// already-consumed one-time prekey — fails closed with [`ChatError::NoSession`] /
    /// [`ChatError::UnknownPrekey`]. Either way this is "not now", not a distinguishable permanent
    /// block, which is exactly what keeps rejection from being an oracle.
    pub fn reject_request(&mut self, sender_ik: &[u8; 32]) -> bool {
        let had = self.pending_requests.remove(sender_ik).is_some();
        if had {
            // (task 3.10) Same reasoning as `accept_request`: pruned here so a rejected request
            // can't linger in `request_order` as a stale, already-decided entry.
            self.request_order.retain(|k| k != sender_ik);
        }
        self.sessions.remove(sender_ik);
        had
    }

    // -- task 3.10: bounding the queue against a stranger flood (review finding F5) -------------

    /// Insert a freshly-gated first-contact request, evicting the oldest still-undecided one first
    /// if `pending_requests` is already at [`MAX_PENDING_REQUESTS`].
    ///
    /// Callers must only reach this once [`open_inbound_gated`](Self::open_inbound_gated) has
    /// already confirmed `sender_ik` has no existing pending request (the `RequestPending` check
    /// at the top of that method) — so every call here is a genuinely new entry, never a
    /// replacement of one already in the queue.
    fn insert_pending_request(&mut self, sender_ik: [u8; 32], req: MessageRequest) {
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            self.evict_oldest_pending();
        }
        self.pending_requests.insert(sender_ik, req);
        self.request_order.push(sender_ik);
    }

    /// Drop the least-recently-arrived entry in `request_order` (and its `Session`) to make room
    /// under [`MAX_PENDING_REQUESTS`].
    ///
    /// **Why this can never evict a decided request.** `request_order` only ever contains keys
    /// for requests that are *currently* in `pending_requests`: every insertion path adds to both
    /// collections together, and both `accept_request` and `reject_request` remove from both
    /// together in the same call. A request that has already been accepted or rejected is
    /// therefore never a member of `request_order` by the time this runs — there is no way for
    /// eviction to reach back and discard a decision the user already made. The `while` loop below
    /// is defense-in-depth against a hypothetical desync (e.g. a future bug, or state reconciled
    /// from an old at-rest blob by [`reconcile_request_order`](Self::reconcile_request_order))
    /// rather than a path this code expects to exercise in the maintained invariant.
    fn evict_oldest_pending(&mut self) {
        while !self.request_order.is_empty() {
            let oldest = self.request_order.remove(0);
            if self.pending_requests.remove(&oldest).is_some() {
                self.sessions.remove(&oldest);
                return;
            }
            // Stale order entry with no matching pending request — shouldn't happen given the
            // lockstep invariant above, but keep looking rather than silently evict nothing.
        }
    }

    /// Repair `request_order` against `pending_requests` after deserializing an at-rest blob:
    /// drop any order entries with no matching pending request, and append any pending request
    /// missing from the order.
    ///
    /// Needed for two cases: a `ChatState` sealed before this task (no `request_order` field in
    /// its CBOR — `#[serde(default)]` leaves it empty even though `pending_requests` may not be),
    /// and defense-in-depth against any other way the two could have drifted apart. Requests
    /// recovered this way are appended in `pending_requests`'s own (`BTreeMap`/key) order — not
    /// true arrival order, since this crate is deliberately clock-free and the original order was
    /// never recorded for them — a deterministic fallback that never invents an eviction
    /// preference it can't actually justify, rather than silently mis-ranking real requests.
    fn reconcile_request_order(&mut self) {
        let known: std::collections::BTreeSet<[u8; 32]> =
            self.pending_requests.keys().copied().collect();
        self.request_order.retain(|k| known.contains(k));
        let already_ordered: std::collections::BTreeSet<[u8; 32]> =
            self.request_order.iter().copied().collect();
        for k in known {
            if !already_ordered.contains(&k) {
                self.request_order.push(k);
            }
        }
    }

    /// Build a signed, ratchet-encrypted envelope for `content` to `peer_ik`. See [`seal_bytes`] for
    /// the generic primitive; this is the `mrd.chat/1` convenience wrapper.
    ///
    /// [`seal_bytes`]: ChatState::seal_bytes
    pub fn seal_outbound(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        content: &ChatContent,
    ) -> Result<Vec<u8>, ChatError> {
        self.seal_bytes(store, handle, our_ik, peer_ik, &content.encode()?)
    }

    /// Seal an **arbitrary** ratchet plaintext into a signed [`MessageEnvelope`] blob on the session
    /// with `peer_ik`. The same primitive carries `mrd.chat/1` payloads and the P2P substrate's
    /// `SignalContent` (SDP/ICE/ctrl) over one ratchet — the transport-independence of §4.3: the
    /// same envelope bytes are valid over WSS routing, the mailbox, or a data channel.
    ///
    /// The session must already exist (initiator: [`Session::initiate`]; responder: created on first
    /// receive via [`open_bytes`](ChatState::open_bytes)).
    pub fn seal_bytes(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ChatError> {
        let session = self.sessions.get_mut(peer_ik).ok_or(ChatError::NoSession)?;
        let ct = session.encrypt(plaintext)?;
        let prekey = if session.needs_prekey() {
            session.prekey_material().map(to_wire_prekey)
        } else {
            None
        };
        let sig = sign(
            store,
            handle,
            &MessageEnvelope::signing_input(our_ik, &prekey, &ct),
        )?;
        let envelope = MessageEnvelope {
            sender_pub: *our_ik,
            prekey,
            ct,
            sig: *sig.as_bytes(),
        };
        Ok(envelope.to_blob()?)
    }

    /// Verify + decrypt an inbound opaque blob delivered from `from`, establishing a responder
    /// session if this is a prekey message. Returns the decoded chat payload — unless `from` is
    /// gated by the task 2.10 message-request queue, in which case it is held in
    /// [`pending_requests`](Self::pending_requests) instead and this returns
    /// [`ChatError::MessageRequest`] (first contact) or [`ChatError::RequestPending`] (a still-gated
    /// sender's follow-up envelope, refused rather than merged).
    ///
    /// **Gate placement, and why it does not touch [`open_bytes`].** This wraps the *content*
    /// entry point only — [`open_bytes`] (the crypto/verification primitive) is also called
    /// directly by the P2P session substrate (`apps/core/src/session.rs`) for `mrd.ctrl/1`
    /// SDP/ICE signaling on the *same* ratchet, and that traffic must never be gated: a call
    /// establishing a P2P session is not a "message" the user is being asked to accept/reject.
    ///
    /// This is a thin wrapper over the crate-private `open_inbound_gated` with
    /// `force_first_contact = false` — i.e. first-contact detection purely from local session
    /// state, correct for this (relay/mailbox) call path. See that method's doc for why the P2P
    /// substrate (task 2.14) needs the forcing variant instead: by the time a `mrd.chat/1` content
    /// frame reaches `P2pSession::pump`, the offer/answer handshake has already installed the
    /// session as a side effect of its own `open_bytes` calls, so this method's own
    /// session-presence check would never see a first contact on that path.
    ///
    /// **Hard invariant (task 2.10): gating happens after signature verification and session
    /// establishment.** The check below runs *after* [`open_bytes`] has already verified the
    /// envelope's signature and (on a first contact) completed X3DH — so a first contact that is
    /// ultimately rejected still cost the sender's one-time prekey. This is the same class of
    /// already-accepted OTK-consumption behavior recorded in `apps/core/src/session.rs`'s
    /// `ANSWER_TIMEOUT` doc comment (task 1.33) and is not "fixed" here; restructuring the
    /// handshake to avoid it would reintroduce the handshake-order problems those notes exist to
    /// avoid.
    pub fn open_inbound(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
    ) -> Result<ChatContent, ChatError> {
        self.open_inbound_gated(store, handle, our_ik, from, blob, false)
    }

    /// (task 2.14) Like [`open_inbound`](Self::open_inbound), but lets the caller assert that this
    /// is genuinely the first-ever content received from `from`, overriding this method's own
    /// session-presence heuristic.
    ///
    /// **Why this exists.** [`open_inbound`](Self::open_inbound)'s first-contact detection —
    /// `!self.sessions.contains_key(from)`, snapshotted before [`open_bytes`] runs — is correct for
    /// the relay/mailbox path, where the very envelope being gated is *also* the one whose
    /// `open_bytes` call installs the responder session (X3DH). The P2P session substrate
    /// (`apps/core/src/session.rs`) is structurally different: its offer/answer handshake calls
    /// [`open_bytes`] directly (never through this gate) to install the session *before* any
    /// `mrd.chat/1` content frame exists to gate — by the time a chat frame reaches
    /// `P2pSession::pump`, the session is already there, so `open_inbound`'s own check would always
    /// read "not first contact", even on a genuine first-ever P2P dial from an unrecognized peer
    /// (this was 2.10's known, tracked gap — see the module docs on `session.rs` and task 2.14).
    ///
    /// `session.rs` closes that gap by snapshotting, from its own vantage point, whether the peer
    /// was known *before* its offer/answer exchange ran (see `dial_established`/
    /// `answer_with_config`) and passing that through as `force_first_contact`. `pub(crate)`: only
    /// `session.rs`, in the same crate, has the handshake-ordering context needed to supply that
    /// flag correctly — every other caller should go through [`open_inbound`](Self::open_inbound).
    ///
    /// Same hard invariant as [`open_inbound`](Self::open_inbound): this still runs *after*
    /// [`open_bytes`] has verified the signature (and, on first contact, completed X3DH) — gating
    /// is delivery-only, never a crypto shortcut, and a rejected first contact still costs whatever
    /// handshake material (e.g. a one-time prekey) it consumed.
    pub(crate) fn open_inbound_gated(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
        force_first_contact: bool,
    ) -> Result<ChatContent, ChatError> {
        // A sender with an undecided pending request is refused outright, before touching crypto
        // state at all: their first envelope already ran X3DH and installed the session (and the
        // OTK-consumption cost above), so there is nothing further to establish, and refusing here
        // means a still-gated sender cannot force extra ratchet-skipped-key churn by re-sending
        // while awaiting a decision. Never merges into the existing request (task 2.10 deliverable).
        if self.pending_requests.contains_key(from) {
            return Err(ChatError::RequestPending);
        }

        // Snapshot *before* `open_bytes`, which — on a genuine first contact — installs the
        // responder session as a side effect. Capturing this first is what lets us tell "this
        // envelope is what just created the session" from "the session already existed". A caller
        // that already knows independently (2.14: `session.rs`) that this is first contact — even
        // though a session now sits in `self.sessions` from its own earlier handshake — forces the
        // gate to fire via `force_first_contact` regardless of that local presence check.
        let is_first_contact = force_first_contact || !self.sessions.contains_key(from);

        let plaintext = self.open_bytes(store, handle, our_ik, from, blob)?;
        let content = ChatContent::decode(&plaintext)?;

        if is_first_contact {
            // system-design.md §3.5: land it in the segregated message-request state instead of
            // delivering it. `unwrap_or_default` only guards a same-call race that cannot actually
            // happen (the session was just installed by `open_bytes`, above, under this same `&mut
            // self` borrow) — never a silent downgrade of a real safety-number mismatch.
            let safety_number = self.safety_number(our_ik, from).unwrap_or_default();
            // (task 3.10 / F5) Bound the intro's storage contribution before it ever lands in the
            // queue; `plaintext.len()` is the already-measured encoded size of `content`, so this
            // avoids a redundant re-encode purely to check it.
            let intro = cap_intro(content, plaintext.len());
            self.insert_pending_request(
                *from,
                MessageRequest {
                    sender_ik: *from,
                    safety_number,
                    intro,
                },
            );
            return Err(ChatError::MessageRequest);
        }

        Ok(content)
    }

    /// Verify + decrypt an inbound blob to its raw ratchet plaintext, establishing a responder
    /// session on a prekey message. The generic counterpart of [`open_inbound`](Self::open_inbound),
    /// used by the substrate to open `SignalContent` on the same ratchet as chat. Every inbound
    /// envelope is signature-verified under its claimed sender key **before** decryption, and the
    /// claimed key is checked against the routing `from` (crypto-protocols rule 4).
    pub fn open_bytes(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
    ) -> Result<Vec<u8>, ChatError> {
        let envelope = MessageEnvelope::from_blob(blob)?;
        if &envelope.sender_pub != from {
            return Err(ChatError::SenderMismatch);
        }
        let pk = PublicKey::from_bytes(envelope.sender_pub).map_err(|_| ChatError::BadSignature)?;
        if !verify(
            &pk,
            &envelope.signing_bytes(),
            &Signature::from_bytes(envelope.sig),
        ) {
            return Err(ChatError::BadSignature);
        }

        // Establish a responder session on the first (prekey) message, if we don't have one.
        if !self.sessions.contains_key(&envelope.sender_pub) {
            let prekey = envelope.prekey.as_ref().ok_or(ChatError::NoSession)?;
            let material = PrekeyMaterial {
                ek_pub: prekey.ek_pub,
                used_spk: prekey.used_spk,
                used_opk: prekey.used_opk,
            };
            let spk_secret = self
                .vault
                .spk_secret_for(&prekey.used_spk)
                .ok_or(ChatError::UnknownPrekey)?;
            let opk_secret = match prekey.used_opk {
                Some(opk) => Some(
                    self.vault
                        .take_otk_secret(&opk)
                        .ok_or(ChatError::UnknownPrekey)?,
                ),
                None => None,
            };
            let session = Session::respond(
                store,
                handle,
                our_ik,
                &envelope.sender_pub,
                &material,
                &spk_secret,
                opk_secret,
            )?;
            self.sessions.insert(envelope.sender_pub, session);
        }

        let session = self
            .sessions
            .get_mut(&envelope.sender_pub)
            .ok_or(ChatError::NoSession)?;
        // Classify an undecryptable header as `Desync` so callers can *report* it distinguishably
        // from malformed/tampered input (task 1.18). This changes no rejection decision: the
        // envelope is dropped either way and the session is left untouched. Callers MUST NOT treat
        // `Desync` as a trigger to reset or re-key — see the variant's doc comment.
        session.decrypt(&envelope.ct).map_err(|e| match e {
            meridian_crypto::CryptoError::UndecryptableHeader => ChatError::Desync,
            other => ChatError::Crypto(other),
        })
    }

    /// Serialize and seal the whole state under a key derived from the account key in `store`.
    pub fn seal_at_rest(
        &self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
    ) -> Result<Vec<u8>, ChatError> {
        let mut plaintext = Vec::new();
        ciborium::into_writer(self, &mut plaintext)
            .map_err(|e| meridian_proto::CodecError::Encode(e.to_string()))?;
        let key = self.store_key(store, handle)?;
        Ok(at_rest::seal(&key, &plaintext)?)
    }

    /// Open a state previously produced by [`seal_at_rest`](Self::seal_at_rest).
    pub fn open_at_rest(
        store: &dyn SecretStore,
        handle: &KeyHandle,
        sealed: &[u8],
    ) -> Result<Self, ChatError> {
        let key = store_key(store, handle)?;
        let plaintext = at_rest::open(&key, sealed)?;
        let mut state: Self = ciborium::from_reader(&plaintext[..])
            .map_err(|e| meridian_proto::CodecError::Decode(e.to_string()))?;
        // (task 3.10) A blob sealed before this task has no `request_order` field at all
        // (`#[serde(default)]` leaves it empty regardless of `pending_requests`); repair it here
        // rather than let `evict_oldest_pending` ever see a mismatch between the two.
        state.reconcile_request_order();
        Ok(state)
    }

    fn store_key(
        &self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
    ) -> Result<[u8; 32], ChatError> {
        store_key(store, handle)
    }
}

fn store_key(store: &dyn SecretStore, handle: &KeyHandle) -> Result<[u8; 32], ChatError> {
    // Derive directly through the store (private key never leaves it), independent of any
    // signature algorithm's determinism (task 1.7, review finding F7).
    Ok(store.derive_key(handle, at_rest::STORE_KEY_INFO)?)
}

fn to_wire_prekey(m: &PrekeyMaterial) -> Prekey {
    Prekey {
        ek_pub: m.ek_pub,
        used_spk: m.used_spk,
        used_opk: m.used_opk,
    }
}

/// Bound `content`'s contribution to a pending request's at-rest size to [`MAX_INTRO_LEN`] (task
/// 3.10 / review finding F5). `raw_len` is `content`'s already-measured encoded byte length (the
/// ratchet plaintext [`ChatState::open_bytes`] just returned) — reusing it avoids a redundant
/// re-encode purely to check the size.
///
/// Only [`ChatContent::Text`]'s `body` is unbounded today, so it is the only variant truncated;
/// [`ChatContent::Receipt`] carries a fixed-size 16-byte id and can never approach the cap on its
/// own. **Residual, stated rather than hidden:** a future `ChatContent` variant
/// (`mrd.chat/1`'s doc comment notes typing/reactions are planned additions) with its own
/// unbounded field would need its own arm here — nothing in the type system enforces that, so
/// it's a manual invariant for whoever adds the next variant to keep alongside it.
fn cap_intro(content: ChatContent, raw_len: usize) -> ChatContent {
    if raw_len <= MAX_INTRO_LEN {
        return content;
    }
    match content {
        ChatContent::Text { id, body } => ChatContent::Text {
            id,
            body: truncate_utf8(&body, MAX_INTRO_LEN),
        },
        other => other,
    }
}

/// Truncate `s` to at most `max_bytes` UTF-8 bytes, backing off to the nearest char boundary so a
/// multi-byte codepoint is never split into invalid UTF-8.
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// Local byte-string serde helpers (kept private to the crate; proto's equivalents are pub(crate)).
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

mod opt_b32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&Wrap(*b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let o: Option<Wrap> = Option::deserialize(d)?;
        Ok(o.map(|w| w.0))
    }
    struct Wrap([u8; 32]);
    impl Serialize for Wrap {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            super::b32::serialize(&self.0, s)
        }
    }
    impl<'de> Deserialize<'de> for Wrap {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(Wrap(super::b32::deserialize(d)?))
        }
    }
}
