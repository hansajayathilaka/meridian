//! Chat session manager (T03): the transport-agnostic glue that turns `mrd.chat/1` payloads into
//! ratchet-encrypted [`MessageEnvelope`]s and back, and owns the persistable session state.
//!
//! This is deliberately I/O-free: it does not touch the network. The CLI (or any shim) fetches
//! bundles + routes/delivers opaque blobs via [`meridian_signaling`], and calls in here to
//! seal/open the content. That separation is the point of §4.3: the *same* ratcheted envelopes
//! ride the relay today and P2P/mailbox later, unchanged.
//!
//! Security (envelope v2, ADR 0016 C2/C3 — task 6.3): there is no per-message identity-key
//! signature. Authentication rests entirely on the ratchet AEAD under the canonical
//! `"mrd.env/2" ‖ AD ‖ preamble ‖ enc_header` AAD: every inbound envelope's decrypt is attempted
//! *provisionally* (a non-destructive prekey lookup, no session installed yet) and only a
//! **successful decrypt** commits — consumes the one-time prekey and installs the session. A
//! failed decrypt leaves no trace (see [`ChatState::open_bytes`]). The claimed sender key is
//! still checked against the routing `from`. The whole state is sealed at rest under a
//! keystore-derived key.
//!
//! (task 6.4, ADR 0016 C7 second half) `MessageEnvelope::eid` — a sender-random, unauthenticated
//! outer-plaintext dedup key — is checked against a bounded, sealed-at-rest recently-seen set
//! *before* the AAD/decrypt machinery above ever runs, so a genuinely redelivered envelope is
//! recognized and dropped without reprocessing it as new. This is strictly a redelivery
//! convenience layered on top of the AEAD/freshness-gate security properties above, never a
//! substitute for them — see [`ChatError::DuplicateEnvelope`] and [`ChatState::open_bytes`]'s doc
//! comment.

use std::collections::BTreeMap;

use meridian_crypto::{at_rest, PrekeyMaterial, Session};
use meridian_envelope::{
    preamble_aad_bytes, ChatContent, MessageEnvelope, Prekey, ENVELOPE_VERSION,
};
use meridian_identity::{KeyHandle, SecretStore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Errors from the chat session manager.
#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("crypto error: {0}")]
    Crypto(#[from] meridian_crypto::CryptoError),
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    #[error("keystore error: {0}")]
    Store(#[from] meridian_store::StoreError),
    /// (task 6.3, ADR 0016 C5/R5) The envelope's leading `v` field was not [`ENVELOPE_VERSION`].
    /// **Always a local, unilateral hard reject — never a round-trip, never a negotiated
    /// fallback.** `v` is sender-declared, not negotiated (see `MessageEnvelope`'s own doc
    /// comment): a v1/v2 mismatch must never be routed through either of the wire's two *existing*
    /// version-negotiation mechanisms (the soft `Bundle.v` downgrade-tolerant path, or
    /// `Hello.streams`' mutual capability discovery) — doing so would reintroduce exactly the
    /// "malicious server claims your peer only speaks v1" downgrade oracle R5 forbids. This is a
    /// hard flag day: envelope v1 and v2 never both parse.
    #[error("unsupported envelope version {0} (expected {ENVELOPE_VERSION})")]
    UnsupportedEnvelopeVersion(u16),
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
    /// [`Crypto`](ChatError::Crypto) case purely so callers can *report* desync diagnosably. Every
    /// single occurrence is still a hard rejection, exactly like any other failure — the envelope is
    /// dropped and [`open_bytes`](ChatState::open_bytes) itself already tries the one narrow, gated
    /// exception inline (a fresh re-initiation from the same sender — task 4.9's discriminator fix,
    /// see that method's doc) before ever returning this variant.
    ///
    /// **(task 6.3, ADR 0016 C2) That gate is freshness *and* commit-on-successful-decrypt, not
    /// authenticity alone.** Envelope v2 drops the per-message signature; there is no longer a
    /// separate "authenticity" check upstream of decryption at all — a provisional X3DH
    /// establishment either decrypts this exact ciphertext successfully or it doesn't, and only a
    /// **successful** decrypt is treated as proof the fallback's re-initiation is genuine (nothing
    /// is ever committed — no OTK consumed, no session installed, no freshness record written — on
    /// a failed one). But **decrypt success alone is still not sufficient**, for the same reason it
    /// wasn't under v1: X3DH is deterministic in its public inputs, so a byte-identical replay of a
    /// sender's own past opening envelope decrypts successfully too (deterministically, every time,
    /// for OTK-free X3DH) — decrypt success proves the bytes are *authentic* (the claimed sender's
    /// real material), never that they are *fresh*. The freshness gate therefore still runs
    /// **first**, strictly before any provisional establishment is even attempted: see
    /// [`open_bytes`](ChatState::open_bytes)'s doc comment for why a replay of a sender's own past
    /// opening envelope must fail a freshness check (checking the incoming prekey's `ek_pub` against
    /// **every** `ek_pub` that established a still-SPK-valid responder session with that sender —
    /// not merely the most recent one; see [`ChatState::responder_session_ek`] for why a
    /// single-value freshness record was itself found exploitable) before a provisional
    /// establish-and-decrypt attempt is ever made at all. The two checks cannot conflict or race:
    /// freshness is a *precondition* for attempting provisional establishment, and
    /// commit-on-decrypt is what happens (or doesn't) *inside* an attempt the freshness gate has
    /// already allowed through — see this task's Outcome section
    /// (`docs/tasks/phase-6/6.3-envelope-v2-core-cutover.md`) for the full design note.
    ///
    /// **Task 1.18 vs. task 4.9 — what changed, precisely.** Task 1.18 stated flatly that callers
    /// MUST NOT react to `Desync` by resetting or re-keying a session: doing so unconditionally
    /// would hand an active attacker (threat-model A2, e.g. a malicious rendezvous server) a
    /// session-reset / skipped-key-destruction / prekey-depletion oracle — a single replayed,
    /// already-consumed envelope would be enough. **Task 4.9 relaxes that, but only under a specific,
    /// multi-part guard**, never unconditionally:
    /// 1. **Repeated, not first-occurrence** — [`ChatState::recovery_recommended`] tracks *consecutive*
    ///    `Desync` from the same peer (reset on any successful decrypt) and only signals once
    ///    [`DESYNC_RECOVERY_THRESHOLD`] is crossed; see that constant's doc for the reasoning.
    /// 2. The actual fetch-a-bundle-and-re-handshake action goes through
    ///    [`crate::desync::attempt_recovery`] only, which consults
    ///    [`crate::trust::TrustStore::can_send`] (task 4.4's block/warn gate) **before** touching
    ///    anything — a peer already flagged by an unresolved key change never gets an automatic
    ///    re-handshake layered on top.
    /// 3. The forced session replacement itself only happens through the separate, explicitly-named
    ///    [`ChatState::replace_session_as_initiator`] — never as a side effect of the ordinary
    ///    [`ChatState::start_initiator_session`] callers already use.
    /// 4. Skipped-message keys and any other session state are never touched by the counter/threshold
    ///    bookkeeping itself — only an actual, decided recovery attempt mutates `self.sessions`.
    ///
    /// This still leaves a rate-limited residual: a persistent attacker who can force
    /// `DESYNC_RECOVERY_THRESHOLD` failures on demand can still trigger one recovery attempt (and,
    /// if `can_send` reads `Ok`, one OTK consumption) per that many forced failures — it is a
    /// *rate-limiting*, not an elimination, of the oracle 1.18 identified; see
    /// `docs/api/messaging-envelope-v1.md` §3 "Desync recovery" for the full guarded design and the
    /// honest statement of that residual.
    ///
    /// **(task 6.3) `open_bytes` has now been rewritten under envelope v2's AAD/commit-on-decrypt
    /// rules ([ADR 0016](../../../docs/adr/0016-envelope-deniability.md) C2/C3, and C7's
    /// short-circuit half), and this task-4.9 discriminator/freshness behavior was re-verified
    /// (not merely preserved by inspection) under the new provisional control flow** — see this
    /// task's Outcome section for the design note on exactly how the freshness gate and
    /// commit-on-decrypt now interact.
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
    /// (task 6.4, ADR 0016 C7 second half) The envelope's `eid` matches one already recorded in
    /// [`ChatState::seen_eids`] — i.e. this exact envelope was already successfully decrypted and
    /// delivered/gated once before. **Not an attack classification and not an error in the ordinary
    /// sense** — reused `Result`'s error channel the same way [`MessageRequest`](ChatError::MessageRequest)
    /// does, for a non-fatal, but distinguishable, "nothing new to do here" outcome: a genuine
    /// redelivery (a relay retry, or the sender's own unconfirmed-initiator resend before it has
    /// seen a reply — see [`ChatState::seal_bytes`]'s doc comment for exactly what "resend" means
    /// here) is recognized and dropped **without reprocessing it as new** — the content was already
    /// delivered on the envelope's first, genuine arrival, so silently no-op'ing the duplicate (never
    /// re-delivering the content a second time, never touching any session/trust/request-queue
    /// state) is correct, not a downgrade. Checked *before* any provisional establishment or decrypt
    /// attempt is made ([`ChatState::open_bytes`]'s very first check after the cheap `v`/`sender_pub`
    /// checks), so a genuinely redelivered envelope costs no crypto work the second time.
    ///
    /// **What this does NOT claim (see ADR 0016 R2 and this task's Outcome section).** `eid` is
    /// unauthenticated outer plaintext with no confidentiality/authenticity property of its own — an
    /// attacker with byte access can freely omit, vary, or replay any `eid` value. This check is
    /// therefore a redelivery/duplicate-processing **convenience**, not a pre-crypto DoS filter and
    /// not an independent security boundary: it never substitutes for the ratchet AEAD's own
    /// authentication, or for [`ChatState::responder_session_ek`]'s freshness gate, both of which
    /// remain the actual security-relevant checks and are exercised exactly as before whenever an
    /// envelope's `eid` has *not* been seen before (including a forged envelope that varies its
    /// `eid` specifically to evade this check — see this task's Outcome section for why that is not
    /// a regression).
    #[error("envelope already processed (duplicate eid)")]
    DuplicateEnvelope,
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

/// Target interval between signed-prekey (SPK) republishes, in seconds (task 6.1, ADR 0016 C1).
///
/// ADR 0016 requires enforced, monitored SPK rotation as envelope v2's compensating control for
/// R1 (key-compromise impersonation on the opening message): the longer a single SPK generation
/// stays published, the longer a single compromised SPK secret can be used to impersonate the
/// account to a new correspondent. The ADR only specifies "~weekly, monitored" as a target with no
/// numeric requirement, so this default is a `TODO: confirm`-flavored policy choice, not a wire or
/// crypto constant: `7 * 24 * 3600` (one week) matches the ADR's own stated cadence directly, is
/// short enough to bound the compromise window to a small, human-legible period, and is long
/// enough that legitimate, always-online devices don't republish (and thereby route around the
/// [`PREV_GENERATION_GRACE_SECS`] reconnect-race grace window) more often than is useful. This
/// constant only feeds [`PrekeyVault::rotation_due`]'s predicate here; nothing in this task acts on
/// it (that is task 6.2 — actual republish-triggering, warning, and monitoring).
pub const SPK_ROTATION_INTERVAL_SECS: u64 = 7 * 24 * 3600;

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

/// Hard cap, in bytes, on the `body` string retained as a pending request's
/// [`MessageRequest::intro`] (task 3.10 / review finding F5).
///
/// This bounds [`ChatContent::Text`]'s `body` field itself (see `cap_intro`/`truncate_utf8`), not
/// the final encoded `mrd.chat/1` payload — the encoded size of a capped intro is `MAX_INTRO_LEN`
/// bytes plus the small fixed CBOR/id framing overhead around `body` (tens of bytes), not exactly
/// `MAX_INTRO_LEN` encoded bytes. Bounds a single request's contribution to `ChatState`'s at-rest
/// size independently of [`MAX_PENDING_REQUESTS`], so a handful of maximally-padded intros can't
/// dominate the queue's footprint even below the count cap. An oversized intro is *truncated*, not
/// dropped: dropping it would leave [`ChatError::MessageRequest`] returned with no corresponding
/// entry in `pending_requests`, breaking the invariant every caller (`apps/cli`) relies on that the
/// error always means "look this sender up, they're queued".
///
/// `TODO: confirm`: no design doc bounds §3.5's "a short encrypted intro" numerically. 4 KiB is
/// generous for a genuine one-line/one-paragraph greeting (an order of magnitude past a typical
/// chat message) while keeping a single request's worst-case storage contribution well under
/// `apps/rendezvous/src/federation/link.rs`'s `MAX_FRAME_LEN` (1 MiB, the wire ceiling a single
/// envelope is bound by upstream of this). See this task's Outcome section for the full
/// reasoning.
pub const MAX_INTRO_LEN: usize = 4096;

/// Consecutive `ChatError::Desync` classifications from the **same** peer required before
/// [`ChatState::recovery_recommended`] signals that task 4.9's guarded receiver-side re-handshake
/// (see [`crate::desync`] and [`ChatError::Desync`]'s doc) should be attempted. Reset to zero on any
/// successful decrypt from that peer (a live, healthy exchange proves the session recovered, or was
/// never actually broken) and by [`ChatState::note_recovery_attempted`] the moment a recovery
/// attempt is made, whatever its outcome.
///
/// `TODO: confirm`: no design doc gives a numeric count here — mirrors [`MAX_PENDING_REQUESTS`]'s
/// own precedent for exactly this kind of open threshold. Reasoning:
/// - **Must not be 1.** Task 1.18's whole point is that a single replayed, already-consumed
///   envelope from a passive/malicious rendezvous server (threat-model A2) must never be enough on
///   its own to force a re-handshake or consume one of the peer's one-time prekeys.
/// - **2–3 is still uncomfortably close to "one bad envelope plus one coincidental retry"** — the
///   relay may legitimately redeliver/duplicate a frame, and that alone must not be mistaken for a
///   genuine desync.
/// - **5** is chosen as comfortably above that noise floor while staying low enough that a
///   genuinely desynced peer — for whom *every* subsequent message fails identically until recovery
///   — reaches the threshold within a handful of exchanged messages, not something the user has to
///   notice and act on manually first.
/// - The residual: [`ChatState::note_recovery_attempted`] resets this counter the instant recovery
///   is attempted (success or gated refusal alike), so even an attacker who can force `Desync` on
///   demand is rate-limited to at most one recovery attempt per `DESYNC_RECOVERY_THRESHOLD` forced
///   failures, not one per failure. This bounds, but does not eliminate, the residual oracle 1.18
///   identified — see `docs/api/messaging-envelope-v1.md` §3 for the honest statement of that
///   trade-off.
pub const DESYNC_RECOVERY_THRESHOLD: u32 = 5;

/// Hard cap on the number of *distinct peer identity keys* [`ChatState::responder_session_ek`]
/// will hold entries for at once (task 4.9, third-round review fixup — the finding: this map is
/// written on **every** ordinary first-contact responder establishment, not merely the recovery
/// path, and OTK-free X3DH is legal, so — exactly [`MAX_PENDING_REQUESTS`]'s own precedent — a
/// first-contact envelope costs its sender nothing but a fresh identity key. Nothing upstream of
/// this bounded how many distinct strangers could each add a new outer-map entry to
/// `responder_session_ek`, independently of whether their request was ever accepted, or even
/// whether it was immediately rejected).
///
/// The cap is on distinct peer keys (the outer map), not total [`ResponderEk`] entries: bounding
/// the peer count already bounds the total, since each peer's own inner `Vec` is separately
/// bounded by generation-tied pruning (at most one entry per still-accepted SPK generation, i.e.
/// at most two in the ordinary case — see [`ChatState::responder_session_ek`]'s doc comment for
/// that axis) — capping peers is therefore the simpler unit to reason about and enforce without
/// also needing to track a separate total counter.
///
/// Eviction is oldest-peer-first, mirroring [`evict_oldest_pending`](ChatState::evict_oldest_pending)'s
/// own insertion-order tracking (`responder_session_ek_order`, the same technique as
/// `request_order`) exactly: [`record_responder_ek`](ChatState::record_responder_ek) — the only
/// writer — evicts the least-recently-*first-seen* peer before admitting a genuinely new one once
/// this cap is reached. Additionally, and independently of the cap,
/// [`reject_request`](ChatState::reject_request) and
/// [`evict_oldest_pending`](ChatState::evict_oldest_pending) now also remove the rejected/evicted
/// sender's `responder_session_ek` entries directly (mirroring how both already remove the
/// `Session` itself) — a rejected or evicted contact is left with no trace here either, which stops
/// the *ordinary* "user rejects every stranger" case from ever growing this map to begin with;
/// the cap below is the backstop for a sender who is never rejected/evicted at all (e.g. because
/// the peer stays under [`MAX_PENDING_REQUESTS`] while flooding with OTK-free-only strangers who
/// are never explicitly decided).
///
/// `TODO: confirm`: no design doc gives a numeric peer cap here — mirrors `MAX_PENDING_REQUESTS`'s
/// own precedent for exactly this kind of open threshold, and is deliberately set to the *same*
/// value: this map's outer key space is bounded by the same attack shape (one entry per distinct,
/// free-to-mint identity key) that `MAX_PENDING_REQUESTS` already reasons about at length, and
/// there's no basis in the design docs for treating the two ceilings differently.
pub const MAX_RESPONDER_SESSION_EK_PEERS: usize = 256;

/// Hard cap on the number of envelope `eid`s [`ChatState`] remembers as "recently, successfully
/// processed" (task 6.4, ADR 0016 C7 second half).
///
/// [`ChatState::open_bytes`]'s dedup check ([`ChatState::seen_eids`]) records an `eid` **only** on a
/// *successful* decrypt — see that field's doc comment — so, unlike [`MAX_PENDING_REQUESTS`]/
/// [`MAX_RESPONDER_SESSION_EK_PEERS`], an attacker cannot grow this set for free with OTK-free
/// first-contact junk alone: every entry costs the attacker a genuine AEAD success (their own key
/// material, or a captured genuine ciphertext that still decrypts). It is still bounded, not
/// literally unbounded, because a flood of **distinct, fresh** identities each completing one
/// genuine (if otherwise pointless) OTK-free X3DH handshake — exactly [`MAX_PENDING_REQUESTS`]'s own
/// attack shape, since a first-contact envelope that lands in the gated request queue still commits
/// per ADR 0016 C2 and therefore still records an `eid` — is a real, if costlier, way to grow this
/// set; see `apps/core/tests/message_request_flood.rs` for the general shape and this task's own
/// `apps/core/tests/eid_dedup.rs` for the `eid`-set-specific bound proof.
///
/// `TODO: confirm`: no design doc gives a numeric bound here — mirrors `MAX_PENDING_REQUESTS`'s own
/// precedent for exactly this kind of open threshold (see that constant's doc). Deliberately set to
/// the *same* value (256) rather than a larger one: `eid` dedup is a **recent-redelivery**
/// convenience (a relay retry landing twice, or a genuine unconfirmed-initiator resend before a
/// reply arrives — see [`ChatState::seal_bytes`]'s doc comment for the retransmit semantics this
/// task settled on), not a permanent replay ledger — R2 already accepts that only a *cheap
/// pre-filter*, never an unconditional guarantee, is in scope here (see [`ChatError::Desync`]'s doc
/// and this task's Outcome section). An `eid` evicted by this cap simply falls back to whatever
/// behavior existed before this task for that specific envelope shape (the ratchet's own
/// single-use-message-key exhaustion for an ordinary steady-state message, or the
/// [`responder_session_ek`](ChatState::responder_session_ek) freshness gate for a prekey-carrying
/// one) — never a silent acceptance. Eviction is oldest-first, mirroring
/// [`evict_oldest_pending`](ChatState::evict_oldest_pending)'s own insertion-order technique exactly
/// (see [`ChatState::seen_eid_order`]).
pub const MAX_SEEN_EIDS: usize = 256;

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
    /// The wall-clock unix second at which the *current* `spk_public`/`spk_secret` generation was
    /// published, i.e. the argument [`set_bundle`](Self::set_bundle) was last called with (task
    /// 6.1, ADR 0016 C1) — the input [`rotation_due`](Self::rotation_due) and
    /// [`generation_age_secs`](Self::generation_age_secs) reason from. `#[serde(default)]`,
    /// mirroring `previous`'s own precedent above, so a `PrekeyVault`/`ChatState` sealed before
    /// this task deserializes as `None` rather than panicking — see `rotation_due`'s doc comment
    /// for what "unknown age" (`None`) means for the predicate.
    #[serde(default)]
    spk_published_at: Option<u64>,
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
    ///
    /// Also stamps `spk_published_at = Some(now_unix)` unconditionally (task 6.1, ADR 0016 C1),
    /// starting a fresh generation's age clock at zero for [`rotation_due`](Self::rotation_due) and
    /// [`generation_age_secs`](Self::generation_age_secs).
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
        // (task 6.1) Record when *this* generation went live, feeding `rotation_due`/
        // `generation_age_secs`. Unconditional: every call to `set_bundle` — first-ever publish or
        // a later republish alike — starts a fresh generation's age clock at zero.
        self.spk_published_at = Some(now_unix);
    }

    /// How long the current signed-prekey generation has been published, in seconds, as of
    /// `now_unix` (task 6.1, ADR 0016 C1).
    ///
    /// Returns `None` when the publish time is unknown — either no bundle has ever been published
    /// ([`set_bundle`](Self::set_bundle) never called) or this `PrekeyVault` was deserialized from
    /// a state sealed before this task (`spk_published_at` defaults to `None`, see that field's
    /// doc comment). See [`rotation_due`](Self::rotation_due) for how the "unknown age" case is
    /// treated by the rotation policy itself.
    pub fn generation_age_secs(&self, now_unix: u64) -> Option<u64> {
        self.spk_published_at
            .map(|published_at| now_unix.saturating_sub(published_at))
    }

    /// Is the current signed-prekey generation due for rotation, as of `now_unix` (task 6.1, ADR
    /// 0016 C1)?
    ///
    /// This is a pure predicate: it only *answers* whether rotation is due. Nothing here
    /// republishes, warns, or reports metrics — that is task 6.2's job, acting on this signal.
    ///
    /// **Unknown-age semantics (deliberate security-relevant default, not a formality).** When
    /// `generation_age_secs` returns `None` — no bundle ever published, or this vault came from a
    /// state sealed before task 6.1 and so has no recorded `spk_published_at` — this returns
    /// `true`: unknown age is treated as due-now, i.e. fail-safe/fail-secure. The alternative
    /// (treating unknown age as *not* due) risks silently running an old SPK generation of
    /// unknown, possibly very old, age past ADR 0016's rotation window with nothing to ever flag
    /// it, which is exactly the "aspirational, not real" rotation posture ADR 0016 C1 exists to
    /// close out. The cost of the fail-safe choice is bounded and one-time: on upgrade from a
    /// pre-6.1 build, every existing session's next check of this predicate reports "due" once,
    /// prompting (once task 6.2 lands and acts on it) a single harmless extra republish — not a
    /// repeating or escalating cost, since `set_bundle` sets `spk_published_at` on that very
    /// republish and every subsequent check has a real, known age to reason from.
    pub fn rotation_due(&self, now_unix: u64) -> bool {
        match self.generation_age_secs(now_unix) {
            Some(age) => age >= SPK_ROTATION_INTERVAL_SECS,
            None => true,
        }
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

    /// Non-destructive lookup of the signed-prekey secret for `spk_public` (current or
    /// grace-window generation) — task 6.3, ADR 0016 C2. Identical to
    /// [`spk_secret_for`](Self::spk_secret_for): the SPK is never single-use, so that lookup was
    /// already read-only. This alias exists purely so the provisional-establishment call site
    /// (`ChatState::establish_responder_session_provisional`) reads symmetrically with
    /// [`peek_otk_secret`](Self::peek_otk_secret) below, which *is* a genuinely new non-destructive
    /// counterpart to the destructive [`take_otk_secret`](Self::take_otk_secret).
    fn peek_spk_secret(&self, spk_public: &[u8; 32]) -> Option<[u8; 32]> {
        self.spk_secret_for(spk_public)
    }

    /// Non-destructive counterpart to [`take_otk_secret`](Self::take_otk_secret) (task 6.3, ADR
    /// 0016 C2): looks up the one-time-prekey secret for `opk_public`, in either generation,
    /// **without removing it**, so a provisional X3DH establish-and-decrypt attempt can be built
    /// and tried before the OTK is actually spent. `ChatState::open_bytes` calls this (via
    /// `establish_responder_session_provisional`) for every establishment attempt, and only calls
    /// the destructive [`take_otk_secret`](Self::take_otk_secret) (via
    /// `ChatState::commit_responder_otk`) once that attempt's decrypt has actually succeeded.
    fn peek_otk_secret(&self, opk_public: &[u8; 32]) -> Option<[u8; 32]> {
        peek_otk(&self.otks, opk_public).or_else(|| {
            self.previous
                .as_ref()
                .and_then(|p| peek_otk(&p.otks, opk_public))
        })
    }

    /// Consume the secret for `opk_public`, whichever generation holds it.
    ///
    /// Single-use is enforced *across* generations: the OTK is removed from the current generation
    /// **and** from the retained previous one, so one published one-time prekey can never establish
    /// two sessions (a second attempt with the same public returns `None` →
    /// [`ChatError::UnknownPrekey`]).
    ///
    /// **(task 6.3) Only ever called after a successful decrypt.** Before ADR 0016 C2 this ran
    /// eagerly, as part of establishment, before the resulting session had even attempted to
    /// decrypt anything — see [`ChatState::commit_responder_otk`], its sole caller now, for the
    /// commit-on-decrypt discipline that replaced that.
    fn take_otk_secret(&mut self, opk_public: &[u8; 32]) -> Option<[u8; 32]> {
        let from_current = take_otk(&mut self.otks, opk_public);
        let from_prev = self
            .previous
            .as_mut()
            .and_then(|p| take_otk(&mut p.otks, opk_public));
        from_current.or(from_prev)
    }
}

/// Find (without removing) the secret behind `opk_public` in `otks`, if present. Non-destructive
/// counterpart to [`take_otk`], used by [`PrekeyVault::peek_otk_secret`].
fn peek_otk(otks: &[Otk], opk_public: &[u8; 32]) -> Option<[u8; 32]> {
    otks.iter()
        .find(|o| &o.public == opk_public)
        .map(|o| o.secret)
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
/// underneath it is *done*: the envelope's AEAD decrypt succeeded (commit-on-decrypt, ADR 0016
/// C2), X3DH ran (or the existing ratchet advanced), and a live [`Session`] is already installed
/// in [`ChatState`]'s session map — see the
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

/// One responder-established X3DH ephemeral key, tagged with the specific signed-prekey generation
/// (`Prekey::used_spk`) it referenced (task 4.9, second-round review fixup — see
/// [`ChatState::responder_session_ek`]'s doc comment for why the generation tag is what makes precise
/// pruning possible).
#[derive(Clone, Serialize, Deserialize)]
struct ResponderEk {
    #[serde(with = "b32")]
    ek_pub: [u8; 32],
    #[serde(with = "b32")]
    spk_public: [u8; 32],
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
    /// (task 4.9) Per-peer consecutive-`Desync` counter driving [`recovery_recommended`](Self::recovery_recommended).
    /// Pure bookkeeping — never itself touches `sessions`; see [`DESYNC_RECOVERY_THRESHOLD`]'s doc.
    /// `#[serde(default)]` so a store sealed before this task still opens (mirrors `request_order`'s
    /// own precedent, task 3.10) — a pre-4.9 store correctly defaults every peer to "no desyncs yet".
    #[serde(default)]
    desync_counts: BTreeMap<[u8; 32], u32>,
    /// (task 4.9 review fixup — the blocking finding, fixed a **second** time after a further review
    /// round found the first fix's own mechanism exploitable) Every [`Prekey::ek_pub`] that
    /// established a **responder** session with each peer, for as long as the specific signed-prekey
    /// generation it referenced ([`ResponderEk::spk_public`]) remains accepted by `self.vault` — keyed
    /// by peer identity key. This is the freshness record `open_bytes`'s stale-session recovery
    /// fallback consults before ever attempting fresh establishment — see that method's doc comment
    /// for the full reasoning, and `docs/api/messaging-envelope-v1.md` §3 for the wire-level statement
    /// of what this closes.
    ///
    /// **Why this is necessary, precisely.** X3DH is deterministic in its public inputs: replaying a
    /// peer's own original opening envelope byte-for-byte reconstructs a byte-identical initial
    /// ratchet state (this is unconditionally true whenever the referenced signed prekey is still
    /// valid, and *always* true for OTK-free X3DH, since the SPK is never consumed on use — the OTK
    /// case additionally requires the OTK not yet be spent). A successful AEAD decrypt alone
    /// proves *authenticity* (the claimed sender really produced these bytes at some point) but says
    /// nothing about *freshness* (whether these are the bytes they intend to send *now*). Without
    /// this record, `open_bytes`'s fallback could not tell a hostile replay of the exact prekey
    /// material that established the session currently held apart from a genuine new re-initiation
    /// — both verify, and for OTK-free X3DH both establish + decrypt successfully, deterministically,
    /// every time.
    ///
    /// **Why a history, not a single scalar — the second-round fix, and precisely what was wrong with
    /// the first.** The original fixup recorded only the single most-recently-established `ek_pub` per
    /// peer, *overwritten* on every new responder establishment for that peer — including a second,
    /// entirely genuine one. That is reachable within one ordinary session, not a rare edge case: an
    /// attacker who can force `DESYNC_RECOVERY_THRESHOLD` consecutive `Desync`s against the *peer's
    /// own* inbound path can drive their guarded recovery (`attempt_recovery` /
    /// `replace_session_as_initiator`) to produce that second, genuine establishment itself. Once the
    /// single recorded value was overwritten to the new `ek_pub`, a replay of the *original* (still
    /// SPK-generation-valid — a signed prekey is never consumed on use, and a real client may not
    /// republish for the lifetime of a long-running session) opening envelope no longer matched the
    /// recorded value, so the freshness check silently failed to fire and the replay was accepted —
    /// exactly reconstructing that first session and rolling the live one back to it. Overwriting was
    /// exactly *clearing*, not (as the field's doc previously, incorrectly, claimed) "strictly more
    /// protective than clearing, never less". The fix: **every** `ek_pub` from a responder
    /// establishment is retained, tagged with the SPK generation it was established under, for as long
    /// as that generation stays accepted — see [`record_responder_ek`](Self::record_responder_ek) (the
    /// only writer) and [`is_recorded_responder_ek`](Self::is_recorded_responder_ek) (the only reader,
    /// used by `open_bytes`'s freshness gate) — rather than a single value that a second legitimate
    /// establishment can silently displace.
    ///
    /// **Pruning, and why it stays bounded.** An entry is retained only as long as
    /// `self.vault.spk_secret_for(&entry.spk_public)` still returns `Some` — i.e. its generation is
    /// either the vault's current one or the single grace-window-retained previous one (exactly
    /// [`PrekeyVault::spk_secret_for`]'s own acceptance rule). [`prune_responder_session_ek`](Self::prune_responder_session_ek)
    /// removes everything else and is called by [`expire_previous_generation`](Self::expire_previous_generation)
    /// in the same call that retires the vault's own superseded generation — callers that previously
    /// called `state.vault.expire_previous_generation(now_unix)` directly (the CLI's inbound path,
    /// task 1.31) now call this `ChatState`-level wrapper instead, so the two stay in lockstep and this
    /// map's growth is bounded by exactly the mechanism that already bounds `PrevGeneration` retention
    /// (at most one superseded generation, for at most [`PREV_GENERATION_GRACE_SECS`]), not a separate,
    /// disconnected accumulation — this bounds the *within-one-peer* axis: while a single SPK
    /// generation stays current for an unusually long time (a long-running process that never
    /// republishes) and a peer's inbound path is repeatedly forced through the guarded-recovery
    /// threshold, one peer's own entry can accumulate one `ResponderEk` per such cycle — bounded by
    /// the same `DESYNC_RECOVERY_THRESHOLD`-gated rate the recovery machinery itself is already
    /// rate-limited by (`ChatError::Desync`'s doc: at most one recovery attempt per that many forced
    /// failures), not literally unbounded even before the cross-peer cap below.
    ///
    /// **The other axis — third-round review fixup: genuinely bounded across distinct peers too.**
    /// Everything above only ever reasoned about one already-recorded peer's own growth. It said
    /// nothing about the *outer* map key space: this field is written on **every** successful
    /// responder establishment, including the ordinary first-contact branch, not merely the
    /// recovery path — and OTK-free X3DH is legal, so (exactly [`MAX_PENDING_REQUESTS`]'s own
    /// precedent) a first-contact envelope costs its sender nothing but a fresh identity key.
    /// Nothing bounded how many distinct never-before-seen identities could each add a new outer-map
    /// entry, independently of whether their request was ever accepted, or even whether it was
    /// immediately rejected — neither [`reject_request`](Self::reject_request) nor
    /// [`evict_oldest_pending`](Self::evict_oldest_pending) used to touch this map at all, so even a
    /// defender who rejects every stranger on sight, or who hits [`MAX_PENDING_REQUESTS`]'s own
    /// eviction cap, still accumulated one lingering entry per distinct attacker identity. Both fixes
    /// now: (a) [`reject_request`](Self::reject_request) and
    /// [`evict_oldest_pending`](Self::evict_oldest_pending) remove the rejected/evicted sender's
    /// entry here too, in the same call that removes their `Session` — consistent, not a regression,
    /// because once the establishing `Session` itself is gone, a later envelope from that same
    /// sender hits `open_bytes`'s unconditional "no session at all" first-contact branch again
    /// exactly like any other never-before-seen contact, so there is no live freshness check left for
    /// a lingering entry to have been protecting; and (b) [`MAX_RESPONDER_SESSION_EK_PEERS`] hard-caps
    /// the number of distinct peer keys this map holds at once, LRU-evicting the least-recently-first-
    /// seen peer in [`record_responder_ek`](Self::record_responder_ek) — see that constant's doc for
    /// the full reasoning. Together, this map's growth is now bounded on **both** axes: within one
    /// peer (generation-tied pruning, above) and across distinct peers (this cap, plus rejection/
    /// eviction cleanup that stops the ordinary "reject every stranger" case from ever needing it).
    ///
    /// Once an entry's generation is genuinely gone, a replay of that `ek_pub` no longer matches
    /// anything here — but it is already independently blocked:
    /// `establish_responder_session_provisional` fails with [`ChatError::UnknownPrekey`]
    /// (`spk_secret_for` returns `None`), which `open_bytes`'s
    /// fallback already treats as an ordinary failed recovery attempt (falls through to `Desync`,
    /// state left untouched) — the same fail-closed path a first-contact attempt against an expired
    /// generation already takes today. Pruning cannot reopen this: it only ever removes entries whose
    /// protection has already, independently, been taken over by that path.
    ///
    /// Still never touched by [`start_initiator_session`] or
    /// [`replace_session_as_initiator`](Self::replace_session_as_initiator) (both establish an
    /// **initiator** session, which is never the target of this specific replay check).
    ///
    /// **The "no recorded entry" case, reasoned through — unchanged from the first fixup.** If
    /// `open_bytes`'s fallback fires for a peer with no entries here at all — either because the
    /// currently-held session was established as an *initiator* (we dialled them; they never sent us a
    /// prekey before, so there is nothing of theirs to replay), or because no responder session has
    /// ever been established for them at all — the freshness check cannot fire, so the fallback
    /// behaves exactly as before either fixup: authenticity (a successful AEAD decrypt) is the
    /// only available gate, and the attempt is allowed. This is deliberately not "fixed" further:
    /// closing *that* gap would
    /// mean either (a) refusing every fallback with no recorded entry, which would silently regress the
    /// legitimate case of a first prekey envelope ever sent in that direction, or (b) inventing a
    /// freshness signal for initiator-established sessions that this module has no cryptographic basis
    /// for.
    #[serde(default)]
    responder_session_ek: BTreeMap<[u8; 32], Vec<ResponderEk>>,
    /// First-seen order (oldest first) of the peer keys currently present in
    /// `responder_session_ek` (task 4.9, third-round review fixup) — the exact same
    /// insertion-order technique `request_order` uses for `pending_requests` (task 3.10), for the
    /// same reason: this crate is deliberately clock-free (wasm32 target), so eviction order is
    /// tracked as a plain sequence rather than by timestamp. Maintained in lockstep with
    /// `responder_session_ek` by every path that adds or removes a peer entry —
    /// [`record_responder_ek`](Self::record_responder_ek) (append on first sight of a peer),
    /// [`forget_responder_session_ek`](Self::forget_responder_session_ek) (used by
    /// [`reject_request`](Self::reject_request) and
    /// [`evict_oldest_pending`](Self::evict_oldest_pending)), and
    /// [`prune_responder_session_ek`](Self::prune_responder_session_ek) — which is what makes
    /// [`evict_oldest_responder_session_ek_peer`](Self::evict_oldest_responder_session_ek_peer)'s
    /// pick always a peer genuinely still present in `responder_session_ek`. `#[serde(default)]` so
    /// a store sealed before this fixup (which has `responder_session_ek` populated but no order
    /// field at all) still opens; [`reconcile_responder_session_ek_order`](Self::reconcile_responder_session_ek_order)
    /// (called from [`open_at_rest`](Self::open_at_rest), mirroring
    /// [`reconcile_request_order`](Self::reconcile_request_order)'s own precedent) repairs it against
    /// `responder_session_ek` right after deserializing.
    #[serde(default)]
    responder_session_ek_order: Vec<[u8; 32]>,
    /// (task 6.4, ADR 0016 C7 second half) Envelope `eid`s [`open_bytes`](Self::open_bytes) has
    /// **successfully decrypted** recently — the dedup check that lets a genuinely redelivered
    /// envelope (relay retry, or a legitimate unconfirmed-initiator resend — see
    /// [`seal_bytes`](Self::seal_bytes)'s doc comment) be recognized and dropped without
    /// reprocessing it as new (see [`ChatError::DuplicateEnvelope`]).
    ///
    /// **Written only on success, deliberately.** An `eid` is recorded here only once its envelope
    /// has actually decrypted (via [`record_seen_eid`](Self::record_seen_eid), called from every one
    /// of `open_bytes`'s three `Ok` return points — first-contact establishment, an existing
    /// session's ordinary decrypt, and the task-4.9 stale-session recovery fallback) — never
    /// speculatively, and never for a rejected/failed attempt. This is what keeps the dedup check
    /// safe to run *before* any crypto work: an attacker cannot pre-poison a legitimate sender's
    /// future `eid` (128 bits of sender-random entropy — see `seal_bytes`), and cannot use a forged
    /// envelope carrying someone else's already-seen `eid` to suppress a *distinct*, not-yet-sent
    /// message, since that future message will carry its own, different, freshly-random `eid` — see
    /// [`ChatError::DuplicateEnvelope`]'s doc comment for the precise, deliberately narrow security
    /// claim (none) this check makes.
    ///
    /// Bounded by [`MAX_SEEN_EIDS`] — see that constant's doc for why this set, unlike
    /// `pending_requests`/`responder_session_ek`, is not free for an attacker to grow. No
    /// `open_at_rest`-time reconciliation is needed against `seen_eid_order` (contrast
    /// `responder_session_ek_order`/`request_order`, both of which repair drift against a field that
    /// predates their own order-tracking companion): `seen_eids` and `seen_eid_order` were
    /// introduced together, in this same task, so there is no pre-existing at-rest blob that could
    /// have one populated and the other empty — both are simply empty on any blob sealed before this
    /// task (`#[serde(default)]`), which is already in sync.
    #[serde(default)]
    seen_eids: std::collections::BTreeSet<[u8; 16]>,
    /// Insertion order (oldest first) of the `eid`s currently present in `seen_eids` — the same
    /// technique `request_order`/`responder_session_ek_order` use, for the same reason (this crate
    /// is deliberately clock-free; see `request_order`'s doc comment). Maintained in lockstep with
    /// `seen_eids` by its only writer, [`record_seen_eid`](Self::record_seen_eid), and consulted only
    /// by [`evict_oldest_seen_eid`](Self::evict_oldest_seen_eid). See `seen_eids`'s own doc comment
    /// for why no `open_at_rest` reconciliation against this field is needed.
    #[serde(default)]
    seen_eid_order: Vec<[u8; 16]>,
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

    // -- task 4.9: guarded receiver-side desync recovery ------------------------------------

    // **Design note (review fixup — not a code change, a flagged consideration for a future
    // task).** `self.sessions` — and therefore everything below, including the
    // `responder_session_ek` freshness tracking and the forced-replacement recovery machinery — is
    // shared between this (relay/mailbox) chat path and the P2P session substrate
    // (`apps/core/src/session.rs`), which calls `open_bytes`/`establish_responder_session_provisional`
    // directly
    // against the exact same `Session` objects, by design ("same ratchet" — see `session.rs`'s
    // module doc). Today the two run as separate command invocations (the CLI's relay/mailbox chat
    // flow and its P2P dial flow are distinct processes or at least distinct, non-overlapping
    // invocations), so there is no live interlock issue: recovery never races a P2P session that is
    // simultaneously in use. A future single-process client that consolidates both paths in one
    // running process (T17's interactive TUI, or the desktop/mobile clients) could change that —
    // stale or hostile relay traffic triggering this guarded recovery could discard ratchet state
    // that a *live* P2P session concurrently depends on, while that P2P session is mid-call. This is
    // not fixed here (task 4.9's scope is the `open_bytes` discriminator + the freshness-replay gap,
    // not a cross-path concurrency redesign) — flagged for whichever future task is the first to run
    // both paths in one process to design an explicit interlock (e.g. refusing recovery while a P2P
    // session for the same peer is active) before shipping that consolidation.

    /// The current consecutive-`Desync` count for `peer_ik` (0 if none, or if never observed).
    /// Read-only diagnostic surface; see [`recovery_recommended`](Self::recovery_recommended) for
    /// the actual decision.
    pub fn desync_count(&self, peer_ik: &[u8; 32]) -> u32 {
        self.desync_counts.get(peer_ik).copied().unwrap_or(0)
    }

    /// Whether task 4.9's guarded receiver-side re-handshake should be attempted for `peer_ik` —
    /// `true` once [`desync_count`](Self::desync_count) has reached [`DESYNC_RECOVERY_THRESHOLD`].
    /// Callers (only [`crate::desync::attempt_recovery`] and its CLI caller today) must still
    /// additionally consult [`crate::trust::TrustStore::can_send`] before acting on this — this
    /// method alone says nothing about whether the peer's trust state permits an automatic
    /// re-handshake right now.
    pub fn recovery_recommended(&self, peer_ik: &[u8; 32]) -> bool {
        self.desync_count(peer_ik) >= DESYNC_RECOVERY_THRESHOLD
    }

    /// Record one more consecutive `Desync` classification for `peer_ik`. Crate-private: the only
    /// caller is [`open_bytes`](Self::open_bytes) itself, at the exact point it is about to return
    /// [`ChatError::Desync`] — never called speculatively, and never for any other error variant.
    fn note_desync(&mut self, peer_ik: [u8; 32]) {
        let count = self.desync_counts.entry(peer_ik).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Clear `peer_ik`'s consecutive-`Desync` counter — called on every successful decrypt from that
    /// peer (a live, healthy exchange proves the session recovered, or was never actually broken).
    /// Crate-private for the same reason as [`note_desync`](Self::note_desync).
    fn reset_desync(&mut self, peer_ik: &[u8; 32]) {
        self.desync_counts.remove(peer_ik);
    }

    /// Mark that a recovery attempt for `peer_ik` has been *decided* — whatever the outcome (a
    /// successful re-handshake, or a refusal because [`crate::trust::TrustStore::can_send`] was not
    /// `Ok`). Resets the counter exactly like the crate-private `reset_desync` above, but is `pub`
    /// (rather than crate-private) because the CLI's own pre-fetch gate check
    /// (`apps/cli/src/chat.rs`) needs to call this too, on the refusal path that short-circuits
    /// *before* ever reaching [`crate::desync::attempt_recovery`] (so it never wastes a network
    /// round-trip on a peer it already locally knows is gated) — see [`DESYNC_RECOVERY_THRESHOLD`]'s
    /// doc for why resetting on a refusal, not just a success, matters for the rate-limiting
    /// property. [`crate::desync::attempt_recovery`] also calls this itself (as its very first
    /// action), so calling it twice for the same decided attempt is harmless (idempotent — removing
    /// an already-absent counter entry is a no-op).
    pub fn note_recovery_attempted(&mut self, peer_ik: &[u8; 32]) {
        self.desync_counts.remove(peer_ik);
    }

    // -- task 4.9 (second-round review fixup): responder_session_ek history -------------------

    /// Record that a responder session with `peer_ik` was just established from `ek_pub` against the
    /// signed prekey `spk_public`. The only writer of [`responder_session_ek`](Self::responder_session_ek)
    /// — see that field's doc comment for why this *appends* rather than overwrites, and never
    /// records a duplicate `(ek_pub, spk_public)` pair twice (harmless either way for the freshness
    /// check itself, which only asks membership, but keeps the vector from growing on a redundant
    /// call). Also enforces [`MAX_RESPONDER_SESSION_EK_PEERS`] (third-round review fixup): if
    /// `peer_ik` is not already a key in `responder_session_ek` and admitting it would exceed the
    /// cap, the least-recently-first-seen peer is evicted first
    /// ([`evict_oldest_responder_session_ek_peer`](Self::evict_oldest_responder_session_ek_peer)) —
    /// see that constant's doc comment for the full reasoning. `responder_session_ek_order` is kept
    /// in lockstep here exactly like `request_order` is by `insert_pending_request`.
    fn record_responder_ek(&mut self, peer_ik: [u8; 32], ek_pub: [u8; 32], spk_public: [u8; 32]) {
        let is_new_peer = !self.responder_session_ek.contains_key(&peer_ik);
        if is_new_peer && self.responder_session_ek.len() >= MAX_RESPONDER_SESSION_EK_PEERS {
            self.evict_oldest_responder_session_ek_peer();
        }
        let entries = self.responder_session_ek.entry(peer_ik).or_default();
        if !entries
            .iter()
            .any(|e| e.ek_pub == ek_pub && e.spk_public == spk_public)
        {
            entries.push(ResponderEk { ek_pub, spk_public });
        }
        if is_new_peer {
            self.responder_session_ek_order.push(peer_ik);
        }
    }

    /// Whether `ek_pub` is recorded as having established a still-SPK-valid responder session with
    /// `peer_ik` — the only reader of [`responder_session_ek`](Self::responder_session_ek), consulted
    /// by `open_bytes`'s freshness gate. `true` for a match against *any* recorded entry for this
    /// peer, not merely the most recent — see that field's doc comment for why.
    fn is_recorded_responder_ek(&self, peer_ik: &[u8; 32], ek_pub: &[u8; 32]) -> bool {
        self.responder_session_ek
            .get(peer_ik)
            .is_some_and(|entries| entries.iter().any(|e| &e.ek_pub == ek_pub))
    }

    /// Drop every recorded `ek_pub` whose referenced SPK generation `self.vault` no longer accepts
    /// (see [`PrekeyVault::spk_secret_for`]), and any peer entry left with none remaining. Crate-private:
    /// the only caller is [`expire_previous_generation`](Self::expire_previous_generation), which runs
    /// this in lockstep with the vault's own generation retirement — see
    /// [`responder_session_ek`](Self::responder_session_ek)'s doc comment for why that lockstep is what
    /// keeps this map's growth bounded.
    fn prune_responder_session_ek(&mut self) {
        let vault = &self.vault;
        self.responder_session_ek.retain(|_peer, entries| {
            entries.retain(|e| vault.spk_secret_for(&e.spk_public).is_some());
            !entries.is_empty()
        });
        // Keep `responder_session_ek_order` in lockstep: drop any peer the retain above just
        // removed entirely, same as `reconcile_request_order` does for `request_order`.
        let remaining = &self.responder_session_ek;
        self.responder_session_ek_order
            .retain(|peer| remaining.contains_key(peer));
    }

    /// Remove `peer_ik`'s entry from `responder_session_ek` (and `responder_session_ek_order` in
    /// lockstep), if present. Crate-private: called by [`reject_request`](Self::reject_request) and
    /// [`evict_oldest_pending`](Self::evict_oldest_pending) — third-round review fixup — in the same
    /// call each already removes the peer's `Session`, so a rejected/evicted contact leaves nothing
    /// behind in either place. See [`responder_session_ek`](Self::responder_session_ek)'s doc comment
    /// for why this is safe: once the establishing `Session` is gone, a later envelope from the same
    /// sender hits `open_bytes`'s unconditional first-contact branch again regardless of what this
    /// map holds, so there is no live freshness check left for a lingering entry to protect.
    fn forget_responder_session_ek(&mut self, peer_ik: &[u8; 32]) {
        if self.responder_session_ek.remove(peer_ik).is_some() {
            self.responder_session_ek_order.retain(|k| k != peer_ik);
        }
    }

    /// Drop the least-recently-first-seen peer in `responder_session_ek_order` (and its
    /// `responder_session_ek` entries) to make room under [`MAX_RESPONDER_SESSION_EK_PEERS`]. Mirrors
    /// [`evict_oldest_pending`](Self::evict_oldest_pending)'s own structure and defense-in-depth
    /// reasoning exactly: `responder_session_ek_order` should only ever contain keys currently present
    /// in `responder_session_ek` (every writer/remover keeps the two in lockstep — see
    /// [`responder_session_ek_order`](Self::responder_session_ek_order)'s doc comment), but the `while`
    /// loop below tolerates a hypothetical desync (e.g. state reconciled from an old at-rest blob by
    /// [`reconcile_responder_session_ek_order`](Self::reconcile_responder_session_ek_order)) rather
    /// than assume it can never happen.
    fn evict_oldest_responder_session_ek_peer(&mut self) {
        while !self.responder_session_ek_order.is_empty() {
            let oldest = self.responder_session_ek_order.remove(0);
            if self.responder_session_ek.remove(&oldest).is_some() {
                return;
            }
            // Stale order entry with no matching map entry — keep looking rather than silently
            // evict nothing (same reasoning as `evict_oldest_pending`'s own loop).
        }
    }

    /// Repair `responder_session_ek_order` against `responder_session_ek` after deserializing an
    /// at-rest blob — the exact same shape of repair
    /// [`reconcile_request_order`](Self::reconcile_request_order) performs for `request_order`, for
    /// the same reason: a blob sealed before this fixup has `responder_session_ek` populated (that
    /// map predates this order-tracking field) but no order field at all
    /// (`#[serde(default)]` leaves it empty). Recovered peers are appended in `responder_session_ek`'s
    /// own (`BTreeMap`/key) order — not true first-seen order, since that was never recorded for them
    /// — mirroring `reconcile_request_order`'s own documented, narrow, one-time residual (see that
    /// method's doc comment; the same reasoning applies here unchanged).
    fn reconcile_responder_session_ek_order(&mut self) {
        let known: std::collections::BTreeSet<[u8; 32]> =
            self.responder_session_ek.keys().copied().collect();
        self.responder_session_ek_order
            .retain(|k| known.contains(k));
        let already_ordered: std::collections::BTreeSet<[u8; 32]> =
            self.responder_session_ek_order.iter().copied().collect();
        for k in known {
            if !already_ordered.contains(&k) {
                self.responder_session_ek_order.push(k);
            }
        }
    }

    // -- task 6.4, ADR 0016 C7 second half: the eid replay-dedup set ------------------------

    /// Whether `eid` has already been recorded as a successfully-decrypted envelope — the check
    /// [`open_bytes`](Self::open_bytes) consults *before* any provisional establishment or decrypt
    /// attempt. See [`seen_eids`](Self::seen_eids)'s doc comment for the full design note.
    fn is_seen_eid(&self, eid: &[u8; 16]) -> bool {
        self.seen_eids.contains(eid)
    }

    /// Record `eid` as successfully processed, evicting the oldest recorded `eid` first if
    /// [`seen_eids`](Self::seen_eids) is already at [`MAX_SEEN_EIDS`]. Mirrors
    /// [`insert_pending_request`](Self::insert_pending_request)'s exact shape (check-then-evict
    /// before insert, insertion-order tracking alongside the set). Idempotent: called only from
    /// `open_bytes`'s three success points, each of which has already independently ruled out `eid`
    /// being present (the dedup check that runs first in the same call), so the `contains` guard
    /// below is defense-in-depth, not a path this code expects to exercise.
    fn record_seen_eid(&mut self, eid: [u8; 16]) {
        if self.seen_eids.contains(&eid) {
            return;
        }
        if self.seen_eids.len() >= MAX_SEEN_EIDS {
            self.evict_oldest_seen_eid();
        }
        self.seen_eids.insert(eid);
        self.seen_eid_order.push(eid);
    }

    /// Drop the least-recently-recorded `eid` (and its `seen_eid_order` entry) to make room under
    /// [`MAX_SEEN_EIDS`]. Mirrors [`evict_oldest_pending`](Self::evict_oldest_pending)'s exact shape,
    /// including the defense-in-depth `while` loop against a hypothetical order/set desync.
    fn evict_oldest_seen_eid(&mut self) {
        while !self.seen_eid_order.is_empty() {
            let oldest = self.seen_eid_order.remove(0);
            if self.seen_eids.remove(&oldest) {
                return;
            }
        }
    }

    /// Retire a superseded prekey generation whose grace window has passed
    /// ([`PrekeyVault::expire_previous_generation`]) **and**, in the same call, prune every
    /// [`responder_session_ek`](Self::responder_session_ek) entry that referenced it — see that
    /// field's doc comment for why the two must stay in lockstep. This wrapper exists specifically
    /// because that pruning needs both `self.vault` and `self.responder_session_ek` and so cannot live
    /// on [`PrekeyVault`] alone (which — by design — knows nothing about session-establishment
    /// bookkeeping).
    ///
    /// Callers that answer incoming X3DH handshakes should call this (with a real wall clock) before
    /// opening inbound blobs — the CLI's inbound path (task 1.31) calls this exactly where it
    /// previously called `state.vault.expire_previous_generation` directly.
    pub fn expire_previous_generation(&mut self, now_unix: u64) {
        self.vault.expire_previous_generation(now_unix);
        self.prune_responder_session_ek();
    }

    /// **The sole, explicit surface for forcing a session replacement** (task 4.9). Discards any
    /// existing session with `peer_ik` — stale or not — and establishes a brand-new **initiator**
    /// session against a freshly fetched, verified bundle, unconditionally, even though a session
    /// already exists.
    ///
    /// **Why this is a separate method, not a change to [`start_initiator_session`](Self::start_initiator_session).**
    /// `start_initiator_session` is deliberately idempotent-as-a-no-op when a session already exists
    /// — that is what lets an ordinary "reopen an existing chat" keep its live ratchet instead of
    /// re-handshaking every time the CLI restarts. Weakening that behavior anywhere would silently
    /// change every one of `start_initiator_session`'s existing callers. This method exists
    /// specifically so the one call site that legitimately needs the opposite behavior — task 4.9's
    /// guarded recovery, via [`crate::desync::attempt_recovery`] only — has its own clearly-named,
    /// impossible-to-reach-by-accident surface, rather than a flag silently changing
    /// `start_initiator_session`'s contract.
    ///
    /// **Build-then-swap ordering (review fixup).** [`Session::initiate`] is called *first*, against
    /// the existing (stale-or-not) session still fully intact; the old session is only ever replaced
    /// — via `self.sessions.insert`'s replace-on-existing-key behavior, a single atomic swap — once
    /// construction has *fully succeeded*. A local failure inside `Session::initiate` (a keystore
    /// error, an RNG failure, or a malformed `peer_ik`/`peer_spk`) therefore leaves the peer with
    /// their old, working (if stale) session, exactly as if this method had never been called, rather
    /// than the previous behavior of removing the old session unconditionally *before* attempting
    /// construction — which left the peer with **no session at all** on any such failure, a strictly
    /// worse outcome than the desync this method exists to recover from. `peer_ik`'s desync counter
    /// (see [`note_recovery_attempted`](Self::note_recovery_attempted)) is still cleared regardless of
    /// outcome — even a failed attempt was still a *decided* attempt, not a skipped one, matching
    /// `note_recovery_attempted`'s own "whatever the outcome" contract — and is safe to call even when
    /// this method is invoked directly (e.g. from a test) without going through
    /// [`crate::desync::attempt_recovery`] first, which already calls it too (idempotent).
    ///
    /// `peer_spk`/`peer_opk` come from the caller's already-fetched, already-signature-verified
    /// bundle (same contract as `start_initiator_session`'s own parameters) — this method does not
    /// fetch or verify anything itself (this crate is I/O-free; see the module doc).
    pub fn replace_session_as_initiator(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        peer_spk: &[u8; 32],
        peer_opk: Option<[u8; 32]>,
    ) -> Result<(), ChatError> {
        let result = Session::initiate(store, handle, our_ik, peer_ik, peer_spk, peer_opk);
        // Whatever the outcome — decided, not skipped. See this method's doc comment.
        self.note_recovery_attempted(peer_ik);
        let (session, _material) = result?;
        // Only reached once construction has fully succeeded: replaces the stale entry in a single
        // atomic swap (`BTreeMap::insert` on an existing key overwrites in place) rather than ever
        // leaving `peer_ik` absent from `self.sessions` in between.
        self.sessions.insert(*peer_ik, session);
        Ok(())
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
    /// (AEAD decrypt succeeded, X3DH complete); accepting is pure local bookkeeping and
    /// re-verifies nothing.
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
        // (task 4.9, third-round review fixup) Same reasoning as the `Session` removal just above,
        // extended to the freshness-history entry it left behind: see
        // `responder_session_ek`'s doc comment for why removing it here is safe, not a regression.
        self.forget_responder_session_ek(sender_ik);
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
                // (task 4.9, third-round review fixup) Same reasoning as `reject_request`'s own
                // cleanup: an evicted contact leaves nothing behind here either.
                self.forget_responder_session_ek(&oldest);
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
    /// never recorded for them.
    ///
    /// **This fallback order is not neutral — it is attacker-influenceable.**
    /// `pending_requests` is keyed by the sender's account identity key, which OTK-free X3DH
    /// (the exact fact `MAX_PENDING_REQUESTS` exists to mitigate) lets an attacker mint for free
    /// and choose freely: a numerically-large-prefix key sorts last, i.e. "most recently arrived",
    /// under this fallback. So an attacker who can predict or force a legacy-blob reconciliation
    /// (e.g. around an upgrade boundary) can grind an identity key to make their own planted
    /// pre-upgrade request look newest, at a genuinely older legitimate request's expense should
    /// eviction pressure hit. This is deliberately accepted as a narrow, one-time residual — see
    /// this task's Outcome section (`docs/tasks/phase-3/3.10-message-request-flood-bound.md`) for
    /// why it doesn't extend past a single `open_at_rest` call and can't touch anything already
    /// decided — rather than a claim that this ordering is neutral or "can't be gamed".
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

    /// Build a ratchet-encrypted envelope for `content` to `peer_ik`. See [`seal_bytes`] for
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

    /// Seal an **arbitrary** ratchet plaintext into a [`MessageEnvelope`] v2 blob on the session
    /// with `peer_ik`. The same primitive carries `mrd.chat/1` payloads and the P2P substrate's
    /// `SignalContent` (SDP/ICE/ctrl) over one ratchet — the transport-independence of §4.3: the
    /// same envelope bytes are valid over WSS routing, the mailbox, or a data channel.
    ///
    /// The session must already exist (initiator: [`Session::initiate`]; responder: created on first
    /// receive via [`open_bytes`](ChatState::open_bytes)).
    ///
    /// **(task 6.3, ADR 0016 C2/C3) No longer signs anything.** `store`/`handle` are accepted for
    /// call-site symmetry with [`open_bytes`](Self::open_bytes) and its own callers (P2P substrate,
    /// CLI) and so this method's signature does not need to change if a future authenticated
    /// operation is ever added here — but this method itself performs no keystore operation today:
    /// authentication of the outbound message is entirely the ratchet AEAD's job now (`AD` is
    /// derived from `our_ik`/`peer_ik` once, at session establishment, not re-signed per message).
    ///
    /// **(task 6.4, ADR 0016 C7 second half) `eid` — minted fresh, every call.** A sender-random
    /// 128-bit `MessageEnvelope::eid` is generated here, via the same CSPRNG source (`getrandom`)
    /// and 128-bit width `ChatContent::Text::id` already uses (mirroring that field's own generation
    /// pattern, per this task's `TODO: confirm` resolution — see the Outcome section in
    /// `docs/tasks/phase-6/6.4-eid-replay-dedup.md`), and embedded once, outer plaintext, alongside
    /// `sender_pub`/`v`/`prekey` — never fed into the ratchet AAD (see `MessageEnvelope`'s own module
    /// doc) and never derived from `plaintext`.
    ///
    /// **What "retransmit dedup" means for this primitive, precisely — read before wiring in a
    /// retry/outbox mechanism.** This method has no notion of "the same logical message" beyond the
    /// `plaintext` bytes handed to it on any one call: it does not cache, hash, or compare previous
    /// calls' plaintext. A **genuine unconfirmed-initiator retransmit dedups against itself** exactly
    /// when the retransmission resends the *exact previously-produced envelope bytes* (the `Vec<u8>`
    /// this method already returned) — never by calling `seal_bytes` a second time for
    /// already-sent content. Resent verbatim, those bytes trivially carry the original `eid` (and the
    /// original prekey preamble, if any — session-unconfirmed re-attachment, an existing, unrelated
    /// property) unchanged, which is exactly what lets [`open_bytes`](Self::open_bytes)'s dedup check
    /// recognize the redelivery. This is deliberate, not an oversight: this codebase has no
    /// persisted-envelope outbox yet (`docs/architecture/data-model.md`'s `outbox/` — "idempotent by
    /// `eid`" — is a client local-store concern for a future task, ADR 0021), so there is today no
    /// caller that would re-invoke `seal_bytes` for content already sealed once. If a future
    /// retry/outbox mechanism instead calls `seal_bytes` again for logically-the-same content (rather
    /// than replaying stored bytes), it will mint a **fresh, different** `eid` — and, since
    /// `Session::encrypt` always advances the sending chain, a genuinely different `ct` too — so the
    /// two envelopes will **not** dedup against each other here; that mechanism would need its own
    /// reuse strategy, out of this method's scope. See this task's Outcome section for the full
    /// design note and why a content-comparison cache inside this method was deliberately not built.
    pub fn seal_bytes(
        &mut self,
        _store: &dyn SecretStore,
        _handle: &KeyHandle,
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
        let mut eid = [0u8; 16];
        getrandom::fill(&mut eid).map_err(|e| meridian_crypto::CryptoError::Rng(e.to_string()))?;
        let envelope = MessageEnvelope {
            v: ENVELOPE_VERSION,
            sender_pub: *our_ik,
            eid,
            prekey,
            ct,
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
    /// **Hard invariant (task 2.10): gating happens after decryption and session establishment.**
    /// The check below runs *after* [`open_bytes`] has already decrypted the envelope and (on a
    /// first contact) completed X3DH — so a first contact that is ultimately rejected still cost
    /// the sender's one-time prekey (task 6.3, ADR 0016 C2: only on a **successful** decrypt —
    /// commit-on-decrypt means a forged/mutated first-contact envelope costs nothing, but a
    /// genuinely-decrypting one that the request-queue subsequently gates still did). This is the
    /// same class of
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
        self.open_inbound_gated(store, handle, our_ik, from, blob, false, false)
    }

    /// (task 8.8, ADR 0024) Like [`open_inbound`](Self::open_inbound), but for a **mailbox-drained**
    /// [`Deliver`](meridian_proto::Deliver) (`mailbox_id.is_some()`, task 8.7): `from` is the
    /// server's `[0u8; 32]` placeholder, never a real routing-layer identity, so the
    /// `envelope.sender_pub != from` defense-in-depth check is skipped — see
    /// [`open_bytes`](Self::open_bytes)'s own doc comment for the full reasoning. Callers must use
    /// this instead of [`open_inbound`](Self::open_inbound) precisely when, and only when,
    /// `deliver.mailbox_id.is_some()`; every live or federated-live delivery
    /// (`mailbox_id: None`) keeps going through the ordinary [`open_inbound`](Self::open_inbound),
    /// which still performs today's exact sender check, unweakened.
    pub fn open_inbound_from_mailbox(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
    ) -> Result<ChatContent, ChatError> {
        self.open_inbound_gated(store, handle, our_ik, from, blob, false, true)
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
    /// [`open_bytes`] has decrypted the envelope (and, on first contact, completed X3DH) — gating
    /// is delivery-only, never a crypto shortcut, and a rejected first contact still costs whatever
    /// handshake material (e.g. a one-time prekey) it consumed on the way to a successful decrypt.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_inbound_gated(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
        force_first_contact: bool,
        mailbox_drained: bool,
    ) -> Result<ChatContent, ChatError> {
        // (task 8.8, ADR 0024) Every piece of *local bookkeeping* below (the pending-request gate,
        // first-contact detection, and the queued request's own key) is keyed by
        // `envelope.sender_pub`, never the routing-layer `from` — on the live path the two are
        // enforced equal by `open_bytes`'s own check below, so this is behaviorally identical
        // there; on a mailbox-drained path `from` is only the server's `[0u8; 32]` placeholder and
        // carries no identity information at all, so keying bookkeeping off it would silently
        // misfile every mailbox-drained first contact under the same meaningless zero key instead
        // of the real sender. This decode is the same cheap, non-cryptographic parse `open_bytes`
        // performs a moment later on its own copy of `blob` — reading `sender_pub` this early is
        // safe precisely because nothing here is trusted as *authenticated* until `open_bytes`
        // below actually succeeds: a forged `sender_pub` at this stage can only cause a wrong map
        // lookup, never a state mutation, since nothing downstream commits before a successful
        // AEAD decrypt.
        let sender_pub = MessageEnvelope::from_blob(blob)?.sender_pub;

        // A sender with an undecided pending request is refused outright, before touching crypto
        // state at all: their first envelope already ran X3DH and installed the session (and the
        // OTK-consumption cost above), so there is nothing further to establish, and refusing here
        // means a still-gated sender cannot force extra ratchet-skipped-key churn by re-sending
        // while awaiting a decision. Never merges into the existing request (task 2.10 deliverable).
        if self.pending_requests.contains_key(&sender_pub) {
            return Err(ChatError::RequestPending);
        }

        // Snapshot *before* `open_bytes`, which — on a genuine first contact — installs the
        // responder session as a side effect. Capturing this first is what lets us tell "this
        // envelope is what just created the session" from "the session already existed". A caller
        // that already knows independently (2.14: `session.rs`) that this is first contact — even
        // though a session now sits in `self.sessions` from its own earlier handshake — forces the
        // gate to fire via `force_first_contact` regardless of that local presence check.
        let is_first_contact = force_first_contact || !self.sessions.contains_key(&sender_pub);

        let plaintext = self.open_bytes(store, handle, our_ik, from, blob, mailbox_drained)?;
        let content = ChatContent::decode(&plaintext)?;

        if is_first_contact {
            // system-design.md §3.5: land it in the segregated message-request state instead of
            // delivering it. `unwrap_or_default` only guards a same-call race that cannot actually
            // happen (the session was just installed by `open_bytes`, above, under this same `&mut
            // self` borrow) — never a silent downgrade of a real safety-number mismatch.
            let safety_number = self.safety_number(our_ik, &sender_pub).unwrap_or_default();
            // (task 3.10 / F5) Bound the intro's storage contribution before it ever lands in the
            // queue; `plaintext.len()` is the already-measured encoded size of `content`, so this
            // avoids a redundant re-encode purely to check it.
            let intro = cap_intro(content, plaintext.len());
            self.insert_pending_request(
                sender_pub,
                MessageRequest {
                    sender_ik: sender_pub,
                    safety_number,
                    intro,
                },
            );
            return Err(ChatError::MessageRequest);
        }

        Ok(content)
    }

    /// Decrypt an inbound blob to its raw ratchet plaintext, establishing a responder session on a
    /// prekey message. The generic counterpart of [`open_inbound`](Self::open_inbound), used by the
    /// substrate to open `SignalContent` on the same ratchet as chat.
    ///
    /// **(task 6.3, ADR 0016 C2/C3/C5) Rewritten for envelope v2: no signature, provisional X3DH,
    /// commit-on-successful-decrypt.** There is no longer a signature to verify before decryption —
    /// authentication is entirely the ratchet AEAD's job, under the canonical
    /// `"mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header` AAD (`AD` baked into the session's ratchet
    /// at construction; `prekey_preamble` is this method's own `preamble_aad_bytes(&envelope.prekey)`
    /// — the RECEIVED bytes, never recomputed — passed to `Session::decrypt` on every call below).
    /// Three checks still run unconditionally, before any crypto/session work, in this order:
    /// 1. `envelope.v == ENVELOPE_VERSION` — a hard, local, unilateral reject on any other value
    ///    (`ChatError::UnsupportedEnvelopeVersion`), never a negotiated fallback (C5/R5).
    /// 2. `envelope.sender_pub == from` (`ChatError::SenderMismatch`) — unchanged from v1.
    ///
    /// Everything downstream of those two — establishing a *new* responder session (first contact,
    /// or the task-4.9 stale-session fallback below) — is now **provisional**: this method builds
    /// the session and attempts to decrypt `envelope.ct` with it, but only *commits* (consumes the
    /// referenced one-time prekey, records the freshness entry, installs the session into
    /// `self.sessions`) once that decrypt has actually succeeded. A mutated/forged preamble on a
    /// prekey envelope therefore derives a session that fails to decrypt the (also-attacker-supplied
    /// or genuine, doesn't matter) ciphertext, and the provisional attempt is discarded without a
    /// trace — see [`establish_responder_session_provisional`](Self::establish_responder_session_provisional)
    /// and [`commit_responder_otk`](Self::commit_responder_otk), and this task's Outcome section
    /// (`docs/tasks/phase-6/6.3-envelope-v2-core-cutover.md`) for the full design note on how this
    /// interacts with the freshness gate below.
    ///
    /// **The task 4.9 discriminator fix (re-verified, not merely preserved, under the new
    /// provisional flow — see the Outcome section above).** Before task 4.9, a fresh responder
    /// session was only ever considered when `!self.sessions.contains_key(&envelope.sender_pub)` —
    /// i.e. only on a literal first-ever contact. That left a real bug: if the peer holds a
    /// **stale** session with the sender (the exact desync scenario task 1.18 describes — the
    /// identity key hasn't changed, only ratchet state diverged, e.g. the sender restored an old
    /// backup or wiped its session store and genuinely re-ran X3DH as initiator), `contains_key`
    /// reads `true`, the fresh-establishment branch is skipped entirely, and the incoming,
    /// legitimate re-initiation is handed to the *stale* session's `decrypt`, which fails and
    /// reclassifies as `Desync` again — permanently. That defeated task 1.18's own "safe half": the
    /// peer that knows it lost state re-initiates, but the counterpart could never actually accept
    /// it.
    ///
    /// The fix is **not** simply "key off `envelope.prekey.is_some()` instead of `contains_key`", as
    /// a literal reading of task 4.9's scope text might suggest — that alone is unsafe: an
    /// *unconfirmed* initiator (see [`meridian_crypto::Session::needs_prekey`]) re-attaches the exact
    /// same prekey preamble to **every** message until it receives a reply, so treating
    /// `prekey.is_some()` as sufficient on its own would re-run X3DH-as-responder (re-consuming an
    /// already-spent one-time prekey, and discarding the live ratchet's ongoing ratchet/skipped-key
    /// state) on every single one of those otherwise-ordinary continuation messages, not just on a
    /// genuine re-initiation. Instead: the *existing* session (if any) is always tried **first** —
    /// exactly as before this task — and the discriminator only applies as a fallback, and only for
    /// the one failure mode a genuine re-initiation actually produces:
    /// [`meridian_crypto::CryptoError::UndecryptableHeader`] (the header opens under neither of the
    /// existing session's header keys — see `DoubleRatchet::decrypt_header`). Only then, and only if
    /// the envelope actually carries a `prekey` preamble, is a **fresh, provisional** responder
    /// session attempted from that preamble and this same ciphertext re-tried against it:
    /// - If establishment fails (e.g. the referenced one-time prekey was already consumed — which is
    ///   exactly what happens for a replayed already-processed opening message, or for an ordinary
    ///   unconfirmed-initiator continuation message once its OTK has already been spent) or the fresh
    ///   session still fails to decrypt this ciphertext, **nothing is touched**: no OTK is consumed
    ///   (only *peeked*, never taken — see [`PrekeyVault::peek_otk_secret`]), the stale session is
    ///   left exactly as it was, and this still returns [`ChatError::Desync`] — preserving task
    ///   1.18's `undecryptable_envelope_is_rejected_without_touching_the_session` invariant
    ///   byte-for-byte for every case except a *successful* recovery.
    /// - Only a full, successful decrypt under the freshly-established session commits: the OTK is
    ///   consumed, the freshness entry recorded, and the stale session entry replaced — all three
    ///   atomically, right here, never split across a window where one has happened and not the
    ///   others.
    ///
    /// **A successful decrypt alone is not enough to gate this — it proves authenticity, not
    /// freshness.** A successful decrypt proves the claimed sender's real X3DH material produced
    /// these bytes *at some point*; it says nothing about whether this is the message they intend to
    /// send *now*. Because X3DH is deterministic in its public inputs, a malicious relay/rendezvous
    /// server that has merely observed one of the sender's own past opening envelopes can replay it
    /// byte-for-byte once the receiver's ratchet has genuinely advanced past it (a couple of ordinary
    /// round-trips is enough), reconstructing the byte-identical initial session and successfully
    /// decrypting the also-replayed ciphertext under it — deterministically, every time, for
    /// OTK-free X3DH (`used_opk: None`, which is legal and happens organically whenever a peer's
    /// one-time-prekey pool was empty). That would silently roll a live, forward-secret-advanced
    /// session back to its own initial state, through the ordinary `Ok` return path, with no gate
    /// and no notice — exactly the "weaker session" outcome `docs/security/threat-model.md` goal 6
    /// rules out. What actually closes this is the freshness check below:
    /// [`responder_session_ek`](Self::responder_session_ek) (this struct's own field; see its doc
    /// comment for the full reasoning, including a second-round fixup for a real gap the first
    /// version of this check itself had) records **every** `ek_pub` that established a responder
    /// session with this peer while its referenced SPK generation is still accepted — not just the
    /// single most recent one — and the fallback refuses outright, **before attempting any
    /// provisional establishment at all**, whenever the incoming prekey's `ek_pub` matches *any*
    /// recorded entry — a byte-identical `ek_pub` is exactly what a replay of that same opening
    /// material looks like, whereas a genuine re-initiator always draws a fresh random ephemeral key
    /// per [`meridian_crypto::Session::initiate`] call, including the "no recorded entry" case that
    /// field's doc comment reasons through.
    ///
    /// **Ordering: freshness gate strictly precedes provisional establishment; the two cannot
    /// conflict.** The freshness gate is evaluated purely from `envelope.prekey.ek_pub` and
    /// `self.responder_session_ek` — it needs no session, no decrypt attempt, and is checked first.
    /// Only once it has passed does `establish_responder_session_provisional` even run, and only a
    /// successful decrypt from *that* provisional session ever commits. There is no scenario where
    /// either check could succeed while the other would refuse: freshness is a *precondition* for
    /// attempting provisional establishment at all, not a competing or racing gate.
    ///
    /// **(task 6.4, ADR 0016 C7 second half) The `eid` dedup check runs before ALL of the above.**
    /// Immediately after the `v`/`sender_pub` checks — strictly before the freshness gate, before
    /// `self.sessions.contains_key`, before any provisional establishment or decrypt attempt of any
    /// kind — `envelope.eid` is checked against [`seen_eids`](Self::seen_eids); a match short-circuits
    /// with [`ChatError::DuplicateEnvelope`] and nothing below this point ever runs. This is a
    /// **layer added on top of**, never a replacement for, the freshness gate and the ratchet AEAD:
    /// `eid` is unauthenticated outer plaintext an attacker can freely vary, so a forged/replayed
    /// envelope that changes only its `eid` reaches every check below completely unaffected by this
    /// one — see [`ChatError::DuplicateEnvelope`]'s doc comment for the precise, narrow claim this
    /// check makes (a redelivery convenience, never a security boundary; ADR 0016 R2) and this task's
    /// Outcome section for the full design note.
    ///
    /// **(task 8.8, ADR 0024) `from` is not checked against `envelope.sender_pub` when
    /// `mailbox_drained` is true.** A mailbox-drained [`Deliver`](meridian_proto::Deliver) carries
    /// a fixed `[0u8; 32]` placeholder as `from` (`meridian_proto::MAILBOX_DRAIN_FROM_PLACEHOLDER`)
    /// — never a real, persisted sender identity, per the server-side invariant ADR 0024 records
    /// (never materialize a server-side contact graph). The server cannot honestly assert a routing
    /// origin for a message it isn't relaying live, so this check — a defense-in-depth comparison
    /// against a routing-layer claim, never the actual trust boundary — has nothing meaningful to
    /// compare against on that path; authentication rests entirely on `envelope.sender_pub` plus
    /// the ratchet AEAD succeeding, exactly as it always has for every other path. Every **live** or
    /// federated-live call (`mailbox_drained: false`, from `session.rs`'s P2P substrate and
    /// `open_inbound`'s ordinary relay path) keeps today's exact check, unchanged.
    pub fn open_bytes(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        from: &[u8; 32],
        blob: &[u8],
        mailbox_drained: bool,
    ) -> Result<Vec<u8>, ChatError> {
        let envelope = MessageEnvelope::from_blob(blob)?;
        if envelope.v != ENVELOPE_VERSION {
            // (ADR 0016 C5/R5) Hard, local, unilateral reject — see this method's doc comment and
            // `ChatError::UnsupportedEnvelopeVersion`'s own doc. Never a negotiated fallback.
            return Err(ChatError::UnsupportedEnvelopeVersion(envelope.v));
        }
        if !mailbox_drained && &envelope.sender_pub != from {
            return Err(ChatError::SenderMismatch);
        }
        // (task 6.4, ADR 0016 C7 second half) The eid dedup check — runs before ANY session lookup,
        // provisional establishment, or decrypt attempt, so a genuinely redelivered envelope costs
        // no crypto work the second time. See `ChatError::DuplicateEnvelope`'s doc comment for the
        // precise (deliberately narrow) claim this makes, and `seen_eids`'s doc comment for why this
        // ordering is safe (an `eid` is recorded only on a *successful* decrypt, never speculatively
        // — an attacker cannot pre-poison a future legitimate `eid`).
        if self.is_seen_eid(&envelope.eid) {
            return Err(ChatError::DuplicateEnvelope);
        }
        let preamble = preamble_aad_bytes(&envelope.prekey);

        // No session at all: the "safe half" (task 1.18) — a peer with no session must always
        // attempt a fresh prekey envelope, replay or not, because there is nothing yet to roll
        // back. **Now provisional (task 6.3, ADR 0016 C2):** establishment and decrypt are
        // attempted before anything commits; only a successful decrypt consumes the OTK, records
        // the freshness entry, and installs the session.
        if !self.sessions.contains_key(&envelope.sender_pub) {
            let prekey = envelope.prekey.clone().ok_or(ChatError::NoSession)?;
            let mut provisional = self.establish_responder_session_provisional(
                store,
                handle,
                our_ik,
                &envelope.sender_pub,
                &prekey,
            )?;
            // Classification choice (task 6.3, deliberate — not carried over from v1): a failed
            // decrypt on this branch propagates as `ChatError::Crypto` via `?`, never `Desync`.
            // `Desync`'s own doc frames it as being about an *existing* session's two live header
            // keys (see `ChatError::Desync`'s doc) — that concept doesn't describe a first-contact
            // attempt, which has no prior session to have desynced from. `note_desync` is
            // therefore not called here, so a burst of bogus first-contact envelopes cannot drive
            // the recovery-recommended threshold; only a genuinely *existing* session repeatedly
            // failing to decrypt (the fallback branch below) can.
            let pt = provisional.decrypt(&envelope.ct, &preamble)?;
            // Reached only on a successful decrypt: commit, atomically, right here.
            self.commit_responder_otk(&prekey);
            self.record_responder_ek(envelope.sender_pub, prekey.ek_pub, prekey.used_spk);
            self.sessions.insert(envelope.sender_pub, provisional);
            self.reset_desync(&envelope.sender_pub);
            self.record_seen_eid(envelope.eid);
            return Ok(pt);
        }

        let session = self
            .sessions
            .get_mut(&envelope.sender_pub)
            .ok_or(ChatError::NoSession)?;
        match session.decrypt(&envelope.ct, &preamble) {
            Ok(pt) => {
                self.reset_desync(&envelope.sender_pub);
                self.record_seen_eid(envelope.eid);
                Ok(pt)
            }
            Err(meridian_crypto::CryptoError::UndecryptableHeader) => {
                // (task 4.9, re-verified under the v2 provisional flow by task 6.3) See this
                // method's doc comment above for the full reasoning, and `responder_session_ek`'s
                // own doc for why this freshness check exists at all and why it checks a *history*,
                // not a single value. Only a prekey-carrying envelope is even considered, and only a
                // genuinely successful fresh establishment + decrypt commits — any failure along the
                // way falls through to the untouched-state `Desync` return below, unchanged from
                // task 1.18's original behavior, and now with no OTK consumed either (task 6.3).
                //
                // **The freshness gate — runs BEFORE any provisional establishment is attempted.**
                // Check the incoming prekey's `ek_pub` against *every* `ek_pub` recorded as having
                // established a still-SPK-valid responder session with this peer (if any — see
                // `responder_session_ek`'s doc for the "no recorded entry" case). A match against
                // any of them means this is a replay of material that established a session we
                // (still-validly) hold or once held: refuse the fallback outright, exactly as if no
                // fallback existed at all — never even attempt a provisional establishment — rather
                // than let a decrypt-successful but stale replay roll the session back to that
                // earlier state. A successful decrypt proves authenticity only, never freshness —
                // X3DH is deterministic in its public inputs, so replaying the same opening envelope
                // reconstructs the same initial ratchet state deterministically (always for OTK-free
                // X3DH, since the SPK is never consumed on use) and would otherwise decrypt this
                // same, also-replayed ciphertext successfully every time.
                let is_replay_of_current_session = envelope.prekey.as_ref().is_some_and(|prekey| {
                    self.is_recorded_responder_ek(&envelope.sender_pub, &prekey.ek_pub)
                });
                if !is_replay_of_current_session {
                    if let Some(prekey) = envelope.prekey.clone() {
                        if let Ok(mut fresh) = self.establish_responder_session_provisional(
                            store,
                            handle,
                            our_ik,
                            &envelope.sender_pub,
                            &prekey,
                        ) {
                            if let Ok(pt) = fresh.decrypt(&envelope.ct, &preamble) {
                                // Commit, atomically, only now.
                                self.commit_responder_otk(&prekey);
                                self.record_responder_ek(
                                    envelope.sender_pub,
                                    prekey.ek_pub,
                                    prekey.used_spk,
                                );
                                self.sessions.insert(envelope.sender_pub, fresh);
                                self.reset_desync(&envelope.sender_pub);
                                self.record_seen_eid(envelope.eid);
                                return Ok(pt);
                            }
                        }
                    }
                }
                // Classify an undecryptable header as `Desync` so callers can *report* it
                // distinguishably from malformed/tampered input (task 1.18), and record it for task
                // 4.9's repeated-Desync recovery signal. This changes no rejection decision here: the
                // envelope is dropped either way and `self.sessions` (and the vault's OTK pool) are
                // left untouched — see `ChatError::Desync`'s doc comment for the full guard this
                // counter feeds.
                self.note_desync(envelope.sender_pub);
                Err(ChatError::Desync)
            }
            Err(other) => Err(ChatError::Crypto(other)),
        }
    }

    /// (task 10.4) Ratchet-encrypt an outbound generic-stream-frame plaintext for `peer_ik`,
    /// returning the ciphertext frame alongside task 10.1's caller-scoped `HKDF(mk, info)` export —
    /// the P2P session substrate's generic outbound path for any non-chat/non-ctrl registered
    /// stream type (`P2pSession::send_stream_frame`).
    ///
    /// **Deliberately not a [`MessageEnvelope`] wrapper**, unlike [`seal_bytes`](Self::seal_bytes):
    /// a stream frame carries no `eid`/prekey material of its own to begin with — a stream can only
    /// be opened over `mrd.ctrl/1` (`CtrlFrame::Open`/`Accept`) once that channel's own handshake
    /// has already exchanged and confirmed at least one full round trip, so by the time any stream
    /// frame is ever sent, [`Session::needs_prekey`] is always `false` on both sides. The `eid`
    /// dedup / prekey-reattachment machinery `MessageEnvelope` exists for therefore has nothing to
    /// do here — the double ratchet's own single-use message keys already give each frame the same
    /// anti-replay property a byte-identical duplicate would need. `info` is caller-opaque (see
    /// [`Session::encrypt_and_export`]'s doc); `session.rs` derives it from the stream's type/sid.
    pub(crate) fn seal_stream_frame(
        &mut self,
        peer_ik: &[u8; 32],
        plaintext: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), ChatError> {
        let session = self.sessions.get_mut(peer_ik).ok_or(ChatError::NoSession)?;
        Ok(session.encrypt_and_export(plaintext, info)?)
    }

    /// The receive-side half of [`seal_stream_frame`](Self::seal_stream_frame): ratchet-decrypt an
    /// inbound generic-stream-frame blob from `peer_ik`, returning the plaintext alongside the same
    /// caller-scoped export. `info` MUST be the identical bytes the sender used to encrypt (the
    /// stream's type/sid) — this is symmetric, unlike the chat/ctrl AAD preamble, since a stream
    /// frame carries no prekey material for the two sides to ever disagree about. The session must
    /// already exist (see [`seal_stream_frame`](Self::seal_stream_frame)'s doc for why a stream
    /// frame is only ever sent post-confirmation): this never performs X3DH/responder establishment
    /// the way [`open_bytes`](Self::open_bytes) does for a first-contact envelope.
    pub(crate) fn open_stream_frame(
        &mut self,
        peer_ik: &[u8; 32],
        blob: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), ChatError> {
        let session = self.sessions.get_mut(peer_ik).ok_or(ChatError::NoSession)?;
        let preamble = preamble_aad_bytes(&None);
        Ok(session.decrypt_and_export(blob, &preamble, info)?)
    }

    /// Shared X3DH-responder establishment, used both by [`open_bytes`](Self::open_bytes)'s
    /// first-contact branch and by its task-4.9 fallback recovery attempt.
    ///
    /// **(task 6.3, ADR 0016 C2) Provisional and non-destructive.** Looks up the referenced signed
    /// prekey and (if any) one-time prekey secrets via [`PrekeyVault::peek_spk_secret`]/
    /// [`PrekeyVault::peek_otk_secret`] — **never** the destructive
    /// [`PrekeyVault::take_otk_secret`] — and does **not** insert the resulting [`Session`] into
    /// `self.sessions`. Every caller must attempt a decrypt against the returned session and call
    /// [`commit_responder_otk`](Self::commit_responder_otk) (and `record_responder_ek`/
    /// `sessions.insert`) **only after that decrypt has actually succeeded**; a caller that commits
    /// on anything less reintroduces the exact R3 vulnerability C2 exists to close (a mutated
    /// preamble burning a one-time prekey and installing a poisoned session before the AEAD ever
    /// gets a say). See [`open_bytes`](Self::open_bytes)'s own doc comment for the full
    /// provisional/commit control flow and this task's Outcome section for the design note.
    fn establish_responder_session_provisional(
        &self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        our_ik: &[u8; 32],
        peer_ik: &[u8; 32],
        prekey: &Prekey,
    ) -> Result<Session, ChatError> {
        let material = PrekeyMaterial {
            ek_pub: prekey.ek_pub,
            used_spk: prekey.used_spk,
            used_opk: prekey.used_opk,
        };
        let spk_secret: Zeroizing<[u8; 32]> = Zeroizing::new(
            self.vault
                .peek_spk_secret(&prekey.used_spk)
                .ok_or(ChatError::UnknownPrekey)?,
        );
        let opk_secret: Option<Zeroizing<[u8; 32]>> = match prekey.used_opk {
            Some(opk) => Some(Zeroizing::new(
                self.vault
                    .peek_otk_secret(&opk)
                    .ok_or(ChatError::UnknownPrekey)?,
            )),
            None => None,
        };
        Ok(Session::respond(
            store,
            handle,
            our_ik,
            peer_ik,
            &material,
            &spk_secret,
            // `Session::respond` needs an owned `Option<[u8; 32]>`; copy the bytes out of the
            // `Zeroizing` wrapper (itself still zeroized on drop at the end of this scope) rather
            // than unwrapping it, so the wrapper keeps clearing its own stack copy.
            opk_secret.as_ref().map(|z| **z),
        )?)
    }

    /// The commit half of provisional responder establishment (task 6.3, ADR 0016 C2): actually
    /// consumes `prekey`'s one-time prekey (if any), via the destructive
    /// [`PrekeyVault::take_otk_secret`]. Callers MUST only reach this after a provisional session
    /// built from the same `prekey` (via
    /// [`establish_responder_session_provisional`](Self::establish_responder_session_provisional))
    /// has **already successfully decrypted** the envelope in question — see
    /// [`open_bytes`](Self::open_bytes), the only caller. A no-op (not an error) if the OTK is
    /// somehow already gone by the time this runs: within one `open_bytes` call there is no
    /// concurrent mutation of `self.vault` between the provisional peek and this commit (both run
    /// under the same `&mut self` borrow, single-threaded), so this can only be reached with the
    /// OTK still present in ordinary operation — this is defense-in-depth, not a path this code
    /// expects to exercise.
    fn commit_responder_otk(&mut self, prekey: &Prekey) {
        if let Some(opk) = prekey.used_opk {
            if let Some(mut secret) = self.vault.take_otk_secret(&opk) {
                secret.zeroize();
            }
        }
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
        // (task 4.9, third-round review fixup) Same reasoning, for `responder_session_ek_order`
        // against `responder_session_ek` — see `reconcile_responder_session_ek_order`'s doc.
        state.reconcile_responder_session_ek_order();
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

#[cfg(test)]
mod tests {
    //! Crate-private unit tests that need direct access to `pending_requests`/`request_order`
    //! (task 3.10 review fixup): the integration tests in `apps/core/tests/` can only drive
    //! `ChatState` through its public API, which never leaves `request_order` empty while
    //! `pending_requests` is populated — so they can exercise `reconcile_request_order`'s
    //! "nothing to repair" path (via the at-rest round trip of a pre-task `ChatState::default()`,
    //! see `message_request_gate.rs`'s `a_chat_state_sealed_before_this_task_still_opens`) but
    //! never its actual repair loop. This module fills that gap.
    use super::*;
    use meridian_identity::{generate_account, MemorySecretStore};

    fn intro(tag: u8) -> MessageRequest {
        MessageRequest {
            sender_ik: [tag; 32],
            safety_number: format!("test-safety-number-{tag}"),
            intro: ChatContent::Text {
                id: [tag; 16],
                body: format!("hi, this is sender {tag}"),
            },
        }
    }

    /// Simulates the exact desynced state `reconcile_request_order` exists to repair — a
    /// `pending_requests` populated directly (bypassing `insert_pending_request`, as a legacy
    /// pre-task-3.10 blob's `#[serde(default)]`-emptied `request_order` would be) — and asserts
    /// the repair loop actually runs: every pending key ends up in `request_order`, in the
    /// documented deterministic ascending-key fallback order, and a subsequent
    /// `evict_oldest_pending` picks the lowest key and drops its session with it.
    #[test]
    fn reconcile_request_order_repairs_desynced_legacy_state() {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, "chat.reconcile.self").unwrap();
        let our_ik = *account.public_key().as_bytes();

        let mut state = ChatState::default();

        // Three distinct sender identity keys, populated straight into `pending_requests` — never
        // through `insert_pending_request`, so `request_order` stays empty exactly as it would
        // for a blob sealed before this task.
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for i in 0..3u8 {
            let sender = generate_account(&store, &format!("chat.reconcile.sender.{i}")).unwrap();
            let sender_ik = *sender.public_key().as_bytes();
            state.pending_requests.insert(sender_ik, intro(i));
            // A live session per pending request, matching the real invariant (a `MessageRequest`
            // never exists without one) — so eviction dropping it is actually observable below.
            state
                .start_initiator_session(
                    &store,
                    account.handle(),
                    &our_ik,
                    &sender_ik,
                    &[7u8; 32],
                    None,
                )
                .unwrap();
            keys.push(sender_ik);
        }
        assert!(
            state.request_order.is_empty(),
            "sanity: this must reproduce the desynced/legacy shape reconcile_request_order repairs"
        );

        state.reconcile_request_order();

        let mut expected_order = keys.clone();
        expected_order.sort();
        assert_eq!(
            state.request_order, expected_order,
            "repaired order must be pending_requests's own ascending-key order, per the \
             documented deterministic fallback"
        );

        // Eviction must now pick the lowest-key entry and drop its session with it.
        let lowest = expected_order[0];
        state.evict_oldest_pending();
        assert!(
            state.pending_request(&lowest).is_none(),
            "evict_oldest_pending must remove the lowest-key (repaired-order-first) entry"
        );
        assert!(
            !state.has_session(&lowest),
            "the evicted entry's session must be dropped with it"
        );
        for k in &expected_order[1..] {
            assert!(
                state.pending_request(k).is_some(),
                "eviction must not touch entries other than the oldest"
            );
            assert!(state.has_session(k));
        }
        assert_eq!(&state.request_order, &expected_order[1..]);
    }

    /// Direct, crypto-free unit test of the `responder_session_ek` history/pruning machinery itself
    /// (task 4.9, second-round review fixup): the freshness gate in `open_bytes` and the exploit in
    /// `apps/core/tests/desync_recovery.rs` exercise this end-to-end through real X3DH, but this cell
    /// isolates the bookkeeping so `record_responder_ek`/`is_recorded_responder_ek`/
    /// `prune_responder_session_ek` are checked precisely, independent of ratchet state.
    #[test]
    fn responder_session_ek_history_tracks_multiple_entries_and_prunes_on_generation_expiry() {
        let mut state = ChatState::default();
        let peer = [0xAAu8; 32];

        let gen1_spk_pub = [1u8; 32];
        let gen1_spk_secret = [2u8; 32];
        let gen2_spk_pub = [3u8; 32];
        let gen2_spk_secret = [4u8; 32];
        let ek_pub_1 = [5u8; 32];
        let ek_pub_2 = [6u8; 32];

        state
            .vault
            .set_bundle(gen1_spk_pub, gen1_spk_secret, Vec::new(), 1_000);
        state.record_responder_ek(peer, ek_pub_1, gen1_spk_pub);
        assert!(state.is_recorded_responder_ek(&peer, &ek_pub_1));

        // Republish rotates generation 1 into the bounded "previous" slot (task 1.31) rather than
        // dropping it immediately.
        state
            .vault
            .set_bundle(gen2_spk_pub, gen2_spk_secret, Vec::new(), 1_001);
        state.record_responder_ek(peer, ek_pub_2, gen2_spk_pub);

        // Both entries are tracked: generation 1 is retained (grace window), generation 2 is
        // current — the core property the first (scalar) fix got wrong.
        assert!(state.is_recorded_responder_ek(&peer, &ek_pub_1));
        assert!(state.is_recorded_responder_ek(&peer, &ek_pub_2));

        // Pruning before the grace window fully passes changes nothing.
        state.expire_previous_generation(1_001 + PREV_GENERATION_GRACE_SECS - 1);
        assert!(state.is_recorded_responder_ek(&peer, &ek_pub_1));
        assert!(state.is_recorded_responder_ek(&peer, &ek_pub_2));

        // Once generation 1's grace window genuinely passes, its entry is pruned; generation 2's
        // entry — still current — survives.
        state.expire_previous_generation(1_001 + PREV_GENERATION_GRACE_SECS);
        assert!(
            !state.is_recorded_responder_ek(&peer, &ek_pub_1),
            "an entry referencing a genuinely expired SPK generation must be pruned"
        );
        assert!(
            state.is_recorded_responder_ek(&peer, &ek_pub_2),
            "an entry referencing the still-current generation must survive pruning"
        );

        // Pruning a peer down to zero remaining entries removes the peer's own map entry too,
        // rather than leaving an empty `Vec` behind forever.
        assert!(state.responder_session_ek.contains_key(&peer));
        state.record_responder_ek(peer, ek_pub_2, gen2_spk_pub); // no-op: already recorded
        assert_eq!(state.responder_session_ek.get(&peer).unwrap().len(), 1);
    }

    /// Third-round review fixup, test (a): many distinct never-before-seen identities each
    /// contributing exactly one responder establishment (the OTK-free-X3DH-first-contact shape
    /// [`MAX_RESPONDER_SESSION_EK_PEERS`]'s doc reasons through — free for an attacker to repeat
    /// with a fresh identity key each time) must not grow `responder_session_ek` without bound.
    /// Drives well past the cap and confirms the oldest-first-seen peers are evicted while the
    /// most recent survivors within the cap remain.
    #[test]
    fn responder_session_ek_peer_count_is_capped_with_oldest_first_eviction() {
        let mut state = ChatState::default();
        let spk_pub = [9u8; 32];
        let spk_secret = [10u8; 32];
        state
            .vault
            .set_bundle(spk_pub, spk_secret, Vec::new(), 1_000);

        let total = MAX_RESPONDER_SESSION_EK_PEERS + 10;
        let mut peers: Vec<[u8; 32]> = Vec::with_capacity(total);
        for i in 0..total {
            let mut peer = [0u8; 32];
            peer[0..2].copy_from_slice(&(i as u16).to_be_bytes());
            state.record_responder_ek(peer, peer, spk_pub);
            peers.push(peer);
        }

        assert_eq!(
            state.responder_session_ek.len(),
            MAX_RESPONDER_SESSION_EK_PEERS,
            "the outer map must never exceed MAX_RESPONDER_SESSION_EK_PEERS distinct peers, no \
             matter how many distinct identities have each been seen exactly once"
        );
        assert_eq!(
            state.responder_session_ek_order.len(),
            MAX_RESPONDER_SESSION_EK_PEERS,
            "the order-tracking vector must stay in lockstep with the map it orders"
        );

        for evicted in &peers[..10] {
            assert!(
                !state.responder_session_ek.contains_key(evicted),
                "an early-seen peer must have been evicted once the cap was exceeded"
            );
        }
        for survivor in &peers[10..] {
            assert!(
                state.responder_session_ek.contains_key(survivor),
                "the most-recently-seen peers, within the cap, must survive"
            );
        }
    }

    /// Third-round review fixup, test (b): rejecting (or evicting) a pending request's sender must
    /// also remove that peer's `responder_session_ek` entry — not just their `Session` — so a
    /// rejected or evicted contact leaves no trace here either.
    #[test]
    fn reject_and_evict_also_forget_responder_session_ek() {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, "chat.forget.self").unwrap();
        let our_ik = *account.public_key().as_bytes();

        let mut state = ChatState::default();
        let spk_pub = [11u8; 32];
        let spk_secret = [12u8; 32];
        state
            .vault
            .set_bundle(spk_pub, spk_secret, Vec::new(), 1_000);

        // Sender A: gated request + responder-establishment freshness record, then explicitly
        // rejected.
        let sender_a = generate_account(&store, "chat.forget.a").unwrap();
        let a_ik = *sender_a.public_key().as_bytes();
        state.pending_requests.insert(a_ik, intro(1));
        state.request_order.push(a_ik);
        state
            .start_initiator_session(&store, account.handle(), &our_ik, &a_ik, &[7u8; 32], None)
            .unwrap();
        state.record_responder_ek(a_ik, [21u8; 32], spk_pub);
        assert!(state.responder_session_ek.contains_key(&a_ik));

        assert!(state.reject_request(&a_ik));
        assert!(
            !state.responder_session_ek.contains_key(&a_ik),
            "reject_request must also forget the rejected sender's responder_session_ek entry"
        );
        assert!(!state.responder_session_ek_order.contains(&a_ik));

        // Sender B: same shape, but forced out through space-eviction instead of an explicit
        // reject.
        let sender_b = generate_account(&store, "chat.forget.b").unwrap();
        let b_ik = *sender_b.public_key().as_bytes();
        state.pending_requests.insert(b_ik, intro(2));
        state.request_order.push(b_ik);
        state
            .start_initiator_session(&store, account.handle(), &our_ik, &b_ik, &[7u8; 32], None)
            .unwrap();
        state.record_responder_ek(b_ik, [22u8; 32], spk_pub);
        assert!(state.responder_session_ek.contains_key(&b_ik));

        state.evict_oldest_pending();
        assert!(state.pending_request(&b_ik).is_none());
        assert!(!state.has_session(&b_ik));
        assert!(
            !state.responder_session_ek.contains_key(&b_ik),
            "evict_oldest_pending must also forget the evicted sender's responder_session_ek entry"
        );
        assert!(!state.responder_session_ek_order.contains(&b_ik));
    }

    // -- task 6.1: SPK rotation age tracking --------------------------------------------------

    /// `rotation_due` must be `false` immediately after a publish — age zero is never overdue,
    /// regardless of how small `SPK_ROTATION_INTERVAL_SECS` might be configured.
    #[test]
    fn rotation_due_is_false_immediately_after_publish() {
        let mut vault = PrekeyVault::default();
        vault.set_bundle([1u8; 32], [2u8; 32], Vec::new(), 1_000);
        assert_eq!(vault.generation_age_secs(1_000), Some(0));
        assert!(!vault.rotation_due(1_000));
    }

    /// `rotation_due` flips to `true` exactly once the elapsed age reaches
    /// `SPK_ROTATION_INTERVAL_SECS` — false the instant before the threshold, true at and past it.
    #[test]
    fn rotation_due_becomes_true_once_the_interval_elapses() {
        let mut vault = PrekeyVault::default();
        vault.set_bundle([1u8; 32], [2u8; 32], Vec::new(), 1_000);

        let just_before = 1_000 + SPK_ROTATION_INTERVAL_SECS - 1;
        assert_eq!(
            vault.generation_age_secs(just_before),
            Some(SPK_ROTATION_INTERVAL_SECS - 1)
        );
        assert!(!vault.rotation_due(just_before));

        let at_threshold = 1_000 + SPK_ROTATION_INTERVAL_SECS;
        assert_eq!(
            vault.generation_age_secs(at_threshold),
            Some(SPK_ROTATION_INTERVAL_SECS)
        );
        assert!(vault.rotation_due(at_threshold));

        let well_past = at_threshold + 1_000;
        assert!(vault.rotation_due(well_past));
    }

    /// The chosen unknown-age default (task 6.1 Outcome / this task file's Risks section):
    /// `spk_published_at: None` — never published, or a vault deserialized from a state sealed
    /// before this task — is treated as due-now (fail-safe), not as not-due. Asserted directly
    /// rather than left to fall out incidentally of some other test.
    #[test]
    fn rotation_due_treats_unknown_age_as_due_now() {
        let vault = PrekeyVault::default();
        assert_eq!(
            vault.generation_age_secs(1_000),
            None,
            "a vault that has never published a bundle has no known age"
        );
        assert!(
            vault.rotation_due(1_000),
            "unknown age must be treated as due-now (fail-safe), per task 6.1's documented choice"
        );
    }

    /// A `PrekeyVault` (and, nested inside it, a whole `ChatState`) serialized without the new
    /// `spk_published_at` field at all — simulating a state sealed by pre-6.1 code, not merely a
    /// freshly-defaulted current-code vault — must still deserialize, defaulting the field to
    /// `None` rather than panicking. Constructed by stripping the field's CBOR map entry out of a
    /// current encoding, the same technique `apps/core/tests/desync_recovery.rs`'s
    /// `state_bytes_excluding_desync_counts` uses for exactly this kind of pre-field-existing
    /// legacy-shape simulation.
    #[test]
    fn a_vault_serialized_without_spk_published_at_still_deserializes() {
        use ciborium::value::Value;

        let mut vault = PrekeyVault::default();
        vault.set_bundle([1u8; 32], [2u8; 32], Vec::new(), 1_000);

        let mut encoded = Vec::new();
        ciborium::into_writer(&vault, &mut encoded).unwrap();
        let mut value: Value = ciborium::from_reader(&encoded[..]).unwrap();
        if let Value::Map(entries) = &mut value {
            entries.retain(|(k, _)| !matches!(k, Value::Text(t) if t == "spk_published_at"));
        } else {
            panic!("PrekeyVault must encode as a CBOR map");
        }
        let mut legacy_shaped = Vec::new();
        ciborium::into_writer(&value, &mut legacy_shaped).unwrap();

        let reopened: PrekeyVault = ciborium::from_reader(&legacy_shaped[..])
            .expect("a PrekeyVault with no spk_published_at field must still deserialize");
        assert_eq!(reopened.spk_published_at, None);
        assert!(reopened.rotation_due(1_000));

        // Same shape, but nested inside a whole `ChatState` under `vault`, mirroring how this
        // field is actually reached at rest via `seal_at_rest`/`open_at_rest`.
        let state = ChatState {
            vault,
            ..ChatState::default()
        };
        let mut state_encoded = Vec::new();
        ciborium::into_writer(&state, &mut state_encoded).unwrap();
        let mut state_value: Value = ciborium::from_reader(&state_encoded[..]).unwrap();
        if let Value::Map(entries) = &mut state_value {
            for (k, v) in entries.iter_mut() {
                if matches!(k, Value::Text(t) if t == "vault") {
                    if let Value::Map(vault_entries) = v {
                        vault_entries.retain(
                            |(k, _)| !matches!(k, Value::Text(t) if t == "spk_published_at"),
                        );
                    }
                }
            }
        } else {
            panic!("ChatState must encode as a CBOR map");
        }
        let mut state_legacy_shaped = Vec::new();
        ciborium::into_writer(&state_value, &mut state_legacy_shaped).unwrap();

        let reopened_state: ChatState = ciborium::from_reader(&state_legacy_shaped[..]).expect(
            "a ChatState whose nested vault has no spk_published_at must still deserialize",
        );
        assert_eq!(reopened_state.vault.spk_published_at, None);
    }
}
