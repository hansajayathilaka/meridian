//! The E2E **message envelope**, v2 (ADR 0016; C2/C3/C5). Serialized, this is exactly the bytes
//! carried in a routing [`OpaqueBlob`]: the server relays it verbatim and never decodes it. Full
//! spec: `docs/api/messaging-envelope-v1.md` (v1; v2's wire-doc update is task 6.7).
//!
//! ADR 0016 drops the per-message Ed25519 identity-key signature v1 carried: authentication now
//! comes entirely from the ratchet AEAD, under the canonical v2 AAD
//! `"mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header` (C3) — `AD = IK_initiator ‖ IK_responder`,
//! baked into [`meridian_crypto::DoubleRatchet`]'s fixed `ad` field at session construction, never
//! recomputed here. This crate only owns the wire shape and the preamble encoding; the AAD
//! construction itself lives in `meridian-crypto` (which cannot depend on this crate — see this
//! crate's own module doc, F15 — so `apps/crypto/src/session.rs` keeps a byte-identical, hand-kept
//! copy of [`preamble_aad_bytes`]'s encoding over its own local `PrekeyMaterial` type).
//!
//! An envelope carries:
//! - `v` — mandatory, always [`ENVELOPE_VERSION`] (2). **Not** a negotiated value: a mismatch is a
//!   local, unilateral hard decode/reject, never a round-trip or a downgrade (ADR 0016 C5/R5 — see
//!   `docs/tasks/phase-6/6.3-envelope-v2-core-cutover.md`'s explicit negative constraint). This is
//!   why the field is a plain mandatory `u16`, never `Option`/defaulted: strict CBOR struct
//!   decoding then rejects any other value (or its absence) for free.
//! - `sender_pub` — the sender's Ed25519 account key. No longer signed over (there is no signature)
//!   — it is authenticated instead by feeding the ratchet's X3DH-derived `AD`, which fails closed
//!   on a substituted key (C3's raw-Ed25519, never-normalized requirement is what keeps a
//!   sign-flipped key from colliding here; see `apps/crypto/src/x3dh.rs`).
//! - `eid` (task 6.4, ADR 0016 C7 second half) — a sender-random 128-bit envelope dedup key,
//!   minted once per `ChatState::seal_bytes` call (`apps/core/src/chat.rs`) and carried **outer
//!   plaintext**, deliberately outside the C3 canonical AAD (it is a redelivery/duplicate-processing
//!   convenience, not a security boundary — see that method's own doc comment and this task's
//!   Outcome section for the full design note; it is fed into no AAD, and
//!   `apps/crypto/src/ratchet.rs`'s AAD construction is untouched by it). It sits alongside
//!   `v`/`sender_pub`/`prekey` for exactly that reason: it is never part of the ratchet-encrypted
//!   `ct`, only of the envelope's own outer, unauthenticated-by-the-AEAD framing — anyone with the
//!   bytes can already see (and forge) it, same as `sender_pub`/`prekey` before this field existed.
//! - `prekey` — present only on the opening message(s) of a session: the X3DH preamble the
//!   responder needs to complete the handshake. Bound into the AAD via [`preamble_aad_bytes`], and
//!   — per C2 — the responder's X3DH runs *provisionally* against it until decrypt actually
//!   succeeds, so a mutated preamble can never burn a one-time prekey or install a poisoned session
//!   (`apps/core/src/chat.rs`'s `open_bytes`/`establish_responder_session_provisional`).
//! - `ct` — the header-encrypted Double Ratchet message (opaque; counters/keys hidden).

use serde::{Deserialize, Serialize};

use meridian_proto::{decode, encode, CodecError};

/// Domain-separation tag baked into every v2 ratchet message's AAD (ADR 0016 C3). A change is a
/// wire break. MUST match `meridian_crypto::ratchet`'s own copy of this constant exactly —
/// `meridian-crypto` cannot depend on this crate in production code (F15/this crate's module doc),
/// so the two are kept in lockstep by hand and pinned together by the v2 conformance vectors (task
/// 6.5).
pub const ENVELOPE_DOMAIN: &[u8] = b"mrd.env/2";

/// The mandatory, non-negotiated envelope version (ADR 0016 C5). See [`MessageEnvelope::v`]'s field
/// doc and the module doc's flag-day note — never compare this against anything but exact equality,
/// and never branch to a different decode/verify path on a mismatch.
pub const ENVELOPE_VERSION: u16 = 2;

/// The X3DH preamble attached to a session's opening message(s): the initiator's ephemeral public
/// key and which of the responder's prekeys were consumed (so it can find the matching secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prekey {
    #[serde(with = "meridian_proto::bytes::b32")]
    pub ek_pub: [u8; 32],
    #[serde(with = "meridian_proto::bytes::b32")]
    pub used_spk: [u8; 32],
    #[serde(with = "meridian_proto::bytes::opt_b32")]
    pub used_opk: Option<[u8; 32]>,
}

/// A ratchet-encrypted message envelope, v2. Opaque to the server; authenticated+decrypted only by
/// the recipient endpoint's ratchet AEAD (no envelope-level signature — see the module doc).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Mandatory leading version tag, always [`ENVELOPE_VERSION`]. See the module doc: this is a
    /// sender-declared value, never negotiated, and a mismatch is always a hard local reject.
    pub v: u16,
    #[serde(with = "meridian_proto::bytes::b32")]
    pub sender_pub: [u8; 32],
    /// (task 6.4, ADR 0016 C7 second half) Sender-random 128-bit dedup key — see the module doc's
    /// `eid` entry. Mandatory (never `Option`/defaulted): every v2 envelope carries one, minted
    /// fresh by `ChatState::seal_bytes` on every call.
    #[serde(with = "meridian_proto::bytes::b16")]
    pub eid: [u8; 16],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prekey: Option<Prekey>,
    #[serde(with = "meridian_proto::bytes::bytes_vec")]
    pub ct: Vec<u8>,
}

impl MessageEnvelope {
    /// Deterministic-CBOR encode to the bytes carried in a routing [`OpaqueBlob`](crate::OpaqueBlob).
    pub fn to_blob(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode an envelope from the bytes of a received [`OpaqueBlob`](crate::OpaqueBlob). Does
    /// **not** check [`v`](Self::v) against [`ENVELOPE_VERSION`] — decoding a well-formed CBOR
    /// object with some other `v` value succeeds structurally; the caller (`ChatState::open_bytes`)
    /// is what enforces the hard version reject, exactly the same way it already owns the
    /// sender/routing cross-check (crypto-protocols rule 4) rather than baking policy into the wire
    /// codec.
    pub fn from_blob(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}

/// The canonical C3 preamble encoding: explicit presence-flag bytes over the (optional) X3DH
/// preamble alone — no domain tag, sender key, or ciphertext (those are bound elsewhere in the v2
/// AAD: the domain tag + `AD` are baked into the ratchet's fixed `ad` at session construction, and
/// the ciphertext is the AEAD's own protected content, never additional AAD). Kept as an explicit
/// 1-byte-presence-flag encoding (not bare CBOR) for the same reason v1's `signing_input` was:
/// without it, `Some(opk)` and a longer/absent field are splice-ambiguous.
///
/// Extracted from v1's `signing_input` so this crate owns the one canonical copy for the *wire*
/// side; `apps/crypto/src/session.rs` keeps a byte-identical copy over its own local
/// `PrekeyMaterial` type (this crate cannot be a production dependency of `meridian-crypto` — see
/// this crate's module doc, F15) — the two MUST be kept in lockstep by hand, and are pinned
/// together by the v2 conformance vectors (task 6.5).
pub fn preamble_aad_bytes(prekey: &Option<Prekey>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 1 + 32);
    match prekey {
        Some(p) => {
            out.push(1);
            out.extend_from_slice(&p.ek_pub);
            out.extend_from_slice(&p.used_spk);
            match &p.used_opk {
                Some(opk) => {
                    out.push(1);
                    out.extend_from_slice(opk);
                }
                None => out.push(0),
            }
        }
        None => out.push(0),
    }
    out
}
