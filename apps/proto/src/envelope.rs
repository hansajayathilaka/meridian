//! The E2E **message envelope** — `Sign_IK{ ratchet_ct }` with the sender key inside (system-design
//! §7.1 step 6). Serialized, this is exactly the bytes carried in a routing [`OpaqueBlob`]: the
//! server relays it verbatim and never decodes it. Full spec: `docs/api/messaging-envelope-v1.md`.
//!
//! An envelope carries:
//! - `sender_pub` — the sender's Ed25519 account key, *inside* the signed object so the recipient
//!   verifies the signature under the identity it expects (a mismatch is a hard failure, never a
//!   downgrade — anonymity-and-retention "must never" #5).
//! - `prekey` — present only on the opening message(s) of a session: the X3DH preamble the
//!   responder needs to complete the handshake.
//! - `ct` — the header-encrypted Double Ratchet message (opaque; counters/keys hidden).
//! - `sig` — `Ed25519(sender)` over [`signing_input`](MessageEnvelope::signing_input).

use serde::{Deserialize, Serialize};

use crate::frame::{decode, encode, CodecError};

/// Domain-separation tag folded into the envelope signature. A change is a wire break.
pub const ENVELOPE_DOMAIN: &[u8] = b"mrd.env/1";

/// The X3DH preamble attached to a session's opening message(s): the initiator's ephemeral public
/// key and which of the responder's prekeys were consumed (so it can find the matching secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prekey {
    #[serde(with = "crate::bytes::b32")]
    pub ek_pub: [u8; 32],
    #[serde(with = "crate::bytes::b32")]
    pub used_spk: [u8; 32],
    #[serde(with = "crate::bytes::opt_b32")]
    pub used_opk: Option<[u8; 32]>,
}

/// A signed, ratchet-encrypted message envelope. Opaque to the server; verified+decrypted only by
/// the recipient endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEnvelope {
    #[serde(with = "crate::bytes::b32")]
    pub sender_pub: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prekey: Option<Prekey>,
    #[serde(with = "crate::bytes::bytes_vec")]
    pub ct: Vec<u8>,
    #[serde(with = "crate::bytes::b64")]
    pub sig: [u8; 64],
}

impl MessageEnvelope {
    /// The exact byte string the sender signs and the recipient verifies. Binds the domain tag,
    /// the sender key, the (optional) prekey preamble, and the ratchet ciphertext together, so none
    /// can be swapped without invalidating the signature.
    pub fn signing_input(sender_pub: &[u8; 32], prekey: &Option<Prekey>, ct: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_DOMAIN.len() + 32 + 1 + 96 + ct.len());
        out.extend_from_slice(ENVELOPE_DOMAIN);
        out.extend_from_slice(sender_pub);
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
        out.extend_from_slice(ct);
        out
    }

    /// The signing input for *this* envelope (convenience for verification).
    pub fn signing_bytes(&self) -> Vec<u8> {
        Self::signing_input(&self.sender_pub, &self.prekey, &self.ct)
    }

    /// Deterministic-CBOR encode to the bytes carried in a routing [`OpaqueBlob`](crate::OpaqueBlob).
    pub fn to_blob(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode an envelope from the bytes of a received [`OpaqueBlob`](crate::OpaqueBlob).
    pub fn from_blob(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}
