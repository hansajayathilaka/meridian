//! `SignalContent` — the P2P session-establishment payloads that ride inside the *same*
//! ratchet-encrypted, identity-signed [`MessageEnvelope`](crate::MessageEnvelope) as chat
//! (wire-protocol §3 `Content` union; system-design §7.1 step 6). Because they are sealed exactly
//! like chat, SDP and ICE candidates **never travel to a server in cleartext** (webrtc-nat-traversal
//! invariant 2) — the rendezvous routes opaque blobs and can neither read nor edit an SDP offer.
//!
//! The DTLS fingerprint is carried *inside* the offer/answer here, so it is authenticated by the
//! envelope's Ed25519 signature and bound to the sender's identity. After the handshake the
//! substrate cross-checks the transport's negotiated fingerprint against [`dtls_fp`] — a mismatch
//! tears the session down (§4.6).
//!
//! [`dtls_fp`]: SignalContent::SdpOffer

use serde::{Deserialize, Serialize};

use meridian_proto::{decode, encode, CodecError};

/// A P2P signaling payload (the ratchet plaintext). `Ctrl` wraps a `mrd.ctrl/1`
/// [`CtrlFrame`](crate::ctrl::CtrlFrame) so channel-0 frames are ratchet-sealed like any payload
/// (wire-protocol §5) whether they ride the relay (pre-connect) or the ctrl data channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalContent {
    /// The dialing side's offer: the opaque SDP, the asserted DTLS fingerprint (identity-bound by
    /// the envelope signature), and any already-gathered ICE candidates.
    SdpOffer {
        #[serde(with = "meridian_proto::bytes::bytes_vec")]
        sdp: Vec<u8>,
        dtls_fp: String,
        ice: Vec<String>,
    },
    /// The answering side's response, same shape.
    SdpAnswer {
        #[serde(with = "meridian_proto::bytes::bytes_vec")]
        sdp: Vec<u8>,
        dtls_fp: String,
        ice: Vec<String>,
    },
    /// Trickled ICE candidates discovered after the offer/answer.
    IceTrickle { candidates: Vec<String> },
    /// A ratchet-sealed `mrd.ctrl/1` frame (channel 0). Carried in-band on the ctrl data channel
    /// once the session is up.
    Ctrl {
        #[serde(with = "meridian_proto::bytes::bytes_vec")]
        frame: Vec<u8>,
    },
}

impl SignalContent {
    /// Deterministic-CBOR encode to the ratchet plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a decrypted ratchet plaintext back into a signaling payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}
