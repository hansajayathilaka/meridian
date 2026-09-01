//! `SignalContent` — the P2P session-establishment payloads that ride inside the *same*
//! ratchet-encrypted [`MessageEnvelope`](crate::MessageEnvelope) as chat (wire-protocol §3 `Content`
//! union; system-design §7.1 step 6). Envelope v2 ([ADR 0016](../../../docs/adr/0016-envelope-deniability.md))
//! carries no per-message signature at all — authentication rests entirely on the ratchet AEAD.
//! Because these payloads are sealed exactly like chat, SDP and ICE candidates **never travel to a
//! server in cleartext** (webrtc-nat-traversal invariant 2) — the rendezvous routes opaque blobs and
//! can neither read nor edit an SDP offer.
//!
//! The DTLS fingerprint is carried *inside* the offer/answer here, so it is bound to the sender's
//! identity. **What binds it is the ratchet AEAD, not an envelope signature — there is no envelope
//! signature to bind it**: `SignalContent` is ratchet *plaintext*, and the AEAD's authentication
//! comes from its AAD, which carries `AD = IK_initiator ‖ IK_responder`, and (on first contact) from
//! X3DH's `DH1`. This is exactly why ADR 0016's removal of the per-message signature at envelope v2
//! is a no-op for fingerprint binding: binding never depended on a signature that has since been
//! removed, only on the AEAD/AD construction that is still fully in place. After the handshake the
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
    /// the ratchet AEAD's `AD = IK_initiator ‖ IK_responder` — there is no envelope signature; see
    /// the module doc), and any already-gathered ICE candidates.
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
    /// An unsolicited ICE-restart offer riding this same session-substrate signaling tier
    /// ([ADR 0025](../../../docs/adr/0025-ice-restart-renegotiation.md)) — same shape as
    /// [`SdpOffer`](SignalContent::SdpOffer), but carries a fresh SDP offer/candidate set for an
    /// *already-established* session whose P2P path has degraded, not the initial session
    /// establishment. Delivery is tolerant (mailbox-eligible), never hard-fail, since a live ratchet
    /// session already exists to fall back on.
    IceRestartOffer {
        #[serde(with = "meridian_proto::bytes::bytes_vec")]
        sdp: Vec<u8>,
        dtls_fp: String,
        ice: Vec<String>,
    },
    /// The response to an [`IceRestartOffer`](SignalContent::IceRestartOffer), same shape as
    /// [`SdpAnswer`](SignalContent::SdpAnswer) ([ADR 0025](../../../docs/adr/0025-ice-restart-renegotiation.md)).
    /// A real ICE restart never recreates the `RTCPeerConnection`, so `dtls_fp` here is expected to
    /// still match the session's already-cached fingerprint — checked as a *second*, additional
    /// assertion layered on top of the ordinary asserted-vs-negotiated cross-check (§4.6), not a
    /// replacement for it.
    IceRestartAnswer {
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
