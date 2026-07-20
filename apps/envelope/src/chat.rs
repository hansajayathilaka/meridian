//! `mrd.chat/1` — the Tier-1 chat stream payload (system-design §5.3). This is the *plaintext*
//! that rides inside the Double Ratchet; the server never sees it (it is sealed, then wrapped in
//! an [`OpaqueBlob`](crate::OpaqueBlob)). It is also the offline-mailbox payload format (T07).
//!
//! T03 scope: text messages and delivery receipts. Typing/reactions are additive variants added
//! later without a wire break (unknown variants fail to decode → forward-compat handled by the
//! version tag in the type name).

use serde::{Deserialize, Serialize};

use meridian_proto::{decode, encode, CodecError};

/// A chat message identifier — a random 128-bit value the sender mints, echoed by receipts.
pub type MessageId = [u8; 16];

/// A `mrd.chat/1` payload. CBOR-encoded, this is the plaintext handed to the ratchet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatContent {
    /// A text message with its sender-minted id (so the peer can acknowledge it).
    Text {
        #[serde(with = "meridian_proto::bytes::b16")]
        id: MessageId,
        body: String,
    },
    /// A delivery receipt acknowledging a previously received [`ChatContent::Text`] by id.
    Receipt {
        #[serde(with = "meridian_proto::bytes::b16")]
        ack: MessageId,
    },
}

impl ChatContent {
    /// Deterministic-CBOR encode to the ratchet plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a decrypted ratchet plaintext back into a chat payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}
