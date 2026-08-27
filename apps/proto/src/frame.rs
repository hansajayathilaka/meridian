//! The `{op, id, body}` frame that carries every client↔rendezvous message (wire-protocol §2).
//!
//! `id` is a client-chosen request id echoed by the server in its reply. `op` selects how `body`
//! is interpreted; `body` is nested CBOR so the frame layer stays agnostic to payload shape (and
//! so the server can route an opaque blob without ever decoding its contents).

use serde::{Deserialize, Serialize};

/// Frame operation selector, encoded as a short CBOR string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// server→client: authentication challenge (first frame).
    Challenge,
    /// client→server: account-key auth + registration.
    Auth,
    /// server→client: auth accepted.
    AuthOk,
    /// client→server: publish a prekey bundle.
    Publish,
    /// server→client: bundle stored.
    PublishOk,
    /// client→server: fetch a bundle by exact key.
    Fetch,
    /// server→client: bundle reply.
    Bundle,
    /// client→server: route an opaque envelope to an online peer.
    Route,
    /// server→client: route outcome.
    RouteOk,
    /// server→recipient: a delivered envelope.
    Deliver,
    /// client→server: request ephemeral TURN credentials for a session (T05).
    TurnReq,
    /// server→client: a minted TURN credential, distinct per request (reuse of one credential is
    /// quota-bounded server-side, not rejected outright — see `TurnGrant` doc).
    TurnGrant,
    /// client→server: acknowledge one or more mailbox-drain `Deliver` pushes so the server can
    /// delete the corresponding rows (T07).
    MailboxAck,
    /// server→client: the `MailboxAck` was processed.
    MailboxAckOk,
    /// server→client: structured error.
    Err,
}

/// A single wire frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub op: Op,
    pub id: u64,
    #[serde(with = "crate::bytes::bytes_vec")]
    pub body: Vec<u8>,
}

/// Errors encoding/decoding frames and bodies.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("CBOR encode failed: {0}")]
    Encode(String),
    #[error("CBOR decode failed: {0}")]
    Decode(String),
}

impl Frame {
    /// Build a frame for `op`/`id`, CBOR-encoding `body` into the nested byte string.
    pub fn new<B: Serialize>(op: Op, id: u64, body: &B) -> Result<Self, CodecError> {
        Ok(Self {
            op,
            id,
            body: encode(body)?,
        })
    }

    /// Decode this frame's body as `B`. Callers match on `self.op` first to pick `B`.
    pub fn decode<B: for<'de> Deserialize<'de>>(&self) -> Result<B, CodecError> {
        decode(&self.body)
    }

    /// Encode the whole frame to CBOR bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a whole frame from CBOR bytes received off the wire.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}

/// Deterministic CBOR encode (ciborium, RFC 8949).
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| CodecError::Encode(e.to_string()))?;
    Ok(buf)
}

/// CBOR decode (ciborium).
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, CodecError> {
    ciborium::from_reader(bytes).map_err(|e| CodecError::Decode(e.to_string()))
}
