//! meridian-proto — shared wire types.
//!
//! Canonical wire spec: ../../docs/api/wire-protocol.md and the T02 client↔rendezvous framing in
//! ../../docs/api/rendezvous-protocol-v1.md. Data model: ../../docs/architecture/data-model.md
//!
//! Compiled by BOTH clients and the rendezvous server so envelope/bundle/frame shapes cannot
//! drift. Encoding is deterministic CBOR (RFC 8949) via ciborium.
//!
//! INVARIANT: envelope bodies are OPAQUE to servers. The routing path must never deserialize
//! payload *contents*. Payloads are carried as [`OpaqueBlob`] — a byte newtype that (de)serializes
//! as a single CBOR byte string, never as structured data. The CI lint
//! `tools/lint-no-serde-on-blob.sh` checks this.
//!
//! Content-shaped types (the message envelope, chat/signal content, `mrd.ctrl/1` frames) live in
//! the separate `meridian-envelope` crate (`apps/envelope`), NOT here — deliberately, so
//! `meridian-rendezvous` (which depends on this crate) has no dependency path, direct or
//! transitive, to any type a server could be tempted to (de)serialize as structured content. See
//! `apps/envelope/src/lib.rs` and `docs/security/anonymity-and-retention.md` "must never" #1.

pub mod bytes;

pub mod bundle;
pub mod frame;
pub mod msg;

pub use bundle::{PrekeyBundle, BUNDLE_VERSION, MAX_ONE_TIME_PREKEYS};
pub use frame::{decode, encode, CodecError, Frame, Op};
pub use msg::{
    error_codes, Auth, AuthOk, Bundle, Challenge, Deliver, ErrBody, Fetch, Publish, PublishOk,
    RouteBody, RouteOk, TurnGrant, TurnReq,
};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque, server-unreadable payload bytes. Servers route these; only endpoints decrypt.
///
/// It (de)serializes as a single CBOR byte string (major type 2). Do NOT add any serde that
/// inspects the inner bytes as structured data — that would break the "payloads stay opaque"
/// invariant (docs/security/anonymity-and-retention.md #1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueBlob(pub Vec<u8>);

impl OpaqueBlob {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for OpaqueBlob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for OpaqueBlob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OpaqueBlob;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an opaque CBOR byte string")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(OpaqueBlob(v.to_vec()))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(OpaqueBlob(v))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(OpaqueBlob(out))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// Wire-protocol major version (wire-protocol.md).
pub const WIRE_VERSION: u8 = 1;
