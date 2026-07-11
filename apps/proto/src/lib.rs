//! meridian-proto — shared wire types (scaffold placeholder).
//!
//! Canonical wire spec: ../../docs/api/wire-protocol.md
//! Data model:          ../../docs/architecture/data-model.md
//!
//! INVARIANT: envelope bodies are OPAQUE to servers. The routing path must never
//! deserialize payload contents. To make that enforceable, payloads are carried as
//! `OpaqueBlob` (a byte newtype with NO serde on its inner content). The CI lint
//! `tools/lint-no-serde-on-blob.sh` checks this.

/// Opaque, server-unreadable payload bytes. Servers route these; only endpoints decrypt.
/// Do NOT add Serialize/Deserialize that inspects the inner bytes as structured data.
#[derive(Clone, Debug)]
pub struct OpaqueBlob(pub Vec<u8>);

impl OpaqueBlob {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Placeholder envelope shape. The real definition (signed, header-encrypted) lands with
/// feature 03; `payload` stays `OpaqueBlob` forever.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub eid: [u8; 16],
    pub sender_pub: [u8; 32],
    pub payload: OpaqueBlob,
    pub sig: [u8; 64],
}

pub const WIRE_VERSION: u8 = 1;
