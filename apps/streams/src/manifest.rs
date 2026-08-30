//! `mrd.file/1` manifest — the metadata a sender attaches when opening a file-transfer stream
//! (T09, docs/architecture/features/09-file-transfer.md). This is the plaintext body that rides
//! inside the ratchet-sealed `mrd.ctrl/1` `Open{type: "mrd.file/1", params: ...}` frame (or an
//! equivalent ratchet-encrypted control payload — the exact carrier is task 10.6's `StreamType`
//! impl); it never touches the server as structured data.
//!
//! Scope note (task 10.3): this module owns only the CBOR **shape**. It deliberately does not:
//! - seal `key` under the Double Ratchet (that happens at the send site, in a later task — this
//!   struct's `key` field is just the resulting opaque bytes to carry);
//! - implement the `StreamType` trait (task 10.6) or per-chunk AEAD (task 10.5);
//! - compute `root`/`size` from an actual file (that is [`crate::merkle`] plus the sender engine,
//!   task 10.7) — this type is a pure data carrier.

use serde::{Deserialize, Serialize};

use meridian_proto::{decode, encode, CodecError};

/// A `mrd.file/1` manifest: `{name, size, root, key}`.
///
/// - `name` — the sender-supplied file name (display only; never used as a path on the receiving
///   side without sanitization — that guard belongs to the receiver engine, task 10.8).
/// - `size` — the file's exact length in bytes.
/// - `root` — the [`crate::merkle`] BLAKE3 merkle root over the file's 64 KiB chunks (see that
///   module's doc comment for the exact, pinned tree construction). Fixed at 32 bytes: it is this
///   crate's own hash output, not an externally-supplied opaque blob.
/// - `key` — the per-file symmetric key (`k_f` in `docs/api/wire-protocol.md` §6) used to derive
///   the per-chunk AEAD (task 10.5 owns the algorithm/length). Carried here as an **opaque** byte
///   blob: this crate neither interprets nor validates it, and its confidentiality comes entirely
///   from being sealed under the Double Ratchet at the send site (`meridian-crypto`), not from
///   anything in this struct or crate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    pub name: String,
    pub size: u64,
    #[serde(with = "meridian_proto::bytes::b32")]
    pub root: [u8; 32],
    #[serde(with = "meridian_proto::bytes::bytes_vec")]
    pub key: Vec<u8>,
}

impl FileManifest {
    /// Deterministic-CBOR encode (the bytes carried inside the ratchet-sealed control payload).
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a manifest from previously-decrypted plaintext bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrips() {
        let manifest = FileManifest {
            name: "vacation.mp4".to_string(),
            size: 123_456_789,
            root: [0x42; 32],
            key: vec![0xAA; 32],
        };
        let bytes = manifest.encode().unwrap();
        assert_eq!(FileManifest::decode(&bytes).unwrap(), manifest);
    }

    #[test]
    fn manifest_root_and_key_are_byte_strings_not_int_arrays() {
        // Wire hygiene: `root`/`key` must encode as CBOR byte strings (major type 2), not as
        // arrays of small integers, matching every other 32-byte field on the wire
        // (apps/proto/src/bytes.rs). A regression here would still round-trip through this
        // crate's own encode/decode but silently balloon/mis-shape the bytes actually on the wire.
        let manifest = FileManifest {
            name: "a".to_string(),
            size: 1,
            root: [0x11; 32],
            key: vec![0x22; 4],
        };
        let bytes = manifest.encode().unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("manifest must encode as a CBOR map");
        };
        for (key, val) in entries {
            let ciborium::value::Value::Text(field) = key else {
                continue;
            };
            if field == "root" || field == "key" {
                assert!(
                    matches!(val, ciborium::value::Value::Bytes(_)),
                    "{field} must encode as a CBOR byte string"
                );
            }
        }
    }
}
