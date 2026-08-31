//! Per-chunk AEAD for `mrd.file/1` (T09, task 10.5): seals/opens one 64 KiB file chunk under the
//! per-file key `k_f` (generated once per file and sealed under the ratchet in the manifest —
//! task 10.6's job; this module only ever sees the resulting raw key bytes) with a nonce derived
//! from the chunk index, per `docs/api/wire-protocol.md` §6: "`mrd.file/1` chunk body: `{i: uint,
//! data: bstr}`, AEAD key = per-file `k_f`, nonce = `i`".
//!
//! Deliberately implemented with `chacha20poly1305` directly, **not** routed through
//! `meridian-crypto`: this is ordinary per-file symmetric encryption under a key that has already
//! been derived and sealed elsewhere (task 10.6), not ratchet/session state, so keeping it here
//! keeps `meridian-streams`'s "additive stream type, zero core-crate edits" contract intact.
//!
//! ## Pinned construction (task 10.5's own required `TODO: confirm` resolution — this is the
//! byte-for-byte spec task 10.12 copies verbatim into the wire doc; changing anything below is a
//! wire-relevant, cross-implementation break)
//!
//! - **Algorithm:** XChaCha20-Poly1305 (`chacha20poly1305::XChaCha20Poly1305`), matching the AEAD
//!   choice used everywhere else in this codebase (crypto-protocols skill, `meridian-crypto`'s
//!   `primitives`/`at_rest` modules).
//! - **Key:** the per-file `k_f`, exactly 32 bytes, used directly as the XChaCha20-Poly1305 key —
//!   no further KDF is applied in this module.
//! - **Nonce (24 bytes):** the chunk index `i` (`u64`) encoded as 8 bytes little-endian, followed
//!   by 16 zero bytes — `LE64(i) ‖ 0x00×16`. This matches the codebase's other little-endian
//!   conventions and gives every chunk of one file a distinct, deterministic nonce without ever
//!   needing to carry a nonce on the wire.
//! - **AAD:** none (empty). The chunk index `i` is bound implicitly by being baked into the nonce
//!   rather than passed as associated data: substituting the ciphertext of chunk `j` for chunk `i`
//!   changes the nonce a legitimate `open_chunk(k_f, i, _)` call derives, so the tag will not
//!   verify unless the caller also mislabels the index (see [`open_chunk`]'s doc).
//! - **Ciphertext layout:** [`seal_chunk`] returns the raw AEAD output (ciphertext ‖ 16-byte
//!   Poly1305 tag) with **no** nonce prepended — the nonce is never carried on the wire, since it
//!   is fully determined by `i`, which is already present alongside `data` in the `mrd.file/1`
//!   chunk body (`{i: uint, data: bstr}`). `data` on the wire is exactly this module's output.
//!
//! ## Critical invariant: `k_f` must never be reused across two different files
//! The nonce depends only on the chunk index `i`, not on any per-file randomness. Because each
//! file's chunks are indexed `0, 1, 2, …` exactly once, nonce reuse **within** one file's chunk
//! stream cannot happen by construction. But if the *same* `k_f` were ever reused to seal chunks
//! of a second, different file, chunk `i` of file A and chunk `i` of file B would be sealed under
//! the identical `(key, nonce)` pair — a catastrophic AEAD failure mode (keystream reuse enabling
//! plaintext recovery and forgery). This module has no way to detect or prevent that; it is a hard
//! contract on whoever generates and seals `k_f` (task 10.6) to mint a **fresh, independently
//! random `k_f` for every file**, never reused across files.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use meridian_proto::{decode, encode, CodecError};

/// Failures opening a sealed chunk.
#[derive(Debug, Error)]
pub enum ChunkError {
    /// AEAD tag verification failed: wrong key, wrong chunk index, or tampered ciphertext.
    /// Deliberately coarse (no distinguishing oracle) — mirrors `meridian-crypto`'s decrypt-path
    /// error granularity.
    #[error("chunk failed to authenticate")]
    Crypto,
}

pub type Result<T> = core::result::Result<T, ChunkError>;

/// Derives this module's pinned 24-byte nonce for chunk index `i` — see the module doc.
fn nonce_bytes(i: u64) -> [u8; 24] {
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&i.to_le_bytes());
    bytes
}

/// Seals one file chunk under the per-file key `k_f` with the nonce derived from chunk index `i`.
/// See the module doc for the exact, pinned algorithm/nonce/AAD/layout. Returns the AEAD output —
/// this is `data` in the `mrd.file/1` chunk body's `{i, data}`; the caller is responsible for
/// pairing it with `i` on the wire.
///
/// # Panics
/// Never panics for any chunk this crate produces (64 KiB, far below XChaCha20-Poly1305's ~256 GiB
/// plaintext limit) sealed under any 32-byte key.
pub fn seal_chunk(k_f: &[u8; 32], i: u64, data: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(k_f)
        .expect("k_f is exactly 32 bytes, which XChaCha20Poly1305::new_from_slice always accepts");
    let nonce = nonce_bytes(i);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: data,
                aad: &[],
            },
        )
        .expect("chunk-sized plaintext is always within the AEAD's length limit")
}

/// Inverse of [`seal_chunk`]: opens a sealed chunk, claiming it is chunk index `i` under `k_f`.
/// Fails (rather than silently returning wrong bytes) if `sealed` was not produced by
/// `seal_chunk(k_f, i, _)` for this exact `(k_f, i)` pair — including when it was sealed for a
/// *different* chunk index under the same `k_f`, since the derived nonce would then differ.
pub fn open_chunk(k_f: &[u8; 32], i: u64, sealed: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(k_f).map_err(|_| ChunkError::Crypto)?;
    let nonce = nonce_bytes(i);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: sealed,
                aad: &[],
            },
        )
        .map_err(|_| ChunkError::Crypto)
}

/// The `mrd.file/1` **wire** chunk frame — `{i: uint, data: bstr}` per
/// `docs/api/wire-protocol.md` §6 — sent as the full body of every `send_stream_frame` call the
/// sender engine (task 10.7) makes while a transfer is in flight. `data` is exactly one call's
/// worth of [`seal_chunk`] output for chunk index `i`; this type owns only the CBOR envelope around
/// it, mirroring [`crate::manifest::FileManifest`]'s own `encode`/`decode` pattern (same
/// deterministic-CBOR helpers, same `bytes_vec` byte-string encoding for the opaque payload).
///
/// This lives here (rather than in `sender.rs`/`receiver.rs`) because it is the wire contract this
/// module's own doc already describes (`{i, data}`) — `seal_chunk`/`open_chunk` produce/consume
/// `data` alone, and this type is the one place that pairs it with `i` for the wire, so both the
/// receiver engine (task 10.8, [`crate::receiver`]) and the sender engine (task 10.7,
/// [`crate::sender`]) build/parse frames against the exact same canonical type — never two
/// independently-hand-rolled CBOR shapes that could silently drift apart.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkFrame {
    /// The chunk index this frame claims to carry.
    pub i: u64,
    /// The AEAD-sealed chunk bytes ([`seal_chunk`]'s output).
    #[serde(with = "meridian_proto::bytes::bytes_vec")]
    pub data: Vec<u8>,
}

impl ChunkFrame {
    /// Deterministic-CBOR encode — this is the exact `bytes` [`crate::sender`] hands to
    /// `P2pSession::send_stream_frame`.
    // NB: `core::result::Result` here, not this module's own `Result<T>` alias (which is fixed to
    // `ChunkError`) — `encode`/`decode` fail with `CodecError`, a distinct error from `ChunkError`.
    pub fn encode(&self) -> core::result::Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a chunk frame from previously-decrypted plaintext bytes (the output of the
    /// session substrate's own ratchet `open`/export step — this type never touches ciphertext).
    /// Every byte off the wire is hostile; this never panics on malformed input, only returns
    /// [`CodecError`].
    pub fn decode(bytes: &[u8]) -> core::result::Result<Self, CodecError> {
        decode(bytes)
    }
}

impl std::fmt::Debug for ChunkFrame {
    /// Deliberately omits the sealed chunk bytes themselves (up to 64 KiB of ciphertext per frame is
    /// noisy, and this crate's convention is to never print bulk payload bytes — see
    /// [`crate::receiver::FileReceiver`]'s own `Debug` impl) in favor of just its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkFrame")
            .field("i", &self.i)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn round_trips() {
        let k_f = key(0x42);
        let data = b"a 64 KiB chunk's worth of pretend file bytes".to_vec();
        let sealed = seal_chunk(&k_f, 7, &data);
        let opened = open_chunk(&k_f, 7, &sealed).expect("must open with the same index");
        assert_eq!(opened, data);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k_f = key(0x11);
        let data = b"hello, meridian".to_vec();
        let mut sealed = seal_chunk(&k_f, 3, &data);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(
            open_chunk(&k_f, 3, &sealed).is_err(),
            "flipping a ciphertext byte must fail authentication"
        );
    }

    #[test]
    fn wrong_index_is_rejected() {
        // Proves the nonce actually binds to `i`: sealing under index 5 and opening while
        // claiming index 6 must fail, even with the correct key and an untouched ciphertext.
        let k_f = key(0x99);
        let data = b"chunk five".to_vec();
        let sealed = seal_chunk(&k_f, 5, &data);
        assert!(
            open_chunk(&k_f, 6, &sealed).is_err(),
            "opening with the wrong chunk index must fail"
        );
        // Sanity: the same ciphertext still opens correctly under its real index.
        assert_eq!(open_chunk(&k_f, 5, &sealed).unwrap(), data);
    }

    #[test]
    fn different_indices_produce_non_colliding_ciphertexts_for_identical_plaintext() {
        // Nonce-uniqueness sanity check: the same k_f and the same plaintext, sealed under two
        // different chunk indices, must not produce the same ciphertext bytes (which would
        // indicate nonce reuse/collision).
        let k_f = key(0x77);
        let data = vec![0xAB; 128];
        let sealed_0 = seal_chunk(&k_f, 0, &data);
        let sealed_1 = seal_chunk(&k_f, 1, &data);
        assert_ne!(
            sealed_0, sealed_1,
            "distinct chunk indices must yield distinct ciphertexts for identical plaintext"
        );
    }

    #[test]
    fn chunk_frame_round_trips_and_data_is_a_cbor_byte_string() {
        // Wire-shape pin (`docs/api/wire-protocol.md` §6): `{i: uint, data: bstr}`, `data` encoded
        // as a CBOR byte string (major type 2), not an array of small integers — matching every
        // other opaque-bytes field in this crate/workspace (`bytes_vec`).
        let frame = ChunkFrame {
            i: 7,
            data: vec![0xEE; 40],
        };
        let bytes = frame.encode().unwrap();
        assert_eq!(ChunkFrame::decode(&bytes).unwrap(), frame);

        let value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("chunk frame must encode as a CBOR map");
        };
        for (key, val) in entries {
            if let ciborium::value::Value::Text(field) = key {
                if field == "data" {
                    assert!(matches!(val, ciborium::value::Value::Bytes(_)));
                }
            }
        }
    }
}
