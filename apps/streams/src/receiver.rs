//! Receiver engine (T09, task 10.8): decode → open (task 10.5) → verify (task 10.3) → write-by-
//! offset for inbound `mrd.file/1` chunk frames, reassembling a file from out-of-order, AEAD-sealed
//! chunks.
//!
//! ## Two independent, distinctly-reported integrity checks
//! Every inbound chunk frame must pass **both**, in this fixed order, before its plaintext is ever
//! written to the reassembly buffer:
//! 1. **Per-chunk AEAD** ([`crate::chunk::open_chunk`]) — a tampered ciphertext, or a ciphertext
//!    sealed for a different chunk index, fails to authenticate and is rejected here
//!    ([`ReceiveError::Crypto`]) *before* merkle is ever consulted.
//! 2. **Merkle subtree verification** ([`crate::merkle::verify`]) against the manifest's root — a
//!    chunk that opens fine (correct key, correct claimed index) but whose plaintext doesn't match
//!    the expected leaf hash (e.g. a different file's chunk re-sealed under the same `k_f`/index) is
//!    rejected here ([`ReceiveError::Corrupt`]), a distinct failure from AEAD rejection.
//!
//! A chunk failing either check is **never** inserted into the reassembly buffer — [`FileReceiver`]
//! only ever gains an entry for offset `i` in [`FileReceiver::receive_frame`]'s success path, so a
//! failed offset is left exactly as it started (absent), not merely reported as an error.
//!
//! ## Chunk-frame wire-decoding
//! `docs/api/wire-protocol.md` §6 documents the `mrd.file/1` chunk body as CBOR `{i: uint,
//! data: bstr}` and nothing more — no merkle proof field. This module decodes inbound frames via
//! [`crate::chunk::ChunkFrame`] (the canonical type for this exact shape, shared with the sender
//! engine, task 10.7, so both sides build/parse against one definition rather than two independently
//! hand-rolled CBOR shapes). [`FileReceiver::receive_frame`] takes a [`MerkleProof`] as a
//! caller-supplied argument rather than assuming one rides inside the same frame — but **no caller
//! in this tree supplies one today**: this type is tested only in isolation
//! ([`FileReceiver`]'s own unit tests below), and the real `meridian send` CLI path
//! (`apps/cli/src/send.rs::run_responder`/`finalize_transfer`) does not call it at all, instead
//! buffering every chunk and doing one whole-file merkle-root recomputation once the transfer
//! completes (review finding F8; task 11.8's decision record,
//! `docs/tasks/phase-11/11.8-chunk-proof-delivery-mechanism.md#risks--notes`). An architect consult
//! (task 11.8) decided the eventual mechanism — a flat leaf-hash list, sent once per transfer via a
//! new in-stream frame tag (`FRAME_TAG_LEAF_HASHES`, mirroring how the resume bitmap already
//! multiplexes onto this same channel, `crate::resume`), verified once against the manifest's root,
//! after which each chunk needs only a cheap `leaf_hash(plaintext) == received_list[i]` comparison —
//! not a per-call [`MerkleProof`]. Wiring that in is a real, tracked follow-up (unowned carry-forward
//! for a future build phase, not a small fix) that will change this function's signature; until then
//! this engine remains a tested-in-isolation component with no live caller.
//!
//! ## Scope
//! In-memory reassembly only (`BTreeMap<u64, Vec<u8>>` keyed by chunk index) — sufficient for this
//! task's own tests; real disk I/O is left to a later task if needed. Offset bookkeeping
//! ([`FileReceiver::received_offsets`]) is exposed for task 10.9's future resume bitmap to consume.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use meridian_proto::CodecError;

use crate::chunk::{open_chunk, ChunkFrame};
use crate::manifest::FileManifest;
use crate::merkle::{verify, MerkleProof, CHUNK_SIZE};

/// Why an inbound chunk frame was rejected before ever reaching the reassembly buffer. The two
/// integrity-check failures ([`Crypto`](Self::Crypto), [`Corrupt`](Self::Corrupt)) are deliberately
/// distinct variants — see the module doc — never collapsed into one generic "verification failed".
#[derive(Debug, Error)]
pub enum ReceiveError {
    /// The frame's own `{i, data}` bytes were not valid CBOR (or not of this shape). Never reaches
    /// the AEAD or merkle checks.
    #[error("malformed chunk frame: {0}")]
    Malformed(#[from] CodecError),
    /// Chunk index `i` is outside the file's known chunk count (from the manifest's `size`). Checked
    /// before AEAD open so an absurd/adversarial index can't be used to probe anything past it.
    #[error("chunk index {i} is out of range for a {leaf_count}-chunk file")]
    OutOfRange { i: u64, leaf_count: usize },
    /// AEAD authentication failed for chunk `i`: wrong key, tampered ciphertext, or a ciphertext
    /// sealed for a different chunk index. See [`crate::chunk::ChunkError`] — deliberately as coarse
    /// as that module's own error (no oracle distinguishing *why* the tag didn't verify).
    #[error("chunk {i} failed to authenticate (AEAD open failed)")]
    Crypto { i: u64 },
    /// Chunk `i` opened and authenticated, but its plaintext does not match the manifest's merkle
    /// root under the supplied proof — either the proof doesn't correspond to `i`, or the plaintext
    /// is not this file's real chunk `i` (e.g. resent from a different file/offset).
    #[error("chunk {i} failed merkle verification")]
    Corrupt { i: u64 },
}

impl ReceiveError {
    /// The chunk index this failure applies to, if the frame decoded far enough to have one.
    pub fn index(&self) -> Option<u64> {
        match self {
            ReceiveError::Malformed(_) => None,
            ReceiveError::OutOfRange { i, .. }
            | ReceiveError::Crypto { i }
            | ReceiveError::Corrupt { i } => Some(*i),
        }
    }
}

/// Number of [`CHUNK_SIZE`] leaves a file of `size` bytes was split into, matching
/// [`crate::merkle::MerkleTree`]'s own empty-file convention (a zero-byte file is exactly one
/// virtual leaf, never zero leaves).
fn leaf_count_for_size(size: u64) -> usize {
    if size == 0 {
        1
    } else {
        size.div_ceil(CHUNK_SIZE as u64) as usize
    }
}

/// Reassembles one file transfer from inbound, out-of-order `mrd.file/1` chunk frames.
///
/// Holds the per-file key `k_f` `Zeroizing`-wrapped (cleared on drop, matching this codebase's
/// convention for key material — `apps/streams/src/file.rs`) and never derives a `Debug` impl that
/// would print it or any plaintext chunk bytes (see the manual [`fmt::Debug`] impl below).
pub struct FileReceiver {
    manifest: FileManifest,
    k_f: Zeroizing<[u8; 32]>,
    leaf_count: usize,
    /// Verified plaintext chunks, keyed by index — the reassembly buffer. An offset only ever
    /// appears here once it has passed *both* the AEAD-open and merkle-verify checks.
    chunks: BTreeMap<u64, Vec<u8>>,
    /// Offsets successfully received so far — feeds task 10.9's future resume bitmap
    /// ([`FileReceiver::received_offsets`]). Always exactly the key set of `chunks`.
    received: BTreeSet<u64>,
}

impl fmt::Debug for FileReceiver {
    /// Deliberately omits `k_f` and every chunk's plaintext bytes — only structural/bookkeeping
    /// state (file name/size, which are already display-only per [`FileManifest`]'s own doc, and
    /// counts) is safe to print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileReceiver")
            .field("name", &self.manifest.name)
            .field("size", &self.manifest.size)
            .field("leaf_count", &self.leaf_count)
            .field("received_count", &self.received.len())
            .finish()
    }
}

impl FileReceiver {
    /// Starts a new receiver for a transfer whose manifest has already been accepted and whose
    /// `k_f` has already been unsealed from the ratchet (both task 10.6's concern, upstream of this
    /// engine).
    pub fn new(manifest: FileManifest, k_f: [u8; 32]) -> Self {
        let leaf_count = leaf_count_for_size(manifest.size);
        Self {
            manifest,
            k_f: Zeroizing::new(k_f),
            leaf_count,
            chunks: BTreeMap::new(),
            received: BTreeSet::new(),
        }
    }

    /// The manifest this receiver is reassembling against.
    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    /// The file's total chunk count, derived from the manifest's `size`.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Offsets (chunk indices) successfully received and verified so far. For task 10.9's future
    /// resume bitmap: "which chunks does the receiver still need" is exactly the complement of this
    /// set against `0..leaf_count()`.
    pub fn received_offsets(&self) -> &BTreeSet<u64> {
        &self.received
    }

    /// The verified plaintext for chunk `i`, if received. `None` both for "not yet received" and
    /// for "was received but failed a check" — a failed chunk is indistinguishable from a
    /// never-attempted one, by design (it was never written).
    pub fn chunk(&self, i: u64) -> Option<&[u8]> {
        self.chunks.get(&i).map(Vec::as_slice)
    }

    /// Whether every chunk of the file has been received and verified.
    pub fn is_complete(&self) -> bool {
        self.received.len() == self.leaf_count
    }

    /// Decodes, opens, and verifies one inbound chunk frame, writing its plaintext into the
    /// reassembly buffer at offset `i` **only if both checks pass**. `proof` must be the merkle
    /// inclusion proof for the frame's own claimed index `i` (see the module doc's wire-decoding
    /// note on how that proof is expected to reach the caller).
    ///
    /// On any failure, the reassembly buffer's slot for `i` is left exactly as it was before this
    /// call (absent, if `i` was never previously received) — never populated with unverified data.
    /// Returns the chunk index on success, so a caller can drive resume/re-request bookkeeping
    /// without re-decoding the frame.
    pub fn receive_frame(
        &mut self,
        frame_bytes: &[u8],
        proof: &MerkleProof,
    ) -> Result<u64, ReceiveError> {
        let frame = ChunkFrame::decode(frame_bytes)?;
        let i = frame.i;

        if i as usize >= self.leaf_count {
            return Err(ReceiveError::OutOfRange {
                i,
                leaf_count: self.leaf_count,
            });
        }

        // Check 1: AEAD open. A tampered ciphertext, or one sealed for a different index, must fail
        // here — before merkle is ever consulted (module doc, task risk note).
        let plaintext =
            open_chunk(&self.k_f, i, &frame.data).map_err(|_| ReceiveError::Crypto { i })?;

        // Defense in depth: the supplied proof must actually claim to be *for* this frame's index —
        // otherwise a caller (or a proof-delivery mechanism not yet pinned) could pair a chunk's
        // wire-claimed `i` with an unrelated proof and have `verify` succeed against the wrong leaf
        // position. `verify` itself independently cross-checks `proof.leaf_index` against its own
        // `steps`' side pattern (see `crate::merkle`'s doc) — this only pins that the proof was
        // meant for *this* chunk in the first place.
        if proof.leaf_index as u64 != i {
            return Err(ReceiveError::Corrupt { i });
        }

        // Check 2: merkle subtree verification against the manifest's root, distinct from check 1.
        if !verify(&self.manifest.root, proof, &plaintext) {
            return Err(ReceiveError::Corrupt { i });
        }

        self.chunks.insert(i, plaintext);
        self.received.insert(i);
        Ok(i)
    }

    /// Concatenates every received chunk in file order into the reassembled file bytes, or `None`
    /// if the transfer isn't complete yet ([`FileReceiver::is_complete`]).
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut out = Vec::with_capacity(self.manifest.size as usize);
        for i in 0..self.leaf_count as u64 {
            out.extend_from_slice(self.chunks.get(&i)?);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    fn k_f(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn manifest_for(name: &str, size: u64, root: [u8; 32]) -> FileManifest {
        FileManifest {
            name: name.to_string(),
            size,
            root,
            key: vec![0xAA; 32],
        }
    }

    /// Builds a multi-chunk file (three chunks: two full [`CHUNK_SIZE`] chunks and one short final
    /// chunk), plus its merkle tree, for the reassembly/corruption tests below.
    fn sample_file() -> (Vec<Vec<u8>>, MerkleTree) {
        let chunks = vec![
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; 1234],
        ];
        let tree = MerkleTree::from_chunks(chunks.clone());
        (chunks, tree)
    }

    fn frame_for(key: &[u8; 32], i: u64, plaintext: &[u8]) -> Vec<u8> {
        let sealed = crate::chunk::seal_chunk(key, i, plaintext);
        ChunkFrame { i, data: sealed }.encode().unwrap()
    }

    #[test]
    fn full_file_reassembles_from_out_of_order_chunks() {
        let (chunks, tree) = sample_file();
        let key = k_f(0x42);
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let manifest = manifest_for("vacation.mp4", total_size, tree.root());
        let mut receiver = FileReceiver::new(manifest, key);
        assert_eq!(receiver.leaf_count(), 3);

        // Feed chunks in reversed/scrambled order: 2, 0, 1.
        for &i in &[2usize, 0, 1] {
            let frame_bytes = frame_for(&key, i as u64, &chunks[i]);
            let proof = tree.proof(i).unwrap();
            let accepted = receiver.receive_frame(&frame_bytes, &proof).unwrap();
            assert_eq!(accepted, i as u64);
        }

        assert!(receiver.is_complete());
        assert_eq!(
            receiver
                .received_offsets()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let expected: Vec<u8> = chunks.concat();
        assert_eq!(receiver.reassemble().unwrap(), expected);
    }

    #[test]
    fn bit_flipped_chunk_is_rejected_by_aead_open_and_never_written() {
        let (chunks, tree) = sample_file();
        let key = k_f(0x11);
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let manifest = manifest_for("bad.bin", total_size, tree.root());
        let mut receiver = FileReceiver::new(manifest, key);

        let target = 1usize;
        let mut frame_bytes = frame_for(&key, target as u64, &chunks[target]);
        // Flip a byte inside the sealed ciphertext (well past the CBOR header for i/len, safely
        // inside `data`'s bytes).
        let last = frame_bytes.len() - 1;
        frame_bytes[last] ^= 0x01;

        let proof = tree.proof(target).unwrap();
        let err = receiver.receive_frame(&frame_bytes, &proof).unwrap_err();
        assert!(
            matches!(err, ReceiveError::Crypto { i } if i == target as u64),
            "a tampered ciphertext must fail via the AEAD path, not merkle: got {err:?}"
        );

        // Never written: the slot for this offset stays absent, not just "an error occurred".
        assert!(receiver.chunk(target as u64).is_none());
        assert!(!receiver.received_offsets().contains(&(target as u64)));
        assert!(!receiver.is_complete());
    }

    #[test]
    fn chunk_from_a_different_file_fails_merkle_verification_not_aead() {
        // File A is what `receiver` is actually reassembling.
        let (chunks_a, tree_a) = sample_file();
        let key = k_f(0x77);
        let total_size_a: u64 = chunks_a.iter().map(|c| c.len() as u64).sum();
        let manifest_a = manifest_for("real.bin", total_size_a, tree_a.root());
        let mut receiver = FileReceiver::new(manifest_a, key);

        // File B: different content entirely, same chunk-size shape, sealed under the *same* k_f
        // and the *same* claimed index — so AEAD authenticates cleanly (it only binds key + index,
        // never file identity or content), but the plaintext doesn't belong to file A.
        let chunks_b = [
            vec![0x01u8; CHUNK_SIZE],
            vec![0x02u8; CHUNK_SIZE],
            vec![0x03u8; 1234],
        ];
        let target = 1usize;
        let frame_bytes = frame_for(&key, target as u64, &chunks_b[target]);
        // A syntactically valid proof for file A's own tree at this index (the attacker doesn't
        // need to forge a proof — the point is that no proof for a foreign chunk can satisfy it).
        let proof = tree_a.proof(target).unwrap();

        let err = receiver.receive_frame(&frame_bytes, &proof).unwrap_err();
        assert!(
            matches!(err, ReceiveError::Corrupt { i } if i == target as u64),
            "a chunk that opens fine but belongs to a different file must fail via merkle, not \
             AEAD: got {err:?}"
        );

        // Never written.
        assert!(receiver.chunk(target as u64).is_none());
        assert!(!receiver.received_offsets().contains(&(target as u64)));
        assert!(!receiver.is_complete());

        // Sanity: file A's own real chunk at the same index still verifies fine afterward.
        let good_frame = frame_for(&key, target as u64, &chunks_a[target]);
        let accepted = receiver.receive_frame(&good_frame, &proof).unwrap();
        assert_eq!(accepted, target as u64);
        assert_eq!(
            receiver.chunk(target as u64).unwrap(),
            &chunks_a[target][..]
        );
    }

    #[test]
    fn malformed_frame_bytes_are_rejected_without_panicking() {
        let (chunks, tree) = sample_file();
        let key = k_f(0x22);
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let manifest = manifest_for("x.bin", total_size, tree.root());
        let mut receiver = FileReceiver::new(manifest, key);

        let proof = tree.proof(0).unwrap();
        let err = receiver
            .receive_frame(b"not a valid cbor chunk frame", &proof)
            .unwrap_err();
        assert!(matches!(err, ReceiveError::Malformed(_)));
        assert!(receiver.received_offsets().is_empty());
    }

    #[test]
    fn out_of_range_index_is_rejected_before_aead_or_merkle() {
        let (chunks, tree) = sample_file();
        let key = k_f(0x33);
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let manifest = manifest_for("x.bin", total_size, tree.root());
        let mut receiver = FileReceiver::new(manifest, key);

        let frame_bytes = frame_for(&key, 99, b"whatever");
        let bogus_proof = tree.proof(0).unwrap();
        let err = receiver
            .receive_frame(&frame_bytes, &bogus_proof)
            .unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::OutOfRange {
                i: 99,
                leaf_count: 3
            }
        ));
        assert!(receiver.received_offsets().is_empty());
    }

    #[test]
    fn proof_leaf_index_mismatched_with_frame_index_is_rejected() {
        // Defense-in-depth: a correctly-opened chunk paired with a valid-but-wrong-index proof
        // (proof for index 0, chunk claiming index 1) must not be treated as verified.
        let (chunks, tree) = sample_file();
        let key = k_f(0x55);
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let manifest = manifest_for("x.bin", total_size, tree.root());
        let mut receiver = FileReceiver::new(manifest, key);

        let frame_bytes = frame_for(&key, 1, &chunks[1]);
        let mismatched_proof = tree.proof(0).unwrap();
        let err = receiver
            .receive_frame(&frame_bytes, &mismatched_proof)
            .unwrap_err();
        assert!(matches!(err, ReceiveError::Corrupt { i: 1 }));
        assert!(receiver.chunk(1).is_none());
    }

    #[test]
    fn zero_byte_file_has_a_single_leaf_and_reassembles_to_empty() {
        let tree = MerkleTree::from_bytes(&[]);
        let key = k_f(0x66);
        let manifest = manifest_for("empty.bin", 0, tree.root());
        let mut receiver = FileReceiver::new(manifest, key);
        assert_eq!(receiver.leaf_count(), 1);

        let frame_bytes = frame_for(&key, 0, &[]);
        let proof = tree.proof(0).unwrap();
        receiver.receive_frame(&frame_bytes, &proof).unwrap();
        assert!(receiver.is_complete());
        assert_eq!(receiver.reassemble().unwrap(), Vec::<u8>::new());
    }
}
