//! BLAKE3 merkle tree over a file's 64 KiB chunks (T09).
//!
//! ## Pinned construction (task 10.3 — this is the byte-for-byte spec task 10.12 copies verbatim
//! into the feature doc; changing anything below is a wire-relevant, cross-implementation break)
//!
//! - **Chunking:** the file is split into consecutive [`CHUNK_SIZE`] (64 KiB = 65536 byte) chunks
//!   in file order; only the final chunk may be shorter (the file's length modulo `CHUNK_SIZE`,
//!   or a full `CHUNK_SIZE` if the file length is an exact multiple). Chunks are never padded.
//! - **Leaf hash:** `leaf_i = BLAKE3(0x00 ‖ chunk_i)` — the BLAKE3-256 hash of a single `0x00`
//!   domain-separation byte followed directly by the raw chunk bytes; no length prefix, no keying.
//!   One leaf per chunk, in file order (`leaf_0` is the first 64 KiB of the file).
//! - **Internal node hash:** `node = BLAKE3(0x01 ‖ left ‖ right)` — the BLAKE3-256 hash of a single
//!   `0x01` domain-separation byte followed by the 32-byte `left` child hash directly concatenated
//!   with the 32-byte `right` child hash (65 input bytes total); no length prefix. The `0x00`
//!   leaf prefix vs. `0x01` internal-node prefix domain-separate leaf hashing from internal-node
//!   hashing by construction (mirroring the RFC 6962 §2.1 fix): no leaf hash can ever equal an
//!   internal node hash, closing the classic Merkle-tree type-confusion / second-preimage
//!   vulnerability where a party could pass off two learned child hashes, concatenated, as a
//!   forged single-leaf file whose root collides with a real multi-chunk root.
//! - **Tree shape — bottom-up pairwise fold, odd node promoted (not duplicated):** starting from
//!   the leaf level, each subsequent level is built by pairing adjacent nodes left-to-right,
//!   `(level[0], level[1]), (level[2], level[3]), ...`, hashing each pair into one parent node in
//!   the same relative order. If a level has an **odd** number of nodes, the final, unpaired node
//!   is carried forward **unchanged** (not re-hashed, not paired with a copy of itself) to become
//!   a node of the next level. This repeats until exactly one node remains: the root. A tree with
//!   exactly one chunk has a root equal to that chunk's own leaf hash (no internal node is ever
//!   computed). This is deliberately **not** the RFC 6962 / Certificate Transparency tree (which
//!   recursively splits at the largest power of two ≤ n before hashing); it is a simple level-by-
//!   level pairwise fold. The only special case is the odd-node promotion above, chosen
//!   specifically to avoid the classic Merkle "duplicate the last leaf" second-preimage weakness
//!   (an attacker being able to present a tree of `n` leaves as equally valid evidence for a
//!   different `n+1`-leaf multiset).
//! - **Zero-chunk (empty file) convention:** `TODO: confirm` with the T09 spec (task 10.12) —
//!   no design doc pins this case. Until then, [`MerkleTree::from_chunks`] treats "no chunks" as a
//!   single virtual leaf `BLAKE3(b"")`, so `root()`/proof construction stay total functions instead
//!   of panicking on a plausible real input (an empty file upload).
//!
//! ## Proofs
//! [`MerkleTree::proof`] returns the sibling hash (and its left/right position) at every level on
//! the path from a leaf to the root, or [`ProofStep::Promoted`] at any level where that task's
//! own construction step above carried the node forward unpaired. [`verify`] recomputes the path
//! from a candidate chunk's bytes and the proof alone (it never needs the whole tree), so it
//! detects corruption in the one chunk it was given a proof for without recomputing every other
//! chunk's hash. `verify` also cross-checks `proof.leaf_index` against the Left/Right/Promoted
//! pattern of `proof.steps` (each step's expected side is exactly `leaf_index`'s bit at that
//! level, read least-significant-bit first), rejecting the proof if they disagree — otherwise a
//! party could relabel `leaf_index` on an untouched, otherwise-valid proof to falsely claim a
//! different chunk offset in the file.

use meridian_proto::bytes::b32;
use serde::{Deserialize, Serialize};

/// Chunk size the file is split into before hashing (T09, 64 KiB).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// A BLAKE3-256 hash, as used for both leaves and internal nodes.
pub type Hash = [u8; 32];

/// Domain-separation prefix for leaf hashes — see the module doc. Must never equal
/// [`NODE_PREFIX`]; that's the whole point.
const LEAF_PREFIX: u8 = 0x00;

/// Domain-separation prefix for internal node hashes — see the module doc.
const NODE_PREFIX: u8 = 0x01;

fn leaf_hash(chunk: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(chunk);
    *hasher.finalize().as_bytes()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 65];
    buf[0] = NODE_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

/// Splits `data` into consecutive [`CHUNK_SIZE`] chunks, the last possibly shorter. Convenience
/// for building/verifying a tree over an in-memory buffer (streaming builders for large files are
/// a later task's concern — [`MerkleTree::from_chunks`] accepts any chunk iterator, in-memory or
/// not).
pub fn chunks_of(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.chunks(CHUNK_SIZE)
}

/// Which side of its parent a sibling hash sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Left,
    Right,
}

/// One step of a merkle proof, from a leaf toward the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStep {
    /// Combine the running hash with `hash` on the given `side` (`BLAKE3(left ‖ right)`).
    Sibling {
        #[serde(with = "b32")]
        hash: Hash,
        side: Side,
    },
    /// This level's node had no sibling (odd node out) and was promoted unchanged — the running
    /// hash passes through this level untouched.
    Promoted,
}

/// A merkle inclusion proof for one chunk of a [`MerkleTree`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub steps: Vec<ProofStep>,
}

/// A BLAKE3 merkle tree built over a file's 64 KiB chunks. See the module doc for the exact,
/// pinned construction.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// `levels[0]` is the leaf level (one hash per chunk, file order); `levels.last()` is always
    /// exactly one hash — the root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Builds a tree from a sequence of chunks, in file order. Each item should be one
    /// [`CHUNK_SIZE`]-or-smaller chunk (only the last chunk of a real file may be shorter); this
    /// function does not itself enforce chunk sizing — it only hashes whatever byte slices it is
    /// given, in the order given — so callers that already have pre-sized chunks (e.g. streamed
    /// off disk) never have to buffer the whole file to build a tree over it.
    pub fn from_chunks<I>(chunks: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut leaves: Vec<Hash> = chunks.into_iter().map(|c| leaf_hash(c.as_ref())).collect();
        if leaves.is_empty() {
            // See the module doc's "Zero-chunk (empty file) convention" TODO.
            leaves.push(leaf_hash(&[]));
        }
        Self {
            levels: build_levels(leaves),
        }
    }

    /// Builds a tree over an in-memory file buffer, chunking it into [`CHUNK_SIZE`] pieces first.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self::from_chunks(chunks_of(data))
    }

    /// The merkle root — goes in [`crate::manifest::FileManifest::root`].
    pub fn root(&self) -> Hash {
        self.levels.last().expect("levels is never empty")[0]
    }

    /// Number of leaves (chunks) in the tree.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Builds an inclusion proof for the chunk at `leaf_index`, or `None` if out of range.
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        let leaf_count = self.leaf_count();
        if leaf_index >= leaf_count {
            return None;
        }
        let mut steps = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut idx = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            if idx.is_multiple_of(2) {
                if idx + 1 < level.len() {
                    steps.push(ProofStep::Sibling {
                        hash: level[idx + 1],
                        side: Side::Right,
                    });
                } else {
                    // Odd node out at this level: it was promoted unchanged, per the module doc.
                    steps.push(ProofStep::Promoted);
                }
            } else {
                steps.push(ProofStep::Sibling {
                    hash: level[idx - 1],
                    side: Side::Left,
                });
            }
            idx /= 2;
        }
        Some(MerkleProof {
            leaf_index,
            leaf_count,
            steps,
        })
    }
}

/// Bottom-up pairwise fold with odd-node promotion. See the module doc for the exact rules.
fn build_levels(leaves: Vec<Hash>) -> Vec<Vec<Hash>> {
    let mut levels = vec![leaves];
    while levels.last().expect("levels is never empty").len() > 1 {
        let prev = levels.last().expect("levels is never empty");
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < prev.len() {
            next.push(node_hash(&prev[i], &prev[i + 1]));
            i += 2;
        }
        if i < prev.len() {
            // Odd node out: promote unchanged rather than duplicate (see module doc).
            next.push(prev[i]);
        }
        levels.push(next);
    }
    levels
}

/// Verifies `chunk` against `proof` and an expected `root`. Recomputes only the path from this one
/// chunk to the root — never the whole tree — so it detects corruption in exactly the chunk it was
/// given a proof for.
///
/// Also cross-checks `proof.leaf_index` against the Left/Right/Promoted pattern of `proof.steps`
/// (see the module doc): each step's side must match `leaf_index`'s bit at that level, LSB first.
/// Without this, a party could relabel `leaf_index` on an otherwise-untouched, valid proof to
/// falsely claim a different chunk offset while `verify` still returned true.
pub fn verify(root: &Hash, proof: &MerkleProof, chunk: &[u8]) -> bool {
    if proof.leaf_index >= proof.leaf_count {
        return false;
    }
    let mut h = leaf_hash(chunk);
    let mut idx = proof.leaf_index;
    for step in &proof.steps {
        let idx_is_even = idx.is_multiple_of(2);
        h = match step {
            ProofStep::Sibling {
                hash,
                side: Side::Right,
            } => {
                if !idx_is_even {
                    return false;
                }
                node_hash(&h, hash)
            }
            ProofStep::Sibling {
                hash,
                side: Side::Left,
            } => {
                if idx_is_even {
                    return false;
                }
                node_hash(hash, &h)
            }
            ProofStep::Promoted => {
                if !idx_is_even {
                    return false;
                }
                h
            }
        };
        idx /= 2;
    }
    // All of `leaf_index`'s bits must have been consumed by the proof's step count — otherwise an
    // out-of-range or aliased `leaf_index` (e.g. `real_index + leaf_count.next_power_of_two()`)
    // whose low bits happen to match the steps' side pattern would still pass.
    if idx != 0 {
        return false;
    }
    &h == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chunks(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| vec![i as u8; CHUNK_SIZE.min(17 + i)])
            .collect()
    }

    #[test]
    fn single_chunk_root_is_its_own_leaf_hash() {
        let chunk = b"hello, meridian".to_vec();
        let tree = MerkleTree::from_chunks(vec![chunk.clone()]);
        assert_eq!(tree.root(), leaf_hash(&chunk));
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn odd_leaf_count_promotes_rather_than_duplicates() {
        // 3 leaves: level0 = [a,b,c] -> level1 = [hash(a,b), c] -> level2(root) = hash(hash(a,b), c)
        let chunks = sample_chunks(3);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let a = leaf_hash(&chunks[0]);
        let b = leaf_hash(&chunks[1]);
        let c = leaf_hash(&chunks[2]);
        let expected_root = node_hash(&node_hash(&a, &b), &c);
        assert_eq!(tree.root(), expected_root);

        // If promotion were instead "duplicate the last leaf", the root would differ.
        let duplicated_root = node_hash(&node_hash(&a, &b), &node_hash(&c, &c));
        assert_ne!(tree.root(), duplicated_root);
    }

    #[test]
    fn even_leaf_count_pairs_cleanly() {
        let chunks = sample_chunks(4);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let hashes: Vec<Hash> = chunks.iter().map(|c| leaf_hash(c)).collect();
        let expected_root = node_hash(
            &node_hash(&hashes[0], &hashes[1]),
            &node_hash(&hashes[2], &hashes[3]),
        );
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn every_chunk_across_varied_counts_verifies_against_the_root() {
        for n in [1, 2, 3, 4, 5, 7, 8, 13, 16, 33] {
            let chunks = sample_chunks(n);
            let tree = MerkleTree::from_chunks(chunks.clone());
            let root = tree.root();
            for (i, chunk) in chunks.iter().enumerate() {
                let proof = tree.proof(i).expect("index in range");
                assert_eq!(proof.leaf_index, i);
                assert_eq!(proof.leaf_count, n);
                assert!(verify(&root, &proof, chunk), "chunk {i} of {n} must verify");
            }
        }
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        let tree = MerkleTree::from_chunks(sample_chunks(3));
        assert!(tree.proof(3).is_none());
        assert!(tree.proof(100).is_none());
    }

    #[test]
    fn empty_file_builds_a_deterministic_single_leaf_tree() {
        let tree = MerkleTree::from_bytes(&[]);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), leaf_hash(&[]));
    }

    /// Corruption detection: flipping one byte in one chunk must fail verification for *that*
    /// chunk's proof, while every other chunk's own (unrelated) proof still verifies fine against
    /// the same, unmodified root.
    #[test]
    fn flipping_a_byte_in_one_chunk_fails_only_that_chunks_proof() {
        let chunks = sample_chunks(8);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let root = tree.root();

        let corrupt_index = 3;
        let mut corrupted = chunks[corrupt_index].clone();
        corrupted[0] ^= 0x01;

        let corrupt_proof = tree.proof(corrupt_index).unwrap();
        assert!(
            !verify(&root, &corrupt_proof, &corrupted),
            "corrupted chunk must fail verification"
        );
        // The proof is still valid for the *original* bytes.
        assert!(verify(&root, &corrupt_proof, &chunks[corrupt_index]));

        // Every other chunk's own proof is unaffected.
        for (i, chunk) in chunks.iter().enumerate() {
            if i == corrupt_index {
                continue;
            }
            let proof = tree.proof(i).unwrap();
            assert!(verify(&root, &proof, chunk), "chunk {i} must still verify");
        }
    }

    #[test]
    fn proof_for_wrong_chunk_index_fails() {
        let chunks = sample_chunks(5);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let root = tree.root();
        let proof_for_1 = tree.proof(1).unwrap();
        assert!(!verify(&root, &proof_for_1, &chunks[2]));
    }

    /// Regression for the leaf/internal-node type-confusion finding: before domain separation,
    /// `leaf_hash(chunk) == BLAKE3(chunk)` and `node_hash(l, r) == BLAKE3(l ‖ r)` were the *same*
    /// function of their input bytes, so the two 32-byte values an attacker learns from any single
    /// legitimate proof (their own running hash and the proof's final revealed sibling) could be
    /// concatenated into a forged 64-byte, one-chunk "file" whose root collided with the real,
    /// multi-chunk file's root. Domain-separation prefixes (`0x00` for leaves, `0x01` for internal
    /// nodes) must make those two roots different.
    #[test]
    fn domain_separation_prevents_leaf_node_type_confusion_forgery() {
        // Power-of-two leaf count: every level pairs cleanly, so the top fold is guaranteed to be
        // a genuine two-child `node_hash`, never a `Promoted` passthrough.
        let chunks = sample_chunks(4);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let real_root = tree.root();

        let proof = tree.proof(0).expect("index in range");
        assert!(proof.steps.len() >= 2, "need at least one non-final step");

        // Recompute the running hash up to (but not including) the proof's last fold step — this
        // is exactly what any holder of this one proof can compute for themselves.
        let mut running = leaf_hash(&chunks[0]);
        for step in &proof.steps[..proof.steps.len() - 1] {
            running = match step {
                ProofStep::Sibling {
                    hash,
                    side: Side::Right,
                } => node_hash(&running, hash),
                ProofStep::Sibling {
                    hash,
                    side: Side::Left,
                } => node_hash(hash, &running),
                ProofStep::Promoted => running,
            };
        }

        // The last step's two inputs are the pair the real root's final `node_hash` was computed
        // over — both learnable from this single proof.
        let (left, right) = match proof.steps.last().unwrap() {
            ProofStep::Sibling {
                hash,
                side: Side::Right,
            } => (running, *hash),
            ProofStep::Sibling {
                hash,
                side: Side::Left,
            } => (*hash, running),
            ProofStep::Promoted => panic!("power-of-two leaf count never promotes at the top"),
        };

        // Forge a single 64-byte "file": one chunk = those two learned hashes, concatenated.
        let mut forged_chunk = Vec::with_capacity(64);
        forged_chunk.extend_from_slice(&left);
        forged_chunk.extend_from_slice(&right);
        let forged_tree = MerkleTree::from_bytes(&forged_chunk);
        assert_eq!(forged_tree.leaf_count(), 1);
        let forged_root = forged_tree.root();

        assert_ne!(
            real_root, forged_root,
            "domain separation must prevent a forged single-chunk file from colliding with a \
             real multi-chunk file's root"
        );
    }

    /// Regression for the leaf-index relabeling finding: mutating only `leaf_index` on an
    /// otherwise-valid proof (same `steps`) must now be rejected, since `verify` cross-checks
    /// `leaf_index`'s bit pattern against each step's Left/Right/Promoted side.
    #[test]
    fn verify_rejects_a_proof_whose_leaf_index_was_relabeled() {
        let chunks = sample_chunks(5);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let root = tree.root();

        let mut proof = tree.proof(1).expect("index in range");
        assert!(
            verify(&root, &proof, &chunks[1]),
            "unmodified proof must still verify"
        );

        // Relabel only the leaf_index, keep the exact same steps.
        proof.leaf_index = 2;
        assert!(
            !verify(&root, &proof, &chunks[1]),
            "verify must reject a proof whose leaf_index doesn't match its steps' side pattern"
        );
    }

    /// Regression for the leaf_index-aliasing gap found in re-verification: a `leaf_index` that is
    /// congruent to the real index modulo `2^(number of proof steps)` — but otherwise out of range
    /// or arbitrarily large — must still be rejected, even though it happens to match the steps'
    /// Left/Right/Promoted bit pattern exactly (since only the low bits were ever checked). This
    /// mirrors the reviewer's exact PoC: a valid proof for real leaf index 4 of a 5-leaf tree,
    /// relabeled to `4 + leaf_count.next_power_of_two()`.
    #[test]
    fn verify_rejects_a_proof_whose_leaf_index_was_aliased_out_of_range() {
        let chunks = sample_chunks(5);
        let tree = MerkleTree::from_chunks(chunks.clone());
        let root = tree.root();

        let real_index = 4;
        let mut proof = tree.proof(real_index).expect("index in range");
        assert!(
            verify(&root, &proof, &chunks[real_index]),
            "unmodified proof must still verify"
        );

        // Alias leaf_index by adding leaf_count's next power of two (8): 4 + 8 = 12, which is
        // out of range for a 5-leaf tree (leaf_count = 5) but shares the same low bits as 4 over
        // the proof's step count, so a bit-pattern-only check would wrongly accept it.
        let aliased = real_index + proof.leaf_count.next_power_of_two();
        proof.leaf_index = aliased;
        assert!(
            !verify(&root, &proof, &chunks[real_index]),
            "verify must reject an out-of-range leaf_index alias ({aliased} for leaf_count {})",
            proof.leaf_count
        );

        // A second, arbitrarily large alias (not just leaf_count-adjacent) must also be rejected.
        proof.leaf_index = real_index + (1 << 20);
        assert!(
            !verify(&root, &proof, &chunks[real_index]),
            "verify must reject an arbitrarily large aliased leaf_index"
        );
    }
}
