//! `mrd.file/1` conformance fixtures (`test-vectors/file-transfer-v1.json`, task 11.7, review
//! finding F7).
//!
//! Phase 10 shipped three new, wire-relevant `meridian-streams` shapes with real round-trip/shape
//! unit tests in-crate but no byte-fixed conformance vector: [`FileManifest`]'s CBOR encoding
//! (task 10.3), the BLAKE3 merkle leaf/internal-node construction plus [`ChunkFrame`]'s CBOR
//! encoding (tasks 10.3/10.5/10.7), and the resume-bitmap byte layout (task 10.9). This is the
//! architect-ratified first `meridian-streams` vector file (Phase 11 review, finding F7) — see
//! `docs/tasks/phase-11/11.7-file-transfer-conformance-vectors.md`'s Risks/notes for the ratified
//! file grouping and boundary-case list this module implements.
//!
//! Every value below comes from the crate's real `MerkleTree`/`seal_chunk`/`FileManifest`/
//! `ChunkFrame`/`ResumeRequest` code — never a parallel reimplementation. Per the architect's
//! ratified decision, this is one of the four wire surfaces where `xtask regenerate-and-diff`
//! self-consistency (already asserted below via each case's own round-trip/`verify` check) is
//! sufficient — no dedicated re-derivation test is required, matching the accepted
//! `federation-v1.json` precedent (the fifth surface, `stream_export_info`, is different: see
//! `session_substrate.rs` and `apps/core/tests/stream_export_info_conformance.rs`).

use meridian_streams::{
    seal_chunk, verify, ChunkFrame, FileManifest, MerkleTree, ProofStep, ResumeRequest, Side,
};
use serde::Serialize;

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    manifest: Vec<ManifestVector>,
    chunk_and_merkle: Vec<ChunkMerkleVector>,
    resume_bitmap: Vec<ResumeVector>,
}

#[derive(Serialize)]
struct ManifestVector {
    name: String,
    note: String,
    name_field: String,
    size: u64,
    root_hex: String,
    key_hex: String,
    /// `FileManifest::encode()` — the exact bytes carried inside the ratchet-sealed `mrd.ctrl/1`
    /// `Open` params.
    encoded_hex: String,
}

fn build_manifest(
    name: &str,
    note: &str,
    file_name: &str,
    size: u64,
    root: [u8; 32],
    key: Vec<u8>,
) -> Result<ManifestVector, String> {
    let manifest = FileManifest {
        name: file_name.to_string(),
        size,
        root,
        key: key.clone(),
    };
    let bytes = manifest.encode().map_err(|e| e.to_string())?;
    let back = FileManifest::decode(&bytes).map_err(|e| e.to_string())?;
    if back != manifest {
        return Err(format!(
            "file-transfer vector 'manifest/{name}': decode(encode(_)) did not round-trip"
        ));
    }
    Ok(ManifestVector {
        name: name.to_string(),
        note: note.to_string(),
        name_field: file_name.to_string(),
        size,
        root_hex: hex::encode(root),
        key_hex: hex::encode(&key),
        encoded_hex: hex::encode(&bytes),
    })
}

#[derive(Serialize)]
struct ChunkMerkleVector {
    name: String,
    note: String,
    /// Every chunk's plaintext bytes, in file order — the exact inputs `MerkleTree::from_chunks`
    /// hashed.
    chunk_hex: Vec<String>,
    leaf_count: usize,
    root_hex: String,
    /// The proof this vector pins, for `proof_leaf_index`.
    proof_leaf_index: usize,
    proof_steps: Vec<serde_json::Value>,
    /// The `ChunkFrame` this vector also pins, for the same `proof_leaf_index` chunk.
    chunk_frame: ChunkFrameVector,
}

#[derive(Serialize)]
struct ChunkFrameVector {
    k_f_hex: String,
    i: u64,
    plaintext_hex: String,
    /// `seal_chunk(k_f, i, plaintext)` — this frame's `data` field.
    sealed_data_hex: String,
    /// `ChunkFrame { i, data: sealed }.encode()` — the exact `mrd.file/1` wire bytes.
    encoded_hex: String,
}

fn proof_step_json(step: &ProofStep) -> serde_json::Value {
    match step {
        ProofStep::Sibling { hash, side } => serde_json::json!({
            "kind": "sibling",
            "side": match side {
                Side::Left => "left",
                Side::Right => "right",
            },
            "hash_hex": hex::encode(hash),
        }),
        ProofStep::Promoted => serde_json::json!({ "kind": "promoted" }),
    }
}

fn build_chunk_and_merkle(
    name: &str,
    note: &str,
    chunks: Vec<Vec<u8>>,
    proof_leaf_index: usize,
    k_f: [u8; 32],
) -> Result<ChunkMerkleVector, String> {
    let tree = MerkleTree::from_chunks(chunks.clone());
    let root = tree.root();
    let proof = tree.proof(proof_leaf_index).ok_or_else(|| {
        format!("file-transfer vector '{name}': leaf index {proof_leaf_index} out of range")
    })?;
    if !verify(&root, &proof, &chunks[proof_leaf_index]) {
        return Err(format!(
            "file-transfer vector '{name}': generated proof does not verify against its own root"
        ));
    }

    let plaintext = chunks[proof_leaf_index].clone();
    let i = proof_leaf_index as u64;
    let sealed = seal_chunk(&k_f, i, &plaintext);
    let frame = ChunkFrame {
        i,
        data: sealed.clone(),
    };
    let encoded = frame.encode().map_err(|e| e.to_string())?;
    let decoded = ChunkFrame::decode(&encoded).map_err(|e| e.to_string())?;
    if decoded != frame {
        return Err(format!(
            "file-transfer vector '{name}': ChunkFrame decode(encode(_)) did not round-trip"
        ));
    }

    Ok(ChunkMerkleVector {
        name: name.to_string(),
        note: note.to_string(),
        chunk_hex: chunks.iter().map(hex::encode).collect(),
        leaf_count: tree.leaf_count(),
        root_hex: hex::encode(root),
        proof_leaf_index,
        proof_steps: proof.steps.iter().map(proof_step_json).collect(),
        chunk_frame: ChunkFrameVector {
            k_f_hex: hex::encode(k_f),
            i,
            plaintext_hex: hex::encode(&plaintext),
            sealed_data_hex: hex::encode(&sealed),
            encoded_hex: hex::encode(&encoded),
        },
    })
}

#[derive(Serialize)]
struct ResumeVector {
    name: String,
    leaf_count: usize,
    /// Chunk indices the (fictional) receiver has already received-and-verified.
    received: Vec<u64>,
    /// `ResumeRequest::from_received(received, leaf_count).bitmap` — LSB-first per byte, `1` =
    /// still missing (module doc: `apps/streams/src/resume.rs`).
    bitmap_hex: String,
    missing_indices: Vec<u64>,
    /// `ResumeRequest { bitmap }.encode()` — the `mrd.file/1` in-stream `FRAME_TAG_RESUME` body.
    encoded_hex: String,
}

fn build_resume(name: &str, leaf_count: usize, received: Vec<u64>) -> Result<ResumeVector, String> {
    let received_set: std::collections::BTreeSet<u64> = received.iter().copied().collect();
    let req = ResumeRequest::from_received(&received_set, leaf_count);
    let bytes = req.encode().map_err(|e| e.to_string())?;
    let back = ResumeRequest::decode(&bytes).map_err(|e| e.to_string())?;
    if back != req {
        return Err(format!(
            "file-transfer vector 'resume/{name}': decode(encode(_)) did not round-trip"
        ));
    }
    Ok(ResumeVector {
        name: name.to_string(),
        leaf_count,
        received,
        bitmap_hex: hex::encode(&req.bitmap),
        missing_indices: req.missing_indices(leaf_count),
        encoded_hex: hex::encode(&bytes),
    })
}

/// `chunks_of_lens([17, 18, 19])` — deterministic, distinct-content chunks of the given lengths,
/// each filled with its own index byte (matches `apps/streams/src/merkle.rs`'s own test
/// convention, `sample_chunks`, so a reviewer can cross-check by eye).
fn chunks_of_lens(lens: &[usize]) -> Vec<Vec<u8>> {
    lens.iter()
        .enumerate()
        .map(|(i, &len)| vec![i as u8; len])
        .collect()
}

pub fn generate_file_transfer() -> Result<(), String> {
    // --- chunk framing + BLAKE3 merkle construction --------------------------------------------
    let k_f = [0x42u8; 32];

    let power_of_two = build_chunk_and_merkle(
        "power-of-two-4-leaves",
        "A clean 4-leaf (power-of-two) tree: every level pairs cleanly, so the pinned proof (for \
         leaf 1) is Sibling/Sibling only — no ProofStep::Promoted.",
        chunks_of_lens(&[17, 18, 19, 20]),
        1,
        k_f,
    )?;

    let odd_leaf_count_promoted = build_chunk_and_merkle(
        "odd-leaf-count-promoted",
        "A 3-leaf tree: level0 = [a,b,c] -> level1 = [hash(a,b), c] -> root = hash(hash(a,b), c). \
         The pinned proof (for leaf 2, the odd node out) is Promoted then Sibling(Left) — this is \
         the exact odd-node-promotion construction a prior domain-separation-bug regression test \
         (apps/streams/src/merkle.rs) already covers functionally; this vector byte-pins it.",
        chunks_of_lens(&[17, 18, 19]),
        2,
        k_f,
    )?;

    let short_final_chunk = build_chunk_and_merkle(
        "short-final-chunk",
        "4 leaves, the last (index 3) far shorter than the others and not a power-of-two length \
         (7 bytes) — the real-world 'file length not a multiple of the chunk size' case. Leaf \
         count is even (no Promoted step here; that's the separate odd-leaf-count case above) — \
         this vector isolates the short-final-chunk leaf-hash byte layout specifically.",
        vec![
            vec![0xA0; 64],
            vec![0xA1; 64],
            vec![0xA2; 64],
            vec![0xA3; 7],
        ],
        3,
        k_f,
    )?;

    // --- FileManifest --------------------------------------------------------------------------
    let empty_tree = MerkleTree::from_bytes(&[]);
    let empty_manifest = build_manifest(
        "empty-file",
        "Zero-chunk (empty file) convention (merkle.rs module doc): a single virtual leaf whose \
         hash is BLAKE3(0x00) (the leaf domain-separation byte still applies) — root computed by \
         the real MerkleTree::from_bytes(&[]), not reproduced by hand.",
        "empty.bin",
        0,
        empty_tree.root(),
        vec![0xAAu8; 32],
    )?;

    let canonical_size: u64 = [17u64, 18, 19, 20].iter().sum();
    let canonical_root: [u8; 32] = {
        let bytes = hex::decode(&power_of_two.root_hex).expect("just-produced hex decodes");
        bytes.try_into().expect("merkle root is exactly 32 bytes")
    };
    let canonical_manifest = build_manifest(
        "canonical",
        "A typical non-empty manifest — `root` is the real merkle root of this same file's \
         `power-of-two-4-leaves` chunk_and_merkle vector above (74 bytes across 4 chunks), tying \
         the two sections together rather than using an unrelated hand-picked root.",
        "vacation.mp4",
        canonical_size,
        canonical_root,
        vec![0xBBu8; 32],
    )?;

    // --- resume bitmap ---------------------------------------------------------------------------
    let all_missing = build_resume("all-missing", 8, vec![])?;
    let all_present = build_resume("all-present", 8, (0..8).collect())?;
    // Mixed pattern crossing a byte boundary (architect-ratified case): 9 leaves needs 2 bytes;
    // receiving {0, 1, 3} exercises both a set and unset bit within byte 0 and the boundary into
    // byte 1, which a uniform all-0x00/all-0xFF bitmap can't pin (bit order, off-by-one).
    let mixed_boundary = build_resume("mixed-crossing-byte-boundary", 9, vec![0, 1, 3])?;

    let fixtures = Fixtures {
        version: 1,
        note: "mrd.file/1 conformance vectors (task 11.7, review finding F7): FileManifest CBOR \
               encoding, BLAKE3 merkle leaf/internal-node construction + ChunkFrame CBOR encoding, \
               and the resume-bitmap byte layout. Deterministic (fixed byte patterns, no \
               RNG/wall-clock). Regenerate with `cargo run -p xtask -- vectors`. Every value comes \
               from meridian-streams's real MerkleTree/seal_chunk/FileManifest/ChunkFrame/\
               ResumeRequest code. Spec: docs/api/stream-types-v1.md, docs/api/wire-protocol.md §6, \
               apps/streams/src/{manifest,chunk,merkle,resume}.rs. Locks in what Phase 10 already \
               shipped — see docs/tasks/phase-11/11.7-file-transfer-conformance-vectors.md."
            .into(),
        manifest: vec![empty_manifest, canonical_manifest],
        chunk_and_merkle: vec![power_of_two, odd_leaf_count_promoted, short_final_chunk],
        resume_bitmap: vec![all_missing, all_present, mixed_boundary],
    };

    super::write_json(&super::vector_path("file-transfer-v1.json"), &fixtures)
}
