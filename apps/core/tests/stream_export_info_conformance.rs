//! Conformance-vector gate for `stream_export_info` (task 11.7, review finding F7): re-derive every
//! committed `test-vectors/session-substrate-v1.json` `stream_export_info` vector via
//! [`meridian_core::test_support::stream_export_info`] — the crate's *real* byte-layout function,
//! exposed only for exactly this purpose (see `apps/core/src/lib.rs`'s `test_support` module doc) —
//! and assert byte-for-byte equality against the committed `info_hex`.
//!
//! This mirrors `apps/crypto/tests/conformance.rs` / `apps/proto/tests/conformance.rs`'s existing
//! bar for wire-critical derivations: "the xtask generator produced a vector and it round-tripped
//! against itself" is not sufficient, because a self-consistent bug baked into both the generator
//! and the vector (e.g. a spec-divergent domain tag) would still pass that check. This file is what
//! actually gates CI against that class of drift for `stream_export_info` — per the task's
//! architect-ratified decision, the *only* one of this task's five wire surfaces that gets a
//! dedicated re-derivation test rather than relying on `xtask regenerate-and-diff` alone (the other
//! four are ordinary public serde/CBOR shapes already exercised by real round-trip/shape-assertion
//! unit tests in-crate).
//!
//! The second test below is the meta-proof this actually works — same spirit as
//! `apps/crypto/src/x3dh.rs::divergent_kdf_label_does_not_match_committed_vector`: mutating one byte
//! of the domain tag must make the real function's output stop matching the committed vector, or
//! this harness would not be able to distinguish "matches spec" from "matches whatever the code
//! currently emits".

use std::path::PathBuf;

use meridian_core::streams::StreamId;
use meridian_core::test_support::{stream_export_info, stream_export_info_tag};
use serde_json::Value;

fn load_vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("meridian-core lives at <root>/apps/core")
        .join("test-vectors")
        .join("session-substrate-v1.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

#[test]
fn stream_export_info_matches_every_committed_vector() {
    let json = load_vectors();
    let vectors = json["stream_export_info"]
        .as_array()
        .expect("stream_export_info array present");
    assert!(
        vectors.len() >= 3,
        "expected at least the canonical/sid-zero/sid-max cases"
    );

    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let ty = vector["ty"].as_str().expect("ty");
        let sid: StreamId = vector["sid"]
            .as_u64()
            .unwrap_or_else(|| panic!("vector '{name}': sid must fit a u64"));
        let expected = hex::decode(vector["info_hex"].as_str().expect("info_hex"))
            .unwrap_or_else(|e| panic!("vector '{name}': info_hex: {e}"));

        let actual = stream_export_info(ty, sid);
        assert_eq!(
            actual, expected,
            "vector '{name}': stream_export_info({ty:?}, {sid}) diverged from the committed vector"
        );
    }
}

#[test]
fn divergent_domain_tag_does_not_match_committed_vector() {
    // Same raw inputs as the committed "canonical" vector.
    let json = load_vectors();
    let vectors = json["stream_export_info"].as_array().expect("array");
    let canonical = vectors
        .iter()
        .find(|v| v["name"] == "canonical")
        .expect("canonical vector present");
    let ty = canonical["ty"].as_str().expect("ty");
    let sid: StreamId = canonical["sid"].as_u64().expect("sid");
    let expected = hex::decode(canonical["info_hex"].as_str().expect("info_hex")).unwrap();

    // Sanity: the real function matches the committed vector.
    assert_eq!(stream_export_info(ty, sid), expected);

    // Reproduce the real construction (tag || ty || sid:u64-be, apps/core/src/session.rs) by hand,
    // but starting from a mutated *copy of the real* domain-tag constant (not an independently
    // hardcoded literal that could itself silently drift from it) with one byte flipped —
    // simulating exactly the class of bug this harness exists to catch (a spec-divergent domain
    // tag). Mirrors `apps/crypto/src/x3dh.rs::divergent_kdf_label_does_not_match_committed_vector`,
    // which likewise mutates a copy of the real `X3DH_INFO` constant rather than a literal.
    let mut mutated_tag = stream_export_info_tag().to_vec();
    let last = mutated_tag.len() - 1;
    mutated_tag[last] ^= 0x01;
    let mut mutated_info = mutated_tag;
    mutated_info.extend_from_slice(ty.as_bytes());
    mutated_info.extend_from_slice(&sid.to_be_bytes());

    assert_ne!(
        mutated_info, expected,
        "a mutated domain tag must NOT reproduce the committed vector — if it does, this harness \
         cannot catch a spec-divergent domain tag"
    );
}
