//! Conformance against the published fixtures (`test-vectors/identity-v1.json`).
//!
//! testing/strategy.md §1: every client must reproduce these byte-identically. This test is the
//! Rust/CLI side of that contract; WASM/mobile run the same JSON. Regenerate with
//! `cargo run -p xtask -- vectors`.

use meridian_identity::{parse_id, same_principal, to_id_string, IdError};
use serde_json::Value;

fn load() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/identity-v1.json"
    );
    let bytes = std::fs::read(path).expect("test-vectors/identity-v1.json must exist");
    serde_json::from_slice(&bytes).expect("fixtures are valid JSON")
}

/// Canonical variant name a parser must report for a given error.
fn error_name(e: &IdError) -> &'static str {
    match e {
        IdError::MissingScheme => "MissingScheme",
        IdError::MalformedStructure => "MalformedStructure",
        IdError::NonCanonicalCase => "NonCanonicalCase",
        IdError::BadBase32 => "BadBase32",
        IdError::BadLength { .. } => "BadLength",
        IdError::UnknownMulticodec => "UnknownMulticodec",
        IdError::ChecksumMismatch => "ChecksumMismatch",
        IdError::BadHint(_) => "BadHint",
        IdError::BadPublicKey => "BadPublicKey",
    }
}

#[test]
fn valid_vectors_reproduce_byte_identically() {
    let fixtures = load();
    for v in fixtures["valid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let pubkey_hex = v["pubkey_hex"].as_str().unwrap();
        let hint = v["hint"].as_str().unwrap();
        let expected_id = v["id"].as_str().unwrap();

        let pk: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();

        // Encode side: our string equals the fixture byte-for-byte.
        let got = to_id_string(&pk, hint).unwrap();
        assert_eq!(got, expected_id, "encode mismatch for vector: {name}");

        // Parse side: the fixture ID decodes back to the same key + hint.
        let parsed =
            parse_id(expected_id).unwrap_or_else(|e| panic!("parse failed for {name}: {e}"));
        assert_eq!(parsed.pubkey(), &pk, "parsed key mismatch for {name}");
        assert_eq!(parsed.hint(), hint, "parsed hint mismatch for {name}");
    }
}

#[test]
fn invalid_vectors_are_rejected_with_the_right_error() {
    let fixtures = load();
    for v in fixtures["invalid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let id = v["id"].as_str().unwrap();
        let expected = v["error"].as_str().unwrap();

        match parse_id(id) {
            Ok(_) => panic!("invalid vector accepted: {name} ({id})"),
            Err(e) => assert_eq!(error_name(&e), expected, "wrong error for {name}: got {e}"),
        }
    }
}

#[test]
fn same_principal_vectors() {
    let fixtures = load();
    for v in fixtures["same_principal"].as_array().unwrap() {
        let a = parse_id(v["a"].as_str().unwrap()).unwrap();
        let b = parse_id(v["b"].as_str().unwrap()).unwrap();
        assert_eq!(same_principal(&a, &b), v["same"].as_bool().unwrap());
    }
}
