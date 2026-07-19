//! Safety-number (fingerprint) conformance fixtures (`test-vectors/safety-numbers-v1.json`).
//!
//! `fingerprint::safety_number` (apps/crypto/src/fingerprint.rs) is a deterministic, iterated
//! SHA-512 construction with no randomness, so the full 60-digit output is byte(-digit)-pinned.

use meridian_crypto::{display_groups, safety_number};
use serde::Serialize;

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    vectors: Vec<Vector>,
    order_independence: Vec<OrderIndependence>,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    a_hex: String,
    b_hex: String,
    safety_number: String,
    display: String,
}

#[derive(Serialize)]
struct OrderIndependence {
    name: String,
    a_hex: String,
    b_hex: String,
    /// `safety_number(a, b) == safety_number(b, a)`.
    same: bool,
}

fn vector(name: &str, a: [u8; 32], b: [u8; 32]) -> Vector {
    let number = safety_number(&a, &b);
    Vector {
        name: name.to_string(),
        a_hex: hex::encode(a),
        b_hex: hex::encode(b),
        display: display_groups(&number),
        safety_number: number,
    }
}

pub fn generate_safety_numbers() -> Result<(), String> {
    let mut iota_a = [0u8; 32];
    for (i, b) in iota_a.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut iota_b = [0u8; 32];
    for (i, b) in iota_b.iter_mut().enumerate() {
        *b = (255 - i) as u8;
    }

    let vectors = vec![
        vector("all-zero pair", [0u8; 32], [0u8; 32]),
        vector("zero + all-one", [0u8; 32], [1u8; 32]),
        vector("all-0xff + all-0x01", [0xffu8; 32], [0x01u8; 32]),
        vector("iota ascending + iota descending", iota_a, iota_b),
        vector("seven + eleven", [7u8; 32], [11u8; 32]),
    ];

    let a = [0x10u8; 32];
    let b = [0x20u8; 32];
    let order_independence = vec![OrderIndependence {
        name: "safety_number(a, b) == safety_number(b, a)".into(),
        a_hex: hex::encode(a),
        b_hex: hex::encode(b),
        same: safety_number(&a, &b) == safety_number(&b, &a),
    }];

    let fixtures = Fixtures {
        version: 1,
        note: "Safety-number (fingerprint) conformance vectors — cross-implementation source of \
               truth. Regenerate with `cargo run -p xtask -- vectors`. Construction: iterated \
               SHA-512 per identity key (version-folded, 5200 rounds), concatenated in a \
               canonical (numerically sorted) key order so both peers derive the same 60-digit \
               number regardless of who computes it. Spec: docs/architecture/system-design.md \
               §4.4, apps/crypto/src/fingerprint.rs."
            .into(),
        vectors,
        order_independence,
    };

    super::write_json(&super::vector_path("safety-numbers-v1.json"), &fixtures)
}
