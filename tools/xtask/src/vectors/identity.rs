//! Generate the T01 identity conformance fixtures (`test-vectors/identity-v1.json`).
//!
//! These are the cross-implementation source of truth (testing/strategy.md §1): every client — CLI,
//! WASM, mobile — must reproduce them byte-identically. The vectors are derived deterministically
//! from fixed seeds using `meridian-identity`, so regenerating is reproducible.

use meridian_identity::{encode_key_part, pubkey_from_seed, to_id_string, SCHEME};
use serde::Serialize;

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    format: Format,
    valid: Vec<Valid>,
    invalid: Vec<Invalid>,
    same_principal: Vec<SamePrincipal>,
}

#[derive(Serialize)]
struct Format {
    scheme: String,
    multicodec_hex: String,
    pubkey_len: usize,
    checksum: String,
    checksum_len: usize,
    base32: String,
}

#[derive(Serialize)]
struct Valid {
    name: String,
    seed_hex: String,
    pubkey_hex: String,
    hint: String,
    id: String,
}

#[derive(Serialize)]
struct Invalid {
    name: String,
    id: String,
    /// The `IdError` variant name a conforming parser must return.
    error: String,
}

#[derive(Serialize)]
struct SamePrincipal {
    a: String,
    b: String,
    same: bool,
}

fn valid_vector(name: &str, seed: [u8; 32], hint: &str) -> Valid {
    let pubkey = *pubkey_from_seed(&seed).as_bytes();
    Valid {
        name: name.to_string(),
        seed_hex: hex::encode(seed),
        pubkey_hex: hex::encode(pubkey),
        hint: hint.to_string(),
        id: to_id_string(&pubkey, hint).expect("hint is canonical in fixtures"),
    }
}

pub fn generate_identity() -> Result<(), String> {
    let seed_zero = [0u8; 32];
    let seed_one = [1u8; 32];
    let seed_ff = [0xffu8; 32];
    let mut seed_iota = [0u8; 32];
    for (i, b) in seed_iota.iter_mut().enumerate() {
        *b = i as u8;
    }
    let seed_seven = [7u8; 32];

    let valid = vec![
        valid_vector("all-zero seed", seed_zero, "chat.example"),
        valid_vector("all-one seed", seed_one, "chat.org-a.example"),
        valid_vector("all-0xff seed", seed_ff, "a"),
        valid_vector(
            "iota seed, punycode IDN hint",
            seed_iota,
            "xn--nxasmq6b.example",
        ),
        valid_vector(
            "seven seed, digit-label hint",
            seed_seven,
            "node1.chat.example",
        ),
    ];

    // Build invalid cases by corrupting the first valid ID.
    let base = &valid[0].id;
    let key_part = &base[SCHEME.len()..base.find('@').unwrap()];
    let hint = &base[base.find('@').unwrap() + 1..];

    // Flip a byte in the middle of the key part → checksum fails.
    let mut corrupt: Vec<char> = key_part.chars().collect();
    let mid = corrupt.len() / 2;
    corrupt[mid] = if corrupt[mid] == 'a' { 'b' } else { 'a' };
    let corrupt_key: String = corrupt.into_iter().collect();

    let invalid = vec![
        Invalid {
            name: "flipped key byte (checksum mismatch)".into(),
            id: format!("{SCHEME}{corrupt_key}@{hint}"),
            error: "ChecksumMismatch".into(),
        },
        Invalid {
            name: "uppercase key part (non-canonical case)".into(),
            id: format!("{SCHEME}{}@{hint}", key_part.to_uppercase()),
            error: "NonCanonicalCase".into(),
        },
        Invalid {
            name: "missing mrd1 scheme".into(),
            id: format!("{key_part}@{hint}"),
            error: "MissingScheme".into(),
        },
        Invalid {
            name: "no @ separator".into(),
            id: format!("{SCHEME}{key_part}"),
            error: "MalformedStructure".into(),
        },
        Invalid {
            name: "homoglyph hint (Cyrillic 'а')".into(),
            id: format!("{SCHEME}{key_part}@chat.ex\u{0430}mple"),
            error: "BadHint".into(),
        },
        Invalid {
            name: "hint with forbidden slash".into(),
            id: format!("{SCHEME}{key_part}@chat.example/x"),
            error: "BadHint".into(),
        },
        Invalid {
            name: "empty hint".into(),
            id: format!("{SCHEME}{key_part}@"),
            error: "BadHint".into(),
        },
    ];

    // Same principal: one key, two different hints.
    let pk_seven = *pubkey_from_seed(&seed_seven).as_bytes();
    let key_seven = encode_key_part(&pk_seven);
    let same_principal = vec![SamePrincipal {
        a: format!("{SCHEME}{key_seven}@chat.org-a.example"),
        b: format!("{SCHEME}{key_seven}@chat.org-b.example"),
        same: true,
    }];

    let fixtures = Fixtures {
        version: 1,
        note: "T01 identity conformance vectors — cross-implementation source of truth. \
               Regenerate with `cargo run -p xtask -- vectors`. Frozen format: docs/api/identity-format.md."
            .into(),
        format: Format {
            scheme: SCHEME.into(),
            multicodec_hex: "ed01".into(),
            pubkey_len: 32,
            checksum: "crc32c-castagnoli-big-endian".into(),
            checksum_len: 4,
            base32: "rfc4648-lowercase-nopad".into(),
        },
        valid,
        invalid,
        same_principal,
    };

    super::write_json(&super::vector_path("identity-v1.json"), &fixtures)
}
