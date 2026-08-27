//! `MessageEnvelope` wire-encoding conformance fixtures (`test-vectors/envelope-v1.json` +
//! `test-vectors/envelope-v2.json`, task 6.5).
//!
//! **(task 6.3, ADR 0016 C2/C3/C5) `generate_envelope` (v1) is a deliberate, permanent no-op.**
//! Envelope v2 changed `MessageEnvelope` in place — a leading mandatory `v: u16`, and the
//! per-message `sig: [u8; 64]` signature field is gone entirely (authentication moved to the
//! ratchet AEAD). There is therefore no way to construct a v1-shaped `MessageEnvelope` from current
//! code any more: this is a hard flag day (R5), not a version this crate can still emit. Per task
//! 6.5's own scope ("the retained, untouched `generate_envelope` (v1)"), this function keeps doing
//! nothing — in particular it does NOT touch `test-vectors/envelope-v1.json`, which stays exactly
//! as committed — so `cargo run -p xtask -- vectors` keeps building and running cleanly across the
//! cutover, and the v1 fixture remains available as a frozen historical record even though nothing
//! can regenerate it from current code.
pub fn generate_envelope() -> Result<(), String> {
    Ok(())
}

use meridian_envelope::{MessageEnvelope, Prekey, ENVELOPE_VERSION};
use serde::Serialize;

#[derive(Serialize)]
struct FixturesV2 {
    version: u32,
    note: String,
    vectors: Vec<VectorV2>,
}

#[derive(Serialize)]
struct VectorV2 {
    name: String,
    v: u16,
    sender_pub_hex: String,
    eid_hex: String,
    prekey: Option<PrekeyV2>,
    ct_hex: String,
    blob_hex: String,
}

#[derive(Serialize)]
struct PrekeyV2 {
    ek_pub_hex: String,
    used_spk_hex: String,
    used_opk_hex: Option<String>,
}

/// `test-vectors/envelope-v2.json` — the v2 `MessageEnvelope` shape (task 6.3/6.4, ADR 0016
/// C2/C3/C5): a leading mandatory `v`, no `sig`, and the new `eid` dedup key, with `sender_pub`/
/// `prekey`/`ct` otherwise unchanged in shape from v1. Every `blob_hex` is produced by the crate's
/// real [`MessageEnvelope::to_blob`] (deterministic CBOR, ciborium — no per-run nondeterminism), so
/// this is a faithful re-encoding of the real wire shape, not a hand-authored guess at it.
pub fn generate_envelope_v2() -> Result<(), String> {
    let sender_pub = [0x77u8; 32];
    let eid = [0x99u8; 16];
    let ct = vec![0x01u8, 2, 3, 4, 5, 6, 7, 8];

    // (task 7.5, review finding F7) Boundary-shape cases beyond the three canonical near-identical-`ct`
    // vectors above. `ct-empty`/`ct-large` pair with the same maximal preamble as `prekey-with-opk` —
    // `Prekey`'s fields are fixed-width 32-byte arrays with no interaction bug to catch against `ct`, so
    // pairing the largest `ct` with the already-maximal preamble produces the single highest-value vector
    // (the true worst-case envelope) for regression-pinning aggregate size/length-prefix handling.
    // 65536 (architect-approved, task 7.5) is the existing `mrd.file/1` file-transfer chunk size
    // (docs/api/stream-types-v1.md:104) and, under ciborium's deterministic CBOR encoding, the first
    // value requiring a 4-byte length prefix — a real codec-class boundary, not an arbitrary size.
    const LARGE_CT_LEN: usize = 65536;

    let maximal_prekey = || {
        Some(Prekey {
            ek_pub: [0x22u8; 32],
            used_spk: [0x33u8; 32],
            used_opk: Some([0x44u8; 32]),
        })
    };

    let cases: Vec<(&str, Option<Prekey>, Vec<u8>)> = vec![
        ("no-prekey", None, ct.clone()),
        (
            "prekey-no-opk",
            Some(Prekey {
                ek_pub: [0x22u8; 32],
                used_spk: [0x33u8; 32],
                used_opk: None,
            }),
            ct.clone(),
        ),
        ("prekey-with-opk", maximal_prekey(), ct.clone()),
        ("ct-empty", maximal_prekey(), vec![]),
        ("ct-large", maximal_prekey(), vec![0xABu8; LARGE_CT_LEN]),
    ];

    let mut vectors = Vec::with_capacity(cases.len());
    for (name, prekey, ct) in cases {
        let env = MessageEnvelope {
            v: ENVELOPE_VERSION,
            sender_pub,
            eid,
            prekey: prekey.clone(),
            ct: ct.clone(),
        };
        let blob = env.to_blob().map_err(|e| e.to_string())?;

        // Self-consistency: the generator's own round trip must hold before it ever gets
        // committed. This is a sanity check on the generator, not a substitute for
        // `apps/crypto/tests/conformance.rs` independently re-deriving `blob_hex` from the real
        // encoder — that test is what actually gates drift.
        let decoded = MessageEnvelope::from_blob(&blob).map_err(|e| e.to_string())?;
        if decoded != env {
            return Err(format!(
                "envelope v2 vector '{name}': from_blob(to_blob(_)) round trip did not match"
            ));
        }

        vectors.push(VectorV2 {
            name: name.to_string(),
            v: env.v,
            sender_pub_hex: hex::encode(sender_pub),
            eid_hex: hex::encode(eid),
            prekey: prekey.map(|p| PrekeyV2 {
                ek_pub_hex: hex::encode(p.ek_pub),
                used_spk_hex: hex::encode(p.used_spk),
                used_opk_hex: p.used_opk.map(hex::encode),
            }),
            ct_hex: hex::encode(&ct),
            blob_hex: hex::encode(&blob),
        });
    }

    let fixtures = FixturesV2 {
        version: 2,
        note: "MessageEnvelope wire-encoding conformance vectors, v2 (deterministic CBOR, no \
               randomness). Regenerate with `cargo run -p xtask -- vectors`. v2 drops the \
               per-message `sig` field (ADR 0016) and adds a mandatory leading `v` and a `eid` \
               dedup key (task 6.4). Spec: docs/adr/0016-envelope-deniability.md, \
               apps/envelope/src/envelope.rs."
            .into(),
        vectors,
    };

    super::write_json(&super::vector_path("envelope-v2.json"), &fixtures)
}
