//! `MessageEnvelope` wire-encoding conformance fixtures (`test-vectors/envelope-v1.json`).
//!
//! Deterministic CBOR (`MessageEnvelope::to_blob`/`from_blob`, apps/proto/src/envelope.rs) over
//! fixed field values — no randomness anywhere in this path, so every byte is pinned exactly.

use meridian_envelope::{MessageEnvelope, Prekey};
use serde::Serialize;

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    vectors: Vec<Vector>,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    sender_pub_hex: String,
    prekey: Option<PrekeyFields>,
    ct_hex: String,
    sig_hex: String,
    /// `MessageEnvelope::to_blob()` — the exact bytes carried in a routing `OpaqueBlob`.
    blob_hex: String,
}

#[derive(Serialize)]
struct PrekeyFields {
    ek_pub_hex: String,
    used_spk_hex: String,
    used_opk_hex: Option<String>,
}

fn build_vector(name: &str, prekey: Option<Prekey>, ct: Vec<u8>) -> Result<Vector, String> {
    let sender_pub = [0x77u8; 32];
    let sig = {
        let mut s = [0u8; 64];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    };
    let env = MessageEnvelope {
        sender_pub,
        prekey: prekey.clone(),
        ct: ct.clone(),
        sig,
    };
    let blob = env.to_blob().map_err(|e| e.to_string())?;
    let decoded = MessageEnvelope::from_blob(&blob).map_err(|e| e.to_string())?;
    if decoded != env {
        return Err(format!(
            "envelope vector '{name}': from_blob(to_blob(_)) did not round-trip"
        ));
    }
    Ok(Vector {
        name: name.to_string(),
        sender_pub_hex: hex::encode(sender_pub),
        prekey: prekey.map(|p| PrekeyFields {
            ek_pub_hex: hex::encode(p.ek_pub),
            used_spk_hex: hex::encode(p.used_spk),
            used_opk_hex: p.used_opk.map(hex::encode),
        }),
        ct_hex: hex::encode(&ct),
        sig_hex: hex::encode(sig),
        blob_hex: hex::encode(&blob),
    })
}

pub fn generate_envelope() -> Result<(), String> {
    let ct = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let vectors = vec![
        build_vector("no-prekey", None, ct.clone())?,
        build_vector(
            "prekey-no-opk",
            Some(Prekey {
                ek_pub: [0x22u8; 32],
                used_spk: [0x33u8; 32],
                used_opk: None,
            }),
            ct.clone(),
        )?,
        build_vector(
            "prekey-with-opk",
            Some(Prekey {
                ek_pub: [0x22u8; 32],
                used_spk: [0x33u8; 32],
                used_opk: Some([0x44u8; 32]),
            }),
            ct,
        )?,
    ];

    let fixtures = Fixtures {
        version: 1,
        note: "MessageEnvelope wire-encoding conformance vectors (deterministic CBOR, no \
               randomness). Regenerate with `cargo run -p xtask -- vectors`. Spec: \
               docs/api/messaging-envelope-v1.md, apps/proto/src/envelope.rs."
            .into(),
        vectors,
    };

    super::write_json(&super::vector_path("envelope-v1.json"), &fixtures)
}
