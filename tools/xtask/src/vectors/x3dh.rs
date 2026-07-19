//! X3DH conformance fixtures (`test-vectors/x3dh-v1.json`).
//!
//! The derived root/shared-header keys (`root`/`hka`/`nhkb`/`ad`) come straight from
//! [`meridian_crypto::x3dh::respond`] — the crate's real derivation code — fed with fixed,
//! deterministic inputs (a store-backed responder identity seed plus raw X25519 secrets/pubkeys
//! for the ephemeral/prekey legs) so the whole handshake is byte-reproducible.
//!
//! The individual DH1..DH4 legs are recorded too, computed via
//! [`meridian_crypto::test_support::dh`]/[`meridian_crypto::test_support::ed25519_pub_to_x25519`]
//! (the crate's real X25519/Ed25519→X25519 primitives — not a reimplementation), so a from-scratch
//! implementation has every intermediate needed to reproduce the final derivation independently.

use meridian_crypto::test_support::{dh, ed25519_pub_to_x25519};
use meridian_crypto::x3dh;
use meridian_identity::pubkey_from_seed;
use meridian_store::{MemorySecretStore, SecretStore, SignOrDh};
use serde::Serialize;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    vectors: Vec<Vector>,
}

#[derive(Serialize)]
struct Inputs {
    /// Responder (Bob)'s Ed25519 account seed — stored in a `MemorySecretStore` so the
    /// `DH(IK_B, ·)` leg runs through the real `SecretStore::use_key` code path.
    responder_ik_seed_hex: String,
    responder_ik_pub_hex: String,
    /// Initiator (Alice)'s Ed25519 account seed — only her public key is an X3DH input; the seed
    /// is recorded so a reimplementation can derive it the same way.
    initiator_ik_seed_hex: String,
    initiator_ik_pub_hex: String,
    /// Bob's signed-prekey X25519 secret/public pair.
    spk_secret_hex: String,
    spk_pub_hex: String,
    /// Bob's one-time-prekey X25519 secret/public pair (omitted in the no-OPK vector).
    #[serde(skip_serializing_if = "Option::is_none")]
    opk_secret_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opk_pub_hex: Option<String>,
    /// Alice's ephemeral X25519 public key (the only ephemeral value `x3dh::respond` needs).
    ek_a_pub_hex: String,
}

#[derive(Serialize)]
struct DhLegs {
    /// `DH(IK_A, SPK_B)` — computed as `DH(SPK_B_secret, ed25519_pub_to_x25519(IK_A))`.
    dh1_hex: String,
    /// `DH(EK_A, IK_B)` — computed via the real store: `SecretStore::use_key(IK_B, Dh, EK_A_pub)`.
    dh2_hex: String,
    /// `DH(EK_A, SPK_B)`.
    dh3_hex: String,
    /// `DH(EK_A, OPK_B)` — present only in the with-OPK vector.
    #[serde(skip_serializing_if = "Option::is_none")]
    dh4_hex: Option<String>,
}

#[derive(Serialize)]
struct Derived {
    root_hex: String,
    hka_hex: String,
    nhkb_hex: String,
    ad_hex: String,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    inputs: Inputs,
    /// `0xFF * 32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4]` — the exact HKDF input `x3dh::respond` builds.
    ikm_hex: String,
    dh_legs: DhLegs,
    derived: Derived,
}

fn x25519_pub(secret: &[u8; 32]) -> [u8; 32] {
    XPublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

fn build_vector(
    name: &str,
    responder_ik_seed: [u8; 32],
    initiator_ik_seed: [u8; 32],
    spk_secret: [u8; 32],
    opk_secret: Option<[u8; 32]>,
    ek_a_pub: [u8; 32],
) -> Result<Vector, String> {
    let responder_ik_pub = *pubkey_from_seed(&responder_ik_seed).as_bytes();
    let initiator_ik_pub = *pubkey_from_seed(&initiator_ik_seed).as_bytes();
    let spk_pub = x25519_pub(&spk_secret);
    let opk_pub = opk_secret.map(|s| x25519_pub(&s));

    let store = MemorySecretStore::new();
    let handle = store
        .store("responder-ik", &responder_ik_seed)
        .map_err(|e| e.to_string())?;

    // DH legs, computed independently via the crate's real X25519/store primitives (never
    // reimplemented) so the JSON carries every intermediate a from-scratch implementer needs.
    let peer_ik_x = ed25519_pub_to_x25519(&initiator_ik_pub).map_err(|e| e.to_string())?;
    let dh1 = dh(&spk_secret, &peer_ik_x);
    let dh2 = store
        .use_key(&handle, SignOrDh::Dh, &ek_a_pub)
        .map_err(|e| e.to_string())?;
    let dh3 = dh(&spk_secret, &ek_a_pub);
    let dh4 = opk_secret.map(|s| dh(&s, &ek_a_pub));

    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1.as_slice());
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(dh3.as_slice());
    if let Some(dh4) = &dh4 {
        ikm.extend_from_slice(dh4.as_slice());
    }

    // The real derivation: `x3dh::respond` (system-design §4.2, meridian-crypto's actual code).
    let result = x3dh::respond(
        &store,
        &handle,
        &responder_ik_pub,
        &initiator_ik_pub,
        &ek_a_pub,
        &spk_secret,
        opk_secret,
    )
    .map_err(|e| e.to_string())?;

    Ok(Vector {
        name: name.to_string(),
        inputs: Inputs {
            responder_ik_seed_hex: hex::encode(responder_ik_seed),
            responder_ik_pub_hex: hex::encode(responder_ik_pub),
            initiator_ik_seed_hex: hex::encode(initiator_ik_seed),
            initiator_ik_pub_hex: hex::encode(initiator_ik_pub),
            spk_secret_hex: hex::encode(spk_secret),
            spk_pub_hex: hex::encode(spk_pub),
            opk_secret_hex: opk_secret.map(hex::encode),
            opk_pub_hex: opk_pub.map(hex::encode),
            ek_a_pub_hex: hex::encode(ek_a_pub),
        },
        ikm_hex: hex::encode(&ikm),
        dh_legs: DhLegs {
            dh1_hex: hex::encode(dh1.as_slice()),
            dh2_hex: hex::encode(&dh2),
            dh3_hex: hex::encode(dh3.as_slice()),
            dh4_hex: dh4.as_ref().map(|d| hex::encode(d.as_slice())),
        },
        derived: Derived {
            root_hex: hex::encode(result.root),
            hka_hex: hex::encode(result.hka),
            nhkb_hex: hex::encode(result.nhkb),
            ad_hex: hex::encode(&result.ad),
        },
    })
}

pub fn generate_x3dh() -> Result<(), String> {
    let responder_ik_seed = [0x10u8; 32];
    let initiator_ik_seed = [0x20u8; 32];
    let spk_secret = [0x30u8; 32];
    let opk_secret = [0x40u8; 32];
    let ek_a_pub = x25519_pub(&[0x50u8; 32]);

    let vectors = vec![
        build_vector(
            "with-opk",
            responder_ik_seed,
            initiator_ik_seed,
            spk_secret,
            Some(opk_secret),
            ek_a_pub,
        )?,
        build_vector(
            "without-opk",
            responder_ik_seed,
            initiator_ik_seed,
            spk_secret,
            None,
            ek_a_pub,
        )?,
    ];

    let fixtures = Fixtures {
        version: 1,
        note: "X3DH conformance vectors — cross-implementation source of truth. Regenerate with \
               `cargo run -p xtask -- vectors`. `derived.*` comes from meridian-crypto's real \
               `x3dh::respond`; `dh_legs`/`ikm_hex` are computed independently from the same raw \
               inputs via the crate's real X25519 primitives so a from-scratch reimplementation \
               can check every intermediate. Construction: docs/architecture/system-design.md \
               §4.2, apps/crypto/src/x3dh.rs."
            .into(),
        vectors,
    };

    super::write_json(&super::vector_path("x3dh-v1.json"), &fixtures)
}
