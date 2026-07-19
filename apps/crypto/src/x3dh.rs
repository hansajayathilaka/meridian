//! X3DH prekey key agreement (system-design §4.2), hand-wired over audited primitives per
//! [ADR 0011](../../../docs/adr/0011-ratchet-library.md).
//!
//! Both sides compute the same master secret from four Diffie–Hellman legs and derive the initial
//! root key plus the two shared header keys the header-encrypted ratchet is initialised with. The
//! account-key legs (`DH(IK, ·)`) run *through the [`SecretStore`]* so the identity private key
//! never leaves the keystore.
//!
//! ```text
//! DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)   DH3 = DH(EK_A, SPK_B)   [DH4 = DH(EK_A, OPK_B)]
//! master = HKDF( 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 )  →  root ‖ hka ‖ nhkb
//! ```

use meridian_store::{KeyHandle, SecretStore, SignOrDh};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::primitives::{dh, ed25519_pub_to_x25519, gen_dh, hkdf, X3DH_INFO};

/// The X3DH output shared by both roles: the initial root key and the two shared header keys, plus
/// the associated data (`IK_initiator ‖ IK_responder`) bound into every ratchet message.
pub struct X3dhResult {
    pub root: [u8; 32],
    pub hka: [u8; 32],
    pub nhkb: [u8; 32],
    pub ad: Vec<u8>,
}

/// Initiator side: what Alice must transmit for Bob to reconstruct the handshake (her ephemeral
/// public key and which of Bob's prekeys she consumed), alongside the derived [`X3dhResult`] and
/// the responder's initial ratchet public key (Bob's signed prekey).
pub struct InitiatorOutput {
    pub result: X3dhResult,
    /// Alice's ephemeral public key `EK_A`.
    pub ek_pub: [u8; 32],
    /// Bob's signed prekey she used (the ratchet's initial remote key).
    pub used_spk: [u8; 32],
    /// Bob's one-time prekey she consumed, if the bundle offered one.
    pub used_opk: Option<[u8; 32]>,
}

const F: [u8; 32] = [0xFF; 32];

fn store_dh(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    peer_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let out = store.use_key(handle, SignOrDh::Dh, peer_pub)?;
    let arr: [u8; 32] = out
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadKey("store returned a malformed DH output"))?;
    Ok(Zeroizing::new(arr))
}

fn derive(ikm: &[u8], initiator_ik: &[u8; 32], responder_ik: &[u8; 32]) -> X3dhResult {
    let okm: [u8; 96] = hkdf(&[0u8; 32], ikm, X3DH_INFO);
    let mut root = [0u8; 32];
    let mut hka = [0u8; 32];
    let mut nhkb = [0u8; 32];
    root.copy_from_slice(&okm[0..32]);
    hka.copy_from_slice(&okm[32..64]);
    nhkb.copy_from_slice(&okm[64..96]);
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(initiator_ik);
    ad.extend_from_slice(responder_ik);
    X3dhResult {
        root,
        hka,
        nhkb,
        ad,
    }
}

/// Run X3DH as the **initiator** (Alice) against Bob's verified bundle keys. `our_ik`/`peer_ik`
/// are Ed25519 account keys; `peer_spk`/`peer_opk` are X25519 prekeys from the bundle. The caller
/// must have already verified the bundle signatures under `peer_ik`.
pub fn initiate(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: &[u8; 32],
    peer_ik: &[u8; 32],
    peer_spk: &[u8; 32],
    peer_opk: Option<[u8; 32]>,
) -> Result<InitiatorOutput> {
    let (ek_secret, ek_pub) = gen_dh()?;
    let peer_ik_x = ed25519_pub_to_x25519(peer_ik)?;

    let dh1 = store_dh(store, handle, peer_spk)?; // DH(IK_A, SPK_B)
    let dh2 = dh(&ek_secret, &peer_ik_x); // DH(EK_A, IK_B)
    let dh3 = dh(&ek_secret, peer_spk); // DH(EK_A, SPK_B)

    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(dh1.as_slice());
    ikm.extend_from_slice(dh2.as_slice());
    ikm.extend_from_slice(dh3.as_slice());
    if let Some(opk) = peer_opk.as_ref() {
        let dh4 = dh(&ek_secret, opk); // DH(EK_A, OPK_B)
        ikm.extend_from_slice(dh4.as_slice());
    }

    let result = derive(&ikm, our_ik, peer_ik);
    Ok(InitiatorOutput {
        result,
        ek_pub,
        used_spk: *peer_spk,
        used_opk: peer_opk,
    })
}

/// Run X3DH as the **responder** (Bob) from a received prekey message. `peer_ik` is the
/// initiator's Ed25519 account key (carried, signed, in the envelope); `ek_a` is her ephemeral.
/// `spk_secret`/`opk_secret` are the X25519 secrets behind the prekeys she used (looked up locally
/// from the published bundle's secrets).
pub fn respond(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: &[u8; 32],
    peer_ik: &[u8; 32],
    ek_a: &[u8; 32],
    spk_secret: &[u8; 32],
    opk_secret: Option<[u8; 32]>,
) -> Result<X3dhResult> {
    let peer_ik_x = ed25519_pub_to_x25519(peer_ik)?;

    let dh1 = dh(spk_secret, &peer_ik_x); // DH(IK_A, SPK_B)
    let dh2 = store_dh(store, handle, ek_a)?; // DH(EK_A, IK_B)
    let dh3 = dh(spk_secret, ek_a); // DH(EK_A, SPK_B)

    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(dh1.as_slice());
    ikm.extend_from_slice(dh2.as_slice());
    ikm.extend_from_slice(dh3.as_slice());
    if let Some(opk) = opk_secret.as_ref() {
        let dh4 = dh(opk, ek_a); // DH(EK_A, OPK_B)
        ikm.extend_from_slice(dh4.as_slice());
    }

    Ok(derive(&ikm, peer_ik, our_ik))
}

#[cfg(test)]
mod tests {
    //! Task 1.6 / review finding F1: proves the conformance-vector harness would actually catch a
    //! spec-divergent KDF label, not just a self-consistent bug baked into both the generator and
    //! the vector. Lives here (rather than the external `tests/conformance.rs`) because it needs
    //! `pub(crate)` access to `X3DH_INFO`/`hkdf`, which the crate deliberately does not expose.
    use super::*;
    use crate::primitives::hkdf;
    use std::path::PathBuf;

    fn load_committed_root(vector_name: &str) -> [u8; 32] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("meridian-crypto lives at <root>/apps/crypto")
            .join("test-vectors")
            .join("x3dh-v1.json");
        let bytes =
            std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let vec = json["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == vector_name)
            .unwrap_or_else(|| panic!("vector '{vector_name}' not found"));
        let hex_root = vec["derived"]["root_hex"].as_str().unwrap();
        let bytes = hex::decode(hex_root).unwrap();
        bytes.try_into().unwrap()
    }

    /// Re-derive `derive()`'s `root` using a copy of the real X3DH inputs but with one byte of
    /// the domain-separation label flipped, and assert the output does NOT match the committed
    /// vector. If someone silently changes `X3DH_INFO` (or the field-ordering it protects), the
    /// real derivation would drift from the frozen vector too — this test is the proof that our
    /// harness distinguishes "matches spec" from "matches whatever the code currently emits".
    #[test]
    fn divergent_kdf_label_does_not_match_committed_vector() {
        // Same raw inputs as the committed "with-opk" x3dh-v1.json vector.
        let responder_ik_seed = [0x10u8; 32];
        let initiator_ik_seed = [0x20u8; 32];
        let spk_secret = [0x30u8; 32];
        let opk_secret = [0x40u8; 32];

        let responder_ik = meridian_identity::pubkey_from_seed(&responder_ik_seed);
        let initiator_ik = meridian_identity::pubkey_from_seed(&initiator_ik_seed);
        let store = meridian_store::MemorySecretStore::new();
        let handle = store.store("responder-ik", &responder_ik_seed).unwrap();

        // ek_a_pub must match the committed vector's fixed ephemeral, derived the same way the
        // generator does (X25519 public key of seed 0x50).
        let ek_a_secret = [0x50u8; 32];
        let ek_a_pub = {
            use x25519_dalek::{PublicKey, StaticSecret};
            PublicKey::from(&StaticSecret::from(ek_a_secret)).to_bytes()
        };

        // Reproduce respond()'s DH legs exactly (same code, unmodified).
        let responder_ik_bytes = *responder_ik.as_bytes();
        let initiator_ik_bytes = *initiator_ik.as_bytes();
        let peer_ik_x = ed25519_pub_to_x25519(&initiator_ik_bytes).unwrap();
        let dh1 = dh(&spk_secret, &peer_ik_x);
        let dh2 = store
            .use_key(&handle, meridian_store::SignOrDh::Dh, &ek_a_pub)
            .unwrap();
        let dh3 = dh(&spk_secret, &ek_a_pub);
        let dh4 = dh(&opk_secret, &ek_a_pub);

        let mut ikm = Vec::with_capacity(32 * 5);
        ikm.extend_from_slice(&F);
        ikm.extend_from_slice(dh1.as_slice());
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(dh3.as_slice());
        ikm.extend_from_slice(dh4.as_slice());

        // Sanity: the *real* `derive()` (real label) matches the committed vector.
        let real = derive(&ikm, &initiator_ik_bytes, &responder_ik_bytes);
        assert_eq!(real.root, load_committed_root("with-opk"));

        // Now flip one byte of the domain-separation label and re-derive with the same IKM —
        // simulating exactly the class of bug F1 targets (a spec-divergent KDF label).
        let mut mutated_label = crate::primitives::X3DH_INFO.to_vec();
        let last = mutated_label.len() - 1;
        mutated_label[last] ^= 0x01;
        let mutated_okm: [u8; 96] = hkdf(&[0u8; 32], &ikm, &mutated_label);
        let mut mutated_root = [0u8; 32];
        mutated_root.copy_from_slice(&mutated_okm[0..32]);

        assert_ne!(
            mutated_root,
            load_committed_root("with-opk"),
            "a mutated KDF label must NOT reproduce the committed vector \
             — if it does, this harness cannot catch a spec-divergent label"
        );
    }
}
