//! At-rest store-key derivation (task 1.7, review finding F7).
//!
//! Proves the session-store key comes from `SecretStore::derive_key` — a dedicated HKDF-Expand op
//! — rather than from signing a fixed label through the store, so a future enclave/HSM
//! `SecretStore` with randomized signatures can never make persisted state undecryptable.

use hkdf::Hkdf;
use meridian_crypto::at_rest;
use meridian_store::{KeyHandle, MemorySecretStore, SecretStore, SignOrDh};
use sha2::Sha256;

const SEED: [u8; 32] = [0x42; 32];

#[test]
fn store_key_matches_hand_computed_hkdf_independent_of_signing() {
    let store = MemorySecretStore::new();
    let handle = store.store("acct", &SEED).unwrap();

    // The public entry point: derive the store key straight through the trait method.
    let derived = store.derive_key(&handle, at_rest::STORE_KEY_INFO).unwrap();

    // Hand-compute the same HKDF-Expand over the raw seed bytes, entirely independently of any
    // signing call, to prove the derivation is exactly HKDF(fixed-salt, seed, info) and does not
    // route through `SignOrDh::Sign` anywhere.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &SEED);
    let mut expected = [0u8; 32];
    hk.expand(at_rest::STORE_KEY_INFO, &mut expected).unwrap();
    assert_eq!(derived, expected);

    // Deterministic/stable across repeated calls.
    let derived_again = store.derive_key(&handle, at_rest::STORE_KEY_INFO).unwrap();
    assert_eq!(derived, derived_again);

    // Sanity: this is *not* derived from a signature over the info bytes — the two constructions
    // diverge (the old scheme HKDF'd a signature, not the raw seed).
    let sig = store
        .use_key(&handle, SignOrDh::Sign, at_rest::STORE_KEY_INFO)
        .unwrap();
    let hk_over_sig = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &sig);
    let mut via_signature = [0u8; 32];
    hk_over_sig
        .expand(at_rest::STORE_KEY_INFO, &mut via_signature)
        .unwrap();
    assert_ne!(
        derived, via_signature,
        "store key must not be derived from a signature over the label"
    );
}

#[test]
fn seal_open_roundtrip_uses_derive_key() {
    let store = MemorySecretStore::new();
    let handle: KeyHandle = store.store("acct", &SEED).unwrap();
    let key = store.derive_key(&handle, at_rest::STORE_KEY_INFO).unwrap();

    let sealed = at_rest::seal(&key, b"ratchet state").unwrap();
    let opened = at_rest::open(&key, &sealed).unwrap();
    assert_eq!(opened, b"ratchet state");
}
