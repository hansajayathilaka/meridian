//! At-rest sealing for the local session store (system-design §4.7).
//!
//! The session store (ratchet state) is encrypted under a key **derived from the account key held
//! in the [`SecretStore`]** via [`meridian_store::SecretStore::derive_key`] — a dedicated
//! HKDF-Expand op over the raw stored seed, independent of any signature algorithm's determinism.
//! The sealed blob is XChaCha20-Poly1305 with a random nonce.
//!
//! **Resolved (task 1.7, review finding F7):** the store now exposes a dedicated `derive_key` op
//! that does not depend on any signature algorithm's determinism, so a future HSM/enclave
//! `SecretStore` with randomized (non-deterministic) signatures can never make previously-sealed
//! session-store state permanently undecryptable. This is a **breaking format change** for any
//! previously-persisted session-store blob: old blobs were sealed under
//! `HKDF(fixed-salt, Ed25519-signature-over-label, info)`; new blobs are sealed directly under
//! `SecretStore::derive_key`'s HKDF-Expand over the raw seed. Acceptable pre-release — there are no
//! deployed users or production data yet — and no migration shim is provided.
//!
//! [`SecretStore`]: meridian_store::SecretStore

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::error::{CryptoError, Result};

/// Domain-separation info the caller passes to [`meridian_store::SecretStore::derive_key`] to seed
/// the session-store key.
pub const STORE_KEY_INFO: &[u8] = b"Meridian/SessionStoreKey/v1";

/// Seal `plaintext` under `key`; output is `nonce(24) ‖ ciphertext`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Crypto)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: b"mrd.session-store/1",
            },
        )
        .map_err(|_| CryptoError::Crypto)?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`]. Returns [`CryptoError::BadState`] on any failure.
pub fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 24 {
        return Err(CryptoError::BadState);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Crypto)?;
    let (nonce, ct) = data.split_at(24);
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: b"mrd.session-store/1",
            },
        )
        .map_err(|_| CryptoError::BadState)
}
