//! At-rest sealing for the local session store (system-design §4.7).
//!
//! The session store (ratchet state) is encrypted under a key **derived from the account key held
//! in the [`SecretStore`]**: the caller signs a fixed label through the store (the private key
//! never leaves it), and the deterministic signature is HKDF'd into a symmetric key here. The
//! sealed blob is XChaCha20-Poly1305 with a random nonce.
//!
//! TODO: confirm a dedicated key-derivation op on `SecretStore` (rather than reusing a signature)
//! when enclave-backed stores land — a deterministic Ed25519 signature is stable and secret, but a
//! purpose-built derive op is cleaner. Tracked with the multi-device work (T13).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::error::{CryptoError, Result};
use crate::primitives::hkdf;

/// Label the caller signs through the [`meridian_store::SecretStore`] to seed the store key.
pub const STORE_KEY_LABEL: &[u8] = b"Meridian/SessionStoreKey/v1";

/// Derive the 32-byte session-store key from a signature over [`STORE_KEY_LABEL`].
pub fn derive_store_key(signature: &[u8]) -> [u8; 32] {
    hkdf::<32>(&[0u8; 32], signature, b"Meridian/SessionStore/HKDF/v1")
}

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
