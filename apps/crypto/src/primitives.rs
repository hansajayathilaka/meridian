//! Thin, audited-primitive wrappers used by X3DH and the Double Ratchet.
//!
//! Every construction here is standard and library-provided — HKDF-SHA256, HMAC-SHA256,
//! XChaCha20-Poly1305, X25519 — assembled per the Signal specs. No primitive is hand-rolled
//! (crypto-protocols skill rule 1). The "assembly" is exactly the well-specified Double Ratchet /
//! X3DH glue that [ADR 0011](../../../docs/adr/0011-ratchet-library.md) allocates to
//! `meridian-crypto`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation labels. Changing any of these is a wire break (bump the envelope version).
pub(crate) const X3DH_INFO: &[u8] = b"Meridian/X3DH/v1";
pub(crate) const RK_INFO: &[u8] = b"Meridian/RatchetRoot/HE/v1";
pub(crate) const MSG_INFO: &[u8] = b"Meridian/MsgKey/v1";

/// Generate a fresh X25519 keypair, returning `(secret_bytes, public_bytes)`.
pub(crate) fn gen_dh() -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let secret = StaticSecret::from(*seed);
    let public = XPublicKey::from(&secret);
    Ok((Zeroizing::new(secret.to_bytes()), public.to_bytes()))
}

/// X25519 Diffie–Hellman between a local secret and a peer public key (both raw 32-byte).
pub(crate) fn dh(secret: &[u8; 32], peer_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let secret = StaticSecret::from(*secret);
    let shared = secret.diffie_hellman(&XPublicKey::from(*peer_pub));
    Zeroizing::new(shared.to_bytes())
}

/// Convert an Ed25519 public key to its birationally-equivalent X25519 (Montgomery) public key,
/// so `DH(·, IK_ed)` legs of X3DH work against an account identity key. Mirrors the private-side
/// conversion in `meridian-store` (libsodium's `crypto_sign_ed25519_pk_to_curve25519`).
pub(crate) fn ed25519_pub_to_x25519(ed_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(ed_pub)
        .map_err(|_| CryptoError::BadKey("identity key is not a valid Ed25519 point"))?;
    Ok(vk.to_montgomery().to_bytes())
}

/// HKDF-SHA256 expand of `ikm` under `salt`/`info` into an `N`-byte output.
pub(crate) fn hkdf<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; N];
    hk.expand(info, &mut okm)
        .expect("HKDF expand length is within SHA-256 bounds");
    okm
}

/// Root-key KDF for the header-encryption variant: from the current root key and a fresh DH
/// output, derive `(root', chain_key, next_header_key)` (Signal `KDF_RK_HE`).
pub(crate) fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let okm: [u8; 96] = hkdf(rk, dh_out, RK_INFO);
    let mut root = [0u8; 32];
    let mut ck = [0u8; 32];
    let mut nhk = [0u8; 32];
    root.copy_from_slice(&okm[0..32]);
    ck.copy_from_slice(&okm[32..64]);
    nhk.copy_from_slice(&okm[64..96]);
    (root, ck, nhk)
}

/// Symmetric chain KDF (Signal `KDF_CK`): from a chain key derive `(next_chain_key, message_key)`
/// via HMAC-SHA256 with distinct one-byte constants.
pub(crate) fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac(ck, &[0x01]);
    let next = hmac(ck, &[0x02]);
    (next, mk)
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// AEAD-seal `plaintext` under a message key, binding `aad`. The 32-byte encryption key and
/// 24-byte nonce are both derived from the (single-use) message key, so no nonce need be carried.
pub(crate) fn aead_seal(mk: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let okm: [u8; 56] = hkdf(&[0u8; 32], mk, MSG_INFO);
    let cipher = XChaCha20Poly1305::new_from_slice(&okm[0..32]).map_err(|_| CryptoError::Crypto)?;
    let nonce = XNonce::from_slice(&okm[32..56]);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Crypto)
}

/// Inverse of [`aead_seal`]. Returns [`CryptoError::Crypto`] on tag mismatch (no distinguishing
/// oracle beyond "failed").
pub(crate) fn aead_open(mk: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let okm: [u8; 56] = hkdf(&[0u8; 32], mk, MSG_INFO);
    let cipher = XChaCha20Poly1305::new_from_slice(&okm[0..32]).map_err(|_| CryptoError::Crypto)?;
    let nonce = XNonce::from_slice(&okm[32..56]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Crypto)
}

/// Encrypt a ratchet header under a header key with a fresh random nonce (Signal `HENCRYPT`).
/// Output is `nonce(24) ‖ ciphertext`; header keys are reused across a chain, so the nonce is
/// random per header rather than derived.
pub(crate) fn header_seal(hk: &[u8; 32], header: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(hk).map_err(|_| CryptoError::Crypto)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: header,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::Crypto)?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Try to decrypt an encrypted header under `hk`. Returns `None` on any failure (wrong key), which
/// is how the receiver distinguishes the current chain from a DH-ratchet step.
pub(crate) fn header_open(hk: &[u8; 32], enc_header: &[u8]) -> Option<Vec<u8>> {
    if enc_header.len() < 24 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(hk).ok()?;
    let (nonce, ct) = enc_header.split_at(24);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
        .ok()
}
