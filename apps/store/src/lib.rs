//! meridian-store — secret storage for the account identity key (T01).
//!
//! Canonical API contract: `../../docs/api/core-api-contracts.md` ("Traits the platform MUST
//! implement"). Security context: keys live either in the OS keystore/enclave (Keychain, DPAPI,
//! Secret Service) or, for headless clients, in an age/scrypt passphrase-wrapped keyfile
//! (system-design §4.7). The private key **never** appears on disk in plaintext.
//!
//! The [`SecretStore`] trait is the seam every platform shim implements. Signing happens *through*
//! the store ([`SecretStore::use_key`]) so an enclave-backed impl can keep the key non-extractable;
//! symmetric-key derivation for callers that need a raw 32-byte key (e.g. sealing local state at
//! rest) happens through [`SecretStore::derive_key`], an HKDF-Expand op that does not depend on any
//! signature algorithm's determinism; the software impls here load the seed into a [`Zeroizing`]
//! buffer only for the length of one operation.

mod error;
mod file;
mod mem;
mod os;

pub use error::{Result, StoreError};
pub use file::FileSecretStore;
pub use mem::MemorySecretStore;
pub use os::{install_mock_keystore, platform_keystore_available, OsSecretStore};

use zeroize::Zeroizing;

/// Length in bytes of an Ed25519 secret seed (the only key type stored in T01).
pub const ED25519_SEED_LEN: usize = 32;

/// Which cryptographic operation to perform with a stored key.
///
/// [`SignOrDh::Sign`] produces detached Ed25519 signatures (IDs, prekey bundles, the T03
/// `Sign_IK{…}` envelope). [`SignOrDh::Dh`] performs an X25519 Diffie–Hellman with the account
/// key — needed by X3DH's `DH(IK_A, ·)` legs (T03, system-design §4.2). Because the account key is
/// Ed25519, the store converts its seed to the birationally-equivalent X25519 secret and does the
/// DH internally, so the private key never leaves the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOrDh {
    /// Ed25519 detached signature over `input`; returns 64 signature bytes.
    Sign,
    /// X25519 Diffie–Hellman: `input` is the 32-byte peer X25519 public key; returns the 32-byte
    /// shared secret. Uses the account seed's X25519 form (Ed25519→X25519, libsodium-compatible).
    Dh,
}

/// An opaque reference to a stored secret. Carries no key material — just the label the store
/// uses to locate it. Clone-cheap and safe to log (contains no secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyHandle {
    label: String,
}

impl KeyHandle {
    /// Reconstruct a handle from a persisted label — e.g. a CLI reloading an account descriptor
    /// after restart. The label must match the one a store returned from [`SecretStore::store`].
    pub fn from_label(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }

    /// The label under which the secret is stored (keychain entry user, or logical name).
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Storage for long-lived secret keys. Implemented by platform shims (system-design §6); the
/// software impls in this crate cover headless/CLI and testing.
///
/// Contract mirror: `docs/api/core-api-contracts.md`.
pub trait SecretStore: Send + Sync {
    /// Persist `secret` under `label`, returning a handle to it. For T01 `secret` is a 32-byte
    /// Ed25519 seed.
    fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle>;

    /// Perform `op` with the key referenced by `h` over `input`, returning the result bytes.
    /// The secret is never returned to the caller.
    fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>>;

    /// Whether keys in this store are non-extractable (true enclave/secure hardware). Surfaced in
    /// diagnostics per the API contract. The software stores here return `false` — they hold key
    /// material in process memory during an operation, honestly reported.
    fn nonextractable(&self) -> bool;

    /// Derive a domain-separated 32-byte symmetric key from the stored secret via HKDF-Expand,
    /// independent of any signature algorithm's determinism. `info` domain-separates the output so
    /// distinct callers/purposes never collide.
    fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]>;
}

/// Ed25519 detached signature helper shared by the software stores.
///
/// Loads `seed` into a [`SigningKey`], signs, and lets the key drop (dalek zeroizes on drop with
/// the `zeroize` feature). Returns the 64-byte signature.
pub(crate) fn ed25519_sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let seed: [u8; ED25519_SEED_LEN] =
        seed.try_into().map_err(|_| StoreError::BadSecretLength {
            expected: ED25519_SEED_LEN,
            got: seed.len(),
        })?;
    // Keep the seed zeroized on the stack for its brief lifetime too.
    let seed = Zeroizing::new(seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let sig = ed25519_dalek::Signer::sign(&signing, msg);
    Ok(sig.to_bytes().to_vec())
}

/// X25519 Diffie–Hellman with the account key: convert the Ed25519 `seed` to its equivalent
/// X25519 secret and DH against the 32-byte peer public key in `peer_pub`.
///
/// The conversion is libsodium's `crypto_sign_ed25519_sk_to_curve25519`: the X25519 scalar is the
/// clamped low half of `SHA-512(seed)`. The matching public key is the Montgomery form of the
/// Ed25519 public key (peers derive it with `VerifyingKey::to_montgomery` — see
/// `meridian-crypto`), so `DH(a, B) == DH(b, A)` holds and X3DH interoperates.
pub(crate) fn ed25519_seed_to_x25519_dh(seed: &[u8], peer_pub: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha512};
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

    let seed: [u8; ED25519_SEED_LEN] =
        seed.try_into().map_err(|_| StoreError::BadSecretLength {
            expected: ED25519_SEED_LEN,
            got: seed.len(),
        })?;
    let peer: [u8; 32] = peer_pub
        .try_into()
        .map_err(|_| StoreError::BadSecretLength {
            expected: 32,
            got: peer_pub.len(),
        })?;

    // X25519 secret scalar = clamp(SHA-512(seed)[..32]). x25519-dalek re-clamps at DH time (clamp
    // is idempotent), so the explicit clamp here only documents the libsodium construction.
    let hash = Sha512::digest(seed);
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let secret = StaticSecret::from(*scalar);
    let shared = secret.diffie_hellman(&XPublicKey::from(peer));
    Ok(shared.to_bytes().to_vec())
}

/// Dispatch a [`SignOrDh`] op against raw seed bytes. Central so every software store applies the
/// same rules and conversions.
pub(crate) fn perform_op(seed: &[u8], op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
    match op {
        SignOrDh::Sign => ed25519_sign(seed, input),
        SignOrDh::Dh => ed25519_seed_to_x25519_dh(seed, input),
    }
}

/// Fixed, zero salt for the HKDF-Extract step. The seed itself supplies all the entropy; `info`
/// domain-separates independent derivations from the same seed.
const DERIVE_KEY_SALT: [u8; 32] = [0u8; 32];

/// Derive a domain-separated 32-byte symmetric key from raw seed bytes via HKDF-Expand
/// (HKDF-SHA256: `Extract(salt=0, ikm=seed)` then `Expand(info)`), independent of any signature
/// algorithm's determinism. Shared by every software store's [`SecretStore::derive_key`] impl.
pub(crate) fn derive_key_from_seed(seed: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let seed: [u8; ED25519_SEED_LEN] =
        seed.try_into().map_err(|_| StoreError::BadSecretLength {
            expected: ED25519_SEED_LEN,
            got: seed.len(),
        })?;
    let seed = Zeroizing::new(seed);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&DERIVE_KEY_SALT), seed.as_slice());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand length is within SHA-256 bounds");
    Ok(okm)
}
