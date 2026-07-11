//! meridian-store — secret storage for the account identity key (T01).
//!
//! Canonical API contract: `../../docs/api/core-api-contracts.md` ("Traits the platform MUST
//! implement"). Security context: keys live either in the OS keystore/enclave (Keychain, DPAPI,
//! Secret Service) or, for headless clients, in an age/scrypt passphrase-wrapped keyfile
//! (system-design §4.7). The private key **never** appears on disk in plaintext.
//!
//! The [`SecretStore`] trait is the seam every platform shim implements. Signing happens *through*
//! the store ([`SecretStore::use_key`]) so an enclave-backed impl can keep the key non-extractable;
//! the software impls here load the seed into a [`Zeroizing`] buffer only for the length of one
//! operation.

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
/// T01 only exercises [`SignOrDh::Sign`] (the account key is Ed25519, used for detached
/// signatures over IDs and every later envelope). [`SignOrDh::Dh`] is reserved for the X25519
/// device/prekeys introduced in T02/T13 and currently returns [`StoreError::UnsupportedOp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOrDh {
    /// Ed25519 detached signature over `input`; returns 64 signature bytes.
    Sign,
    /// X25519 Diffie–Hellman against the peer public key in `input`. Not used in T01.
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

/// Dispatch a [`SignOrDh`] op against raw seed bytes. Central so every store applies the same
/// rules (in particular, that `Dh` is unsupported in T01).
pub(crate) fn perform_op(seed: &[u8], op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
    match op {
        SignOrDh::Sign => ed25519_sign(seed, input),
        SignOrDh::Dh => Err(StoreError::UnsupportedOp(
            "X25519 DH is introduced with prekeys in T02/T13, not the T01 account key",
        )),
    }
}
