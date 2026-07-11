//! Account keys and detached signatures — the sign/verify API every later envelope uses.

use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use meridian_store::{KeyHandle, SecretStore, SignOrDh, ED25519_SEED_LEN};
use zeroize::Zeroizing;

use crate::error::IdError;
use crate::id::{to_id_string, Identity, PUBKEY_LEN};

/// An Ed25519 account public key — the principal. Validated to be a canonical curve point on
/// construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; PUBKEY_LEN]);

impl PublicKey {
    /// Wrap raw bytes, verifying they decode to a valid Ed25519 point.
    pub fn from_bytes(bytes: [u8; PUBKEY_LEN]) -> Result<Self, IdError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| IdError::BadPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; PUBKEY_LEN] {
        &self.0
    }

    /// Canonical `mrd1:…@hint` string for this key.
    pub fn to_id_string(&self, hint: &str) -> Result<String, IdError> {
        to_id_string(&self.0, hint)
    }
}

/// A detached Ed25519 signature (64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, IdError> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| IdError::BadPublicKey)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// A freshly created account: its public key, its home-domain hint, and the store handle that
/// unlocks its private key. Returned by [`generate_account`].
#[derive(Clone, Debug)]
pub struct AccountId {
    public_key: PublicKey,
    hint: String,
    handle: KeyHandle,
}

impl AccountId {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// The store handle for this account's private key (feed to [`sign`]).
    pub fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    /// This account as a parsed [`Identity`].
    pub fn identity(&self) -> Identity {
        // Hint was validated when the account was created, so this cannot fail.
        Identity::new(self.public_key.0, self.hint.clone())
            .expect("account hint validated at creation")
    }

    /// Canonical `mrd1:…@hint` string.
    pub fn to_id_string(&self) -> String {
        self.identity().to_id_string()
    }
}

/// Generate a new Ed25519 account key, store the private seed in `store`, and return the account.
///
/// The seed is generated with the OS CSPRNG, handed to the store, and zeroized locally. The
/// private key never leaves the store after this call — [`sign`] operates through it.
pub fn generate_account(store: &dyn SecretStore, hint: &str) -> Result<AccountId, GenerateError> {
    // Fail fast on a bad hint before touching any RNG or store.
    crate::id::validate_hint(hint)?;

    let mut seed = Zeroizing::new([0u8; ED25519_SEED_LEN]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| GenerateError::Rng(e.to_string()))?;

    let signing = SigningKey::from_bytes(&seed);
    let public_key = PublicKey(signing.verifying_key().to_bytes());
    drop(signing); // zeroizes (dalek `zeroize` feature)

    // Label the entry by the public key: stable, unique, and not secret.
    let label = hex_lower(public_key.as_bytes());
    let handle = store.store(&label, seed.as_slice())?;

    Ok(AccountId {
        public_key,
        hint: hint.to_string(),
        handle,
    })
}

/// Derive the Ed25519 public key from a 32-byte seed, without a store.
///
/// Used when re-labelling an imported key by its public key. The seed is consumed only to derive
/// the (public) verifying key; callers still hand the seed to a [`SecretStore`] for safekeeping.
pub fn pubkey_from_seed(seed: &[u8; ED25519_SEED_LEN]) -> PublicKey {
    let signing = SigningKey::from_bytes(seed);
    PublicKey(signing.verifying_key().to_bytes())
}

/// Produce a detached signature over `msg` using the private key referenced by `handle`.
pub fn sign(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    msg: &[u8],
) -> Result<Signature, meridian_store::StoreError> {
    let bytes = store.use_key(handle, SignOrDh::Sign, msg)?;
    Signature::from_slice(&bytes).map_err(|_| {
        meridian_store::StoreError::Backend("store returned a malformed signature".into())
    })
}

/// Verify a detached signature. Returns `false` for any malformed key/signature — never panics.
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&pk.0) else {
        return false;
    };
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify(msg, &dalek_sig).is_ok()
}

/// Errors from [`generate_account`].
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error("invalid hint: {0}")]
    BadHint(#[from] crate::error::HintError),
    #[error("failed to gather randomness: {0}")]
    Rng(String),
    #[error(transparent)]
    Store(#[from] meridian_store::StoreError),
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
