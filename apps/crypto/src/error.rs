//! Errors from the X3DH + Double Ratchet layer. Deliberately coarse on the decrypt path so a
//! remote peer/server cannot use failure reasons as an oracle.

use thiserror::Error;

/// Failures in session establishment (X3DH) and message protection (Double Ratchet).
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A key or scalar was not a valid length / point.
    #[error("invalid key material: {0}")]
    BadKey(&'static str),

    /// The keystore rejected a sign or DH operation (key missing, DH unsupported, …).
    #[error("keystore error: {0}")]
    Store(#[from] meridian_store::StoreError),

    /// KDF/AEAD primitive failure — includes AEAD tag mismatch on decrypt.
    #[error("cryptographic operation failed")]
    Crypto,

    /// The ratchet message could not be parsed off the wire.
    #[error("malformed ratchet message")]
    Malformed,

    /// A header could not be decrypted under either header key — cannot advance the ratchet.
    #[error("undecryptable header")]
    UndecryptableHeader,

    /// The peer skipped more messages than [`crate::ratchet::MAX_SKIP`] allows in one chain — a
    /// resource-exhaustion guard, not a normal condition.
    #[error("too many skipped messages")]
    TooManySkipped,

    /// Randomness could not be gathered.
    #[error("rng failure: {0}")]
    Rng(String),

    /// Persisted ratchet state could not be decoded (corrupt or wrong version).
    #[error("could not decode session state")]
    BadState,
}

pub type Result<T> = core::result::Result<T, CryptoError>;
