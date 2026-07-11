//! Errors for the keystore layer.

use thiserror::Error;

/// Failure modes when storing or using a secret. Deliberately coarse: callers should not learn
/// *why* a keychain rejected them (avoids oracle leaks), only that the operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The secret has the wrong length for the requested key type (Ed25519 seed = 32 bytes).
    #[error("secret has invalid length: expected {expected}, got {got}")]
    BadSecretLength { expected: usize, got: usize },

    /// No secret is stored under this handle.
    #[error("no secret found for handle {0:?}")]
    NotFound(String),

    /// The requested operation is not supported by this key type (e.g. Dh on an Ed25519 seed).
    #[error("operation not supported for this key: {0}")]
    UnsupportedOp(&'static str),

    /// The passphrase was wrong or the wrapped keyfile is corrupt. One error for both so a
    /// caller cannot use it as a passphrase-guessing oracle.
    #[error("could not unwrap keyfile (wrong passphrase or corrupt data)")]
    Unwrap,

    /// The underlying OS keystore is unavailable or failed. `os` stores need a platform
    /// credential store installed (Keychain / DPAPI / Secret Service); headless CI installs the
    /// mock store via [`crate::install_mock_keystore`].
    #[error("os keystore backend error: {0}")]
    Backend(String),

    /// Encrypting / persisting the wrapped keyfile failed.
    #[error("keyfile i/o error: {0}")]
    Io(String),
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

pub type Result<T> = core::result::Result<T, StoreError>;
