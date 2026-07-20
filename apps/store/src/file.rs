//! Passphrase-wrapped keyfile store (age + scrypt) for headless / terminal clients.
//!
//! system-design §4.7: "headless/terminal clients use an age/scrypt-wrapped keyfile". The secret
//! is encrypted with an age scrypt recipient (scrypt-derived key from the passphrase) before it
//! ever touches disk, so the raw seed is never persisted in plaintext.

use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::{
    derive_key_from_seed, perform_op, KeyHandle, Result, SecretStore, SignOrDh, StoreError,
};

/// A single Ed25519 account key wrapped in one age/scrypt keyfile.
///
/// The passphrase is held (as a [`SecretString`]) for the lifetime of the store so `use_key` can
/// unwrap on demand. One store == one keyfile == one account key.
pub struct FileSecretStore {
    path: PathBuf,
    passphrase: SecretString,
}

impl FileSecretStore {
    /// Bind a store to `path`, unlocked by `passphrase`. Does not touch the filesystem until
    /// [`SecretStore::store`] (write) or [`SecretStore::use_key`] (read) is called.
    pub fn new(path: impl AsRef<Path>, passphrase: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            passphrase: SecretString::from(passphrase.into()),
        }
    }

    /// The keyfile path this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Extract the raw seed for user-managed encrypted backup (`meridian id export`).
    ///
    /// This is the deliberate, user-visible exception to keeping keys in the store — the design
    /// permits "an age-encrypted file the user stores themselves" as the only recovery softening
    /// (system-design §4.7/§10). Not on [`SecretStore`], so enclave-backed stores never expose it.
    pub fn export_seed(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.decrypt_seed()
    }

    fn decrypt_seed(&self) -> Result<Zeroizing<Vec<u8>>> {
        let ciphertext = fs::read(&self.path)
            .map_err(|_| StoreError::NotFound(self.path.display().to_string()))?;
        let identity = age::scrypt::Identity::new(self.passphrase.clone());
        let plaintext = age::decrypt(&identity, &ciphertext).map_err(|_| StoreError::Unwrap)?;
        Ok(Zeroizing::new(plaintext))
    }
}

impl SecretStore for FileSecretStore {
    fn store(&self, _label: &str, secret: &[u8]) -> Result<KeyHandle> {
        let recipient = age::scrypt::Recipient::new(self.passphrase.clone());
        let ciphertext =
            age::encrypt(&recipient, secret).map_err(|e| StoreError::Io(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&self.path, &ciphertext)?;
        Ok(KeyHandle {
            label: self.path.display().to_string(),
        })
    }

    fn use_key(&self, _h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
        let seed = self.decrypt_seed()?;
        perform_op(&seed, op, input)
    }

    fn nonextractable(&self) -> bool {
        false
    }

    fn derive_key(&self, _h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]> {
        let seed = self.decrypt_seed()?;
        derive_key_from_seed(&seed, info)
    }
}
