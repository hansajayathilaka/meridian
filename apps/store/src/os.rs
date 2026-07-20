//! OS keystore-backed secret store (Keychain / DPAPI / Secret Service via `keyring-core`).
//!
//! The private seed is handed to the platform credential store, which encrypts it at rest — it
//! never lands in a plaintext file we control. That is the T01 acceptance property for
//! `--store os`: "keys created with `--store os` never appear on disk in plaintext."
//!
//! Production callers must install a platform credential store (the `meridian-cli` binary wires up
//! the OS store; other embedders link one of the `*-keyring-store` crates and call
//! [`keyring_core::set_default_store`]). Headless CI installs the mock store via
//! [`install_mock_keystore`], which keeps secrets in process memory only — no disk, no D-Bus.

use zeroize::Zeroizing;

use crate::{
    derive_key_from_seed, perform_op, KeyHandle, Result, SecretStore, SignOrDh, StoreError,
};

fn backend_err(e: keyring_core::Error) -> StoreError {
    match e {
        keyring_core::Error::NoEntry => StoreError::NotFound("os-keystore entry".into()),
        other => StoreError::Backend(other.to_string()),
    }
}

/// A secret store that persists keys in the platform credential store under a fixed service name.
pub struct OsSecretStore {
    service: String,
}

impl OsSecretStore {
    /// Create a store that files its entries under `service` (e.g. `"meridian"`). The service is
    /// the keychain "service"/"target" grouping; the per-key label becomes the entry user.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, label: &str) -> Result<keyring_core::Entry> {
        keyring_core::Entry::new(&self.service, label).map_err(backend_err)
    }

    /// Extract the raw seed for user-managed encrypted backup (`meridian id export`). See
    /// [`FileSecretStore::export_seed`](crate::FileSecretStore::export_seed) for the rationale.
    /// Only works because software keychains return bytes; a true enclave store would not offer
    /// this.
    pub fn export_seed(&self, h: &KeyHandle) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            self.entry(h.label())?.get_secret().map_err(backend_err)?,
        ))
    }
}

impl SecretStore for OsSecretStore {
    fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle> {
        self.entry(label)?.set_secret(secret).map_err(backend_err)?;
        Ok(KeyHandle {
            label: label.to_string(),
        })
    }

    fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
        let seed = Zeroizing::new(self.entry(&h.label)?.get_secret().map_err(backend_err)?);
        perform_op(&seed, op, input)
    }

    fn nonextractable(&self) -> bool {
        // `keyring-core` returns raw bytes, so from the core's perspective the key is extractable.
        // A future enclave/StrongBox-backed store would override this to `true`. Reported honestly
        // in diagnostics rather than overclaimed (docs/security/anonymity-and-retention.md).
        false
    }

    fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]> {
        let seed = Zeroizing::new(self.entry(&h.label)?.get_secret().map_err(backend_err)?);
        derive_key_from_seed(&seed, info)
    }
}

/// Whether a platform credential store is currently installed (so `OsSecretStore` will work).
pub fn platform_keystore_available() -> bool {
    keyring_core::get_default_store().is_some()
}

/// Install the in-memory mock credential store as the process default.
///
/// For tests and headless environments without a real keychain. Idempotent-ish: installing twice
/// simply replaces the store. Never use in production — it does not persist and is not secure.
pub fn install_mock_keystore() {
    keyring_core::set_default_store(
        keyring_core::mock::Store::new().expect("mock keystore construction is infallible"),
    );
}
