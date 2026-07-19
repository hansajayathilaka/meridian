//! In-memory secret store — for tests and the "keys never touch disk" harness.
//!
//! Represents an off-disk sink (an OS keystore stand-in) that keeps nothing on the filesystem, so
//! the T01 acceptance harness can assert the `os`-store path writes no plaintext key file while
//! still exercising [`crate::SecretStore`] end to end without a platform keychain.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::{
    derive_key_from_seed, perform_op, KeyHandle, Result, SecretStore, SignOrDh, StoreError,
};

/// A process-local, filesystem-free secret store.
#[derive(Default)]
pub struct MemorySecretStore {
    keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemorySecretStore {
    fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle> {
        self.keys
            .lock()
            .expect("MemorySecretStore mutex poisoned")
            .insert(label.to_string(), Zeroizing::new(secret.to_vec()));
        Ok(KeyHandle {
            label: label.to_string(),
        })
    }

    fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
        let keys = self.keys.lock().expect("MemorySecretStore mutex poisoned");
        let seed = keys
            .get(&h.label)
            .ok_or_else(|| StoreError::NotFound(h.label.clone()))?;
        perform_op(seed, op, input)
    }

    fn nonextractable(&self) -> bool {
        false
    }

    fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]> {
        let keys = self.keys.lock().expect("MemorySecretStore mutex poisoned");
        let seed = keys
            .get(&h.label)
            .ok_or_else(|| StoreError::NotFound(h.label.clone()))?;
        derive_key_from_seed(seed, info)
    }
}
