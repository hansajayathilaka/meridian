//! Account descriptor persistence and the portable (export/import) keyfile.
//!
//! `config_dir()`, [`AccountDescriptor`]/[`StoreKind`], and `sessions_path()` moved to
//! `meridian_core::account` (task 4.13) so every shim — this CLI, and per ADR 0020 the
//! core-only `meridian-tui` — reaches the same `$MERIDIAN_HOME` layout through one code path.
//! This module re-exports them for existing CLI call sites and keeps only what's CLI-specific:
//! the portable (export/import) keyfile, which operates on a caller-supplied path rather than the
//! `$MERIDIAN_HOME` layout itself.
//!
//! Security note: the descriptor holds only public data (public key, hint, store location). The
//! private key is never in it — for `--store os` nothing secret touches disk at all, which is the
//! T01 acceptance property.

use std::path::Path;

use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};

pub use meridian_core::account::{config_dir, sessions_path, AccountDescriptor, StoreKind};

const PORTABLE_VERSION: u8 = 1;

/// The portable keyfile payload (age-encrypted). Carries the seed + hint so an import fully
/// reconstructs the account.
#[derive(Serialize, Deserialize)]
struct Portable {
    v: u8,
    /// Ed25519 seed, lowercase hex.
    seed: String,
    hint: String,
}

/// Write a passphrase-encrypted portable keyfile (age/scrypt).
pub fn write_portable(out: &Path, seed: &[u8], hint: &str, passphrase: &str) -> Result<(), String> {
    let payload = Portable {
        v: PORTABLE_VERSION,
        seed: hex::encode(seed),
        hint: hint.to_string(),
    };
    let plaintext =
        serde_json::to_vec(&payload).map_err(|e| format!("serializing portable key: {e}"))?;
    let recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_string()));
    let ciphertext = age::encrypt(&recipient, &plaintext)
        .map_err(|e| format!("encrypting portable key: {e}"))?;
    std::fs::write(out, ciphertext).map_err(|e| format!("writing {}: {e}", out.display()))?;
    Ok(())
}

/// Read and decrypt a portable keyfile, returning `(seed, hint)`.
pub fn read_portable(path: &Path, passphrase: &str) -> Result<(Vec<u8>, String), String> {
    let ciphertext = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));
    let plaintext = age::decrypt(&identity, &ciphertext)
        .map_err(|_| "could not decrypt portable key (wrong passphrase or corrupt file)")?;
    let payload: Portable =
        serde_json::from_slice(&plaintext).map_err(|e| format!("parsing portable key: {e}"))?;
    let seed = hex::decode(&payload.seed).map_err(|_| "portable key seed is not valid hex")?;
    Ok((seed, payload.hint))
}
