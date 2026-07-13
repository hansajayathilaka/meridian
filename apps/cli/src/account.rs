//! Account descriptor persistence and the portable (export/import) keyfile.
//!
//! The descriptor is the small, **non-secret** record that tells the CLI where the current
//! account's private key lives (an age keyfile path, or an OS-keystore service+label) plus the
//! public key and hint needed to render the ID without unlocking anything. It is written to
//! `$MERIDIAN_HOME` (default `~/.config/meridian`).
//!
//! Security note: the descriptor holds only public data (public key, hint, store location). The
//! private key is never in it — for `--store os` nothing secret touches disk at all, which is the
//! T01 acceptance property.

use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use meridian_core::identity::{pubkey_from_seed, to_id_string, AccountId};
use serde::{Deserialize, Serialize};

const DESCRIPTOR_VERSION: u8 = 1;
const PORTABLE_VERSION: u8 = 1;

/// Which kind of secret store backs the account.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    File,
    Os,
}

/// The on-disk, non-secret account record.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountDescriptor {
    pub v: u8,
    /// Ed25519 public key, lowercase hex (64 chars).
    pub pubkey: String,
    /// Advisory routing hint (`@domain`).
    pub hint: String,
    pub store: StoreKind,
    /// Keyfile path for `StoreKind::File`.
    pub keyfile: Option<PathBuf>,
    /// Keychain service for `StoreKind::Os`.
    pub service: Option<String>,
    /// The store label (keychain entry user) for the private key — the public-key hex.
    pub label: String,
}

impl AccountDescriptor {
    pub fn new_file(account: &AccountId, keyfile: &Path) -> Self {
        let pubkey = hex::encode(account.public_key().as_bytes());
        Self {
            v: DESCRIPTOR_VERSION,
            hint: account.hint().to_string(),
            store: StoreKind::File,
            keyfile: Some(absolutize(keyfile)),
            service: None,
            label: pubkey.clone(),
            pubkey,
        }
    }

    pub fn new_os(account: &AccountId, service: &str) -> Self {
        let pubkey = hex::encode(account.public_key().as_bytes());
        Self {
            v: DESCRIPTOR_VERSION,
            hint: account.hint().to_string(),
            store: StoreKind::Os,
            keyfile: None,
            service: Some(service.to_string()),
            label: pubkey.clone(),
            pubkey,
        }
    }

    /// Build a descriptor for an imported key from its raw parts.
    pub fn from_parts(
        seed: &[u8; 32],
        hint: &str,
        store: StoreKind,
        keyfile: Option<PathBuf>,
        service: Option<String>,
        label: &str,
    ) -> Result<Self, String> {
        let pubkey = hex::encode(pubkey_from_seed(seed).as_bytes());
        Ok(Self {
            v: DESCRIPTOR_VERSION,
            pubkey,
            hint: hint.to_string(),
            store,
            keyfile: keyfile.map(|p| absolutize(&p)),
            service,
            label: label.to_string(),
        })
    }

    /// Canonical `mrd1:…@hint` string for this account.
    pub fn id_string(&self) -> Result<String, String> {
        let raw = hex::decode(&self.pubkey).map_err(|_| "descriptor pubkey is not valid hex")?;
        let pk: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "descriptor pubkey is not 32 bytes")?;
        to_id_string(&pk, &self.hint).map_err(|e| e.to_string())
    }

    pub fn save(&self) -> Result<(), String> {
        let path = descriptor_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        let json =
            serde_json::to_vec_pretty(self).map_err(|e| format!("serializing descriptor: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("writing {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn load() -> Result<Self, String> {
        let path = descriptor_path()?;
        let bytes = std::fs::read(&path).map_err(|_| {
            format!(
                "no account found at {} — run `meridian id new` first",
                path.display()
            )
        })?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parsing {}: {e}", path.display()))
    }
}

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

/// The config directory: `$MERIDIAN_HOME`, else `~/.config/meridian`.
fn config_dir() -> Result<PathBuf, String> {
    if let Ok(home) = std::env::var("MERIDIAN_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = std::env::var("HOME").map_err(|_| "neither MERIDIAN_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".config").join("meridian"))
}

fn descriptor_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("account.json"))
}

/// The sealed chat-session store path (ratchet state + prekey vault), next to the account
/// descriptor. Contents are E2EE-sealed under a keystore-derived key (never plaintext).
pub fn sessions_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("sessions.bin"))
}

fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}
