//! Account descriptor persistence and `$MERIDIAN_HOME` layout helpers.
//!
//! The descriptor is the small, **non-secret** record that tells a shim (CLI, TUI, …) where the
//! current account's private key lives (an age keyfile path, or an OS-keystore service+label) plus
//! the public key and hint needed to render the ID without unlocking anything. It is written to
//! `$MERIDIAN_HOME` (default `~/.config/meridian`).
//!
//! This module lives in `meridian-core` (not `meridian-cli`) so every shim can reach the same
//! `$MERIDIAN_HOME` layout through the same code path — per ADR 0020, `meridian-tui` depends on
//! `meridian-core` only, never on `meridian-cli`, so this could not stay CLI-local without forking
//! the account-descriptor logic between clients (task 4.13).
//!
//! Security note: the descriptor holds only public data (public key, hint, store location). The
//! private key is never in it — for `--store os` nothing secret touches disk at all, which is the
//! T01 acceptance property.

use std::path::{Path, PathBuf};

use figment::providers::{Format, Json};
use figment::Figment;
use serde::{Deserialize, Serialize};

use meridian_identity::{pubkey_from_seed, to_id_string, AccountId};

const DESCRIPTOR_VERSION: u8 = 1;

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

    /// Deliberately **not** given an environment-variable override layer (ADR 0018): every field
    /// here is identity-bearing (`pubkey`, `keyfile` path, `service`, `label`), and an env var
    /// silently redirecting which identity a command operates on is an identity-substitution
    /// risk, not a legitimate config knob. Only the file-parsing engine uses `figment`, for
    /// consistency with the CLI's `policy.rs`.
    pub fn load() -> Result<Self, String> {
        let path = descriptor_path()?;
        if !path.exists() {
            return Err(format!(
                "no account found at {} — run `meridian id new` first",
                path.display()
            ));
        }
        Figment::from(Json::file(&path))
            .extract()
            .map_err(|e| format!("parsing {}: {e}", path.display()))
    }
}

/// The config directory: `$MERIDIAN_HOME`, else `~/.config/meridian`.
pub fn config_dir() -> Result<PathBuf, String> {
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

/// The sealed trust-store path (`trust.rs`'s `TrustStore`: contacts + pinned-key history +
/// key-change state), next to the account descriptor — same layout convention as
/// [`sessions_path`], and (task 4.4) sealed under the identical `at_rest::STORE_KEY_INFO`
/// derivation (ADR 0021: one key derivation, shared by every client-local sealed store).
pub fn trust_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("trust.bin"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_identity::{generate_account, MemorySecretStore};

    /// Serializes test access to `MERIDIAN_HOME`/`HOME` env vars, which are process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev_home: Option<String>,
    }

    impl EnvGuard {
        fn set(dir: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev_home = std::env::var("MERIDIAN_HOME").ok();
            // SAFETY: guarded by ENV_LOCK, single-threaded test access to this process-global.
            unsafe {
                std::env::set_var("MERIDIAN_HOME", dir);
            }
            Self {
                _lock: lock,
                prev_home,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: guarded by ENV_LOCK, single-threaded test access to this process-global.
            unsafe {
                match &self.prev_home {
                    Some(v) => std::env::set_var("MERIDIAN_HOME", v),
                    None => std::env::remove_var("MERIDIAN_HOME"),
                }
            }
        }
    }

    #[test]
    fn config_dir_honors_meridian_home() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set(tmp.path());
        assert_eq!(config_dir().expect("config_dir"), tmp.path());
    }

    #[test]
    fn sessions_path_is_config_dir_sessions_bin() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set(tmp.path());
        assert_eq!(
            sessions_path().expect("sessions_path"),
            tmp.path().join("sessions.bin")
        );
    }

    #[test]
    fn trust_path_is_config_dir_trust_bin() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set(tmp.path());
        assert_eq!(
            trust_path().expect("trust_path"),
            tmp.path().join("trust.bin")
        );
    }

    #[test]
    fn descriptor_round_trips_through_save_and_load() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set(tmp.path());

        let store = MemorySecretStore::new();
        let account = generate_account(&store, "example.org").expect("generate_account");
        let descriptor = AccountDescriptor::new_file(&account, Path::new("key.age"));
        descriptor.save().expect("save");

        let loaded = AccountDescriptor::load().expect("load");
        assert_eq!(loaded.pubkey, descriptor.pubkey);
        assert_eq!(loaded.hint, descriptor.hint);
        assert_eq!(loaded.store, descriptor.store);
        assert_eq!(
            loaded.id_string().expect("id_string"),
            account.to_id_string()
        );
    }

    #[test]
    fn load_without_descriptor_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set(tmp.path());
        assert!(AccountDescriptor::load().is_err());
    }
}
