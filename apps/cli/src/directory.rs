//! `meridian directory import <path> --org-key <hex>` — the reference CLI surface over
//! [`meridian_core::directory`] (task 4.8): ingest a signed org directory-attestation artifact as
//! a **display-name suggestion with recorded provenance**, never a petname assignment and never a
//! trust decision. See `docs/security/directory-attestation.md` for the settled schema and
//! `meridian_core::directory`'s module doc for the provenance-not-authority boundary this module
//! itself never touches — it only decodes the file, calls
//! [`TrustStore::ingest_directory`](meridian_core::trust::TrustStore::ingest_directory), and
//! reports the result.
//!
//! `--org-key` is the caller-supplied trust anchor (hex-encoded Ed25519 public key), exactly
//! mirroring `federation_map.toml`'s `pinned_identity` — a value the org distributes to its
//! members out-of-band, pinned locally, never fetched or discovered automatically. Never a panic
//! on malformed/hostile input: every failure path (bad hex, wrong length, bad CBOR, signature
//! mismatch, key mismatch, oversized artifact) is reported as a clean error.

use meridian_core::directory::DirectoryAttestation;
use meridian_core::identity::{KeyHandle, SecretStore};
use meridian_core::trust::TrustStore;

use crate::account;

/// `meridian directory import <path> --org-key <hex>`.
pub fn cmd_import(
    path: &std::path::Path,
    org_key_hex: &str,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let expected_org_signing_pub = decode_org_key(org_key_hex)?;

    let raw = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let artifact = DirectoryAttestation::from_cbor(&raw).map_err(|e| {
        format!(
            "{} is not a valid directory attestation: {e}",
            path.display()
        )
    })?;

    let mut trust = load_trust(store, handle)?;
    let ingested = trust
        .ingest_directory(&artifact, &expected_org_signing_pub)
        .map_err(|e| format!("rejected: {e}"))?;
    save_trust(&trust, store, handle)?;

    println!(
        "imported {ingested} directory suggestion(s) from {} (org_domain={})",
        path.display(),
        artifact.org_domain
    );
    Ok(())
}

fn decode_org_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|_| "--org-key is not valid hex".to_string())?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "--org-key must be exactly 32 bytes (64 hex chars)".to_string())
}

/// Mirrors `contact.rs`'s `load_trust` exactly.
fn load_trust(store: &dyn SecretStore, handle: &KeyHandle) -> Result<TrustStore, String> {
    let path = account::trust_path()?;
    match std::fs::read(&path) {
        Ok(sealed) => TrustStore::open_at_rest(store, handle, &sealed)
            .map_err(|e| format!("opening trust store {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Mirrors `contact.rs`'s `save_trust` exactly.
fn save_trust(
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let path = account::trust_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let sealed = trust
        .seal_at_rest(store, handle)
        .map_err(|e| format!("sealing trust store: {e}"))?;
    std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
}
