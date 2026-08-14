//! The sealed local JSON store — `contacts.json`, `history/<peer-pubkey-hex>.jsonl`,
//! `outbox.json` — plus the deliberately-unsealed `state.json` (task 4.15, ADR 0021,
//! [tui-client.md §5](../../../../docs/architecture/tui-client.md#5-local-store--configuration)).
//!
//! ## Layout
//! ```text
//! $MERIDIAN_HOME/tui/
//!   config.toml                     (4.14 — not this module's concern)
//!   contacts.json                   sealed
//!   history/<peer-pubkey-hex>.jsonl sealed, whole-document (see history.rs)
//!   outbox.json                     sealed, local retry queue
//!   state.json                      plaintext UI state
//! ```
//!
//! ## Sealing
//! Every *sealed* file here is a `serde_json`-encoded document, XChaCha20-Poly1305-sealed via
//! [`meridian_core::crypto::at_rest::seal`]/[`open`](meridian_core::crypto::at_rest::open) under a
//! key derived through [`SecretStore::derive_key`] with
//! [`at_rest::STORE_KEY_INFO`](meridian_core::crypto::at_rest::STORE_KEY_INFO) — the *same*
//! derivation `sessions.bin` (`apps/core/src/chat.rs`) and `trust.bin` (`apps/core/src/trust.rs`)
//! already use (ADR 0021: one key derivation, shared by every client-local sealed store). Unlike
//! those two, which seal CBOR, tui-client.md §5 is explicit that these files are sealed **JSON**
//! ("the *content* is plain JSON; the *container* is not") — so every `seal`/`open` call in this
//! module family operates on `serde_json`-encoded bytes, never `ciborium`.
//!
//! [`open`](meridian_core::crypto::at_rest::open)-wrapping functions here fail closed on any
//! AEAD/decode error (ADR 0021 condition 5b, mirroring `trust.rs`'s `open_at_rest` doc comment):
//! a corrupt/tampered/wrong-key blob is a hard [`StoreError`], never silently reinitialized as an
//! empty/default store — that would be indistinguishable from a "reinitialize" attack erasing
//! contacts/history.
//!
//! ## Migrations
//! [`migrate`] is the shared, file-agnostic harness: every document here carries a top-level
//! `"v"`; opening a document whose `"v"` is newer than this build understands is a hard, named
//! error (never silently truncated to old-schema semantics), and a forward migration writes a
//! `.bak` of the pre-migration bytes before rewriting the file in place. See [`migrate`]'s module
//! doc for the "why is there no real v1→v2 step yet" note and how one slots in later.
//!
//! `apps/tui` depends on `meridian-core` only (ADR 0020) — every crypto/identity type below is
//! reached through `meridian_core::{crypto, identity}`'s re-exports, never a direct
//! `meridian-crypto`/`meridian-identity` dependency.
//!
//! The read/write/migrate helpers below (`read_sealed_migrating`, `write_sealed`,
//! `read_plain_migrating`, `write_plain`, `atomic_write`, `bak_path`, `store_key`) are `pub` rather
//! than `pub(crate)` deliberately: they are the harness surface a real future document type would
//! build on, and `tests/store.rs` exercises the migration+`.bak` mechanics against a synthetic
//! schema directly through them (see `migrate.rs`'s module doc for why that test is synthetic
//! rather than against a fabricated `v0` of a real document type).

pub mod contacts;
pub mod export;
pub mod history;
pub mod migrate;
pub mod outbox;
pub mod state;

use std::path::{Path, PathBuf};

use meridian_core::crypto::at_rest;
use meridian_core::identity::{KeyHandle, SecretStore};

pub use migrate::{MigrationStep, StoreError};

/// `$MERIDIAN_HOME/tui` — the directory every file this module manages lives under. Reuses
/// `meridian_core::account::config_dir` (the same `$MERIDIAN_HOME` resolution `account.json` /
/// `sessions.bin` / `trust.bin` use), joined with `tui`, exactly mirroring `config.rs`'s
/// `default_config_path` (`config_dir()?.join("tui").join("config.toml")`).
pub fn tui_store_dir() -> Result<PathBuf, StoreError> {
    Ok(meridian_core::account::config_dir()
        .map_err(StoreError::Path)?
        .join("tui"))
}

/// `$MERIDIAN_HOME/tui/contacts.json`.
pub fn contacts_path() -> Result<PathBuf, StoreError> {
    Ok(tui_store_dir()?.join("contacts.json"))
}

/// `$MERIDIAN_HOME/tui/outbox.json`.
pub fn outbox_path() -> Result<PathBuf, StoreError> {
    Ok(tui_store_dir()?.join("outbox.json"))
}

/// `$MERIDIAN_HOME/tui/state.json`.
pub fn state_path() -> Result<PathBuf, StoreError> {
    Ok(tui_store_dir()?.join("state.json"))
}

/// `$MERIDIAN_HOME/tui/history`.
pub fn history_dir() -> Result<PathBuf, StoreError> {
    Ok(tui_store_dir()?.join("history"))
}

/// `$MERIDIAN_HOME/tui/history/<peer_pubkey_hex>.jsonl`.
pub fn history_path(peer_pubkey_hex: &str) -> Result<PathBuf, StoreError> {
    Ok(history_dir()?.join(format!("{peer_pubkey_hex}.jsonl")))
}

/// Derive the store key through `store` (the private seed never leaves it) — identical call to
/// `chat.rs`'s and `trust.rs`'s own `store_key` helpers, deliberately the same
/// [`at_rest::STORE_KEY_INFO`] label (ADR 0021: one derivation per account, shared by every
/// client-local sealed store rather than a bespoke domain-separation string per store).
pub fn store_key(store: &dyn SecretStore, handle: &KeyHandle) -> Result<[u8; 32], StoreError> {
    Ok(store.derive_key(handle, at_rest::STORE_KEY_INFO)?)
}

/// The sibling `.bak` path for `path` (`contacts.json` → `contacts.json.bak`), written before a
/// forward migration rewrites `path` in place (task deliverable 2).
pub fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

/// Write `bytes` to `path` via a same-directory temp file + rename, so a crash mid-write leaves
/// either the old file or the new one intact, never a truncated/partial one. Used for every
/// whole-document rewrite in this module family (`contacts.json`, `outbox.json`, `state.json`,
/// and the resealed `history/*.jsonl` — see that module's doc for why history's "append" is a
/// whole-document rewrite too, not a true incremental append).
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Reads, decrypts, version-checks, and (if a forward migration applies) migrates+reseals+
/// rewrites-in-place the sealed document at `path`. `path` must already exist — a genuinely
/// missing file is each document type's own `load_or_default`'s concern (mirroring
/// `apps/cli/src/chat.rs`'s `load_state`/`load_trust`: "missing file means fresh store, any other
/// error is fatal"), not this function's.
///
/// Fails closed on any AEAD/decode failure ([`StoreError::SealFailure`], ADR 0021 condition 5b):
/// never falls back to a fresh/default document on a decrypt failure.
pub fn read_sealed_migrating(
    path: &Path,
    file: &'static str,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    current_version: u64,
    steps: &[MigrationStep],
) -> Result<serde_json::Value, StoreError> {
    let sealed = std::fs::read(path)?;
    let key = store_key(store, handle)?;
    let plaintext = at_rest::open(&key, &sealed).map_err(|_| StoreError::SealFailure { file })?;
    let value: serde_json::Value = serde_json::from_slice(&plaintext)?;
    let (migrated_value, migrated) = migrate::migrate_forward(value, file, current_version, steps)?;
    if migrated {
        atomic_write(&bak_path(path), &sealed)?;
        let replacement = serde_json::to_vec(&migrated_value)?;
        let resealed = at_rest::seal(&key, &replacement)?;
        atomic_write(path, &resealed)?;
    }
    Ok(migrated_value)
}

/// Serializes `doc` (already at `current_version`) as JSON, seals it, and writes it to `path`
/// atomically. The write-side counterpart to [`read_sealed_migrating`] for the three sealed
/// non-append document types (`contacts.json`, `outbox.json`, and history's whole-file rewrite).
pub fn write_sealed<T: serde::Serialize>(
    path: &Path,
    doc: &T,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    let key = store_key(store, handle)?;
    let plaintext = serde_json::to_vec(doc)?;
    let sealed = at_rest::seal(&key, &plaintext)?;
    atomic_write(path, &sealed)
}

/// The plaintext counterpart to [`read_sealed_migrating`], for `state.json` — no seal/open, same
/// version-check/`.bak`/rewrite-in-place plumbing.
pub fn read_plain_migrating(
    path: &Path,
    file: &'static str,
    current_version: u64,
    steps: &[MigrationStep],
) -> Result<serde_json::Value, StoreError> {
    let raw = std::fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    let (migrated_value, migrated) = migrate::migrate_forward(value, file, current_version, steps)?;
    if migrated {
        atomic_write(&bak_path(path), &raw)?;
        let replacement = serde_json::to_vec_pretty(&migrated_value)?;
        atomic_write(path, &replacement)?;
    }
    Ok(migrated_value)
}

/// The plaintext counterpart to [`write_sealed`], for `state.json`.
pub fn write_plain<T: serde::Serialize>(path: &Path, doc: &T) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec_pretty(doc)?;
    atomic_write(path, &bytes)
}
