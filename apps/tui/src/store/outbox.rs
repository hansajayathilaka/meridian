//! `$MERIDIAN_HOME/tui/outbox.json` (v1) — sealed, local retry queue.
//!
//! **`TODO: confirm` this schema.** tui-client.md §5 describes `outbox.json` only at the layout
//! level ("sealed, local retry queue") — no field-by-field shape is given, unlike `contacts.json`
//! and `history/*.jsonl`, which the doc spells out exactly. Until T07 (offline mailbox) lands,
//! `config.toml`'s own doc (task 4.14) is explicit that `pending` means "this client will retry
//! sending while it is running" — never server-side store-and-forward — so this file is understood
//! here as the **persisted form of that in-process retry queue**, surviving a restart of the TUI
//! itself (not a durability promise beyond that: there is still no server-side mailbox).
//!
//! The fields below are a deliberately small, working guess at what a restart-surviving retry
//! queue needs — `peer_pubkey`/`mid`/`stream` to identify what's being retried and correlate it
//! with the matching `history/*.jsonl` entry (same `mid`), `body` so a retry can actually resend
//! without depending on the history file also being intact, and `attempt_count`/`next_retry_at`
//! for backoff. Revisit this shape once a real send-effect wiring (post-4.15) or T07 needs
//! something this design didn't anticipate — nothing downstream depends on this exact shape yet.

use std::path::Path;

use meridian_core::identity::{KeyHandle, SecretStore};
use serde::{Deserialize, Serialize};

use super::migrate::MigrationStep;
use super::StoreError;

pub const CURRENT_VERSION: u64 = 1;
const FILE_NAME: &str = "outbox.json";

/// No `v1 -> v2` step exists yet (see `migrate.rs`'s module doc).
const MIGRATIONS: &[MigrationStep] = &[];

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OutboxDocument {
    pub v: u64,
    pub entries: Vec<OutboxEntry>,
}

/// `TODO: confirm` — see the module doc. One message this client is still retrying to send.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// 64 lowercase hex — same shape as `contacts.json`'s `pubkey`.
    pub peer_pubkey: String,
    /// The same locally generated message id as the matching `history/*.jsonl` entry, for
    /// correlation/dedup.
    pub mid: String,
    pub stream: String,
    /// Kept here (rather than only referenced by `mid` into the sealed history file) so a retry
    /// does not depend on that file also being present/intact — see the module doc's cost/benefit
    /// note. No new exposure versus keeping it only in history: both files are sealed under the
    /// same derived key.
    pub body: String,
    pub attempt_count: u32,
    pub next_retry_at: u64,
    pub created_at: u64,
}

/// Loads `outbox.json` from its default path, or an empty `v1` document if it does not exist yet.
pub fn load_or_default(
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<OutboxDocument, StoreError> {
    load_or_default_at(&super::outbox_path()?, store, handle)
}

/// [`load_or_default`], but against an explicit path (test seam).
pub fn load_or_default_at(
    path: &Path,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<OutboxDocument, StoreError> {
    match std::fs::metadata(path) {
        Ok(_) => {
            let value = super::read_sealed_migrating(
                path,
                FILE_NAME,
                store,
                handle,
                CURRENT_VERSION,
                MIGRATIONS,
            )?;
            Ok(serde_json::from_value(value)?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(OutboxDocument {
            v: CURRENT_VERSION,
            entries: Vec::new(),
        }),
        Err(e) => Err(e.into()),
    }
}

/// Seals and writes `doc` to `outbox.json`'s default path.
pub fn save(
    doc: &OutboxDocument,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    save_at(&super::outbox_path()?, doc, store, handle)
}

/// [`save`], but against an explicit path (test seam).
pub fn save_at(
    path: &Path,
    doc: &OutboxDocument,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    super::write_sealed(path, doc, store, handle)
}
