//! `$MERIDIAN_HOME/tui/history/<peer-pubkey-hex>.jsonl` (v1) — sealed, one JSON object per line.
//! Schema exactly as given in
//! [tui-client.md §5](../../../../docs/architecture/tui-client.md#5-local-store--configuration).
//!
//! **Whole-document sealing, not line-by-line.** tui-client.md §5's "Sealing" paragraph states
//! "every file marked *sealed* is a JSON document encrypted with ... `at_rest::seal`" without
//! carving out an exception for the one file that happens to be JSON-Lines-formatted; a `.jsonl`
//! file is still one document for this purpose, exactly like `contacts.json`. That reading is
//! deliberate here, not an oversight — the alternative (seal each line independently) would need
//! its own per-line nonce/AEAD framing that tui-client.md §5 never specifies, and would leak the
//! message *count* and each entry's ciphertext length pattern to anyone who can see the file,
//! which whole-document sealing does not.
//!
//! **The consequence: append is not O(1).** tui-client.md §5's per-line note — "one JSON object
//! per line, append-only, so a partial write costs at most the last message" — describes the
//! *plaintext* JSONL format's own crash-safety property in isolation. Once the whole file is
//! sealed as a single AEAD document, [`append`] must actually decrypt the whole file, add the new
//! entry in memory, and reseal+rewrite the whole file — a read-modify-reseal-write, not a true
//! incremental disk append. This module is honest about that rather than silently implying
//! O(1)-append survives the seal. Crash-safety instead comes from [`super::atomic_write`]'s
//! temp-file-then-rename: an interrupted [`append`] leaves either the prior sealed file intact or
//! the fully-rewritten new one, never a half-written/corrupt blob.
//!
//! **Peer binding (review fix).** Every `history/*.jsonl` file is sealed under the *same* derived
//! key and has an identical [`HistoryEntry`] schema carrying no peer-identity field — so anyone
//! with local filesystem *write* access (not the decrypt key) could otherwise swap two peers'
//! sealed files on disk and have both decrypt and deserialize cleanly, silently misattributing one
//! contact's transcript to the other. To close this, the plaintext body's first line is always a
//! [`HistoryHeader`] naming the peer this file belongs to; [`load_or_default_at`] verifies it
//! against the `peer_pubkey_hex` the caller asked to open before returning any entries, and
//! [`StoreError::PeerMismatch`] is a hard, fail-closed error, never a silent accept.

use std::path::Path;

use meridian_core::identity::{KeyHandle, SecretStore};
use serde::{Deserialize, Serialize};

use super::migrate::MigrationStep;
use super::StoreError;

pub const CURRENT_VERSION: u64 = 1;
const FILE_NAME: &str = "history/<peer>.jsonl";

/// No `v1 -> v2` step exists yet (see `migrate.rs`'s module doc).
const MIGRATIONS: &[MigrationStep] = &[];

/// The first line of every sealed history file's decrypted plaintext body — binds the file to the
/// peer it claims to hold a transcript for (see the module doc's "Peer binding" note). Not a
/// [`HistoryEntry`]; [`load_or_default_at`] parses and verifies exactly one of these before any
/// entry lines.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct HistoryHeader {
    /// 64 lowercase hex — same shape as `contacts.json`'s `pubkey`, and the same string this
    /// file's own `history_path`-derived filename is built from.
    peer_pubkey: String,
}

/// One transcript entry — one line of the `.jsonl` document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub v: u64,
    /// A locally generated 128-bit message id (hex), used for dedup and matching delivery
    /// updates. Not a wire field — see the module-level `TODO: confirm` in tui-client.md §5 about
    /// adopting envelope v2's `eid` for this once it exists.
    pub mid: String,
    pub dir: Direction,
    pub ts: u64,
    /// The stream-type id (`mrd.chat/1`, …) so future stream types append to the same transcript
    /// and unknown ones render as a placeholder (tui-client.md §8).
    pub stream: String,
    pub body: String,
    pub state: MessageState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageState {
    Composing,
    Pending,
    Sent,
    Delivered,
    Failed,
    Received,
}

/// Reads and decrypts `path`'s whole transcript, verifying the leading [`HistoryHeader`] names
/// `peer_pubkey_hex` (see the module doc's "Peer binding" note — a mismatch is
/// [`StoreError::PeerMismatch`], hard and fail-closed) and migrating each entry line forward if
/// needed (see the module doc: each JSONL entry line carries its own `"v"`, so migration is
/// checked and, if it changed any line, the *whole* resealed file is rewritten together with one
/// `.bak` of the pre-migration sealed bytes). Returns an empty transcript if `path` does not exist
/// yet (no header to check — there is nothing on disk yet to have been swapped).
pub fn load_or_default(
    peer_pubkey_hex: &str,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<Vec<HistoryEntry>, StoreError> {
    load_or_default_at(
        &super::history_path(peer_pubkey_hex)?,
        peer_pubkey_hex,
        store,
        handle,
    )
}

/// [`load_or_default`], but against an explicit path (test seam).
pub fn load_or_default_at(
    path: &Path,
    peer_pubkey_hex: &str,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<Vec<HistoryEntry>, StoreError> {
    let sealed = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let key = super::store_key(store, handle)?;
    let plaintext = meridian_core::crypto::at_rest::open(&key, &sealed)
        .map_err(|_| StoreError::SealFailure { file: FILE_NAME })?;
    let text = String::from_utf8(plaintext).map_err(|_| StoreError::InvalidUtf8(FILE_NAME))?;

    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header: HistoryHeader = match lines.next() {
        Some(line) => serde_json::from_str(line)?,
        // An empty (but present and successfully-decrypted) file has no entries and no header to
        // check — treat like "no transcript yet", consistent with the not-found case above.
        None => return Ok(Vec::new()),
    };
    if header.peer_pubkey != peer_pubkey_hex {
        return Err(StoreError::PeerMismatch {
            file: FILE_NAME,
            expected: peer_pubkey_hex.to_string(),
            found: header.peer_pubkey,
        });
    }

    let mut entries = Vec::new();
    let mut migrated_values = Vec::new();
    let mut any_migrated = false;
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line)?;
        let (migrated_value, migrated) =
            super::migrate::migrate_forward(value, FILE_NAME, CURRENT_VERSION, MIGRATIONS)?;
        any_migrated |= migrated;
        let entry: HistoryEntry = serde_json::from_value(migrated_value.clone())?;
        entries.push(entry);
        migrated_values.push(migrated_value);
    }

    if any_migrated {
        super::atomic_write(&super::bak_path(path), &sealed)?;
        let mut buf = String::new();
        buf.push_str(&serde_json::to_string(&header)?);
        buf.push('\n');
        for v in &migrated_values {
            buf.push_str(&serde_json::to_string(v)?);
            buf.push('\n');
        }
        let resealed = meridian_core::crypto::at_rest::seal(&key, buf.as_bytes())?;
        super::atomic_write(path, &resealed)?;
    }

    Ok(entries)
}

/// Appends `entry` to `peer_pubkey_hex`'s transcript at the default path. See the module doc for
/// why this is a whole-document read-modify-reseal-write, not a true disk append.
pub fn append(
    peer_pubkey_hex: &str,
    entry: &HistoryEntry,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    append_at(
        &super::history_path(peer_pubkey_hex)?,
        peer_pubkey_hex,
        entry,
        store,
        handle,
    )
}

/// [`append`], but against an explicit path (test seam).
pub fn append_at(
    path: &Path,
    peer_pubkey_hex: &str,
    entry: &HistoryEntry,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    let mut entries = load_or_default_at(path, peer_pubkey_hex, store, handle)?;
    entries.push(entry.clone());
    write_all_at(path, peer_pubkey_hex, &entries, store, handle)
}

/// Overwrites `path` with the sealed, whole-document encoding of `entries`, headed by a
/// [`HistoryHeader`] naming `peer_pubkey_hex` — the shared write path [`append_at`] and
/// [`load_or_default_at`]'s migration-rewrite both build on.
pub fn write_all_at(
    path: &Path,
    peer_pubkey_hex: &str,
    entries: &[HistoryEntry],
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    let key = super::store_key(store, handle)?;
    let mut buf = String::new();
    let header = HistoryHeader {
        peer_pubkey: peer_pubkey_hex.to_string(),
    };
    buf.push_str(&serde_json::to_string(&header)?);
    buf.push('\n');
    for entry in entries {
        buf.push_str(&serde_json::to_string(entry)?);
        buf.push('\n');
    }
    let sealed = meridian_core::crypto::at_rest::seal(&key, buf.as_bytes())?;
    super::atomic_write(path, &sealed)
}
