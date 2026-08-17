//! `$MERIDIAN_HOME/tui/state.json` (v1) — deliberately **unsealed** plaintext UI state.
//!
//! tui-client.md §5's binding invariant: `state.json` "must therefore contain no petnames, no
//! message text, and no key material — only view geometry and a conversation index."
//!
//! **`TODO: confirm` this exact field list** — tui-client.md §5 only describes the shape at a high
//! level ("last conversation, pane widths, scroll" + "a conversation index"); the concrete fields
//! below are this task's own reasonable-minimum reading of that sentence, not something the design
//! doc pins down field-by-field the way it does for `contacts.json`/`history/*.jsonl`.
//!
//! **The invariant is enforced by construction, not just by convention.** Every field in
//! [`StateDocument`] (and its nested [`PaneGeometry`]/[`ScrollState`]) is a number, a bool, or —
//! for [`StateDocument::last_conversation`] — an opaque `[u8; 16]` token, which `serde` encodes as
//! a JSON array of 16 numbers, never a string. There is deliberately no `String` field anywhere in
//! this type: a petname or message body could only be smuggled in by *adding* a `String`-typed
//! field, which is exactly what `tests/store.rs`'s structural test (serialize → walk every JSON
//! leaf → assert none is a `Value::String`, and none is a byte-array leaf matching a real contact
//! pubkey) is designed to catch.
//!
//! **`last_conversation` is an opaque, locally-generated, non-identifying handle — never the
//! contact's pubkey, its `mrd1:` id, or a positional index into `contacts.json`** (ADR 0021
//! condition 2, binding, not a convention). It mirrors [`ContactRecord::conv_handle`]
//! (`store::contacts`) — a random 16-byte token minted once per contact (see that field's doc for
//! the minting-policy choice) and persisted in the *sealed* `contacts.json`. Reading `state.json`
//! alone (no account key, no decrypt of `contacts.json`) therefore reveals only "some conversation,
//! identified by this opaque token, was last open" — not *which* contact, matching ADR 0021's
//! accepted residual R1. 16 bytes is a deliberate, distinct byte length from a raw 32-byte Ed25519
//! pubkey, so a byte-length check alone rules out this token ever structurally coinciding with one.
//!
//! [`ContactRecord::conv_handle`]: super::contacts::ContactRecord::conv_handle

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::migrate::MigrationStep;
use super::StoreError;

pub const CURRENT_VERSION: u64 = 1;
const FILE_NAME: &str = "state.json";

/// No `v1 -> v2` step exists yet (see `migrate.rs`'s module doc).
const MIGRATIONS: &[MigrationStep] = &[];

/// The whole `state.json` document. See the module doc for the no-prohibited-fields invariant and
/// how it's enforced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDocument {
    pub v: u64,
    /// The opaque conversation handle (mirrors a contact's `contacts.json`-side
    /// [`ContactRecord::conv_handle`](super::contacts::ContactRecord::conv_handle)) of the
    /// last-open conversation, if any. Never a pubkey, `mrd1:` id, or index — see the module doc.
    /// `None` before any conversation has ever been opened.
    pub last_conversation: Option<[u8; 16]>,
    pub panes: PaneGeometry,
    pub scroll: ScrollState,
}

impl Default for StateDocument {
    fn default() -> Self {
        Self {
            v: CURRENT_VERSION,
            last_conversation: None,
            panes: PaneGeometry::default(),
            scroll: ScrollState::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaneGeometry {
    pub sidebar_width: u16,
    pub composer_height: u16,
}

impl Default for PaneGeometry {
    fn default() -> Self {
        Self {
            sidebar_width: 24,
            composer_height: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScrollState {
    pub offset: u32,
}

/// Loads `state.json` from its default path, or [`StateDocument::default`] if it does not exist
/// yet.
pub fn load_or_default() -> Result<StateDocument, StoreError> {
    load_or_default_at(&super::state_path()?)
}

/// [`load_or_default`], but against an explicit path (test seam).
pub fn load_or_default_at(path: &Path) -> Result<StateDocument, StoreError> {
    match std::fs::metadata(path) {
        Ok(_) => {
            let value = super::read_plain_migrating(path, FILE_NAME, CURRENT_VERSION, MIGRATIONS)?;
            Ok(serde_json::from_value(value)?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StateDocument::default()),
        Err(e) => Err(e.into()),
    }
}

/// Writes `doc` to `state.json`'s default path, plaintext.
pub fn save(doc: &StateDocument) -> Result<(), StoreError> {
    save_at(&super::state_path()?, doc)
}

/// [`save`], but against an explicit path (test seam).
pub fn save_at(path: &Path, doc: &StateDocument) -> Result<(), StoreError> {
    super::write_plain(path, doc)
}
