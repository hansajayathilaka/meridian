//! `$MERIDIAN_HOME/tui/contacts.json` (v1) — sealed. Schema exactly as given in
//! [tui-client.md §5](../../../../docs/architecture/tui-client.md#5-local-store--configuration).
//!
//! This deliberately **duplicates** what `meridian_core::trust::TrustStore`/`Contact` already
//! track (petname, trust state, pinned-key history): that store is the crypto-relevant source of
//! truth every client shares (`trust.bin`); this one is the TUI's own display-oriented local cache
//! screens read from directly, per tui-client.md §5. Not something to unify in this task.

use std::path::Path;

use meridian_core::identity::{KeyHandle, SecretStore};
use serde::{Deserialize, Serialize};

use super::migrate::MigrationStep;
use super::StoreError;

pub const CURRENT_VERSION: u64 = 1;
const FILE_NAME: &str = "contacts.json";

/// No `v1 -> v2` step exists yet (see `migrate.rs`'s module doc) — this is where one would be
/// registered.
const MIGRATIONS: &[MigrationStep] = &[];

/// The whole `contacts.json` document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ContactsDocument {
    pub v: u64,
    pub contacts: Vec<ContactRecord>,
}

/// One entry in `contacts.json`. Field-for-field the schema tui-client.md §5 specifies.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactRecord {
    /// 64 lowercase hex — the primary key, not the petname.
    pub pubkey: String,
    /// Full ID as entered, for display and routing hint.
    pub id: String,
    pub hint: String,
    /// LOCAL ONLY — never taken from the wire (system-design.md §3.1, mirrored from
    /// `meridian_core::trust::Contact::petname`'s own invariant).
    #[serde(default)]
    pub petname: Option<String>,
    pub trust: TrustLabel,
    #[serde(default)]
    pub pinned_key_history: Vec<PinnedKeyRecord>,
    /// Reserved for T13 multi-device.
    #[serde(default)]
    pub device_record_version_seen: Option<u64>,
    #[serde(default)]
    pub policy_override: Option<PolicyOverride>,
    pub added_at: u64,
    pub last_activity_at: u64,
    #[serde(default)]
    pub unread: u64,
    /// Opaque, locally-generated, non-identifying handle for this contact's conversation
    /// (ADR 0021 condition 2). Only this token — never `pubkey` or `id` above — is ever mirrored
    /// into the unsealed `state.json`'s `last_conversation` field, so reading `state.json` alone
    /// (no account key, no decrypt of this *sealed* file) cannot identify which contact a
    /// conversation handle belongs to. 16 bytes: a byte length distinct from `pubkey`'s 32 raw
    /// bytes, so even a structural (length-only) check rules out confusing the two, not just
    /// convention. `None` until [`ContactRecord::conv_handle_or_mint`] mints one.
    ///
    /// **Minting policy (documented choice, ADR 0021 condition 2 leaves it open):** the ADR's
    /// wording — "a random token minted when a conversation is first opened" — is read here as
    /// *once per contact*, not once per open/session: lazily minted the first time it's needed,
    /// then stable and persisted for that contact's lifetime. This is the simpler reading that
    /// still satisfies "opaque, non-identifying" (a stable-but-opaque handle leaks no more than a
    /// freshly-reminted one — both alike fail to identify *which* contact per ADR 0021's own R1)
    /// without forcing a `contacts.json` rewrite every time a conversation is merely reopened.
    #[serde(default)]
    pub conv_handle: Option<[u8; 16]>,
}

impl ContactRecord {
    /// Returns this contact's opaque conversation handle, minting and persisting one into this
    /// in-memory record the first time it's needed (see the field doc for the once-per-contact
    /// minting policy). The caller is responsible for saving the owning [`ContactsDocument`]
    /// afterward, exactly as for any other in-memory mutation of a `ContactRecord`.
    pub fn conv_handle_or_mint(&mut self) -> Result<[u8; 16], StoreError> {
        if let Some(handle) = self.conv_handle {
            return Ok(handle);
        }
        let mut handle = [0u8; 16];
        getrandom::fill(&mut handle).map_err(|e| std::io::Error::other(e.to_string()))?;
        self.conv_handle = Some(handle);
        Ok(handle)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLabel {
    New,
    Pinned,
    Verified,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyOverride {
    Direct,
    PreferRelay,
    RelayOnly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PinnedKeyRecord {
    pub pubkey: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Loads `contacts.json` from its default path (`$MERIDIAN_HOME/tui/contacts.json`), or an empty
/// `v1` document if the file does not exist yet. Any other I/O/decrypt/decode error is fatal —
/// mirrors `apps/cli/src/chat.rs`'s `load_state`/`load_trust` shape exactly.
pub fn load_or_default(
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<ContactsDocument, StoreError> {
    load_or_default_at(&super::contacts_path()?, store, handle)
}

/// [`load_or_default`], but against an explicit path (test seam, and the one `export.rs` uses
/// against the real default path).
pub fn load_or_default_at(
    path: &Path,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<ContactsDocument, StoreError> {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ContactsDocument {
            v: CURRENT_VERSION,
            contacts: Vec::new(),
        }),
        Err(e) => Err(e.into()),
    }
}

/// Seals and writes `doc` to `contacts.json`'s default path.
pub fn save(
    doc: &ContactsDocument,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    save_at(&super::contacts_path()?, doc, store, handle)
}

/// [`save`], but against an explicit path (test seam).
pub fn save_at(
    path: &Path,
    doc: &ContactsDocument,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    super::write_sealed(path, doc, store, handle)
}
