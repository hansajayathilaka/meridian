//! Shared migration machinery for every versioned document in this store family
//! (`contacts.json`, `history/*.jsonl` entries, `outbox.json`, `state.json`) — one harness, not
//! four copy-pasted version checks (task deliverable 2).
//!
//! **Today, every document's schema is `v1` and there is no real `v1 → v2` step** — this crate has
//! shipped only one schema generation so far. What this module implements and tests *now*,
//! ahead of a real second version ever existing, is the harness itself:
//! - **Refuse a newer schema than understood.** [`migrate_forward`] hard-errors with
//!   [`StoreError::NewerSchema`] (naming both the found and understood versions) the moment a
//!   document's `"v"` exceeds `current_version` — never silently truncated to old-schema
//!   semantics, never a partial read.
//! - **The `.bak`-before-migrating plumbing.** [`super::read_sealed_migrating`] and
//!   [`super::read_plain_migrating`] write a sibling `.bak` of the pre-migration bytes before
//!   rewriting a file in place — exercised in this crate's tests against a *synthetic* schema (see
//!   below), since no real document here has ever shipped a `v1 → v2` step to exercise against.
//!
//! A real `v1 → v2` migration later is just one more `MigrationStep { from: 1, upgrade: fn(Value)
//! -> Value }` entry in a document type's `MIGRATIONS` slice — [`migrate_forward`] itself does not
//! change.
//!
//! ## The "v0 fixture" test, and why it's synthetic
//! The task's own test deliverable asks for "forward migration from a v0 fixture". None of the
//! schemas in tui-client.md §5 ever had a `"v": 0` generation — every one of them was born at
//! `v1`. Rather than fabricate a fake `v0` wire format nothing in this codebase ever produced,
//! `tests/store.rs`'s migration test exercises [`migrate_forward`] directly against a small
//! synthetic two-version schema (`v1` with a field a hypothetical `v2` defaults/renames) — proving
//! the harness's forward-migration + `.bak` mechanics work, without inventing history for the real
//! document types that never had it.

use serde_json::Value;

/// One forward step: `from` a document at schema version `from`, `upgrade` returns the equivalent
/// document at version `from + 1`. [`migrate_forward`] applies these in sequence until the
/// document reaches `current_version`.
pub struct MigrationStep {
    pub from: u64,
    pub upgrade: fn(Value) -> Value,
}

/// Errors from opening/migrating a versioned document in this store family.
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] meridian_core::crypto::CryptoError),
    #[error("keystore error: {0}")]
    Keystore(#[from] meridian_core::identity::StoreError),
    #[error("resolving $MERIDIAN_HOME: {0}")]
    Path(String),
    /// `path`'s "v" field is newer than this build understands — fail closed rather than guess at
    /// forward-compatible field semantics (task deliverable 2: "refuses to run against a newer
    /// schema than it understands ... rather than silently discarding fields").
    #[error(
        "{file}: schema version {found} is newer than this client understands (up to v{understood}) \
         — upgrade meridian-tui before opening this store"
    )]
    NewerSchema {
        file: &'static str,
        found: u64,
        understood: u64,
    },
    /// A document's `"v"` is older than `current_version`, but no [`MigrationStep`] starts at that
    /// version — a gap in the migration chain, not a normal "nothing to do" case.
    #[error("{file}: no migration step from v{from} toward v{to}")]
    NoMigrationPath {
        file: &'static str,
        from: u64,
        to: u64,
    },
    /// A document is missing its `"v"` field, or it isn't a non-negative integer.
    #[error("{0}: missing or malformed \"v\" field")]
    MissingVersion(&'static str),
    /// [`meridian_core::crypto::at_rest::open`] failed — AEAD tag mismatch, truncated blob, or
    /// wrong key. Fails closed (ADR 0021 condition 5b): never treated as "no store yet".
    #[error("{file}: sealed document failed to authenticate — refusing to open (tamper, corruption, or wrong key)")]
    SealFailure { file: &'static str },
    /// A sealed document's decrypted plaintext was not valid UTF-8 (history's `.jsonl` encoding
    /// requires it). Distinct from [`StoreError::SealFailure`]: the AEAD tag verified, but the
    /// content still isn't the JSON-Lines text this module expects.
    #[error("{0}: decrypted content is not valid UTF-8")]
    InvalidUtf8(&'static str),
    /// A sealed `history/<peer-pubkey-hex>.jsonl` file's embedded peer-binding header does not
    /// match the peer pubkey the caller asked to open it as. Most likely two peers' sealed files
    /// were swapped on disk by someone with local filesystem write access (they decrypt and
    /// deserialize cleanly under the shared derived key, so nothing else would catch this) — fails
    /// closed rather than silently returning the wrong peer's transcript.
    #[error(
        "{file}: sealed file's peer binding ({found}) does not match the requested peer \
         ({expected}) — refusing to open a possibly swapped or mismatched history file"
    )]
    PeerMismatch {
        file: &'static str,
        expected: String,
        found: String,
    },
}

/// Reads `value`'s `"v"` field. Errs [`StoreError::MissingVersion`] if absent or not a
/// non-negative integer — every document in this family carries `"v"` unconditionally, so a
/// missing one is itself a fail-closed condition, not treated as "assume v1".
fn read_version(value: &Value, file: &'static str) -> Result<u64, StoreError> {
    value
        .get("v")
        .and_then(Value::as_u64)
        .ok_or(StoreError::MissingVersion(file))
}

/// Checks `value`'s version against `current_version` and, if it's older, applies `steps` in
/// sequence until it reaches `current_version`. Returns the (possibly unchanged) value and whether
/// any step actually ran.
///
/// - `value`'s version newer than `current_version` → [`StoreError::NewerSchema`] (hard, named).
/// - `value`'s version equal to `current_version` → returned unchanged, `migrated = false` (the
///   "identity migration", task's own wording: "the identity migration from v1 to v1 (no-op)").
/// - `value`'s version older, with a complete step chain to `current_version` → each step applied
///   in order, `migrated = true`.
/// - `value`'s version older, with a gap in the step chain → [`StoreError::NoMigrationPath`].
pub fn migrate_forward(
    mut value: Value,
    file: &'static str,
    current_version: u64,
    steps: &[MigrationStep],
) -> Result<(Value, bool), StoreError> {
    let mut v = read_version(&value, file)?;
    if v > current_version {
        return Err(StoreError::NewerSchema {
            file,
            found: v,
            understood: current_version,
        });
    }
    let mut migrated = false;
    while v < current_version {
        let step = steps
            .iter()
            .find(|s| s.from == v)
            .ok_or(StoreError::NoMigrationPath {
                file,
                from: v,
                to: current_version,
            })?;
        value = (step.upgrade)(value);
        migrated = true;
        v += 1;
    }
    Ok((value, migrated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_version_is_a_no_op_identity_migration() {
        let doc = serde_json::json!({ "v": 1, "x": 1 });
        let (out, migrated) = migrate_forward(doc.clone(), "test", 1, &[]).expect("v1 == v1");
        assert_eq!(out, doc);
        assert!(!migrated);
    }

    #[test]
    fn newer_than_understood_is_a_named_hard_error() {
        let doc = serde_json::json!({ "v": 2, "x": 1 });
        let err = migrate_forward(doc, "widget.json", 1, &[]).expect_err("v2 > v1 must refuse");
        match err {
            StoreError::NewerSchema {
                file,
                found,
                understood,
            } => {
                assert_eq!(file, "widget.json");
                assert_eq!(found, 2);
                assert_eq!(understood, 1);
            }
            other => panic!("expected NewerSchema, got {other:?}"),
        }
    }

    #[test]
    fn missing_version_field_is_rejected() {
        let doc = serde_json::json!({ "x": 1 });
        let err = migrate_forward(doc, "widget.json", 1, &[]).expect_err("no v field");
        assert!(matches!(err, StoreError::MissingVersion("widget.json")));
    }

    /// The synthetic "v0 fixture" case (see module doc): a two-version schema this test invents
    /// purely to prove the harness's step-chain application actually runs and produces the
    /// upgraded document, since no real store document here has ever had more than one version.
    #[test]
    fn forward_migration_applies_registered_steps_in_order() {
        fn v1_to_v2(mut value: Value) -> Value {
            // A hypothetical v2 renames "name" to "petname" and bumps v.
            if let Some(obj) = value.as_object_mut() {
                if let Some(name) = obj.remove("name") {
                    obj.insert("petname".to_string(), name);
                }
                obj.insert("v".to_string(), serde_json::json!(2));
            }
            value
        }
        fn v2_to_v3(mut value: Value) -> Value {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("v".to_string(), serde_json::json!(3));
                obj.insert("new_field".to_string(), serde_json::json!(null));
            }
            value
        }
        let steps = [
            MigrationStep {
                from: 1,
                upgrade: v1_to_v2,
            },
            MigrationStep {
                from: 2,
                upgrade: v2_to_v3,
            },
        ];

        let v1_doc = serde_json::json!({ "v": 1, "name": "bob" });
        let (migrated, changed) =
            migrate_forward(v1_doc, "synthetic.json", 3, &steps).expect("v1 -> v3 chain");
        assert!(changed);
        assert_eq!(migrated["v"], serde_json::json!(3));
        assert_eq!(migrated["petname"], serde_json::json!("bob"));
        assert!(migrated.get("name").is_none());
        assert_eq!(migrated["new_field"], Value::Null);
    }

    #[test]
    fn gap_in_the_migration_chain_is_a_named_error_not_a_silent_partial_migration() {
        // A document at v1 but the harness only knows a v2 -> v3 step: it can never reach v1 -> v2.
        fn noop(v: Value) -> Value {
            v
        }
        let steps = [MigrationStep {
            from: 2,
            upgrade: noop,
        }];
        let doc = serde_json::json!({ "v": 1 });
        let err = migrate_forward(doc, "gappy.json", 3, &steps).expect_err("no v1 -> v2 step");
        assert!(matches!(
            err,
            StoreError::NoMigrationPath {
                file: "gappy.json",
                from: 1,
                to: 3
            }
        ));
    }
}
