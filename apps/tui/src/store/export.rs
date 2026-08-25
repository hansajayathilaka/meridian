//! `meridian tui --export-json <path>` (task deliverable 3, tui-client.md §5): "writes the same
//! documents unsealed, on demand, for inspection or backup — which is why no persistent-plaintext
//! mode is offered."
//!
//! **Split with `apps/cli/src/tui.rs`.** ADR 0020 keeps `apps/tui` core-only (never depending on
//! `apps/cli`), so the actual `--export-json <path>` **flag** lives in `apps/cli/src/tui.rs`
//! (which already depends on both `meridian-tui` and `meridian-core`, and already knows how to
//! open the account's [`SecretStore`]/[`KeyHandle`] — see that file's `cmd_chat` precedent). This
//! module exposes the plain, I/O-only [`export_json`] function the flag calls into: read each
//! sealed store, decrypt it, and write plain JSON to a mirror of the sealed layout under
//! `<path>/`. `state.json` is copied as-is (it's already unsealed).
//!
//! **Permission hardening (review fix, Unix-only).** `--export-json`'s whole point is to write
//! sealed content — contacts, history, the outbox — as plaintext to disk on demand, so that
//! plaintext must not simply inherit the process umask (commonly world/group-readable). On
//! `cfg(unix)`, [`export_json`] `chmod`s the destination directory (and any `history/` subdirectory
//! it creates) `0700` and every file it writes `0600`, immediately as part of each write rather
//! than as an afterthought pass at the end, so a crash between a write and its `chmod` leaves as
//! small a window as practical. Non-Unix platforms (Windows) do not get this hardening yet — this
//! codebase has no existing precedent for cross-platform permission handling for
//! [`export_json`] to follow, so that gap is left honest rather than papered over.
//!
//! **Live `trust.bin` join (task 5.14).** `contacts.json`'s own [`contacts::ContactRecord::trust`]
//! field is a write-only cache: whichever trust-mutating handler in `crate::worker` last touched a
//! given contact (`run_mark_verified`, `run_set_petname`'s neighbors, `run_acknowledge_key_change`,
//! …) stamps it at that moment, and — absent this join — it goes stale the instant `trust.bin`
//! changes again through any *other* path. Task 5.3 first hit this for `run_mark_verified` and
//! fixed it there with a write-through (reload `contacts.json`, patch the row, save). Task 5.14
//! found the identical bug a second time in `run_acknowledge_key_change`'s escalation branch
//! (`PinnedKeyChanged` → `Blocked`) and made the call this module's doc now documents: rather than
//! add a third, fourth, … write-through at every future trust-mutating call site, [`export_json`]
//! joins `trust.bin` fresh at export time — the same join
//! `crate::screens::main::build_contact_entries` already performs for the live UI, reusing its
//! exact `TrustState -> TrustLabel` mapping ([`crate::worker::to_trust_label`], now `pub(crate)`)
//! rather than a second copy. This closes the bug class at its one true choke point: every
//! `--export-json` run, present and future, reflects the real `trust.bin` state regardless of
//! whether the handler that last touched a contact remembered to write through `contacts.json`.
//! **5.3's own write-through was deliberately left in place**, not removed — the exported
//! `contacts.json` row is now always overwritten with the live value regardless, so that write is
//! genuinely-redundant, harmless belt-and-suspenders (it also still matters for
//! `build_contact_entries`'s own defensive fallback branch, taken when a `trust.bin` record is
//! missing entirely — see that function's doc comment). `run_acknowledge_key_change` itself was
//! *not* given a matching write-through: with the join in place here, one would be pure unused
//! work on every call.

use std::path::Path;

use meridian_core::identity::{KeyHandle, SecretStore};

use super::{contacts, history, outbox, state, StoreError};

/// `chmod 0700` on `dir`. Unix-only — see the module doc.
#[cfg(unix)]
fn harden_dir_permissions(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn harden_dir_permissions(_dir: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// `chmod 0600` on `path`. Unix-only — see the module doc.
#[cfg(unix)]
fn harden_file_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn harden_file_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// `std::fs::create_dir_all(dir)` immediately followed by [`harden_dir_permissions`], so the
/// window between "directory exists" and "directory is `0700`" is as small as practical.
fn create_dir_hardened(dir: &Path) -> Result<(), StoreError> {
    std::fs::create_dir_all(dir)?;
    harden_dir_permissions(dir)?;
    Ok(())
}

/// `std::fs::write(path, bytes)` immediately followed by [`harden_file_permissions`], so the
/// window between "plaintext exists on disk" and "plaintext is `0600`" is as small as practical.
fn write_hardened(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    std::fs::write(path, bytes)?;
    harden_file_permissions(path)?;
    Ok(())
}

/// Writes every store document, unsealed, into `dest_dir` (created if it does not exist), mirroring
/// the sealed layout:
/// ```text
/// <dest_dir>/contacts.json
/// <dest_dir>/history/<peer-pubkey-hex>.jsonl
/// <dest_dir>/outbox.json
/// <dest_dir>/state.json
/// ```
/// A document that does not exist yet on disk (e.g. no contacts added, an empty history
/// directory) is skipped rather than written as an empty placeholder file, so the exported
/// directory reflects only what actually exists — except `state.json`, which — since
/// `StateDocument::default()` is a well-defined, harmless starting point — is always written, for
/// consistency with how the running client would treat a missing one.
pub fn export_json(
    dest_dir: &Path,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    create_dir_hardened(dest_dir)?;

    if super::contacts_path()?.exists() {
        let mut doc = contacts::load_or_default(store, handle)?;
        join_live_trust(&mut doc, store, handle)?;
        let bytes = serde_json::to_vec_pretty(&doc)?;
        write_hardened(&dest_dir.join("contacts.json"), &bytes)?;
    }

    if super::outbox_path()?.exists() {
        let doc = outbox::load_or_default(store, handle)?;
        let bytes = serde_json::to_vec_pretty(&doc)?;
        write_hardened(&dest_dir.join("outbox.json"), &bytes)?;
    }

    let history_dir = super::history_dir()?;
    if history_dir.is_dir() {
        let dest_history_dir = dest_dir.join("history");
        create_dir_hardened(&dest_history_dir)?;
        for entry in std::fs::read_dir(&history_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Some(peer_hex) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let entries = history::load_or_default(peer_hex, store, handle)?;
            let mut buf = String::new();
            for e in &entries {
                buf.push_str(&serde_json::to_string(e)?);
                buf.push('\n');
            }
            write_hardened(
                &dest_history_dir.join(format!("{peer_hex}.jsonl")),
                buf.as_bytes(),
            )?;
        }
    }

    // Already unsealed — always written (see doc comment).
    let state_doc = state::load_or_default()?;
    let bytes = serde_json::to_vec_pretty(&state_doc)?;
    write_hardened(&dest_dir.join("state.json"), &bytes)?;

    Ok(())
}

/// Task 5.14: overwrites every row's `trust` field with the live value from `trust.bin`, so
/// [`export_json`]'s output can never lag behind whatever `contacts.json` itself last happened to
/// have written — see the module doc's "Live `trust.bin` join" section. Mirrors
/// `crate::screens::main::build_contact_entries`'s own join exactly: a row with no matching
/// `trust.bin` record (an inconsistent store — a `contacts.json` row and its `trust.bin` record are
/// always written together in the normal path, per `crate::worker::upsert_contact_record`'s own doc
/// comment) is left at whatever `contacts.json` already recorded, the same defensive fallback that
/// function uses, never a hard error over a merely-absent record.
///
/// **Fails closed, unlike the fallback above, if `trust.bin` exists but won't open** (tamper,
/// corruption, wrong key — [`crate::worker::load_trust`]'s own "missing file means fresh store, any
/// other error is fatal" contract): that is a real integrity failure, not "nothing to join yet",
/// and silently falling back to `contacts.json`'s possibly-stale field in that case would defeat
/// the whole point of this join.
fn join_live_trust(
    doc: &mut contacts::ContactsDocument,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), StoreError> {
    let trust = crate::worker::load_trust(store, handle).map_err(StoreError::TrustLoad)?;
    for record in doc.contacts.iter_mut() {
        if let Some(pubkey) = parse_pubkey_hex(&record.pubkey) {
            if let Some(contact) = trust.contact(&pubkey) {
                record.trust = crate::worker::to_trust_label(contact.state);
            }
        }
    }
    Ok(())
}

/// Mirrors `crate::screens::main`'s own private `parse_pubkey_hex` exactly (same "malformed hex or
/// wrong length is `None`, never a panic" contract) — a small enough helper that a second,
/// module-local copy (rather than a shared export solely for this) matches this codebase's existing
/// precedent (e.g. `to_trust_label`'s own doc comment on `tests/at_rest_audit.rs`'s independent
/// copy).
fn parse_pubkey_hex(s: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(s).ok()?;
    raw.as_slice().try_into().ok()
}

#[cfg(all(test, unix))]
mod tests {
    //! Unix-only regression coverage for the permission-hardening helpers themselves
    //! ([`create_dir_hardened`]/[`write_hardened`]), isolated from [`export_json`]'s own
    //! `$MERIDIAN_HOME`-derived default paths (which would require mutating process-global
    //! environment state — racy across `cargo test`'s parallel test threads — to exercise safely).

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn create_dir_hardened_sets_0700() {
        let base = tempfile::tempdir().expect("tempdir");
        let dir = base.path().join("dest");
        create_dir_hardened(&dir).expect("create_dir_hardened");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "exported directory must be chmod 0700");
    }

    #[test]
    fn write_hardened_sets_0600() {
        let base = tempfile::tempdir().expect("tempdir");
        let path = base.path().join("contacts.json");
        write_hardened(&path, b"{}").expect("write_hardened");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exported file must be chmod 0600");
    }
}
