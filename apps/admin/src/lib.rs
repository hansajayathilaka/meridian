//! meridian-admin — operator inspection tooling (task 8.11, feature T07's "honesty demo").
//!
//! `mailbox dump <pubkey>` is this crate's ONLY subcommand (see `main.rs`'s module doc — the task
//! file's Scope explicitly forbids scope creep into a general admin CLI here). It opens the SAME
//! on-disk store a real `meridian-rendezvous` deployment would (`meridian_rendezvous::Config` +
//! `Store`, via that crate's own `default_store`) and prints exactly what an admin with DB access
//! — threat A7, `docs/architecture/data-model.md` — can see about one recipient's mailbox: how
//! many envelopes, their sizes, `arrived_at`/`expires_at`, and an opaque marker for each blob.
//!
//! This module NEVER reads a [`MailboxEntry::blob`]'s bytes beyond `size_bytes` (itself already
//! computed server-side, at enqueue time, from `blob.len()` — see `store.rs`). Never parse,
//! decode, or preview blob contents here, even for a "helpful" preview: T07's own Risks/notes say
//! "the mailbox's entire security argument is its poverty of function," and that applies as much
//! to this inspection tool as to the mailbox itself — see `tools/lint-no-serde-on-blob.sh`, which
//! scans this crate too.

use meridian_rendezvous::store::{MailboxEntry, StoreError};
use meridian_rendezvous::Store;

/// Fetch `recipient`'s mailbox rows from `store` and render them via [`format_dump`]. The only
/// place this crate calls into [`Store`] at all — [`Store::mailbox_list_for_recipient`], nothing
/// else (no ack/delete, no enqueue: this tool is read-only by construction, matching the task
/// file's "read-only access — no new store methods" scope).
pub async fn dump_mailbox(store: &dyn Store, recipient: [u8; 32]) -> Result<String, StoreError> {
    let entries = store.mailbox_list_for_recipient(&recipient).await?;
    Ok(format_dump(&recipient, &entries))
}

/// Render the operator-facing dump of one recipient's mailbox: a one-line header (`hex(recipient)
/// | N envelopes`), then one line per row with its size, `arrived_at`, `expires_at`, and an opaque
/// marker for the blob — never its contents, and never anything derived from its contents beyond
/// the length `size_bytes` already carries. Pure formatting over already-fetched [`MailboxEntry`]
/// rows (no I/O), kept separate from [`dump_mailbox`] so it's trivially unit-testable and so a
/// caller building this crate's own tests never needs a real `Store` at all.
///
/// An empty mailbox renders as an explicit `(empty)` line, matching the feature spec demo's
/// "→ empty (deleted on delivery)" case — a clean, obviously-empty state, never a bare blank line
/// or a panic.
pub fn format_dump(recipient: &[u8; 32], entries: &[MailboxEntry]) -> String {
    let mut out = format!(
        "{} | {} envelope{}\n",
        hex::encode(recipient),
        entries.len(),
        if entries.len() == 1 { "" } else { "s" }
    );
    if entries.is_empty() {
        out.push_str("  (empty)\n");
        return out;
    }
    for entry in entries {
        out.push_str(&format!(
            "  #{id}  {size}  arrived_at={arrived_at}  expires_at={expires_at}  contents: <opaque, {bytes} bytes>\n",
            id = entry.id,
            size = human_size(entry.size_bytes),
            arrived_at = entry.arrived_at,
            expires_at = entry.expires_at,
            bytes = entry.size_bytes,
        ));
    }
    out
}

/// Human-readable byte size, binary units (KiB/MiB/GiB), one decimal place — e.g. `1.2 KiB`,
/// matching the feature spec demo's `1.2 KiB, 0.9 KiB, 4.1 KiB` shape. Binary (1024-based), the
/// same convention `store.rs`'s `MAILBOX_QUOTA_BYTES_PER_MB` already documents for this codebase's
/// one other mailbox size figure.
pub fn human_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if b < MIB {
        format!("{:.1} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.1} MiB", b / MIB)
    } else {
        format!("{:.1} GiB", b / GIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_renders_expected_units() {
        assert_eq!(human_size(0), "0 bytes");
        assert_eq!(human_size(1023), "1023 bytes");
        assert_eq!(human_size(1229), "1.2 KiB");
        assert_eq!(human_size(921), "921 bytes");
        assert_eq!(human_size(4198), "4.1 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn format_dump_of_empty_mailbox_is_explicit_not_blank() {
        let recipient = [7u8; 32];
        let out = format_dump(&recipient, &[]);
        assert!(out.contains("0 envelopes"));
        assert!(out.contains("(empty)"));
    }

    #[test]
    fn format_dump_never_touches_blob_bytes() {
        // `blob` deliberately looks like plaintext, to prove format_dump never reads it — only
        // `size_bytes` (already computed server-side from `blob.len()`, not re-derived here).
        let recipient = [1u8; 32];
        let entries = vec![MailboxEntry {
            id: 1,
            recipient_pub: recipient,
            blob: b"TOP-SECRET-PLAINTEXT-CHAT-MESSAGE".to_vec(),
            arrived_at: 100,
            expires_at: 200,
            size_bytes: 34,
        }];
        let out = format_dump(&recipient, &entries);
        assert!(!out.contains("TOP-SECRET"));
        assert!(out.contains("1 envelope"));
        assert!(out.contains("arrived_at=100"));
        assert!(out.contains("expires_at=200"));
        assert!(out.contains("<opaque, 34 bytes>"));
    }

    #[test]
    fn format_dump_multiple_rows_matches_demo_shape() {
        let recipient = [2u8; 32];
        let entries = vec![
            MailboxEntry {
                id: 1,
                recipient_pub: recipient,
                blob: vec![0u8; 1229],
                arrived_at: 1,
                expires_at: 2,
                size_bytes: 1229,
            },
            MailboxEntry {
                id: 2,
                recipient_pub: recipient,
                blob: vec![0u8; 921],
                arrived_at: 3,
                expires_at: 4,
                size_bytes: 921,
            },
            MailboxEntry {
                id: 3,
                recipient_pub: recipient,
                blob: vec![0u8; 4198],
                arrived_at: 5,
                expires_at: 6,
                size_bytes: 4198,
            },
        ];
        let out = format_dump(&recipient, &entries);
        assert!(out.contains("3 envelopes"));
        assert!(out.contains("1.2 KiB"));
        assert!(out.contains("921 bytes"));
        assert!(out.contains("4.1 KiB"));
        assert!(out.contains("<opaque, 1229 bytes>"));
        assert!(out.contains("<opaque, 921 bytes>"));
        assert!(out.contains("<opaque, 4198 bytes>"));
    }
}
