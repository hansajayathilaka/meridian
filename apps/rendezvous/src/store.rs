//! Server-side storage: accounts + their published prekey bundles.
//!
//! What an admin with this store learns (threat A7) is bounded to the [data model](../../../docs/architecture/data-model.md):
//! which pubkeys registered and their PUBLIC prekeys. No contact graph, no content — bundles are
//! public key material by construction.
//!
//! Storage is a trait so the in-memory default (tests, MVP) and a persistent SQLite/sqlx backend
//! (the `sqlite` feature, stack.md §3) are interchangeable. Postgres is a later flag.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use meridian_proto::PrekeyBundle;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage backend error: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The persistence seam. All methods are keyed by the **full** account key — there is no
/// prefix/range lookup, by design (anti-enumeration §3.5).
#[async_trait]
pub trait Store: Send + Sync {
    /// Idempotently record an account (created on first auth). Updates `max_bundle_v`.
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> StoreResult<()>;

    /// Store (replace) an account's prekey bundle.
    async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()>;

    /// Fetch a bundle by exact account key, or `None` if absent.
    async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>>;

    /// Total one-time prekeys currently held across all accounts (the `prekey_pool_depth` gauge).
    async fn total_otks(&self) -> StoreResult<u64>;

    // -- Offline ciphertext mailbox (T07, ADR 0007, data-model.md's `mailbox` table) -------------
    //
    // Storage-seam only (task 8.1): no route-path wiring, no purge-job scheduling, no wire/proto
    // changes here — those land in 8.2/8.3/8.5/8.6/8.9. `blob` is opaque ciphertext end to end;
    // this crate never deserializes it (no-serde-on-blob lint, `tools/lint-no-serde-on-blob.sh`) —
    // same discipline as `put_bundle`'s bundle bytes on the SQLite backend.
    //
    // Every method below has a default implementation that returns a `StoreError::Backend` "not
    // implemented" error, so backends other than `MemoryStore` (namely `SqliteStore`, task 8.2's
    // job) keep compiling without edits to this task. `MemoryStore` below overrides all five.

    /// Enqueue one opaque envelope for `recipient_pub`, returning the server-assigned row id
    /// (`mailbox.id`, sequential — same shape as `one_time_prekeys.id`). `size_bytes` is derived
    /// from `blob.len()` by the implementation, never trusted from a caller-supplied value, since
    /// it mirrors data-model.md's `size_bytes` column exactly and is used for quota accounting.
    /// `arrived_at`/`expires_at` are injected by the caller (unix seconds), not read from the wall
    /// clock here, mirroring [`crate::turn::mint_at`]'s `now_unix` injection so callers stay
    /// testable without a real clock.
    async fn mailbox_enqueue(
        &self,
        recipient_pub: [u8; 32],
        blob: Vec<u8>,
        arrived_at: u64,
        expires_at: u64,
    ) -> StoreResult<u64> {
        let _ = (recipient_pub, blob, arrived_at, expires_at);
        Err(StoreError::Backend(
            "mailbox_enqueue is not implemented for this store backend".to_string(),
        ))
    }

    /// List every row currently held for `recipient_pub`, ordered by `arrived_at` then `id` (the
    /// tie-break for same-timestamp arrivals, since `id` is assigned sequentially).
    async fn mailbox_list_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
    ) -> StoreResult<Vec<MailboxEntry>> {
        let _ = recipient_pub;
        Err(StoreError::Backend(
            "mailbox_list_for_recipient is not implemented for this store backend".to_string(),
        ))
    }

    /// Delete only the rows in `ids` that ALSO belong to `recipient_pub`. An id naming another
    /// recipient's row is a silent no-op for that id, never an error and never a cross-recipient
    /// deletion — the caller's own `recipient_pub` is never trusted to be verified upstream by id
    /// alone (8.7's `MailboxAck` handler depends on this being safe to call with
    /// attacker-influenced ids). Returns the count of rows actually deleted.
    async fn mailbox_delete_by_ids(
        &self,
        recipient_pub: &[u8; 32],
        ids: &[u64],
    ) -> StoreResult<u64> {
        let _ = (recipient_pub, ids);
        Err(StoreError::Backend(
            "mailbox_delete_by_ids is not implemented for this store backend".to_string(),
        ))
    }

    /// Remove every row (across all recipients) whose `expires_at <= now` (unix seconds, injected
    /// by the caller — same testability rationale as [`Store::mailbox_enqueue`]'s timestamps).
    /// Returns the count of rows purged. Scheduling this on a timer is 8.9's job; this method only
    /// performs one purge pass.
    async fn mailbox_purge_expired(&self, now: u64) -> StoreResult<u64> {
        let _ = now;
        Err(StoreError::Backend(
            "mailbox_purge_expired is not implemented for this store backend".to_string(),
        ))
    }

    /// Sum of `size_bytes` across every row currently held for `recipient_pub` — the quota
    /// accounting primitive a later task's "mailbox full" check reads.
    async fn mailbox_size_bytes_for_recipient(&self, recipient_pub: &[u8; 32]) -> StoreResult<u64> {
        let _ = recipient_pub;
        Err(StoreError::Backend(
            "mailbox_size_bytes_for_recipient is not implemented for this store backend"
                .to_string(),
        ))
    }
}

/// One row of the mailbox table (data-model.md §1 `mailbox`), mirrored exactly: no extra columns.
/// `blob` is opaque ciphertext — never deserialized in this crate (no-serde-on-blob lint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxEntry {
    /// Server-assigned sequential row id.
    pub id: u64,
    pub recipient_pub: [u8; 32],
    /// Opaque ciphertext envelope bytes — never deserialized here.
    pub blob: Vec<u8>,
    /// Unix seconds.
    pub arrived_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
    /// `blob.len()` at enqueue time, kept as its own column (matching the data model) so quota
    /// accounting never has to re-touch (let alone parse) the blob itself.
    pub size_bytes: u64,
}

/// `MB` in `config::Mailbox::quota_mb` means MiB (binary) — no design doc pins this down
/// (`config::Mailbox::quota_mb`'s own doc comment carries a `TODO: confirm` on the default number
/// itself), so this is a disambiguation, not an invented requirement, consistent with the
/// codebase's one other documented size precedent (`mrd.file/1`'s 64 KiB chunk size, task 7.5).
pub const MAILBOX_QUOTA_BYTES_PER_MB: u64 = 1024 * 1024;

/// Outcome of a quota-aware mailbox enqueue attempt (tasks 8.5/8.6's shared logic).
pub enum MailboxEnqueueOutcome {
    /// Enqueued; carries the new row's server-assigned id.
    Queued(u64),
    /// Enqueueing `blob` would have exceeded `recipient`'s configured quota — nothing was written.
    QuotaExceeded,
}

/// Check `recipient`'s current mailbox usage against `quota_mb`, then enqueue `blob` if it fits.
/// Shared by the local route path (task 8.5, `ws::handle_route`) and the federated route path
/// (task 8.6, `federation::inbound::handle_fed_route`) so the quota math lives in exactly one
/// place. Callers are responsible for the `ttl_days == 0` (mailbox disabled) short-circuit — this
/// function always attempts to enqueue, matching the "quota is the only enqueue-time gate" scope
/// of both call sites.
pub async fn mailbox_enqueue_with_quota(
    store: &dyn Store,
    recipient: [u8; 32],
    blob: Vec<u8>,
    now: u64,
    ttl_days: u32,
    quota_mb: u32,
) -> StoreResult<MailboxEnqueueOutcome> {
    let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;
    let current_bytes = store.mailbox_size_bytes_for_recipient(&recipient).await?;
    if current_bytes + blob.len() as u64 > quota_bytes {
        return Ok(MailboxEnqueueOutcome::QuotaExceeded);
    }
    let ttl_secs = ttl_days as u64 * 86_400;
    let id = store
        .mailbox_enqueue(recipient, blob, now, now + ttl_secs)
        .await?;
    Ok(MailboxEnqueueOutcome::Queued(id))
}

#[derive(Default)]
struct Account {
    #[allow(dead_code)]
    admission: String,
    #[allow(dead_code)]
    max_bundle_v: u16,
    bundle: Option<PrekeyBundle>,
}

/// In-memory store — the default for the MVP and all tests. Loses data on restart (clients
/// republish bundles on reconnect; ADR-8 "losing this DB costs reachability, never identity").
#[derive(Default)]
pub struct MemoryStore {
    accounts: Mutex<HashMap<[u8; 32], Account>>,
    /// Mailbox rows, keyed by recipient — the same per-recipient partitioning as the real
    /// `mailbox` table's `recipient_pub` column, which is also what makes
    /// [`Store::mailbox_delete_by_ids`]'s recipient-scoping invariant hold structurally: an id can
    /// only ever be found (and thus removed) inside its own recipient's `Vec`, never another's.
    mailboxes: Mutex<HashMap<[u8; 32], Vec<MailboxEntry>>>,
    /// Global sequential id counter for `MailboxEntry::id` (mirrors `id INTEGER PK` autoincrement
    /// semantics — unique and increasing across all recipients, not per-recipient).
    next_mailbox_id: AtomicU64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc_mailbox_id(&self) -> u64 {
        self.next_mailbox_id.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> StoreResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        let entry = accounts.entry(account_pub).or_default();
        entry.admission = admission.to_string();
        entry.max_bundle_v = max_bundle_v;
        Ok(())
    }

    async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        let entry = accounts.entry(bundle.account_pub).or_default();
        entry.bundle = Some(bundle);
        Ok(())
    }

    async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts.get(target).and_then(|a| a.bundle.clone()))
    }

    async fn total_otks(&self) -> StoreResult<u64> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts
            .values()
            .filter_map(|a| a.bundle.as_ref())
            .map(|b| b.otks.len() as u64)
            .sum())
    }

    async fn mailbox_enqueue(
        &self,
        recipient_pub: [u8; 32],
        blob: Vec<u8>,
        arrived_at: u64,
        expires_at: u64,
    ) -> StoreResult<u64> {
        let id = self.alloc_mailbox_id();
        let size_bytes = blob.len() as u64;
        let mut mailboxes = self.mailboxes.lock().unwrap();
        mailboxes
            .entry(recipient_pub)
            .or_default()
            .push(MailboxEntry {
                id,
                recipient_pub,
                blob,
                arrived_at,
                expires_at,
                size_bytes,
            });
        Ok(id)
    }

    async fn mailbox_list_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
    ) -> StoreResult<Vec<MailboxEntry>> {
        let mailboxes = self.mailboxes.lock().unwrap();
        let mut entries = mailboxes.get(recipient_pub).cloned().unwrap_or_default();
        entries.sort_by_key(|e| (e.arrived_at, e.id));
        Ok(entries)
    }

    async fn mailbox_delete_by_ids(
        &self,
        recipient_pub: &[u8; 32],
        ids: &[u64],
    ) -> StoreResult<u64> {
        let mut mailboxes = self.mailboxes.lock().unwrap();
        let Some(entries) = mailboxes.get_mut(recipient_pub) else {
            // No mailbox at all for this recipient: every id is a no-op, never an error.
            return Ok(0);
        };
        let before = entries.len();
        entries.retain(|e| !ids.contains(&e.id));
        Ok((before - entries.len()) as u64)
    }

    async fn mailbox_purge_expired(&self, now: u64) -> StoreResult<u64> {
        let mut mailboxes = self.mailboxes.lock().unwrap();
        let mut purged = 0u64;
        for entries in mailboxes.values_mut() {
            let before = entries.len();
            entries.retain(|e| e.expires_at > now);
            purged += (before - entries.len()) as u64;
        }
        Ok(purged)
    }

    async fn mailbox_size_bytes_for_recipient(&self, recipient_pub: &[u8; 32]) -> StoreResult<u64> {
        let mailboxes = self.mailboxes.lock().unwrap();
        Ok(mailboxes
            .get(recipient_pub)
            .map(|entries| entries.iter().map(|e| e.size_bytes).sum())
            .unwrap_or(0))
    }
}

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mailbox_enqueue_then_list_returns_in_arrival_order() {
        let store = MemoryStore::new();
        let recipient = [7u8; 32];

        let id_a = store
            .mailbox_enqueue(recipient, vec![1, 2, 3], 100, 200)
            .await
            .unwrap();
        let id_b = store
            .mailbox_enqueue(recipient, vec![4, 5], 150, 250)
            .await
            .unwrap();

        let entries = store.mailbox_list_for_recipient(&recipient).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, id_a);
        assert_eq!(entries[0].blob, vec![1, 2, 3]);
        assert_eq!(entries[0].size_bytes, 3);
        assert_eq!(entries[0].arrived_at, 100);
        assert_eq!(entries[0].expires_at, 200);
        assert_eq!(entries[1].id, id_b);
        assert_eq!(entries[1].blob, vec![4, 5]);
    }

    #[tokio::test]
    async fn mailbox_list_orders_by_arrived_at_then_id_for_ties() {
        let store = MemoryStore::new();
        let recipient = [1u8; 32];

        // Same `arrived_at`: tie-break must fall back to `id` (assignment order).
        let id_a = store
            .mailbox_enqueue(recipient, vec![0], 500, 600)
            .await
            .unwrap();
        let id_b = store
            .mailbox_enqueue(recipient, vec![1], 500, 600)
            .await
            .unwrap();

        let entries = store.mailbox_list_for_recipient(&recipient).await.unwrap();
        assert_eq!(
            entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![id_a, id_b]
        );
    }

    #[tokio::test]
    async fn mailbox_delete_by_ids_removes_only_the_matching_row_for_the_matching_recipient() {
        let store = MemoryStore::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];

        let alice_id = store
            .mailbox_enqueue(alice, vec![9, 9], 10, 20)
            .await
            .unwrap();
        let bob_id = store
            .mailbox_enqueue(bob, vec![8, 8], 10, 20)
            .await
            .unwrap();

        // A delete request scoped to `bob` naming `alice`'s row id must be a silent no-op: no
        // error, and alice's row survives untouched.
        let deleted = store
            .mailbox_delete_by_ids(&bob, &[alice_id])
            .await
            .unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(
            store
                .mailbox_list_for_recipient(&alice)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store.mailbox_list_for_recipient(&bob).await.unwrap().len(),
            1
        );

        // The correctly-scoped delete (bob deleting his own row) succeeds and only affects bob.
        let deleted = store.mailbox_delete_by_ids(&bob, &[bob_id]).await.unwrap();
        assert_eq!(deleted, 1);
        assert!(store
            .mailbox_list_for_recipient(&bob)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .mailbox_list_for_recipient(&alice)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn mailbox_delete_by_ids_for_unknown_recipient_is_a_no_op() {
        let store = MemoryStore::new();
        // No mailbox has ever been created for this recipient at all.
        let stranger = [3u8; 32];

        let deleted = store
            .mailbox_delete_by_ids(&stranger, &[1, 2, 3])
            .await
            .unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn mailbox_purge_expired_removes_only_rows_past_their_deadline() {
        let store = MemoryStore::new();
        let recipient = [4u8; 32];

        let fresh_id = store
            .mailbox_enqueue(recipient, vec![1], 0, 1_000)
            .await
            .unwrap();
        let expired_id = store
            .mailbox_enqueue(recipient, vec![2], 0, 500)
            .await
            .unwrap();

        let purged = store.mailbox_purge_expired(500).await.unwrap();
        assert_eq!(purged, 1);

        let remaining = store.mailbox_list_for_recipient(&recipient).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, fresh_id);
        assert_ne!(remaining[0].id, expired_id);
    }

    #[tokio::test]
    async fn mailbox_size_bytes_for_recipient_sums_per_recipient() {
        let store = MemoryStore::new();
        let alice = [5u8; 32];
        let bob = [6u8; 32];

        store
            .mailbox_enqueue(alice, vec![0; 100], 0, 1_000)
            .await
            .unwrap();
        store
            .mailbox_enqueue(alice, vec![0; 50], 0, 1_000)
            .await
            .unwrap();
        store
            .mailbox_enqueue(bob, vec![0; 7], 0, 1_000)
            .await
            .unwrap();

        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&alice)
                .await
                .unwrap(),
            150
        );
        assert_eq!(
            store.mailbox_size_bytes_for_recipient(&bob).await.unwrap(),
            7
        );
        // A recipient with no mailbox at all sums to zero, not an error.
        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&[9u8; 32])
                .await
                .unwrap(),
            0
        );
    }
}
