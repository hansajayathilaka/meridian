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
use tokio::sync::Mutex as AsyncMutex;

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

    /// List every row currently held for `recipient_pub` that has NOT yet expired
    /// (`expires_at > now`), ordered by `arrived_at` then `id` (the tie-break for same-timestamp
    /// arrivals, since `id` is assigned sequentially).
    ///
    /// `now` is caller-injected (unix seconds), the same testability rationale
    /// [`Store::mailbox_enqueue`]'s own doc comment gives for `arrived_at`/`expires_at` — task 9.3
    /// (review finding F5). A row whose `expires_at <= now` is excluded here even though it may
    /// not yet have been physically reclaimed by [`Store::mailbox_purge_expired`]'s periodic pass:
    /// this is the "not yet observed by callers" half of that gap; `mailbox_purge_expired` stays
    /// the sole mechanism that actually deletes the row (task 9.3's Scope explicitly leaves
    /// `mailbox_purge.rs` unchanged).
    async fn mailbox_list_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        let _ = (recipient_pub, now);
        Err(StoreError::Backend(
            "mailbox_list_for_recipient is not implemented for this store backend".to_string(),
        ))
    }

    /// Delete only the rows in `ids` that ALSO belong to `recipient_pub`. An id naming another
    /// recipient's row is a silent no-op for that id, never an error and never a cross-recipient
    /// deletion — the caller's own `recipient_pub` is never trusted to be verified upstream by id
    /// alone (8.7's `MailboxAck` handler depends on this being safe to call with
    /// attacker-influenced ids). Returns the count of rows actually deleted.
    ///
    /// A backend that issues one bound SQL statement per `ids` batch (namely `SqliteStore`, task
    /// 9.5) MUST chunk internally so no single statement's bound-parameter count can approach
    /// SQLite's conservative compile-time default `SQLITE_MAX_VARIABLE_NUMBER = 999` — this method
    /// accepts arbitrarily large `ids` slices from callers (`ws.rs`'s `MAILBOX_ACK_MAX_IDS` cap
    /// bounds it to 4096) and must not error out on a large-but-capped batch.
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

    /// Sum of `size_bytes` across every row currently held for `recipient_pub` that has NOT yet
    /// expired (`expires_at > now`) — the quota accounting primitive
    /// [`mailbox_enqueue_with_quota`]'s "mailbox full" check reads.
    ///
    /// `now` is caller-injected, same rationale as [`Store::mailbox_list_for_recipient`]'s own doc
    /// comment (task 9.3, review finding F5): without this filter, expired-but-not-yet-purged
    /// bytes would wrongly count toward `quota_mb`, causing spurious `mailbox_full` errors for
    /// senders until the next purge pass reclaims them.
    async fn mailbox_size_bytes_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<u64> {
        let _ = (recipient_pub, now);
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

/// Number of shards [`MailboxLocks`] stripes its per-recipient locking across. Fixed-size (not a
/// `HashMap<[u8; 32], _>` entry per recipient that would grow unboundedly with every distinct
/// recipient a server ever sees — no cleanup bookkeeping needed), and large enough that two
/// *different* recipients landing in the same shard (and so incidentally serializing against each
/// other, which is the one accepted imprecision of striping) is rare in practice.
const MAILBOX_LOCK_SHARDS: usize = 256;

/// Per-recipient serialization for [`mailbox_enqueue_with_quota`]'s check-then-write (task 9.1,
/// review finding F1). The read (`Store::mailbox_size_bytes_for_recipient`) and write
/// (`Store::mailbox_enqueue`) are two separate `Store` calls with no shared transaction — without
/// an external lock, N concurrent callers targeting the SAME offline recipient can all read the
/// same stale `current_bytes`, each independently decide "this still fits," and all enqueue,
/// overrunning `quota_mb` by up to N x envelope size instead of the intended "at most one envelope
/// over" bound.
///
/// A fixed-size striped lock (hash `recipient` into one of [`MAILBOX_LOCK_SHARDS`]
/// `tokio::sync::Mutex`es) rather than a compare-and-swap primitive added to the [`Store`] trait
/// itself: it serializes calls for the SAME recipient identically regardless of which `Store`
/// backend is in use (`MemoryStore` or `SqliteStore`) since the lock lives entirely in this crate,
/// outside the trait — no new obligation on either backend impl, and no per-backend atomic-SQL
/// special-casing to keep behaviorally identical to `MemoryStore`. Held only across one bounded
/// `Store` call — [`mailbox_enqueue_with_quota`]'s check-then-write, or (task 9.4) `ws::drain_mailbox`'s
/// `mailbox_list_for_recipient` read — never across unrelated recipients' calls (bar the rare shard
/// collision above) and, just as importantly, never across a `send` to a client socket or any other
/// I/O the server doesn't control the pace of: an earlier version of the 9.4 fix held this lock
/// across `drain_mailbox`'s per-row sends too, which let one slow or adversarial reader stall the
/// lock indefinitely and block every other sender targeting this shard. This is the "keep the lock
/// scope narrow" constraint both tasks' own notes call out.
///
/// One instance lives on [`crate::state::AppState`] and is shared by the local route path
/// (`ws::queue_to_mailbox`), the federated route path (`federation::inbound::handle_fed_route`),
/// AND (task 9.4, review finding F4) `ws::drain_mailbox`'s own mailbox read, run right after this
/// connection is registered as reachable — see that function's doc comment for why. A local
/// enqueue, a federated enqueue, and a reconnecting recipient's own drain read, all racing at the
/// same recipient, are therefore all serialized against EACH OTHER at the point they touch the
/// `Store`, not just pairwise.
pub struct MailboxLocks {
    shards: Vec<AsyncMutex<()>>,
}

impl Default for MailboxLocks {
    fn default() -> Self {
        Self {
            shards: (0..MAILBOX_LOCK_SHARDS)
                .map(|_| AsyncMutex::new(()))
                .collect(),
        }
    }
}

impl MailboxLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the shard guarding `recipient`. Held by the returned guard until dropped — callers
    /// must hold it across the bounded `Store` call(s) they're serializing (e.g. both the quota
    /// read and the enqueue write, for [`mailbox_enqueue_with_quota`]) and MUST release it before
    /// any unbounded I/O such as a send to a client socket.
    ///
    /// `pub(crate)` (not private): task 9.4 reuses this directly from `ws::drain_mailbox` (held only
    /// across its `mailbox_list_for_recipient` read — see that function's own doc comment) rather
    /// than only ever being reached indirectly through [`mailbox_enqueue_with_quota`].
    pub(crate) async fn lock_recipient(
        &self,
        recipient: &[u8; 32],
    ) -> tokio::sync::MutexGuard<'_, ()> {
        // First 8 bytes of an already-uniformly-random Ed25519/X25519 pubkey as a shard selector —
        // no need for a real hash function over key material that's already high-entropy.
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&recipient[..8]);
        let shard = (u64::from_le_bytes(buf) as usize) % self.shards.len();
        self.shards[shard].lock().await
    }
}

/// Check `recipient`'s current mailbox usage against `quota_mb`, then enqueue `blob` if it fits.
/// Shared by the local route path (task 8.5, `ws::handle_route`) and the federated route path
/// (task 8.6, `federation::inbound::handle_fed_route`) so the quota math lives in exactly one
/// place. Callers are responsible for the `ttl_days == 0` (mailbox disabled) short-circuit — this
/// function always attempts to enqueue, matching the "quota is the only enqueue-time gate" scope
/// of both call sites.
///
/// **Task 9.1 (review finding F1):** `locks` serializes this whole check-then-write against every
/// OTHER concurrent call (from either route path) naming the same `recipient` — see
/// [`MailboxLocks`]'s own doc comment for why a striped async lock, not a `Store`-trait
/// compare-and-swap primitive, closes the race identically for both backends.
pub async fn mailbox_enqueue_with_quota(
    store: &dyn Store,
    locks: &MailboxLocks,
    recipient: [u8; 32],
    blob: Vec<u8>,
    now: u64,
    ttl_days: u32,
    quota_mb: u32,
) -> StoreResult<MailboxEnqueueOutcome> {
    let _guard = locks.lock_recipient(&recipient).await;
    let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;
    // Task 9.3: `now` (already caller-injected here, pre-dating this task) is also the "not yet
    // expired" cutoff for the read below — an expired-but-not-yet-purged row must not count
    // toward the quota this check enforces.
    let current_bytes = store
        .mailbox_size_bytes_for_recipient(&recipient, now)
        .await?;
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
        now: u64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        let mailboxes = self.mailboxes.lock().unwrap();
        let mut entries: Vec<MailboxEntry> = mailboxes
            .get(recipient_pub)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
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

    async fn mailbox_size_bytes_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<u64> {
        let mailboxes = self.mailboxes.lock().unwrap();
        Ok(mailboxes
            .get(recipient_pub)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.expires_at > now)
                    .map(|e| e.size_bytes)
                    .sum()
            })
            .unwrap_or(0))
    }
}

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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

        let entries = store
            .mailbox_list_for_recipient(&recipient, 0)
            .await
            .unwrap();
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

        let entries = store
            .mailbox_list_for_recipient(&recipient, 0)
            .await
            .unwrap();
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
                .mailbox_list_for_recipient(&alice, 0)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .mailbox_list_for_recipient(&bob, 0)
                .await
                .unwrap()
                .len(),
            1
        );

        // The correctly-scoped delete (bob deleting his own row) succeeds and only affects bob.
        let deleted = store.mailbox_delete_by_ids(&bob, &[bob_id]).await.unwrap();
        assert_eq!(deleted, 1);
        assert!(store
            .mailbox_list_for_recipient(&bob, 0)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .mailbox_list_for_recipient(&alice, 0)
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

        // Same `now` (500) as the purge pass above: the surviving row's `expires_at` (1_000) is
        // still in its future either way, so this also exercises `mailbox_list_for_recipient`'s
        // own `expires_at > now` filter (task 9.3) alongside the physical purge, not just the
        // purge in isolation.
        let remaining = store
            .mailbox_list_for_recipient(&recipient, 500)
            .await
            .unwrap();
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
                .mailbox_size_bytes_for_recipient(&alice, 0)
                .await
                .unwrap(),
            150
        );
        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&bob, 0)
                .await
                .unwrap(),
            7
        );
        // A recipient with no mailbox at all sums to zero, not an error.
        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&[9u8; 32], 0)
                .await
                .unwrap(),
            0
        );
    }

    // -- task 9.3: `expires_at` read filter (review finding F5) --------------------------------
    //
    // Deliverable 3: a drain against a mix of expired-but-not-yet-purged and live rows must return
    // only the live ones, and quota accounting must ignore expired-unpurged bytes. `mailbox_purge_
    // expired` is never called in either test below — the row that "should already be gone" is
    // still physically present, proving the filter (not the purge job) is what excludes it.

    #[tokio::test]
    async fn mailbox_list_for_recipient_excludes_expired_but_unpurged_rows() {
        let store = MemoryStore::new();
        let recipient = [13u8; 32];

        let live_id = store
            .mailbox_enqueue(recipient, vec![1], 0, 1_000)
            .await
            .unwrap();
        // Past its deadline relative to `now` below, but never purged in this test.
        let expired_id = store
            .mailbox_enqueue(recipient, vec![2], 0, 100)
            .await
            .unwrap();

        let now = 500; // > expired's expires_at (100), < live's expires_at (1_000)
        let entries = store
            .mailbox_list_for_recipient(&recipient, now)
            .await
            .unwrap();
        assert_eq!(
            entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![live_id],
            "an expired-but-unpurged row must not be observed by a list/drain call, even though \
             it is still physically present — expired_id={expired_id} must be absent"
        );

        // Belt-and-suspenders: the row really is still there, just not surfaced by the filtered
        // read above — proving this is a read-time filter, not an accidental purge side effect.
        assert_eq!(
            store.mailbox_purge_expired(0).await.unwrap(),
            0,
            "no purge pass ran in this test — the row's continued physical presence below is not \
             explained by an unrelated deletion"
        );
    }

    #[tokio::test]
    async fn mailbox_size_bytes_for_recipient_ignores_expired_unpurged_bytes() {
        let store = MemoryStore::new();
        let recipient = [14u8; 32];

        store
            .mailbox_enqueue(recipient, vec![0u8; 40], 0, 1_000) // live
            .await
            .unwrap();
        store
            .mailbox_enqueue(recipient, vec![0u8; 999_999], 0, 100) // expired, unpurged
            .await
            .unwrap();

        let now = 500;
        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&recipient, now)
                .await
                .unwrap(),
            40,
            "the large expired-but-unpurged row must not count toward quota accounting"
        );
    }

    /// End-to-end through [`mailbox_enqueue_with_quota`] itself (not just the raw size read above):
    /// a huge expired-unpurged row must not cause a spurious `mailbox_full` for a new, small
    /// enqueue that easily fits within `quota_mb` once the expired bytes are correctly excluded.
    #[tokio::test]
    async fn mailbox_enqueue_with_quota_ignores_expired_unpurged_bytes_against_the_cap() {
        let store = MemoryStore::new();
        let locks = MailboxLocks::default();
        let recipient = [15u8; 32];
        let quota_mb: u32 = 1;
        let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;

        // Already exceeds the 1 MiB quota on its own, but expired as of `now` below and never
        // purged — without the fix, this would wrongly count toward quota and reject the enqueue.
        store
            .mailbox_enqueue(recipient, vec![0u8; (quota_bytes + 1) as usize], 0, 100)
            .await
            .unwrap();

        let now = 500; // > the pre-filled row's expires_at (100)
        let outcome =
            mailbox_enqueue_with_quota(&store, &locks, recipient, vec![0u8; 10], now, 14, quota_mb)
                .await
                .unwrap();
        assert!(
            matches!(outcome, MailboxEnqueueOutcome::Queued(_)),
            "an expired-but-unpurged row must not count toward quota_mb — this enqueue should \
             have fit"
        );
    }

    // -- task 9.1: mailbox quota check-then-write race (review finding F1) -----------------------

    /// A `Store` wrapper that inserts a short artificial delay inside
    /// `mailbox_size_bytes_for_recipient`, AFTER the read completes but before it returns.
    /// `MemoryStore`'s own operations never actually suspend (a `std::sync::Mutex` lock/read/
    /// unlock, with no real I/O) — so [`mailbox_enqueue_with_quota`]'s read-then-write race window
    /// against a raw `MemoryStore` is only ever as wide as two OS threads happening to execute that
    /// tiny synchronous section at literally the same instant, which real scheduling rarely lines
    /// up even under a `Barrier`-synchronized burst. Widening the window here makes a genuine race
    /// (the SAME one a slower backend, or a busier server, would hit far more easily) deterministic
    /// to observe in a fast unit test — it does not change what is being tested: the locking in
    /// [`mailbox_enqueue_with_quota`] itself, exercised for real, unmodified, against this backend.
    struct DelayedStore {
        inner: MemoryStore,
    }

    #[async_trait]
    impl Store for DelayedStore {
        async fn register_account(
            &self,
            account_pub: [u8; 32],
            admission: &str,
            max_bundle_v: u16,
        ) -> StoreResult<()> {
            self.inner
                .register_account(account_pub, admission, max_bundle_v)
                .await
        }
        async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()> {
            self.inner.put_bundle(bundle).await
        }
        async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>> {
            self.inner.get_bundle(target).await
        }
        async fn total_otks(&self) -> StoreResult<u64> {
            self.inner.total_otks().await
        }
        async fn mailbox_enqueue(
            &self,
            recipient_pub: [u8; 32],
            blob: Vec<u8>,
            arrived_at: u64,
            expires_at: u64,
        ) -> StoreResult<u64> {
            self.inner
                .mailbox_enqueue(recipient_pub, blob, arrived_at, expires_at)
                .await
        }
        async fn mailbox_list_for_recipient(
            &self,
            recipient_pub: &[u8; 32],
            now: u64,
        ) -> StoreResult<Vec<MailboxEntry>> {
            self.inner
                .mailbox_list_for_recipient(recipient_pub, now)
                .await
        }
        async fn mailbox_delete_by_ids(
            &self,
            recipient_pub: &[u8; 32],
            ids: &[u64],
        ) -> StoreResult<u64> {
            self.inner.mailbox_delete_by_ids(recipient_pub, ids).await
        }
        async fn mailbox_purge_expired(&self, now: u64) -> StoreResult<u64> {
            self.inner.mailbox_purge_expired(now).await
        }
        async fn mailbox_size_bytes_for_recipient(
            &self,
            recipient_pub: &[u8; 32],
            now: u64,
        ) -> StoreResult<u64> {
            let bytes = self
                .inner
                .mailbox_size_bytes_for_recipient(recipient_pub, now)
                .await?;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok(bytes)
        }
    }

    /// N concurrent `mailbox_enqueue_with_quota` calls racing at the SAME offline recipient, with
    /// envelopes sized large relative to the configured quota (near-`MAX_FRAME_LEN`, matching this
    /// task's Deliverable 3 — the previously-documented "bounded, roughly one envelope" assumption
    /// is what this proves, not merely "a small overrun"). Pre-fix (unserialized read-then-write)
    /// this reliably overran `quota_mb` by multiples of `envelope_size`; post-fix the final byte
    /// total must never exceed `quota_mb` by more than one envelope's worth, and quota must
    /// genuinely have been enforced (not every racer can have been queued). Every racer is lined up
    /// on a [`tokio::sync::Barrier`] immediately before calling `mailbox_enqueue_with_quota`, and
    /// races against a [`DelayedStore`] (see its own doc comment for why) — the same real
    /// `MailboxLocks`-guarded function under test either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn mailbox_enqueue_with_quota_races_at_one_recipient_never_overrun_by_more_than_one_envelope(
    ) {
        let store = Arc::new(DelayedStore {
            inner: MemoryStore::new(),
        });
        let locks = Arc::new(MailboxLocks::default());
        let recipient = [42u8; 32];
        let quota_mb: u32 = 1; // 1 MiB — fits exactly one near-maximal envelope, never two.
        let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;
        // Comfortably under `federation::link::MAX_FRAME_LEN` (1 MiB) — "near-maximal" per
        // Deliverable 3 — and large relative to the 1 MiB quota above.
        let envelope_size: usize = 1_000_000;
        let concurrency = 24;
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let store = store.clone();
            let locks = locks.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                mailbox_enqueue_with_quota(
                    store.as_ref(),
                    locks.as_ref(),
                    recipient,
                    vec![0u8; envelope_size],
                    0,
                    14,
                    quota_mb,
                )
                .await
                .unwrap()
            }));
        }

        let mut queued = 0usize;
        let mut quota_exceeded = 0usize;
        for h in handles {
            match h.await.unwrap() {
                MailboxEnqueueOutcome::Queued(_) => queued += 1,
                MailboxEnqueueOutcome::QuotaExceeded => quota_exceeded += 1,
            }
        }
        assert_eq!(queued + quota_exceeded, concurrency);

        // `now=0`: matches the `now=0` every racer above passed to `mailbox_enqueue_with_quota`
        // (so `expires_at = 0 + 14 days`, always `> 0`) — this assertion is about the race's byte
        // bound, not about task 9.3's expiry filter, so `0` never spuriously excludes a row here.
        let total = store
            .mailbox_size_bytes_for_recipient(&recipient, 0)
            .await
            .unwrap();
        assert!(
            total <= quota_bytes + envelope_size as u64,
            "concurrent same-recipient enqueues overran quota_mb by more than one envelope's \
             worth: total={total} quota_bytes={quota_bytes} envelope_size={envelope_size} \
             queued={queued}"
        );
        assert!(
            queued >= 1,
            "at least one racer should have fit before the quota filled"
        );
        assert!(
            queued < concurrency,
            "quota must actually have been enforced — not every racer can have queued \
             (queued={queued} of {concurrency})"
        );
    }

    // -- task 9.2: quota exact-at-cap boundary (review finding F6) --------------------------------
    //
    // `mailbox_enqueue_with_quota` rejects on `current_bytes + blob.len() > quota_bytes` — a
    // deliberate strict `>`, not `>=`. These two tests pin the boundary itself: filling the quota
    // exactly is allowed, one byte past it is not. The existing quota tests above only exercise
    // `quota_mb = 0` (the "obviously over" case) or a randomized race, neither of which proves this.

    #[tokio::test]
    async fn mailbox_enqueue_with_quota_allows_filling_the_quota_exactly() {
        let store = MemoryStore::new();
        let locks = MailboxLocks::default();
        let recipient = [11u8; 32];
        let quota_mb: u32 = 1;
        let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;

        // Pre-fill directly (bypassing the quota gate, which isn't under test here) to
        // `quota_bytes - 10`, so the `mailbox_enqueue_with_quota` call below with a 10-byte blob
        // lands EXACTLY at the boundary: `current_bytes + blob.len() == quota_bytes`.
        store
            .mailbox_enqueue(recipient, vec![0u8; (quota_bytes - 10) as usize], 0, 1_000)
            .await
            .unwrap();

        let outcome =
            mailbox_enqueue_with_quota(&store, &locks, recipient, vec![0u8; 10], 0, 14, quota_mb)
                .await
                .unwrap();
        assert!(
            matches!(outcome, MailboxEnqueueOutcome::Queued(_)),
            "filling the quota exactly must be allowed (strict `>` comparison, not `>=`)"
        );
        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&recipient, 0)
                .await
                .unwrap(),
            quota_bytes
        );
    }

    #[tokio::test]
    async fn mailbox_enqueue_with_quota_rejects_one_byte_over_the_quota() {
        let store = MemoryStore::new();
        let locks = MailboxLocks::default();
        let recipient = [12u8; 32];
        let quota_mb: u32 = 1;
        let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;

        // Pre-fill directly to exactly `quota_bytes`, so the next call's
        // `current_bytes + blob.len()` is `quota_bytes + 1` — one byte over.
        store
            .mailbox_enqueue(recipient, vec![0u8; quota_bytes as usize], 0, 1_000)
            .await
            .unwrap();

        let outcome =
            mailbox_enqueue_with_quota(&store, &locks, recipient, vec![0u8; 1], 0, 14, quota_mb)
                .await
                .unwrap();
        assert!(
            matches!(outcome, MailboxEnqueueOutcome::QuotaExceeded),
            "one byte past the quota must be rejected"
        );
        // The rejected attempt wrote nothing.
        assert_eq!(
            store
                .mailbox_size_bytes_for_recipient(&recipient, 0)
                .await
                .unwrap(),
            quota_bytes
        );
    }
}
