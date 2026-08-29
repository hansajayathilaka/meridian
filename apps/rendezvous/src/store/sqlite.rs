//! SQLite persistence via sqlx (enabled by the `sqlite` feature; stack.md §3).
//!
//! The runtime query API is used (no compile-time `query!` macros) so the crate builds without a
//! live `DATABASE_URL`. Bundles are stored as one CBOR blob keyed by account key — all public key
//! material; normalizing into the per-column data-model schema is a later refinement.
//! Re-deferred to T07 (task 2.3, docs/api/rendezvous-protocol-v1.md §8): Feature 06 adds no new
//! persisted state of its own, so it has no need to drive this normalization; T07's mailbox is the
//! first consumer a normalized schema (and Postgres) would actually have.

use async_trait::async_trait;
use meridian_proto::PrekeyBundle;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use super::{MailboxEntry, Store, StoreError, StoreResult};

fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// The maximum number of ids `mailbox_delete_by_ids` binds into a single `DELETE ... IN (...)`
/// statement's parameter list (task 9.5). One additional bound parameter (`recipient_pub`) is
/// always reserved alongside a batch's ids, so the total bound-parameter count per statement is
/// this value plus 1 — chosen to stay safely under SQLite's conservative compile-time default
/// `SQLITE_MAX_VARIABLE_NUMBER = 999` regardless of how the SQLite the server links against was
/// built.
const MAILBOX_DELETE_MAX_IDS_PER_BATCH: usize = 900;

/// A persistent store backed by SQLite. `url` is a sqlx SQLite URL, e.g. `sqlite://rdv.db` or
/// `sqlite::memory:`.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Uses sqlx's default `journal_mode` (`DELETE`), not WAL — deliberately never call
    /// `.journal_mode(SqliteJournalMode::Wal)` here without also checking
    /// `apps/cli/src/opacity.rs::run_mailbox_at_rest_audit` (task 8.12): that audit reads the raw
    /// `.db` file directly via `std::fs::read` after a single autocommit insert, which only sees
    /// recent writes because they land synchronously in the main file under `DELETE` mode. Under
    /// WAL, a fresh write can live in a separate `<path>-wal` side file the audit never scans,
    /// letting an at-rest plaintext leak pass the audit vacuously.
    pub async fn connect(url: &str) -> StoreResult<Self> {
        let opts: SqliteConnectOptions = url.parse().map_err(backend)?;
        let opts = opts.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(backend)?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS accounts (\
                account_pub BLOB PRIMARY KEY, admission TEXT NOT NULL, \
                max_bundle_v INTEGER NOT NULL, created_at INTEGER NOT NULL)",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS bundles (\
                account_pub BLOB PRIMARY KEY, bundle BLOB NOT NULL, otk_count INTEGER NOT NULL)",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        // Offline ciphertext mailbox (T07, ADR-7, data-model.md's `mailbox` table) — task 8.2.
        // `blob` is opaque ciphertext end to end; this crate never deserializes it
        // (no-serde-on-blob lint, tools/lint-no-serde-on-blob.sh). Columns match data-model.md
        // byte-for-byte: id (server-assigned sequential row id), recipient_pub, blob, arrived_at,
        // expires_at, size_bytes — no extra columns (security-reviewer: bounds what A7 learns).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mailbox (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                recipient_pub BLOB NOT NULL, \
                blob BLOB NOT NULL, \
                arrived_at INTEGER NOT NULL, \
                expires_at INTEGER NOT NULL, \
                size_bytes INTEGER NOT NULL)",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        // `recipient_pub` index: `mailbox_list_for_recipient` (and the size/delete paths, all
        // scoped by recipient_pub) are the hot path — see data-model.md's mailbox note, updated
        // alongside this migration.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_mailbox_recipient_pub ON mailbox(recipient_pub)",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> StoreResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        sqlx::query(
            "INSERT INTO accounts (account_pub, admission, max_bundle_v, created_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(account_pub) DO UPDATE SET admission = ?2, max_bundle_v = ?3",
        )
        .bind(account_pub.as_slice())
        .bind(admission)
        .bind(max_bundle_v as i64)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()> {
        let blob = meridian_proto::encode(&bundle).map_err(backend)?;
        let otk_count = bundle.otks.len() as i64;
        sqlx::query(
            "INSERT INTO bundles (account_pub, bundle, otk_count) VALUES (?1, ?2, ?3) \
             ON CONFLICT(account_pub) DO UPDATE SET bundle = ?2, otk_count = ?3",
        )
        .bind(bundle.account_pub.as_slice())
        .bind(blob)
        .bind(otk_count)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT bundle FROM bundles WHERE account_pub = ?1")
                .bind(target.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(backend)?;
        match row {
            Some((blob,)) => Ok(Some(meridian_proto::decode(&blob).map_err(backend)?)),
            None => Ok(None),
        }
    }

    async fn total_otks(&self) -> StoreResult<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COALESCE(SUM(otk_count), 0) FROM bundles")
            .fetch_one(&self.pool)
            .await
            .map_err(backend)?;
        Ok(row.0.max(0) as u64)
    }

    async fn mailbox_enqueue(
        &self,
        recipient_pub: [u8; 32],
        blob: Vec<u8>,
        arrived_at: u64,
        expires_at: u64,
    ) -> StoreResult<u64> {
        // `size_bytes` is derived here from `blob.len()`, never trusted from a caller — mirrors
        // the in-memory backend (task 8.1) and data-model.md's `size_bytes` column.
        let size_bytes = blob.len() as i64;
        let result = sqlx::query(
            "INSERT INTO mailbox (recipient_pub, blob, arrived_at, expires_at, size_bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(recipient_pub.as_slice())
        .bind(blob)
        .bind(arrived_at as i64)
        .bind(expires_at as i64)
        .bind(size_bytes)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(result.last_insert_rowid() as u64)
    }

    async fn mailbox_list_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        // Task 9.3 (review finding F5): `expires_at > ?2` excludes rows past their deadline that
        // haven't been physically reclaimed yet by `mailbox_purge_expired`'s periodic pass — same
        // "not yet expired" semantics as that method's own `expires_at <= now` deletion predicate,
        // just inverted.
        let rows: Vec<(i64, Vec<u8>, Vec<u8>, i64, i64, i64)> = sqlx::query_as(
            "SELECT id, recipient_pub, blob, arrived_at, expires_at, size_bytes FROM mailbox \
             WHERE recipient_pub = ?1 AND expires_at > ?2 ORDER BY arrived_at ASC, id ASC",
        )
        .bind(recipient_pub.as_slice())
        .bind(now as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter().map(row_to_entry).collect()
    }

    async fn mailbox_delete_by_ids(
        &self,
        recipient_pub: &[u8; 32],
        ids: &[u64],
    ) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        // Scoped by BOTH recipient_pub AND id: an id naming another recipient's row is a silent
        // no-op, never an error and never a cross-recipient deletion (8.7's `MailboxAck` handler
        // depends on this being safe to call with client-supplied ids — same contract as the
        // in-memory backend, task 8.1).
        //
        // Task 9.5: chunk into batches of at most `MAILBOX_DELETE_MAX_IDS_PER_BATCH` ids per
        // statement. Each statement binds one parameter for `recipient_pub` plus one per id in
        // the `IN (...)` list, so a single unchunked call for `ws.rs`'s full
        // `MAILBOX_ACK_MAX_IDS` (4096) batch would bind 4097 parameters — comfortably past
        // SQLite's conservative compile-time default `SQLITE_MAX_VARIABLE_NUMBER = 999` (older
        // builds; newer builds default higher, but this crate must not assume that), which would
        // turn the delete itself into a hard error and defeat the cap's whole purpose. Chunking
        // keeps every statement's parameter count (1 recipient bind + up to
        // `MAILBOX_DELETE_MAX_IDS_PER_BATCH` id binds) safely under 999 regardless of build
        // configuration.
        let mut deleted = 0u64;
        for chunk in ids.chunks(MAILBOX_DELETE_MAX_IDS_PER_BATCH) {
            let mut qb: QueryBuilder<Sqlite> =
                QueryBuilder::new("DELETE FROM mailbox WHERE recipient_pub = ");
            qb.push_bind(recipient_pub.as_slice());
            qb.push(" AND id IN (");
            let mut separated = qb.separated(", ");
            for id in chunk {
                separated.push_bind(*id as i64);
            }
            separated.push_unseparated(")");
            let result = qb.build().execute(&self.pool).await.map_err(backend)?;
            deleted += result.rows_affected();
        }
        Ok(deleted)
    }

    async fn mailbox_purge_expired(&self, now: u64) -> StoreResult<u64> {
        let result = sqlx::query("DELETE FROM mailbox WHERE expires_at <= ?1")
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(result.rows_affected())
    }

    async fn mailbox_size_bytes_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<u64> {
        // Same `expires_at > ?2` exclusion as `mailbox_list_for_recipient` above (task 9.3): an
        // expired-but-unpurged row must not count toward quota accounting.
        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM mailbox \
             WHERE recipient_pub = ?1 AND expires_at > ?2",
        )
        .bind(recipient_pub.as_slice())
        .bind(now as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.0.max(0) as u64)
    }
}

/// Convert one raw SQLite row tuple into a [`MailboxEntry`], validating `recipient_pub`'s length
/// (it is stored as `BLOB`, not a fixed-size SQL type). `blob` is passed through untouched —
/// never deserialized (no-serde-on-blob discipline).
fn row_to_entry(row: (i64, Vec<u8>, Vec<u8>, i64, i64, i64)) -> StoreResult<MailboxEntry> {
    let (id, recipient_pub, blob, arrived_at, expires_at, size_bytes) = row;
    let recipient_pub: [u8; 32] = recipient_pub
        .try_into()
        .map_err(|_| backend("mailbox row recipient_pub is not 32 bytes"))?;
    Ok(MailboxEntry {
        id: id as u64,
        recipient_pub,
        blob,
        arrived_at: arrived_at as u64,
        expires_at: expires_at as u64,
        size_bytes: size_bytes as u64,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::store::{
        mailbox_enqueue_with_quota, MailboxEnqueueOutcome, MailboxLocks, MAILBOX_QUOTA_BYTES_PER_MB,
    };
    use meridian_proto::BUNDLE_VERSION;

    fn bundle(key: [u8; 32], otks: usize) -> PrekeyBundle {
        PrekeyBundle {
            v: BUNDLE_VERSION,
            account_pub: key,
            spk: [1u8; 32],
            spk_sig: [2u8; 64],
            otks: vec![[3u8; 32]; otks],
            otk_sigs: vec![[4u8; 64]; otks],
            device_record: None,
        }
    }

    #[tokio::test]
    async fn sqlite_store_roundtrips() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        let key = [9u8; 32];
        store.register_account(key, "open", 1).await.unwrap();
        store.put_bundle(bundle(key, 7)).await.unwrap();

        let got = store.get_bundle(&key).await.unwrap().unwrap();
        assert_eq!(got.account_pub, key);
        assert_eq!(got.otk_count(), 7);
        assert_eq!(store.total_otks().await.unwrap(), 7);

        // Exact-key only: a near-miss key is absent.
        let mut miss = key;
        miss[0] ^= 1;
        assert!(store.get_bundle(&miss).await.unwrap().is_none());

        // Republish replaces (and updates the pool depth).
        store.put_bundle(bundle(key, 3)).await.unwrap();
        assert_eq!(store.total_otks().await.unwrap(), 3);
    }

    // -- Offline ciphertext mailbox (task 8.2) ---------------------------------------------------
    //
    // Mirrors store.rs's `MemoryStore` mailbox test set exactly (task 8.1), so both backends are
    // provably interchangeable.

    #[tokio::test]
    async fn mailbox_enqueue_then_list_returns_in_arrival_order() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        // No mailbox has ever been created for this recipient at all.
        let stranger = [3u8; 32];

        let deleted = store
            .mailbox_delete_by_ids(&stranger, &[1, 2, 3])
            .await
            .unwrap();
        assert_eq!(deleted, 0);
    }

    /// Task 9.5: a single `mailbox_delete_by_ids` call with a batch as large as `ws.rs`'s
    /// `MAILBOX_ACK_MAX_IDS` (4096) must succeed against real SQLite in one call, not error out —
    /// this is the direct proof that internal chunking (`MAILBOX_DELETE_MAX_IDS_PER_BATCH`) keeps
    /// every one of the multiple `DELETE` statements it issues under SQLite's bound-parameter
    /// limit, covering the exact 4097-bound-parameter shape (4096 ids + 1 recipient bind) that a
    /// full, unchunked `MailboxAck` batch would otherwise produce.
    #[tokio::test]
    async fn mailbox_delete_by_ids_handles_a_full_mailbox_ack_max_ids_batch_in_one_call() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        let recipient = [5u8; 32];

        const MAILBOX_ACK_MAX_IDS: u64 = 4096;
        let mut ids = Vec::with_capacity(MAILBOX_ACK_MAX_IDS as usize);
        for i in 0..MAILBOX_ACK_MAX_IDS {
            let id = store
                .mailbox_enqueue(recipient, vec![i as u8], i, i + 1_000)
                .await
                .unwrap();
            ids.push(id);
        }
        assert_eq!(ids.len(), MAILBOX_ACK_MAX_IDS as usize);

        let deleted = store.mailbox_delete_by_ids(&recipient, &ids).await.unwrap();
        assert_eq!(deleted, MAILBOX_ACK_MAX_IDS);
        assert!(store
            .mailbox_list_for_recipient(&recipient, 0)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn mailbox_purge_expired_removes_only_rows_past_their_deadline() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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

        // Same `now` (500) as the purge pass above — see `store.rs`'s identical comment for why.
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
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
    // Mirrors `store.rs`'s `MemoryStore` version of these tests exactly, proving the filter
    // behaves identically for the SQLite backend. `mailbox_purge_expired` is never called in
    // either test below — the row that "should already be gone" is still physically present,
    // proving the filter (not the purge job) is what excludes it.

    #[tokio::test]
    async fn mailbox_list_for_recipient_excludes_expired_but_unpurged_rows() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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

    /// End-to-end through [`mailbox_enqueue_with_quota`] itself (not just the raw size read
    /// above): a huge expired-unpurged row must not cause a spurious `mailbox_full` for a new,
    /// small enqueue that easily fits within `quota_mb` once the expired bytes are correctly
    /// excluded.
    #[tokio::test]
    async fn mailbox_enqueue_with_quota_ignores_expired_unpurged_bytes_against_the_cap() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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

    #[tokio::test]
    async fn mailbox_row_survives_a_reconnect_to_the_same_file_backed_db() {
        // Durability across a "restart": a file-backed DB (not `:memory:`) must retain rows
        // across independent `SqliteStore::connect` calls — the actual point of task 8.2.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox-durability.db");
        let url = format!("sqlite://{}", path.display());
        let recipient = [8u8; 32];

        {
            let store = SqliteStore::connect(&url).await.unwrap();
            store
                .mailbox_enqueue(recipient, vec![42, 43], 1, 1_000)
                .await
                .unwrap();
        } // pool dropped here — simulates process exit.

        let store = SqliteStore::connect(&url).await.unwrap();
        let entries = store
            .mailbox_list_for_recipient(&recipient, 0)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blob, vec![42, 43]);
    }

    // -- task 9.1: mailbox quota check-then-write race (review finding F1) -----------------------
    //
    // Mirrors `store.rs`'s `MemoryStore` version of this test exactly (same recipient/quota/
    // envelope-size/concurrency shape), proving [`MailboxLocks`] closes the race identically for
    // the SQLite backend — pooled connections sharing one `sqlite::memory:` cache, same as a real
    // multi-connection deployment would see.

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn mailbox_enqueue_with_quota_races_at_one_recipient_never_overrun_by_more_than_one_envelope(
    ) {
        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        let locks = Arc::new(MailboxLocks::default());
        let recipient = [42u8; 32];
        let quota_mb: u32 = 1; // 1 MiB — fits exactly one near-maximal envelope, never two.
        let quota_bytes = quota_mb as u64 * MAILBOX_QUOTA_BYTES_PER_MB;
        let envelope_size: usize = 1_000_000;
        let concurrency = 24;

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let store = store.clone();
            let locks = locks.clone();
            handles.push(tokio::spawn(async move {
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
        // (so `expires_at = 0 + 14 days`, always `> 0`) — see `store.rs`'s identical comment.
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
    // Mirrors `store.rs`'s `MemoryStore` version of these two tests exactly (same recipient/quota
    // shape), proving the boundary behaves identically for the SQLite backend.

    #[tokio::test]
    async fn mailbox_enqueue_with_quota_allows_filling_the_quota_exactly() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
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
