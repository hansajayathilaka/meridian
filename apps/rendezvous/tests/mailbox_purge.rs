//! Task 8.9 acceptance: the mailbox TTL-expiry purge job provably purges — physically deletes —
//! expired rows, not merely excludes them from a query. This remains meaningful even after task
//! 9.3 gave `mailbox_list_for_recipient`/`mailbox_size_bytes_for_recipient` their own
//! `expires_at > now` read-time filter (review finding F5): that filter only stops expired rows
//! from being *observed*, it does not reclaim storage — this file's SQLite test additionally
//! proves genuine physical deletion with a raw, independent row-count query that bypasses the
//! `Store` trait (and so bypasses task 9.3's filter) entirely.

use std::sync::Arc;

use meridian_rendezvous::mailbox_purge::run_purge_once;
use meridian_rendezvous::{AppState, MemoryStore, Store};

mod support;
use support::base_config;

/// In-memory backend: enqueue a row, advance an injected clock past `expires_at`, run one purge
/// pass, confirm `mailbox_list_for_recipient` returns empty.
#[tokio::test]
async fn purge_once_removes_a_row_past_its_deadline() {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(base_config("localhost"), store.clone());
    let recipient = [7u8; 32];

    store
        .mailbox_enqueue(recipient, vec![1, 2, 3], 0, 1_000)
        .await
        .unwrap();

    // Before the deadline: purging at `now < expires_at` must not touch it. Uses the same `now`
    // (500) for the list call's own `expires_at > now` filter (task 9.3) — the row is genuinely
    // live at this point either way.
    run_purge_once(&state, 500).await.unwrap();
    assert_eq!(
        store
            .mailbox_list_for_recipient(&recipient, 500)
            .await
            .unwrap()
            .len(),
        1,
        "a purge pass before expiry must not remove the row"
    );

    // Past the deadline: one purge pass removes it.
    run_purge_once(&state, 1_001).await.unwrap();
    assert!(
        store
            .mailbox_list_for_recipient(&recipient, 1_001)
            .await
            .unwrap()
            .is_empty(),
        "a purge pass past expiry must remove the row"
    );
}

/// SQLite backend: same clock-injected purge, but proven with a raw, independent `SELECT COUNT(*)`
/// against the same on-disk database file — physical deletion, not merely `mailbox_list_for_
/// recipient`'s own read-time `expires_at > now` filter (task 9.3), so this is genuinely testing
/// the purge job's own DELETE, not incidentally relying on the list query's filter to mask a bug.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn purge_once_physically_deletes_the_row_sqlite() {
    use meridian_rendezvous::store::SqliteStore;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::Row;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mailbox-purge.db");
    let url = format!("sqlite://{}", path.display());
    let recipient = [8u8; 32];

    let store = Arc::new(SqliteStore::connect(&url).await.unwrap());
    let state = AppState::new(base_config("localhost"), store.clone());

    store
        .mailbox_enqueue(recipient, vec![9, 9], 0, 1_000)
        .await
        .unwrap();

    // A second, independent connection to the same file — this is not the connection the purge
    // job itself uses, so a count of 0 here can only mean the row is genuinely gone from disk.
    let raw = SqlitePoolOptions::new().connect(&url).await.unwrap();
    let count_before: i64 = sqlx::query("SELECT COUNT(*) AS c FROM mailbox")
        .fetch_one(&raw)
        .await
        .unwrap()
        .get("c");
    assert_eq!(count_before, 1);

    run_purge_once(&state, 1_001).await.unwrap();

    let count_after: i64 = sqlx::query("SELECT COUNT(*) AS c FROM mailbox")
        .fetch_one(&raw)
        .await
        .unwrap()
        .get("c");
    assert_eq!(
        count_after, 0,
        "the row must be physically absent from the table, not merely filtered out of a query"
    );

    // Belt-and-suspenders: the store's own list query also reports empty.
    assert!(store
        .mailbox_list_for_recipient(&recipient, 1_001)
        .await
        .unwrap()
        .is_empty());
}
