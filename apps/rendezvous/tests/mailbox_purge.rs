//! Task 8.9 acceptance: the mailbox TTL-expiry purge job provably purges — physically deletes —
//! expired rows, not merely excludes them from a query. This remains meaningful even after task
//! 9.3 gave `mailbox_list_for_recipient`/`mailbox_size_bytes_for_recipient` their own
//! `expires_at > now` read-time filter (review finding F5): that filter only stops expired rows
//! from being *observed*, it does not reclaim storage — this file's SQLite test additionally
//! proves genuine physical deletion with a raw, independent row-count query that bypasses the
//! `Store` trait (and so bypasses task 9.3's filter) entirely.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use meridian_proto::PrekeyBundle;
use meridian_rendezvous::mailbox_purge::{purge_loop, run_purge_once};
use meridian_rendezvous::store::{MailboxEntry, StoreError, StoreResult};
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

// -- task 9.10 (N4): `purge_loop`'s scheduling wrapper, not just the pure `run_purge_once` it
// calls --------------------------------------------------------------------------------------
//
// `purge_loop` reads the wall clock itself (`crate::ws::now_secs`, `SystemTime`-based, never
// paused by `tokio::time::pause`), so both tests below enqueue rows already expired as of ANY
// real wall-clock timestamp (`expires_at = 1`, i.e. one second past the Unix epoch) rather than
// trying to line up an injected `now` with the interval ticks themselves — the loop's own
// `now_secs()` call is exactly what's under test here, not a fake clock.

/// `tokio::time::interval`'s documented default behavior — the first `.tick()` completes
/// immediately, without waiting out a full `interval_secs` first — is `purge_loop`'s own doc
/// comment's claim ("promptly on boot, not wait a full interval first"). Proven by using a
/// deliberately huge `purge_interval_secs` (so the test would need to advance a virtual hour for
/// a SECOND tick to ever fire) and observing the purge happen without advancing the paused clock
/// at all — only yielding the executor so the spawned loop task gets scheduled.
#[tokio::test(start_paused = true)]
async fn purge_loop_fires_its_first_purge_pass_immediately() {
    let store = Arc::new(MemoryStore::new());
    let mut config = base_config("localhost");
    config.mailbox.purge_interval_secs = 3_600; // if the first pass waited a full interval, this
                                                // test's zero-time-advance budget would never see it
    let state = AppState::new(config, store.clone());
    let recipient = [21u8; 32];

    store
        .mailbox_enqueue(recipient, vec![1, 2, 3], 0, 1)
        .await
        .unwrap();

    let handle = tokio::spawn(purge_loop(state.clone()));

    // Let the spawned task run its first `.tick().await` and purge pass — no virtual time is
    // advanced here at all, only executor turns, so this cannot pass by accident via the SECOND
    // tick firing early.
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }

    // An independent `mailbox_purge_expired` call against the SAME store now finds nothing left
    // to purge — proof of genuine physical deletion by `purge_loop`'s own first pass, not merely
    // a read-time filter (this bypasses `mailbox_list_for_recipient`'s task-9.3 `expires_at > now`
    // filter entirely by calling the purge primitive itself).
    assert_eq!(
        store.mailbox_purge_expired(u64::MAX).await.unwrap(),
        0,
        "purge_loop's first tick must have already purged the pre-expired row; a nonzero count \
         here means the first pass never ran despite tokio::time::interval's documented \
         'first tick fires immediately' default"
    );

    handle.abort();
}

/// A `Store` wrapper whose `mailbox_purge_expired` fails outright on its first call, then
/// delegates normally to a real `MemoryStore` thereafter — simulating exactly one bad purge pass
/// (a transient backend hiccup), the scenario `purge_loop`'s own doc comment names ("a single
/// purge-pass failure ... is not fatal to the loop").
struct FlakyPurgeStore {
    inner: MemoryStore,
    purge_calls: AtomicUsize,
}

#[async_trait]
impl Store for FlakyPurgeStore {
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
        let call_no = self.purge_calls.fetch_add(1, Ordering::SeqCst);
        if call_no == 0 {
            Err(StoreError::Backend(
                "simulated transient purge-pass failure (task 9.10 N4 fixture)".to_string(),
            ))
        } else {
            self.inner.mailbox_purge_expired(now).await
        }
    }
    async fn mailbox_size_bytes_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<u64> {
        self.inner
            .mailbox_size_bytes_for_recipient(recipient_pub, now)
            .await
    }
}

/// The loop's SECOND tick must still fire, and still genuinely purge, after the first tick's
/// purge pass returned an error — `purge_loop`'s `let _ = run_purge_once(...).await;` must
/// discard the error and keep ticking forever, never propagate it, panic, or exit the task.
#[tokio::test(start_paused = true)]
async fn purge_loop_survives_a_single_purge_pass_failure_and_keeps_ticking() {
    let store = Arc::new(FlakyPurgeStore {
        inner: MemoryStore::new(),
        purge_calls: AtomicUsize::new(0),
    });
    let mut config = base_config("localhost");
    config.mailbox.purge_interval_secs = 5;
    let state = AppState::new(config, store.clone());
    let recipient = [22u8; 32];

    // Enqueued directly against the inner store (the wrapper only intercepts
    // `mailbox_purge_expired`), already expired as of any real wall-clock `now_secs()`.
    store
        .inner
        .mailbox_enqueue(recipient, vec![9], 0, 1)
        .await
        .unwrap();

    let handle = tokio::spawn(purge_loop(state.clone()));

    // First tick fires immediately and calls `mailbox_purge_expired` once — rigged to fail.
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        store.purge_calls.load(Ordering::SeqCst),
        1,
        "the loop's first tick must have attempted (and, per this fixture, failed) exactly one \
         purge pass by now"
    );
    assert!(
        !handle.is_finished(),
        "a purge-pass failure must not crash or exit the loop task"
    );

    // Advance past the deadline for the SECOND tick. The whole runtime is otherwise idle on
    // timers at this point (this sleep, and purge_loop's own next `ticker.tick()`), so tokio's
    // paused clock auto-advances to the earliest one and runs it — the same pattern
    // `apps/core/tests/p2p_session.rs`'s `start_paused` tests already rely on.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }

    assert!(
        store.purge_calls.load(Ordering::SeqCst) >= 2,
        "purge_loop must still be ticking and calling mailbox_purge_expired again after the \
         first pass's failure — got only {} call(s) so far",
        store.purge_calls.load(Ordering::SeqCst)
    );
    // And the later, successful pass genuinely did real purge work — the pre-expired row is
    // physically gone — proving the loop recovered to doing real purging, not merely surviving
    // as an inert no-op.
    assert_eq!(
        store.inner.mailbox_purge_expired(u64::MAX).await.unwrap(),
        0,
        "a later successful purge pass must have actually purged the pre-expired row"
    );

    handle.abort();
}
