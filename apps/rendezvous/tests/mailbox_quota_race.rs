//! Task 9.1 acceptance (review finding F1): the mailbox quota check-then-write race, exercised at
//! the wire level — real `Route` frames, over real WebSocket connections, racing at one offline
//! recipient — not merely a direct call into `mailbox_enqueue_with_quota` (that lower-level proof,
//! for both `Store` backends, lives alongside the function itself: `store.rs`'s and
//! `store/sqlite.rs`'s own `#[cfg(test)]` modules).
//!
//! Before this task, `mailbox_enqueue_with_quota`'s read
//! (`Store::mailbox_size_bytes_for_recipient`) and write (`Store::mailbox_enqueue`) were two
//! unserialized `Store` calls: a single free-to-create account, opening multiple connections and
//! bursting near-simultaneous, near-maximal `Route` frames at one offline victim, could overrun
//! `quota_mb` by concurrency x envelope size — not merely "one extra envelope," as the original
//! task 8.5/8.7 carry-forward note assumed. This file proves the fixed bound holds, for both
//! `Store` backends, driven entirely through `ws::handle_route` (never a direct `Store` call).

use std::sync::Arc;

use futures_util::future::join_all;
use meridian_proto::{error_codes, ErrBody};
use meridian_signaling::SignalError;
use tokio::sync::Barrier;

mod support;
use support::{base_config, new_acct};

/// Envelope size for the race: comfortably under `federation::link::MAX_FRAME_LEN` (1 MiB) so it
/// passes this task's own new local size cap (`ws::handle_route`'s defense-in-depth check), but
/// large relative to the 1 MiB `quota_mb` below — "near-maximal," per this task's Deliverable 3.
const ENVELOPE_SIZE: usize = 1_000_000;
/// 1 MiB — fits exactly one [`ENVELOPE_SIZE`] envelope, never two.
const QUOTA_MB: u32 = 1;
const QUOTA_BYTES: u64 = QUOTA_MB as u64 * 1024 * 1024;
/// Multiple live connections from the SAME attacking account (the Goal section's own attack
/// shape) — `Registry`/rate-limiting are both per-account, not per-connection, so this matches the
/// real attack, not a distributed one.
const CONCURRENCY: usize = 24;

/// Race `CONCURRENCY` `Route` frames, from `CONCURRENCY` separate connections all authenticated as
/// the SAME sender account, at one never-connected recipient — asserting the final mailbox byte
/// total never exceeds `quota_mb` by more than one envelope's worth, and that quota was genuinely
/// enforced (not every racer can have queued). Generic over the store backend so the identical
/// wire-level scenario proves the fix for both.
///
/// All `CONCURRENCY` connections are established FIRST, concurrently (`join_all`, not one at a
/// time) and a [`Barrier`] then lines every task up immediately before it sends its `Route` frame —
/// without this, sequential per-task connect/auth latency naturally staggers the actual `Route`
/// sends far enough apart that even the pre-fix race rarely reproduces (the real attack this task
/// closes bursts truly near-simultaneous frames, not gradually staggered ones).
async fn race_routes_at_one_offline_recipient(url: &str, bob: [u8; 32]) -> (usize, usize) {
    let alice = new_acct("localhost");
    let payload = vec![0xABu8; ENVELOPE_SIZE];

    let clients = join_all((0..CONCURRENCY).map(|_| alice.connect(url))).await;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));

    let mut handles = Vec::with_capacity(CONCURRENCY);
    for client in clients {
        let mut client = client.unwrap();
        let payload = payload.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            client.route(bob, payload).await
        }));
    }

    let mut queued = 0usize;
    let mut mailbox_full = 0usize;
    for h in handles {
        match h.await.unwrap() {
            Ok(delivered) => {
                assert!(
                    !delivered,
                    "bob never connects in this test — no route can ever deliver live"
                );
                queued += 1;
            }
            Err(SignalError::Server(ErrBody { code, .. })) if code == error_codes::MAILBOX_FULL => {
                mailbox_full += 1;
            }
            other => panic!("expected either a queued RouteOk or mailbox_full, got {other:?}"),
        }
    }
    assert_eq!(queued + mailbox_full, CONCURRENCY);
    (queued, mailbox_full)
}

fn assert_bound_holds(total: u64, queued: usize) {
    assert!(
        total <= QUOTA_BYTES + ENVELOPE_SIZE as u64,
        "concurrent Route frames at one offline recipient overran quota_mb by more than one \
         envelope's worth: total={total} quota_bytes={QUOTA_BYTES} envelope_size={ENVELOPE_SIZE} \
         queued={queued}"
    );
    assert!(
        queued >= 1,
        "at least one racing route should have fit before the quota filled"
    );
    assert!(
        queued < CONCURRENCY,
        "quota must actually have been enforced — not every racing route can have queued \
         (queued={queued} of {CONCURRENCY})"
    );
}

mod memory_backend {
    use std::sync::Arc;

    use async_trait::async_trait;
    use meridian_proto::PrekeyBundle;
    use meridian_rendezvous::store::{MailboxEntry, StoreResult};
    use meridian_rendezvous::{serve, AppState, MemoryStore, Store};
    use tokio::net::TcpListener;

    use super::*;

    /// See `store.rs`'s own `DelayedStore` (task 9.1) for why: `MemoryStore`'s operations never
    /// actually suspend (a `std::sync::Mutex` lock/read/unlock, no real I/O), so a genuine
    /// `mailbox_enqueue_with_quota` race against a raw `MemoryStore` — even driven by real,
    /// `Barrier`-synchronized WebSocket connections — depends on two OS threads happening to
    /// execute that tiny synchronous section at literally the same instant, which is too narrow to
    /// reproduce deterministically. Widening it here (same technique, same non-goal: this changes
    /// nothing about what's under test — `ws::handle_route` → `queue_to_mailbox` →
    /// `mailbox_enqueue_with_quota`, exercised for real, unmodified) makes the wire-level proof
    /// deterministic instead of relying on scheduling luck.
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

    async fn spawn_with_store(config: meridian_rendezvous::Config) -> (String, Arc<DelayedStore>) {
        let store = Arc::new(DelayedStore {
            inner: MemoryStore::new(),
        });
        let state = AppState::new(config, store.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(state, listener).await;
        });
        (format!("ws://{addr}"), store)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_routes_at_one_offline_recipient_never_overrun_quota_memory() {
        let mut config = base_config("localhost");
        config.mailbox.quota_mb = QUOTA_MB;
        let (url, store) = spawn_with_store(config).await;
        let bob = new_acct("localhost"); // never connects

        let (queued, _mailbox_full) = race_routes_at_one_offline_recipient(&url, bob.pubkey).await;

        // `now=0`: every row here was enqueued through the real route path using the real wall
        // clock (`ws::now_secs()`) and `base_config`'s multi-day `ttl_days`, so `expires_at` is
        // always far in the future relative to `0` — this assertion is about the race's byte
        // bound (task 9.1), not task 9.3's expiry filter, so `0` never spuriously excludes a row.
        let total = store
            .mailbox_size_bytes_for_recipient(&bob.pubkey, 0)
            .await
            .unwrap();
        assert_bound_holds(total, queued);
    }
}

#[cfg(feature = "sqlite")]
mod sqlite_backend {
    use std::sync::Arc;

    use meridian_rendezvous::store::SqliteStore;
    use meridian_rendezvous::{serve, AppState, Store};
    use tokio::net::TcpListener;

    use super::*;

    async fn spawn_with_store(config: meridian_rendezvous::Config) -> (String, Arc<SqliteStore>) {
        // A real, pooled, shared-cache in-memory SQLite DB (`sqlite::memory:` sets sqlx's
        // `shared_cache = true` automatically) — genuinely concurrent connections against the same
        // logical database, the same shape a file-backed deployment sees, not one private
        // in-memory DB per pooled connection.
        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        let state = AppState::new(config, store.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(state, listener).await;
        });
        (format!("ws://{addr}"), store)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_routes_at_one_offline_recipient_never_overrun_quota_sqlite() {
        let mut config = base_config("localhost");
        config.mailbox.quota_mb = QUOTA_MB;
        let (url, store) = spawn_with_store(config).await;
        let bob = new_acct("localhost"); // never connects

        let (queued, _mailbox_full) = race_routes_at_one_offline_recipient(&url, bob.pubkey).await;

        // `now=0`: every row here was enqueued through the real route path using the real wall
        // clock (`ws::now_secs()`) and `base_config`'s multi-day `ttl_days`, so `expires_at` is
        // always far in the future relative to `0` — this assertion is about the race's byte
        // bound (task 9.1), not task 9.3's expiry filter, so `0` never spuriously excludes a row.
        let total = store
            .mailbox_size_bytes_for_recipient(&bob.pubkey, 0)
            .await
            .unwrap();
        assert_bound_holds(total, queued);
    }
}
