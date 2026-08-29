//! Task 9.4 acceptance (review finding F4): the drain/registration race window in
//! `ws::handle_socket`'s connection-setup sequence, exercised at the wire level — a real `Route`
//! frame, over a real WebSocket connection, landing while a reconnecting recipient's own
//! connect-flow is still in flight.
//!
//! Before this task, `drain_mailbox` ran BEFORE `state.registry.add(...)` registered the
//! connection as reachable. A `Route` from a third party landing in the (very narrow, but real)
//! gap between the drain finishing and registration running found the recipient not-yet-registered,
//! fell through to `queue_to_mailbox`, and then sat mailboxed until the recipient's *next*
//! reconnect — even though the recipient was, in wall-clock terms, already live by the time that
//! `Route` was processed. This file proves that gap is closed: driven entirely through
//! `ws::handle_route`/`ws::handle_socket` (never a direct `Store`/`Registry` call), a `Route`
//! landing during a recipient's connect-flow is now delivered LIVE, never mailboxed.
//!
//! **Determinism, reusing task 9.1's own technique** (`store.rs`'s and `mailbox_quota_race.rs`'s
//! `DelayedStore`): the race this task closes is naturally far too narrow to hit by chance (the
//! pre-fix code's drain-then-register gap has no `.await` between the two steps at all). Rather
//! than adding a new `#[cfg(test)]`-only synchronization hook to production code, this reuses the
//! exact same lever 9.1 already established as the crate's accepted pattern for this kind of test:
//! wrap the `Store` so the SAME call `drain_mailbox` already makes
//! (`mailbox_list_for_recipient`) sleeps for a controlled interval before returning. Because task
//! 9.4's fix moved `registry.add` to run BEFORE that call (rather than after), widening that one
//! call's duration deterministically widens the window during which:
//!   - pre-fix (drain-then-register): the recipient is reachable in the registry, so any `Route`
//!     landing in that window is incorrectly queued to the mailbox instead of delivered live —
//!     this file's test would fail against that code shape (verified locally; see this task's own
//!     report, not re-asserted here since the fixed source is what ships).
//!   - post-fix (register-then-drain, this task): the recipient is ALREADY reachable in the
//!     registry for that entire window, so a `Route` landing there is delivered live immediately.
//!
//! This changes nothing about what's under test — `ws::handle_socket` → `ws::handle_route` →
//! `deliver_one`/`queue_to_mailbox`, exercised for real, unmodified.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use meridian_proto::PrekeyBundle;
use meridian_rendezvous::store::{MailboxEntry, StoreResult};
use meridian_rendezvous::{serve, AppState, MemoryStore, Store};
use tokio::net::TcpListener;

mod support;
use support::{base_config, new_acct};

/// Comfortably longer than a loopback WebSocket round trip (single-digit ms in CI), short enough
/// to keep the test fast. Widens the post-registration, in-drain window `drain_mailbox`'s own
/// `mailbox_list_for_recipient` call spans — see this file's own doc comment.
const DRAIN_DELAY: Duration = Duration::from_millis(250);

/// See this file's own doc comment, and `store.rs`'s/`mailbox_quota_race.rs`'s identical-purpose
/// `DelayedStore` (task 9.1) for the base pattern this mirrors: every other `Store` method is a
/// plain passthrough to `MemoryStore`, and only the ONE method `drain_mailbox` actually calls is
/// widened.
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
    /// The one widened method: `ws::drain_mailbox` calls exactly this, while holding the
    /// recipient's `MailboxLocks` shard (task 9.4's fix) — see this file's own doc comment for why
    /// widening it here is what makes the race deterministic to observe.
    async fn mailbox_list_for_recipient(
        &self,
        recipient_pub: &[u8; 32],
        now: u64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        let entries = self
            .inner
            .mailbox_list_for_recipient(recipient_pub, now)
            .await?;
        tokio::time::sleep(DRAIN_DELAY).await;
        Ok(entries)
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
        self.inner
            .mailbox_size_bytes_for_recipient(recipient_pub, now)
            .await
    }
}

async fn spawn_with_delayed_drain(config: meridian_rendezvous::Config) -> String {
    let store = Arc::new(DelayedStore {
        inner: MemoryStore::new(),
    });
    let state = AppState::new(config, store);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(state, listener).await;
    });
    format!("ws://{addr}")
}

/// Deliverable 2: a `Route` landing while the recipient's OWN connect-flow is still inside its
/// (widened) drain must be delivered live, not queued to the mailbox — proving the
/// erstwhile drain/registration gap is closed.
#[tokio::test]
async fn route_landing_during_recipients_drain_is_delivered_live_not_mailboxed() {
    let url = spawn_with_delayed_drain(base_config("localhost")).await;
    let bob = new_acct("localhost");
    let alice = new_acct("localhost");

    // Alice connects and fully settles FIRST (waits well past `DRAIN_DELAY`, so her own
    // connect-flow's delayed drain — of her own, empty, mailbox — has already completed and her
    // connection is inside `serve`, actively reading further frames) — otherwise her own `Route`
    // request below would itself sit unread behind her own connect-flow's delay, corrupting the
    // timing this test depends on.
    let mut ac = alice.connect(&url).await.unwrap();
    tokio::time::sleep(DRAIN_DELAY * 2).await;

    // Bob connects. `bob.connect()` returns as soon as `AuthOk` arrives over the wire — which
    // happens BEFORE the server-side connect-flow reaches `registry.add`/the drain at all (`AuthOk`
    // is sent from inside `authenticate`, several steps earlier). By the time this `.await`
    // resolves client-side, the server-side task handling bob's connection has, with overwhelming
    // likelihood, already run `registry.add` (a couple of synchronous lines, no `.await` in
    // between) and is now paused `DRAIN_DELAY` deep inside the locked drain that follows it.
    let mut bc = bob.connect(&url).await.unwrap();

    // Fire alice's `Route` at bob immediately — landing, by design, inside that window.
    let outcome = ac
        .route_with_hint_detailed(bob.pubkey, None, vec![9, 9, 9])
        .await
        .unwrap();
    assert!(
        outcome.delivered,
        "bob was already registered as reachable when this Route landed (task 9.4's fix runs \
         registry.add before the drain) — mailboxing it here would strand it until bob's NEXT \
         reconnect even though bob was live in wall-clock terms right now"
    );
    assert!(
        !outcome.queued,
        "delivered and queued must never both be true (RouteOk's own contract)"
    );

    // Bob actually receives it live — `mailbox_id: None` distinguishes a live push from a
    // mailbox-drained one (task 8.7's own shape).
    let live = bc.next_deliver().await.unwrap();
    assert_eq!(live.blob.as_bytes(), &[9, 9, 9]);
    assert_eq!(
        live.mailbox_id, None,
        "a live push carries no mailbox_id — if this were `Some(_)`, the message actually went \
         through the mailbox instead of being delivered directly"
    );

    // No double delivery: bob had zero pre-existing mailbox rows, so the drain itself (still
    // running out from under this test, `DRAIN_DELAY` after it started) has nothing else to send.
    // If the fix somehow delivered this message BOTH live and via the drain, a second `Deliver`
    // carrying the same payload would show up here.
    let second = tokio::time::timeout(DRAIN_DELAY * 2, bc.next_deliver()).await;
    assert!(
        second.is_err(),
        "no second Deliver should ever arrive for this message — got {second:?}"
    );
}
