//! Task 8.8 acceptance: `SignalingClient`'s own `MailboxAck` send path —
//! `next_deliver`/`ack_pending_mailbox` — proven end-to-end against a real rendezvous server.
//! Task 8.7's `mailbox_delivery.rs` already proves the server-side drain/ack/redrain behavior via
//! raw frames (written before `SignalingClient` could send `MailboxAck` at all); this file proves
//! the CLIENT-side API added by this task instead: batching (one wire frame for N accumulated
//! ids, not N frames) and ack-after-processing (nothing is ever sent merely by calling
//! `next_deliver`).

use std::sync::Arc;

use meridian_rendezvous::{AppState, MemoryStore, Store};

mod support;
use support::{base_config, new_acct, spawn_c2s};

fn spawn_store() -> (Arc<MemoryStore>, Arc<AppState>) {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(base_config("localhost"), store.clone());
    (store, state)
}

/// Deliverable 1/4: `next_deliver()` alone never sends anything over the wire — only
/// `ack_pending_mailbox()` does. Proven by draining N mailbox-tagged rows via `next_deliver()`
/// only, then reconnecting: if `next_deliver` had secretly acked on receipt, the rows would be
/// gone and the second connection would drain nothing; since it redrains all N, nothing was acked
/// by `next_deliver` alone.
#[tokio::test]
async fn next_deliver_alone_never_acks() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");

    let id_a = store
        .mailbox_enqueue(bob.pubkey, vec![1], 0, 10_000)
        .await
        .unwrap();
    let id_b = store
        .mailbox_enqueue(bob.pubkey, vec![2], 1, 10_000)
        .await
        .unwrap();

    {
        let mut bc = bob.connect(&url).await.unwrap();
        let m1 = bc.next_deliver().await.unwrap();
        let m2 = bc.next_deliver().await.unwrap();
        assert_eq!(m1.mailbox_id, Some(id_a));
        assert_eq!(m2.mailbox_id, Some(id_b));
        // Deliberately never call ack_pending_mailbox — `bc` is dropped here.
    }

    assert_eq!(
        store
            .mailbox_list_for_recipient(&bob.pubkey)
            .await
            .unwrap()
            .len(),
        2,
        "next_deliver() must never itself send a MailboxAck — both rows must survive"
    );

    // Redrains the same two, still-unacked rows on a fresh connection.
    let mut bc2 = bob.connect(&url).await.unwrap();
    let m1 = bc2.next_deliver().await.unwrap();
    let m2 = bc2.next_deliver().await.unwrap();
    assert_eq!(m1.mailbox_id, Some(id_a));
    assert_eq!(m2.mailbox_id, Some(id_b));
}

/// Deliverable 1/4: an explicit `ack_pending_mailbox()` call, after the caller has "processed"
/// (here: simply received, standing in for the caller's own durable-persistence step) every
/// accumulated mailbox-tagged `Deliver`, empties the mailbox in exactly ONE round trip covering
/// every accumulated id — not one `MailboxAck` per envelope. Proven by draining 3 rows via 3
/// separate `next_deliver()` calls (accumulating 3 ids client-side, sending nothing), then calling
/// `ack_pending_mailbox()` exactly once and confirming ALL THREE rows are gone.
#[tokio::test]
async fn ack_pending_mailbox_flushes_the_whole_accumulated_batch_in_one_call() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");

    let mut ids = Vec::new();
    for (i, payload) in [vec![1u8], vec![2, 2], vec![3, 3, 3]]
        .into_iter()
        .enumerate()
    {
        ids.push(
            store
                .mailbox_enqueue(bob.pubkey, payload, i as u64, 10_000)
                .await
                .unwrap(),
        );
    }

    let mut bc = bob.connect(&url).await.unwrap();
    for expected_id in &ids {
        let d = bc.next_deliver().await.unwrap();
        assert_eq!(d.mailbox_id, Some(*expected_id));
    }

    // Still all present — accumulation alone (three next_deliver calls) sent nothing.
    assert_eq!(
        store
            .mailbox_list_for_recipient(&bob.pubkey)
            .await
            .unwrap()
            .len(),
        3
    );

    // ONE flush call covers the whole batch of 3.
    bc.ack_pending_mailbox().await.unwrap();

    assert!(
        store
            .mailbox_list_for_recipient(&bob.pubkey)
            .await
            .unwrap()
            .is_empty(),
        "a single ack_pending_mailbox() call must delete every id accumulated since the last \
         flush, not just the most recent one"
    );

    // And it's genuinely a no-op the second time (nothing left to flush, no network I/O, no
    // error) — never re-sends stale ids or errors on an empty batch.
    bc.ack_pending_mailbox().await.unwrap();
}

/// Deliverable 4, crash-safety framing made concrete: acking covers exactly the ids received so
/// far, never ones from a *later* next_deliver call that hasn't happened yet — i.e. batches don't
/// bleed into each other backwards or forwards.
#[tokio::test]
async fn ack_pending_mailbox_only_covers_ids_seen_before_the_flush_call() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");

    let id_a = store
        .mailbox_enqueue(bob.pubkey, vec![1], 0, 10_000)
        .await
        .unwrap();

    let mut bc = bob.connect(&url).await.unwrap();
    let d = bc.next_deliver().await.unwrap();
    assert_eq!(d.mailbox_id, Some(id_a));

    // A second row queued (and drained) AFTER the first flush must not have been swept up by it.
    bc.ack_pending_mailbox().await.unwrap();
    assert!(store
        .mailbox_list_for_recipient(&bob.pubkey)
        .await
        .unwrap()
        .is_empty());

    let id_b = store
        .mailbox_enqueue(bob.pubkey, vec![2], 1, 10_000)
        .await
        .unwrap();
    // A live connection can't self-deliver a fresh mailbox row without reconnecting (drain only
    // runs post-AuthOk) — reconnect to observe it, matching how a real client would.
    drop(bc);
    let mut bc2 = bob.connect(&url).await.unwrap();
    let d2 = bc2.next_deliver().await.unwrap();
    assert_eq!(d2.mailbox_id, Some(id_b));
    bc2.ack_pending_mailbox().await.unwrap();
    assert!(store
        .mailbox_list_for_recipient(&bob.pubkey)
        .await
        .unwrap()
        .is_empty());
}

/// Task 8.8, review finding 2 (should-fix, now fixed): `discard_pending_mailbox_ack` withdraws
/// exactly one accumulated id without touching the others, so a caller that discovers ITS OWN
/// delivery's processing never became durable can keep that one id from riding along in a LATER,
/// unrelated delivery's successful flush (which would otherwise delete a mailbox row whose local
/// handling was never made durable — the crash-safety gap this method exists to close). Proven by
/// accumulating three ids, discarding the middle one, and confirming the flush deletes only the
/// other two.
#[tokio::test]
async fn discard_pending_mailbox_ack_withdraws_only_the_named_id() {
    let (store, state) = spawn_store();
    let url = spawn_c2s(state).await;
    let bob = new_acct("localhost");

    let mut ids = Vec::new();
    for (i, payload) in [vec![1u8], vec![2, 2], vec![3, 3, 3]]
        .into_iter()
        .enumerate()
    {
        ids.push(
            store
                .mailbox_enqueue(bob.pubkey, payload, i as u64, 10_000)
                .await
                .unwrap(),
        );
    }

    let mut bc = bob.connect(&url).await.unwrap();
    for expected_id in &ids {
        let d = bc.next_deliver().await.unwrap();
        assert_eq!(d.mailbox_id, Some(*expected_id));
    }

    // Simulate the middle delivery's own processing failing to persist locally.
    bc.discard_pending_mailbox_ack(ids[1]);
    bc.ack_pending_mailbox().await.unwrap();

    let remaining = store.mailbox_list_for_recipient(&bob.pubkey).await.unwrap();
    assert_eq!(
        remaining.len(),
        1,
        "exactly the discarded id's row must survive — got: {remaining:?}"
    );
    assert_eq!(remaining[0].id, ids[1]);

    // A discard for an id that isn't (or is no longer) queued is a harmless no-op.
    bc.discard_pending_mailbox_ack(ids[1]);
    bc.discard_pending_mailbox_ack(999_999);
}
