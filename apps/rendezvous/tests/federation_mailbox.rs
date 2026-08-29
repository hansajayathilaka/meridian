//! Task 8.13 acceptance: the feature spec's "works across federation" scope item, end-to-end on a
//! real two-org stack — not a unit test of `handle_fed_route` in total isolation (that's task 8.6's
//! own `federation_route.rs` cells, which build fresh, disposable `Registry`/`FederationPolicy`/
//! `FederationLimits`/`MemoryStore` test doubles with no real second server at all), and not the
//! phase-exit demo (8.14, live/manual). This file drives `handle_fed_route` against Org B's REAL,
//! live `AppState` — the exact `Registry`/`FederationPolicy`/`FederationLimits`/`Metrics`/`Store`/
//! `Mailbox` config a real, in-process `meridian-rendezvous` server for B (booted via the shared
//! `tests/support/mod.rs::boot_federated_pair` harness, task 3.4, over a real s2s mTLS link) is
//! actually running with — then continues onto a REAL client (`SignalingClient`, not a mock)
//! connecting to that same live server over a real WebSocket, draining the queued row, acking it,
//! and confirming deletion. This is strictly more end-to-end than 8.6's own coverage (which never
//! drove a real client) while still being deterministic — see the doc comment on the first test
//! below for exactly why "drive it through Org A's real `route_with_hint` call, uninterrupted, from
//! a genuinely-never-connected Bob" is NOT achievable deterministically, a structural fact of this
//! codebase's design (architect decision #3) that task 8.6's own Status section already
//! independently discovered and had reviewed clean.

use meridian_proto::{FedRoute, OpaqueBlob};
use meridian_rendezvous::config::FederationPolicyMode;
use meridian_rendezvous::federation::inbound::{handle_fed_route, FedRouteDeps};

mod support;
use support::{boot_federated_pair, new_acct, FederatedPairOpts};

/// Deliverable 1/2's queuing half, and task 8.7's reconnect/ack/delete cycle, proven for a row that
/// arrived via the FEDERATED enqueue path specifically (task 8.6), not the local one (8.7's own
/// tests) — across a real s2s mTLS link and a real client connection, not mocks.
///
/// **Why this calls `handle_fed_route` directly instead of driving it through Org A's own
/// `SignalingClient::route_with_hint`:** `route_foreign` (Org A's outbound path) pre-checks target
/// liveness via a real `FedReachability` round trip to B (architect decision #3,
/// `apps/rendezvous/src/federation/outbound.rs::route_foreign`) *before* it ever sends the actual
/// `FedRoute` — B answers with `registry.is_connected(&target)`. A recipient that never connected to
/// B at all is therefore `not_connected` *at Org A*, and `handle_fed_route`'s offline-enqueue branch
/// on B is never reached — task 8.6's own Status section already independently discovered and
/// documented this exact structural fact ("only through a narrow, unconstructable pre-check/
/// delivery disconnect race — not something a fast, non-flaky test can construct"), reviewed clean.
/// This test instead calls the real `handle_fed_route` — the exact function `serve_link` dispatches
/// `FedOp::Route` frames to — directly against B's real, live `AppState` fields (`pair.b_state`,
/// not fresh test doubles), which is what `serve_link` would receive over the wire from a real
/// `FedRoute` frame sent by A. This proves the FEDERATED code path, wired to the real production
/// server state, durably queues when the target is genuinely offline (`registry.send_to` returns
/// false against the real, empty `Registry`).
///
/// **The `RouteOk{delivered:true}` half of Deliverable 2** follows by construction rather than by a
/// live round trip that cannot be built deterministically: `handle_federated_route`
/// (`apps/rendezvous/src/ws.rs`) maps ANY `Ok(())` from `route_foreign` to `RouteOk{delivered:true,
/// queued:false}` completely unconditionally — the match arm has no branch on *how* B's
/// `handle_fed_route` produced that `Ok(())` (live deliver vs. mailbox enqueue; see that function's
/// own doc comment). Given that mapping (fixed, unconditional, already covered live by
/// `federation_route.rs::federated_route_delivers_byte_identical_envelope`) and this test's own
/// proof that the offline branch really does return `Ok(())` against B's real state, A seeing
/// `delivered:true` for a route that actually queued follows necessarily — it is the exact
/// documented optimistic-ack residual from this phase's own architect consult (point 2).
#[tokio::test]
async fn federated_enqueue_against_bs_real_live_state_queues_then_drains_reconnect_ack_delete() {
    let pair = boot_federated_pair(FederatedPairOpts {
        b_policy: FederationPolicyMode::Open,
        ..Default::default()
    })
    .await;

    let alice = new_acct("org-a.test");
    // Bob is genuinely offline: never connects to B at all before the federated route arrives.
    let bob = new_acct("org-b.test");

    let payload =
        b"queued at org-b while bob was offline, across a real mTLS federation link".to_vec();
    let req = FedRoute {
        to: bob.pubkey,
        from: alice.pubkey,
        envelope: OpaqueBlob::new(payload.clone()),
    };

    // The real production dispatch target for an inbound `FedOp::Route` frame, called against B's
    // own live `AppState` — the same `Registry` (empty: bob never connected), `FederationPolicy`,
    // `FederationLimits`, `Metrics`, `Store`, and `Mailbox` config the real spun-up server for B is
    // actually running with.
    let result = handle_fed_route(
        &pair.b_state.registry,
        &pair.b_state.federation.policy,
        &pair.b_state.federation.limits,
        FedRouteDeps {
            metrics: &pair.b_state.metrics,
            store: pair.b_state.store.as_ref(),
            mailbox: &pair.b_state.config.mailbox,
            mailbox_locks: &pair.b_state.mailbox_locks,
        },
        &["org-a.test".to_string()],
        "org-a.test",
        &req,
    )
    .await;
    assert!(
        result.is_ok(),
        "offline + mailbox enabled + under quota must still report Ok(()) against B's real live \
         state — matches the fire-and-forget-on-success shape `serve_link` relies on — got {result:?}"
    );

    // The real, verifiable proof of queuing: B's own live store, off the exact `Arc<dyn Store>` its
    // running server holds.
    let queued = pair
        .b_state
        .store
        .mailbox_list_for_recipient(&bob.pubkey, 0)
        .await
        .expect("mailbox_list_for_recipient must succeed");
    assert_eq!(
        queued.len(),
        1,
        "exactly one row must be durably queued at B for bob — got {queued:?}"
    );
    assert_eq!(
        queued[0].blob, payload,
        "the queued blob must be byte-for-byte what was routed, across the federation hop"
    );

    // Bob connects for the first time, for real, over the real c2s WebSocket to B's actual running
    // server — task 8.7's own drain-on-`AuthOk` behavior fires, now proven for a row that was
    // queued via the FEDERATED enqueue path (task 8.6), not the local one (already covered by task
    // 8.7's own single-server tests).
    let b_c2s_url = pair
        .b_c2s_url
        .clone()
        .expect("boot_federated_pair spawns B's c2s by default");
    let mut bc = bob.connect(&b_c2s_url).await.unwrap();
    let msg = bc
        .next_deliver()
        .await
        .expect("next_deliver for the drained row");
    assert_eq!(
        msg.mailbox_id,
        Some(queued[0].id),
        "the drained Deliver must carry the same mailbox row id observed via the store above"
    );
    assert_eq!(
        msg.from,
        meridian_proto::MAILBOX_DRAIN_FROM_PLACEHOLDER,
        "a mailbox-drained push must carry the placeholder, never a persisted sender identity \
         (ADR 0024) — regardless of whether the row arrived via the local or federated enqueue path"
    );
    assert_eq!(
        msg.blob.as_bytes(),
        payload.as_slice(),
        "the drained bytes must still be byte-for-byte identical to what was originally routed"
    );

    // Ack it (task 8.8's real client-side send path, over the real wire) and confirm the row is
    // genuinely gone from B's live store afterward — the delete-on-acknowledged-delivery half of
    // this task's own path.
    bc.ack_pending_mailbox()
        .await
        .expect("ack_pending_mailbox must succeed");
    let after_ack = pair
        .b_state
        .store
        .mailbox_list_for_recipient(&bob.pubkey, 0)
        .await
        .expect("mailbox_list_for_recipient must succeed");
    assert!(
        after_ack.is_empty(),
        "the row must be deleted at B once acked — still present: {after_ack:?}"
    );
}

/// Deliverable 1's own quota-exceeded angle, carried across the federation boundary, proven against
/// B's real live state (task 8.6's own `federated_route_to_offline_recipient_over_quota_is_rejected`
/// already proves this shape with fresh test doubles): a federated route to an offline, over-quota
/// recipient at B must surface `FedErr{mailbox_full}` — never a silent drop, never `Ok(())`. See the
/// doc comment on the test above for why this is exercised via a direct `handle_fed_route` call
/// against B's real `AppState` rather than through Org A's own `route_with_hint` — the identical
/// `reachable_foreign` pre-check structurally prevents reaching this branch through the real,
/// uninterrupted A-to-B wire path when the recipient never connects at all.
#[tokio::test]
async fn federated_enqueue_against_bs_real_live_state_over_quota_is_rejected_not_a_silent_drop() {
    use meridian_rendezvous::config::Mailbox;

    let pair = boot_federated_pair(FederatedPairOpts {
        b_policy: FederationPolicyMode::Open,
        b_mailbox: Mailbox {
            ttl_days: 14,
            quota_mb: 0, // any non-empty enqueue immediately exceeds a zero quota
            ..Mailbox::default()
        },
        ..Default::default()
    })
    .await;

    let alice = new_acct("org-a.test");
    let bob = new_acct("org-b.test");

    let req = FedRoute {
        to: bob.pubkey,
        from: alice.pubkey,
        envelope: OpaqueBlob::new(b"this must never fit".to_vec()),
    };

    let result = handle_fed_route(
        &pair.b_state.registry,
        &pair.b_state.federation.policy,
        &pair.b_state.federation.limits,
        FedRouteDeps {
            metrics: &pair.b_state.metrics,
            store: pair.b_state.store.as_ref(),
            mailbox: &pair.b_state.config.mailbox,
            mailbox_locks: &pair.b_state.mailbox_locks,
        },
        &["org-a.test".to_string()],
        "org-a.test",
        &req,
    )
    .await;

    let err = result.expect_err(
        "an over-quota federated enqueue against B's real live state must be a client-visible \
         error, not Ok",
    );
    assert_eq!(
        err.code,
        meridian_proto::fed_error_codes::MAILBOX_FULL,
        "an over-quota federated route must surface fed mailbox_full — got: {err:?}"
    );

    // Nothing was ever queued.
    let rows = pair
        .b_state
        .store
        .mailbox_list_for_recipient(&bob.pubkey, 0)
        .await
        .expect("mailbox_list_for_recipient must succeed");
    assert!(
        rows.is_empty(),
        "a rejected over-quota enqueue must not leave a partial row behind: {rows:?}"
    );
}
