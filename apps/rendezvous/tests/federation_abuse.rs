//! Task 2.12 — the phase-2 exit gate: Feature 06's cross-org abuse acceptance criteria, turned
//! into executable, CI-wired tests (docs/architecture/features/06-cross-org-federation.md's
//! "Acceptance criteria" + "Abuse tests" deliverable).
//!
//! Reuses the real two-real-server-over-real-mTLS harness `federation_fetch.rs`/
//! `federation_route.rs` (tasks 2.7/2.8) already established — this crate's existing duplication
//! convention (code-reviewer-accepted on 2.7) rather than factoring out a shared `tests/support`
//! module. Each test maps to one Feature-06 acceptance criterion not already pinned elsewhere in
//! this crate's test suite:
//! - **rate-limit enforcement** on the *route* dimension (task 2.6/2.8) — `federation_fetch.rs`
//!   already covers the *fetch* dimension; this file closes the route-side gap.
//! - **allowlist rejection specifically** (not just `closed`, which `federation_fetch.rs`/
//!   `federation_route.rs` already cover) — a non-allowlisted origin under `policy = "allowlist"`.
//! - **oversized-envelope rejection**, restated here so the full abuse suite is discoverable from
//!   one file (federation_route.rs owns the detailed pre-dial/defense-in-depth split; this is the
//!   acceptance-level restatement the task file calls for).
//! - **the A2×2 cross-org malicious-server bundle-substitution test**: Org B's server lies about
//!   the requested identity's prekey bundle over the federated fetch path (the new
//!   `test-tamper-hook` extension, task 2.12 deliverable 1) — Alice's client (via Org A) must
//!   abort via its own `verify_bundle` check, exactly as the single-hop version already does
//!   (`apps/rendezvous/tests/rendezvous.rs::tampered_bundle_is_rejected`), pinned to
//!   `SignalError::BundleVerification` specifically (never a generic catch-all), mirroring how
//!   1.28/1.32 pin outcomes to a specific variant on a specific side.
//! - **F17 structural inertness** of the new federated tamper hook: without the
//!   `test-tamper-hook` cargo feature, even `allow_test_tamper = true` at B must leave the
//!   federated fetch reply byte-identical to what B's store actually holds — see this file's CI
//!   note below on why that assertion needs its own package-scoped, default-features CI step.
//!
//! ## The 1.28/1.32 resolver-2 trap, applied to federation
//! Exactly as `apps/rendezvous/tests/rendezvous.rs` documents: resolver-2 feature unification turns
//! `test-tamper-hook` ON workspace-wide whenever a dev target (e.g. `apps/cli`, whose
//! dev-dependency on `meridian-rendezvous` pins the feature) is built — so a `#[cfg(not(feature =
//! "test-tamper-hook"))]` guard in THIS file would be silently compiled out under `cargo test
//! --workspace`, and the only invocation under which it (and the feature-ON cell next to it)
//! genuinely execute is the existing package-scoped CI steps (`cargo test -p meridian-rendezvous`
//! / `cargo test -p meridian-rendezvous --features test-tamper-hook`) — both already exist (task
//! 1.28/1.32) and, being package-scoped with no `--test` filter, automatically pick up this new
//! test binary with no CI edit required. See `.github/workflows/ci.yml`'s "Tamper-hook" steps.

use std::sync::Arc;

use meridian_proto::error_codes;
use meridian_rendezvous::config::{Federation, FederationPolicyMode};
use meridian_rendezvous::AppState;
use meridian_signaling::SignalError;

mod support;
use support::{boot_federated_pair, new_acct, FederatedPairOpts};

/// Stand up A (dialing out) + B (accepting), returning both `AppState`s and both c2s URLs.
struct Rig {
    // Only read directly by the tamper-hook cell below (`#[cfg(feature = "test-tamper-hook")]`),
    // to reach into B's store and prove the substitution left the store itself untouched.
    #[cfg_attr(not(feature = "test-tamper-hook"), allow(dead_code))]
    b_state: Arc<AppState>,
    a_c2s_url: String,
    b_c2s_url: String,
    _dir: tempfile::TempDir,
}

#[allow(clippy::too_many_arguments)]
async fn stand_up(
    b_policy: FederationPolicyMode,
    b_allowlist: Vec<String>,
    fed_fetch_per_origin_per_min: u32,
    fed_route_per_origin_per_min: u32,
    fed_per_origin_account_per_min: u32,
    arm_b_test_tamper: bool,
) -> Rig {
    stand_up_with_reachability(
        b_policy,
        b_allowlist,
        fed_fetch_per_origin_per_min,
        fed_route_per_origin_per_min,
        fed_per_origin_account_per_min,
        // `Federation::default`'s own value — callers not exercising the reachability dimension
        // specifically get its ordinary generous default, never an accidentally-tight one. (Task
        // 3.5 second follow-up, re-review of F4: raised from 300 to 600 alongside the real default,
        // which must stay `>=` `fed_route_per_origin_per_min` — see `config::Federation::validate`.)
        600,
        arm_b_test_tamper,
    )
    .await
}

/// Same as [`stand_up`], with an explicit `fed_reachability_per_origin_per_min` — needed by the
/// reachability-specific rate-limit cell below, which must set this one tight while keeping the
/// other three generous (so it fails only on the dimension actually under test).
#[allow(clippy::too_many_arguments)]
async fn stand_up_with_reachability(
    b_policy: FederationPolicyMode,
    b_allowlist: Vec<String>,
    fed_fetch_per_origin_per_min: u32,
    fed_route_per_origin_per_min: u32,
    fed_per_origin_account_per_min: u32,
    fed_reachability_per_origin_per_min: u32,
    arm_b_test_tamper: bool,
) -> Rig {
    let pair = boot_federated_pair(FederatedPairOpts {
        b_policy,
        b_allowlist,
        b_fed_fetch_per_origin_per_min: fed_fetch_per_origin_per_min,
        b_fed_route_per_origin_per_min: fed_route_per_origin_per_min,
        b_fed_per_origin_account_per_min: fed_per_origin_account_per_min,
        b_fed_reachability_per_origin_per_min: fed_reachability_per_origin_per_min,
        b_allow_test_tamper: arm_b_test_tamper,
        ..Default::default()
    })
    .await;
    Rig {
        b_state: pair.b_state,
        a_c2s_url: pair.a_c2s_url,
        b_c2s_url: pair
            .b_c2s_url
            .expect("boot_federated_pair spawns B's c2s by default"),
        _dir: pair.dir,
    }
}

// -- rate-limit enforcement: the ROUTE dimension (2.6/2.8) --------------------------------------
//
// `federation_fetch.rs::bs_federation_edge_rate_limit_trips_through_the_real_path` already proves
// this for FETCH. Nothing in this crate's existing suite drives the identical property for ROUTE
// through the real wire path — this closes that gap, which is exactly what Feature 06's "abuse
// tests: rate-limit enforcement" criterion asks for.
//
// **Task 3.5 (review finding F4) rewrite.** Before this task, `route_foreign` always ran an
// internal `fed_reachability` pre-check that ALSO spent `route_per_origin`, so a target that was
// simply offline (`not_connected`) still cost the origin budget a unit via that pre-check alone —
// this test used to prove the budget tripped WITHOUT ever reaching a real `fed_route` delivery,
// which was itself a symptom of the bug this task fixes (see `federation::inbound::
// handle_fed_reachability`'s doc comment). As of 3.5, the pre-check spends no budget at all, so
// this test now connects a real, reachable Bob and proves the origin budget is spent by, and only
// by, actual routed DELIVERIES — the true post-fix behavior.

#[tokio::test]
async fn bs_federation_route_rate_limit_trips_through_the_real_path() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 2, 30, false).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    // `fed_route_per_origin_per_min = 2`: the first two real, delivered messages must succeed —
    // each one real `fed_route` costing exactly one unit of the origin budget (task 3.5's fix;
    // before it, each would have cost two: one from the reachability pre-check, one from the real
    // route). The per-origin-ACCOUNT limiter (keyed on Alice, the sender) is set far higher
    // (30/min) so it never trips first.
    for _ in 0..2u8 {
        let delivered = ac
            .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
            .await
            .unwrap();
        assert!(
            delivered,
            "bob is connected; every one of the first two routes must deliver"
        );
        bc.next_deliver().await.unwrap(); // drain, so B's socket buffer never backs up
    }
    // A third real route, once the 2/min origin budget is spent, must be rejected as
    // `rate_limited` — not silently delivered, and not conflated with `not_connected` (bob is
    // still connected the whole time).
    let err = ac
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(
            body.code,
            error_codes::RATE_LIMITED,
            "once B's per-origin ROUTE budget (2/min) is spent by two real deliveries, a third \
             real route to the SAME still-connected target must be rejected as rate_limited"
        ),
        other => panic!("expected rate_limited, got {other:?}"),
    }
}

// -- rate-limit enforcement: the REACHABILITY dimension (task 3.5 follow-up, review finding F4) --
//
// Blocking finding on the ORIGINAL 3.5 fix: removing `check_route` from
// `handle_fed_reachability` correctly stopped it double-spending the route/account budgets, but
// also left `FedOp::Reachability` completely UNMETERED, bounded only by task 3.2's *global* link
// caps, not anything per-peer — a real, distinct DoS/enumeration-probing surface. This proves the
// follow-up fix (a fourth, dedicated `reachability_per_origin` limiter) actually bounds sustained
// reachability probing through the real wire path, not merely at the unit level.
//
// `route_with_hint` is the one client-reachable trigger for an outbound `FedOp::Reachability`
// request in this codebase (`route_foreign`'s own internal `reachable_foreign` pre-check, run
// before every route attempt) — so a sustained series of routes to a connected, reachable target
// drives exactly one reachability probe per call. The route and per-account budgets are set far
// above the tight reachability budget so this test fails ONLY on the reachability dimension, never
// conflating it with `bs_federation_route_rate_limit_trips_through_the_real_path` above.

#[tokio::test]
async fn bs_federation_reachability_rate_limit_trips_through_the_real_path() {
    const REACHABILITY_BUDGET: u32 = 2;
    let rig = stand_up_with_reachability(
        FederationPolicyMode::Open,
        Vec::new(),
        300,
        300,
        300,
        REACHABILITY_BUDGET,
        false,
    )
    .await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    // The first REACHABILITY_BUDGET real routes must succeed — each one spends exactly one unit of
    // B's `reachability_per_origin` budget via `route_foreign`'s internal pre-check, well within
    // the far higher route (300/min) and per-account (300/min) budgets, so neither of those trips
    // first.
    for i in 0..REACHABILITY_BUDGET {
        let delivered = ac
            .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
            .await
            .unwrap_or_else(|e| {
                panic!("route {i} of the {REACHABILITY_BUDGET}-unit reachability budget must succeed: {e:?}")
            });
        assert!(delivered, "bob is connected the whole time; every one of the first {REACHABILITY_BUDGET} routes must deliver");
        bc.next_deliver().await.unwrap(); // drain, so B's socket buffer never backs up
    }
    // The next route's internal reachability pre-check must now be rejected as rate_limited —
    // bob is STILL connected the whole time, so this is not a `not_connected`/target-liveness
    // outcome (which task 2.8's architect decision #3 already covers elsewhere): it is B's
    // dedicated reachability budget, and only that budget, tripping.
    let err = ac
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(
            body.code,
            error_codes::RATE_LIMITED,
            "once B's dedicated reachability budget ({REACHABILITY_BUDGET}/min) is spent, a \
             further route's internal reachability pre-check must be rejected as rate_limited — \
             before the task 3.5 follow-up fix, this request was completely unmetered and this \
             assertion would never fire no matter how many times this loop ran"
        ),
        other => panic!("expected rate_limited, got {other:?}"),
    }
}

// -- task 3.5 deliverable 3: the fix actually restores documented throughput --------------------
//
// Three cells, each proving a distinct part of the Goal ("one federated message must cost one
// route unit and one per-account unit, not two"):
// - sustained ordinary chat, well under budget, never spuriously rate-limits;
// - the CONFIGURED org-wide route budget is genuinely achievable one-for-one by real deliveries
//   (not silently halved);
// - per-account counters are truly per-ACCOUNT, not shared with a phantom RECIPIENT-keyed
//   counter — the precise, corrected mechanism behind the account-axis half of the bug (see
//   below).

/// Ordinary sustained cross-org chat, well under every configured budget, must never spuriously
/// rate-limit — the direct, practical restatement of this task's Goal.
#[tokio::test]
async fn sustained_cross_org_messages_under_budget_all_succeed() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, false).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    // 10 messages: comfortably under BOTH the per-origin (600/min) and per-account (30/min)
    // defaults, so nothing here should ever trip a limiter — before this task's fix, the ORIGIN
    // budget alone would have silently been exhausted twice as fast (effectively ~300/min), and
    // this cell would still have passed at N=10 (10 << 300) — the point is establishing the
    // baseline "ordinary chat just works" cell the other two cells in this section build on.
    const N: usize = 10;
    for i in 0..N {
        let delivered = ac
            .route_with_hint(
                bob.pubkey,
                Some("org-b.test".to_string()),
                format!("message {i}").into_bytes(),
            )
            .await
            .unwrap_or_else(|e| panic!("message {i} of {N} must succeed under budget: {e:?}"));
        assert!(delivered);
        let msg = bc.next_deliver().await.unwrap();
        assert_eq!(msg.blob.as_bytes(), format!("message {i}").as_bytes());
    }
}

/// The CONFIGURED `fed_route_per_origin_per_min` budget must be achievable one-for-one by real
/// deliveries — i.e. N configured units buy N real routed messages, not N/2 (or, per the re-review
/// of F4, not silently capped by an under-sized `fed_reachability_per_origin_per_min` chained 1:1
/// in front of every real route — see `config::Federation::fed_reachability_per_origin_per_min`'s
/// doc comment and `Federation::validate` for that coupling).
///
/// Uses a scaled-down pair of limits (rather than the full shipped defaults) purely to keep this
/// test fast — each successful `fed_route` pays a fixed `ROUTE_REPLY_GRACE` (500ms) latency tax by
/// design (fire-and-forget on success), so wall-clock cost scales linearly with the route budget
/// exercised. **Critically, unlike this test's pre-re-review version, the scaled-down reachability
/// budget is DERIVED from the real shipped defaults' ratio, not hand-picked.** The bug this
/// specifically guards against: the previous version fixed `ROUTE_BUDGET = 20` while leaving
/// `fed_reachability_per_origin_per_min` at a separately-chosen value comfortably above 20 — so
/// `route_foreign`'s mandatory, uncached, 1:1 reachability pre-check (see that function's doc
/// comment) never became the binding constraint in the test, even though the real shipped defaults
/// at the time (`route = 600`, `reachability = 300`) meant it WAS the binding constraint in
/// production (`min(600, 300) = 300`, not `600`). Deriving the test's ratio from
/// `Federation::default()` itself means a future edit that reintroduces `reachability < route` in
/// the shipped defaults shrinks `reachability_budget` below `ROUTE_BUDGET` here too, and this test
/// fails on the same re-review finding it was written to close.
#[tokio::test]
async fn documented_org_wide_route_throughput_is_achievable_one_for_one() {
    let default_route = Federation::default().fed_route_per_origin_per_min;
    let default_reachability = Federation::default().fed_reachability_per_origin_per_min;
    // Belt-and-suspenders: `Federation::validate` already enforces this at config-load time (task
    // 3.5 second follow-up), but this test derives its own scaled budgets from these two values
    // below, so if this ever fires, `Federation::default()` itself regressed — a config-loading
    // caller would already see a hard `Err` from `Config::load` before ever reaching this test's
    // scenario.
    assert!(
        default_reachability >= default_route,
        "Federation::default() must satisfy reachability >= route (see Federation::validate); \
         found reachability={default_reachability}, route={default_route}"
    );

    // Route budget is the tight, scaled-down stand-in for the documented default; the account
    // budget is set far above it so the ACCOUNT limiter can never be what's actually tested here.
    const ROUTE_BUDGET: u32 = 20;
    // The reachability budget exercised by this test, at the SAME ratio to ROUTE_BUDGET that
    // `fed_reachability_per_origin_per_min` has to `fed_route_per_origin_per_min` in the real
    // shipped defaults — rounded down, so this test can never end up accidentally MORE generous
    // (relative to ROUTE_BUDGET) than production actually is.
    let reachability_budget =
        ((ROUTE_BUDGET as u64 * default_reachability as u64) / default_route as u64) as u32;
    assert!(
        reachability_budget >= ROUTE_BUDGET,
        "derived reachability_budget ({reachability_budget}) must be >= ROUTE_BUDGET \
         ({ROUTE_BUDGET}) — otherwise this test would itself be exercising a coupling ratio the \
         real defaults reject"
    );

    let rig = stand_up_with_reachability(
        FederationPolicyMode::Open,
        Vec::new(),
        300,
        ROUTE_BUDGET,
        1_000,
        reachability_budget,
        false,
    )
    .await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    // All ROUTE_BUDGET real messages must deliver: before this task's original fix, only
    // ROUTE_BUDGET / 2 of these would have succeeded (the reachability pre-check preceding each
    // route silently spent a second unit of this same shared budget); before the re-review's
    // second follow-up fix, an under-ratioed reachability budget could cap real deliveries below
    // ROUTE_BUDGET even with the original double-spend fixed.
    for i in 0..ROUTE_BUDGET {
        let delivered = ac
            .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "message {i} of the full {ROUTE_BUDGET}-unit route budget must succeed — the \
                     documented org-wide route throughput must be genuinely achievable one-for-one, \
                     not silently capped by the reachability pre-check's own budget: {e:?}"
                )
            });
        assert!(delivered);
        bc.next_deliver().await.unwrap();
    }
    // The very next one, having now genuinely exhausted the budget with ROUTE_BUDGET real
    // deliveries (not ROUTE_BUDGET/2 deliveries plus ROUTE_BUDGET/2 phantom pre-check spends, and
    // not fewer than ROUTE_BUDGET deliveries capped by an under-sized reachability budget), must be
    // rejected.
    let err = ac
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(body.code, error_codes::RATE_LIMITED),
        other => panic!("expected rate_limited once the full budget is spent, got {other:?}"),
    }
}

/// Direct regression test for the account-axis half of F4's double-spend, pinned to its actual
/// mechanism (corrected from this task's initial description): the bug was never "each of the two
/// parties in a conversation pays twice" — `handle_fed_route`'s own per-account check was always
/// correctly keyed on the real sender (`req.from`) alone, so a single sender's own budget was
/// never itself double-spent. The real bug was that `handle_fed_reachability`'s pre-check ALSO
/// spent the shared `per_origin_account` `RateLimiter`, keyed on `req.target` — the RECIPIENT —
/// so every real route's own liveness pre-check silently charged a budget shared by, and
/// indistinguishable from, every OTHER sender addressing that same recipient. A popular/frequently
/// -messaged recipient's inbound capacity from a given origin was therefore capped at
/// `fed_per_origin_account_per_min` in aggregate, across ALL senders — not per sender, and not a
/// budget any single sender's own usage controlled.
///
/// Proven directly: exhaust one sender's (alice1's) own per-account budget messaging bob, then
/// prove a SECOND, previously-silent sender (alice2) — who has sent nothing at all — can still
/// reach the SAME bob immediately afterward. Pre-fix, alice2's first-ever message would have been
/// rejected too: alice1's 3 successful sends would have already driven bob's phantom
/// `(origin_domain, bob)` counter to the same cap via their reachability pre-checks, so alice2's
/// own pre-check would find that shared counter already exhausted before her own real per-account
/// counter (never yet touched) was ever consulted.
#[tokio::test]
async fn per_account_counters_are_keyed_on_the_real_sender_not_a_shared_recipient_counter() {
    const ACCOUNT_BUDGET: u32 = 3;
    let rig = stand_up(
        FederationPolicyMode::Open,
        Vec::new(),
        300,
        300,
        ACCOUNT_BUDGET,
        false,
    )
    .await;

    let alice1 = new_acct("org-a.test");
    let mut ac1 = alice1.connect(&rig.a_c2s_url).await.unwrap();
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();

    // alice1 spends her own full per-account budget messaging bob.
    for i in 0..ACCOUNT_BUDGET {
        let delivered = ac1
            .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
            .await
            .unwrap_or_else(|e| panic!("alice1's message {i} must succeed: {e:?}"));
        assert!(delivered);
        bc.next_deliver().await.unwrap();
    }
    // alice1's OWN next message correctly trips her OWN budget.
    let err = ac1
        .route_with_hint(bob.pubkey, Some("org-b.test".to_string()), b"hi".to_vec())
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(body.code, error_codes::RATE_LIMITED),
        other => panic!("expected alice1 to be rate_limited on her own budget, got {other:?}"),
    }

    // alice2 — a wholly distinct account, who has never sent a single message — must still be
    // able to reach bob right now. This is the actual regression test: a shared, recipient-keyed
    // phantom counter (the pre-fix bug) would make this fail even though alice2's real per-account
    // counter has never been touched.
    let alice2 = new_acct("org-a.test");
    let mut ac2 = alice2.connect(&rig.a_c2s_url).await.unwrap();
    let delivered = ac2
        .route_with_hint(
            bob.pubkey,
            Some("org-b.test".to_string()),
            b"hi from alice2".to_vec(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "alice2 has never sent a message and must not be affected by alice1's usage or by \
                 alice1's reachability pre-checks against the same recipient: {e:?}"
            )
        });
    assert!(delivered);
    let msg = bc.next_deliver().await.unwrap();
    assert_eq!(msg.from, alice2.pubkey);
}

// -- allowlist rejection, specifically (not just `closed`) --------------------------------------
//
// `federation_fetch.rs`/`federation_route.rs` already cover `policy = "closed"`. Feature 06's
// acceptance criterion separately names "a closed-policy org rejects inbound federation" but the
// abuse-test deliverable also names "allowlist rejection" as its own criterion — a domain that is
// simply NOT on the allowlist (as opposed to policy being closed outright) must fail the same way.

#[tokio::test]
async fn allowlist_policy_rejects_a_non_allowlisted_origin_as_fed_denied() {
    // B's allowlist deliberately does NOT include "org-a.test" — some other domain instead, so
    // this is a genuine allowlist MISS, not an empty (vacuously-rejects-everything) allowlist.
    let rig = stand_up(
        FederationPolicyMode::Allowlist,
        vec!["org-c.test".to_string()],
        300,
        600,
        30,
        false,
    )
    .await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let target = [0x22u8; 32]; // identity is irrelevant — B rejects on policy alone
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::FedDenied { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!(
            "a domain absent from B's allowlist must be rejected exactly like `closed` (a clean, \
             client-visible fed_denied) — got {other:?}"
        ),
    }
}

#[tokio::test]
async fn allowlist_policy_admits_the_listed_origin() {
    // The control: the SAME allowlist policy, with "org-a.test" actually present, must NOT reject
    // — proving the cell above is measuring the allowlist-miss specifically, not "allowlist mode
    // rejects everything unconditionally."
    let rig = stand_up(
        FederationPolicyMode::Allowlist,
        vec!["org-a.test".to_string()],
        300,
        600,
        30,
        false,
    )
    .await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let target = [0x22u8; 32];
    let err = ac
        .fetch_bundle(target, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    // Not present at B, but NOT a policy rejection: proves the allowlisted domain was admitted and
    // the request reached the store lookup.
    match err {
        SignalError::NotFoundAtHint { .. } => {}
        other => panic!(
            "an allowlisted origin must be admitted past the policy check (rejected only for \
             lacking the target, not for policy) — got {other:?}"
        ),
    }
}

// -- oversized-envelope rejection (acceptance-level restatement) ---------------------------------
//
// `federation_route.rs` owns the detailed pre-dial/defense-in-depth split; this is the
// acceptance-level cell Feature 06's own "abuse tests" deliverable names directly, kept here so
// the whole abuse suite is discoverable from one file.

#[tokio::test]
async fn oversized_envelope_is_rejected_cross_org() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, false).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let oversized = vec![0x41u8; 2 * 1024 * 1024]; // 2 MiB, well over MAX_FRAME_LEN (1 MiB)
    let target = [0x33u8; 32];
    let err = ac
        .route_with_hint(target, Some("org-b.test".to_string()), oversized)
        .await
        .unwrap_err();
    match err {
        SignalError::Server(body) => assert_eq!(body.code, error_codes::BAD_REQUEST),
        other => panic!("expected bad_request for an oversized cross-org envelope, got {other:?}"),
    }
}

// -- A2×2: cross-org malicious-server bundle substitution (task 2.12 deliverable 1) -------------
//
// Org B's server lies to Org A about the requested identity's prekey bundle over the FEDERATED
// fetch path — the cross-org analogue of `rendezvous.rs::tampered_bundle_is_rejected`. Alice's
// client (talking only to Org A) must abort via its OWN `verify_bundle` check
// (`meridian-signaling::bundle::verify_bundle`, applied identically to a local or federated
// fetch reply — see `SignalingClient::fetch_bundle`'s doc comment) even though B actively tried to
// substitute. Pinned to `SignalError::BundleVerification` specifically, never a generic
// `unwrap_err()`/catch-all, mirroring 1.28/1.32's "pin the specific variant on the specific side"
// discipline.

#[cfg(feature = "test-tamper-hook")]
#[tokio::test]
async fn cross_org_malicious_server_bundle_substitution_is_rejected_by_the_client() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, true).await;

    // Bob's REAL bundle is published at B — the tamper hook substitutes a DIFFERENT bundle in the
    // fed_fetch_bundle reply, so this test also proves the substitution is B lying about a real,
    // existing identity, not merely reporting "not found" under a different guise.
    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();
    bc.publish_bundle(
        &bob.store,
        &bob.handle,
        meridian_signaling::DEFAULT_OTK_COUNT,
    )
    .await
    .unwrap();

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    let err = ac
        .fetch_bundle(bob.pubkey, Some("org-b.test".to_string()), false)
        .await
        .unwrap_err();
    match err {
        SignalError::BundleVerification(_) => {}
        other => panic!(
            "a bundle substituted by a malicious FOREIGN server must be rejected by the client's \
             OWN verify_bundle check with SignalError::BundleVerification specifically — anything \
             else (including a bare unwrap_err on some other variant) does not prove the client-side \
             trust anchor actually fired. Got: {other:?}"
        ),
    }

    // Non-vacuity / direct proof the substitution actually happened, not merely that SOME error
    // fired: read B's own store directly and confirm the (real, untampered) bundle held there is
    // for Bob's real key — the client's rejection above is therefore of a bundle that differs from
    // what the client asked for, not of a store miss.
    let direct = rig
        .b_state
        .store
        .get_bundle(&bob.pubkey)
        .await
        .unwrap()
        .expect("bob's real bundle must exist in B's own store, untouched by the hook");
    assert_eq!(
        direct.account_pub, bob.pubkey,
        "B's own store must still hold the REAL bundle under bob's real key — only the wire reply \
         to A was substituted, proving this is a lying-server attack, not data corruption at rest"
    );
}

/// **F17 structural inertness.** Without the `test-tamper-hook` cargo feature, the substitution
/// code in `federation::inbound::handle_fed_fetch` does not exist at all — so even
/// `allow_test_tamper = true` at B must leave the federated reply byte-identical to what B's own
/// store holds. This is the federated counterpart to
/// `rendezvous.rs::tamper_flag_is_inert_without_feature`.
///
/// NOTE ON CI (see this file's module doc): this guard only runs under
/// `cargo test -p meridian-rendezvous` (default features) — `cargo test --workspace` compiles it
/// out entirely via resolver-2 unification (apps/cli's dev-dependency pins the feature on
/// workspace-wide). That CI step already exists (task 1.28/1.32) and needs no change to pick up
/// this new test binary.
#[cfg(not(feature = "test-tamper-hook"))]
#[tokio::test]
async fn fed_fetch_tamper_flag_is_inert_without_feature() {
    let rig = stand_up(FederationPolicyMode::Open, Vec::new(), 300, 600, 30, true).await;

    let bob = new_acct("org-b.test");
    let mut bc = bob.connect(&rig.b_c2s_url).await.unwrap();
    bc.publish_bundle(
        &bob.store,
        &bob.handle,
        meridian_signaling::DEFAULT_OTK_COUNT,
    )
    .await
    .unwrap();

    let alice = new_acct("org-a.test");
    let mut ac = alice.connect(&rig.a_c2s_url).await.unwrap();
    // Even with `allow_test_tamper = true` "enabled" at the config layer, the hook doesn't exist
    // in this build at all — the real bundle must come back and pass verification.
    let fetched = ac
        .fetch_bundle(bob.pubkey, Some("org-b.test".to_string()), false)
        .await
        .expect("without the cargo feature, the federated fetch must return bob's REAL bundle");
    assert_eq!(fetched.account_pub, bob.pubkey);
}
