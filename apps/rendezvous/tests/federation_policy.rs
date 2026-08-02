//! Task 2.6 acceptance: `federation::policy` — the pure `FederationPolicy`/`FederationLimits`
//! decision layer. No handler wiring here (that's 2.7/2.8); no client-visible error copy (2.9).

use meridian_rendezvous::federation::{
    Decision, FederationLimits, FederationPolicy, RateLimitScope, RejectReason,
};

// -- FederationPolicy: closed ------------------------------------------------------------------

#[test]
fn closed_rejects_every_domain() {
    let policy = FederationPolicy::Closed;

    assert_eq!(
        policy.admit("org-a.test"),
        Decision::Reject(RejectReason::Closed)
    );
    assert_eq!(
        policy.admit("anything.example"),
        Decision::Reject(RejectReason::Closed)
    );
}

#[test]
fn closed_rejects_a_domain_even_when_it_is_also_allowlisted() {
    // The easy footgun the task file calls out: an allowlist entry must not resurrect admission
    // once policy is `closed`. Build a policy that is simultaneously "closed" in mode and "would
    // have admitted org-b.test" in allowlist shape, by constructing each independently and
    // checking `Closed` never consults any allowlist data at all.
    let closed = FederationPolicy::Closed;
    let allowlist_with_same_domain = FederationPolicy::allowlist(["org-b.test"]);

    // Sanity: the allowlist policy alone WOULD admit this domain...
    assert_eq!(
        allowlist_with_same_domain.admit("org-b.test"),
        Decision::Admit
    );
    // ...but `closed` rejects it regardless of what any allowlist might have said.
    assert_eq!(
        closed.admit("org-b.test"),
        Decision::Reject(RejectReason::Closed)
    );
}

// -- FederationPolicy: allowlist (exact match only) --------------------------------------------

#[test]
fn allowlist_admits_an_exact_match() {
    let policy = FederationPolicy::allowlist(["org-b.test"]);

    assert_eq!(policy.admit("org-b.test"), Decision::Admit);
}

#[test]
fn allowlist_is_exact_match_not_substring_or_suffix() {
    let policy = FederationPolicy::allowlist(["org-b.test"]);

    // A domain that merely contains, is prefixed/suffixed by, or superstrings the allowlisted
    // domain must NOT match.
    for attacker_domain in [
        "evil-org-b.test",
        "org-b.test.evil.example",
        "evil.org-b.test",
        "org-b.testevil",
        "org-b",
    ] {
        assert_eq!(
            policy.admit(attacker_domain),
            Decision::Reject(RejectReason::NotAllowlisted),
            "{attacker_domain:?} must not match allowlisted \"org-b.test\""
        );
    }
}

#[test]
fn allowlist_match_is_case_insensitive_but_still_exact() {
    // DNS domains are case-insensitive (RFC 4343) — matches `federation::discovery::StaticMap`'s
    // normalization of the same kind of value.
    let policy = FederationPolicy::allowlist(["Org-B.test"]);

    assert_eq!(policy.admit("org-b.test"), Decision::Admit);
    assert_eq!(policy.admit("ORG-B.TEST"), Decision::Admit);
}

#[test]
fn allowlist_rejects_domains_not_in_the_list() {
    let policy = FederationPolicy::allowlist(["org-a.test", "org-b.test"]);

    assert_eq!(
        policy.admit("org-c.test"),
        Decision::Reject(RejectReason::NotAllowlisted)
    );
}

// -- FederationPolicy: open ----------------------------------------------------------------------

#[test]
fn open_admits_any_domain() {
    let policy = FederationPolicy::Open;

    for domain in ["org-a.test", "totally-unknown.example", "evil-org-b.test"] {
        assert_eq!(policy.admit(domain), Decision::Admit);
    }
}

// -- FederationLimits: per-origin and per-account budgets are independent -----------------------

#[test]
fn exhausting_the_per_origin_budget_does_not_affect_a_different_origins_budget() {
    let limits = FederationLimits::new(
        /* fetch */ 1, /* route */ 1, /* account */ 100,
    );

    assert_eq!(limits.check_fetch("org-a.test", b"alice"), Decision::Admit);
    // org-a.test's fetch budget (1/min) is now exhausted...
    assert_eq!(
        limits.check_fetch("org-a.test", b"bob"),
        Decision::Reject(RejectReason::RateLimited(RateLimitScope::Origin))
    );
    // ...but a different origin domain has its own, untouched budget.
    assert_eq!(limits.check_fetch("org-b.test", b"carol"), Decision::Admit);
}

#[test]
fn exhausting_the_per_account_budget_does_not_exhaust_the_per_origin_budget() {
    let limits = FederationLimits::new(
        /* fetch */ 100, /* route */ 100, /* account */ 1,
    );

    assert_eq!(limits.check_fetch("org-a.test", b"alice"), Decision::Admit);
    // alice@org-a.test's account budget (1/min) is now exhausted...
    assert_eq!(
        limits.check_fetch("org-a.test", b"alice"),
        Decision::Reject(RejectReason::RateLimited(RateLimitScope::OriginAccount))
    );
    // ...but a different account at the SAME origin still has budget, proving the origin-level
    // counter (still well within its own budget of 100) was not consumed by, nor conflated with,
    // the per-account rejection above.
    assert_eq!(limits.check_fetch("org-a.test", b"bob"), Decision::Admit);
}

#[test]
fn exhausting_the_per_origin_budget_does_not_exhaust_any_accounts_budget() {
    let limits = FederationLimits::new(
        /* fetch */ 1, /* route */ 100, /* account */ 100,
    );

    assert_eq!(limits.check_fetch("org-a.test", b"alice"), Decision::Admit);
    // The origin's fetch budget is now exhausted for THIS origin...
    assert_eq!(
        limits.check_fetch("org-a.test", b"bob"),
        Decision::Reject(RejectReason::RateLimited(RateLimitScope::Origin))
    );
    // ...but alice's own per-account budget (100/min, untouched by bob's rejection above) still
    // has room, and a different operation kind (route) draws from a separate per-origin budget
    // entirely, so it is unaffected by fetch's exhausted origin budget.
    assert_eq!(limits.check_route("org-a.test", b"alice"), Decision::Admit);
}

#[test]
fn fetch_and_route_per_origin_budgets_are_independent_operation_kinds() {
    let limits = FederationLimits::new(
        /* fetch */ 1, /* route */ 1, /* account */ 100,
    );

    assert_eq!(limits.check_fetch("org-a.test", b"alice"), Decision::Admit);
    assert_eq!(
        limits.check_fetch("org-a.test", b"bob"),
        Decision::Reject(RejectReason::RateLimited(RateLimitScope::Origin))
    );
    // Route has its own per-origin budget, unaffected by fetch's exhaustion above.
    assert_eq!(limits.check_route("org-a.test", b"carol"), Decision::Admit);
}

#[test]
fn per_account_budget_is_shared_across_fetch_and_route_for_the_same_pair() {
    // `fed_per_origin_account_per_min` is a single config field, not one per operation kind — the
    // budget is spent by either request kind against the same counter.
    let limits = FederationLimits::new(
        /* fetch */ 100, /* route */ 100, /* account */ 1,
    );

    assert_eq!(limits.check_fetch("org-a.test", b"alice"), Decision::Admit);
    assert_eq!(
        limits.check_route("org-a.test", b"alice"),
        Decision::Reject(RejectReason::RateLimited(RateLimitScope::OriginAccount))
    );
}

#[test]
fn different_origins_claiming_the_same_account_bytes_have_independent_budgets() {
    // The rate-limit key is `(origin_domain, origin_account)`, not `origin_account` alone — two
    // different origins asserting the identical account byte string must not share a budget.
    let limits = FederationLimits::new(
        /* fetch */ 100, /* route */ 100, /* account */ 1,
    );

    assert_eq!(
        limits.check_fetch("org-a.test", b"same-account-bytes"),
        Decision::Admit
    );
    assert_eq!(
        limits.check_fetch("org-b.test", b"same-account-bytes"),
        Decision::Admit,
        "org-b.test's budget for this account must be untouched by org-a.test's usage"
    );
}

// -- Rate-limit keys never reach a log line unhashed (task 1.20's LogId mechanism) --------------

/// Task 2.6 deliberately adds **no logging at all** to `federation::policy` — see that module's
/// doc comment for why (mirrors how `src/logid.rs`'s invariant #4 guard rail was landed before any
/// logging existed in this crate, task 1.20). This test does not just trust that comment: it reads
/// the module's own source and fails loudly the moment a logging macro appears in it that isn't
/// wrapped in `LogId` — the same detection shape `tools/lint-no-raw-id-logging.sh` uses crate-wide,
/// scoped here to one file so this assertion doesn't depend on remembering to run the shell script.
#[test]
fn policy_module_introduces_no_unhashed_identifier_logging() {
    let src = include_str!("../src/federation/policy.rs");
    let logging_macros = [
        "trace!",
        "debug!",
        "info!",
        "warn!",
        "error!",
        "println!",
        "eprintln!",
        "print!",
        "eprint!",
        "panic!",
        "dbg!",
    ];

    for (lineno, line) in src.lines().enumerate() {
        // Skip comment lines (including doc comments) — this file's own doc comments discuss
        // logging/LogId in prose and must not trip a source-level heuristic aimed at real code,
        // mirroring `tools/lint-no-raw-id-logging.sh`'s own comment-stripping step.
        if line.trim_start().starts_with("//") {
            continue;
        }
        for m in logging_macros {
            assert!(
                !line.contains(m),
                "policy.rs:{}: found a logging macro ({m}) in federation::policy — this module \
                 must add no logging at all (see its module doc); if this is intentional, the \
                 rate-limit key it logs MUST be wrapped in `LogId` first, and this test's \
                 exemption list must be updated deliberately, not silently: {line}",
                lineno + 1,
            );
        }
    }
}
