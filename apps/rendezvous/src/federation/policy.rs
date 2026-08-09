//! Federation admission policy + per-origin/per-origin-account edge rate limits (task 2.6, ADR
//! 0002 "federation abuse handled bilaterally (rate limits, allowlists) rather than by global
//! consensus").
//!
//! Two independent questions, kept as two independent types on purpose:
//! - **[`FederationPolicy`]** — *may* this origin server federate with us at all
//!   (`open` / `allowlist` / `closed`)? This is the "outbound policy check": whether we are
//!   willing to talk to a partner domain in the first place, decided once per domain, with no
//!   notion of a request rate.
//! - **[`FederationLimits`]** — given that a domain IS allowed to federate, *is this particular
//!   request within budget*, checked **per origin server AND per origin account** (Goal — neither
//!   alone is sufficient: a per-origin-only budget lets one claimed account inside a partner org
//!   starve every other account behind the same origin, and a per-account-only budget lets a
//!   malicious/compromised partner server spray requests across many claimed accounts to evade
//!   any single counter).
//!
//! ## Scope boundary (see the task file's "Out")
//! This module is a pure, unit-testable decision layer. It does **not**:
//! - wire into any `fed_*` request handler — that is
//!   [2.7](../../../../docs/tasks/phase-2/2.7-federated-prekey-fetch.md) (prekey fetch) and
//!   [2.8](../../../../docs/tasks/phase-2/2.8-federated-route-reachability.md) (route
//!   reachability), which will call [`FederationLimits::check_fetch`]/
//!   [`FederationLimits::check_route`]/[`FederationLimits::check_reachability`] from their handler
//!   bodies. **Task 3.5 (review finding F4):** `check_route` is now called from exactly ONE handler
//!   body, `federation::inbound::handle_fed_route` — the real `fed_route` delivery path, keyed on
//!   `req.from` alone. `handle_fed_reachability` (2.8's `fed_reachability` handler) calls neither
//!   `check_fetch` nor `check_route`; see that function's own doc comment for why (it used to call
//!   `check_route` too, which meant `route_foreign`'s internal reachability pre-check and the real
//!   route it precedes both spent the same shared `route_per_origin` budget for one logical
//!   message, and spent two DIFFERENT `per_origin_account` keys — halving real cross-org route
//!   throughput against the documented per-minute numbers).
//!   **Task 3.5 follow-up (review finding F4, blocking):** simply removing `check_route` from
//!   `handle_fed_reachability` stopped that double-spend, but also left `FedOp::Reachability` —
//!   2.8's own independent wire op, not solely an internal implementation detail of
//!   `route_foreign`'s pre-check (a peer cannot be told apart from the wire frame alone) —
//!   completely unmetered, bounded only by task 3.2's *global*, not per-peer, link-count caps: a
//!   real, distinct DoS/enumeration-probing surface (thousands of presence probes per minute
//!   against arbitrary account IDs from one admitted-but-hostile peer), and one that made
//!   `docs/architecture/system-design.md` §3.5 and `docs/api/wire-protocol.md` §4's claims that the
//!   federation API rate-limits every query overclaim relative to the code. The fix, landed in this
//!   follow-up: a FOURTH, separate [`RateLimiter`] dimension, `reachability_per_origin`, consulted
//!   by [`FederationLimits::check_reachability`] — deliberately its own budget, not a reuse of
//!   `route_per_origin` (that would reintroduce coupling reachability's budget to real route
//!   throughput, the original bug's shape), and deliberately keyed on `origin_domain` ALONE, no
//!   account axis: `FedReachability` (like `FedFetchBundle` — see
//!   [`handle_fed_fetch`](crate::federation::inbound::handle_fed_fetch)'s doc comment on that same
//!   "no requester-account field" wire shape) carries no `from`/requester-account field at all, so
//!   there is nothing request-shaped to key a per-account budget on here (unlike `check_fetch`,
//!   which has `req.target` to stand in for one). `handle_fed_reachability` now calls
//!   [`FederationLimits::check_reachability`] before proceeding — see that function's own doc
//!   comment for the corrected accounting;
//! - decide what a rejected client is told — [`Decision`]/[`RejectReason`] carry enough internal
//!   structure for [2.9](../../../../docs/tasks/phase-2/2.9-federation-error-copy.md) to build
//!   client-visible error copy from later, but **nothing in this module renders that structure to
//!   the wire**. Handler wiring (2.7/2.8) decides how much of `RejectReason` a response is allowed
//!   to reveal; 2.9 decides the actual copy. Collapsing `closed` vs `allowlist-miss` vs
//!   `rate_limited` into client-visible detail leaks Org B's policy *and*, for a per-account
//!   rejection, that the claimed account exists at all — the anti-enumeration concern this task's
//!   own task file calls out. This module intentionally does not make that call.
//!
//! ## Not verified across the trust boundary (ADR 0017 / ADR 0002)
//! The `origin_account` bytes [`FederationLimits::check_fetch`]/`check_route` are keyed on are
//! **self-asserted by the partner server**, not independently verified by us — ADR 0017 draws the
//! trust boundary at the mTLS-authenticated *origin domain* (the peer's certificate identity),
//! not at any claim the peer makes about which of *its own* accounts a request is on behalf of.
//! A per-account budget is therefore only as good as the partner server's honesty about that
//! claim: a malicious or compromised partner can always attribute all of its traffic to freshly
//! invented account identifiers and get a fresh per-account budget for each one, bounded only by
//! the (still-enforced) per-origin budget above it. That is accepted, not a gap this task closes —
//! ADR 0002's consequences are explicit that federation abuse is handled **bilaterally** between
//! the two federating orgs (rate limits, allowlists) rather than by any global, cross-org-verified
//! consensus. Writing this down here, rather than leaving it implicit, is itself part of the task.
//!
//! ## `(origin_domain, origin_account)` counters are not a contact graph
//! [`FederationLimits`] holds one [`crate::ratelimit::RateLimiter`] whose keys are
//! `origin_domain || 0x00 || origin_account` (see [`origin_account_key`]). Per
//! `docs/security/anonymity-and-retention.md` must-never #2 (no materialized cross-org contact
//! graph), this is explicitly **not** that:
//! - **Same class of state as the existing per-account limiters**, the precedent the task file
//!   points at: `state::AppState::fetch_limiter`/`route_limiter` already key a
//!   [`crate::ratelimit::RateLimiter`] on a bare local `account_pub` (see `src/ws.rs`), and that
//!   has never been treated as a retention concern, because a `RateLimiter` is not a log or a
//!   table — see the next two points for why.
//! - **Transient and bounded, not accumulating.** A counter is `{window_start, count}` — it does
//!   not record *who the counterpart is*, *what was requested*, or *any past window*; it is
//!   overwritten in place every time the window rolls (see `RateLimiter::check`), and evicted
//!   entirely once its window has elapsed (task 1.20's amortised sweep, confirmed still to apply
//!   per-instance below). There is no operation on `RateLimiter` that lists, walks, or exports its
//!   keys outside of a `#[cfg(test)]`-only introspection helper — nothing here is queryable as "who
//!   has origin X talked to."
//! - **Never persisted, never logged.** The map lives in one `Mutex` inside one `RateLimiter`
//!   instance, in process memory only; it is dropped on restart (no cross-restart correlation is
//!   even possible) and this module adds no logging at all (see the module-level note below on
//!   why, and `tests/federation_policy.rs`'s `policy_module_introduces_no_unhashed_identifier_logging`,
//!   which pins that fact).
//!
//! In short: this is an in-memory, per-minute-window admission-control counter with no history,
//! not a stored table of cross-org relationships — the same shape as the pre-existing per-account
//! limiters `state::AppState` already runs, just keyed on `(origin_domain, origin_account)` instead
//! of a bare local account.
//!
//! ## Growth bound holds per `RateLimiter` instance (task 1.20 / review finding F21)
//! [`FederationLimits`] adds a **third rate-limit key class** on top of the two `state::AppState`
//! already has (IP-keyed `auth_limiter`; account-keyed `fetch_limiter`/`route_limiter`/
//! `turn_limiter`) — now FOUR `RateLimiter` instances (`fetch_per_origin`, `route_per_origin`,
//! `per_origin_account`, and, as of the 3.5 follow-up above, `reachability_per_origin`), all still
//! the one "per origin server, and/or per origin account" key class, not a fourth *class* of key.
//! Confirmed, not assumed: `RateLimiter`'s amortised-sweep growth bound
//! (`src/ratelimit.rs`) is a property of **each instance**, not of any shared/global state —
//! `Counters { map, last_sweep }` lives behind a `Mutex` field owned by that one `RateLimiter`
//! struct, and nothing in `ratelimit.rs` is `static`/thread-local/otherwise shared across
//! instances. Each of the limiters below therefore has its own independent map, its own
//! independent sweep cadence, and its own independent "eviction can never reset a live budget"
//! guarantee (see `RateLimiter::check`'s doc comment) — adding more instances changes nothing
//! about any single instance's bound; it only adds more independently-bounded maps. The residual,
//! stated the same way `ratelimit.rs` states it for the existing limiters: within a single window
//! an attacker can still create one entry per distinct key they present, bounded here by the
//! number of distinct `(domain, account)` claims a single connected federation peer chooses to
//! assert (`per_origin_account`) and by the number of distinct domains actually enrolled in this
//! server's federation policy (`fetch_per_origin`/`route_per_origin`/`reachability_per_origin` — an
//! unlisted domain never reaches `FederationLimits` at all, having already been rejected by
//! [`FederationPolicy::admit`]).
//!
//! ## No logging in this module
//! This decision layer adds no `tracing`/`println!`-style logging at all — mirroring how
//! `src/logid.rs`'s invariant #4 guard rail was landed *before* any logging existed in this crate
//! (task 1.20), rather than inventing a new log line here that would need its own `LogId`
//! wrapping. If/when 2.7/2.8's handler wiring later logs a rejection, the raw `origin_domain`/
//! `origin_account` bytes MUST be wrapped in [`crate::logid::LogId`] first, exactly as every other
//! identifier in this crate must be (enforced crate-wide by
//! `tools/lint-no-raw-id-logging.sh`) — this module does not itself need to touch `LogId` because
//! it produces no log line to guard.

use std::collections::HashSet;

use crate::ratelimit::RateLimiter;

// ---------------------------------------------------------------------------------------------
// FederationPolicy
// ---------------------------------------------------------------------------------------------

/// Whether this server is willing to federate with a given origin domain at all. The "outbound
/// policy check" — no rate limiting, no notion of a request rate, just admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FederationPolicy {
    /// Federate with any origin domain.
    Open,
    /// Federate only with the exact domains in the set (case-insensitive, normalized to ASCII
    /// lowercase at construction — see [`FederationPolicy::allowlist`]). **Exact match only**: no
    /// substring, prefix, or suffix matching. `evil-org-b.test` does not match an allowlisted
    /// `org-b.test`, nor does `org-b.test.evil.example`.
    Allowlist(HashSet<String>),
    /// Federate with nobody. Fail-closed default (see `config::Federation::default`) — the most
    /// restrictive of the three modes, chosen deliberately as the out-of-the-box behavior for a
    /// brand-new, untrusted-by-default surface.
    Closed,
}

impl FederationPolicy {
    /// Build an [`FederationPolicy::Allowlist`] from a set of domains, normalizing each to ASCII
    /// lowercase (DNS domains are case-insensitive, RFC 4343 — mirrors
    /// `federation::discovery::StaticMap`'s normalization of the same kind of value) so that a
    /// differently-cased entry in config still matches a differently-cased lookup.
    pub fn allowlist<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::Allowlist(
            domains
                .into_iter()
                .map(|d| d.as_ref().to_ascii_lowercase())
                .collect(),
        )
    }

    /// May `origin_domain` federate with us at all?
    ///
    /// `closed` rejects **every** domain, including one that also appears in the allowlist — the
    /// allowlist is meaningless once policy is closed; `closed` always wins and is checked first,
    /// with no other branch able to override it.
    pub fn admit(&self, origin_domain: &str) -> Decision {
        match self {
            FederationPolicy::Closed => Decision::Reject(RejectReason::Closed),
            FederationPolicy::Open => Decision::Admit,
            FederationPolicy::Allowlist(set) => {
                if set.contains(&origin_domain.to_ascii_lowercase()) {
                    Decision::Admit
                } else {
                    Decision::Reject(RejectReason::NotAllowlisted)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Decision / RejectReason
// ---------------------------------------------------------------------------------------------

/// The outcome of a policy or rate-limit check. Internal structure only — see this module's doc
/// comment on the 2.7/2.8/2.9 boundary: nothing here is client-visible copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Allowed to proceed.
    Admit,
    /// Not allowed, with enough internal detail for a caller (a handler in 2.7/2.8) to decide
    /// what, if anything, to do — logging, metrics, or building a (separately-designed,
    /// anti-enumeration-aware) client response in 2.9.
    Reject(RejectReason),
}

impl Decision {
    /// Convenience for callers that only care about admit/reject, not the reason.
    pub fn is_admit(&self) -> bool {
        matches!(self, Decision::Admit)
    }
}

/// Why a [`Decision::Reject`] happened. Deliberately does **not** carry the raw `origin_domain` or
/// `origin_account` bytes that triggered it — the caller already has those (it passed them in);
/// echoing them back here would be one more place a future refactor could accidentally end up
/// logging or wire-serializing an unhashed identifier.
///
/// No `NotFound` variant: this module never sees "domain doesn't resolve" — that is
/// `federation::discovery::DiscoveryError::NotFound`, a *discovery* miss, produced by a different
/// module before `FederationPolicy`/`FederationLimits` are ever consulted (see
/// `federation::discovery`'s module doc on the discovery/policy split). Conflating the two here
/// would blur a boundary the discovery module already drew deliberately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// `FederationPolicy::Closed`. Also produced when policy is `Closed` even if the domain
    /// happens to also be present in `allowlist` — closed always wins.
    Closed,
    /// `FederationPolicy::Allowlist` and `origin_domain` has no exact-match entry.
    NotAllowlisted,
    /// A [`FederationLimits`] budget was exceeded, at the indicated scope.
    RateLimited(RateLimitScope),
}

/// Which of the two independent budgets ([`FederationLimits`]'s Goal: "per origin server AND per
/// origin account, not either alone") was exceeded. [`FederationLimits::check_reachability`] always
/// reports [`RateLimitScope::Origin`] — see that method's doc comment for why it has no account
/// axis at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitScope {
    /// The whole origin server's aggregate budget for this operation kind (fetch, route, or
    /// reachability).
    Origin,
    /// This specific `(origin_domain, origin_account)` pair's shared budget.
    OriginAccount,
}

// ---------------------------------------------------------------------------------------------
// FederationLimits
// ---------------------------------------------------------------------------------------------

/// The two rate-limit *dimensions* the Goal requires (per origin server; per origin account),
/// realized as four [`RateLimiter`] instances: separate per-origin budgets for the three federated
/// operation kinds — prekey fetch (2.7), route (2.8), and, as of the task 3.5 follow-up (review
/// finding F4), reachability (2.8) — plus one budget shared by fetch and route (never
/// reachability, which has no account axis at all — see [`check_reachability`](Self::check_reachability))
/// for a given `(origin_domain, origin_account)` pair. Matches `config::Federation`'s
/// `fed_fetch_per_origin_per_min`/`fed_route_per_origin_per_min`/`fed_per_origin_account_per_min`/
/// `fed_reachability_per_origin_per_min` field-for-field, one `RateLimiter` per field.
pub struct FederationLimits {
    fetch_per_origin: RateLimiter,
    route_per_origin: RateLimiter,
    per_origin_account: RateLimiter,
    reachability_per_origin: RateLimiter,
}

/// Which federated operation kind a [`FederationLimits`] check is for. Determines which
/// *per-origin* limiter is consulted; the per-origin-account limiter is shared by both kinds
/// (mirrors `config::Federation::fed_per_origin_account_per_min` being a single field, not one per
/// operation kind). [`Operation::Reachability`] is deliberately absent from this enum:
/// [`FederationLimits::check_reachability`] does not go through [`FederationLimits::check`] at all
/// (no per-account axis to order against — see that method's doc comment), so it has no need of a
/// variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Fetch,
    Route,
}

impl FederationLimits {
    /// Build from the four per-minute limits (`config::Federation::to_limits` is the intended
    /// caller — see that method's doc comment for why config assembly, not this module, owns the
    /// conversion from raw config fields).
    pub fn new(
        fetch_per_origin_per_min: u32,
        route_per_origin_per_min: u32,
        per_origin_account_per_min: u32,
        reachability_per_origin_per_min: u32,
    ) -> Self {
        Self {
            fetch_per_origin: RateLimiter::per_minute(fetch_per_origin_per_min),
            route_per_origin: RateLimiter::per_minute(route_per_origin_per_min),
            per_origin_account: RateLimiter::per_minute(per_origin_account_per_min),
            reachability_per_origin: RateLimiter::per_minute(reachability_per_origin_per_min),
        }
    }

    /// Is a prekey-fetch request (2.7) from `origin_account`, claimed by `origin_domain`, within
    /// budget? Checks the per-origin-account budget, then the shared per-origin budget.
    pub fn check_fetch(&self, origin_domain: &str, origin_account: &[u8]) -> Decision {
        self.check(Operation::Fetch, origin_domain, origin_account)
    }

    /// Is a real message-routing request (2.8's `fed_route`, delivering an envelope) from
    /// `origin_account`, claimed by `origin_domain`, within budget? Same ordering guarantee as
    /// [`check_fetch`](Self::check_fetch). Despite the name (kept from 2.8, "route" is the
    /// operation kind this budget covers, not "route-or-reachability"), task 3.5 (review finding
    /// F4) made this the ONLY check spent per logical routed message: `handle_fed_route` is now
    /// this method's sole caller — `handle_fed_reachability` spends its own, separate
    /// `reachability_per_origin` budget instead (see [`check_reachability`](Self::check_reachability)).
    /// One real `fed_route` request therefore costs exactly one `route_per_origin` unit and one
    /// `per_origin_account` unit, keyed on `origin_account` = the SENDER (`req.from`) — never
    /// doubled, never charged to the recipient.
    pub fn check_route(&self, origin_domain: &str, origin_account: &[u8]) -> Decision {
        self.check(Operation::Route, origin_domain, origin_account)
    }

    /// Is a `fed_reachability` request (2.8) claimed by `origin_domain` within budget? Task 3.5
    /// follow-up (review finding F4, blocking): a FOURTH, independent [`RateLimiter`] dimension,
    /// deliberately NOT a reuse of `route_per_origin` (that would reintroduce coupling
    /// reachability's budget to real route throughput — the shape of the original double-spend
    /// bug this task's first fix closed) and deliberately keyed on `origin_domain` alone, with no
    /// per-account check at all: `FedReachability` (federation-protocol-v1.md §2) carries no
    /// `from`/requester-account field, unlike `FedRoute` (which has `from`) — mirrors how
    /// [`check_fetch`](Self::check_fetch) reads `FedFetchBundle`'s identically-shaped absence of a
    /// requester-account field (see `federation::inbound::handle_fed_fetch`'s doc comment), except
    /// `check_fetch` has `req.target` available as a practical per-account stand-in and
    /// `FedReachability` genuinely has nothing else request-shaped to key a second dimension on —
    /// keying on `req.target` here would make this indistinguishable from a second, redundant
    /// per-origin-account fetch-style budget rather than a real second dimension. Always reports
    /// [`RateLimitScope::Origin`] on rejection, never `OriginAccount` — there is no account-scoped
    /// counter here to have been the one that tripped.
    pub fn check_reachability(&self, origin_domain: &str) -> Decision {
        if !self
            .reachability_per_origin
            .check(origin_key(origin_domain).as_slice())
        {
            return Decision::Reject(RejectReason::RateLimited(RateLimitScope::Origin));
        }
        Decision::Admit
    }

    /// Per-account budget first, **then** the shared per-origin budget — deliberately not the other
    /// order (code-reviewer finding on task 2.6). Checking `per_origin` first meant every call spent
    /// a unit of the *shared* pool even for a caller already over its own account limit, so one
    /// claimed account's repeated (rejected) retries could still starve every other account behind
    /// the same origin — exactly the failure mode the per-account budget exists to prevent. With
    /// account-first ordering, a caller already over its own budget is rejected before ever touching
    /// the shared pool, so its retries cost it nothing beyond its own counter. This does not
    /// reintroduce the symmetric problem: an origin that's collectively over budget across many
    /// distinct, individually-within-budget accounts still correctly hits the origin limit, and each
    /// such rejection only costs that account's own private counter — never another account's.
    fn check(&self, op: Operation, origin_domain: &str, origin_account: &[u8]) -> Decision {
        let per_origin = match op {
            Operation::Fetch => &self.fetch_per_origin,
            Operation::Route => &self.route_per_origin,
        };
        if !self
            .per_origin_account
            .check(origin_account_key(origin_domain, origin_account).as_slice())
        {
            return Decision::Reject(RejectReason::RateLimited(RateLimitScope::OriginAccount));
        }
        if !per_origin.check(origin_key(origin_domain).as_slice()) {
            return Decision::Reject(RejectReason::RateLimited(RateLimitScope::Origin));
        }
        Decision::Admit
    }
}

/// Rate-limit key for a per-origin (whole partner server) budget: the domain alone, normalized to
/// ASCII lowercase (DNS case-insensitivity, mirrors `origin_account_key` and
/// `federation::discovery::StaticMap`'s normalization).
fn origin_key(origin_domain: &str) -> Vec<u8> {
    origin_domain.to_ascii_lowercase().into_bytes()
}

/// Rate-limit key for a per-origin-account budget: `origin_domain || 0x00 || origin_account`.
/// `0x00` is an unambiguous separator — a DNS domain name cannot contain a NUL byte — so no
/// `(domain, account)` pair can collide with a *different* `(domain, account)` pair by shifting
/// bytes across the boundary (e.g. domain `"ab"` + account `b"c"` staying distinguishable from
/// domain `"a"` + account `b"bc"`).
fn origin_account_key(origin_domain: &str, origin_account: &[u8]) -> Vec<u8> {
    let domain = origin_domain.to_ascii_lowercase();
    let mut key = Vec::with_capacity(domain.len() + 1 + origin_account.len());
    key.extend_from_slice(domain.as_bytes());
    key.push(0);
    key.extend_from_slice(origin_account);
    key
}
