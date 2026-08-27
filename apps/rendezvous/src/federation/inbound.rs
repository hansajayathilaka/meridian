//! Server B's inbound handling of federated requests (task 2.7: `fed_fetch_bundle`; task 2.8 adds
//! `fed_route`/`fed_reachability` to the same [`serve_link`] dispatch loop).
//!
//! ## `origin_domains`/`metering_key` are always the mTLS-authenticated peer identity
//! Every handler here takes `origin_domains: &[String]` (for the admission decision) and
//! `metering_key: &str` (for rate-limit keying) as explicit parameters rather than reading
//! anything off the request body. Callers MUST pass [`FederationLink::peer_domains`]/
//! [`FederationLink::metering_key`] — the TLS-certificate-derived identity/identities established
//! when the link was accepted — never `FedFetchBundle::requesting_server` (self-asserted,
//! informational only; see `meridian_proto::fed`'s module docs and ADR 0017 (a)). [`serve_link`]
//! is the one place that makes this binding, so nothing downstream of it can accidentally key a
//! policy/rate-limit decision off attacker-controlled bytes.
//!
//! **Task 3.6 (review finding F9):** a partner's client certificate can authenticate more than
//! one domain (multi-SAN); admission ([`FederationPolicy::admit_any`]) matches against the WHOLE
//! validated set (so a cert whose allowlisted domain isn't the cert's first SAN is still
//! correctly admitted), while rate-limit keying uses a single, deterministic
//! [`FederationLink::metering_key`] (so a cert renewal that reorders — without changing the
//! values of — the same SAN set doesn't fragment an origin's rate-limit history). These are
//! deliberately two different values, sourced from the same underlying [`FederationLink`], not
//! one collapsed parameter — see `link.rs`'s and `policy.rs`'s own doc comments for why.
//!
//! ## `origin_account` for the fetch rate limit
//! [`crate::federation::policy::FederationLimits::check_fetch`] wants a per-*account* rate-limit
//! key, but `FedFetchBundle` (federation-protocol-v1.md §2) carries no requesting-account field at
//! all — unlike `FedRoute`, which carries `from` (the field federation-protocol-v1.md §0 explicitly
//! names as the "origin account" axis's source, C5). There is nothing else request-shaped to key
//! on here, so [`handle_fed_fetch`] uses `req.target` (the account BEING fetched) as the
//! per-account dimension instead: it bounds how many times per minute a single foreign origin may
//! query for the *same* target, on top of the aggregate per-origin budget — a materially different
//! but still real anti-abuse property (a single claimed target can't be hammered by one origin
//! beyond its own budget, independent of how many other targets that origin is also querying).
//! This is a deliberate reading of an underspecified wire shape, not a wire change: `FedFetchBundle`
//! is reused verbatim, per this task's scope.
//!
//! **Residual (security-reviewer, task 2.7):** keying on `req.target` bounds repeated queries
//! against *one* target, but provides no defense against a malicious/compromised origin that
//! sprays requests across many distinct (real or fabricated) targets — each fresh target starts
//! its own per-account counter at zero, so this dimension alone cannot be exhausted by varying
//! the target. `apps/rendezvous/tests/federation_fetch.rs::bs_federation_edge_rate_limit_trips_through_the_real_path`
//! demonstrates exactly this by construction (it varies the target per call so only the
//! per-*origin* budget trips). This is not a hard hole — the 256-bit keyspace already makes
//! target-guessing useless for enumeration, and the aggregate per-origin budget still bounds
//! total throughput regardless of how targets are varied — but it means the per-account
//! dimension's real guarantee is narrower than "bounds one origin's total fetch volume": it only
//! bounds volume against a single repeatedly-queried target. Recorded here rather than only
//! implied by the positive framing above (mirrors `federation::policy`'s own residual-risk
//! documentation style).
//!
//! ## Dependency-trap note (see this task's Risks)
//! Nothing here decodes, verifies, or otherwise inspects the *cryptographic* validity of a fetched
//! [`meridian_proto::PrekeyBundle`] — this module only does a `Store::get_bundle` lookup and wraps
//! the result in [`FedBundle`]. `meridian-signaling::verify_bundle` (the client-side check) is
//! never imported into this crate (enforced by `tools/lint-server-no-core.sh`); §3.3 step 4 puts
//! bundle verification at the client, deliberately.

use std::sync::Arc;

use axum::extract::ws::Message;
use meridian_proto::{
    fed_error_codes, Deliver, FedBundle, FedErr, FedFetchBundle, FedFrame, FedOp, FedReachability,
    FedReachable, FedRoute, Frame, Op,
};

use crate::federation::link::{LinkError, MAX_FRAME_LEN};
use crate::federation::policy::{Decision, FederationLimits, FederationPolicy};
use crate::federation::{FederationLink, FederationListener};
use crate::metrics::Metrics;
use crate::state::{AppState, Registry};
use crate::store::Store;

/// Server B's inbound `fed_fetch_bundle` handler: origin admission (2.6), then the
/// per-origin/per-origin-account rate limits (2.6), then an exact-key store lookup — the federated
/// mirror of `ws::handle_fetch`'s local path, minus anything socket-shaped (this function never
/// touches a client connection; [`serve_link`] is what talks to the wire on both sides).
///
/// **TEST HOOK (task 2.12, F17 discipline):** when compiled with the `test-tamper-hook` cargo
/// feature AND `server_cfg.allow_test_tamper` is `true`, the bundle handed back is
/// [`crate::auth::substitute_bundle`]'d before it is returned — a malicious/compromised B lying to
/// A about the requested identity's prekey bundle, the cross-org analogue of `ws::handle_fetch`'s
/// existing local substitution. Deliberately **unconditional** on this flag alone, unlike the local
/// path's additional client-supplied `Fetch.tamper` bit: `FedFetchBundle`
/// (federation-protocol-v1.md §2) carries no such field, and a wire change to add one is out of
/// this task's scope (any wire change is a `meridian-proto` change, versioned, per this crate's own
/// invariants) — a real malicious B does not wait to be asked to lie. Compiled in only under the
/// cargo feature (absent from release binaries entirely, not merely runtime-gated, F17); see
/// `apps/rendezvous/tests/federation_abuse.rs` for the adversarial cell and its structural
/// inertness proof.
pub async fn handle_fed_fetch(
    store: &dyn Store,
    policy: &FederationPolicy,
    limits: &FederationLimits,
    server_cfg: &crate::config::Server,
    origin_domains: &[String],
    metering_key: &str,
    req: &FedFetchBundle,
) -> Result<FedBundle, FedErr> {
    if let Decision::Reject(_reason) = policy.admit_any(origin_domains.iter().map(String::as_str)) {
        // `_reason` (Closed vs. NotAllowlisted) is internal detail only — see `policy` module's
        // doc comment on the 2.7/2.8/2.9 boundary. Both collapse to the same client-visible code.
        return Err(FedErr {
            code: fed_error_codes::POLICY_DENIED.to_string(),
            msg: "federation is closed for this origin".to_string(),
        });
    }
    // See this module's doc comment: `req.target`, not a requesting-account field that doesn't
    // exist on this request type, is the per-account rate-limit dimension for a fetch.
    if let Decision::Reject(_reason) = limits.check_fetch(metering_key, req.target.as_slice()) {
        return Err(FedErr {
            code: fed_error_codes::RATE_LIMITED.to_string(),
            msg: "too many federated fetch requests".to_string(),
        });
    }
    match store.get_bundle(&req.target).await {
        Ok(Some(bundle)) => {
            // TEST HOOK (F17): compiled in only under `test-tamper-hook`; see this function's doc
            // comment. Without the feature, `server_cfg` is unused by this branch entirely (still
            // referenced by the `#[cfg(not(...))]` arm below so the parameter itself is never
            // reported as dead).
            #[cfg(feature = "test-tamper-hook")]
            let bundle = if server_cfg.allow_test_tamper {
                crate::auth::substitute_bundle(&bundle)
            } else {
                bundle
            };
            #[cfg(not(feature = "test-tamper-hook"))]
            let _ = server_cfg;
            Ok(FedBundle { bundle })
        }
        Ok(None) => Err(FedErr {
            code: fed_error_codes::NOT_FOUND.to_string(),
            msg: "no bundle for the requested account".to_string(),
        }),
        Err(_) => Err(FedErr {
            code: fed_error_codes::BAD_REQUEST.to_string(),
            msg: "store lookup failed".to_string(),
        }),
    }
}

/// Server B's inbound `fed_route` handler (task 2.8): origin admission, then the per-origin/
/// per-origin-account rate limits keyed on `req.from` — the field ADR 0017 C5 names as the
/// "origin account" axis's source, unlike `FedFetchBundle` which carries none (see this module's
/// doc comment on `handle_fed_fetch`'s different reading of that same underspecified shape) —
/// then a defense-in-depth oversized check, then delivery into B's own local [`Registry`].
///
/// **Task 3.5 (review finding F4): this is now the ONLY place a route budget is spent for a
/// given logical message.** Before this task, [`route_foreign`](crate::federation::outbound::route_foreign)'s
/// internal [`reachable_foreign`](crate::federation::outbound::reachable_foreign) pre-check and
/// this function's real `fed_route` both called `limits.check_route`, so one client-originated
/// route cost the org-wide [`FederationLimits`] `route_per_origin` budget TWICE (halving real
/// cross-org route throughput against the documented `fed_route_per_origin_per_min` number), and
/// separately touched two DIFFERENT `per_origin_account` keys — the pre-check keyed on `to` (the
/// recipient), this handler keyed on `from` (the sender) — so in an ordinary two-way conversation
/// EVERY message, whether sent or received, cost each participant a unit of their own per-account
/// budget (once as `from` when they send, once as the reachability pre-check's `target` when the
/// other side sends to them), roughly doubling the effective per-message cost against the
/// documented `fed_per_origin_account_per_min` number too. See
/// [`handle_fed_reachability`]'s doc comment for why the pre-check no longer spends either of
/// THIS budget's units at all (it spends its own, separate `reachability_per_origin` budget
/// instead, as of the task 3.5 follow-up — never this one): **one real routed message now costs
/// exactly one `route_per_origin` unit and one `per_origin_account` unit (keyed on `req.from`, the
/// sender, alone)** — matching the Goal this task was filed to restore.
///
/// **`req.from` is relayed verbatim, never inspected.** Per [`FedRoute`]'s own doc comment and
/// `apps/proto/src/fed.rs`'s module docs (ADR 0017 C1/C2), `from` is routing metadata asserted by
/// the sending (origin) server — this function passes it straight through as the `Deliver.from`
/// pushed to B's own client, exactly as a purely local route already does. `req.envelope`'s bytes
/// are moved into `Deliver.blob` the same way: never decoded, parsed, or otherwise inspected —
/// that would need `meridian-envelope`, which this crate must never depend on
/// (`tools/lint-no-serde-on-blob.sh`). The client-side `SenderMismatch` check
/// (`apps/core/src/chat.rs`) remains the load-bearing defence against a forged `from`; a hostile
/// foreign server asserting someone else's key is a client-side detection, not something this
/// server can or should verify.
///
/// **Fire-and-forget on success** (federation-protocol-v1.md §2): this function's `Ok(())` means
/// [`serve_link`] sends NO reply frame at all — not even one signalling that the local recipient
/// was actually connected. `Registry::send_to`'s own return value (`bool`, whether it found a live
/// connection and enqueued onto it) is never surfaced back across the federation boundary — not
/// just in the disconnect-race sense: this also silently swallows an outbound-side delivery
/// failure at B (e.g. a full mpsc channel to a slow client) exactly as it swallows a target that
/// disconnected between `route_foreign`'s `reachable_foreign` pre-check (architect decision #3)
/// and this call. Neither path is reported back to the calling peer — `route_foreign`'s pre-check
/// is what a caller relies on for target liveness, not this call's outcome. Both are the same
/// accepted residual, not a new error this function invents a code for: see this task's "Out:
/// offline queuing" scope boundary (a defined error at fed_route time, never a queue).
///
/// **Task 3.8 (review findings F8 + N4).** Two fixes, both local to this function:
///
/// 1. **F8**: `Registry::send_to`'s `bool` IS now read (just never relayed to the peer, per the
///    fire-and-forget note above) so that a successful federated delivery increments
///    [`Metrics::envelope_routed`] exactly like the local (same-server) path already does in
///    `ws::deliver_one` — before this fix, every delivery that crossed the federation boundary was
///    invisible to `meridian_envelopes_routed_total`, silently under-counting exactly the traffic
///    Phase 2 added. No new metric, no new label: this calls the same existing, unparameterized
///    counter local routes already use — in particular, deliberately no `peer_domain`/origin label
///    (that would materialize the cross-org contact graph; anonymity-and-retention.md must-never
///    #2, already settled the same way for `meridian_federation_link_up` in task 2.4).
/// 2. **N4**: the oversized check below now measures `req.envelope`'s own byte length directly
///    instead of re-encoding the whole [`FedFrame`] just to measure it — see that check's own doc
///    comment for the approximation this introduces.
pub async fn handle_fed_route(
    registry: &Registry,
    policy: &FederationPolicy,
    limits: &FederationLimits,
    metrics: &Metrics,
    origin_domains: &[String],
    metering_key: &str,
    req: &FedRoute,
) -> Result<(), FedErr> {
    if let Decision::Reject(_reason) = policy.admit_any(origin_domains.iter().map(String::as_str)) {
        return Err(FedErr {
            code: fed_error_codes::POLICY_DENIED.to_string(),
            msg: "federation is closed for this origin".to_string(),
        });
    }
    if let Decision::Reject(_reason) = limits.check_route(metering_key, req.from.as_slice()) {
        return Err(FedErr {
            code: fed_error_codes::RATE_LIMITED.to_string(),
            msg: "too many federated route requests".to_string(),
        });
    }
    // Architect decision #1, defense-in-depth: a `req` that arrived through `serve_link`'s normal
    // wire path already passed through `link::read_frame`'s own `MAX_FRAME_LEN` cap before it was
    // ever decoded into a `FedRoute` at all, so this branch is structurally unreachable via that
    // path today — it exists for a non-compliant peer (or a caller that built `req` some other
    // way, e.g. a direct unit test) rather than the wire itself.
    //
    // Task 3.8 (N4): this used to build a full `FedFrame`, CBOR-encode it, and measure THAT — a
    // full re-encode of the entire frame (re-serializing `req.to`/`req.from`/`req.envelope` all
    // over again) just to measure a length dominated by `req.envelope`'s own size. Measuring
    // `req.envelope`'s byte length directly is cheaper and avoids the re-encode entirely.
    //
    // This is NOT byte-identical to the old `encoded_len`: the old value also counted the fixed
    // `to`/`from` fields (32 bytes each) plus CBOR framing/tag overhead for the whole `FedRoute`
    // struct, so this check is a strictly more permissive approximation — it can let through a
    // request whose real encoded size is up to roughly that fixed overhead (well under 1 KiB) over
    // `MAX_FRAME_LEN`, when `req.envelope`'s own length alone sits just at the boundary. That slack
    // is acceptable here specifically because this check is explicitly defense-in-depth, not the
    // load-bearing size cap — `link::read_frame`'s own `MAX_FRAME_LEN` check on the real wire path
    // already rejects an oversized frame before it is ever decoded into a `FedRoute` at all (see
    // above); this check only ever fires for a non-compliant peer or a caller that built `req`
    // some other way.
    if req.envelope.as_bytes().len() > MAX_FRAME_LEN {
        return Err(FedErr {
            code: fed_error_codes::BAD_REQUEST.to_string(),
            msg: "envelope too large to route".to_string(),
        });
    }

    let deliver = Deliver {
        from: req.from,
        blob: req.envelope.clone(),
        // A live push of a route that just crossed the federation boundary, never a mailbox drain
        // (T07's federated mailbox enqueue is 8.6/8.7's job) — `mailbox_id` stays absent here.
        mailbox_id: None,
    };
    let bytes = Frame::new(Op::Deliver, 0, &deliver)
        .and_then(|f| f.to_bytes())
        .map_err(|_| FedErr {
            code: fed_error_codes::BAD_REQUEST.to_string(),
            msg: "encode failed".to_string(),
        })?;
    // Task 3.8 (F8): mirrors `ws::deliver_one`'s identical local-route logic — count a federated
    // delivery in `envelopes_routed_total` exactly when `Registry::send_to` actually found a live
    // connection and enqueued onto it. Whether the target was connected is still never reported
    // back across the federation boundary (see doc comment above) — this only affects the local
    // metric, not the wire reply (there is none, on either branch).
    if registry.send_to(&req.to, Message::Binary(bytes)) {
        metrics.envelope_routed();
    }
    Ok(())
}

/// Server B's inbound `fed_reachability` handler (task 2.8): origin admission, then the DEDICATED
/// `reachability_per_origin` rate-limit check (task 3.5 follow-up, review finding F4, blocking —
/// see below), then EXACTLY `FedReachable{connected}` — no other branch, ever.
/// `Registry::is_connected` already returns `false` identically whether `target` never registered
/// or registered-then-disconnected (see [`Registry`]'s own doc comment); there is no separate
/// existence check here to leak, and this function must never grow one. Nothing on this path is
/// logged or persisted: `registry` is an in-memory `Registry` lookup only, and this module (like
/// `federation::policy`) adds no `tracing`/`println!`-style logging at all.
///
/// **Task 3.5's original fix (review finding F4) removed this function's `check_route` call
/// entirely** — before it, `route_foreign`'s internal reachability pre-check and the real
/// `fed_route` it precedes both spent the same shared `route_per_origin`/`per_origin_account`
/// budgets for one logical message, halving real cross-org route throughput against the
/// documented per-minute numbers (see [`handle_fed_route`]'s doc comment for the exact
/// double-spend that closed). That much of the original fix is unchanged by this follow-up.
///
/// **What that original fix got wrong, and this follow-up corrects (review finding F4, blocking):**
/// removing `check_route` left `FedOp::Reachability` completely UNMETERED, for any peer,
/// indefinitely. That was not a safe residual: `FedOp::Reachability` is task 2.8's own independent
/// wire op (federation-protocol-v1.md §2), not solely an implementation detail of routing — this
/// server cannot tell, from the wire frame alone, "A's own `route_foreign` pre-check" apart from
/// "a federated peer directly probing reachability as a standalone operation." Worse, task 3.2's
/// `max_links` semaphore (the only thing bounding this before this follow-up) is a *global* cap
/// shared across every partner, not per-peer — so one hostile-but-admitted peer holding open a
/// large share of that shared budget could loop reachability probes serially, at wire-RTT speed,
/// indefinitely, against arbitrary account IDs, while also starving every other legitimate partner
/// of link capacity (re-opening the DoS class task 3.2 exists to bound). It also made
/// `docs/architecture/system-design.md` §3.5 and `docs/api/wire-protocol.md` §4's claims that the
/// federation API rate-limits every query overclaim relative to the code.
///
/// The fix: [`FederationLimits::check_reachability`] — a fourth, independent [`RateLimiter`]
/// dimension (`reachability_per_origin`), deliberately NOT a reuse of `route_per_origin` (that
/// would reintroduce coupling reachability's budget to real route throughput, the original bug's
/// shape) and keyed on `origin_domain` alone, with no per-account axis (`FedReachability` carries
/// no `from`/requester-account field — see that method's own doc comment). `handle_fed_reachability`
/// is the only caller. This is not a bypass of the *route* rate limit in the sense of getting more
/// actual message content delivered for free: `handle_fed_route` still spends its own,
/// unconditional budget on every real delivery, regardless of how many reachability probes
/// preceded it — this is a genuinely separate budget for a genuinely separate operation.
///
/// [`RateLimiter`]: crate::ratelimit::RateLimiter
pub async fn handle_fed_reachability(
    registry: &Registry,
    policy: &FederationPolicy,
    limits: &FederationLimits,
    origin_domains: &[String],
    metering_key: &str,
    req: &FedReachability,
) -> Result<FedReachable, FedErr> {
    if let Decision::Reject(_reason) = policy.admit_any(origin_domains.iter().map(String::as_str)) {
        return Err(FedErr {
            code: fed_error_codes::POLICY_DENIED.to_string(),
            msg: "federation is closed for this origin".to_string(),
        });
    }
    if let Decision::Reject(_reason) = limits.check_reachability(metering_key) {
        return Err(FedErr {
            code: fed_error_codes::RATE_LIMITED.to_string(),
            msg: "too many federated reachability requests".to_string(),
        });
    }
    Ok(FedReachable {
        connected: registry.is_connected(&req.target),
    })
}

/// Serve one already-established inbound [`FederationLink`] until it closes, errors, or sits idle
/// past `federation.serve_idle_timeout_ms` (task 3.23) waiting for the peer's next frame: read
/// frames, dispatch by [`FedOp`], reply. `FedOp::FetchBundle` (2.7), `FedOp::Route` and
/// `FedOp::Reachability` (2.8 — `Hello` is already consumed by link establishment) are handled;
/// every other/unknown op still replies `FedErr{bad_request}`.
pub async fn serve_link(mut link: FederationLink, state: Arc<AppState>) {
    // `link.peer_domains`/`link.metering_key()` are the mTLS-authenticated identity (see this
    // module's doc comment) — captured once, used for every request on this link, never
    // re-derived from a request body.
    let origin_domains = link.peer_domains.clone();
    let metering_key = link.metering_key().to_string();
    // Task 3.23: computed once, before the loop, not per-iteration — mirrors `run_federation`'s
    // own `handshake_timeout`, which is likewise read from config once rather than on every pass.
    let idle_timeout =
        std::time::Duration::from_millis(state.config.federation.serve_idle_timeout_ms);
    loop {
        let frame =
            match crate::federation::link::with_deadline(idle_timeout, link.recv_frame()).await {
                Ok(Ok(f)) => f,
                Ok(Err(_)) => return, // link closed or errored — nothing more to serve
                // Task 3.23 (found during 3.22's coverage work): an already-handshaked peer that
                // stalls or trickles a frame indefinitely must not hold this link's `max_links`
                // permit forever. `serve_idle_timeout_ms` is a DELIBERATELY separate config knob from
                // `handshake_timeout_ms` (bounds the PRE-AUTH mTLS+FedHello handshake — never reached
                // by an already-established link like this one) and from `request_timeout_ms` (bounds
                // an OUTBOUND request/reply round trip this server itself initiates, not an inbound
                // peer's next frame on a link it already holds) — see
                // `Federation::serve_idle_timeout_ms`'s own doc comment for the full reasoning.
                // Dropping here, with no reply frame, is the same "link closed, nothing more to
                // serve" shape as the arm above: the caller (`run_federation`) releases the
                // `max_links` permit the instant this function returns.
                Err(_deadline_exceeded) => return,
            };
        match frame.op {
            FedOp::FetchBundle => {
                let req: FedFetchBundle = match frame.decode() {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = reply_fed_err(
                            &mut link,
                            frame.id,
                            fed_error_codes::BAD_REQUEST,
                            "malformed fed_fetch_bundle body",
                        )
                        .await;
                        continue;
                    }
                };
                let result = handle_fed_fetch(
                    state.store.as_ref(),
                    &state.federation.policy,
                    &state.federation.limits,
                    &state.config.server,
                    &origin_domains,
                    &metering_key,
                    &req,
                )
                .await;
                match result {
                    Ok(bundle) => {
                        if let Ok(out) = FedFrame::new(FedOp::Bundle, frame.id, &bundle) {
                            let _ = link.send_frame(&out).await;
                        }
                    }
                    Err(err) => {
                        if let Ok(out) = FedFrame::new(FedOp::Err, frame.id, &err) {
                            let _ = link.send_frame(&out).await;
                        }
                    }
                }
            }
            FedOp::Route => {
                let req: FedRoute = match frame.decode() {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = reply_fed_err(
                            &mut link,
                            frame.id,
                            fed_error_codes::BAD_REQUEST,
                            "malformed fed_route body",
                        )
                        .await;
                        continue;
                    }
                };
                let result = handle_fed_route(
                    &state.registry,
                    &state.federation.policy,
                    &state.federation.limits,
                    &state.metrics,
                    &origin_domains,
                    &metering_key,
                    &req,
                )
                .await;
                // `FedOp::Route` is fire-and-forget on success (federation-protocol-v1.md §2,
                // "there is no FedRouteOk" — do not add one): only the error case replies at all.
                if let Err(err) = result {
                    if let Ok(out) = FedFrame::new(FedOp::Err, frame.id, &err) {
                        let _ = link.send_frame(&out).await;
                    }
                }
            }
            FedOp::Reachability => {
                let req: FedReachability = match frame.decode() {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = reply_fed_err(
                            &mut link,
                            frame.id,
                            fed_error_codes::BAD_REQUEST,
                            "malformed fed_reachability body",
                        )
                        .await;
                        continue;
                    }
                };
                let result = handle_fed_reachability(
                    &state.registry,
                    &state.federation.policy,
                    &state.federation.limits,
                    &origin_domains,
                    &metering_key,
                    &req,
                )
                .await;
                match result {
                    Ok(reachable) => {
                        if let Ok(out) = FedFrame::new(FedOp::Reachable, frame.id, &reachable) {
                            let _ = link.send_frame(&out).await;
                        }
                    }
                    Err(err) => {
                        if let Ok(out) = FedFrame::new(FedOp::Err, frame.id, &err) {
                            let _ = link.send_frame(&out).await;
                        }
                    }
                }
            }
            _ => {
                // Any other/unknown op (`Hello` mid-stream, a future op this server doesn't know
                // about yet): fail closed with a structured error rather than silently dropping
                // the frame — the peer's request gets a defined reply either way.
                let _ = reply_fed_err(
                    &mut link,
                    frame.id,
                    fed_error_codes::BAD_REQUEST,
                    "operation not supported by this server",
                )
                .await;
            }
        }
    }
}

async fn reply_fed_err(
    link: &mut FederationLink,
    id: u64,
    code: &str,
    msg: &str,
) -> Result<(), LinkError> {
    let err = FedErr {
        code: code.to_string(),
        msg: msg.to_string(),
    };
    let frame = FedFrame::new(FedOp::Err, id, &err)?;
    link.send_frame(&frame).await
}

/// Bind this server's s2s mTLS listener (task 2.4's [`FederationListener`]) from `state`'s
/// resolved federation config. Split out from [`run_federation`]/[`serve_federation`] so a caller
/// (a test harness, or [`serve_federation`] itself) can read back the bound ephemeral address
/// before the accept loop starts consuming the listener.
pub async fn bind_federation(state: &AppState) -> Result<FederationListener, LinkError> {
    let paths = state.federation.tls.as_paths();
    FederationListener::bind(
        &state.config.federation.bind,
        &paths,
        &state.federation.own_domain,
        Some(state.metrics.clone()),
    )
    .await
}

/// Minimum interval between two "dropped for capacity" stderr lines, per [`DropRateLimiter`]
/// instance (one per [`run_federation`] call — i.e. one per bound listener). Chosen to keep a
/// sustained flood of over-capacity connection attempts from turning into a comparably-sized flood
/// of log lines, while still surfacing the condition promptly and periodically (task 3.2 / F2-N5's
/// "log a rate-limited stderr line" requirement). `TODO: confirm` alongside this task's three
/// numeric config knobs — not grounded in an existing doc, just a conservative starting point.
const DROP_LOG_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Coalesces repeated "connection dropped: no free permit" events into at most one stderr line per
/// [`DROP_LOG_MIN_INTERVAL`], reporting how many were suppressed since the last line. Carries no
/// peer-identifying state at all (no IP, no cert identity — those are never even looked at on this
/// path, since the drop happens before or immediately after `accept_raw`, well before any identity
/// is established) — only a timestamp and a count, so there is nothing raw-identifier-shaped for
/// `tools/lint-no-raw-id-logging.sh` to ever have to catch here.
struct DropRateLimiter {
    state: std::sync::Mutex<(std::time::Instant, u64)>,
}

impl DropRateLimiter {
    fn new() -> Self {
        Self {
            // Backdated by a full interval so the very first drop ever logs immediately, rather
            // than needing to wait out one interval before its first line appears.
            state: std::sync::Mutex::new((std::time::Instant::now() - DROP_LOG_MIN_INTERVAL, 0)),
        }
    }

    /// Record one dropped connection for `reason` (a static, non-identifying label — e.g.
    /// `"handshake capacity"`); emit a coalesced stderr line at most once per
    /// [`DROP_LOG_MIN_INTERVAL`].
    ///
    /// **Not** "log the first of every burst immediately, then coalesce the rest": that shape logs
    /// once per burst rather than once per interval, and under a sustained flood (drops arriving
    /// faster than they ever go quiet) degenerates back into one line per drop. Instead this is a
    /// plain fixed-window coalescer keyed on wall-clock time alone: at most one line escapes per
    /// [`DROP_LOG_MIN_INTERVAL`], and that line reports how many drops (including itself) happened
    /// since the previous line — a real, constant upper bound on log volume regardless of how
    /// bursty or sustained the drops are.
    fn note_drop(&self, reason: &'static str) {
        let mut guard = self.state.lock().unwrap();
        let (last_logged, suppressed) = &mut *guard;
        let now = std::time::Instant::now();
        if now.duration_since(*last_logged) >= DROP_LOG_MIN_INTERVAL {
            if *suppressed > 0 {
                let total = *suppressed + 1;
                eprintln!(
                    "federation: dropped {total} inbound s2s connection(s) in the last \
                     {DROP_LOG_MIN_INTERVAL:?} (rate-limited); most recent reason: {reason}"
                );
            } else {
                eprintln!("federation: dropped an inbound s2s connection (rate-limited): {reason}");
            }
            *last_logged = now;
            *suppressed = 0;
        } else {
            *suppressed += 1;
        }
    }
}

/// Accept inbound federation links forever, hardened against one silent/slow/hostile peer wedging
/// every other partner's connection attempt (task 3.2, review findings F2 + N5).
///
/// The loop itself does only [`FederationListener::accept_raw`] — a bare TCP accept, bounded by the
/// OS accept queue, never by anything a peer does after connecting — then hands each connection off
/// to its own spawned task and immediately loops back for the next one. Per connection, that task:
///
/// 1. Tries to acquire a permit from the **handshake** semaphore
///    (`federation.max_concurrent_handshakes`). If none is free, the raw connection is dropped
///    immediately (no bytes are ever sent to it) and a rate-limited, identity-free line is logged
///    (via [`DropRateLimiter`]) — this is the pre-auth admission control: an unbounded number of
///    concurrent in-handshake connections is itself the resource-exhaustion surface this task
///    closes.
/// 2. Runs [`FederationListener::finish_handshake`] (mTLS + `FedHello`) under
///    [`crate::federation::link::with_deadline`], bounded by `federation.handshake_timeout_ms`. The
///    handshake permit is released as soon as this step finishes, one way or another (success,
///    protocol/TLS error, or deadline).
/// 3. On a successful handshake, tries to acquire a permit from the separate **link** semaphore
///    (`federation.max_links`) — deliberately a second semaphore, not the same permit held since
///    step 1: an in-progress handshake and an established, actively-served link have very different
///    resource footprints and very different attacker-reachable-before-authentication status, so
///    they get independently operator-tunable caps. Exhaustion here drops the (already
///    TLS-authenticated) link the same way — rate-limited, identity-free log line, no reply frame.
/// 4. Holds the link permit for exactly as long as [`serve_link`] runs, releasing it when the link
///    closes.
pub async fn run_federation(listener: FederationListener, state: Arc<AppState>) {
    let listener = Arc::new(listener);
    let handshake_timeout =
        std::time::Duration::from_millis(state.config.federation.handshake_timeout_ms);
    let handshake_slots = Arc::new(tokio::sync::Semaphore::new(
        state.config.federation.max_concurrent_handshakes as usize,
    ));
    let link_slots = Arc::new(tokio::sync::Semaphore::new(
        state.config.federation.max_links as usize,
    ));
    let drop_log = Arc::new(DropRateLimiter::new());

    loop {
        let (tcp, peer_addr) = match listener.accept_raw().await {
            Ok(pair) => pair,
            Err(e) => {
                // An OS-level accept failure (e.g. the process is out of file descriptors) —
                // distinct from, and rarer than, a per-connection handshake failure below. Still
                // must not take the loop down.
                eprintln!("federation: accept() failed: {e}");
                continue;
            }
        };

        let Ok(handshake_permit) = handshake_slots.clone().try_acquire_owned() else {
            // No free handshake slot: drop the raw connection outright (never even reaches the TLS
            // acceptor) rather than queue it — queueing would just move the same unbounded-wait
            // problem this task exists to close from "the accept loop blocks" to "an unbounded
            // number of connections sit half-open waiting for a slot".
            drop(tcp);
            drop_log.note_drop("handshake capacity");
            continue;
        };

        let listener = listener.clone();
        let state = state.clone();
        let link_slots = link_slots.clone();
        let drop_log = drop_log.clone();

        tokio::spawn(async move {
            let handshake_result = crate::federation::link::with_deadline(
                handshake_timeout,
                listener.finish_handshake(tcp, peer_addr),
            )
            .await;
            // Release the handshake slot the instant the handshake step is over, success or not —
            // it must never be held for the link's full (potentially very long) subsequent
            // lifetime, which is exactly what the separate link semaphore below is for.
            drop(handshake_permit);

            let (link, _peer_addr) = match handshake_result {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    eprintln!("federation: rejected an inbound s2s connection attempt: {e}");
                    return;
                }
                Err(_deadline_exceeded) => {
                    eprintln!(
                        "federation: inbound s2s handshake exceeded its {handshake_timeout:?} \
                         deadline; dropping the connection"
                    );
                    return;
                }
            };

            let Ok(link_permit) = link_slots.try_acquire_owned() else {
                drop_log.note_drop("established-link capacity");
                drop(link); // closes the TLS connection (Drop on the underlying stream)
                return;
            };

            serve_link(link, state).await;
            drop(link_permit);
        });
    }
}

/// Convenience combining [`bind_federation`] + [`run_federation`] for callers (`main.rs`) that
/// don't need the intermediate bound address. Never returns on success; returns `Err` only if the
/// initial bind itself fails.
pub async fn serve_federation(state: Arc<AppState>) -> Result<(), LinkError> {
    let listener = bind_federation(&state).await?;
    run_federation(listener, state).await;
    Ok(())
}
