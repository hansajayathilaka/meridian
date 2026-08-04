//! Server B's inbound handling of federated requests (task 2.7: `fed_fetch_bundle`; task 2.8 adds
//! `fed_route`/`fed_reachability` to the same [`serve_link`] dispatch loop).
//!
//! ## `origin_domain` is always the mTLS-authenticated peer identity
//! Every function here takes `origin_domain` as an explicit `&str` parameter rather than reading
//! it off the request body. Callers MUST pass [`FederationLink::peer_domain`] — the
//! TLS-certificate-derived identity established when the link was accepted — never
//! `FedFetchBundle::requesting_server` (self-asserted, informational only; see
//! `meridian_proto::fed`'s module docs and ADR 0017 (a)). [`serve_link`] is the one place that
//! makes this binding, so nothing downstream of it can accidentally key a policy/rate-limit
//! decision off attacker-controlled bytes.
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
    origin_domain: &str,
    req: &FedFetchBundle,
) -> Result<FedBundle, FedErr> {
    if let Decision::Reject(_reason) = policy.admit(origin_domain) {
        // `_reason` (Closed vs. NotAllowlisted) is internal detail only — see `policy` module's
        // doc comment on the 2.7/2.8/2.9 boundary. Both collapse to the same client-visible code.
        return Err(FedErr {
            code: fed_error_codes::POLICY_DENIED.to_string(),
            msg: "federation is closed for this origin".to_string(),
        });
    }
    // See this module's doc comment: `req.target`, not a requesting-account field that doesn't
    // exist on this request type, is the per-account rate-limit dimension for a fetch.
    if let Decision::Reject(_reason) = limits.check_fetch(origin_domain, req.target.as_slice()) {
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
/// connection and enqueued onto it) is deliberately discarded below, not just in the disconnect-race
/// sense: this also silently swallows an outbound-side delivery failure at B (e.g. a full mpsc
/// channel to a slow client) exactly as it swallows a target that disconnected between
/// `route_foreign`'s `reachable_foreign` pre-check (architect decision #3) and this call. Neither
/// path is reported back across the federation boundary — `route_foreign`'s pre-check is what a
/// caller relies on for target liveness, not this call's outcome. Both are the same accepted
/// residual, not a new error this function invents a code for: see this task's "Out: offline
/// queuing" scope boundary (a defined error at fed_route time, never a queue).
pub async fn handle_fed_route(
    registry: &Registry,
    policy: &FederationPolicy,
    limits: &FederationLimits,
    origin_domain: &str,
    req: &FedRoute,
) -> Result<(), FedErr> {
    if let Decision::Reject(_reason) = policy.admit(origin_domain) {
        return Err(FedErr {
            code: fed_error_codes::POLICY_DENIED.to_string(),
            msg: "federation is closed for this origin".to_string(),
        });
    }
    if let Decision::Reject(_reason) = limits.check_route(origin_domain, req.from.as_slice()) {
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
    let out = FedFrame::new(FedOp::Route, 0, req).map_err(|_| FedErr {
        code: fed_error_codes::BAD_REQUEST.to_string(),
        msg: "malformed fed_route body".to_string(),
    })?;
    let encoded_len = out
        .to_bytes()
        .map_err(|_| FedErr {
            code: fed_error_codes::BAD_REQUEST.to_string(),
            msg: "malformed fed_route body".to_string(),
        })?
        .len();
    if encoded_len > MAX_FRAME_LEN {
        return Err(FedErr {
            code: fed_error_codes::BAD_REQUEST.to_string(),
            msg: "envelope too large to route".to_string(),
        });
    }

    let deliver = Deliver {
        from: req.from,
        blob: req.envelope.clone(),
    };
    let bytes = Frame::new(Op::Deliver, 0, &deliver)
        .and_then(|f| f.to_bytes())
        .map_err(|_| FedErr {
            code: fed_error_codes::BAD_REQUEST.to_string(),
            msg: "encode failed".to_string(),
        })?;
    // Result intentionally discarded (see doc comment above): whether the target was connected is
    // not reported back across the federation boundary.
    let _ = registry.send_to(&req.to, Message::Binary(bytes));
    Ok(())
}

/// Server B's inbound `fed_reachability` handler (task 2.8): origin admission, then the same
/// rate-limit machinery as [`handle_fed_route`] but keyed on `req.target` (architect decision #3
/// — `FedReachability` carries no `from` field, the same deliberate reading
/// `handle_fed_fetch` already established for `FedFetchBundle`), then EXACTLY
/// `FedReachable{connected}` — no other branch, ever. `Registry::is_connected` already returns
/// `false` identically whether `target` never registered or registered-then-disconnected (see
/// [`Registry`]'s own doc comment); there is no separate existence check here to leak, and this
/// function must never grow one. Nothing on this path is logged or persisted: `registry` is an
/// in-memory `Registry` lookup only, and this module (like `federation::policy`) adds no
/// `tracing`/`println!`-style logging at all.
pub async fn handle_fed_reachability(
    registry: &Registry,
    policy: &FederationPolicy,
    limits: &FederationLimits,
    origin_domain: &str,
    req: &FedReachability,
) -> Result<FedReachable, FedErr> {
    if let Decision::Reject(_reason) = policy.admit(origin_domain) {
        return Err(FedErr {
            code: fed_error_codes::POLICY_DENIED.to_string(),
            msg: "federation is closed for this origin".to_string(),
        });
    }
    if let Decision::Reject(_reason) = limits.check_route(origin_domain, req.target.as_slice()) {
        return Err(FedErr {
            code: fed_error_codes::RATE_LIMITED.to_string(),
            msg: "too many federated reachability requests".to_string(),
        });
    }
    Ok(FedReachable {
        connected: registry.is_connected(&req.target),
    })
}

/// Serve one already-established inbound [`FederationLink`] until it closes or errors: read
/// frames, dispatch by [`FedOp`], reply. `FedOp::FetchBundle` (2.7), `FedOp::Route` and
/// `FedOp::Reachability` (2.8 — `Hello` is already consumed by link establishment) are handled;
/// every other/unknown op still replies `FedErr{bad_request}`.
pub async fn serve_link(mut link: FederationLink, state: Arc<AppState>) {
    // `link.peer_domain` is the mTLS-authenticated identity (see this module's doc comment) —
    // captured once, used for every request on this link, never re-derived from a request body.
    let origin_domain = link.peer_domain.clone();
    loop {
        let frame = match link.recv_frame().await {
            Ok(f) => f,
            Err(_) => return, // link closed or errored — nothing more to serve
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
                    &origin_domain,
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
                    &origin_domain,
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
                    &origin_domain,
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

/// Accept inbound federation links forever, spawning [`serve_link`] per accepted link. A single
/// failed accept (a peer that dropped mid-handshake, a bad cert, ...) logs to stderr and continues
/// — it must not take the whole listener down.
pub async fn run_federation(listener: FederationListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((link, _peer_addr)) => {
                let st = state.clone();
                tokio::spawn(async move { serve_link(link, st).await });
            }
            Err(e) => {
                eprintln!("federation: rejected an inbound s2s connection attempt: {e}");
            }
        }
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
