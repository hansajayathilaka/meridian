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

use meridian_proto::{fed_error_codes, FedBundle, FedErr, FedFetchBundle, FedFrame, FedOp};

use crate::federation::link::LinkError;
use crate::federation::policy::{Decision, FederationLimits, FederationPolicy};
use crate::federation::{FederationLink, FederationListener};
use crate::state::AppState;
use crate::store::Store;

/// Server B's inbound `fed_fetch_bundle` handler: origin admission (2.6), then the
/// per-origin/per-origin-account rate limits (2.6), then an exact-key store lookup — the federated
/// mirror of `ws::handle_fetch`'s local path, minus anything socket-shaped (this function never
/// touches a client connection; [`serve_link`] is what talks to the wire on both sides).
pub async fn handle_fed_fetch(
    store: &dyn Store,
    policy: &FederationPolicy,
    limits: &FederationLimits,
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
        Ok(Some(bundle)) => Ok(FedBundle { bundle }),
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

/// Serve one already-established inbound [`FederationLink`] until it closes or errors: read
/// frames, dispatch by [`FedOp`], reply. Only `FedOp::FetchBundle` is handled in this task (2.7);
/// every other op (`Route`, `Reachability` — `Hello` is already consumed by link establishment)
/// replies `FedErr{bad_request}` for now — task 2.8 replaces that fallback arm with real handling,
/// it does not change this function's `FetchBundle` arm.
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
            _ => {
                // FedOp::Route / FedOp::Reachability (2.8) and any other/unknown op: not yet
                // implemented at this layer. Fail closed with a structured error rather than
                // silently dropping the frame — the peer's request gets a defined reply either way.
                let _ = reply_fed_err(
                    &mut link,
                    frame.id,
                    fed_error_codes::BAD_REQUEST,
                    "operation not supported by this server yet",
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
