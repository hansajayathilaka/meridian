//! Server A's outbound dial-out path: resolve a hint domain, dial the peer's s2s mTLS listener,
//! speak one `fed_fetch_bundle` request/reply, and hand the reply back as-is (task 2.7; task 2.8
//! adds `route_foreign`/`reachable_foreign` to this same module).
//!
//! ## Dependency-trap note (see this task's Risks — non-negotiable)
//! [`fetch_foreign_bundle`] decodes the reply frame's CBOR body into [`FedBundle`] — a
//! `meridian-proto` type, the same crate this server already depends on and already decodes
//! [`meridian_proto::PrekeyBundle`] from for a purely local fetch (`ws::handle_fetch`). That is
//! structural CBOR parsing, not cryptographic verification, and it is unavoidable: something has to
//! turn the wire bytes into a value `ws.rs` can re-wrap as a client-facing `Bundle` frame. What this
//! function MUST NOT do — and does not — is call `meridian_signaling::verify_bundle` or anything
//! like it: that function lives in `meridian-signaling`, which pulls in `meridian-identity` and
//! `meridian-store`, and importing it here would both break `tools/lint-server-no-core.sh` and be
//! architecturally wrong (system-design.md §3.3 step 4 puts verification at the client; a bug in
//! server-side verification could mask a real substitution attack mounted by the foreign server,
//! defeating client-side trust anchoring). `meridian-signaling` is not, and must never become, a
//! dependency of this crate — see `apps/rendezvous/Cargo.toml`'s own invariant comment.
//!
//! Because `PrekeyBundle`'s CBOR encoding is deterministic (ciborium; no map-ordering
//! nondeterminism, `apps/proto/CLAUDE.md`), decoding then re-encoding the *same* value round-trips
//! to byte-identical output — so the client-visible bytes end up identical to what B's store held,
//! without this server needing to smuggle raw, unparsed bytes through `ws.rs`'s existing
//! `Bundle{bundle: PrekeyBundle}` response shape.

use std::net::SocketAddr;
use std::time::Duration;

use meridian_proto::{
    FedBundle, FedErr, FedFetchBundle, FedFrame, FedOp, FedReachability, FedReachable, FedRoute,
    OpaqueBlob,
};

use crate::federation::discovery::{DiscoveryError, Endpoint};
use crate::federation::link::{self, FederationLink, LinkError};
use crate::federation::policy::Decision;
use crate::state::AppState;

/// Everything that can go wrong resolving/dialing/speaking to a foreign server on the outbound
/// fetch path. Distinguished from [`FedErr`] (a reply the FOREIGN server sent us) so `ws.rs` can
/// tell "we couldn't even talk to org-b" (`fed_unreachable`) apart from "org-b answered and said
/// no" (`fed_denied` / `rate_limited` / `not_found_at_hint`, decoded from the `Fed` variant).
#[derive(Debug, thiserror::Error)]
pub enum FetchForeignError {
    /// This server has no federation configured at all (`federation.enabled = false`, or
    /// discovery otherwise unavailable) — never even attempted a lookup.
    #[error("federation is not enabled on this server")]
    NotConfigured,
    /// [`crate::federation::Discovery::resolve`] failed: the hint domain has no known endpoint.
    #[error("resolving {domain:?}: {source}")]
    Discovery {
        domain: String,
        #[source]
        source: DiscoveryError,
    },
    /// Turning a resolved [`Endpoint`]'s `host:port` into a socket address failed (DNS failure for
    /// the *dial* target — distinct from discovery's own domain-to-endpoint resolution).
    #[error("resolving dial address {host}:{port}: {source}")]
    AddrResolution {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    /// [`link::dial`] failed: TLS handshake, certificate-identity mismatch, or a plain connection
    /// failure.
    #[error("dialing {domain:?}: {source}")]
    Dial {
        domain: String,
        #[source]
        source: LinkError,
    },
    /// The foreign server answered with a structured [`FedErr`] (policy/rate-limit/not-found).
    #[error("peer server declined: [{}] {}", .0.code, .0.msg)]
    Fed(FedErr),
    /// Anything else that broke the request/reply exchange itself (encode/decode failure, an
    /// unexpected `FedOp` in the reply).
    #[error("federation protocol error: {0}")]
    Protocol(String),
    /// This server's OWN outbound federation admission policy (`state.federation.policy`)
    /// rejected `hint_domain` before [`dial_foreign`] ever attempted discovery or a dial — task
    /// 3.1 (review finding F1). Distinct from [`FetchForeignError::Fed`]: `Fed` means a FOREIGN
    /// server dialed successfully and then declined; `Denied` means THIS server refused to dial at
    /// all.
    #[error("federation policy denies dialing this domain")]
    Denied,
}

/// Server A's outbound path for a client's `Fetch{target, hint}` naming a foreign account: resolve
/// `hint_domain` via [`crate::federation::Discovery`], dial the resolved [`Endpoint`], and speak
/// one `fed_fetch_bundle` request/reply over a fresh [`crate::federation::FederationLink`].
///
/// **Non-negotiable (inherited from task 2.5's security review):** the peer identity the dial
/// pins its handshake to is `Endpoint::pinned_identity` when `Some` (private-CA / air-gap mode,
/// ADR 0017 C4) — **never** `hint_domain` in that mode. Falling back to `hint_domain` whenever a
/// pin is configured would collapse private-CA mode to ADR 0017 (a)'s rejected "Option A": under a
/// shared private CA, any org enrolled under that CA can present a certificate whose SAN matches
/// any domain string a caller merely *hoped* to reach, so the self-asserted hint alone is not a
/// trust boundary there. In WebPKI mode (`pinned_identity: None`, the common case), `hint_domain`
/// itself is the correct — and only available — verification target. This pinning logic lives in
/// exactly one place, [`dial_foreign`], reused here via [`convert_dial_error`] rather than
/// duplicated (code-reviewer finding, task 2.8: two independent copies of this security-sensitive
/// logic would let a future pinning fix land in only one).
pub async fn fetch_foreign_bundle(
    state: &AppState,
    hint_domain: &str,
    target: [u8; 32],
) -> Result<FedBundle, FetchForeignError> {
    let (mut fed_link, expected_domain) = dial_foreign(state, hint_domain)
        .await
        .map_err(convert_dial_error)?;

    let req = FedFetchBundle {
        target,
        requesting_server: state.federation.own_domain.clone(),
    };
    let out = FedFrame::new(FedOp::FetchBundle, 1, &req)
        .map_err(|e| FetchForeignError::Protocol(e.to_string()))?;
    // Task 3.3 (F3): bounded under `state.federation.timeouts.request` — a foreign server that
    // completed `FedHello` but never reads/answers this request can no longer hang this call, or
    // this connection's server-side task, forever.
    let request_timeout = state.federation.timeouts.request;
    with_request_deadline(request_timeout, &expected_domain, fed_link.send_frame(&out))
        .await
        .map_err(convert_dial_error)?;

    let reply = with_request_deadline(request_timeout, &expected_domain, fed_link.recv_frame())
        .await
        .map_err(convert_dial_error)?;

    match reply.op {
        FedOp::Bundle => reply
            .decode::<FedBundle>()
            .map_err(|e| FetchForeignError::Protocol(e.to_string())),
        FedOp::Err => {
            let err: FedErr = reply
                .decode()
                .map_err(|e| FetchForeignError::Protocol(e.to_string()))?;
            Err(FetchForeignError::Fed(err))
        }
        other => Err(FetchForeignError::Protocol(format!(
            "unexpected fed op in fetch reply: {other:?}"
        ))),
    }
}

/// [`dial_foreign`] returns [`RouteForeignError`] (it's shared with [`route_foreign`]/
/// [`reachable_foreign`]), but [`fetch_foreign_bundle`] speaks [`FetchForeignError`] — this maps
/// the variants the two types actually share. `dial_foreign` never itself produces
/// `EnvelopeTooLarge` or `TargetUnreachable` (both are 2.8-specific, constructed only by
/// `route_foreign`'s own oversized/pre-check logic, never by the shared dial path) or `Fed`
/// (`dial_foreign` never sends a request, so nothing can reply) — those three arms are
/// structurally unreachable here, not merely assumed to be. `Denied` (task 3.1), by contrast, IS
/// producible by `dial_foreign` itself (its choke-point policy check) and so gets a real mapped
/// arm below, not folded into the `unreachable!()` group.
fn convert_dial_error(e: RouteForeignError) -> FetchForeignError {
    match e {
        RouteForeignError::NotConfigured => FetchForeignError::NotConfigured,
        RouteForeignError::Discovery { domain, source } => {
            FetchForeignError::Discovery { domain, source }
        }
        RouteForeignError::AddrResolution { host, port, source } => {
            FetchForeignError::AddrResolution { host, port, source }
        }
        RouteForeignError::Dial { domain, source } => FetchForeignError::Dial { domain, source },
        RouteForeignError::Denied => FetchForeignError::Denied,
        RouteForeignError::EnvelopeTooLarge { .. }
        | RouteForeignError::TargetUnreachable
        | RouteForeignError::Fed(_) => {
            unreachable!("dial_foreign never constructs {e:?}")
        }
        RouteForeignError::Protocol(msg) => FetchForeignError::Protocol(msg),
    }
}

// -------------------------------------------------------------------------------------------
// task 2.8: route_foreign / reachable_foreign
// -------------------------------------------------------------------------------------------

/// Everything that can go wrong resolving/dialing/speaking to a foreign server on the outbound
/// route or reachability path. Mirrors [`FetchForeignError`]'s shape (a distinct type, not a
/// reuse, per this task's precedent) so `ws.rs` can tell "we couldn't even talk to org-b"
/// (`fed_unreachable`) apart from "org-b answered and said no" (`fed_denied` / `rate_limited`,
/// decoded from the `Fed` variant) apart from the target-liveness axis
/// ([`RouteForeignError::TargetUnreachable`], decision #3 — see `ws.rs::federated_route_error_reply`
/// for the full client-visible mapping).
#[derive(Debug, thiserror::Error)]
pub enum RouteForeignError {
    /// This server has no federation configured at all — never even attempted a lookup.
    #[error("federation is not enabled on this server")]
    NotConfigured,
    /// [`crate::federation::Discovery::resolve`] failed: the hint domain has no known endpoint.
    #[error("resolving {domain:?}: {source}")]
    Discovery {
        domain: String,
        #[source]
        source: DiscoveryError,
    },
    /// Turning a resolved [`Endpoint`]'s `host:port` into a socket address failed.
    #[error("resolving dial address {host}:{port}: {source}")]
    AddrResolution {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    /// [`link::dial`] (or a send/recv on an already-established link) failed: TLS handshake,
    /// certificate-identity mismatch, or a plain connection failure.
    #[error("dialing {domain:?}: {source}")]
    Dial {
        domain: String,
        #[source]
        source: LinkError,
    },
    /// Architect decision #1: the encoded [`FedFrame`] this call would send exceeds
    /// [`link::MAX_FRAME_LEN`] — rejected here, before ever dialing, rather than letting the
    /// link-level `FrameTooLarge` I/O error do the job.
    #[error("encoded route envelope of {len} bytes exceeds the federation frame size limit")]
    EnvelopeTooLarge { len: usize },
    /// Architect decision #3: [`route_foreign`]'s own [`reachable_foreign`] pre-check did not
    /// come back with a confirmed `connected: true` — either it answered `connected: false`, or
    /// the pre-check itself failed for any reason (any other variant of this same enum,
    /// including a pre-check dial failure). Every one of those causes collapses to this single
    /// variant so that "target unknown," "target known-offline," and "the reachability check
    /// itself failed" are indistinguishable to a caller — `ws.rs` maps this, and only this, to
    /// the same `error_codes::NOT_CONNECTED` a local offline recipient already produces. This is
    /// the anti-existence-oracle requirement: nothing here or in `ws.rs` may branch further on
    /// *why* the pre-check didn't confirm liveness.
    #[error("target is not confirmed reachable at the foreign server")]
    TargetUnreachable,
    /// The foreign server answered with a structured [`FedErr`] (policy/rate-limit/malformed) —
    /// only reachable for the actual `fed_route`/`fed_reachability` round trip itself, never for
    /// the internal pre-check (folded into [`RouteForeignError::TargetUnreachable`] above).
    #[error("peer server declined: [{}] {}", .0.code, .0.msg)]
    Fed(FedErr),
    /// Anything else that broke the request/reply exchange itself (encode/decode failure, an
    /// unexpected `FedOp` in the reply).
    #[error("federation protocol error: {0}")]
    Protocol(String),
    /// This server's OWN outbound federation admission policy (`state.federation.policy`)
    /// rejected `hint_domain` before [`dial_foreign`] ever attempted discovery or a dial — task
    /// 3.1 (review finding F1: a client naming an arbitrary foreign domain must not be able to
    /// force this server to resolve DNS for, or open a TCP connection to, that domain when this
    /// server's own policy is `closed`/`allowlist` and doesn't admit it — even a DNS lookup alone
    /// is an SSRF/internal-port-probe oracle). Distinct from [`RouteForeignError::Fed`]: `Fed`
    /// means a FOREIGN server dialed successfully and then declined; `Denied` means THIS server
    /// refused to dial at all.
    #[error("federation policy denies dialing this domain")]
    Denied,
}

/// How long [`route_foreign`] waits, after sending a `FedRoute`, for a possible `FedErr` reply
/// before treating the wire protocol's documented "fire-and-forget on success" (no reply frame at
/// all — federation-protocol-v1.md §2) as exactly what it says: silent success. `FedOp::Route`
/// deliberately has no `FedRouteOk` (same doc, "do not add one") — given that already-landed,
/// binding wire decision, a bounded wait is the only available way to turn "nothing else is
/// coming" into a return value in finite time; it is not an invented deviation from the protocol.
///
/// **`pub`, not merely crate-private:** so `apps/rendezvous/tests/federation_route.rs`'s boundary
/// test (task 3.20) can size its injected delay relative to this constant's REAL value instead of
/// hand-duplicating the number — a copy would silently drift the day this value changes again.
///
/// **Measured (task 3.20), not guessed — this is the follow-up task 2.8's residual note (below)
/// named.** `apps/rendezvous/tests/federation_route.rs::measure_route_reply_rtt_distribution`
/// times exactly the span this constant bounds — from finishing the `FedRoute` write to finishing
/// the `FedErr` read — over the SAME two-real-server-over-real-mTLS harness every test in that file
/// uses, one link dialed once and reused for every sample (so dial/TLS cost is never in the
/// numbers), against a `Closed`-policy B whose `handle_fed_route` rejects on its very first,
/// purely in-process check (no rate limiter, no registry lookup) — i.e. the exact "B's processing
/// cost is ~0, wire RTT is what dominates" case the residual note below describes. N=200 samples,
/// taken **after** both of this constant's stated dependencies (task 3.3's timeout framework, task
/// 3.7's link-reuse-per-message change) had already landed, per this task's own Risk note:
///
/// ```text
/// min=87.1ms  p50=88.0ms  mean=88.1ms  p95=88.2ms  p99=92.1ms  max=92.9ms
/// ```
///
/// **This is surprising — not "sub-millisecond loopback" — and the reason is a real, separate
/// finding, recorded here rather than silently folded into the constant alone:** neither
/// [`dial`](crate::federation::link::dial) nor
/// [`FederationListener::bind`](crate::federation::link::FederationListener::bind) ever sets
/// `TCP_NODELAY` on the underlying `TcpStream`, so `link.rs`'s `write_frame` — which issues two
/// separate `write_all` calls per frame (the 4-byte length prefix, then the CBOR body) before one
/// `flush` — lets Nagle's algorithm hold the second write back waiting for the first's ACK, which
/// the peer's own delayed-ACK timer (a standard OS TCP behavior, commonly ~40ms) doesn't send
/// promptly either; two such frames crossing (the `FedRoute` request, the `FedErr` reply) compound
/// into the ~87–93ms floor measured above even on loopback, where physical transit time is
/// negligible. This is a genuine property of the CURRENT implementation, not measurement noise —
/// the near-zero spread (min to p99 is under 6ms) is consistent with a fixed protocol-level
/// interaction, not queuing/scheduling jitter. Fixing it (a `set_nodelay(true)` call in `link.rs`)
/// is out of this task's file-scope (`outbound.rs`/`federation_route.rs`/
/// `federation-protocol-v1.md` only) and is left as a `TODO: confirm`-style follow-up, not
/// something this task's Scope covers — but it directly explains why this measurement is tens of
/// milliseconds, not fractions of one, and why the tightened value below already has to budget for
/// it as a standing cost of THIS implementation, independent of physical network distance.
///
/// **Residual, recorded rather than silently accepted (architect + security-reviewer + code-reviewer,
/// task 2.8; re-measured and re-justified, not closed, by task 3.20):** two failure directions are
/// in tension: (a) too short risks a genuine policy/rate-limit rejection arriving after the window
/// elapses under real packet loss/congestion, which `route_foreign` would then report as success —
/// a false-positive delivery confirmation, strictly worse than a false negative; (b) every
/// SUCCESSFUL federated route pays this as a fixed latency tax, since the happy path is only ever
/// detected by the wait running to completion, never by an explicit ack. Because (a) is the
/// strictly worse direction, this tightening is deliberately conservative rather than aggressive:
/// round the measured max (92.9ms) up to 100ms, then apply a 3× real-network-headroom multiplier —
/// this measurement is same-host loopback; a real cross-org federation link (ADR 0002's bilateral
/// model has no geographic restriction) legitimately adds real WAN RTT and congestion on top of the
/// fixed Nagle/delayed-ACK cost documented above, which this measurement cannot capture — giving
/// **300ms**. That is a real, measured 40% reduction in the latency tax every successful federated
/// route pays (direction (b)) relative to the original unmeasured 500ms guess, while still keeping
/// **over 3.2× the measured max** — comfortably more headroom over a real reply than
/// `request_timeout_ms`'s own "TLS handshake + `FedHello` + one round trip" budget keeps over ITS
/// components (see that field's doc comment) — for direction (a). It does **not** close the
/// residual outright: a `FedErr` that is genuinely in flight but crosses the wire slower than
/// 300ms (real congestion, an overloaded peer, a slow path) is still reported as success — see
/// `apps/rendezvous/tests/federation_route.rs::fed_err_delayed_past_route_reply_grace_is_still_reported_as_false_success`,
/// the boundary test task 2.8's own residual note asked for and task 3.20 delivers, which pins
/// this exact behavior at the new value. Closing it outright needs
/// federation-protocol-v1.md's "do not add a `FedRouteOk`" decision reopened — a protocol revision
/// via an ADR, the architect reviewer's call, not a unilateral change here (task 3.20's own Scope
/// "Out" boundary) — so it stays a documented, measured, bounded residual rather than an
/// unmeasured, unbounded one.
pub const ROUTE_REPLY_GRACE: Duration = Duration::from_millis(300);

/// Resolve `hint_domain` and dial the FIRST candidate [`Endpoint`] that succeeds, exactly as
/// [`fetch_foreign_bundle`] does (same discovery lookup, same `pinned_identity`-over-`hint_domain`
/// pin — see that function's doc comment for the non-negotiable reasoning), factored out here
/// because [`route_foreign`] and [`reachable_foreign`] both need a fresh one-shot link and share
/// [`RouteForeignError`] as their error type.
///
/// **Task 3.7 (N2, SRV failover):** `discovery.resolve` can return more than one candidate
/// [`Endpoint`] — `SrvDiscovery` sorts them by RFC 2782 priority ascending, then weight descending
/// (`SrvDiscovery::resolve`'s doc comment); `StaticMap` always returns exactly one, so this loop
/// degrades to the old single-candidate behavior there with no change in observable behavior. This
/// tries each candidate, in the order `resolve` already returned (never re-sorted here), falling
/// through to the next on ANY failure — address resolution or the dial itself (TCP/TLS/`FedHello`)
/// — rather than giving up after the first. Only once every candidate has been tried and failed is
/// an `Err` returned, carrying whichever failure the LAST candidate produced (arbitrary among
/// possibly-differing per-candidate failures, but no caller today branches on that — see
/// `RouteForeignError`'s own doc comments on what `ws.rs` does with each variant).
///
/// **Domain pin, per candidate (task 3.7's Risk note — security-critical, do not relax):**
/// `expected_domain` is computed FRESH for every candidate, from THAT candidate's own
/// `pinned_identity` — never reused from an earlier failed candidate, never widened to "any
/// domain" merely because earlier candidates failed. The mTLS handshake's certificate validation
/// against `expected_domain` (`link::dial`) still runs in full for every candidate dialed, exactly
/// as it did for the single-candidate path this replaces — a compromised or merely misconfigured
/// second SRV target still has to present a certificate for the SAME intended domain (or pinned
/// identity) as the first, or its dial fails exactly like any other domain mismatch.
async fn dial_foreign(
    state: &AppState,
    hint_domain: &str,
) -> Result<(FederationLink, String), RouteForeignError> {
    // `NotConfigured` first, ahead of the SSRF choke point below: both are zero-I/O checks (no
    // discovery call, no DNS lookup, no TCP dial either way), so ordering them this way costs
    // nothing on the SSRF closure. It does keep `fetch_foreign_bundle` (which has no guard of its
    // own and relies entirely on this one) consistent with `route_foreign` (which has its own
    // early `discovery.is_none()` guard, `outbound.rs` `route_foreign`, before it ever reaches
    // here) about which error a client sees when federation is simply switched off vs. actively
    // refusing a domain: `fed_unreachable` ("not configured"), never `fed_denied` ("policy
    // refuses"), when there is no policy decision to report at all.
    let discovery = state
        .federation
        .discovery
        .as_deref()
        .ok_or(RouteForeignError::NotConfigured)?;

    // SSRF choke point (task 3.1, review finding F1) — the first statement to touch discovery or
    // dial, before any discovery call, DNS lookup, or TCP dial. Even a DNS lookup alone is an
    // oracle: a client that can name an arbitrary foreign domain and observe "resolved" vs.
    // "didn't resolve"/"connection refused" vs. "connection timed out" can probe this server's
    // internal DNS visibility and network reachability (including internal, non-federation ports)
    // regardless of whether the domain is an actual federation partner. `state.federation.policy`
    // is this server's OWN admission policy — the identical `FederationPolicy` value
    // `federation::inbound`'s handlers (`handle_fed_fetch`/`handle_fed_route`/
    // `handle_fed_reachability`) already consult for the INBOUND direction. Federation admission
    // is symmetric (ADR 0002's bilateral federation model, ADR 0017): a `closed`/`allowlist`
    // server refuses a non-admitted domain in either direction, not merely when that domain dials
    // in.
    if let Decision::Reject(_reason) = state.federation.policy.admit(hint_domain) {
        // `_reason` (Closed vs. NotAllowlisted) is internal detail only — mirrors
        // `federation::inbound`'s identical discard of the same `Decision::Reject` payload (see
        // `policy` module's doc comment on the 2.7/2.8/2.9 boundary this task inherits). Both
        // collapse to the same client-visible `fed_denied` code in `ws.rs`; leaking WHY would
        // itself tell a client whether this server even has an allowlist, let alone what's on it.
        return Err(RouteForeignError::Denied);
    }

    let endpoints =
        discovery
            .resolve(hint_domain)
            .await
            .map_err(|source| RouteForeignError::Discovery {
                domain: hint_domain.to_string(),
                source,
            })?;

    // Task 3.7 (F10): the outbound `ClientConfig` is built once at startup
    // (`state::FederationRuntime::client_tls`) and reused across every candidate dialed here —
    // `link::dial` itself does no filesystem I/O or cert/key parsing anymore. `discovery.is_some()`
    // (checked above) and `client_tls.is_some()` are always built together, in the same
    // `if config.federation.enabled` branch of `build_federation_runtime`, so this can never
    // observe federation enabled with no cached TLS config.
    let client_tls = state.federation.client_tls.clone().expect(
        "state.federation.discovery.is_some() (checked above) implies client_tls is also Some — \
         both are built together in build_federation_runtime only when federation.enabled",
    );

    // `Discovery::resolve`'s own contract (see its doc comment) never returns `Ok(vec![])` — a
    // domain with no usable endpoint is always an `Err` before this point — so `endpoints` is
    // non-empty and this loop always runs at least once; `last_err` is populated by the first
    // iteration and this `Option` wrapper exists only so the compiler can see a value on every
    // path, not because a genuinely-empty `endpoints` is expected in practice.
    let mut last_err: Option<RouteForeignError> = None;
    for endpoint in endpoints {
        let expected_domain = endpoint
            .pinned_identity
            .as_deref()
            .unwrap_or(hint_domain)
            .to_string();

        let addr = match resolve_dial_addr(&endpoint).await {
            Ok(addr) => addr,
            Err(source) => {
                last_err = Some(RouteForeignError::AddrResolution {
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                    source,
                });
                continue;
            }
        };

        // Task 3.3 (F3): `dial` itself bounds its own connect/TLS/hello steps against
        // `state.federation.timeouts` — see `link::dial`'s doc comment. A black-holed candidate
        // (accepts TCP, then silence; or completes TLS+FedHello, then never answers a later
        // request) can no longer hang this call, and thus never leaks the task awaiting it,
        // forever — it simply counts as this candidate's failure and the loop moves on.
        match link::dial(
            addr,
            &expected_domain,
            client_tls.clone(),
            &state.federation.own_domain,
            Some(state.metrics.clone()),
            state.federation.timeouts,
        )
        .await
        {
            Ok(fed_link) => return Ok((fed_link, expected_domain)),
            Err(source) => {
                last_err = Some(RouteForeignError::Dial {
                    domain: expected_domain,
                    source,
                });
            }
        }
    }

    Err(last_err.unwrap_or_else(|| RouteForeignError::Discovery {
        domain: hint_domain.to_string(),
        source: DiscoveryError::NotFound(hint_domain.to_string()),
    }))
}

/// Await one outbound s2s exchange step (`send_frame`/`recv_frame`) over an already-established
/// [`FederationLink`] under `timeout`, folding a deadline expiry into the SAME
/// `RouteForeignError::Dial { source: LinkError::Timeout, .. }` shape a timed-out [`dial`] itself
/// would have produced (task 3.3, review finding F3) — so a caller downstream (`ws.rs`) cannot
/// distinguish "the connect/TLS/hello step timed out inside `dial`" from "the actual
/// fed_fetch_bundle/fed_reachability round trip itself timed out": both collapse to the identical
/// `Dial{..}` variant, which already maps to the client-visible `fed_unreachable` code — no new
/// error shape, and no new observable signal, for either failure mode.
///
/// Returns [`RouteForeignError`] (not [`FetchForeignError`]) even though [`fetch_foreign_bundle`]
/// is one of the two callers: `convert_dial_error`'s existing `Dial` mapping already handles this
/// exact shape, so `fetch_foreign_bundle` reuses it via `.map_err(convert_dial_error)` rather than
/// this function needing a second, near-identical copy.
async fn with_request_deadline<F, T>(
    timeout: std::time::Duration,
    expected_domain: &str,
    fut: F,
) -> Result<T, RouteForeignError>
where
    F: std::future::Future<Output = Result<T, LinkError>>,
{
    match link::with_deadline(timeout, fut).await {
        Ok(inner) => inner.map_err(|source| RouteForeignError::Dial {
            domain: expected_domain.to_string(),
            source,
        }),
        Err(link::DeadlineExceeded(duration)) => Err(RouteForeignError::Dial {
            domain: expected_domain.to_string(),
            source: LinkError::Timeout {
                phase: "request",
                duration,
            },
        }),
    }
}

/// Server A's outbound path for a client's `RouteBody{to, to_hint}` naming a foreign account:
/// resolve `hint_domain`, confirm liveness with an internal [`reachable_foreign`] pre-check (fail
/// fast on an offline target rather than after a full route round trip — architect decision #3),
/// then speak one `fed_route` request over a fresh [`FederationLink`].
///
/// **Envelope bytes are moved, never inspected.** `envelope` is carried into [`FedRoute::envelope`]
/// as an opaque [`OpaqueBlob`] and `from` is carried alongside it as routing metadata this server
/// asserts (ADR 0017 C1/C2) — this function does not decode, parse, or otherwise interpret
/// `envelope`'s contents, and cannot: that would need `meridian-envelope`, which this crate must
/// never depend on (`tools/lint-no-serde-on-blob.sh`).
///
/// **Oversized rejection is pre-dial** (architect decision #1): the real `FedFrame` this call
/// would send is built and measured against [`link::MAX_FRAME_LEN`] before any network I/O at
/// all, including before the reachability pre-check's own dial.
///
/// **Task 3.7 (review finding F10, single-link exchange):** this used to call
/// [`reachable_foreign`] for the reachability pre-check — which dialed its own, fresh
/// [`FederationLink`] internally — and THEN, if the pre-check confirmed `connected: true`, called
/// [`dial_foreign`] again for the actual `FedRoute`: two entirely separate TCP+TLS connections
/// (two mTLS handshakes) to the same peer for one logical routed message. This now dials
/// [`dial_foreign`] exactly ONCE and speaks both the `FedReachability` pre-check
/// ([`reachable_on_link`]) and (if confirmed reachable) the `FedRoute` itself, sequentially, over
/// that SAME link.
///
/// **TOCTOU note (task 3.7's Risk note, inherited from task 2.8):** narrowing to one dial per
/// message legitimately narrows — but does **not** close — the window task 2.8 already documented
/// between "confirmed reachable" and "actually routed": `to` can still disconnect from B in the
/// interval between the `FedReachable{connected: true}` reply and the `FedRoute` send below, even
/// though that interval is now bounded by one link's round-trip latency rather than two separate
/// dials' worth of connection setup. This function does not, and per task 3.7's scope cannot,
/// close that window outright.
pub async fn route_foreign(
    state: &AppState,
    hint_domain: &str,
    to: [u8; 32],
    from: [u8; 32],
    envelope: Vec<u8>,
) -> Result<(), RouteForeignError> {
    if state.federation.discovery.is_none() {
        return Err(RouteForeignError::NotConfigured);
    }

    let req = FedRoute {
        to,
        from,
        envelope: OpaqueBlob::new(envelope),
    };
    let out = FedFrame::new(FedOp::Route, 1, &req)
        .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
    let encoded = out
        .to_bytes()
        .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
    if encoded.len() > link::MAX_FRAME_LEN {
        return Err(RouteForeignError::EnvelopeTooLarge { len: encoded.len() });
    }

    // Task 3.7: the single dial this whole exchange now uses. A failure here — before we've even
    // learned whether `to` is reachable — gets exactly the same collapsing treatment the PRE-CHECK's
    // own (formerly separate) dial always got, per architect decision #3 below: `Denied` (this
    // server's own policy refusing to dial `hint_domain` at all) surfaces as itself, since it's the
    // identical axis as B declining outright (`Fed`, below); every other cause (discovery miss,
    // address resolution failure, TLS/connect failure across every SRV-failover candidate) collapses
    // into `TargetUnreachable` — this server genuinely could not determine `to`'s liveness, which is
    // indistinguishable, by design, from `to` simply being offline (the anti-existence-oracle
    // requirement this task inherits unchanged).
    let (mut fed_link, expected_domain) = match dial_foreign(state, hint_domain).await {
        Ok(pair) => pair,
        Err(RouteForeignError::Denied) => return Err(RouteForeignError::Denied),
        Err(_) => return Err(RouteForeignError::TargetUnreachable),
    };
    let request_timeout = state.federation.timeouts.request;

    // Architect decision #3: the pre-check's TARGET-LIVENESS outcome (offline, unknown, or a
    // connectivity/protocol failure that leaves liveness undetermined) collapses to
    // `TargetUnreachable` — never a distinct signal. This is deliberately NOT the same as B
    // *answering* the pre-check with a structured policy/rate-limit refusal
    // (`RouteForeignError::Fed`, e.g. `fed_denied`/`rate_limited`): that is B definitively
    // declining to engage at all, an orthogonal axis from target liveness, and must surface as
    // itself — collapsing a closed-policy answer into "recipient offline" would both hide a real
    // policy signal from the caller and contradict this task's own required behaviour ("closed
    // origin at B → fed_denied", not `not_connected`).
    match reachable_on_link(&mut fed_link, &expected_domain, to, request_timeout).await {
        Ok(true) => {}
        Ok(false) => return Err(RouteForeignError::TargetUnreachable),
        Err(RouteForeignError::Fed(fed_err)) => return Err(RouteForeignError::Fed(fed_err)),
        Err(_) => return Err(RouteForeignError::TargetUnreachable),
    }

    // From here on B is known-reachable (the exchange just above confirmed it over this same
    // link) — a failure sending/receiving the actual `FedRoute` now is a genuine "could not
    // complete the route right now" outcome, not a target-liveness signal, and surfaces as itself
    // (`fed_unreachable`), exactly as it did before this task when this was still a second,
    // independent dial.
    //
    // Task 3.3 (F3), review fix: bounded under `state.federation.timeouts.request` — same
    // treatment as `fetch_foreign_bundle`'s and `reachable_foreign`'s send/recv exchanges (see
    // `with_request_deadline`'s doc comment). Without this, a partner that completes real
    // mTLS+`FedHello` (i.e. is admitted by policy) and then never drains its TCP receive window
    // hangs this `write_all`/`flush` forever, leaking a pinned task plus TLS link on the path
    // that carries an actual authenticated user's routed envelope — exactly the failure mode this
    // task exists to close, just missed on this one call site in the original diff.
    with_request_deadline(request_timeout, &expected_domain, fed_link.send_frame(&out)).await?;

    // See `ROUTE_REPLY_GRACE`'s doc comment: `FedOp::Route` is fire-and-forget on success, so
    // "nothing arrived within a generous bound" IS the success outcome, not an error.
    match tokio::time::timeout(ROUTE_REPLY_GRACE, fed_link.recv_frame()).await {
        Ok(Ok(reply)) => match reply.op {
            FedOp::Err => {
                let err: FedErr = reply
                    .decode()
                    .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
                Err(RouteForeignError::Fed(err))
            }
            other => Err(RouteForeignError::Protocol(format!(
                "unexpected fed op in route reply: {other:?}"
            ))),
        },
        Ok(Err(source)) => Err(RouteForeignError::Dial {
            domain: expected_domain,
            source,
        }),
        Err(_elapsed) => Ok(()),
    }
}

/// The `fed_reachability` request/reply exchange itself — send `FedReachability`, await
/// `FedReachable`/`FedErr` — over an ALREADY-established [`FederationLink`]. Factored out of
/// [`reachable_foreign`] (task 3.7, review finding F10) so [`route_foreign`] can run this same
/// exchange on the ONE link it already dialed, instead of [`reachable_foreign`] dialing a second,
/// independent link purely for the pre-check. [`reachable_foreign`] itself is now a thin wrapper:
/// dial, then delegate here.
async fn reachable_on_link(
    fed_link: &mut FederationLink,
    expected_domain: &str,
    target: [u8; 32],
    request_timeout: Duration,
) -> Result<bool, RouteForeignError> {
    let req = FedReachability { target };
    let out = FedFrame::new(FedOp::Reachability, 1, &req)
        .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
    // Task 3.3 (F3): same bounded-wait treatment as `fetch_foreign_bundle`'s identical shape —
    // see `with_request_deadline`'s doc comment.
    with_request_deadline(request_timeout, expected_domain, fed_link.send_frame(&out)).await?;

    let reply =
        with_request_deadline(request_timeout, expected_domain, fed_link.recv_frame()).await?;

    match reply.op {
        FedOp::Reachable => {
            let r: FedReachable = reply
                .decode()
                .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
            Ok(r.connected)
        }
        FedOp::Err => {
            let err: FedErr = reply
                .decode()
                .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
            Err(RouteForeignError::Fed(err))
        }
        other => Err(RouteForeignError::Protocol(format!(
            "unexpected fed op in reachability reply: {other:?}"
        ))),
    }
}

/// Server A's outbound path for `fed_reachability`: resolve `hint_domain`, dial, and ask "is a
/// device for `target` connected right now?" — per-request only, never a subscription (system
/// design §3.4). Kept as its own `pub` entry point (task 3.7) for a caller that wants a standalone
/// reachability check with no follow-up route — [`route_foreign`]'s own internal pre-check (architect
/// decision #3) no longer calls this directly; it calls [`dial_foreign`] + [`reachable_on_link`]
/// itself instead, so its pre-check and its follow-up `FedRoute` share the one link
/// [`dial_foreign`] opens rather than each dialing independently. Nothing here makes this a new
/// client-visible c2s trigger.
///
/// **Task 3.5 + its review follow-up (review finding F4):** the request this sends is answered, on
/// B's side, by `federation::inbound::handle_fed_reachability`, which spends its own dedicated
/// `reachability_per_origin` budget — never `route_per_origin`/`per_origin_account` (the original
/// double-spend this task closed), and never fully unmetered either (the review-finding gap the
/// follow-up closed) — see that function's doc comment for the full accounting fix. Nothing on A's
/// side changes: this call still costs exactly one wire round trip, same as before.
pub async fn reachable_foreign(
    state: &AppState,
    hint_domain: &str,
    target: [u8; 32],
) -> Result<bool, RouteForeignError> {
    let (mut fed_link, expected_domain) = dial_foreign(state, hint_domain).await?;
    let request_timeout = state.federation.timeouts.request;
    reachable_on_link(&mut fed_link, &expected_domain, target, request_timeout).await
}

/// Resolve an [`Endpoint`]'s `host:port` to a concrete [`SocketAddr`] to dial. This is ordinary
/// hostname resolution for the s2s *dial target* (e.g. an internal-DNS service name in
/// `federation_map.toml`, per that file's own doc comment) — a different, unrelated DNS query from
/// `_meridian-fed._tcp` SRV discovery, and orthogonal to `StaticMap`'s "no lookup through this
/// crate's `SrvResolver` abstraction" air-gap claim (`federation::discovery` module docs): a
/// `federation_map.toml` `endpoint` naming a plain hostname always needed *some* host resolution to
/// ever be dialable at all.
async fn resolve_dial_addr(endpoint: &Endpoint) -> std::io::Result<SocketAddr> {
    tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no address found for {}:{}", endpoint.host, endpoint.port),
            )
        })
}

#[cfg(test)]
mod tests {
    //! Task 3.3 review follow-up (finding F3, blocking): a deterministic, no-real-socket proof
    //! that [`with_request_deadline`] genuinely bounds an indefinitely-pending send/recv future —
    //! complementing `tests/federation_timeouts.rs`'s
    //! `route_foreigns_outbound_send_is_wrapped_under_the_request_deadline`, which pins that
    //! [`route_foreign`]'s own outbound `send_frame` call is actually wrapped by this helper. That
    //! test proves the wrap is PRESENT; this one proves the wrap WORKS — together they cover what
    //! a live-socket integration test would have claimed to prove, without that test's vacuous-pass
    //! risk (see this crate's `tests/federation_timeouts.rs` module doc comment, case (d), for why
    //! a live-socket version of this specific assertion cannot reliably distinguish "wrapped" from
    //! "not wrapped" at all: a single envelope-sized `write_all` essentially never blocks at the
    //! syscall level on ordinary Linux TCP defaults, regardless of peer behavior).
    use super::*;

    #[tokio::test]
    async fn with_request_deadline_bounds_a_future_that_never_resolves() {
        let timeout = Duration::from_millis(50);
        let start = std::time::Instant::now();
        // `std::future::pending` never completes, on its own, under any circumstances — the same
        // shape as a `send_frame`/`recv_frame` call against a peer that never reads or replies.
        let never_resolves = std::future::pending::<Result<(), LinkError>>();
        let result = with_request_deadline(timeout, "org-b.test", never_resolves).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "with_request_deadline must not itself hang waiting on a future that never resolves"
        );
        match result {
            Err(RouteForeignError::Dial {
                domain,
                source: LinkError::Timeout { phase, duration },
            }) => {
                assert_eq!(domain, "org-b.test");
                assert_eq!(phase, "request");
                assert_eq!(duration, timeout);
            }
            other => panic!(
                "expected RouteForeignError::Dial{{source: LinkError::Timeout{{..}}, ..}} once \
                 the deadline elapsed, got {other:?}"
            ),
        }
    }
}
