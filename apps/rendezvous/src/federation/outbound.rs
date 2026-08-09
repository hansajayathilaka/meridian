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
/// **Residual, recorded rather than silently accepted (architect + security-reviewer + code-reviewer,
/// task 2.8):** `handle_fed_route`'s own checks (policy admission, an in-memory rate limiter, a
/// `Registry` push) are purely in-process with no I/O of their own, so a genuine `FedErr` costs
/// essentially zero *processing* time on B's side — but this bound also has to cover one real wire
/// round trip for that reply to travel back over the already-established TLS link, which this
/// constant's value does not explicitly model. Two failure directions are in tension, and neither
/// reviewer proposed a specific better number, so none is guessed here: (a) too short risks a
/// genuine policy/rate-limit rejection arriving after the window elapses under real packet
/// loss/congestion, which `route_foreign` would then report as success — a false-positive delivery
/// confirmation, strictly worse than a false negative; (b) every SUCCESSFUL federated route pays
/// this as a fixed latency tax, since the happy path is only ever detected by the wait running to
/// completion, never by an explicit ack. 500ms is a defensible heuristic for the common case, not
/// a value derived from a measured RTT distribution. Revisiting this — either tightening the bound
/// with real measurements, or reopening federation-protocol-v1.md's "do not add a `FedRouteOk`"
/// decision, which needs a protocol revision, not a unilateral change here — is left as an
/// explicit follow-up, not resolved by this task.
const ROUTE_REPLY_GRACE: Duration = Duration::from_millis(500);

/// Resolve `hint_domain` and dial the resulting [`Endpoint`], exactly as
/// [`fetch_foreign_bundle`] does (same discovery lookup, same `pinned_identity`-over-`hint_domain`
/// pin — see that function's doc comment for the non-negotiable reasoning), factored out here
/// because [`route_foreign`] and [`reachable_foreign`] both need a fresh one-shot link and share
/// [`RouteForeignError`] as their error type.
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
    let endpoint = endpoints
        .into_iter()
        .next()
        .ok_or_else(|| RouteForeignError::Discovery {
            domain: hint_domain.to_string(),
            source: DiscoveryError::NotFound(hint_domain.to_string()),
        })?;

    let addr =
        resolve_dial_addr(&endpoint)
            .await
            .map_err(|source| RouteForeignError::AddrResolution {
                host: endpoint.host.clone(),
                port: endpoint.port,
                source,
            })?;

    let expected_domain = endpoint
        .pinned_identity
        .as_deref()
        .unwrap_or(hint_domain)
        .to_string();

    // Task 3.3 (F3): `dial` itself bounds its own connect/TLS/hello steps against
    // `state.federation.timeouts` — see `link::dial`'s doc comment. A black-holed `hint_domain`
    // (accepts TCP, then silence; or completes TLS+FedHello, then never answers a later request)
    // can no longer hang this call, and thus never leaks the task awaiting it, forever.
    let fed_link = link::dial(
        addr,
        &expected_domain,
        &state.federation.tls.as_paths(),
        &state.federation.own_domain,
        Some(state.metrics.clone()),
        state.federation.timeouts,
    )
    .await
    .map_err(|source| RouteForeignError::Dial {
        domain: expected_domain.clone(),
        source,
    })?;

    Ok((fed_link, expected_domain))
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

    // Architect decision #3: the pre-check's TARGET-LIVENESS outcome (offline, unknown, or a
    // connectivity/protocol failure that leaves liveness undetermined) collapses to
    // `TargetUnreachable` — never a distinct signal. This is deliberately NOT the same as B
    // *answering* the pre-check with a structured policy/rate-limit refusal
    // (`RouteForeignError::Fed`, e.g. `fed_denied`/`rate_limited`): that is B definitively
    // declining to engage at all, an orthogonal axis from target liveness, and must surface as
    // itself — collapsing a closed-policy answer into "recipient offline" would both hide a real
    // policy signal from the caller and contradict this task's own required behaviour ("closed
    // origin at B → fed_denied", not `not_connected`).
    //
    // (task 3.1) `RouteForeignError::Denied` — THIS server's own policy refusing to dial
    // `hint_domain` at all, surfaced by the pre-check's own internal `dial_foreign` call — is the
    // identical axis as `Fed` above, not the target-liveness axis: A never even attempted to learn
    // whether `to` is reachable, so folding this into `TargetUnreachable` would misreport a local
    // policy refusal as "recipient offline" and (worse, since this task's whole point is closing an
    // SSRF oracle) would make the pre-check's own denial indistinguishable from the real dial
    // attempt just below ever having happened at all.
    match reachable_foreign(state, hint_domain, to).await {
        Ok(true) => {}
        Ok(false) => return Err(RouteForeignError::TargetUnreachable),
        Err(RouteForeignError::Fed(fed_err)) => return Err(RouteForeignError::Fed(fed_err)),
        Err(RouteForeignError::Denied) => return Err(RouteForeignError::Denied),
        Err(_) => return Err(RouteForeignError::TargetUnreachable),
    }

    let (mut fed_link, expected_domain) = dial_foreign(state, hint_domain).await?;
    // Task 3.3 (F3), review fix: bounded under `state.federation.timeouts.request` — same
    // treatment as `fetch_foreign_bundle`'s and `reachable_foreign`'s send/recv exchanges (see
    // `with_request_deadline`'s doc comment). Without this, a partner that completes real
    // mTLS+`FedHello` (i.e. is admitted by policy) and then never drains its TCP receive window
    // hangs this `write_all`/`flush` forever, leaking a pinned task plus TLS link on the path
    // that carries an actual authenticated user's routed envelope — exactly the failure mode this
    // task exists to close, just missed on this one call site in the original diff.
    let request_timeout = state.federation.timeouts.request;
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

/// Server A's outbound path for `fed_reachability`: resolve `hint_domain`, dial, and ask "is a
/// device for `target` connected right now?" — per-request only, never a subscription (system
/// design §3.4). The only caller in this task is [`route_foreign`]'s own internal pre-check
/// (architect decision #3); nothing here makes this a new client-visible c2s trigger.
pub async fn reachable_foreign(
    state: &AppState,
    hint_domain: &str,
    target: [u8; 32],
) -> Result<bool, RouteForeignError> {
    let (mut fed_link, expected_domain) = dial_foreign(state, hint_domain).await?;

    let req = FedReachability { target };
    let out = FedFrame::new(FedOp::Reachability, 1, &req)
        .map_err(|e| RouteForeignError::Protocol(e.to_string()))?;
    // Task 3.3 (F3): same bounded-wait treatment as `fetch_foreign_bundle`'s identical shape —
    // see `with_request_deadline`'s doc comment.
    let request_timeout = state.federation.timeouts.request;
    with_request_deadline(request_timeout, &expected_domain, fed_link.send_frame(&out)).await?;

    let reply =
        with_request_deadline(request_timeout, &expected_domain, fed_link.recv_frame()).await?;

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
