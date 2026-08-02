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
    fed_link
        .send_frame(&out)
        .await
        .map_err(|source| FetchForeignError::Dial {
            domain: expected_domain.to_string(),
            source,
        })?;

    let reply = fed_link
        .recv_frame()
        .await
        .map_err(|source| FetchForeignError::Dial {
            domain: expected_domain.to_string(),
            source,
        })?;

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
/// structurally unreachable here, not merely assumed to be.
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
    let discovery = state
        .federation
        .discovery
        .as_deref()
        .ok_or(RouteForeignError::NotConfigured)?;

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

    let fed_link = link::dial(
        addr,
        &expected_domain,
        &state.federation.tls.as_paths(),
        &state.federation.own_domain,
        Some(state.metrics.clone()),
    )
    .await
    .map_err(|source| RouteForeignError::Dial {
        domain: expected_domain.clone(),
        source,
    })?;

    Ok((fed_link, expected_domain))
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
    match reachable_foreign(state, hint_domain, to).await {
        Ok(true) => {}
        Ok(false) => return Err(RouteForeignError::TargetUnreachable),
        Err(RouteForeignError::Fed(fed_err)) => return Err(RouteForeignError::Fed(fed_err)),
        Err(_) => return Err(RouteForeignError::TargetUnreachable),
    }

    let (mut fed_link, expected_domain) = dial_foreign(state, hint_domain).await?;
    fed_link
        .send_frame(&out)
        .await
        .map_err(|source| RouteForeignError::Dial {
            domain: expected_domain.clone(),
            source,
        })?;

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
    fed_link
        .send_frame(&out)
        .await
        .map_err(|source| RouteForeignError::Dial {
            domain: expected_domain.clone(),
            source,
        })?;

    let reply = fed_link
        .recv_frame()
        .await
        .map_err(|source| RouteForeignError::Dial {
            domain: expected_domain,
            source,
        })?;

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
