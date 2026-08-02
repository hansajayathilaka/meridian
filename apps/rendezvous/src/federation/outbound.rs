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

use meridian_proto::{FedBundle, FedErr, FedFetchBundle, FedFrame, FedOp};

use crate::federation::discovery::{DiscoveryError, Endpoint};
use crate::federation::link::{self, LinkError};
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
/// **Non-negotiable (inherited from task 2.5's security review):** the peer identity
/// [`link::dial`] pins its handshake to is `Endpoint::pinned_identity` when `Some` (private-CA /
/// air-gap mode, ADR 0017 C4) — **never** `hint_domain` in that mode. Falling back to `hint_domain`
/// whenever a pin is configured would collapse private-CA mode to ADR 0017 (a)'s rejected "Option
/// A": under a shared private CA, any org enrolled under that CA can present a certificate whose
/// SAN matches any domain string a caller merely *hoped* to reach, so the self-asserted hint alone
/// is not a trust boundary there. In WebPKI mode (`pinned_identity: None`, the common case),
/// `hint_domain` itself is the correct — and only available — verification target.
pub async fn fetch_foreign_bundle(
    state: &AppState,
    hint_domain: &str,
    target: [u8; 32],
) -> Result<FedBundle, FetchForeignError> {
    let discovery = state
        .federation
        .discovery
        .as_deref()
        .ok_or(FetchForeignError::NotConfigured)?;

    let endpoints =
        discovery
            .resolve(hint_domain)
            .await
            .map_err(|source| FetchForeignError::Discovery {
                domain: hint_domain.to_string(),
                source,
            })?;
    // `Discovery::resolve`'s contract (see its doc comment) guarantees a non-empty vec on `Ok`;
    // still handled explicitly rather than indexing, in case a future implementation regresses it.
    let endpoint = endpoints
        .into_iter()
        .next()
        .ok_or_else(|| FetchForeignError::Discovery {
            domain: hint_domain.to_string(),
            source: DiscoveryError::NotFound(hint_domain.to_string()),
        })?;

    let addr =
        resolve_dial_addr(&endpoint)
            .await
            .map_err(|source| FetchForeignError::AddrResolution {
                host: endpoint.host.clone(),
                port: endpoint.port,
                source,
            })?;

    // THE key requirement (2.5 security review, see doc comment above): pin to
    // `pinned_identity` when present, never silently fall back to `hint_domain` in that case.
    let expected_domain = endpoint.pinned_identity.as_deref().unwrap_or(hint_domain);

    let mut fed_link = link::dial(
        addr,
        expected_domain,
        &state.federation.tls.as_paths(),
        &state.federation.own_domain,
        Some(state.metrics.clone()),
    )
    .await
    .map_err(|source| FetchForeignError::Dial {
        domain: expected_domain.to_string(),
        source,
    })?;

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
