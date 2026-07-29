//! Server ↔ server federation wire types (docs/api/federation-protocol-v1.md).
//!
//! This is a **separate** plane from the client↔rendezvous protocol in [`crate::frame`] /
//! [`crate::msg`]: [`FedOp`]/[`FedFrame`] are their own types, never a reuse of [`crate::Op`] /
//! [`crate::Frame`]. The c2s `serve` loop only ever decodes `Op`; there is no shared enum a client
//! socket could exploit to nominally speak federation ops, and no s2s listener ever decodes `Op`.
//!
//! Canonical shape per [ADR 0017](../../../docs/adr/0017-federation-trust-boundary.md) C1/C2:
//! [`FedRoute`] carries `from` as routing metadata asserted by the sending (origin) server,
//! carried alongside — never decoded from — the opaque `envelope` blob.
//!
//! `FedHello.domain` and `FedFetchBundle.requesting_server` are **self-asserted, informational
//! only** — never an identity or policy input. The authoritative peer identity for every
//! routing/policy/rate-limit decision is always the mTLS peer certificate validated in-process
//! per ADR 0017 (a)/C7, never a field carried inside a frame body.
//!
//! `wire-protocol.md §4`'s optional `contact_token{issuer_sig, audience, exp}` is documented but
//! deliberately **not** a type here: contact tokens are out of scope for this task (→ T08/T14).
//! Reserved name, no corresponding Rust field.

use serde::{Deserialize, Serialize};

use crate::bundle::PrekeyBundle;
use crate::OpaqueBlob;

/// Federation wire-protocol major version (docs/api/federation-protocol-v1.md).
pub const FED_VERSION: u8 = 1;

/// Federation frame operation selector. A distinct enum from [`crate::Op`] by construction — see
/// module docs — so a client-facing socket can never nominally speak a federation op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedOp {
    /// Exchanged once by each side, at `id = 0`, immediately after the mTLS handshake completes.
    Hello,
    /// Requesting side → peer: fetch a prekey bundle for an account the peer's org is
    /// authoritative for.
    FetchBundle,
    /// Reply to [`FedOp::FetchBundle`]: the requested bundle.
    Bundle,
    /// Either side → peer: route an opaque, already-signed envelope to an account the peer's org
    /// is authoritative for. Fire-and-forget on success (silent); errors via `FedErr` echoing
    /// this frame's `id`. There is no `FedRouteOk`.
    Route,
    /// Requesting side → peer: is a device for `target` connected right now? Per-request only —
    /// no persistent cross-org presence subscription (system design §3.4).
    Reachability,
    /// Reply to [`FedOp::Reachability`].
    Reachable,
    /// Either side → peer: structured error, echoing the failed request's `id`.
    Err,
}

/// A single s2s wire frame: `{op, id, body}`, mirroring the c2s [`crate::Frame`] shape exactly
/// (docs/api/federation-protocol-v1.md §1). `body` is nested CBOR, opaque at the frame layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedFrame {
    pub op: FedOp,
    pub id: u64,
    #[serde(with = "crate::bytes::bytes_vec")]
    pub body: Vec<u8>,
}

impl FedFrame {
    /// Build a frame for `op`/`id`, CBOR-encoding `body` into the nested byte string.
    pub fn new<B: Serialize>(
        op: FedOp,
        id: u64,
        body: &B,
    ) -> Result<Self, crate::frame::CodecError> {
        Ok(Self {
            op,
            id,
            body: crate::frame::encode(body)?,
        })
    }

    /// Decode this frame's body as `B`. Callers match on `self.op` first to pick `B`.
    pub fn decode<B: for<'de> Deserialize<'de>>(&self) -> Result<B, crate::frame::CodecError> {
        crate::frame::decode(&self.body)
    }

    /// Encode the whole frame to CBOR bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::frame::CodecError> {
        crate::frame::encode(self)
    }

    /// Decode a whole frame from CBOR bytes received off the wire.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::frame::CodecError> {
        crate::frame::decode(bytes)
    }
}

/// Exchanged once by each side at `id = 0` right after the mTLS handshake completes (mirrors
/// `Challenge`'s `id = 0` role in the c2s protocol, though this is a two-way exchange, not a
/// server-issued challenge). `domain` is the sender's own self-asserted domain —
/// informational/diagnostic only (logging, mismatch warnings). It is **never** the authenticated
/// identity: that is always the mTLS peer certificate per ADR 0017 (a). No policy, routing, or
/// rate-limit decision may be made from this field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedHello {
    pub v: u8,
    pub domain: String,
}

/// Requesting side → peer: fetch a bundle for `target`, an account the peer's org is
/// authoritative for. `requesting_server` is likewise self-asserted / informational only, same
/// caveat as [`FedHello::domain`] — the authoritative "origin server" for rate-limit keying (ADR
/// 0017 C5) is the mTLS peer identity, never this field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedFetchBundle {
    #[serde(with = "crate::bytes::b32")]
    pub target: [u8; 32],
    pub requesting_server: String,
}

/// Reply to [`FedFetchBundle`]: the requested bundle, reusing [`PrekeyBundle`] verbatim (not
/// redefined here). The client's mandatory signature-verification-under-the-requested-key check
/// (rendezvous-protocol-v1 §3) applies identically to a federated fetch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedBundle {
    pub bundle: PrekeyBundle,
}

/// Either side → peer: route an opaque envelope across the federation boundary. Canonical shape
/// per [ADR 0017](../../../docs/adr/0017-federation-trust-boundary.md) C1/C2. `from` is asserted
/// by the sending (origin) server, carried as routing metadata alongside — never decoded from —
/// the opaque `envelope`. Field name `envelope` (not `blob`) matches wire-protocol.md §4's
/// existing name for this op. The receiving server relays `from` verbatim as the `from` in the
/// `Deliver{from, blob}` it pushes to its own client, exactly as it already does for a purely
/// local route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedRoute {
    #[serde(with = "crate::bytes::b32")]
    pub to: [u8; 32],
    #[serde(with = "crate::bytes::b32")]
    pub from: [u8; 32],
    pub envelope: OpaqueBlob,
}

/// Requesting side → peer: is a device for `target` connected right now? Per-request only — no
/// persistent cross-org presence subscription (system design §3.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedReachability {
    #[serde(with = "crate::bytes::b32")]
    pub target: [u8; 32],
}

/// Reply to [`FedReachability`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedReachable {
    pub connected: bool,
}

/// Either side → peer: a structured error reply (see [`fed_error_codes`]), mirroring
/// [`crate::msg::ErrBody`] exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedErr {
    pub code: String,
    pub msg: String,
}

/// Stable error `code` strings used in [`FedErr`].
pub mod fed_error_codes {
    /// Federation to/from this origin is closed, or the origin is not on an allowlist policy's
    /// list ([2.6](../../../docs/tasks/phase-2/2.6-federation-policy-limits.md) emits this).
    pub const POLICY_DENIED: &str = "policy_denied";
    /// Federation-edge rate limits exceeded, keyed per ADR 0017 C5
    /// ([2.6](../../../docs/tasks/phase-2/2.6-federation-policy-limits.md) emits this).
    pub const RATE_LIMITED: &str = "rate_limited";
    /// `FedFetchBundle`'s target is not an account this org is authoritative for
    /// ([2.7](../../../docs/tasks/phase-2/2.7-federated-prekey-fetch.md) emits this).
    pub const NOT_FOUND: &str = "not_found";
    /// Malformed frame or body.
    pub const BAD_REQUEST: &str = "bad_request";
}
