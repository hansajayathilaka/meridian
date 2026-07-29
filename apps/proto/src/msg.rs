//! Frame body types for the client↔rendezvous protocol (docs/api/rendezvous-protocol-v1.md).
//!
//! Each body is the CBOR payload carried in a [`Frame`](crate::Frame)'s `body` field, selected by
//! the frame's [`Op`](crate::Op). Bodies are deliberately small and flat.
//!
//! Naming note: the routing body is `RouteBody` and carries an [`OpaqueBlob`]; no body type is
//! named `Envelope`/`Message`/`Chat`, and the server never decodes a blob's *contents* — the
//! payloads-stay-opaque invariant (docs/security/anonymity-and-retention.md #1), also enforced by
//! `tools/lint-no-serde-on-blob.sh`.

use serde::{Deserialize, Serialize};

use crate::bundle::PrekeyBundle;
use crate::OpaqueBlob;

/// Server → client, first frame on connect: a single-use challenge to authenticate the account
/// key. The client signs `nonce ‖ server_domain` (domain binding prevents cross-server replay,
/// wire-protocol §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(with = "crate::bytes::b32")]
    pub nonce: [u8; 32],
    /// Advisory server clock (seconds since epoch) for validity-window hints.
    pub server_time: u64,
    /// The domain the client must fold into its signature (the server's own hint-domain).
    pub server_domain: String,
}

/// Client → server: proof of account-key control, plus registration intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    #[serde(with = "crate::bytes::b32")]
    pub account_pub: [u8; 32],
    /// Ed25519(account) over `nonce ‖ server_domain` from the [`Challenge`].
    #[serde(with = "crate::bytes::b64")]
    pub sig: [u8; 64],
    /// Admission token for `invite`-mode servers; ignored by `open` servers. OIDC gating (§3.2) is
    /// a server-side admission trait, not carried here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<String>,
    /// Highest bundle version the client supports (anti-rollback, wire-protocol §7).
    pub max_bundle_v: u16,
}

/// Server → client: authentication accepted; the account row exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthOk {
    /// Echoes the domain the session is bound to.
    pub server_domain: String,
}

/// Client → server: publish (replace) this account's prekey bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publish {
    pub bundle: PrekeyBundle,
}

/// Server → client: bundle stored; `accepted_otks` echoes the pool depth now held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishOk {
    pub accepted_otks: u16,
}

/// Client → server: fetch a bundle by **exact, full** account key. There is deliberately no
/// prefix/search field — anti-enumeration (system-design §3.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetch {
    #[serde(with = "crate::bytes::b32")]
    pub target: [u8; 32],
    /// Optional foreign-domain hint, present when `target` names an account this server is not
    /// itself authoritative for — the wire encoding of the routing invariant *client → own server
    /// → foreign server → client* (docs/api/federation-protocol-v1.md). It is a **plain domain
    /// string**, never a parsed `mrd1:` ID: the server must not decode identity strings (that
    /// needs `meridian-identity`, which would break `tools/lint-server-no-core.sh`); parsing stays
    /// client-side in `apps/identity/src/id.rs`. Advisory only, same footing as
    /// [`crate::fed::FedHello::domain`] — a stale hint is a routing failure
    /// (`not_found_at_hint`/`fed_unreachable`), never a security warning (ADR 0001). Absent for a
    /// same-server fetch; omitted from the wire entirely when `None`, so existing hint-less clients
    /// are unaffected. Whether the server enforces a max length or LDH form is server behaviour,
    /// deferred to whichever task first needs it (2.7) — this type places no constraint beyond
    /// being a CBOR text string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// TEST HOOK ONLY: ask the server to substitute a different key (malicious-server demo). The
    /// server honors it *only* when started with `allow_test_tamper = true`; production ignores it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tamper: bool,
}

/// Server → client: the requested bundle. The client MUST verify every signature under the key it
/// asked for before use; a bundle that verifies under any other key is a hard error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle: PrekeyBundle,
}

/// Client → server: route an opaque, client-signed envelope to a peer, of this org or a federated
/// one. `blob` is never inspected by the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBody {
    #[serde(with = "crate::bytes::b32")]
    pub to: [u8; 32],
    /// Optional foreign-domain hint, same shape and caveats as [`Fetch::hint`] — present when `to`
    /// names an account this server is not itself authoritative for, telling the server to forward
    /// across the federation boundary (`FedRoute`, docs/api/federation-protocol-v1.md) rather than
    /// deliver locally. Absent for a same-server route; omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_hint: Option<String>,
    pub blob: OpaqueBlob,
}

/// Server → client: outcome of a route. `delivered = false` means the recipient was not connected
/// (the mailbox that would hold it offline is T07, out of scope here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteOk {
    pub delivered: bool,
}

/// Server → recipient: a routed envelope pushed to a connected client. `from` is the sender key
/// the envelope claims; the recipient verifies the envelope signature under it (T03), rejecting a
/// mismatch as `ChatError::SenderMismatch`.
///
/// **Federated origin (ADR 0017 (b)/C2/C6).** This shape is unchanged by federation and carries no
/// new field: for a route that crossed a federation boundary, `from` is the value the *foreign*
/// server asserted in its `FedRoute{from}` (docs/api/federation-protocol-v1.md), relayed verbatim
/// by this server exactly as it already does for a purely local route. The client-side check does
/// not weaken — it now compares against server testimony that is one hop further from the client
/// (own server relaying a foreign server's assertion, not asserting its own connection), the same
/// "server testimony, not a cryptographic proof" category as the single-hop case
/// ([ADR 0016](../../../docs/adr/0016-envelope-deniability.md) residual R4, scope-corrected).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deliver {
    #[serde(with = "crate::bytes::b32")]
    pub from: [u8; 32],
    pub blob: OpaqueBlob,
}

/// Client → server: request ephemeral TURN credentials for a new session (T05, wire-protocol §2,
/// system-design §5.4). The body is intentionally empty — the server mints a fresh, time-limited,
/// per-session HMAC credential regardless of who asks; the client never sends a static TURN secret
/// (webrtc-nat-traversal invariant 4). A future `session_hint` could bind a credential to a
/// specific peer for finer allocation accounting; not carried in v1 (`TODO: confirm` in T14).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnReq {}

/// Server → client: a freshly-minted TURN credential, distinct from every other grant. `username`
/// embeds the UNIX expiry (`<expiry>:<nonce>`) so coturn's shared-secret (`use-auth-secret`) check
/// enforces the TTL without any server-side session state; `credential` is
/// `base64(HMAC-SHA1(secret, username))`. The `nonce` makes every grant unique, so a captured
/// credential can't be used to mint allocations under a *different* username — but reuse of that one
/// captured credential itself, within its own TTL window, is bounded by coturn's `user-quota`, not
/// rejected outright. `urls` is the full candidate ladder in preference order — TURN/UDP, TURN/TCP,
/// then TURN/TLS-443 as the hostile-egress last resort (§5.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnGrant {
    /// ICE-server URLs in ladder order, e.g. `turn:turn.org:3478?transport=udp`,
    /// `turn:turn.org:3478?transport=tcp`, `turns:turn.org:443?transport=tcp`.
    pub urls: Vec<String>,
    /// The ephemeral username `<expiry-unix>:<nonce-hex>`.
    pub username: String,
    /// `base64(HMAC-SHA1(shared_secret, username))` — the coturn REST-mechanism password.
    pub credential: String,
    /// Seconds until `username`'s embedded expiry; advisory for the client's re-mint timer.
    pub ttl_secs: u64,
    /// The TURN realm the credential is scoped to.
    pub realm: String,
}

/// Server → client: a structured error reply (see [`error_codes`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrBody {
    pub code: String,
    pub msg: String,
}

/// Stable error `code` strings used in [`ErrBody`].
pub mod error_codes {
    pub const AUTH_REQUIRED: &str = "auth_required";
    pub const AUTH_FAILED: &str = "auth_failed";
    pub const REPLAY: &str = "replay";
    pub const ADMISSION_DENIED: &str = "admission_denied";
    pub const NOT_FOUND: &str = "not_found";
    pub const NOT_CONNECTED: &str = "not_connected";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const BAD_BUNDLE: &str = "bad_bundle";
    pub const BAD_REQUEST: &str = "bad_request";
    /// TURN credential minting is disabled (no shared secret configured, or air-gapped with no
    /// relay). The client falls back to the STUN/host ladder and surfaces the blocked path via
    /// `meridian doctor` (T05).
    pub const TURN_UNAVAILABLE: &str = "turn_unavailable";
    /// A `Fetch`/`RouteBody` named a foreign target, but this org's federation policy
    /// (`open | allowlist | closed`) refuses to fetch from, or route to, the hinted domain
    /// ([2.6](../../../docs/tasks/phase-2/2.6-federation-policy-limits.md) emits this).
    pub const FED_DENIED: &str = "fed_denied";
    /// The hinted foreign server could not be reached (discovery failure, dial failure, or the
    /// federation link itself returned an error) — a connectivity/availability outcome, distinct
    /// from `fed_denied`'s policy outcome
    /// ([2.7](../../../docs/tasks/phase-2/2.7-federated-prekey-fetch.md)/
    /// [2.8](../../../docs/tasks/phase-2/2.8-federated-route-reachability.md) emit this).
    pub const FED_UNREACHABLE: &str = "fed_unreachable";
    /// `Fetch.hint` resolved to a foreign server that reached back with `FedErr{not_found}`, or
    /// otherwise doesn't hold `target` — the federated analogue of `not_found`, kept distinct so a
    /// client can tell "no such account here" from "no such account at the org your hint named"
    /// (the stale-hint case, ADR 0001 consequences — a UX/reachability outcome, never a security
    /// warning) ([2.7](../../../docs/tasks/phase-2/2.7-federated-prekey-fetch.md) emits this).
    pub const NOT_FOUND_AT_HINT: &str = "not_found_at_hint";
}

fn is_false(b: &bool) -> bool {
    !*b
}
