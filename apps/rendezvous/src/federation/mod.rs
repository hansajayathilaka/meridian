//! Server↔server (s2s) federation link establishment (task 2.4) and domain discovery (task 2.5).
//!
//! Implements the parts of [ADR 0017](../../../../docs/adr/0017-federation-trust-boundary.md)
//! this task owns:
//!
//! - **(a)/C3** — certificate validation targets the domain THIS side intended to reach, never the
//!   literal dial target: `dial`'s `expected_domain` parameter is checked by rustls's standard
//!   hostname verification during the handshake, and re-asserted explicitly afterward against the
//!   peer's SAN/CN (belt-and-suspenders — see the `link` submodule's docs).
//! - **C7** — TLS terminates **in-process**. `FederationListener` binds a raw TCP listener and
//!   wraps each accepted connection in `rustls` directly; there is no proxy/VIP upstream of
//!   this process, unlike the c2s WSS listener (proxy-terminated per
//!   [ADR 0008](../../../../docs/adr/0008-infra-topology.md) — safe there only because c2s
//!   identity comes from the post-TLS `Auth` signature, never from the TLS layer itself).
//!
//! Both WebPKI and private-CA (air-gap) modes share **one verification rule** — chain to a trusted
//! root, SAN/CN matches the intended domain — differing only in where the trusted root comes from
//! (`config::Federation::ca_bundle_path` empty ⇒ OS/system trust store; non-empty ⇒ that bundle,
//! exclusively).
//!
//! The [`discovery`] submodule (task 2.5) resolves a partner domain to dial-target `Endpoint`s —
//! via `_meridian-fed._tcp` SRV records or a `federation_map.toml` static/air-gap map — but
//! performs no dialling itself; `link::dial` above still takes an explicit address and
//! `expected_domain`, with discovery as one (not the only) way a caller might obtain them.
//!
//! Policy/rate-limits are [2.6](../../../../docs/tasks/phase-2/2.6-federation-policy-limits.md)'s
//! [`policy`] submodule — a pure decision layer, not wired into any handler here. **Still out of
//! scope for this crate module as a whole**: every `fed_*` request handler beyond the
//! link-establishing `FedHello` exchange
//! ([2.7](../../../../docs/tasks/phase-2/2.7-federated-prekey-fetch.md)/
//! [2.8](../../../../docs/tasks/phase-2/2.8-federated-route-reachability.md)), and any
//! client-visible error copy
//! ([2.9](../../../../docs/tasks/phase-2/2.9-federation-error-copy.md)). In particular: nothing
//! in [`discovery`] decides *whether* to federate with a given domain — a resolved `Endpoint` is a
//! discovery answer, not a policy allowance; that allowance is [`policy::FederationPolicy`].

pub mod discovery;
/// Server B's inbound handling of `fed_*` requests arriving over an already-established
/// [`FederationLink`] (task 2.7 adds `handle_fed_fetch` + the `FetchBundle` case of
/// [`inbound::serve_link`]'s dispatch loop; task 2.8 extends the same loop with `Route`/
/// `Reachability`).
pub mod inbound;
pub mod link;
/// Server A's outbound dial-out path: resolve a hint domain via [`Discovery`], dial via
/// [`dial`] (pinning to `Endpoint::pinned_identity` when private-CA/air-gap mode supplies one —
/// see [`outbound::fetch_foreign_bundle`]'s doc comment), and speak one `fed_*` request/reply
/// (task 2.7: `FetchBundle`/`Bundle`; task 2.8 adds `Route`/`Reachability`).
pub mod outbound;
pub mod policy;

pub use discovery::{
    Discovery, DiscoveryError, Endpoint, HickoryResolver, RawSrv, SrvDiscovery, SrvResolver,
    StaticMap,
};
pub use link::{
    dial, with_deadline, DeadlineExceeded, FederationLink, FederationListener, FederationTlsPaths,
    LinkError,
};
pub use policy::{Decision, FederationLimits, FederationPolicy, RateLimitScope, RejectReason};
