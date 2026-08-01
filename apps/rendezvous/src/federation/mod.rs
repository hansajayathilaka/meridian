//! Server↔server (s2s) federation link establishment (task 2.4).
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
//! **Out of scope** (see the task file): discovery
//! ([2.5](../../../../docs/tasks/phase-2/2.5-federation-discovery.md)), policy/rate-limits
//! ([2.6](../../../../docs/tasks/phase-2/2.6-federation-policy-limits.md)), and every `fed_*`
//! request handler beyond the link-establishing `FedHello` exchange
//! ([2.7](../../../../docs/tasks/phase-2/2.7-federated-prekey-fetch.md)/
//! [2.8](../../../../docs/tasks/phase-2/2.8-federated-route-reachability.md)). In particular:
//! nothing here decides *whether* to federate with a given domain, or dials it automatically — a
//! caller (a later task) supplies the address and the expected/pinned domain explicitly.

pub mod link;

pub use link::{dial, FederationLink, FederationListener, FederationTlsPaths, LinkError};
