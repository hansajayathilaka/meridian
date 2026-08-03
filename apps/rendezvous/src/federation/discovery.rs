//! Domain → s2s endpoint resolution (task 2.5, ADR 0002 "federated s2s signaling, DNS-SRV/
//! static-map discovery").
//!
//! Two [`Discovery`] implementations, selected by `config::Federation::discovery`:
//! - [`StaticMap`] — parses `federation_map.toml` (a config file, not a database table — see this
//!   module's doc note below on the data-model.md/feature-spec contradiction this task resolves).
//!   Air-gap mode: this type has **no field of any DNS-resolver type at all**, so it is
//!   structurally incapable of making a DNS query, not merely configured not to.
//! - [`SrvDiscovery`] — resolves `_meridian-fed._tcp.<domain>` SRV records (RFC 2782) through an
//!   injectable [`SrvResolver`] (the real backend is [`HickoryResolver`]; tests inject a stub).
//!
//! ## Scope (task 2.5)
//! Pure resolution: domain in, `Vec<Endpoint>` out. No sockets — dialling is
//! [2.4](../../../../docs/tasks/phase-2/2.4-s2s-mtls-link.md)'s `federation::link::dial`, already
//! landed, which takes an address and an `expected_domain` to pin certificate validation to (ADR
//! 0017 (a)/C3). No policy — *whether* a resolved domain is actually allowed to federate is
//! [2.6](../../../../docs/tasks/phase-2/2.6-federation-policy-limits.md)'s job; an unlisted domain
//! failing to resolve here is a *discovery* miss, not a policy rejection, and callers must not
//! conflate the two.
//!
//! ## `federation_map.toml` vs. data-model.md's `federation_map` table (resolved contradiction)
//! [data-model.md](../../../../docs/architecture/data-model.md) used to define `federation_map` as
//! a **database table** (`domain PK, endpoint, ca_pin, policy`); the feature spec, the phase-2
//! README, `deployment.md`, and the deployment-topology diagram all call it a **config file**,
//! `federation_map.toml`. This task resolves the contradiction in favor of the config file: task
//! 2.3 already re-deferred "normalized schema + Postgres" to T07 with "Feature 06 adds no new
//! persisted state," and a config file is what actually air-gaps (ADR 0002's whole point — "static
//! federation map + private CA" with **no** shared/queryable state). `data-model.md` is edited to
//! point here instead of describing a table that was never built.
//!
//! ## Resolved `TODO: confirm`s (see the task file's Risks section)
//! - **`federation_map.toml` schema:** an array of `[[partner]]` tables (not a `domain`-keyed
//!   TOML table — a domain like `org-b.test` as a raw TOML key needs quoting/escaping for no
//!   benefit here). Fields: `domain` (the discovery/hint domain — ADR 0017 (a)/C3's certificate
//!   validation target), `endpoint` (`host:port` to dial), `pinned_identity` (the SAN/CN ADR 0017
//!   C4 requires for private-CA/air-gap mode, **mandatory**, fail-closed at parse time — see
//!   [`StaticMap::load`]), and `policy` (optional, carried through unparsed/uninterpreted for
//!   [2.6](../../../../docs/tasks/phase-2/2.6-federation-policy-limits.md) to define; this task
//!   neither validates nor acts on its contents). Named `pinned_identity`, not `ca_pin` (the task
//!   file's suggested name, inherited from data-model.md's abandoned table): ADR 0017 C4's pin is
//!   an identity name (SAN/CN) compared against the peer certificate's subject fields, never a
//!   certificate/key fingerprint — "ca_pin" reads as the *rejected* SPKI-fingerprint option ((a)
//!   option C in ADR 0017), which this schema deliberately does not implement. `pinned_identity`
//!   names what the field actually holds.
//! - **No-SRV-record behavior:** refuse (fail closed), never fall back to A/AAAA + a guessed port.
//!   [`SrvDiscovery::resolve`] returns [`DiscoveryError::NoSrvRecord`] rather than attempting any
//!   other record type. An A/AAAA fallback would let an attacker who controls neither the SRV
//!   record nor a valid certificate nonetheless redirect the TCP dial by controlling only the A
//!   record — TLS validation still targets the hint domain either way (ADR 0017 (a)/C3), so this
//!   isn't a spoofing hole by itself, but it silently accepts a materially weaker, non-standard
//!   discovery signal (a guessed/default port, a record type the operator never published for
//!   federation) exactly where the project's fail-closed posture says refuse and surface the
//!   misconfiguration instead. This is the resolved architect call for this task; architect review
//!   may override it.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;

/// One resolved s2s dial target for a federation partner domain.
///
/// `host`/`port` are what [`link::dial`](super::link::dial) connects a TCP socket to; they are
/// **never** the certificate-validation target. Which field IS the trust anchor depends on mode:
/// - **WebPKI mode** (`pinned_identity: None` — every `SrvDiscovery`-sourced `Endpoint`, and any
///   `StaticMap` entry in a deployment that isn't running private-CA/air-gap mode): the
///   verification target is the `domain` string passed to [`Discovery::resolve`] — the
///   hint/discovery domain, never the literal SRV/static-map dial target (ADR 0017 (a)/C3).
/// - **Private-CA / air-gap mode** (`pinned_identity: Some(_)` — every `StaticMap`-sourced
///   `Endpoint`, see below): the verification target is **`pinned_identity`**, not `domain`. ADR
///   0017 C4's whole point is that a self-asserted hint domain is not itself a trust boundary
///   under a private CA — anyone enrolled under that CA can present a cert whose SAN matches any
///   domain string a caller merely *hoped* to reach. A future caller (2.7's dial-out path) MUST
///   pass `pinned_identity`, when `Some`, as [`link::dial`](super::link::dial)'s
///   `expected_domain` — not `domain` — or private-CA mode collapses to ADR 0017 (a)'s rejected
///   "Option A" impersonation hole.
///
/// Keeping the dial address and the trust anchor as separate values (never collapsing them into
/// one "endpoint" string) is what makes a hijacked SRV record, or a typo'd `endpoint` in
/// `federation_map.toml`, a reachability failure rather than an impersonation risk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Host to dial: an SRV `target` hostname, or the host half of a `federation_map.toml`
    /// `endpoint` entry.
    pub host: String,
    /// Port to dial.
    pub port: u16,
    /// SRV priority (RFC 2782): lower values are tried first. `0` for every `StaticMap`-sourced
    /// endpoint — a map entry names exactly one endpoint, so there is nothing to order.
    pub priority: u16,
    /// SRV weight (RFC 2782): among endpoints sharing the lowest `priority`, higher weights are
    /// preferred. `0` for `StaticMap`-sourced endpoints, same reasoning as `priority`.
    pub weight: u16,
    /// Private-CA (air-gap) mode pinned peer identity (SAN/CN), per ADR 0017 C4. Always `Some` for
    /// `StaticMap`-sourced endpoints ([`StaticMap::load`] fails closed on a missing/empty pin, so
    /// this invariant holds by construction, not merely by convention). Always `None` for
    /// `SrvDiscovery`-sourced endpoints: SRV is an unauthenticated discovery mechanism only, never
    /// a trust source (ADR 0017 (a)) — a caller resolving via SRV pins to the hint `domain` itself
    /// (WebPKI mode), not to any value this struct carries.
    pub pinned_identity: Option<String>,
    /// Federation policy label carried through unparsed from the `federation_map.toml` entry, for
    /// [2.6](../../../../docs/tasks/phase-2/2.6-federation-policy-limits.md) to define and enforce.
    /// This task neither validates nor interprets its contents — `None` if the entry omitted it,
    /// and always `None` for SRV-sourced endpoints (SRV carries no policy information at all).
    pub policy: Option<String>,
}

/// Errors resolving a federation partner domain to dial targets.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// `StaticMap`: the domain has no entry in the loaded map. A discovery miss, not a policy
    /// rejection — see this module's doc comment on the discovery/policy split.
    #[error("no federation_map.toml entry for domain {0:?}")]
    NotFound(String),
    /// `StaticMap::load`: the map file could not be read.
    #[error("failed to read federation map {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `StaticMap::load`: the map file's contents are not valid TOML, or don't match the expected
    /// shape. Fails closed — never silently treated as an empty map.
    #[error("malformed federation map TOML in {path:?}: {source}")]
    Toml {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    /// `StaticMap::load`: an entry is missing its `pinned_identity`, or it is empty/whitespace.
    /// ADR 0017 C4: a map entry missing its pin is a fail-closed *configuration* error, rejected
    /// at load time, never silently downgraded to "chains to the trusted CA" with no name check.
    #[error(
        "federation_map.toml entry for domain {domain:?} has a missing or empty pinned_identity \
         (ADR 0017 C4 requires an explicit SAN/CN pin per partner)"
    )]
    MissingPin { domain: String },
    /// `StaticMap::load`: an entry's `endpoint` isn't `host:port`, or the port doesn't parse.
    #[error("federation_map.toml entry for domain {domain:?} has an invalid endpoint {endpoint:?}: {reason}")]
    InvalidEndpoint {
        domain: String,
        endpoint: String,
        reason: String,
    },
    /// `StaticMap::load`: the same domain appears in more than one `[[partner]]` entry.
    #[error("federation_map.toml has more than one entry for domain {0:?}")]
    DuplicateDomain(String),
    /// `SrvDiscovery`: no `_meridian-fed._tcp.<domain>` SRV record exists. Refused, not
    /// downgraded to A/AAAA — see this module's doc comment on the resolved `TODO: confirm`.
    #[error(
        "no _meridian-fed._tcp.{0} SRV record found — refusing to fall back to A/AAAA \
         (fail-closed discovery; see federation::discovery module docs)"
    )]
    NoSrvRecord(String),
    /// `SrvDiscovery`: the DNS query itself failed (timeout, SERVFAIL, transport error, ...) —
    /// distinct from a clean "no record" answer, which is [`DiscoveryError::NoSrvRecord`].
    #[error("DNS SRV lookup for {domain:?} failed: {reason}")]
    Resolver { domain: String, reason: String },
    /// [`SrvDiscovery::new`]: the resolver backend itself could not be constructed (e.g. no usable
    /// system resolver configuration).
    #[error("failed to construct DNS resolver: {0}")]
    ResolverInit(String),
}

/// Resolves a federation partner's discovery/hint domain to the s2s endpoint(s) to dial. Pure
/// resolution only — see this module's doc comment for the discovery/dial/policy split.
#[async_trait]
pub trait Discovery: Send + Sync {
    /// Resolve `domain` (the discovery/hint domain — ADR 0017 (a)/C3's certificate-validation
    /// target) to the endpoint(s) a caller may dial. An empty `Ok(vec![])` is never returned by
    /// either implementation in this module: a domain with no usable endpoint is always an `Err`
    /// (`NotFound` or `NoSrvRecord`), so callers can treat "resolved" as "at least one candidate."
    async fn resolve(&self, domain: &str) -> Result<Vec<Endpoint>, DiscoveryError>;
}

// ---------------------------------------------------------------------------------------------
// StaticMap
// ---------------------------------------------------------------------------------------------

/// One `[[partner]]` entry as it appears in `federation_map.toml`.
#[derive(Clone, Debug, Deserialize)]
struct PartnerEntry {
    domain: String,
    endpoint: String,
    #[serde(default)]
    pinned_identity: String,
    #[serde(default)]
    policy: Option<String>,
}

/// Top-level shape of `federation_map.toml`: `partner` is an array of tables (`[[partner]]`), not
/// a `domain`-keyed map — a domain like `"org-b.test"` as a raw TOML key needs quoting for no
/// benefit here, and an array is unambiguous about entry identity even before validation.
#[derive(Clone, Debug, Deserialize)]
struct StaticMapFile {
    #[serde(default)]
    partner: Vec<PartnerEntry>,
}

/// Static, air-gap-capable [`Discovery`]: every partner is named explicitly in
/// `federation_map.toml`, loaded once at startup. Deliberately holds **no field of any DNS
/// resolver type** — not merely "configured to skip DNS," but structurally incapable of routing a
/// DNS query through this crate's `SrvResolver` abstraction, which is one leg of what the air-gap
/// deployment mode (ADR 0002, `deployment.md`) depends on. That structural claim is checked at
/// compile time by this module's own `structural_tests`; `tests/federation_discovery.rs`'s
/// `static_mode_performs_zero_dns_lookups` checks the dispatch-level companion claim (selecting
/// `StaticMap` via the `Discovery` trait object never routes through a live `SrvResolver`
/// alongside it). Neither of those proves `resolve`, below, is free of some OTHER, ad hoc network
/// call that bypasses `SrvResolver` entirely — that's what
/// `tests/federation_discovery.rs`'s `airgap_syscall_probe::static_map_resolve_makes_zero_getaddrinfo_calls`
/// (a syscall-level `LD_PRELOAD` proof) exists to close; see its doc comment for why a
/// field-shaped or trait-shaped guarantee alone isn't the whole story.
#[derive(Clone, Debug)]
pub struct StaticMap {
    entries: HashMap<String, Endpoint>,
}

impl StaticMap {
    /// Parse `federation_map.toml` from `path`. Fails closed on every malformed input: unreadable
    /// file, invalid TOML, a `[[partner]]` entry missing `domain`/`endpoint`, an unparsable
    /// `endpoint`, a missing/empty `pinned_identity` (ADR 0017 C4), or a duplicate `domain`. There
    /// is no partial-success mode — one bad entry rejects the whole file, matching this crate's
    /// existing config-loading posture (`config::Config::load`'s "any malformed TOML file is a
    /// hard Err, never a silent fallback").
    pub fn load(path: &str) -> Result<Self, DiscoveryError> {
        let contents = std::fs::read_to_string(path).map_err(|source| DiscoveryError::Io {
            path: path.to_string(),
            source,
        })?;
        Self::from_toml_str(&contents, path)
    }

    /// Parse already-read TOML contents. Split out from [`StaticMap::load`] so tests can exercise
    /// malformed-TOML and validation rejection without touching the filesystem; `path` is used
    /// only to label errors.
    pub fn from_toml_str(contents: &str, path: &str) -> Result<Self, DiscoveryError> {
        let file: StaticMapFile =
            toml::from_str(contents).map_err(|source| DiscoveryError::Toml {
                path: path.to_string(),
                source,
            })?;

        let mut entries = HashMap::with_capacity(file.partner.len());
        for p in file.partner {
            if p.pinned_identity.trim().is_empty() {
                return Err(DiscoveryError::MissingPin { domain: p.domain });
            }
            let (host, port) =
                parse_host_port(&p.endpoint).map_err(|reason| DiscoveryError::InvalidEndpoint {
                    domain: p.domain.clone(),
                    endpoint: p.endpoint.clone(),
                    reason,
                })?;
            let endpoint = Endpoint {
                host,
                port,
                priority: 0,
                weight: 0,
                pinned_identity: Some(p.pinned_identity),
                policy: p.policy,
            };
            // DNS domains are case-insensitive (RFC 4343). Normalize to ASCII-lowercase before
            // both insertion and (in `resolve`, below) lookup, so a differently-cased entry for
            // the same real domain is caught as a `DuplicateDomain` here rather than silently
            // creating two live, potentially-conflicting `pinned_identity` trust pins for what
            // DNS treats as a single partner — and so an operator-written mixed-case `domain`
            // (e.g. `"Org-A.test"`) still resolves for a lookup of `"org-a.test"`. Mirrors
            // `link::peer_identities`'s `to_ascii_lowercase`/`eq_ignore_ascii_case` handling of
            // the same DNS case-insensitivity elsewhere in this crate.
            let key = p.domain.to_ascii_lowercase();
            if entries.insert(key, endpoint).is_some() {
                return Err(DiscoveryError::DuplicateDomain(p.domain));
            }
        }
        Ok(Self { entries })
    }
}

#[async_trait]
impl Discovery for StaticMap {
    async fn resolve(&self, domain: &str) -> Result<Vec<Endpoint>, DiscoveryError> {
        // No `.await` on anything but this fn's own signature, no I/O, no resolver field to
        // consult — a HashMap lookup is the entire body, TODAY. Keep it that way: `StaticMap`
        // holding no resolver-shaped field (checked by `structural_tests`, below) means this
        // method has nothing DNS-capable to reach *through a field* — it does NOT mean the method
        // body itself is incapable of an ad hoc network call typed directly into it (an inline
        // `tokio::net::lookup_host(...)`, say), which needs no field at all. That gap is real: a
        // mutation test that inserted exactly such a call here caused zero failures in this
        // module's then-existing tests. `tests/federation_discovery.rs`'s
        // `airgap_syscall_probe::static_map_resolve_makes_zero_getaddrinfo_calls` is what actually
        // proves this method makes no hostname-resolution call, at the syscall level, regardless
        // of how one might be written into it — read its doc comment before trusting this
        // comment's "the entire body" claim on faith.
        //
        // Lowercase the query key to match how `from_toml_str` normalizes entries — DNS domains
        // are case-insensitive, so `resolve("ORG-A.TEST")` must hit the same entry as
        // `resolve("org-a.test")`.
        match self.entries.get(&domain.to_ascii_lowercase()) {
            Some(endpoint) => Ok(vec![endpoint.clone()]),
            None => Err(DiscoveryError::NotFound(domain.to_string())),
        }
    }
}

/// Split `"host:port"` into `(host, port)`. Accepts a bracketed IPv6 literal (`"[::1]:8444"`) for
/// completeness; the common case is a plain hostname or IPv4 literal.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| "expected \"host:port\"".to_string())?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port {port_str:?}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok((host.to_string(), port))
}

// ---------------------------------------------------------------------------------------------
// SrvDiscovery
// ---------------------------------------------------------------------------------------------

/// One raw SRV record as returned by a [`SrvResolver`], before this module's priority/weight
/// ordering and [`Endpoint`] conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSrv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// The DNS backend [`SrvDiscovery`] queries. A trait so tests can inject a stub resolver instead
/// of making real DNS queries (the task's "SRV priority/weight ordering against a stub resolver"
/// requirement) — the real backend is [`HickoryResolver`].
///
/// A clean "no such record" answer (NXDOMAIN, or a positive response with zero SRV records) MUST
/// be returned as `Ok(vec![])`, never as an `Err` — [`SrvDiscovery::resolve`] is the single place
/// that turns "zero records" into the fail-closed [`DiscoveryError::NoSrvRecord`], regardless of
/// which backend produced the empty result, so that behavior doesn't depend on a specific
/// resolver's error taxonomy.
#[async_trait]
pub trait SrvResolver: Send + Sync {
    /// Look up all SRV records for `query` (already the full
    /// `_meridian-fed._tcp.<domain>` name — this trait does no name construction of its own).
    async fn lookup_srv(&self, query: &str) -> Result<Vec<RawSrv>, DiscoveryError>;
}

/// DNS SRV [`Discovery`]: resolves `_meridian-fed._tcp.<domain>` (RFC 2782) through an injectable
/// [`SrvResolver`]. Refuses (fails closed) rather than falling back to A/AAAA when no SRV record
/// exists — see this module's doc comment on the resolved `TODO: confirm`.
pub struct SrvDiscovery<R: SrvResolver> {
    resolver: R,
}

impl<R: SrvResolver> SrvDiscovery<R> {
    /// Build an `SrvDiscovery` over an arbitrary [`SrvResolver`] — the injection point tests use
    /// to supply a stub instead of `HickoryResolver`.
    pub fn with_resolver(resolver: R) -> Self {
        Self { resolver }
    }
}

impl SrvDiscovery<HickoryResolver> {
    /// Build an `SrvDiscovery` backed by the real system DNS resolver (`/etc/resolv.conf` on
    /// Unix). This is the only constructor in this module that can perform a real DNS query.
    pub fn new() -> Result<Self, DiscoveryError> {
        Ok(Self::with_resolver(HickoryResolver::from_system_conf()?))
    }
}

#[async_trait]
impl<R: SrvResolver> Discovery for SrvDiscovery<R> {
    async fn resolve(&self, domain: &str) -> Result<Vec<Endpoint>, DiscoveryError> {
        let query = format!("_meridian-fed._tcp.{domain}");
        let mut records = self.resolver.lookup_srv(&query).await?;
        if records.is_empty() || records.iter().all(|r| r.target == ".") {
            // RFC 2782: a single SRV RR with `Target == "."` is the standard way to explicitly
            // declare "service not available at this domain" — distinct from publishing no
            // record at all, but equivalent for this fail-closed discovery layer's purposes.
            // Without this check a lone `Target = "."` record would survive the empty-vec check
            // above, get sorted, and be returned as a bogus `Ok(vec![Endpoint{host: ".", port:
            // 0, ..}])` instead of the `NoSrvRecord` refusal every other "not available" case
            // produces.
            return Err(DiscoveryError::NoSrvRecord(domain.to_string()));
        }

        // RFC 2782 ordering: try the lowest `priority` first. Within a priority tier RFC 2782
        // specifies weighted-random selection (a domain administrator's stated preference among
        // otherwise-equal targets, not a security property this project relies on). This
        // implementation sorts by descending `weight` instead of drawing a weighted-random
        // permutation — a deliberate, deterministic simplification for a bilateral federation
        // deployment (ADR 0002: 2-200 orgs, not public internet-scale load balancing), and it is
        // what makes the ordering assertion in `tests/federation_discovery.rs` a stable, non-flaky
        // check rather than a statistical one. `priority`/`weight` still ride along on every
        // `Endpoint` so a caller that wants true RFC 2782 weighted-random selection later can
        // implement it without another discovery-layer change.
        records.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        Ok(records
            .into_iter()
            .map(|r| Endpoint {
                host: r.target,
                port: r.port,
                priority: r.priority,
                weight: r.weight,
                // SRV is unauthenticated discovery only, never a trust source (ADR 0017 (a)) — no
                // pinned identity to carry. Certificate validation for an SRV-resolved endpoint
                // targets the hint `domain` itself (WebPKI mode).
                pinned_identity: None,
                // SRV carries no federation-policy information.
                policy: None,
            })
            .collect())
    }
}

/// [`SrvResolver`] backed by `hickory-resolver`'s Tokio resolver, using the host's system DNS
/// configuration (`/etc/resolv.conf` on Unix). The only type in this module that actually performs
/// a DNS query.
pub struct HickoryResolver(Arc<hickory_resolver::TokioResolver>);

impl HickoryResolver {
    /// Build a resolver from the system's DNS configuration. Fails closed: a resolver that cannot
    /// be constructed (e.g. no usable `/etc/resolv.conf`) is a hard `Err`, never a silent
    /// "resolves nothing" stand-in that could be mistaken for a clean NXDOMAIN.
    pub fn from_system_conf() -> Result<Self, DiscoveryError> {
        let builder = hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| DiscoveryError::ResolverInit(e.to_string()))?;
        let resolver = builder
            .build()
            .map_err(|e| DiscoveryError::ResolverInit(e.to_string()))?;
        Ok(Self(Arc::new(resolver)))
    }
}

#[async_trait]
impl SrvResolver for HickoryResolver {
    async fn lookup_srv(&self, query: &str) -> Result<Vec<RawSrv>, DiscoveryError> {
        use hickory_resolver::proto::rr::RData;

        match self.0.srv_lookup(query).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::SRV(srv) => Some(RawSrv {
                        priority: srv.priority,
                        weight: srv.weight,
                        port: srv.port,
                        target: srv.target.to_utf8(),
                    }),
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => {
                // A clean "no SRV record" answer — see this trait's doc comment on why this is
                // `Ok(vec![])`, not an `Err`.
                Ok(Vec::new())
            }
            Err(e) => Err(DiscoveryError::Resolver {
                domain: query.to_string(),
                reason: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod structural_tests {
    //! Compile-time/structural proof that [`StaticMap`] never implements or holds this module's
    //! own `SrvResolver` abstraction — one leg of task 2.5's "air-gap assertion", complementing
    //! `tests/federation_discovery.rs`'s dispatch-level `static_mode_performs_zero_dns_lookups`
    //! test and its syscall-level
    //! `airgap_syscall_probe::static_map_resolve_makes_zero_getaddrinfo_calls`. None of the three
    //! alone is the whole proof — see each test's own doc comment for exactly what it does and
    //! does not cover; in particular, this module proves `StaticMap` cannot reach a DNS resolver
    //! *through this crate's own resolver abstraction*, not that its `resolve` method body is
    //! incapable of an ad hoc network call written directly into it (that's the syscall-level
    //! test's job).
    use super::*;

    #[test]
    fn static_map_does_not_implement_srv_resolver() {
        // `StaticMap` never implements the trait through which any lookup in this module reaches
        // a real resolver — it isn't merely "unused," the capability doesn't exist on the type.
        // A future change that gave `StaticMap` a `SrvResolver` impl (e.g. as a fallback path)
        // would fail this at COMPILE time, not at test-run time.
        static_assertions::assert_not_impl_any!(StaticMap: SrvResolver);
    }

    #[test]
    fn static_map_has_no_resolver_shaped_field() {
        // `StaticMap`'s only field is `entries: HashMap<String, Endpoint>` (see its definition
        // above) — its size is exactly that HashMap's size. Every resolver-capable type in this
        // module (`HickoryResolver`, any `Arc<dyn SrvResolver>`) is itself nonzero-sized (at
        // minimum a pointer), so a future edit that gave `StaticMap` such a field — even one never
        // read on the `resolve` fast path — would grow its size and fail this assertion. A
        // regression guard for the structural claim above, not a substitute for it.
        assert_eq!(
            std::mem::size_of::<StaticMap>(),
            std::mem::size_of::<HashMap<String, Endpoint>>(),
            "StaticMap must hold nothing beyond its domain->Endpoint map — a resolver-shaped \
             field here would silently reopen the air-gap invariant task 2.5 exists to close"
        );
    }
}
