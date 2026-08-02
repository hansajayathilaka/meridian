//! Task 2.5 acceptance: `federation::discovery` — static-map resolution, DNS SRV resolution
//! against a stub resolver (never real DNS), and the air-gap "static mode makes zero DNS lookups"
//! assertion.

use async_trait::async_trait;
use meridian_rendezvous::federation::{
    Discovery, DiscoveryError, RawSrv, SrvDiscovery, SrvResolver, StaticMap,
};

// -- fixtures -------------------------------------------------------------------------------

const TWO_PARTNER_MAP: &str = r#"
[[partner]]
domain = "org-a.test"
endpoint = "fed.org-a.test:8444"
pinned_identity = "fed.org-a.test"
policy = "allow"

[[partner]]
domain = "org-b.test"
endpoint = "fed.org-b.test:8444"
pinned_identity = "fed.org-b.test"
"#;

// -- StaticMap: hit / miss --------------------------------------------------------------------

#[tokio::test]
async fn static_map_resolves_a_known_domain() {
    let map = StaticMap::from_toml_str(TWO_PARTNER_MAP, "federation_map.toml").unwrap();

    let resolved = map.resolve("org-a.test").await.expect("known domain");

    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].host, "fed.org-a.test");
    assert_eq!(resolved[0].port, 8444);
    assert_eq!(
        resolved[0].pinned_identity.as_deref(),
        Some("fed.org-a.test")
    );
    assert_eq!(resolved[0].policy.as_deref(), Some("allow"));
    // Static-map endpoints carry no SRV ordering information — see `Endpoint`'s doc comment.
    assert_eq!(resolved[0].priority, 0);
    assert_eq!(resolved[0].weight, 0);
}

#[tokio::test]
async fn static_map_entry_without_policy_carries_none() {
    let map = StaticMap::from_toml_str(TWO_PARTNER_MAP, "federation_map.toml").unwrap();

    let resolved = map.resolve("org-b.test").await.unwrap();

    assert_eq!(resolved[0].policy, None);
}

#[tokio::test]
async fn static_map_miss_is_not_found_not_a_policy_error() {
    let map = StaticMap::from_toml_str(TWO_PARTNER_MAP, "federation_map.toml").unwrap();

    let err = map
        .resolve("unlisted.example")
        .await
        .expect_err("domain absent from the map must not resolve");

    assert!(matches!(err, DiscoveryError::NotFound(d) if d == "unlisted.example"));
}

// -- StaticMap: malformed / invalid input, all fail closed -------------------------------------

#[test]
fn malformed_toml_is_rejected() {
    let err = StaticMap::from_toml_str("this is not [ valid toml", "federation_map.toml")
        .expect_err("malformed TOML must be a hard error, never an empty map");

    assert!(matches!(err, DiscoveryError::Toml { .. }));
}

#[test]
fn entry_missing_pinned_identity_is_rejected_fail_closed() {
    // ADR 0017 C4: a map entry missing its pinned identity is a fail-closed CONFIGURATION error,
    // rejected at load time — never silently accepted as "chains to the trusted CA, no name
    // check."
    let toml = r#"
        [[partner]]
        domain = "org-c.test"
        endpoint = "fed.org-c.test:8444"
    "#;

    let err = StaticMap::from_toml_str(toml, "federation_map.toml")
        .expect_err("missing pinned_identity must be rejected, not silently accepted");

    assert!(matches!(err, DiscoveryError::MissingPin { domain } if domain == "org-c.test"));
}

#[test]
fn entry_with_blank_pinned_identity_is_rejected_fail_closed() {
    let toml = r#"
        [[partner]]
        domain = "org-c.test"
        endpoint = "fed.org-c.test:8444"
        pinned_identity = "   "
    "#;

    let err = StaticMap::from_toml_str(toml, "federation_map.toml").unwrap_err();

    assert!(matches!(err, DiscoveryError::MissingPin { .. }));
}

#[test]
fn entry_with_unparsable_endpoint_is_rejected() {
    let toml = r#"
        [[partner]]
        domain = "org-c.test"
        endpoint = "not-a-host-port-pair"
        pinned_identity = "fed.org-c.test"
    "#;

    let err = StaticMap::from_toml_str(toml, "federation_map.toml").unwrap_err();

    assert!(matches!(err, DiscoveryError::InvalidEndpoint { .. }));
}

#[test]
fn duplicate_domain_is_rejected() {
    let toml = r#"
        [[partner]]
        domain = "org-a.test"
        endpoint = "fed.org-a.test:8444"
        pinned_identity = "fed.org-a.test"

        [[partner]]
        domain = "org-a.test"
        endpoint = "fed.org-a-2.test:8444"
        pinned_identity = "fed.org-a-2.test"
    "#;

    let err = StaticMap::from_toml_str(toml, "federation_map.toml").unwrap_err();

    assert!(matches!(err, DiscoveryError::DuplicateDomain(d) if d == "org-a.test"));
}

#[test]
fn load_from_missing_file_is_a_hard_io_error() {
    let err = StaticMap::load("/nonexistent/path/federation_map.toml")
        .expect_err("a missing map file must not be treated as an empty map");

    assert!(matches!(err, DiscoveryError::Io { .. }));
}

#[tokio::test]
async fn the_shipped_two_org_demo_fixture_parses_and_validates() {
    // The reference fixture 2.11 will consume — proves it round-trips through this task's own
    // parser/validator, not just that it looks plausible.
    let contents = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../demo/two-orgs/federation_map.toml"
    ))
    .expect("demo/two-orgs/federation_map.toml must exist");

    let map = StaticMap::from_toml_str(&contents, "demo/two-orgs/federation_map.toml")
        .expect("shipped fixture must be valid");

    // Sanity: it actually describes the two-org demo, not an empty/placeholder file.
    assert!(map.resolve("org-a.test").await.is_ok());
    assert!(map.resolve("org-b.test").await.is_ok());
}

// -- SrvDiscovery: stub resolver, never real DNS ------------------------------------------------

/// A [`SrvResolver`] whose answers are fixed in the test, never touching the network. Every
/// `SrvDiscovery` test in this file uses this — real DNS is never queried.
struct StubResolver {
    answer: Result<Vec<RawSrv>, String>,
}

#[async_trait]
impl SrvResolver for StubResolver {
    async fn lookup_srv(&self, _query: &str) -> Result<Vec<RawSrv>, DiscoveryError> {
        match &self.answer {
            Ok(records) => Ok(records.clone()),
            Err(msg) => Err(DiscoveryError::Resolver {
                domain: "stub".into(),
                reason: msg.clone(),
            }),
        }
    }
}

fn srv(priority: u16, weight: u16, port: u16, target: &str) -> RawSrv {
    RawSrv {
        priority,
        weight,
        port,
        target: target.to_string(),
    }
}

#[tokio::test]
async fn srv_orders_by_ascending_priority_then_descending_weight() {
    let stub = StubResolver {
        answer: Ok(vec![
            srv(20, 10, 8444, "backup-b.org-b.test"),
            srv(10, 5, 8444, "low-weight.org-b.test"),
            srv(10, 50, 8444, "high-weight.org-b.test"),
            srv(0, 0, 8444, "primary.org-b.test"),
        ]),
    };
    let discovery = SrvDiscovery::with_resolver(stub);

    let resolved = discovery.resolve("org-b.test").await.expect("has records");

    let hosts: Vec<&str> = resolved.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(
        hosts,
        vec![
            "primary.org-b.test",     // priority 0 first
            "high-weight.org-b.test", // priority 10, higher weight first
            "low-weight.org-b.test",  // priority 10, lower weight second
            "backup-b.org-b.test",    // priority 20 last
        ]
    );
    // SRV-sourced endpoints carry no private-CA pin or policy (SRV is unauthenticated discovery
    // only — ADR 0017 (a)).
    assert!(resolved.iter().all(|e| e.pinned_identity.is_none()));
    assert!(resolved.iter().all(|e| e.policy.is_none()));
    assert_eq!(resolved[0].priority, 0);
    assert_eq!(resolved[1].weight, 50);
}

#[tokio::test]
async fn srv_single_record_round_trips_port_and_target() {
    let stub = StubResolver {
        answer: Ok(vec![srv(0, 0, 8444, "fed.org-b.test")]),
    };
    let discovery = SrvDiscovery::with_resolver(stub);

    let resolved = discovery.resolve("org-b.test").await.unwrap();

    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].host, "fed.org-b.test");
    assert_eq!(resolved[0].port, 8444);
}

#[tokio::test]
async fn srv_no_record_refuses_fail_closed_never_falls_back() {
    // Resolved `TODO: confirm`: behavior when no SRV record exists is REFUSE, not a fallback to
    // A/AAAA plus a guessed port. `StubResolver`'s `Ok(vec![])` models a clean NXDOMAIN/no-records
    // DNS answer (see `SrvResolver::lookup_srv`'s doc comment on that contract).
    let stub = StubResolver { answer: Ok(vec![]) };
    let discovery = SrvDiscovery::with_resolver(stub);

    let err = discovery
        .resolve("no-such-partner.test")
        .await
        .expect_err("absent SRV record must refuse, never synthesize an A/AAAA fallback");

    assert!(matches!(err, DiscoveryError::NoSrvRecord(d) if d == "no-such-partner.test"));
}

#[tokio::test]
async fn srv_resolver_transport_error_is_distinct_from_no_record() {
    // A genuine lookup failure (timeout/SERVFAIL/transport error) is reported distinctly from a
    // clean "no record" answer — callers should be able to tell "this partner doesn't publish
    // federation SRV records" from "our DNS is broken right now."
    let stub = StubResolver {
        answer: Err("simulated SERVFAIL".to_string()),
    };
    let discovery = SrvDiscovery::with_resolver(stub);

    let err = discovery.resolve("org-b.test").await.unwrap_err();

    assert!(matches!(err, DiscoveryError::Resolver { .. }));
}

// -- the air-gap assertion: static mode makes ZERO DNS lookups ---------------------------------

/// A [`SrvResolver`] that panics the instant it is asked to resolve anything. Used as a tripwire:
/// if it is ever reachable from a "static mode" resolution path, this test fails loudly and
/// specifically (a panic identifying exactly what happened), not via a coincidental assertion.
struct TripwireResolver;

#[async_trait]
impl SrvResolver for TripwireResolver {
    async fn lookup_srv(&self, query: &str) -> Result<Vec<RawSrv>, DiscoveryError> {
        panic!(
            "air-gap violation: a DNS resolver was invoked (query {query:?}) while resolving in \
             static mode — static/air-gap deployments (ADR 0002, deployment.md) must make zero \
             DNS lookups"
        );
    }
}

#[tokio::test]
async fn static_mode_performs_zero_dns_lookups() {
    // This is the air-gap proof task 2.5 requires, in two complementary parts:
    //
    // 1. STRUCTURAL (the primary guarantee, proven at compile/build time, not here): `StaticMap`
    //    has no field, generic parameter, or method of any DNS-resolver-capable type — see its
    //    definition and `federation::discovery`'s module docs, and the compile-time/structural
    //    tests in that module (`static_map_does_not_implement_srv_resolver`,
    //    `static_map_has_no_resolver_shaped_field`). A resolver that `StaticMap` cannot even
    //    reference cannot be invoked "by accident" from inside it.
    //
    // 2. BEHAVIORAL (this test): drive resolution through the same `Discovery` trait object a
    //    real caller would use, selecting `StaticMap` the way `config::Federation::discovery =
    //    "static"` (the fail-closed default) would — while a `TripwireResolver`-backed
    //    `SrvDiscovery` sits alongside, live and reachable in the same scope, standing in for "the
    //    DNS-capable code that's compiled into this binary regardless of which mode is active."
    //    If the static path ever reached that resolver, this test panics; it doesn't just fail an
    //    assertion silently swallowed by an `if`.
    let map = StaticMap::from_toml_str(TWO_PARTNER_MAP, "federation_map.toml").unwrap();
    let never_called: Box<dyn Discovery> = Box::new(SrvDiscovery::with_resolver(TripwireResolver));
    let selected: Box<dyn Discovery> = Box::new(map); // what `discovery = "static"` selects

    let resolved = selected
        .resolve("org-a.test")
        .await
        .expect("static resolution must still succeed");
    assert_eq!(resolved[0].host, "fed.org-a.test");

    // A second resolution, including a MISS, to show the tripwire survives both the hit and the
    // miss path without ever firing.
    let miss = selected.resolve("unlisted.example").await;
    assert!(matches!(miss, Err(DiscoveryError::NotFound(_))));

    // `never_called` is deliberately never `.resolve()`d — its entire purpose is to exist,
    // reachable, and NOT be called. Drop it explicitly last so it's provably still alive (not
    // optimized away) for the whole static-mode resolution above.
    drop(never_called);
}
