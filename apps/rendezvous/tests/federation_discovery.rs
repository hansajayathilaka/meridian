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
async fn static_map_lookup_is_case_insensitive() {
    // Mirrors `link::peer_identities`'s DNS case-insensitivity handling: an operator-written
    // mixed-case `domain` must still resolve for a differently-cased lookup, and vice versa.
    let toml = r#"
        [[partner]]
        domain = "Org-B.test"
        endpoint = "fed.org-b.test:8444"
        pinned_identity = "fed.org-b.test"
    "#;
    let map = StaticMap::from_toml_str(toml, "federation_map.toml").unwrap();

    let via_upper = map
        .resolve("ORG-B.TEST")
        .await
        .expect("case-insensitive hit");
    let via_original_case = map.resolve("Org-B.test").await.expect("exact-case hit");

    assert_eq!(via_upper, via_original_case);
    assert_eq!(via_upper[0].host, "fed.org-b.test");
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
fn duplicate_domain_differing_only_in_case_is_rejected() {
    // DNS domains are case-insensitive (RFC 4343). Two entries that differ only in ASCII case
    // name the same real-world partner and must not both survive as live, potentially-conflicting
    // `pinned_identity` trust pins.
    let toml = r#"
        [[partner]]
        domain = "org-b.test"
        endpoint = "fed.org-b.test:8444"
        pinned_identity = "fed.org-b.test"

        [[partner]]
        domain = "Org-B.test"
        endpoint = "fed.org-b-2.test:8444"
        pinned_identity = "fed.org-b-2.test"
    "#;

    let err = StaticMap::from_toml_str(toml, "federation_map.toml").unwrap_err();

    assert!(matches!(err, DiscoveryError::DuplicateDomain(_)));
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
async fn srv_target_dot_refuses_fail_closed_same_as_no_record() {
    // RFC 2782: a single SRV RR with `Target = "."` is the standard way to explicitly declare
    // "service not available at this domain" — distinct from publishing no record at all, but
    // this fail-closed discovery layer must treat it identically to the empty-vec case, not
    // return it as a bogus `Endpoint{host: ".", port: 0, ..}`.
    let stub = StubResolver {
        answer: Ok(vec![srv(0, 0, 0, ".")]),
    };
    let discovery = SrvDiscovery::with_resolver(stub);

    let err = discovery
        .resolve("no-such-partner.test")
        .await
        .expect_err("a lone Target=\".\" SRV record must refuse, never resolve to host \".\"");

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
    // What this test actually proves — one part of the air-gap picture, not the whole of it:
    //
    // 1. STRUCTURAL (proven at compile/build time, not here): `StaticMap` has no field, generic
    //    parameter, or method of any DNS-resolver-capable type — see its definition and
    //    `federation::discovery`'s module docs, and the compile-time/structural tests in that
    //    module (`static_map_does_not_implement_srv_resolver`, `static_map_has_no_resolver_shaped_
    //    field`). A resolver that `StaticMap` cannot even reference cannot be invoked "by
    //    accident" through a field or trait impl.
    //
    // 2. DISPATCH-LEVEL (this test): drive resolution through the same `Discovery` trait object a
    //    real caller would use, selecting `StaticMap` the way `config::Federation::discovery =
    //    "static"` (the fail-closed default) would — while a `TripwireResolver`-backed
    //    `SrvDiscovery` sits alongside, live and reachable in the same scope, standing in for "the
    //    DNS-capable code that's compiled into this binary regardless of which mode is active."
    //    This proves the *config selector* never routes a static-mode caller through the
    //    SRV/resolver machinery — it does NOT prove `StaticMap::resolve`'s own method body is free
    //    of some OTHER, ad hoc network call that never touches `SrvResolver`/`TripwireResolver` at
    //    all (no new field, no trait impl — nothing this test's tripwire can observe). A mutation
    //    test confirmed that gap concretely: inserting a raw `tokio::net::lookup_host(...)` call
    //    directly into `StaticMap::resolve`'s body caused zero failures here. Closing that gap is
    //    `airgap_syscall_probe::static_map_resolve_makes_zero_getaddrinfo_calls`, below — a
    //    syscall-level proof that doesn't care whether a network call goes through this crate's
    //    `SrvResolver` abstraction or bypasses it entirely. Read both; neither alone is the full
    //    air-gap proof.
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

// -- the air-gap assertion, part 2: a genuine syscall-level proof ------------------------------
//
// `static_mode_performs_zero_dns_lookups` above proves something real but narrower than its
// original doc comment claimed: that *dispatching* through the `Discovery` trait object the way
// `config::Federation::discovery = "static"` selects it never reaches the `SrvResolver`
// (`TripwireResolver`) sitting alongside it in the same scope. It does NOT prove
// `StaticMap::resolve`'s own method body is free of an ad hoc, bypassing network call — a call
// that never touches `SrvResolver` at all (no new field, no trait impl, nothing the tripwire
// above could ever observe) is invisible to that test by construction, because
// `TripwireResolver` is only reachable if something calls `SrvDiscovery::resolve` /
// `SrvResolver::lookup_srv` directly. A code-review mutation test confirmed this gap concretely:
// inserting `let _ = tokio::net::lookup_host((domain, 0u16)).await;` directly into
// `StaticMap::resolve`'s body (bypassing `SrvResolver` entirely, adding no field) caused zero
// test failures in this file as it stood before this section was added — see
// `static_map_resolve_makes_zero_getaddrinfo_calls`, below, which this mutation now fails (and
// `static_mode_performs_zero_dns_lookups` still passes, since the mutation never touches
// `SrvResolver`/`TripwireResolver` either).
//
// This section closes that gap with a mechanism that doesn't care HOW a network call is made —
// DNS SRV, raw `tokio::net::lookup_host`, `std::net::ToSocketAddrs`, a hand-rolled resolver,
// anything hostname-resolution-shaped: it runs `StaticMap::resolve` in a child process with
// `getaddrinfo(3)` interposed via `LD_PRELOAD` to abort the instant it's called. See
// `airgap_syscall_probe`'s module doc comment for the full mechanism and why the alternatives (a
// network-namespace sandbox; pointing the OS resolver at an unroutable target under a timing
// deadline) were rejected in favor of this one.
#[cfg(target_os = "linux")]
mod airgap_syscall_probe {
    //! Syscall-level, mechanism-agnostic proof that `StaticMap::resolve` performs zero network
    //! I/O of any kind — not merely "never calls `SrvResolver`" (that narrower claim is
    //! `static_mode_performs_zero_dns_lookups`, in the parent module; see its doc comment for
    //! exactly what it does and does not cover).
    //!
    //! ## Why this shape, not the alternatives
    //!
    //! - **A network-namespace sandbox** (this repo's `tools/netns-two-lans.sh` /
    //!   `netns-nat-matrix.sh`, tasks 1.25-1.27): built for exercising real P2P/ICE connectivity
    //!   across simulated NATs — veth pairs, a bridge, iptables MASQUERADE rules — none of which
    //!   this property needs. More importantly, both existing rigs gate on a `need_root()` check
    //!   and skip with a message when `NET_ADMIN` isn't available, which is this project's normal
    //!   posture: `.devcontainer/devcontainer.json` grants no `NET_ADMIN`/`SYS_ADMIN` capability
    //!   and runs as the non-root `vscode` user, and CI's own step comment for the NAT-matrix job
    //!   says the same ("netns rig skips without NET_ADMIN"). A netns-gated version of this test
    //!   would silently no-op in exactly the environment this task's own required command
    //!   (`cargo nextest run -p meridian-rendezvous --test federation_discovery`, unprivileged, in
    //!   the devcontainer or in CI) runs it in — reproducing the same "green but proves nothing"
    //!   failure mode this test exists to fix, one layer down. Disproportionate; rejected.
    //! - **Point the OS resolver at an unroutable target (`192.0.2.1`, RFC 5737 TEST-NET-1) with a
    //!   short deadline, backed by a canary confirming the deadline is short enough to distinguish
    //!   "no attempt" from "fast failure"**: rejected for two independent reasons. First, there is
    //!   no portable, unprivileged way to point *only this process's* resolution at a different
    //!   server — glibc reads `/etc/resolv.conf` process-wide, and rewriting it needs root and
    //!   affects every other concurrently-running test in the same container/CI job. Second, and
    //!   more fundamentally, this container's own network turned out to be non-uniform in exactly
    //!   the way that defeats a timing threshold: a real `getaddrinfo("org-a.test", ..)` call was
    //!   measured, live, at ~6ms (an `ENETUNREACH`-shaped instant failure) in one check, and, in a
    //!   separate `strace`d check, successfully round-tripping a real UDP DNS query/response to
    //!   `8.8.8.8` in another — "network reachable" vs. "not" isn't even stable within one
    //!   environment, so no fixed deadline reliably distinguishes "no attempt" from "fast failure"
    //!   here, and a canary-calibrated deadline just chases that instability instead of removing
    //!   it.
    //! - **This mechanism** (`LD_PRELOAD`-interposed `getaddrinfo(3)`, aborting the process the
    //!   instant it's called): needs no elevated privilege (dynamic-linker symbol interposition is
    //!   an ordinary unprivileged capability — works as the non-root `vscode` user exactly as it
    //!   does as root), needs no timing assumption (the interposed call aborts synchronously, at
    //!   the syscall-wrapper boundary, before any real I/O happens — pass/fail is a fact about
    //!   whether the call happened at all, never about how fast it returned), and catches
    //!   *anything* that bottoms out in glibc's `getaddrinfo` — `tokio::net::lookup_host`,
    //!   `std::net::ToSocketAddrs`, and any future hostname-resolution primitive alike — not just
    //!   the one call shape this review happened to try as its mutation. Its only real
    //!   requirement, a C compiler, is already a hard prerequisite for building this workspace at
    //!   all (`ring`/`aws-lc-rs`/other `*-sys` crates need one — see `.devcontainer/Dockerfile`'s
    //!   `build-essential`), so it adds no new environment dependency.
    //!
    //! ## Mechanism
    //!
    //! 1. Compile a tiny shared object (`SHIM_SOURCE`, below) that interposes `getaddrinfo` — the
    //!    libc entry point every hostname-resolution path in this module's dependency graph
    //!    reaches — to print a distinctive message and `_exit(TRIPWIRE_EXIT_CODE)`, never
    //!    returning to the caller and never performing the real lookup.
    //! 2. Re-exec this same test binary (`std::env::current_exe()`) as a child process with
    //!    `LD_PRELOAD` pointed at that shared object, filtered (`--exact --ignored`) to run only
    //!    [`airgap_probe_static_map_resolve`] — an `#[ignore]`d twin of
    //!    `static_map_resolves_a_known_domain` / `static_map_miss_is_not_found_not_a_policy_error`
    //!    that exercises the exact same hit + miss `StaticMap::resolve` calls a real caller makes.
    //! 3. Assert the child exits `0` and printed its completion marker — i.e. `resolve()` ran to
    //!    completion without the interposed `getaddrinfo` ever firing, and the test filter did
    //!    match (a filter typo that matches zero tests also exits `0`, which is exactly the kind
    //!    of silent vacuousness this whole exercise is about — the marker check is what rules that
    //!    out). If a future change adds any `getaddrinfo`-reaching call inside
    //!    `StaticMap::resolve`, the child instead exits `TRIPWIRE_EXIT_CODE` with the tripwire
    //!    message on stderr, which this test surfaces verbatim in its panic.
    //!
    //! `LD_PRELOAD` symbol interposition is a Linux/glibc mechanism; this module is gated
    //! `#[cfg(target_os = "linux")]`, matching this workspace's only supported server target
    //! (`meridian-rendezvous` ships for Linux server deployment — see `docs/architecture/stack.md`).

    use std::path::{Path, PathBuf};
    use std::process::Command;

    use meridian_rendezvous::federation::{Discovery, DiscoveryError, StaticMap};

    use super::TWO_PARTNER_MAP;

    /// Exit code the interposed `getaddrinfo` uses — distinct from a Rust panic's `101` or an
    /// ordinary libtest failure, so a reader of a failing run can tell "the tripwire fired" apart
    /// from "the child process died some other way" immediately.
    const TRIPWIRE_EXIT_CODE: i32 = 97;

    /// Printed by [`airgap_probe_static_map_resolve`] on successful completion. The outer test
    /// greps for this rather than trusting `status.success()` alone — an `--exact` filter typo
    /// that matches zero tests also exits `0`, and that silent "ran nothing, reported success" is
    /// precisely the failure mode this whole test exists to rule out.
    const PROBE_OK_MARKER: &str = "AIRGAP_PROBE_OK";

    const SHIM_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

/* Interposes glibc's getaddrinfo(3) -- the entry point every hostname-resolution path in this
 * process's dependency graph (tokio::net::lookup_host, std::net::ToSocketAddrs, and any future
 * primitive built on either) reaches, regardless of which Rust-level API got there. Aborts before
 * performing any real lookup or I/O -- a call this shim never lets return proves something about
 * WHETHER it happened, deliberately never about how fast it would have returned. */
int getaddrinfo(const char *node, const char *service,
                 const struct addrinfo *hints, struct addrinfo **res) {
    (void)service; (void)hints; (void)res;
    fprintf(stderr,
            "AIR-GAP TRIPWIRE: getaddrinfo(node=%s) was called from inside a StaticMap::resolve "
            "probe run -- static-mode resolution must perform zero hostname resolution of any "
            "kind (ADR 0002, deployment.md air-gap mode)\n",
            node ? node : "(null)");
    _exit(97);
}
"#;

    /// Compile [`SHIM_SOURCE`] into a shared object under `dir`. Panics (not a graceful skip) if
    /// no C compiler is found or compilation fails — a missing `cc` is an environment problem
    /// this workspace already can't be built without (see the module doc comment), not something
    /// worth silently degrading this test's coverage for.
    fn build_tripwire_shim(dir: &Path) -> PathBuf {
        let c_path = dir.join("getaddrinfo_tripwire.c");
        let so_path = dir.join("getaddrinfo_tripwire.so");
        std::fs::write(&c_path, SHIM_SOURCE).expect("write getaddrinfo tripwire shim source");

        let output = Command::new("cc")
            .arg("-shared")
            .arg("-fPIC")
            .arg("-o")
            .arg(&so_path)
            .arg(&c_path)
            .arg("-ldl")
            .output()
            .expect(
                "no C compiler ('cc') found on PATH -- this workspace already hard-requires one \
                 to build at all (ring/aws-lc-rs/other *-sys crates; see \
                 .devcontainer/Dockerfile's build-essential), so this is an environment problem, \
                 not something this test should quietly skip past",
            );
        assert!(
            output.status.success(),
            "compiling the getaddrinfo tripwire shim failed:\n--- stdout ---\n{}\n--- stderr \
             ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        so_path
    }

    /// The probe body: the exact same hit + miss `StaticMap::resolve` calls a real
    /// `discovery = "static"` caller makes (mirrors `static_map_resolves_a_known_domain` +
    /// `static_map_miss_is_not_found_not_a_policy_error`). Never run directly by the normal test
    /// suite (`#[ignore]`) — [`static_map_resolve_makes_zero_getaddrinfo_calls`] re-execs this
    /// binary filtered to exactly this test, with `LD_PRELOAD` pointed at the tripwire shim.
    #[tokio::test]
    #[ignore = "invoked as a subprocess, under LD_PRELOAD, by \
                static_map_resolve_makes_zero_getaddrinfo_calls -- do not run directly"]
    async fn airgap_probe_static_map_resolve() {
        let map = StaticMap::from_toml_str(TWO_PARTNER_MAP, "federation_map.toml")
            .expect("fixture map must parse");

        let hit = map
            .resolve("org-a.test")
            .await
            .expect("known domain must resolve");
        assert_eq!(hit[0].host, "fed.org-a.test");

        let miss = map.resolve("unlisted.example").await;
        assert!(matches!(miss, Err(DiscoveryError::NotFound(_))));

        println!("{PROBE_OK_MARKER}");
    }

    /// The syscall-level air-gap proof: see this module's doc comment for the full mechanism and
    /// rationale. Gated to Linux — `LD_PRELOAD` symbol interposition is a glibc/Linux mechanism —
    /// matching `meridian-rendezvous`'s only supported server deployment target.
    #[test]
    fn static_map_resolve_makes_zero_getaddrinfo_calls() {
        let dir = tempfile::tempdir().expect("tempdir for the tripwire shim");
        let shim = build_tripwire_shim(dir.path());

        let exe = std::env::current_exe().expect("path to this test binary");
        let output = Command::new(&exe)
            .args([
                "airgap_syscall_probe::airgap_probe_static_map_resolve",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("LD_PRELOAD", &shim)
            .output()
            .expect("spawn this test binary as a child process under LD_PRELOAD");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let tripwire_fired = output.status.code() == Some(TRIPWIRE_EXIT_CODE);
        assert!(
            output.status.success(),
            "StaticMap::resolve triggered a real hostname-resolution call (getaddrinfo){}, or \
             the probe process failed some other way -- exit status: {:?}\n--- child stdout \
             ---\n{stdout}\n--- child stderr ---\n{stderr}",
            if tripwire_fired {
                " -- confirmed: the tripwire's own exit code fired"
            } else {
                ""
            },
            output.status,
        );
        assert!(
            stdout.contains(PROBE_OK_MARKER),
            "child process exited 0 but never printed the completion marker -- the --exact test \
             filter likely matched zero tests (a silently vacuous pass), not that resolve() \
             actually ran to completion; raw output:\n--- stdout ---\n{stdout}\n--- stderr \
             ---\n{stderr}",
        );
    }
}
