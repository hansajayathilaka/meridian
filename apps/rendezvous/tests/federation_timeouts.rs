//! Task 3.3 acceptance (review finding F3, blocking): a black-holed federation partner — one that
//! accepts a TCP connection but never completes TLS, or one that completes the s2s handshake but
//! never replies to the actual request — must not hang the originating client's WebSocket session,
//! and must not leak a pinned server-side task/link forever.
//!
//! Uses this crate's shared `tests/support/mod.rs` harness (task 3.4/F18: `TestCa`/`base_config`/
//! `spawn_c2s`/`Acct`, replacing the per-file `mint_identity`/etc. duplication this comment used to
//! describe) for the PKI + server-boot boilerplate, plus a small file-local `org_a_federation` for
//! this task's two timeout knobs.
//!
//! Each test maps to one of the task file's required cases:
//! - (a) a peer that accepts TCP but never completes TLS → `fetch_bundle` resolves to
//!   `fed_unreachable` within a bounded assert, not a hang.
//! - (b) a peer that completes the real mTLS+`FedHello` handshake but never answers the actual
//!   `fed_fetch_bundle` request → same outcome, same bound.
//! - (c) **the no-leak assertion** (explicitly flagged in the task file as "most likely to be
//!   asserted vacuously"): a client that vanishes mid-request does not free the server-side
//!   resource immediately (proving the eventual cleanup below is genuinely caused by the bounded
//!   timeout elapsing, not some other/vacuous mechanism), and the resource — `Metrics::
//!   connections_active`, this crate's existing allowlisted live-connection gauge — DOES return to
//!   baseline once that timeout elapses, not held open forever.
//! - (d) code-review follow-up on this same task (`route_foreign`'s outbound `send_frame` was left
//!   unbounded by the original diff — the one call site in this file that carries an actual
//!   authenticated user's routed envelope). See
//!   `route_foreigns_outbound_send_is_wrapped_under_the_request_deadline`'s own doc comment for why
//!   this is a source-level structural test rather than a live-socket one: a single
//!   `route_foreign` call sends at most one `link::MAX_FRAME_LEN`-bounded (1 MiB) frame over a
//!   *fresh* one-shot link, and on ordinary Linux TCP defaults (confirmed empirically against this
//!   very environment) a brand-new socket's send buffer is already sized in the multi-MiB range
//!   before a single byte is written — so a genuinely black-holed peer that "never drains its
//!   receive window" does not, in practice, make a single sub-1-MiB `write_all` block at the
//!   syscall level at all (`write()` only blocks once the LOCAL kernel send buffer itself is full,
//!   which never happens for a payload this small on a fresh connection, regardless of what the
//!   peer does or does not read). Shrinking the *dialer's own* `SO_SNDBUF` would reliably induce
//!   blocking well under `MAX_FRAME_LEN` (confirmed empirically) and could distinguish wrapped from
//!   unwrapped — but `link::dial`'s `TcpStream::connect` has no socket-options hook and
//!   `FederationLink` has no test-only constructor from a pre-configured stream, so that path isn't
//!   wired up today; adding one would be its own scope-creeping change with its own review burden.
//!   Given that, a live-socket test built on "shrink the peer's receive window" specifically would
//!   pass identically whether or not the fix is present — i.e. it would be exactly the "asserted
//!   vacuously" failure mode this task's own Risks section warns about — so this task's actual
//!   proof is source-level (the exact vulnerable call site is wrapped) plus a colocated
//!   `outbound.rs` unit test proving the wrapping mechanism itself genuinely bounds an
//!   indefinitely-pending send/recv future. The defensive value of the fix (never trust an
//!   unbounded network await, even one that doesn't block under today's typical buffer sizing) is
//!   real regardless of what a specific test environment's socket buffers happen to do.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use meridian_rendezvous::config::{DiscoveryMode, Federation, FederationPolicyMode};
use meridian_rendezvous::federation::FederationListener;
use meridian_rendezvous::{AppState, MemoryStore};
use meridian_signaling::SignalError;
use tokio::net::TcpListener;

mod support;
use support::{base_config, new_acct, spawn_c2s, write_federation_map, TestCa};

/// Server A's federation config, with THIS task's two knobs overridden — everything else mirrors
/// `federation_fetch.rs::org_a_federation`.
fn org_a_federation(
    dir: &Path,
    ca: &TestCa,
    a_domain: &str,
    b_domain: &str,
    b_fed_addr: SocketAddr,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
) -> Federation {
    let id = ca.issue(dir, a_domain);
    let map_path = write_federation_map(dir, &[(b_domain, b_fed_addr, b_domain)]);
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path_str().to_string(),
        key_path: id.key_path_str().to_string(),
        ca_bundle_path: id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        // A itself must be willing to dial `b_domain` at all — these tests are about A's outbound
        // TIMEOUT behavior, not its admission policy (that's task 3.1's own dedicated coverage).
        policy: FederationPolicyMode::Open,
        connect_timeout_ms,
        request_timeout_ms,
        ..Federation::default()
    }
}

// -- (a) TCP accepted, TLS never completed ---------------------------------------------------

#[tokio::test]
async fn tcp_accept_without_tls_handshake_returns_fed_unreachable_within_bound() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.3 timeouts a)");

    // A raw TCP listener standing in for B's s2s port: accepts every connection, then reads and
    // writes nothing at all — no TLS ServerHello ever arrives. A's raw `TcpStream::connect`
    // itself succeeds immediately (the OS completes the three-way handshake once the connection
    // is queued); what genuinely blocks is `dial`'s subsequent TLS step.
    let black_hole = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let black_hole_addr = black_hole.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = black_hole.accept().await {
            held.push(tcp); // keep the fd open; never read/write it
        }
    });

    let connect_timeout_ms = 300;
    let request_timeout_ms = 300;
    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        black_hole_addr,
        connect_timeout_ms,
        request_timeout_ms,
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice
        .connect(&a_c2s_url)
        .await
        .expect("connect + authenticate to A's own c2s listener");
    let target = [0x55u8; 32];

    // Bounded well above what a correctly-timing-out dial needs, well below "looks like a hang".
    let bound = Duration::from_millis(connect_timeout_ms + request_timeout_ms + 5_000);
    let outcome = tokio::time::timeout(
        bound,
        ac.fetch_bundle(target, Some("org-b.test".to_string()), false),
    )
    .await
    .expect(
        "fetch must resolve within a bounded time — a black-holed peer that never completes TLS \
         must not hang the client's request forever",
    );

    match outcome.unwrap_err() {
        SignalError::FedUnreachable { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedUnreachable, got {other:?}"),
    }
}

// -- (b) handshake completes, request never answered ------------------------------------------

#[tokio::test]
async fn peer_completes_hello_but_never_replies_returns_fed_unreachable_within_bound() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.3 timeouts b)");

    // B's own HONEST link-establishment identity: mTLS + FedHello complete for real via the same
    // `FederationListener` production code path (task 2.4). What never happens is B replying to
    // the `FedFetchBundle` request that follows — the request is read (consumed), then silence.
    let b_id = ca.issue(dir.path(), "org-b.test");
    let b_listener = FederationListener::bind("127.0.0.1:0", &b_id.paths(), "org-b.test", None)
        .await
        .expect("bind B's raw federation listener");
    let b_addr = b_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut link, _addr)) = b_listener.accept().await {
            tokio::spawn(async move {
                // Consume exactly one frame (A's FetchBundle request) and never answer.
                let _ = link.recv_frame().await;
                std::future::pending::<()>().await;
            });
        }
    });

    let connect_timeout_ms = 5_000; // generous — the real TCP connect + TLS + hello all succeed
    let request_timeout_ms = 300; // tight — only the actual fed request/reply is under test
    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        b_addr,
        connect_timeout_ms,
        request_timeout_ms,
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice
        .connect(&a_c2s_url)
        .await
        .expect("connect + authenticate to A's own c2s listener");
    let target = [0x66u8; 32];

    let bound = Duration::from_millis(request_timeout_ms + 5_000);
    let outcome = tokio::time::timeout(
        bound,
        ac.fetch_bundle(target, Some("org-b.test".to_string()), false),
    )
    .await
    .expect(
        "fetch must resolve within a bounded time — a peer that completes FedHello and then \
         goes silent must not hang the client's request forever",
    );

    match outcome.unwrap_err() {
        SignalError::FedUnreachable { hint, .. } => assert_eq!(hint, "org-b.test"),
        other => panic!("expected FedUnreachable, got {other:?}"),
    }
}

// -- (d) route_foreign's own outbound send is wrapped under the request deadline ------------

/// Code-review follow-up (finding F3, blocking): the original 3.3 diff wrapped every send/recv in
/// this file under `with_request_deadline` except `route_foreign`'s own outbound `send_frame` —
/// the one call site that carries an actual authenticated user's routed envelope. This is a
/// source-level structural test, not a live-socket one, deliberately: a live-socket version would
/// need a real black-holed peer's `write_all` to genuinely block at the syscall level, but
/// `write()` only blocks once the LOCAL kernel send buffer is full — and a single `route_foreign`
/// call sends at most one `link::MAX_FRAME_LEN`-bounded (1 MiB) frame over a *fresh* one-shot
/// link (`dial_foreign` is called anew each time, never reused — task 3.7's territory, not
/// touched here). On ordinary Linux TCP defaults, a brand-new socket's send buffer is already
/// sized in the multi-MiB range from the moment it connects (confirmed empirically against this
/// crate's own CI-shaped sandbox: a fresh loopback socket's `SO_SNDBUF` measured ~3.75 MiB before
/// a single byte was written, and a 900 KiB `write_all` against a peer whose receive window was
/// explicitly shrunk to a few KiB still completed in well under a second) — so a genuinely
/// black-holed peer that "never drains its receive window" does not, in practice, make a single
/// sub-1-MiB `write_all` block at all, regardless of whether the call is wrapped in a deadline.
/// Shrinking the *dialer's own* send buffer would reliably induce blocking and could distinguish
/// wrapped from unwrapped, but `link::dial`/`FederationLink` have no hook to configure that from a
/// test today — wiring one up would be its own scope-creeping change. Given that, a live-socket
/// test built on "shrink the peer's receive window" specifically would pass identically whether or
/// not this fix is present — the exact "asserted vacuously" failure mode task 3.3's own Risks
/// section warns about (confirmed directly: this same live-socket scenario was run against BOTH
/// the pre-fix and post-fix code during this task and passed either way, for the reason above).
///
/// The real proof is two-part instead: this test pins that the exact vulnerable call site is
/// wrapped (so the fix cannot silently regress), and `outbound.rs`'s own colocated unit test
/// (`with_request_deadline_bounds_a_future_that_never_resolves`) proves the wrapping mechanism
/// itself genuinely turns an indefinitely-pending send/recv future into a bounded
/// `RouteForeignError::Dial{source: LinkError::Timeout}` — deterministically, with no real socket
/// involved at all. Together they cover what a live-socket test would have claimed to prove,
/// without the vacuous-pass risk.
#[test]
fn route_foreigns_outbound_send_is_wrapped_under_the_request_deadline() {
    let src = include_str!("../src/federation/outbound.rs");
    let start = src
        .find("pub async fn route_foreign")
        .expect("route_foreign must exist in outbound.rs");
    // The next `pub async fn` after it is `reachable_foreign` — bound the search to exactly this
    // function's body, so this test cannot accidentally match `fetch_foreign_bundle`'s or
    // `reachable_foreign`'s already-wrapped sends instead of `route_foreign`'s own.
    let after = &src[start..];
    let end = after[1..]
        .find("\npub async fn ")
        .map(|i| i + 1)
        .unwrap_or(after.len());
    let body = &after[..end];

    assert!(
        !body.contains("fed_link\n        .send_frame(&out)\n        .await\n        .map_err(|source| RouteForeignError::Dial"),
        "route_foreign must not go back to sending `out` via a bare, unwrapped \
         `fed_link.send_frame(&out).await` — that is the exact F3 regression this test guards \
         against: {body}"
    );
    assert!(
        body.contains(
            "with_request_deadline(request_timeout, &expected_domain, fed_link.send_frame(&out))"
        ),
        "route_foreign's own outbound send_frame call must be wrapped under \
         with_request_deadline, exactly like fetch_foreign_bundle's and reachable_foreign's \
         already-bounded sends — a caller (ws.rs) must never be able to observe a difference \
         between this call site and those two: {body}"
    );
}

// -- (c) no-leak: the resource returns to baseline, but only once the deadline elapses --------

/// Test-engineer note (task 3.3's own Risks section flags this exact assertion as "most likely to
/// be asserted vacuously" — this is the deliberately non-vacuous version):
///
/// Server A's per-connection handling (`ws::serve`) is a single sequential task: while it is
/// blocked inside the outbound dial/exchange call, it is not concurrently polling the client's own
/// socket, so it cannot react to the client disconnecting *while still blocked* — it only notices
/// once that blocked call itself resolves (by succeeding, erroring, or — this task's whole point —
/// timing out). A version of this test that only asserted "eventually the count returns to 0"
/// would pass even if `dial`/`fetch_foreign_bundle` were NOT bounded at all, for the boring reason
/// that `tokio::test`'s runtime just keeps polling forever and the outer test timeout would fire
/// first, masking the real hang as "test timed out" rather than demonstrating a fix. The middle
/// assertion below closes that gap: it proves the resource is STILL held immediately after the
/// client vanishes (so the eventual drop to 0 cannot be coincidental or already-baseline), and ONLY
/// THEN waits for the configured deadline and confirms recovery — i.e. it measures a real
/// live-resource count (`Metrics::connections_active`, already Prometheus-exported) at three
/// distinct points in time, not just the final one.
#[tokio::test]
async fn client_disconnect_mid_wait_does_not_leak_the_blocked_server_task() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.3 timeouts c)");

    // Same black-holed-TCP peer shape as test (a): A's dial genuinely blocks for the full
    // connect/request timeout window, never completing TLS.
    let black_hole = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let black_hole_addr = black_hole.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = black_hole.accept().await {
            held.push(tcp);
        }
    });

    let connect_timeout_ms = 700;
    let request_timeout_ms = 700;
    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(
        dir.path(),
        &ca,
        "org-a.test",
        "org-b.test",
        black_hole_addr,
        connect_timeout_ms,
        request_timeout_ms,
    );
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let metrics = a_state.metrics.clone();
    let a_c2s_url = spawn_c2s(a_state).await;

    let alice = new_acct("org-a.test");
    let mut ac = alice
        .connect(&a_c2s_url)
        .await
        .expect("connect + authenticate to A's own c2s listener");
    let target = [0x77u8; 32];

    assert_eq!(
        metrics.connections_active(),
        1,
        "the authenticated client must already count as one live server-side connection before \
         the fetch is even sent"
    );

    // Fire the fetch off in its own task — it cannot resolve on its own until A's dial times out
    // against the black-holed peer — and hold its `JoinHandle` so it can be aborted below,
    // simulating the client's own WebSocket session dropping mid-request without ever waiting for
    // a reply.
    let fetch_task = tokio::spawn(async move {
        let _ = ac
            .fetch_bundle(target, Some("org-b.test".to_string()), false)
            .await;
    });

    // Give the server side time to actually receive the Fetch frame and enter its blocking dial.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        metrics.connections_active(),
        1,
        "the server-side connection must still be live and blocked in the outbound dial"
    );

    // Simulate the client's WS session dropping: abort the task holding the ONLY `SignalingClient`
    // — dropping it drops its owned `WebSocketStream`/TCP socket, closing A's c2s connection out
    // from under the server without ever completing (or even receiving a reply to) the fetch.
    fetch_task.abort();
    let _ = fetch_task.await;

    // THE non-vacuous check: immediately after the client vanishes, the count must STILL be 1, not
    // already 0. The server-side task is blocked deep inside `dial`'s own timeout-bounded TLS
    // step and is not concurrently watching the client's socket while blocked — so if this were
    // already 0 here, either there was never a real resource held to begin with (a vacuous test)
    // or something is cleaning up via a mechanism this task never implements (instant reactive
    // cancellation on disconnect, which the single-task `ws::serve` loop structurally cannot do).
    // Proving it's STILL 1 here is what makes the eventual recovery below meaningful: it shows
    // that recovery is caused by the bounded deadline elapsing, not by the disconnect itself.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        metrics.connections_active(),
        1,
        "the server-side resource must still be held shortly after the client vanishes — proving \
         the eventual cleanup below is caused by the bounded timeout elapsing, not by the \
         disconnect being detected some other way"
    );

    // Once A's own connect/request deadline elapses, the blocked dial call returns a timeout
    // error, the handler tries (and silently fails) to reply to a socket that's already gone, the
    // read loop observes the dead connection and returns, and full teardown runs. The gauge must
    // return to baseline — this is the actual "no leak" property, not just "eventually the test
    // process exits".
    let recovered = tokio::time::timeout(
        Duration::from_millis(connect_timeout_ms + request_timeout_ms + 5_000),
        async {
            loop {
                if metrics.connections_active() == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        },
    )
    .await;
    assert!(
        recovered.is_ok(),
        "the server-side connection/task must be reclaimed once the outbound deadline elapses, \
         not held open forever — connections_active is still {}",
        metrics.connections_active()
    );
}
