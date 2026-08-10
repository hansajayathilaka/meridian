//! Task 3.2 acceptance (review findings F2 + N5): one silent/slow inbound s2s connection must not
//! wedge `run_federation`'s accept loop and stop every other partner from federating.
//!
//! Drives the real `federation::inbound::{bind_federation, run_federation}` accept loop — the same
//! path `main.rs` runs — against a single real listener, with `federation.handshake_timeout_ms` /
//! `federation.max_concurrent_handshakes` set small so the whole suite stays fast (well under the
//! ~15s wall-clock budget this task's Risks note asks for). PKI/harness setup mirrors
//! `federation_mtls.rs`/`federation_fetch.rs`'s existing per-file duplication convention.
//!
//! Each test maps to one of the task file's required cases:
//! - (a) a raw `TcpStream::connect` that sends nothing, followed by a legitimate mTLS dial that
//!   still completes within a bounded assert — proves the silent connection doesn't wedge the
//!   listener. **This is the test that must fail against the old serial `accept().await` loop**:
//!   under the old code, the raw TCP accept for the *second* connection never even happens until
//!   the first connection's entire (TLS handshake + FedHello) future resolves, so the legitimate
//!   dial below would hang forever waiting for a peer that never even reaches TCP-accept.
//! - (b) a connection that completes mTLS but stalls mid-`FedHello`-length-prefix gets dropped once
//!   `handshake_timeout_ms` elapses.
//! - (c) exhausting `max_concurrent_handshakes` gets the *next* connection dropped **promptly** —
//!   a fast, `try_acquire`-failure-shaped signal well under the handshake timeout, not merely
//!   "eventually" — and once a stalled slot's own handshake timeout reclaims it, the listener goes
//!   on to serve a legitimate connection. The prompt-drop half is what makes this mutation-proof:
//!   a cap that is unenforced (or sized far too generously) still lets a legitimate dial through
//!   *eventually* (every stalling connection times out on its own on `handshake_timeout_ms`
//!   regardless of whether the cap ever bound anything), so "eventually succeeds" alone cannot
//!   distinguish an enforced cap from a no-op one — only the fast/near-instant rejection can.
//! - (d) the separate `max_links` cap (task 3.2 / N5's other half): once every link slot is held by
//!   an established, fully-handshaked link, the next connection's mTLS + `FedHello` handshake still
//!   completes (a different semaphore, checked strictly after the handshake — see
//!   `run_federation`'s doc comment), but the server drops it immediately afterward, before
//!   `serve_link` ever runs. Same mutation-proof shape as (c): prove the drop by its promptness
//!   (an immediate EOF/IO error from the client's own `recv_frame`), not merely "some later
//!   connection eventually got through".
//!
//! ## Task 3.22 (optional, coverage-only): `serve_link`'s adversarial framing arms
//! Four more cells, below the (a)–(d) set above, exercise `inbound::serve_link`'s `bad_request`
//! reply arms (never reached by any test before this task) plus the length-prefix framing this
//! task's own `link::read_frame` enforces. These drive genuinely malformed bytes at an already
//! ESTABLISHED link — after `finish_handshake` succeeds and `serve_link` is sitting in its main
//! `recv_frame` loop — which `FederationLink::send_frame` cannot itself produce (it only ever
//! emits well-formed frames), so each cell hand-rolls the wire format on a raw `TlsStream` instead
//! (see the `raw_write_frame`/`raw_read_frame`/`establish_raw_link` helpers below):
//! - malformed CBOR body (a syntactically valid `FedFrame{op: FetchBundle, ...}` whose nested body
//!   is not valid CBOR for `FedFetchBundle`) → `FedErr{bad_request}`, link survives.
//! - unknown `FedOp` mid-stream (a syntactically valid `FedOp::Hello` frame sent after the
//!   handshake's own `Hello` exchange already completed) → `FedErr{bad_request}`, link survives.
//! - truncated / oversized length prefix → no reply frame (the framing layer itself, `link::
//!   read_frame`, errors before a `FedFrame` is ever decoded) — the link closes instead, and the
//!   server as a whole is proven not to be wedged by a subsequent legitimate dial.
//! - slow-loris **after** the link is established (distinct from case (b) above, which is about
//!   the handshake, bounded by `handshake_timeout_ms`): task 3.22 found `serve_link`'s
//!   `recv_frame` had no idle/read deadline of its own; task 3.23 closed that gap with the
//!   separate `serve_idle_timeout_ms` knob — see that test's own doc comment for what it now
//!   proves.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use meridian_proto::{
    fed_error_codes, FedErr, FedFrame, FedHello, FedOp, FedReachability, FED_VERSION,
};
use meridian_rendezvous::config::{Config, DiscoveryMode, Federation, FederationPolicyMode};
use meridian_rendezvous::federation::link::{build_client_tls_config, MAX_FRAME_LEN};
use meridian_rendezvous::federation::{dial, FederationTimeouts};
use meridian_rendezvous::{AppState, MemoryStore};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

mod support;
use support::{spawn_federation, write, Identity, TestCa};

// -- server harness ------------------------------------------------------------------------

/// A tuned-down `Federation` config, full control over all three of task 3.2's numeric knobs plus
/// task 3.23's `serve_idle_timeout_ms`. Private-CA mode under `ca`.
#[allow(clippy::too_many_arguments)]
fn federation_config_full(
    dir: &Path,
    ca: &TestCa,
    domain: &str,
    handshake_timeout_ms: u64,
    max_concurrent_handshakes: u32,
    max_links: u32,
    serve_idle_timeout_ms: u64,
) -> (Federation, Identity) {
    let id = ca.issue(dir, domain);
    let empty_map = write(dir, "empty-federation_map.toml", "");
    let federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path_str().to_string(),
        key_path: id.key_path_str().to_string(),
        ca_bundle_path: id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: empty_map.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        handshake_timeout_ms,
        max_concurrent_handshakes,
        max_links,
        serve_idle_timeout_ms,
        ..Federation::default()
    };
    (federation, id)
}

/// (a)/(b)/(c)'s config: `handshake_timeout_ms` and `max_concurrent_handshakes` overridden small
/// (so this whole suite stays fast and deterministic), `max_links` and `serve_idle_timeout_ms`
/// left at their generous defaults — these tests are about the handshake cap, not the link cap or
/// the idle-read deadline; (d) below builds its own config via [`federation_config_full`] to
/// exercise `max_links` specifically (handshake cap generous instead), and the task 3.23 test
/// below exercises `serve_idle_timeout_ms` specifically (both other knobs generous instead).
fn federation_config(
    dir: &Path,
    ca: &TestCa,
    domain: &str,
    handshake_timeout_ms: u64,
    max_concurrent_handshakes: u32,
) -> (Federation, Identity) {
    federation_config_full(
        dir,
        ca,
        domain,
        handshake_timeout_ms,
        max_concurrent_handshakes,
        Federation::default().max_links,
        Federation::default().serve_idle_timeout_ms,
    )
}

fn base_config(domain: &str, federation: Federation) -> Config {
    support::config_with_federation(domain, federation)
}

/// Bind B's real hardened accept loop (`bind_federation` + `run_federation`, task 3.2) and start
/// serving it in the background. Returns the bound address.
async fn spawn_hardened_listener(config: Config) -> SocketAddr {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(config, store);
    spawn_federation(state).await
}

// -- 3.22: raw framing adversarial helpers ---------------------------------------------------
//
// `FederationLink::send_frame`/`recv_frame` can only ever produce/consume a WELL-FORMED frame —
// several of the shapes below need bytes that API cannot itself express (a bad length prefix, a
// syntactically-valid-outer-frame-but-garbage-body). These three helpers hand-roll exactly the
// wire format `link.rs`'s (private) `write_frame`/`read_frame`/`exchange_hello` implement, on a
// raw stream the test controls directly, so each cell can inject exactly the malformed bytes it
// needs to.

/// Write one length-delimited `FedFrame`: `uint32-le(len(cbor(FedFrame))) || cbor(FedFrame)`
/// (docs/api/federation-protocol-v1.md §1) — mirrors `link::write_frame`.
async fn raw_write_frame<S: AsyncWrite + Unpin>(stream: &mut S, frame: &FedFrame) {
    let bytes = frame.to_bytes().expect("frame encodes");
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .expect("write length prefix");
    stream.write_all(&bytes).await.expect("write frame body");
    stream.flush().await.expect("flush");
}

/// Read one length-delimited `FedFrame` — mirrors `link::read_frame` (private to `link.rs`, so
/// tests that need raw-stream access can't call it directly).
async fn raw_read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<FedFrame> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    FedFrame::from_bytes(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Complete a real mTLS handshake AND the `FedHello` exchange by hand — `federation::dial` also
/// does this, but hands back an opaque `FederationLink` with no raw-stream access, which is
/// exactly what the shapes below need. Returns the raw, fully-established `TlsStream`: at this
/// point B's `serve_link` (inbound.rs) is sitting in its main `recv_frame` loop, waiting for the
/// very next frame — precisely where each shape below wants to inject its malformed bytes.
async fn establish_raw_link(
    dir: &Path,
    ca: &TestCa,
    addr: SocketAddr,
    a_domain: &str,
    b_domain: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let a = ca.issue(dir, a_domain);
    let client_tls = build_client_tls_config(&a.paths()).expect("build client tls config");
    let connector = TlsConnector::from(client_tls);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from(b_domain.to_string()).expect("valid domain");
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("mTLS handshake completes (both sides present valid certs)");

    let hello = FedHello {
        v: FED_VERSION,
        domain: a_domain.to_string(),
    };
    let out = FedFrame::new(FedOp::Hello, 0, &hello).expect("encode FedHello");
    raw_write_frame(&mut stream, &out).await;
    let in_frame = raw_read_frame(&mut stream)
        .await
        .expect("read B's FedHello");
    assert_eq!(
        in_frame.op,
        FedOp::Hello,
        "expected B's own FedHello reply to complete the handshake"
    );

    stream
}

// -- (a) a silent connection must not wedge the accept loop ---------------------------------

#[tokio::test]
async fn silent_connection_does_not_wedge_the_listener_for_a_legitimate_dial() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.2 dos a)");
    let (b_federation, _b_id) = federation_config(dir.path(), &ca, "b.federation.test", 5_000, 4);
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    // Open a raw TCP connection and send NOTHING at all — no TLS ClientHello, ever. Held open for
    // the whole test (never dropped, never read/written to) so its handshake genuinely never
    // progresses; under the OLD serial `accept().await` loop this alone would be enough to hang
    // every subsequent connection attempt forever.
    let _silent = TcpStream::connect(addr)
        .await
        .expect("raw TCP connect to the federation listener succeeds");

    // A real, legitimate mTLS dial, started right after the silent connection. If the accept loop
    // is genuinely non-blocking per-connection (task 3.2), this completes quickly regardless of the
    // still-open, still-silent connection above. Bounded well under this test's own timeout so a
    // regression to the old wedging behavior fails loudly rather than hanging the suite.
    let a = ca.issue(dir.path(), "a.federation.test");
    let dial_result = tokio::time::timeout(
        Duration::from_secs(5),
        dial(
            addr,
            "b.federation.test",
            a.client_tls(),
            "a.federation.test",
            None,
            FederationTimeouts::default(),
        ),
    )
    .await;

    let link = dial_result
        .expect("a legitimate dial must complete promptly, not hang behind the silent connection")
        .expect("the legitimate dial itself must succeed (valid cert, matching domain)");
    assert_eq!(link.peer_domains, vec!["b.federation.test".to_string()]);
}

// -- (b) stalled mid-length-prefix is dropped by the handshake timeout ----------------------

#[tokio::test]
async fn connection_stalled_mid_length_prefix_is_dropped_by_the_handshake_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.2 dos b)");
    let handshake_timeout_ms = 300;
    let (b_federation, _b_id) = federation_config(
        dir.path(),
        &ca,
        "b.federation.test",
        handshake_timeout_ms,
        4,
    );
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    // A real client identity, signed by the same CA B trusts — so the TLS handshake itself
    // completes fine; what stalls is what comes AFTER it (the FedHello length-prefix read).
    let a = ca.issue(dir.path(), "a.federation.test");
    let client_tls = meridian_rendezvous::federation::link::build_client_tls_config(&a.paths())
        .expect("build client tls config");
    let connector = tokio_rustls::TlsConnector::from(client_tls);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name =
        rustls::pki_types::ServerName::try_from("b.federation.test".to_string()).unwrap();
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("mTLS handshake completes (both sides present valid certs)");

    // Write only 2 of the 4 length-prefix bytes B's `read_frame` expects, then stop — a stall
    // mid-length-prefix, never a full frame. Do not close the socket: B must actively time this
    // connection out, not merely observe an EOF.
    use tokio::io::AsyncWriteExt;
    tls_stream.write_all(&[0x01, 0x00]).await.unwrap();
    tls_stream.flush().await.unwrap();

    // B must close the connection once its handshake deadline elapses. B's own `exchange_hello`
    // writes ITS `FedHello` frame before reading ours (see `link.rs`'s doc comment on why that
    // ordering is safe), so the client side legitimately has bytes to read first — drain and
    // discard those, and keep reading until the connection actually closes (EOF or a TLS-level
    // error), bounded at several times the configured timeout so this is robust to scheduling
    // jitter without being a real "wait for it" sleep-then-assert (a read that never gets a
    // response would hang the test past its overall budget instead of failing crisply).
    use tokio::io::AsyncReadExt;
    let closed = tokio::time::timeout(Duration::from_millis(handshake_timeout_ms * 5), async {
        let mut buf = [0u8; 256];
        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) => return true,
                Ok(_) => continue, // drain B's own FedHello bytes, keep waiting for the close
                Err(_) => return true, // a TLS-level teardown counts as "closed" too
            }
        }
    })
    .await
    .expect("the handshake timeout must close the stalled connection within a bounded time");
    assert!(
        closed,
        "expected the server to close the connection once its handshake deadline elapsed"
    );
}

// -- (c) exhausting max_concurrent_handshakes drops the next connection promptly, then recovers --

/// Mutation-check note (test-engineer, task 3.2 follow-up): the original version of this test only
/// asserted that a legitimate dial *eventually* succeeded after `max_concurrent_handshakes` was
/// exhausted. That's true even with the cap completely unenforced (e.g. a `handshake_slots`
/// semaphore constructed with `1_000_000` permits): every stalling connection still gets admitted
/// and still times out on its own `handshake_timeout_ms`, freeing things up "eventually" regardless
/// of whether the cap ever bound anything. The load-bearing property a cap actually adds is that
/// the connection which arrives *after* the cap is already exhausted gets rejected immediately —
/// dropped by a failed `try_acquire_owned()` before it ever reaches the TLS acceptor — not merely
/// admitted and left to expire on the same handshake deadline as everything else. This test now
/// asserts exactly that fast/near-instant rejection, in addition to the original recovery check.
#[tokio::test]
async fn exhausting_max_concurrent_handshakes_drops_the_next_connection_promptly_then_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.2 dos c)");
    let handshake_timeout_ms = 250;
    let max_concurrent_handshakes = 2;
    let (b_federation, _b_id) = federation_config(
        dir.path(),
        &ca,
        "b.federation.test",
        handshake_timeout_ms,
        max_concurrent_handshakes,
    );
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    // Saturate every handshake slot — exactly `max_concurrent_handshakes`, no more — with silent
    // connections that never send a byte. Held open for the whole test.
    let mut stallers = Vec::new();
    for _ in 0..(max_concurrent_handshakes as usize) {
        stallers.push(
            TcpStream::connect(addr)
                .await
                .expect("raw TCP connect succeeds even while handshake slots are full"),
        );
    }
    // Let the accept loop actually pull each staller off the OS accept queue and acquire its
    // handshake permit before probing the over-cap connection below — otherwise this could race a
    // not-yet-acquired staller permit instead of proving what it's meant to prove.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // One more raw connection, over the cap. With the cap correctly enforced, `run_federation`
    // drops this the instant its `try_acquire_owned()` fails — before any bytes are read or
    // written, well before the handshake deadline could ever fire. Assert the connection closes
    // within a budget well under `handshake_timeout_ms`: an unenforced (or too-generous) cap would
    // instead admit this connection as just another silent staller, which only closes once ITS OWN
    // handshake deadline elapses — comfortably past this bound.
    let mut over_cap = TcpStream::connect(addr)
        .await
        .expect("raw TCP connect succeeds even while handshake slots are full");
    let prompt_budget = Duration::from_millis(handshake_timeout_ms / 2);
    use tokio::io::AsyncReadExt;
    let closed_promptly = tokio::time::timeout(prompt_budget, async {
        let mut buf = [0u8; 1];
        matches!(over_cap.read(&mut buf).await, Ok(0))
    })
    .await;
    assert_eq!(
        closed_promptly,
        Ok(true),
        "a connection over max_concurrent_handshakes must be dropped promptly by the failed \
         try_acquire (well under the handshake timeout), not admitted and left to expire on the \
         handshake deadline like a connection that DID get a permit — a cap that isn't actually \
         enforced would fail this assertion even though the recovery check below would still pass"
    );
    drop(over_cap);

    // A legitimate dial, retried with a short backoff, must eventually succeed once the stallers'
    // handshake slots are reclaimed by `handshake_timeout_ms`. Bounded well above the handshake
    // timeout so this both proves recovery AND stays well under this task's ~15s suite budget.
    let a = ca.issue(dir.path(), "a.federation.test");
    let overall_budget = Duration::from_millis(handshake_timeout_ms * 10);
    let outcome = tokio::time::timeout(overall_budget, async {
        loop {
            let attempt = dial(
                addr,
                "b.federation.test",
                a.client_tls(),
                "a.federation.test",
                None,
                FederationTimeouts::default(),
            )
            .await;
            if let Ok(link) = attempt {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    let link = outcome.expect(
        "the listener must go on to serve a legitimate connection once handshake slots free up, \
         not stay wedged by the stalling connections that exhausted max_concurrent_handshakes",
    );
    assert_eq!(link.peer_domains, vec!["b.federation.test".to_string()]);

    // The stalling connections stay in scope (and thus open) for the whole test — drop them
    // explicitly at the end so the intent is clear rather than left to an implicit end-of-fn drop.
    drop(stallers);
}

// -- (d) exhausting max_links drops the next link promptly after a successful handshake -----

/// Task 3.2 / N5's other half: a semaphore cap on total live `serve_link` tasks, entirely separate
/// from the handshake cap above (`run_federation`'s doc comment, step 3: "deliberately a second
/// semaphore, not the same permit held since step 1"). `max_concurrent_handshakes` is left generous
/// here (mirroring how (c) above left `max_links` generous) so only the link cap is what's under
/// test.
///
/// Same mutation-proof shape as (c): a `max_links` cap that is unenforced (or sized far too
/// generously) would still let the over-cap connection below complete its handshake and just sit
/// there — since nothing here ever sends it a request, there is no "eventually" outcome to fall
/// back on the way (c)'s handshake-timeout-driven recovery gave it; the only way to observe the cap
/// actually working is the prompt drop itself.
#[tokio::test]
async fn exhausting_max_links_drops_the_next_link_promptly_after_a_successful_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.2 dos link-cap)");
    let max_links = 2;
    let (b_federation, _b_id) = federation_config_full(
        dir.path(),
        &ca,
        "b.federation.test",
        5_000, // generous handshake timeout — not what this test is about
        64,    // generous handshake cap — not what this test is about
        max_links,
        Federation::default().serve_idle_timeout_ms, // generous — not what this test is about
    );
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    // Establish exactly `max_links` legitimate, fully-handshaked links, and hold each one open
    // (never send a frame, never drop it) for the rest of the test. Server-side, each one's
    // `serve_link` (inbound.rs) is blocked on `link.recv_frame()` — exactly what `run_federation`'s
    // doc comment (step 4) says holds a link-cap permit "for exactly as long as `serve_link`
    // runs" — so this occupies both link-cap permits without needing any lower-level access to the
    // semaphore itself.
    let mut links = Vec::new();
    for i in 0..max_links {
        let a = ca.issue(dir.path(), &format!("a{i}.federation.test"));
        let link = dial(
            addr,
            "b.federation.test",
            a.client_tls(),
            &format!("a{i}.federation.test"),
            None,
            FederationTimeouts::default(),
        )
        .await
        .expect("legitimate dial completes while link slots remain");
        links.push(link);
    }
    // Let each link's server-side task actually reach (and succeed at) its own link-cap
    // `try_acquire_owned()` before probing the over-cap connection below — the client-side `dial`
    // above returns as soon as ITS OWN `exchange_hello` read completes, which happens strictly
    // inside `finish_handshake`, before the server ever reaches the link-cap check that follows it.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // One more legitimate dial, over the link cap. Its mTLS + `FedHello` handshake completes in
    // full — `dial` itself returns `Ok` — because the SEPARATE handshake cap is generous and
    // untouched by this test. Only after `finish_handshake` returns does the link-cap check happen
    // — and with both permits already held by the two links above, it fails, so the server drops
    // this link immediately afterward, before `serve_link` ever runs and before any reply frame.
    let over = ca.issue(dir.path(), "over.federation.test");
    let mut over_link = dial(
        addr,
        "b.federation.test",
        over.client_tls(),
        "over.federation.test",
        None,
        FederationTimeouts::default(),
    )
    .await
    .expect(
        "the handshake itself still completes — it's the separate link cap, not the handshake \
         cap, that's exhausted here",
    );

    // Prove the drop from the CLIENT's own perspective, without ever sending anything: reading on a
    // link whose server side was genuinely dropped for link-cap exhaustion gets an EOF/IO error
    // almost immediately (well inside this bounded budget). A mutant that fails to enforce
    // `max_links` would instead let this connection reach a live `serve_link` loop exactly like the
    // two links above — whose `recv_frame` never resolves at all absent a request, since nothing
    // here ever sends one — so the read would still be pending when the budget elapses, and the
    // assertion below fails.
    let closed_promptly =
        tokio::time::timeout(Duration::from_millis(500), over_link.recv_frame()).await;
    assert!(
        matches!(&closed_promptly, Ok(Err(_))),
        "a link over max_links must be dropped promptly once its (successful) handshake \
         completes — recv_frame should observe the server-side close almost immediately, not hang \
         the way a live serve_link loop's read would with no request ever sent on it: {closed_promptly:?}"
    );

    // The in-cap links stay open (and thus keep occupying their permits) for the whole test — drop
    // them explicitly at the end so the intent is clear.
    drop(links);
}

// -- 3.22 (e) malformed CBOR body: bad_request, link survives -------------------------------

/// Mutation-check (test-engineer, task 3.22): temporarily replacing `inbound.rs`'s
/// `FedOp::FetchBundle` decode-error arm's body with a bare `continue;` (dropping the malformed
/// frame silently instead of replying `bad_request`) makes this test fail — the `raw_read_frame`
/// below then times out waiting for a reply that never arrives. Restored after confirming that.
#[tokio::test]
async fn malformed_fetch_bundle_body_gets_bad_request_and_the_link_survives() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.22 malformed-body)");
    let (b_federation, _b_id) = federation_config(dir.path(), &ca, "b.federation.test", 5_000, 8);
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    let mut stream = establish_raw_link(
        dir.path(),
        &ca,
        addr,
        "a.federation.test",
        "b.federation.test",
    )
    .await;

    // A syntactically valid outer `FedFrame{op: FetchBundle, id: 7, ...}` whose nested `body` is
    // NOT valid CBOR for `FedFetchBundle` at all — `FedFrame::new` (used by every legitimate
    // caller, including `FederationLink::send_frame`) can only ever encode a real body, so this
    // has to be built by hand.
    let bad = FedFrame {
        op: FedOp::FetchBundle,
        id: 7,
        body: vec![0xff, 0xff, 0xff, 0xff],
    };
    raw_write_frame(&mut stream, &bad).await;

    let reply = tokio::time::timeout(Duration::from_secs(5), raw_read_frame(&mut stream))
        .await
        .expect("a bad_request reply arrives promptly, not a hang")
        .expect("reading the reply frame succeeds");
    assert_eq!(reply.op, FedOp::Err, "expected a FedErr reply");
    assert_eq!(
        reply.id, 7,
        "the reply must echo the malformed request's id"
    );
    let err: FedErr = reply.decode().expect("FedErr body decodes");
    assert_eq!(err.code, fed_error_codes::BAD_REQUEST);
    assert!(
        err.msg.contains("fed_fetch_bundle"),
        "expected the fetch_bundle-specific malformed-body message, got {:?}",
        err.msg
    );

    // The link survives: a subsequent LEGITIMATE request on the SAME connection still gets
    // served normally — the malformed frame above did not kill or otherwise wedge `serve_link`'s
    // loop, only the one bad request within it.
    let ok = FedFrame::new(
        FedOp::Reachability,
        8,
        &FedReachability {
            target: [0x11u8; 32],
        },
    )
    .unwrap();
    raw_write_frame(&mut stream, &ok).await;
    let reply2 = tokio::time::timeout(Duration::from_secs(5), raw_read_frame(&mut stream))
        .await
        .expect("a second, legitimate reply arrives promptly")
        .expect("reading the second reply frame succeeds");
    assert_eq!(
        reply2.op,
        FedOp::Reachable,
        "expected the link to keep serving"
    );
    assert_eq!(reply2.id, 8);
}

// -- 3.22 (f) unknown FedOp mid-stream: bad_request, link survives ---------------------------

/// Mutation-check (test-engineer, task 3.22): temporarily replacing `inbound.rs`'s final
/// `_ => { ... }` catch-all arm's body with `_ => {}` (silently drop the unknown-op frame instead
/// of replying `bad_request`) makes this test fail the same way as the malformed-body test above.
/// Restored after confirming that.
#[tokio::test]
async fn unknown_op_mid_stream_gets_bad_request_and_the_link_survives() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.22 unknown-op)");
    let (b_federation, _b_id) = federation_config(dir.path(), &ca, "b.federation.test", 5_000, 8);
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    let mut stream = establish_raw_link(
        dir.path(),
        &ca,
        addr,
        "a.federation.test",
        "b.federation.test",
    )
    .await;

    // A syntactically valid frame naming an op `serve_link`'s `match` doesn't dispatch on: a
    // second, mid-stream `FedOp::Hello` — `Hello` is only ever handled once, inline, during
    // `finish_handshake`'s own `exchange_hello`; `serve_link`'s loop has never seen it before and
    // has no arm for it (falls into the final `_ =>` catch-all, per that arm's own doc comment).
    let stray_hello = FedFrame::new(
        FedOp::Hello,
        3,
        &FedHello {
            v: FED_VERSION,
            domain: "a.federation.test".to_string(),
        },
    )
    .unwrap();
    raw_write_frame(&mut stream, &stray_hello).await;

    let reply = tokio::time::timeout(Duration::from_secs(5), raw_read_frame(&mut stream))
        .await
        .expect("a bad_request reply arrives promptly, not a hang")
        .expect("reading the reply frame succeeds");
    assert_eq!(reply.op, FedOp::Err, "expected a FedErr reply");
    assert_eq!(
        reply.id, 3,
        "the reply must echo the unknown-op request's id"
    );
    let err: FedErr = reply.decode().expect("FedErr body decodes");
    assert_eq!(err.code, fed_error_codes::BAD_REQUEST);
    assert!(
        err.msg.contains("not supported"),
        "expected the unknown-op message, got {:?}",
        err.msg
    );

    // The link survives: a subsequent LEGITIMATE request on the SAME connection still gets served.
    let ok = FedFrame::new(
        FedOp::Reachability,
        4,
        &FedReachability {
            target: [0x22u8; 32],
        },
    )
    .unwrap();
    raw_write_frame(&mut stream, &ok).await;
    let reply2 = tokio::time::timeout(Duration::from_secs(5), raw_read_frame(&mut stream))
        .await
        .expect("a second, legitimate reply arrives promptly")
        .expect("reading the second reply frame succeeds");
    assert_eq!(
        reply2.op,
        FedOp::Reachable,
        "expected the link to keep serving"
    );
    assert_eq!(reply2.id, 4);
}

// -- 3.22 (g) truncated / oversized length prefix: no reply, link closes, server unwedged ----

/// Mutation-check (test-engineer, task 3.22): temporarily removing `link.rs::read_frame`'s
/// `if len > MAX_FRAME_LEN { return Err(...) }` guard (so an oversized declared length is no
/// longer rejected before the receive buffer is allocated) makes the oversized half of this test
/// fail — with nothing enforcing the cap, B just blocks in `read_exact` waiting for the
/// (never-sent) rest of the declared body, so the connection is never closed within this test's
/// bounded window. Restored after confirming that.
///
/// The truncated (EOF) half below has no equivalent single guard to neuter — it exercises
/// `read_exact`'s own built-in short-read-then-EOF propagation, not an explicit `if`, so it is not
/// separately mutation-checked (noted here rather than silently skipped).
#[tokio::test]
async fn truncated_and_oversized_length_prefixes_close_the_link_without_wedging_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.22 length-prefix)");
    let (b_federation, _b_id) = federation_config(dir.path(), &ca, "b.federation.test", 5_000, 8);
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    // -- oversized: the declared length alone exceeds MAX_FRAME_LEN; no body ever follows -------
    {
        let mut stream = establish_raw_link(
            dir.path(),
            &ca,
            addr,
            "a1.federation.test",
            "b.federation.test",
        )
        .await;
        let oversized_len: u32 = (MAX_FRAME_LEN as u32) + 1;
        stream
            .write_all(&oversized_len.to_le_bytes())
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // `link::read_frame` rejects the length prefix BEFORE allocating/reading any body — no
        // `FedErr` reply is possible at this layer (there is no decoded `FedFrame` to reply to
        // yet); the connection must simply close, promptly, well before any real 1 MiB+ body
        // could ever plausibly arrive.
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            let mut buf = [0u8; 1];
            stream.read(&mut buf).await
        })
        .await
        .expect("the server closes an oversized-length-prefix connection promptly");
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "expected EOF/IO-error from a connection whose declared length exceeded \
             MAX_FRAME_LEN, got {closed:?}"
        );
    }

    // -- truncated: a small, in-bounds length prefix, then fewer body bytes than declared, then
    //    the peer hangs up outright — the frame is never completed ----------------------------
    {
        let mut stream = establish_raw_link(
            dir.path(),
            &ca,
            addr,
            "a2.federation.test",
            "b.federation.test",
        )
        .await;
        stream.write_all(&100u32.to_le_bytes()).await.unwrap(); // declares 100 body bytes
        stream.write_all(&[0u8; 10]).await.unwrap(); // sends only 10
        stream.flush().await.unwrap();
        drop(stream); // hang up mid-frame — the other 90 bytes never arrive
    }

    // Neither bad connection above must have wedged the server (leaked its `max_links` permit
    // forever, panicked the accept loop, etc.): a fresh, entirely legitimate dial right
    // afterward still completes normally.
    let a3 = ca.issue(dir.path(), "a3.federation.test");
    let link = tokio::time::timeout(
        Duration::from_secs(5),
        dial(
            addr,
            "b.federation.test",
            a3.client_tls(),
            "a3.federation.test",
            None,
            FederationTimeouts::default(),
        ),
    )
    .await
    .expect("a legitimate dial after the bad connections completes promptly, not hang")
    .expect("the legitimate dial itself succeeds");
    assert_eq!(link.peer_domains, vec!["b.federation.test".to_string()]);
}

// -- 3.23 (h) slow-loris AFTER the link is established: dropped by the idle-read deadline ----

/// Distinct from case (b) above: (b) stalls DURING the mTLS+`FedHello` handshake, which
/// `federation.handshake_timeout_ms` bounds (task 3.2). This test stalls a frame AFTER that
/// handshake has already succeeded and `serve_link` has taken over — a phase `handshake_timeout_ms`
/// never covers, bounded instead by the separate `federation.serve_idle_timeout_ms` knob (task
/// 3.23; see [`Federation::serve_idle_timeout_ms`]'s own doc comment for why it is a third,
/// independent timeout rather than a reuse of either sibling).
///
/// Originally (task 3.22) this test only pinned the *absence* of any such deadline: it asserted
/// the stalled connection sat idle within a bounded window, then resumed normally once the
/// trickled frame was eventually completed. Task 3.23 closes that gap, and this test now proves
/// the fix instead: (a) a peer that stalls mid-frame on an already-established link is dropped
/// PROMPTLY once `serve_idle_timeout_ms` elapses — not merely "eventually" — mirroring this file's
/// own (c)/(d) mutation-proof shape (a deadline that is unenforced, or wired to the wrong config
/// field, would instead leave the connection open well past this test's bounded assertion
/// window); and (b) the `max_links` permit that connection was holding is genuinely reclaimed
/// afterward — a fresh dial, against what would otherwise be an exhausted `max_links = 1` budget,
/// eventually succeeds, AND a real request/reply round-trip over that retried link succeeds too.
/// The round-trip is the part that actually proves the permit was reclaimed: `dial()` returning
/// `Ok` only proves the client-side mTLS + `FedHello` handshake completed, which (per case (d)
/// above) is entirely independent of the server's `max_links` semaphore — a connection that loses
/// the link-cap race still completes its handshake and is only dropped, silently, strictly
/// afterward. So `dial()` succeeding alone cannot distinguish "the permit was genuinely reclaimed"
/// from "the permit leaked forever but the handshake slot cap this test leaves generous happened
/// to have room"; only a real, well-formed reply from `serve_link` (which only runs once the
/// link-cap `try_acquire_owned()` genuinely succeeds) can. (Case (c)'s old "resume the stalled
/// frame" check no longer applies: once the connection is proactively dropped on idle, there is
/// nothing left to resume — proving the permit is freed for a NEW dial, and genuinely usable by
/// it, is the more useful property once that behavior changed.)
#[tokio::test]
async fn slow_loris_after_link_established_is_dropped_by_the_idle_read_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.23 slow-loris)");
    // A tight max_links cap (1) makes the fix directly observable: only if the sole permit is
    // genuinely released once `serve_link` returns can the follow-up dial in (b) below succeed at
    // all. `serve_idle_timeout_ms` is kept short (same range as this file's own
    // `handshake_timeout_ms` test values, e.g. case (b)/(c) above) so the whole suite stays fast.
    let serve_idle_timeout_ms = 300;
    let (b_federation, _b_id) = federation_config_full(
        dir.path(),
        &ca,
        "b.federation.test",
        5_000,
        8,
        1,
        serve_idle_timeout_ms,
    );
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    let mut stream = establish_raw_link(
        dir.path(),
        &ca,
        addr,
        "a.federation.test",
        "b.federation.test",
    )
    .await;

    // A real, legitimate follow-up frame, computed up front so its exact encoded length is known
    // — needed to trickle only PART of its 4-byte length prefix, then stop.
    let follow_up = FedFrame::new(
        FedOp::Reachability,
        55,
        &FedReachability {
            target: [0x33u8; 32],
        },
    )
    .unwrap();
    let follow_bytes = follow_up.to_bytes().unwrap();
    let len_bytes = (follow_bytes.len() as u32).to_le_bytes();

    // Trickle only the first 2 of the 4 length-prefix bytes B's `serve_link` → `recv_frame` is
    // waiting for, then stop for good — unlike the pre-fix version of this test, nothing ever
    // completes this frame.
    stream.write_all(&len_bytes[0..2]).await.unwrap();
    stream.flush().await.unwrap();

    // (a) Prompt drop: once `serve_idle_timeout_ms` elapses, B must close the connection — no
    // reply frame is possible (the idle-read deadline fires inside `recv_frame`'s own
    // `read_exact`, before any `FedFrame` is ever decoded). Bounded at a few multiples of the
    // configured deadline, mirroring case (b) above, so this is robust to scheduling jitter
    // without degenerating into an unbounded "wait for it" sleep-then-assert.
    let closed = tokio::time::timeout(Duration::from_millis(serve_idle_timeout_ms * 5), async {
        let mut buf = [0u8; 1];
        stream.read(&mut buf).await
    })
    .await
    .expect(
        "the idle-read deadline must close the stalled connection within a bounded time, not \
         leave it open indefinitely",
    );
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "expected EOF/IO-error once serve_idle_timeout_ms elapsed, got {closed:?}"
    );

    // (b) The max_links permit that connection held is genuinely reclaimed, not merely closed on
    // B's side while the permit itself leaks: with max_links = 1, a fresh dial can only succeed if
    // the idle-dropped connection's permit was actually released back to the semaphore. Retried
    // with a short backoff (mirroring case (c)'s recovery check) so this also tolerates the small
    // scheduling gap between the socket closing and `run_federation` observing `serve_link`'s
    // return and dropping the permit guard, rather than requiring the permit to free up in the
    // very same instant the client observes the close.
    //
    // NOTE: `dial()` returning `Ok` only proves the CLIENT-side mTLS + `FedHello` handshake
    // completed — that happens entirely independent of the server's `max_links` semaphore (see
    // `run_federation`'s doc comment / case (d) above: the link-cap `try_acquire_owned()` is
    // checked strictly *after* the handshake finishes, and a permit-exhausted connection is
    // dropped silently, with no reply frame, before `serve_link` ever runs). So a retry loop that
    // stops as soon as `dial()` succeeds would pass even if the idle-dropped connection's permit
    // were never actually reclaimed, as long as `dial()`'s own (separate, generous) handshake-slot
    // cap had room — it says nothing about `max_links`. To actually prove the permit was reclaimed
    // and consumed by this new link, drive a real request over it and require a real, well-formed
    // reply: that only happens if `serve_link` genuinely took over the connection, which only
    // happens if the link-cap `try_acquire_owned()` genuinely succeeded.
    let a2 = ca.issue(dir.path(), "a2.federation.test");
    let overall_budget = Duration::from_millis(serve_idle_timeout_ms * 10);
    let mut link = tokio::time::timeout(overall_budget, async {
        loop {
            let attempt = dial(
                addr,
                "b.federation.test",
                a2.client_tls(),
                "a2.federation.test",
                None,
                FederationTimeouts::default(),
            )
            .await;
            if let Ok(link) = attempt {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "the max_links permit held by the idle-dropped connection must be reclaimed once \
         serve_link returns — a fresh dial over the max_links=1 budget must eventually succeed",
    );
    assert_eq!(link.peer_domains, vec!["b.federation.test".to_string()]);

    let probe = FedFrame::new(
        FedOp::Reachability,
        99,
        &FedReachability {
            target: [0x44u8; 32],
        },
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), link.send_frame(&probe))
        .await
        .expect("sending a real request on the retried link completes promptly")
        .expect("send_frame itself succeeds");
    let reply = tokio::time::timeout(Duration::from_secs(5), link.recv_frame())
        .await
        .expect(
            "a real reply on the retried link arrives promptly — proving serve_link is genuinely \
             running (and thus that the max_links permit was truly acquired), not merely that \
             the client-side handshake completed",
        )
        .expect("reading the reply frame succeeds");
    assert_eq!(
        reply.op,
        FedOp::Reachable,
        "expected a well-formed Reachable reply from serve_link on the retried link"
    );
    assert_eq!(reply.id, 99, "the reply must echo the probe's id");
}

// -- 3.23 (i) idle timeout resets per-iteration, it is not a total-lifetime cap -------------

/// Non-blocking follow-up (reviewer note on the (h) test above): nothing else in this file proves
/// `serve_idle_timeout_ms` is an IDLE deadline — reset every time a frame is read, per
/// `serve_link`'s loop shape (`inbound.rs`: `with_deadline(idle_timeout, link.recv_frame())` is
/// called fresh on every pass) — rather than some hypothetical TOTAL-lifetime cap on the link as a
/// whole. A link that keeps sending real frames slower than `serve_idle_timeout_ms` apart, but
/// well within it each individual gap, must stay alive indefinitely; a (wrong) lifetime-cap
/// implementation would instead kill it once the cumulative connection age crossed the same
/// threshold, even though no single gap between frames was ever too long.
///
/// Kept small and low-risk: reuses the same `dial` + `send_frame`/`recv_frame` round-trip shape as
/// case (b) above, with generous spacing relative to scheduling jitter (`idle_timeout / 2`) and
/// few enough iterations that the whole test finishes in well under a second.
#[tokio::test]
async fn periodic_frames_slower_than_the_idle_timeout_keep_the_link_alive() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::named("Meridian Test Federation CA (3.23 idle-reset)");
    let serve_idle_timeout_ms = 200;
    let (b_federation, _b_id) = federation_config_full(
        dir.path(),
        &ca,
        "b.federation.test",
        5_000, // generous handshake timeout — not what this test is about
        8,     // generous handshake cap — not what this test is about
        4,     // generous link cap — not what this test is about
        serve_idle_timeout_ms,
    );
    let addr = spawn_hardened_listener(base_config("b.federation.test", b_federation)).await;

    let a = ca.issue(dir.path(), "a.federation.test");
    let mut link = dial(
        addr,
        "b.federation.test",
        a.client_tls(),
        "a.federation.test",
        None,
        FederationTimeouts::default(),
    )
    .await
    .expect("legitimate dial completes");

    // Each gap between frames is well under `serve_idle_timeout_ms` (half of it), but the
    // cumulative wall-clock span across all iterations comfortably exceeds `serve_idle_timeout_ms`
    // — the property a total-lifetime cap would violate but a genuinely per-read idle deadline
    // would not.
    let gap = Duration::from_millis(serve_idle_timeout_ms / 2);
    let iterations: u64 = 6;
    for i in 0..iterations {
        tokio::time::sleep(gap).await;
        let req = FedFrame::new(
            FedOp::Reachability,
            i,
            &FedReachability {
                target: [0x55u8; 32],
            },
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), link.send_frame(&req))
            .await
            .unwrap_or_else(|_| panic!("send_frame {i} completes promptly"))
            .unwrap_or_else(|e| panic!("send_frame {i} succeeds: {e:?}"));
        let reply = tokio::time::timeout(Duration::from_secs(5), link.recv_frame())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "reply {i} arrives promptly — a link killed by a (wrong) total-lifetime cap \
                     would instead have gone silent partway through this loop, well before any \
                     single gap ever exceeded serve_idle_timeout_ms"
                )
            })
            .unwrap_or_else(|e| panic!("reading reply {i} succeeds: {e:?}"));
        assert_eq!(
            reply.op,
            FedOp::Reachable,
            "expected reply {i} to be Reachable"
        );
        assert_eq!(reply.id, i, "reply {i} must echo its request id");
    }
}
