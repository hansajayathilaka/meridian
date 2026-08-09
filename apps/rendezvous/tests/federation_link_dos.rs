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

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::federation::{dial, FederationTimeouts, FederationTlsPaths};
use meridian_rendezvous::{AppState, MemoryStore};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::net::TcpStream;

// -- PKI test harness (mirrors apps/rendezvous/tests/federation_mtls.rs) --------------------

struct TestCa {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(common_name: &str) -> TestCa {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let key = KeyPair::generate().expect("generate CA key");
    let cert = params.self_signed(&key).expect("self-sign CA cert");
    TestCa { cert, key }
}

fn make_leaf(domain: &str, ca: &TestCa) -> (rcgen::Certificate, KeyPair) {
    let mut params =
        CertificateParams::new(vec![domain.to_string()]).expect("SAN must be a valid DNS name");
    params.distinguished_name.push(DnType::CommonName, domain);
    let key = KeyPair::generate().expect("generate leaf key");
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("sign leaf cert");
    (cert, key)
}

fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

struct Identity {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    ca_bundle_path: std::path::PathBuf,
}

impl Identity {
    fn paths(&self) -> FederationTlsPaths<'_> {
        FederationTlsPaths {
            cert_path: self.cert_path.to_str().unwrap(),
            key_path: self.key_path.to_str().unwrap(),
            ca_bundle_path: self.ca_bundle_path.to_str().unwrap(),
        }
    }
}

fn mint_identity(dir: &Path, tag: &str, domain: &str, ca: &TestCa) -> Identity {
    let (leaf_cert, leaf_key) = make_leaf(domain, ca);
    Identity {
        cert_path: write(dir, &format!("{tag}.crt.pem"), &leaf_cert.pem()),
        key_path: write(dir, &format!("{tag}.key.pem"), &leaf_key.serialize_pem()),
        ca_bundle_path: write(dir, &format!("{tag}.ca.pem"), &ca.cert.pem()),
    }
}

// -- server harness ------------------------------------------------------------------------

/// A tuned-down `Federation` config, full control over all three of task 3.2's numeric knobs.
/// Private-CA mode under `ca`.
fn federation_config_full(
    dir: &Path,
    ca: &TestCa,
    domain: &str,
    handshake_timeout_ms: u64,
    max_concurrent_handshakes: u32,
    max_links: u32,
) -> (Federation, Identity) {
    let id = mint_identity(dir, "b", domain, ca);
    let empty_map = write(dir, "empty-federation_map.toml", "");
    let federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path.to_str().unwrap().to_string(),
        key_path: id.key_path.to_str().unwrap().to_string(),
        ca_bundle_path: id.ca_bundle_path.to_str().unwrap().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: empty_map.to_str().unwrap().to_string(),
        policy: FederationPolicyMode::Open,
        handshake_timeout_ms,
        max_concurrent_handshakes,
        max_links,
        ..Federation::default()
    };
    (federation, id)
}

/// (a)/(b)/(c)'s config: `handshake_timeout_ms` and `max_concurrent_handshakes` overridden small
/// (so this whole suite stays fast and deterministic), `max_links` left at its generous default —
/// these tests are about the handshake cap, not the link cap; (d) below builds its own config via
/// [`federation_config_full`] to exercise `max_links` specifically, with the handshake cap generous
/// instead.
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
    )
}

fn base_config(domain: &str, federation: Federation) -> Config {
    Config {
        server: Server {
            domain: domain.to_string(),
            bind: "127.0.0.1:0".to_string(),
            ..Server::default()
        },
        limits: Limits::default(),
        turn: Turn::default(),
        federation,
    }
}

/// Bind B's real hardened accept loop (`bind_federation` + `run_federation`, task 3.2) and start
/// serving it in the background. Returns the bound address.
async fn spawn_hardened_listener(config: Config) -> SocketAddr {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(config, store);
    let listener = bind_federation(&state).await.expect("bind s2s listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_federation(listener, state).await;
    });
    addr
}

// -- (a) a silent connection must not wedge the accept loop ---------------------------------

#[tokio::test]
async fn silent_connection_does_not_wedge_the_listener_for_a_legitimate_dial() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA (3.2 dos a)");
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
    let a = mint_identity(dir.path(), "a", "a.federation.test", &ca);
    let dial_result = tokio::time::timeout(
        Duration::from_secs(5),
        dial(
            addr,
            "b.federation.test",
            &a.paths(),
            "a.federation.test",
            None,
            FederationTimeouts::default(),
        ),
    )
    .await;

    let link = dial_result
        .expect("a legitimate dial must complete promptly, not hang behind the silent connection")
        .expect("the legitimate dial itself must succeed (valid cert, matching domain)");
    assert_eq!(link.peer_domain, "b.federation.test");
}

// -- (b) stalled mid-length-prefix is dropped by the handshake timeout ----------------------

#[tokio::test]
async fn connection_stalled_mid_length_prefix_is_dropped_by_the_handshake_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA (3.2 dos b)");
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
    let a = mint_identity(dir.path(), "a", "a.federation.test", &ca);
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
    let ca = make_ca("Meridian Test Federation CA (3.2 dos c)");
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
    let a = mint_identity(dir.path(), "a", "a.federation.test", &ca);
    let overall_budget = Duration::from_millis(handshake_timeout_ms * 10);
    let outcome = tokio::time::timeout(overall_budget, async {
        loop {
            let attempt = dial(
                addr,
                "b.federation.test",
                &a.paths(),
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
    assert_eq!(link.peer_domain, "b.federation.test");

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
    let ca = make_ca("Meridian Test Federation CA (3.2 dos link-cap)");
    let max_links = 2;
    let (b_federation, _b_id) = federation_config_full(
        dir.path(),
        &ca,
        "b.federation.test",
        5_000, // generous handshake timeout — not what this test is about
        64,    // generous handshake cap — not what this test is about
        max_links,
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
        let a = mint_identity(
            dir.path(),
            &format!("a{i}"),
            &format!("a{i}.federation.test"),
            &ca,
        );
        let link = dial(
            addr,
            "b.federation.test",
            &a.paths(),
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
    let over = mint_identity(dir.path(), "over", "over.federation.test", &ca);
    let mut over_link = dial(
        addr,
        "b.federation.test",
        &over.paths(),
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
