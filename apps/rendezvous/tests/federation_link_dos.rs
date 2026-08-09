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
//! - (c) enough concurrent stalling connections to exhaust `max_concurrent_handshakes` still lets
//!   the listener go on to serve a legitimate connection (once the stallers' slots are reclaimed by
//!   the same handshake timeout).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::federation::{dial, FederationTlsPaths};
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

/// A tuned-down `Federation` config: private-CA mode under `ca`, `handshake_timeout_ms` and
/// `max_concurrent_handshakes` overridden small (so this whole suite stays fast and deterministic),
/// `max_links` left generous (these tests are about the handshake cap, not the link cap).
fn federation_config(
    dir: &Path,
    ca: &TestCa,
    domain: &str,
    handshake_timeout_ms: u64,
    max_concurrent_handshakes: u32,
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
        ..Federation::default()
    };
    (federation, id)
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

// -- (c) exhausting max_concurrent_handshakes still lets the listener recover ---------------

#[tokio::test]
async fn exhausting_max_concurrent_handshakes_still_leaves_the_listener_able_to_serve_a_legitimate_connection(
) {
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

    // Saturate every handshake slot (plus one extra, guaranteed-dropped connection) with silent
    // connections that never send a byte. Held open for the whole test.
    let mut stallers = Vec::new();
    for _ in 0..(max_concurrent_handshakes as usize + 1) {
        stallers.push(
            TcpStream::connect(addr)
                .await
                .expect("raw TCP connect succeeds even while handshake slots are full"),
        );
    }

    // A legitimate dial, retried with a short backoff, must eventually succeed: either the accept
    // loop was never actually blocked (so it could always have served a fresh connection once a
    // slot exists) or, once the stallers' handshake slots are reclaimed by
    // `handshake_timeout_ms`, a subsequent attempt gets a free slot and proceeds normally. Bounded
    // well above the handshake timeout so this both proves recovery AND stays well under this
    // task's ~15s suite budget.
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
