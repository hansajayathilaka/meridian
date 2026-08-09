//! Task 2.4 acceptance: s2s mTLS link establishment, both WebPKI and private-CA (air-gap) modes.
//!
//! Drives the real `federation::link` listener/dialer end to end with `rcgen`-minted test certs
//! (dev-dependency only — never linked into the production server binary, per the task's risk
//! note). Each test maps directly to one of the task file's required cases:
//! - happy path, private-CA mode
//! - happy path, WebPKI mode (via `SSL_CERT_FILE`, the standard rustls-native-certs test hook)
//! - untrusted CA rejected
//! - valid cert for the wrong domain rejected (ADR 0017 (a)/C3's whole point)
//! - missing client cert rejected
//! - fail-closed cert/key/CA-bundle loading (security-reviewer follow-up on task 2.4)

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use meridian_proto::{FedFrame, FedOp, FedReachability};
use meridian_rendezvous::federation::link::{build_client_tls_config, build_server_tls_config};
use meridian_rendezvous::federation::{
    dial, FederationListener, FederationTimeouts, FederationTlsPaths, LinkError,
};
use meridian_rendezvous::metrics::Metrics;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

// -- PKI test harness ---------------------------------------------------------

/// A minted CA: its self-signed `rcgen::Certificate` (used as the `signed_by` issuer) and key.
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

/// Mint a leaf cert for `domain` (used as both the SAN dNSName and the CN), signed by `ca`.
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

/// A minted identity's cert+key PEM files, written under `dir`, plus the CA bundle PEM it was
/// signed under (also written under `dir`) — everything [`FederationTlsPaths`] needs.
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

    /// Same identity, but as a WebPKI-mode path set (empty `ca_bundle_path` — trust the OS/system
    /// store, which the WebPKI tests point at this identity's CA via `SSL_CERT_FILE`).
    fn webpki_paths(&self) -> FederationTlsPaths<'_> {
        FederationTlsPaths {
            cert_path: self.cert_path.to_str().unwrap(),
            key_path: self.key_path.to_str().unwrap(),
            ca_bundle_path: "",
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// Mint a leaf identity for `domain` signed by `ca`, writing cert/key/CA-bundle PEMs under `dir`.
/// `tag` disambiguates filenames when several identities share one tempdir.
fn mint_identity(dir: &Path, tag: &str, domain: &str, ca: &TestCa) -> Identity {
    let (leaf_cert, leaf_key) = make_leaf(domain, ca);
    Identity {
        cert_path: write(dir, &format!("{tag}.crt.pem"), &leaf_cert.pem()),
        key_path: write(dir, &format!("{tag}.key.pem"), &leaf_key.serialize_pem()),
        ca_bundle_path: write(dir, &format!("{tag}.ca.pem"), &ca.cert.pem()),
    }
}

// -- SSL_CERT_FILE guard (WebPKI-mode tests) -----------------------------------

// `rustls-native-certs` reads `SSL_CERT_FILE` in place of the platform trust store when set
// (documented behavior, not a hack) — the standard way to make "WebPKI mode" deterministic in a
// test without touching /etc. `cargo nextest` runs each test in its own process, so no cross-test
// mutex is needed the way `apps/rendezvous/src/config.rs`'s env-var tests need one under plain
// `cargo test`; this file is still only ever exercised via nextest per the task's Tests list.
struct SslCertFileGuard;

impl SslCertFileGuard {
    fn set(path: &Path) -> Self {
        // SAFETY: single-threaded-per-process under nextest; no other code in this test binary
        // reads/writes SSL_CERT_FILE concurrently.
        unsafe { std::env::set_var("SSL_CERT_FILE", path) };
        Self
    }
}

impl Drop for SslCertFileGuard {
    fn drop(&mut self) {
        // SAFETY: see `set`.
        unsafe { std::env::remove_var("SSL_CERT_FILE") };
    }
}

// -- harness --------------------------------------------------------------------

/// Bind a [`FederationListener`] on an ephemeral port and return it with its address.
async fn bind_listener(
    paths: &FederationTlsPaths<'_>,
    own_domain: &str,
    metrics: Option<Arc<Metrics>>,
) -> (FederationListener, SocketAddr) {
    let listener = FederationListener::bind("127.0.0.1:0", paths, own_domain, metrics)
        .await
        .expect("bind federation listener");
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

// -- happy path -------------------------------------------------------------

#[tokio::test]
async fn happy_path_private_ca_mode() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");
    let a = mint_identity(dir.path(), "a", "a.federation.test", &ca);
    let b = mint_identity(dir.path(), "b", "b.federation.test", &ca);

    let metrics = Arc::new(Metrics::new());
    let (listener, addr) =
        bind_listener(&b.paths(), "b.federation.test", Some(metrics.clone())).await;

    let accept_task = tokio::spawn(async move { listener.accept().await });

    let mut dialer_link = dial(
        addr,
        "b.federation.test",
        &a.paths(),
        "a.federation.test",
        Some(metrics.clone()),
        FederationTimeouts::default(),
    )
    .await
    .expect("dial succeeds under a shared private CA with matching pinned domain");
    assert_eq!(dialer_link.peer_domain, "b.federation.test");

    let (mut listener_link, _peer_addr) = accept_task
        .await
        .unwrap()
        .expect("listener accepts a client cert that chains to the same private CA");
    assert_eq!(listener_link.peer_domain, "a.federation.test");

    // Both sides established — the aggregate gauge counts both ends of the same logical link.
    assert_eq!(metrics.federation_links_up(), 2);

    // Framing round-trips over the mTLS link (federation-protocol-v1.md §1).
    let target = [7u8; 32];
    let out = FedFrame::new(FedOp::Reachability, 42, &FedReachability { target }).unwrap();
    dialer_link.send_frame(&out).await.unwrap();
    let got = listener_link.recv_frame().await.unwrap();
    assert_eq!(got.op, FedOp::Reachability);
    assert_eq!(got.id, 42);
    let got_body: FedReachability = got.decode().unwrap();
    assert_eq!(got_body.target, target);

    drop(dialer_link);
    drop(listener_link);
    assert_eq!(metrics.federation_links_up(), 0);
}

#[tokio::test]
async fn happy_path_webpki_mode() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA (WebPKI-mode fixture)");
    let a = mint_identity(dir.path(), "a", "a.federation.test", &ca);
    let b = mint_identity(dir.path(), "b", "b.federation.test", &ca);

    // WebPKI mode: no `ca_bundle_path`, validate against the OS/system trust store — pointed at
    // our test CA via SSL_CERT_FILE (rustls-native-certs' documented override), never a real
    // system CA.
    let _guard = SslCertFileGuard::set(&b.ca_bundle_path);

    let (listener, addr) = bind_listener(&b.webpki_paths(), "b.federation.test", None).await;
    let accept_task = tokio::spawn(async move { listener.accept().await });

    let dialer_link = dial(
        addr,
        "b.federation.test",
        &a.webpki_paths(),
        "a.federation.test",
        None,
        FederationTimeouts::default(),
    )
    .await
    .expect("WebPKI-mode dial succeeds when SSL_CERT_FILE trusts the issuing CA");
    assert_eq!(dialer_link.peer_domain, "b.federation.test");

    let (listener_link, _addr) = accept_task
        .await
        .unwrap()
        .expect("WebPKI-mode accept succeeds symmetrically");
    assert_eq!(listener_link.peer_domain, "a.federation.test");
}

// -- untrusted CA rejected ----------------------------------------------------

#[tokio::test]
async fn untrusted_ca_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let legit_ca = make_ca("Meridian Test Federation CA (legit)");
    let rogue_ca = make_ca("Not The Federation CA");

    // The listener only trusts `legit_ca` and presents a `legit_ca`-signed identity.
    let b = mint_identity(dir.path(), "b", "b.federation.test", &legit_ca);
    // The dialer presents a cert for the SAME domain name, but signed by a CA the listener never
    // enrolled — the private-CA impersonation hole ADR 0017 (a) exists to close.
    let a_rogue = mint_identity(dir.path(), "a-rogue", "a.federation.test", &rogue_ca);
    // Dialer still needs to trust the listener's (legit) CA to get far enough to present its own
    // (rogue) client cert — otherwise this test would fail for the wrong reason (server-cert
    // rejection, not client-cert rejection).
    let a_dial_paths = FederationTlsPaths {
        cert_path: a_rogue.paths().cert_path,
        key_path: a_rogue.paths().key_path,
        ca_bundle_path: b.paths().ca_bundle_path, // trusts legit_ca, to reach the client-cert check
    };

    let (listener, addr) = bind_listener(&b.paths(), "b.federation.test", None).await;
    let accept_task = tokio::spawn(async move { listener.accept().await });

    let dial_result = dial(
        addr,
        "b.federation.test",
        &a_dial_paths,
        "a.federation.test",
        None,
        FederationTimeouts::default(),
    )
    .await;
    assert!(
        dial_result.is_err(),
        "dial must fail: the listener does not trust the rogue CA that signed the client cert"
    );

    let accept_result = accept_task.await.unwrap();
    assert!(
        accept_result.is_err(),
        "accept must fail: client cert chains to an untrusted CA"
    );
}

// -- wrong domain rejected ----------------------------------------------------

#[tokio::test]
async fn valid_cert_for_wrong_domain_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");
    // The listener's cert is validly signed by the shared CA, but for "wrong.federation.test" —
    // NOT the domain the dialer intends to reach.
    let wrong_domain_server = mint_identity(dir.path(), "wrong", "wrong.federation.test", &ca);
    let a = mint_identity(dir.path(), "a", "a.federation.test", &ca);

    let (listener, addr) =
        bind_listener(&wrong_domain_server.paths(), "wrong.federation.test", None).await;
    let accept_task = tokio::spawn(async move { listener.accept().await });

    // The dialer PINS to "b.federation.test" (what it actually intended to reach), never the
    // listener's real identity — this is ADR 0017 (a)/C3's entire point: a cert that is otherwise
    // perfectly valid (chains to the trusted CA) must still be rejected if it's for the wrong name.
    let dial_result = dial(
        addr,
        "b.federation.test",
        &a.paths(),
        "a.federation.test",
        None,
        FederationTimeouts::default(),
    )
    .await;
    let err = dial_result
        .err()
        .expect("dial must fail: server cert is valid but for a different domain than intended");
    match err {
        LinkError::Io(_) => {} // rustls's own hostname verification rejected it first
        LinkError::DomainMismatch { .. } => {} // or our own belt-and-suspenders check did
        other => {
            panic!("expected an Io (rustls hostname check) or DomainMismatch error, got {other:?}")
        }
    }

    // The listener's accept() future either errors (rustls saw the handshake abort) or simply
    // never completes because the dialer walked away first; either is an acceptable outcome here
    // (the security property under test is entirely on the dialer's pinning, which the assertion
    // above already proved) — abort the still-pending accept rather than hang the test.
    accept_task.abort();
}

// -- missing client cert rejected ---------------------------------------------

/// NOTE (code-reviewer follow-up on task 2.4): this test on its own only proves "no client cert
/// ⇒ no usable link" — it does NOT, by itself, isolate *why* the connection fails. Empirically, it
/// still passes even if `build_server_tls_config` were regressed to `with_no_client_auth` (i.e.
/// mTLS made optional at the TLS layer), because `FederationListener::accept`'s own
/// `conn.peer_certificates().ok_or(LinkError::NoPeerIdentity)` app-level check coincidentally also
/// rejects a certless peer. And in that broken configuration it would in fact reject EVERY
/// connection, not just this deliberately certless one — a regression that this test alone would
/// NOT distinguish from a healthy server.
///
/// What actually proves mTLS is mandatory (i.e. that `WebPkiClientVerifier`/
/// `with_client_cert_verifier` is wired into `build_server_tls_config`, not `with_no_client_auth`)
/// is the happy-path tests above (`happy_path_private_ca_mode`/`happy_path_webpki_mode`): under
/// `with_no_client_auth`, the server never sends a `CertificateRequest`, so the dialer — even
/// though `federation::dial`'s `ClientConfig` is always configured with a client cert via
/// `with_client_auth_cert` — never presents one, and `accept()`'s `peer_certificates()` check then
/// finds nothing and errors. So the happy-path tests would start failing under that regression,
/// which is what actually pins mandatory client auth to the TLS-layer verifier rather than to this
/// test's app-level fallback check.
#[tokio::test]
async fn missing_client_cert_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca("Meridian Test Federation CA");
    let b = mint_identity(dir.path(), "b", "b.federation.test", &ca);

    let (listener, addr) = bind_listener(&b.paths(), "b.federation.test", None).await;
    let accept_task = tokio::spawn(async move { listener.accept().await });

    // Bypass `federation::dial` (which always attaches a client cert) and connect with a bare
    // rustls client that presents NO client certificate at all.
    let mut roots = rustls::RootCertStore::empty();
    let ca_bundle_bytes = std::fs::read(&b.ca_bundle_path).unwrap();
    for cert in CertificateDer::pem_slice_iter(&ca_bundle_bytes)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        roots.add(cert).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name =
        rustls::pki_types::ServerName::try_from("b.federation.test".to_string()).unwrap();

    // NOTE on why this isn't a plain `connect(...).await.is_err()` assertion: in TLS 1.3
    // (RFC 8446 §4.4.2), a client with no certificate sends an empty Certificate message and
    // considers ITS side of the handshake complete once it has sent its own Finished — it does not
    // wait for the server's verdict. The server-side mandatory-client-cert check runs when the
    // server processes that (empty) Certificate message, which happens strictly after the client
    // already returned from `connect()`; the rejection (a fatal `CertificateRequired` alert) only
    // surfaces to the client on its next read. So `connect()` itself is expected to succeed here —
    // the assertion is on the first read afterward.
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("client-side TLS 1.3 handshake completes without waiting for the server's verdict");
    let mut buf = [0u8; 1];
    let read_result = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
    assert!(
        matches!(read_result, Err(_) | Ok(0)),
        "the server must tear down the connection (fatal alert / close) once it processes the \
         missing client certificate — got {read_result:?}"
    );

    let accept_result = accept_task.await.unwrap();
    assert!(
        accept_result.is_err(),
        "accept() must reject a peer that never presented a client certificate"
    );
}

// -- fail-closed cert/key/CA-bundle loading (security-reviewer follow-up) -----
//
// The happy-path/rejection tests above only exercise `load_cert_chain`/`load_private_key`/
// `load_root_store` indirectly, via a `dial`/`accept` that always has valid on-disk material —
// the "missing/empty/bogus material fails closed" property was previously only implicit in
// `std::fs::read`'s own error behavior, with no test asserting it. These tests call
// `build_client_tls_config`/`build_server_tls_config` directly (no need to go through a full
// `FederationListener`/`dial`) to prove each way that material can be missing or malformed is
// rejected with `Err`, never silently downgraded to a permissive/empty config.

/// One otherwise-valid identity (leaf cert + key + the CA bundle it was signed under), for the
/// fail-closed tests below to selectively swap one path out to something broken.
fn valid_identity(dir: &Path) -> Identity {
    let ca = make_ca("Meridian Test Federation CA (fail-closed fixtures)");
    mint_identity(dir, "fail-closed", "fail-closed.federation.test", &ca)
}

#[test]
fn empty_cert_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let id = valid_identity(dir.path());
    let paths = FederationTlsPaths {
        cert_path: "",
        key_path: id.paths().key_path,
        ca_bundle_path: id.paths().ca_bundle_path,
    };
    assert!(
        build_client_tls_config(&paths).is_err(),
        "build_client_tls_config must fail closed on an empty cert_path"
    );
    assert!(
        build_server_tls_config(&paths).is_err(),
        "build_server_tls_config must fail closed on an empty cert_path"
    );
}

#[test]
fn empty_key_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let id = valid_identity(dir.path());
    let paths = FederationTlsPaths {
        cert_path: id.paths().cert_path,
        key_path: "",
        ca_bundle_path: id.paths().ca_bundle_path,
    };
    assert!(
        build_client_tls_config(&paths).is_err(),
        "build_client_tls_config must fail closed on an empty key_path"
    );
    assert!(
        build_server_tls_config(&paths).is_err(),
        "build_server_tls_config must fail closed on an empty key_path"
    );
}

#[test]
fn nonexistent_ca_bundle_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let id = valid_identity(dir.path());
    // Never actually written — `ca_bundle_path` non-empty selects private-CA mode, and this path
    // simply doesn't exist on disk.
    let missing = dir.path().join("does-not-exist.pem");
    let paths = FederationTlsPaths {
        cert_path: id.paths().cert_path,
        key_path: id.paths().key_path,
        ca_bundle_path: missing.to_str().unwrap(),
    };
    assert!(
        build_client_tls_config(&paths).is_err(),
        "build_client_tls_config must fail closed on a nonexistent ca_bundle_path"
    );
    assert!(
        build_server_tls_config(&paths).is_err(),
        "build_server_tls_config must fail closed on a nonexistent ca_bundle_path"
    );
}

#[test]
fn ca_bundle_with_zero_certs_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let id = valid_identity(dir.path());
    // Exists and reads fine, but contains no PEM certificate — `CertificateDer::pem_slice_iter`
    // parses zero entries out of this, exactly as it would for e.g. an accidentally-truncated file
    // or one that was never actually a certificate bundle.
    let bogus_bundle = write(dir.path(), "empty.ca.pem", "not a pem file at all\n");
    let paths = FederationTlsPaths {
        cert_path: id.paths().cert_path,
        key_path: id.paths().key_path,
        ca_bundle_path: bogus_bundle.to_str().unwrap(),
    };
    assert!(
        build_client_tls_config(&paths).is_err(),
        "build_client_tls_config must fail closed on a ca_bundle_path that parses to zero certs"
    );
    assert!(
        build_server_tls_config(&paths).is_err(),
        "build_server_tls_config must fail closed on a ca_bundle_path that parses to zero certs"
    );
}
