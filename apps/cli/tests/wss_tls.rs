//! T3.13 / review finding F13 — proves the `wss://` crypto-provider install
//! (`meridian_signaling::install_crypto_provider`, called from `SignalingClient::connect` /
//! `connect_with_test_ca_pem`) actually unblocks a **real** TLS handshake, not just that
//! `rustls::crypto::CryptoProvider::get_default()` returns `Some` in isolation — the narrower unit
//! test for that lives next to the function itself
//! (`apps/signaling/src/client.rs`'s `#[cfg(test)] mod tests`).
//!
//! Before this was fixed (PR #42), every `wss://` connection panicked at runtime with no
//! `CryptoProvider` installed, and nothing tested it — the only `wss://` path in this repo runs
//! behind Docker (a reverse proxy terminating TLS in front of `meridian-rendezvous`'s
//! plaintext-only c2s listener, ADR 0008; unlike the s2s federation link, which terminates TLS
//! in-process, see `apps/rendezvous/Cargo.toml`), which CI never exercises.
//!
//! ## Ordering: why this test's own TLS front end defers building its `ServerConfig`
//! `rustls::ClientConfig::builder()`/`ServerConfig::builder()` both panic if no default
//! `CryptoProvider` has ever been resolved for the process. [`run_tls_front_once`] — this test's
//! stand-in for the reverse proxy — defers its OWN `rustls::ServerConfig::builder()` call until
//! *after* accepting the incoming TCP connection, which can only happen once the client has
//! actually dialed out; the client (`wss_connect_completes_a_real_tls_handshake`, below) calls
//! `SignalingClient::connect_with_test_ca_pem`, whose `install_crypto_provider()` call is plain
//! synchronous program order strictly before it ever opens that TCP connection. This keeps the
//! test correct and non-flaky (the front end is never the first thing to need a provider) and
//! keeps `install_crypto_provider()`'s call site the *only* place that explicitly installs one in
//! this test binary.
//!
//! **That said — read this before trusting this test as T3.13/F13's mutation-check.** rustls
//! 0.23's `ClientConfig::builder()`/`ServerConfig::builder()` have their own convenience fallback:
//! if *exactly one* provider crate-feature is compiled in (here, `ring` — this workspace never
//! enables `aws-lc-rs`), they silently self-install it on first use
//! (`CryptoProvider::get_default_or_install_from_crate_features`), whether or not
//! `install_crypto_provider()` ever ran. Deleting that call's body does **not** turn this
//! particular test red — confirmed by trial, see the task file's Outcome, which also covers why
//! forcing genuine ambiguity via rustls's `custom-provider` feature was tried and reverted (it
//! broke an unrelated `dtls`/`webrtc` code path). The actual red/green mutation-check for
//! T3.13/F13 is `apps/signaling/src/client.rs`'s `install_crypto_provider_installs_a_default` unit
//! test, which calls `install_crypto_provider()` directly and checks `get_default()` *without*
//! ever going through a rustls builder — so rustls's fallback can't mask it. This integration test
//! still matters in its own right: it's the only place in this repo that proves a `wss://`
//! `SignalingClient` connection — TLS handshake, then the full rendezvous challenge/auth exchange
//! — actually completes against a real (self-signed) TLS listener.

mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use meridian_core::identity::{generate_account, MemorySecretStore};
use meridian_core::signaling::SignalingClient;
use meridian_rendezvous::{AppState, MemoryStore};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};

use support::{base_config, spawn_c2s, TestCa};

/// Accept exactly one TCP connection on `tls_listener`, TLS-terminate it against
/// `cert_path`/`key_path` (built lazily — see this file's module docs on why), then splice the
/// decrypted bytes into a fresh plain-TCP connection to `plain_addr`: a minimal stand-in for the
/// reverse proxy that terminates `wss://` in front of `meridian-rendezvous`'s c2s listener in
/// production.
async fn run_tls_front_once(
    tls_listener: TcpListener,
    cert_path: PathBuf,
    key_path: PathBuf,
    plain_addr: SocketAddr,
) {
    let (tcp, _peer) = tls_listener.accept().await.expect("accept tls front");

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert_path)
        .expect("open leaf cert pem")
        .collect::<Result<_, _>>()
        .expect("parse leaf cert pem");
    let key = PrivateKeyDer::from_pem_file(&key_path).expect("parse leaf key pem");
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build server tls config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let mut tls_stream = acceptor.accept(tcp).await.expect("tls accept");

    let mut plain = TcpStream::connect(plain_addr)
        .await
        .expect("connect to plain c2s listener");
    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut plain).await;
}

/// Real self-signed `wss://` end to end: `SignalingClient::connect_with_test_ca_pem` completes a
/// genuine TCP connect + TLS handshake (against a certificate this test's own CA minted) THEN the
/// rendezvous challenge/auth handshake, against a TLS-terminating front standing in front of a
/// real in-process rendezvous server. Failing anywhere in that chain fails this test — including a
/// `rustls` panic from a missing `CryptoProvider`, though see the module docs above for why that
/// specific failure mode doesn't currently reproduce from deleting `install_crypto_provider()`
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wss_connect_completes_a_real_tls_handshake() {
    // -- a real (plaintext) c2s rendezvous, exactly as production runs it in-process --
    let config = base_config("wss-test.example");
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(config, store);
    let plain_url = spawn_c2s(state).await;
    let plain_addr: SocketAddr = plain_url
        .strip_prefix("ws://")
        .expect("spawn_c2s returns a ws:// url")
        .parse()
        .expect("valid socket addr");

    // -- this test's own CA + leaf cert; an IP SAN (not a DNS name) so there is no hostname
    // resolution ambiguity between the client's connect address and what the cert covers.
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();
    let leaf = ca.issue(dir.path(), "wss", "127.0.0.1");

    // -- TLS-terminating front end (builds its ServerConfig lazily — see module docs) --
    let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_addr = tls_listener.local_addr().unwrap();
    let front = tokio::spawn(run_tls_front_once(
        tls_listener,
        leaf.cert_path.clone(),
        leaf.key_path.clone(),
        plain_addr,
    ));

    // -- the client path under test --
    let ca_pem = std::fs::read(&leaf.ca_bundle_path).unwrap();
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "wss-test.example").unwrap();
    let ik = *account.public_key().as_bytes();
    let url = format!("wss://{tls_addr}");

    let client = SignalingClient::connect_with_test_ca_pem(
        &url,
        &ca_pem,
        &store,
        account.handle(),
        ik,
        None,
        1,
    )
    .await
    .expect("wss:// connect must complete a real TLS handshake and the rendezvous auth handshake");

    assert_eq!(client.account_pub(), &ik);

    // Drop the client to close its end of the TLS connection, letting the front end's
    // `copy_bidirectional` observe EOF and return instead of hanging.
    drop(client);
    front.await.expect("tls front task must not panic");
}
