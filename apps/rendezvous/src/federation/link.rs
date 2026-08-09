//! rustls-based s2s mTLS listener + dialer, and the `FedHello` link-establishment exchange
//! (docs/api/federation-protocol-v1.md §1/§2).
//!
//! ## Verification model (ADR 0017 (a)/C3, one rule for both modes)
//!
//! Both the dialer and the listener build their `rustls` config from the same
//! [`FederationTlsPaths`]: a leaf cert + key (this server's own federation identity, presented as
//! both the TLS *client* cert when dialing and the TLS *server* cert when listening) and a trust
//! root, which is either:
//! - the **OS/system trust store** (`ca_bundle_path` empty — "WebPKI mode"), loaded via
//!   `rustls-native-certs`, or
//! - **exactly** the certificates in `ca_bundle_path` (non-empty — "private-CA / air-gap mode"),
//!   never additionally the system store — the whole air-gap trust model depends on this being an
//!   *exclusive* root, not an additive one (ADR 0017 C4).
//!
//! [`dial`] additionally takes `expected_domain`: the domain THIS side intended to reach, per ADR
//! 0017 (a) — never the literal address/hostname it happened to dial (that's a job for discovery,
//! [2.5](../../../../docs/tasks/phase-2/2.5-federation-discovery.md), out of scope here). rustls's
//! own hostname verification, driven by the `ServerName` passed to `TlsConnector::connect`, is the
//! primary enforcement of this pin — a cert that chains to the trust root but whose SAN doesn't
//! cover `expected_domain` fails the handshake outright. [`dial`] additionally re-extracts and
//! re-asserts the peer's SAN/CN identity after the handshake succeeds, purely as defense in depth
//! (belt-and-suspenders: the pin stays explicit in this crate's own code, not only implicit in
//! `rustls`'s internals).
//!
//! [`FederationListener::accept`] has no prior "expected domain" to pin against — any inbound peer
//! whose client cert chains to the configured trust root is accepted at the TLS layer; *which*
//! peers are actually allowed to federate at all is a policy decision
//! ([2.6](../../../../docs/tasks/phase-2/2.6-federation-policy-limits.md), out of scope here). What
//! this task's listener does is learn and report the peer's authenticated origin domain (SAN/CN of
//! the validated client cert) so that later policy can act on it.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use meridian_proto::{FedFrame, FedHello, FedOp, FED_VERSION};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::metrics::Metrics;

/// Hard ceiling on one frame's encoded length (the u32-LE length prefix,
/// docs/api/federation-protocol-v1.md §1). Enforced BEFORE allocating a receive buffer: even a
/// peer that has already completed mTLS may misbehave (or be compromised), and must not be able to
/// force an unbounded allocation merely by sending a large length prefix ahead of a short or absent
/// body. Generous relative to any `FedHello`/`FedRoute`-sized body.
pub const MAX_FRAME_LEN: usize = 1 << 20; // 1 MiB

/// A deadline (`tokio::time::timeout`) elapsed before `fut` completed. Kept as its own tiny error
/// type — not folded into [`LinkError`] — because [`with_deadline`] is generic over ANY future, not
/// just link-establishment ones: task 3.3 (outbound s2s dial timeouts) wraps
/// [`dial`]/connect-and-write futures in the exact same helper, and a caller composing `with_deadline`
/// around some other future entirely (not a `Result<_, LinkError>`) still gets a meaningful error.
#[derive(Debug, thiserror::Error)]
#[error("operation did not complete within {0:?}")]
pub struct DeadlineExceeded(pub Duration);

/// Run `fut` to completion, or fail with [`DeadlineExceeded`] once `duration` elapses — a thin,
/// consistently-typed wrapper around `tokio::time::timeout`.
///
/// Shared by both directions of s2s federation:
/// - inbound (this task, 3.2): [`FederationListener`]'s accept loop wraps
///   [`FederationListener::finish_handshake`] in `with_deadline(handshake_timeout, ...)` so one
///   silent/slow peer's mTLS+`FedHello` handshake cannot wedge the whole listener (the raw
///   `tcp.accept()` itself — [`FederationListener::accept_raw`] — stays outside any deadline: it is
///   already bounded by the OS accept queue and must never be blocked on a peer's behavior at all).
/// - outbound (task 3.3, not this task): the dial-out path reuses this same helper rather than
///   hand-rolling its own `tokio::time::timeout` call with a different error shape.
pub async fn with_deadline<F, T>(duration: Duration, fut: F) -> Result<T, DeadlineExceeded>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(duration, fut)
        .await
        .map_err(|_elapsed| DeadlineExceeded(duration))
}

/// Errors establishing or operating an s2s federation link.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("tls config error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("frame codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    #[error("failed to load certificate/key material: {0}")]
    Cert(String),
    #[error("peer presented no usable domain identity (no SAN or CN found on its certificate)")]
    NoPeerIdentity,
    #[error(
        "peer certificate identity {found:?} does not include the intended domain {expected:?}"
    )]
    DomainMismatch {
        expected: String,
        found: Vec<String>,
    },
    #[error("unexpected FedHello: {0}")]
    Handshake(String),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    FrameTooLarge(usize),
    /// (task 3.3, review finding F3) One step of the OUTBOUND dial/exchange path — `phase` is a
    /// static, non-identifying label (`"connect"` | `"tls"` | `"hello"` | `"request"`), never
    /// anything derived from the peer's address/domain, mirroring `inbound.rs`'s `DropRateLimiter`
    /// convention of static reason strings only — did not complete within `duration`. Kept as a
    /// single variant covering every phase (rather than one variant per phase) because every
    /// caller (`ws.rs`'s `federated_fetch_error_reply`/`federated_route_error_reply`) already
    /// treats every other `Dial{source: LinkError, ..}` outcome identically (`FED_UNREACHABLE`) —
    /// a genuinely different variant per phase would add no client-visible distinction, only more
    /// match arms to keep in sync.
    #[error("dial timed out during {phase} after {duration:?}")]
    Timeout {
        phase: &'static str,
        duration: Duration,
    },
}

/// Outbound dial timeout budget (task 3.3, review finding F3): bounds how long [`dial`] — and,
/// reused by [`crate::federation::outbound`], each individual s2s request/reply exchange over an
/// already-established link (`fetch_foreign_bundle`, `reachable_foreign`) — will wait at each
/// step before giving up, so a black-holed partner (one that accepts a TCP connection but never
/// completes TLS, or completes the handshake but never answers) cannot hang the originating
/// client's WebSocket session or leak a pinned task plus TLS link forever.
///
/// The concrete default values (`config::Federation::connect_timeout_ms`/`request_timeout_ms`)
/// are `TODO: confirm` there, not here — this type only carries whatever the caller resolved.
#[derive(Clone, Copy, Debug)]
pub struct FederationTimeouts {
    /// Bounds the raw `TcpStream::connect` step only — before any TLS byte is exchanged.
    pub connect: Duration,
    /// Bounds EACH of `dial`'s TLS-handshake and `FedHello`-exchange steps (two separate
    /// deadlines, not one shared budget spanning both), and each individual outbound s2s
    /// request/reply exchange over an already-established link. One shared knob across all of
    /// these post-connect steps, mirroring `Federation::handshake_timeout_ms`'s single knob for
    /// the whole INBOUND mTLS+`FedHello` handshake, rather than a separate knob per step.
    pub request: Duration,
}

impl Default for FederationTimeouts {
    /// Mirrors `config::Federation::default`'s `connect_timeout_ms = 5_000` /
    /// `request_timeout_ms = 10_000` — kept in sync manually since this type has no dependency on
    /// `crate::config` (same split as `FederationTlsPaths`/`config::Federation`'s TLS-path
    /// fields). Used by tests that don't care about this task's specific timeout values; `dial`'s
    /// real callers always pass an explicit value resolved from config.
    fn default() -> Self {
        Self {
            connect: Duration::from_millis(5_000),
            request: Duration::from_millis(10_000),
        }
    }
}

/// Await one phase of [`dial`]'s connect/TLS/hello sequence under `duration`, collapsing BOTH "the
/// phase's own operation failed" and "the phase's deadline elapsed" into a single [`LinkError`] —
/// callers need only one `?`, and a deadline expiry becomes [`LinkError::Timeout`] tagged with
/// `phase` rather than a bare [`DeadlineExceeded`] that would need re-wrapping at every call site.
async fn dial_phase<F, T, E>(
    duration: Duration,
    phase: &'static str,
    fut: F,
) -> Result<T, LinkError>
where
    F: Future<Output = Result<T, E>>,
    LinkError: From<E>,
{
    match with_deadline(duration, fut).await {
        Ok(inner) => inner.map_err(LinkError::from),
        Err(DeadlineExceeded(duration)) => Err(LinkError::Timeout { phase, duration }),
    }
}

/// PEM file paths for this rendezvous's own federation identity and trust root. Mirrors
/// `config::Federation`'s `cert_path`/`key_path`/`ca_bundle_path` field-for-field; kept as its own
/// (borrowed) type so this module has no dependency on `crate::config` beyond what its caller
/// hands it explicitly.
#[derive(Clone, Copy, Debug)]
pub struct FederationTlsPaths<'a> {
    /// This server's own federation identity certificate (leaf, optionally + intermediate chain).
    pub cert_path: &'a str,
    /// The private key matching `cert_path`.
    pub key_path: &'a str,
    /// Empty ⇒ WebPKI mode (OS/system trust store via `rustls-native-certs`). Non-empty ⇒
    /// private-CA / air-gap mode: trust ONLY this bundle (ADR 0017 (a)/C3/C4).
    pub ca_bundle_path: &'a str,
}

/// Install `ring` as the process-wide default `rustls` crypto provider, once. Idempotent: a second
/// (or concurrent) call observes "already installed" and is silently ignored — `rustls::ClientConfig
/// ::builder()`/`ServerConfig::builder()` panic if no default provider is installed at all, and
/// this crate links exactly one provider (`ring`, `Cargo.toml`), so there is never a genuine choice
/// to make here.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Read `path` and parse every PEM certificate in it (leaf + any intermediates, in file order).
///
/// Uses `rustls-pki-types`'s own `PemObject` trait rather than `rustls-pemfile`: the latter is
/// unmaintained (RUSTSEC-2025-0134, no safe upgrade) and is now just a thin wrapper around this
/// same parsing code, which `rustls-pki-types` has shipped directly since 1.9.0.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, LinkError> {
    let bytes =
        std::fs::read(Path::new(path)).map_err(|e| LinkError::Cert(format!("{path}: {e}")))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .map_err(|e| LinkError::Cert(format!("{path}: {e}")))?;
    if certs.is_empty() {
        return Err(LinkError::Cert(format!(
            "{path}: no PEM certificates found"
        )));
    }
    Ok(certs)
}

/// Read `path` and parse the single PEM private key in it (PKCS#1/PKCS#8/SEC1, whichever it is).
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, LinkError> {
    let bytes =
        std::fs::read(Path::new(path)).map_err(|e| LinkError::Cert(format!("{path}: {e}")))?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| LinkError::Cert(format!("{path}: {e}")))
}

/// Build the trust root: the OS/system store (`ca_bundle_path` empty) or exclusively the
/// configured bundle (non-empty) — see this module's doc comment on the air-gap exclusivity
/// requirement (ADR 0017 C4).
fn load_root_store(ca_bundle_path: &str) -> Result<RootCertStore, LinkError> {
    let mut roots = RootCertStore::empty();
    if ca_bundle_path.is_empty() {
        let native = rustls_native_certs::load_native_certs();
        // Per-certificate parse errors are logged, not fatal (mirrors rustls-native-certs' own
        // documented behavior — a single malformed entry in a large OS store shouldn't take the
        // whole store down); a store that ends up empty after loading IS fatal, below.
        for err in &native.errors {
            eprintln!("federation: warning: native cert store: {err}");
        }
        for cert in native.certs {
            roots
                .add(cert)
                .map_err(|e| LinkError::Cert(format!("native trust store: {e}")))?;
        }
        if roots.is_empty() {
            return Err(LinkError::Cert(
                "WebPKI mode: no usable certificates in the OS/system trust store".into(),
            ));
        }
    } else {
        for cert in load_cert_chain(ca_bundle_path)? {
            roots
                .add(cert)
                .map_err(|e| LinkError::Cert(format!("{ca_bundle_path}: {e}")))?;
        }
    }
    Ok(roots)
}

/// Build the `rustls::ClientConfig` used to dial outbound federation links: trust root per
/// `load_root_store` (WebPKI or private-CA, see the module docs), presenting
/// `paths.cert_path`/`paths.key_path` as the mTLS client certificate (mandatory — s2s has no
/// unauthenticated mode, ADR 0017 C7).
pub fn build_client_tls_config(
    paths: &FederationTlsPaths<'_>,
) -> Result<Arc<ClientConfig>, LinkError> {
    ensure_crypto_provider();
    let roots = load_root_store(paths.ca_bundle_path)?;
    let cert_chain = load_cert_chain(paths.cert_path)?;
    let key = load_private_key(paths.key_path)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

/// Build the `rustls::ServerConfig` used to accept inbound federation links: requires a valid
/// client certificate chaining to the same trust root (`with_client_cert_verifier`, never
/// `with_no_client_auth` — a missing client cert must be rejected, ADR 0017 C7), presenting
/// `paths.cert_path`/`paths.key_path` as the server's own mTLS identity.
pub fn build_server_tls_config(
    paths: &FederationTlsPaths<'_>,
) -> Result<Arc<ServerConfig>, LinkError> {
    ensure_crypto_provider();
    let roots = Arc::new(load_root_store(paths.ca_bundle_path)?);
    let cert_chain = load_cert_chain(paths.cert_path)?;
    let key = load_private_key(paths.key_path)?;
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|e| LinkError::Cert(format!("client cert verifier: {e}")))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

/// Extract every DNS identity a leaf certificate asserts: SAN `dNSName` entries first (the
/// authoritative field per ADR 0017 (a)), falling back to the subject Common Name only if the
/// certificate carries no SAN at all (compatibility with minimal/legacy certs — never preferred
/// over SAN when both are present). Lowercased for case-insensitive comparison.
fn peer_identities(cert_der: &CertificateDer<'_>) -> Result<Vec<String>, LinkError> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| LinkError::Cert(format!("parsing peer certificate: {e}")))?;

    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in san.value.general_names.iter() {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                names.push(dns.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        for cn in cert.subject().iter_common_name() {
            if let Ok(s) = cn.as_str() {
                names.push(s.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        return Err(LinkError::NoPeerIdentity);
    }
    Ok(names)
}

/// Write one length-delimited [`FedFrame`]: `uint32-le(len(cbor(FedFrame))) || cbor(FedFrame)`
/// (docs/api/federation-protocol-v1.md §1).
async fn write_frame<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &FedFrame,
) -> Result<(), LinkError> {
    let bytes = frame.to_bytes()?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(LinkError::FrameTooLarge(bytes.len()));
    }
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one length-delimited [`FedFrame`], enforcing [`MAX_FRAME_LEN`] on the length prefix before
/// allocating the receive buffer.
async fn read_frame<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<FedFrame, LinkError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(LinkError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(FedFrame::from_bytes(&buf)?)
}

/// Perform the `FedHello` exchange (federation-protocol-v1.md §2): send our own
/// `FedHello{v, domain}` at `id = 0`, then read the peer's. Writes before reads — safe because
/// `FedHello` is a handful of bytes, far under any OS socket send buffer, so this cannot deadlock
/// waiting on a true full-duplex rendezvous the way a protocol with large first messages could.
///
/// Returns the peer's *self-asserted* `FedHello.domain`, for logging/diagnostics ONLY — never for
/// any policy/routing decision (ADR 0017 (a); federation-protocol-v1.md §2 "self-asserted /
/// informational only"). The authoritative peer domain is always the TLS-certificate-derived one
/// the caller already established before calling this.
async fn exchange_hello<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    own_domain: &str,
) -> Result<String, LinkError> {
    let hello = FedHello {
        v: FED_VERSION,
        domain: own_domain.to_string(),
    };
    let out = FedFrame::new(FedOp::Hello, 0, &hello)?;
    write_frame(stream, &out).await?;

    let in_frame = read_frame(stream).await?;
    if in_frame.op != FedOp::Hello || in_frame.id != 0 {
        return Err(LinkError::Handshake(format!(
            "expected Hello{{id=0}}, got {:?}{{id={}}}",
            in_frame.op, in_frame.id
        )));
    }
    let peer_hello: FedHello = in_frame.decode()?;
    if peer_hello.v != FED_VERSION {
        return Err(LinkError::Handshake(format!(
            "peer FED_VERSION {} != ours {FED_VERSION}",
            peer_hello.v
        )));
    }
    Ok(peer_hello.domain)
}

/// An established, mutually authenticated s2s link.
///
/// `peer_domain` is the peer's **cryptographically authenticated** origin domain: for a dialed
/// link this is the caller's own `expected_domain` (proven by the TLS handshake succeeding at
/// all, per this module's doc comment); for an accepted link it is extracted from the validated
/// client certificate's SAN/CN. It is NEVER the self-asserted `FedHello.domain` — see the
/// `exchange_hello` helper's docs.
pub struct FederationLink {
    pub peer_domain: String,
    stream: TlsStream<TcpStream>,
    metrics: Option<Arc<Metrics>>,
}

impl FederationLink {
    /// Send one [`FedFrame`] on this link.
    pub async fn send_frame(&mut self, frame: &FedFrame) -> Result<(), LinkError> {
        write_frame(&mut self.stream, frame).await
    }

    /// Receive one [`FedFrame`] from this link.
    pub async fn recv_frame(&mut self) -> Result<FedFrame, LinkError> {
        read_frame(&mut self.stream).await
    }
}

impl Drop for FederationLink {
    fn drop(&mut self) {
        // Link lifecycle (task 2.4 scope): every established link decrements the same aggregate
        // gauge it incremented on success, however the link ends (graceful close, error, or simply
        // being dropped) — see crate::metrics::Metrics::federation_link_up's doc for why this stays
        // a single aggregate counter with no per-partner label.
        if let Some(m) = &self.metrics {
            m.federation_link_down();
        }
    }
}

/// Dial `addr` and establish a federation link, pinning certificate validation to
/// `expected_domain` — the domain THIS side intended to reach (ADR 0017 (a)/C3), never the literal
/// `addr` it happened to dial. `addr` would normally come from discovery
/// ([2.5](../../../../docs/tasks/phase-2/2.5-federation-discovery.md)); this task takes it as an
/// explicit parameter since discovery doesn't exist yet. `own_domain` is this server's own
/// self-asserted `FedHello.domain` (diagnostic only). `metrics`, if given, is updated for the
/// link's lifetime (see [`FederationLink`]'s `Drop` impl).
///
/// **Task 3.3 (review finding F3, blocking):** every step that can block on a black-holed or
/// merely slow partner — the raw `TcpStream::connect`, the TLS handshake, and the `FedHello`
/// exchange — runs under [`dial_phase`]/[`with_deadline`], bounded by `timeouts.connect` (the
/// first step) or `timeouts.request` (the latter two, each its own independent deadline). Without
/// this, a partner that merely accepts a TCP connection and goes silent — never completing TLS —
/// would hang this call, and the pinned task plus TLS-layer resources awaiting it, forever; a
/// deadline that elapses at any of the three steps surfaces as [`LinkError::Timeout`], which
/// `federation::outbound`'s callers already fold into the same client-visible `fed_unreachable`
/// outcome as every other dial failure (see `outbound.rs`'s `Dial` error variant).
pub async fn dial(
    addr: SocketAddr,
    expected_domain: &str,
    paths: &FederationTlsPaths<'_>,
    own_domain: &str,
    metrics: Option<Arc<Metrics>>,
    timeouts: FederationTimeouts,
) -> Result<FederationLink, LinkError> {
    let tls_config = build_client_tls_config(paths)?;
    let connector = TlsConnector::from(tls_config);
    let tcp = dial_phase(timeouts.connect, "connect", TcpStream::connect(addr)).await?;
    let server_name = ServerName::try_from(expected_domain.to_string())
        .map_err(|e| LinkError::Cert(format!("invalid domain {expected_domain:?}: {e}")))?;

    // The handshake itself is the primary enforcement of the domain pin: rustls's hostname
    // verification rejects a cert that chains to the trust root but whose SAN doesn't cover
    // `server_name` before `connect` ever returns Ok.
    let tls_stream =
        dial_phase(timeouts.request, "tls", connector.connect(server_name, tcp)).await?;

    // Belt-and-suspenders re-check (see module docs): re-extract the peer's SAN/CN and re-assert
    // it covers `expected_domain` explicitly, rather than relying solely on the above having
    // already enforced it.
    let peer_cert = {
        let (_, conn) = tls_stream.get_ref();
        conn.peer_certificates()
            .and_then(|c| c.first())
            .cloned()
            .ok_or(LinkError::NoPeerIdentity)?
    };
    let identities = peer_identities(&peer_cert)?;
    if !identities
        .iter()
        .any(|n| n.eq_ignore_ascii_case(expected_domain))
    {
        return Err(LinkError::DomainMismatch {
            expected: expected_domain.to_string(),
            found: identities,
        });
    }

    let mut stream: TlsStream<TcpStream> = tls_stream.into();
    let _peer_asserted_domain = dial_phase(
        timeouts.request,
        "hello",
        exchange_hello(&mut stream, own_domain),
    )
    .await?;

    if let Some(m) = &metrics {
        m.federation_link_up();
    }
    Ok(FederationLink {
        peer_domain: expected_domain.to_string(),
        stream,
        metrics,
    })
}

/// Accepts inbound s2s mTLS connections and establishes [`FederationLink`]s (ADR 0017 C7:
/// terminates TLS in-process — this IS the TLS listener, not a hand-off point to a proxy/VIP).
pub struct FederationListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    own_domain: String,
    metrics: Option<Arc<Metrics>>,
}

impl FederationListener {
    /// Bind `bind_addr` and build the mTLS acceptor from `paths`. Fails closed: any error loading
    /// cert/key/CA material or binding the socket is returned, never silently degrades to "no
    /// client cert required" or "any CA trusted".
    pub async fn bind(
        bind_addr: &str,
        paths: &FederationTlsPaths<'_>,
        own_domain: &str,
        metrics: Option<Arc<Metrics>>,
    ) -> Result<Self, LinkError> {
        let tls_config = build_server_tls_config(paths)?;
        let tcp = TcpListener::bind(bind_addr).await?;
        Ok(Self {
            tcp,
            acceptor: TlsAcceptor::from(tls_config),
            own_domain: own_domain.to_string(),
            metrics,
        })
    }

    /// The bound local address (tests bind an ephemeral port and read it back).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    /// Accept one raw TCP connection — nothing more. Deliberately the *only* work `run_federation`'s
    /// accept loop (task 3.2) does inline: cheap, and bounded by the OS accept queue rather than by
    /// anything a peer does after connecting. Everything that CAN block on a hostile/slow peer (the
    /// mTLS handshake, the `FedHello` exchange) lives in [`Self::finish_handshake`] instead, which
    /// callers spawn as their own task, typically under [`with_deadline`].
    pub async fn accept_raw(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.tcp.accept().await
    }

    /// Finish establishing one inbound federation link from an already-`accept_raw`'d TCP stream:
    /// mTLS handshake (client certificate mandatory), origin-domain extraction from the validated
    /// client certificate's SAN/CN, and the `FedHello` exchange.
    ///
    /// Split out of [`Self::accept`] (task 3.2, F2/N5): this is the part of accepting a connection
    /// that a hostile or merely slow peer can stall indefinitely (an mTLS handshake that never
    /// sends a `ClientHello`, a `FedHello` whose length prefix never arrives), so callers that care
    /// about one such peer never blocking every other inbound connection — i.e. `run_federation` —
    /// spawn this per-connection and wrap it in [`with_deadline`], rather than `await`ing it inline
    /// in the accept loop the way [`Self::accept`] still does for callers (tests, mostly) that don't
    /// need that.
    pub async fn finish_handshake(
        &self,
        tcp: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(FederationLink, SocketAddr), LinkError> {
        // A missing (or otherwise invalid) client certificate is rejected here: this errors before
        // returning a stream, because `build_server_tls_config` always installs a
        // `WebPkiClientVerifier` (never `with_no_client_auth`) — mTLS is mandatory, ADR 0017 C7.
        let tls_stream = self.acceptor.accept(tcp).await?;

        let peer_cert = {
            let (_, conn) = tls_stream.get_ref();
            conn.peer_certificates()
                .and_then(|c| c.first())
                .cloned()
                .ok_or(LinkError::NoPeerIdentity)?
        };
        let identities = peer_identities(&peer_cert)?;
        // No prior "expected domain" to pin against on the accept side (see module docs) — the
        // first SAN/CN entry is what this side learns as the peer's authenticated origin domain.
        let peer_domain = identities[0].clone();

        let mut stream: TlsStream<TcpStream> = tls_stream.into();
        let _peer_asserted_domain = exchange_hello(&mut stream, &self.own_domain).await?;

        if let Some(m) = &self.metrics {
            m.federation_link_up();
        }
        Ok((
            FederationLink {
                peer_domain,
                stream,
                metrics: self.metrics.clone(),
            },
            peer_addr,
        ))
    }

    /// Accept and fully establish one inbound federation link in one call: [`Self::accept_raw`]
    /// followed immediately by [`Self::finish_handshake`], with no deadline and no concurrency cap.
    /// Kept for callers (chiefly tests, e.g. `tests/federation_mtls.rs`) that just want one link
    /// end to end; `run_federation`'s hardened accept loop (task 3.2) calls the two halves
    /// separately instead, so it is never blocked awaiting one peer's handshake.
    pub async fn accept(&self) -> Result<(FederationLink, SocketAddr), LinkError> {
        let (tcp, peer_addr) = self.accept_raw().await?;
        self.finish_handshake(tcp, peer_addr).await
    }
}
