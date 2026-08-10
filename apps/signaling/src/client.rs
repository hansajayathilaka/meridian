//! The async client half of the rendezvous protocol: connect, authenticate by account-key
//! challenge, publish a bundle, fetch-and-verify a peer bundle, and route/receive opaque envelopes.

use std::collections::VecDeque;

use futures_util::{SinkExt, StreamExt};
use meridian_identity::{sign, KeyHandle, SecretStore};
use meridian_proto::{
    Auth, AuthOk, Bundle, Challenge, Deliver, Fetch, Frame, Op, OpaqueBlob, PrekeyBundle, Publish,
    PublishOk, RouteBody, RouteOk, TurnGrant, TurnReq,
};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::bundle::{generate_bundle, verify_bundle, GeneratedBundle};
use crate::error::{Result, SignalError};

/// Install `ring` as the process-wide default `rustls` crypto provider, once. rustls 0.23 no
/// longer auto-selects a backend — `rustls::ClientConfig::builder()` (and `ServerConfig::builder()`)
/// **panics** if none is installed, so this must run before the first `wss://` TLS handshake this
/// process ever attempts.
///
/// Called at the top of [`SignalingClient::connect`] itself (previously this lived only in
/// `apps/cli/src/main.rs`'s `fn main()`, which meant every OTHER binary embedding `meridian-core`
/// — a future Tauri desktop backend, a mobile UniFFI host — would have hit the same "every `wss://`
/// connection panics" defect main.rs's own copy was written to fix, T3.13/F13). Putting it here
/// instead means it's impossible to reach a `wss://` handshake through this client without it
/// having run first, regardless of caller.
///
/// Idempotent: a second (or concurrent) call observes "already installed" and is silently
/// ignored — this crate links exactly one provider (`ring`, this crate's `Cargo.toml`), so there is
/// never a genuine choice to make here.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// An authenticated client session to a rendezvous server.
pub struct SignalingClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    account_pub: [u8; 32],
    server_domain: String,
    /// Server-pushed [`Deliver`] frames that arrived while awaiting a request reply.
    pending_delivers: VecDeque<Deliver>,
}

impl SignalingClient {
    /// Connect to `url` (`ws://` or `wss://`), complete the challenge–response handshake by
    /// signing `nonce ‖ server_domain` through `store`, and register the account.
    pub async fn connect(
        url: &str,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        install_crypto_provider();
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))?;
        Self::handshake(ws, store, handle, account_pub, invite, max_bundle_v).await
    }

    /// Same as [`Self::connect`], but trusting `ca_cert_pem` (one or more PEM certificates) as the
    /// **exclusive** TLS root instead of the OS/native trust store — for tests that stand up a
    /// self-signed `wss://` listener rather than reaching a real WebPKI-trusted host. Only built
    /// with `test-support` (this crate's `Cargo.toml`); never linked into a production binary.
    ///
    /// Calls [`install_crypto_provider`] first (below), same as [`Self::connect`], and this
    /// function's own `rustls::ClientConfig` is the first thing in a fresh test process to call
    /// `ClientConfig::builder()` (`apps/cli/tests/wss_tls.rs` defers its TLS-terminating test
    /// listener's `ServerConfig::builder()` call until after accepting the client's connection,
    /// specifically so no OTHER code in that process calls a rustls builder first).
    ///
    /// **Caveat (T3.13/F13 Outcome, read before trusting this as the mutation-check):** rustls
    /// 0.23's `ClientConfig::builder()`/`ServerConfig::builder()` silently self-install a default
    /// provider on first use when exactly one provider crate-feature is compiled in
    /// (`CryptoProvider::get_default_or_install_from_crate_features`) — true throughout this
    /// workspace, which only ever enables `ring`. That means deleting this function's (or
    /// [`Self::connect`]'s) call to [`install_crypto_provider`] does **not** make
    /// `wss_tls.rs` fail — rustls's own fallback quietly does the install instead. The genuinely
    /// mutation-sensitive proof for this task lives in `install_crypto_provider`'s own unit test,
    /// next to it below; this integration test still earns its keep by proving the rest of the
    /// `wss://` plumbing (root-trust wiring, the handshake, `connect_async_tls_with_config`) works
    /// end-to-end, just not that one specific line in isolation. See the task file's Outcome for
    /// the full investigation (an attempt to force genuine ambiguity via rustls's
    /// `custom-provider` feature broke an unrelated `dtls`/`webrtc` code path and was reverted).
    #[cfg(feature = "test-support")]
    pub async fn connect_with_test_ca_pem(
        url: &str,
        ca_cert_pem: &[u8],
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        use rustls::pki_types::pem::PemObject;

        install_crypto_provider();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(ca_cert_pem)
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| SignalError::Ws(format!("test CA pem: {e}")))?;
        if certs.is_empty() {
            return Err(SignalError::Ws("test CA pem: no certificates found".into()));
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| SignalError::Ws(format!("test CA pem: {e}")))?;
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(client_config));
        let (ws, _resp) =
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .map_err(|e| SignalError::Ws(e.to_string()))?;
        Self::handshake(ws, store, handle, account_pub, invite, max_bundle_v).await
    }

    /// Shared post-connect handshake: the server speaks first with a single-use challenge; sign
    /// `nonce ‖ server_domain` and register the account. Used by both [`Self::connect`] and (with
    /// `test-support`) [`Self::connect_with_test_ca_pem`] — the two differ only in how the
    /// underlying `WebSocketStream` was obtained.
    async fn handshake(
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        let mut client = Self {
            ws,
            next_id: 1,
            account_pub,
            server_domain: String::new(),
            pending_delivers: VecDeque::new(),
        };

        // The server speaks first with a single-use challenge.
        let frame = client.recv_frame().await?;
        if frame.op != Op::Challenge {
            return Err(SignalError::Unexpected {
                got: frame.op,
                expected: "challenge",
            });
        }
        let challenge: Challenge = frame.decode()?;
        client.server_domain = challenge.server_domain.clone();

        // Sign nonce ‖ server_domain (domain binding defeats cross-server challenge replay).
        let mut to_sign = challenge.nonce.to_vec();
        to_sign.extend_from_slice(challenge.server_domain.as_bytes());
        let sig = sign(store, handle, &to_sign)?;

        let auth = Auth {
            account_pub,
            sig: *sig.as_bytes(),
            invite,
            max_bundle_v,
        };
        let reply = client
            .request(Op::Auth, &auth, Op::AuthOk, "auth_ok")
            .await?;
        let _ok: AuthOk = reply.decode()?;
        Ok(client)
    }

    /// The account key this session authenticated as.
    pub fn account_pub(&self) -> &[u8; 32] {
        &self.account_pub
    }

    /// The rendezvous domain this session is bound to.
    pub fn server_domain(&self) -> &str {
        &self.server_domain
    }

    /// Generate and publish a fresh prekey bundle (1 signed prekey + `otk_count` one-time
    /// prekeys). Returns the generated bundle *and its secret scalars* for the caller to persist.
    pub async fn publish_bundle(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        otk_count: usize,
    ) -> Result<GeneratedBundle> {
        let generated = generate_bundle(store, handle, self.account_pub, otk_count)?;
        let publish = Publish {
            bundle: generated.bundle.clone(),
        };
        let reply = self
            .request(Op::Publish, &publish, Op::PublishOk, "publish_ok")
            .await?;
        let _ok: PublishOk = reply.decode()?;
        Ok(generated)
    }

    /// Fetch a peer's bundle by **exact** account key and verify every signature under that key.
    /// A bundle that fails verification (including one claiming a different key) is a hard error —
    /// the client refuses to proceed rather than downgrading.
    ///
    /// `hint` is the wire-level routing hint (task 2.7, `docs/api/wire-protocol.md` §2): a plain
    /// domain string, `None` for a same-server (local) fetch, `Some(domain)` when `target` names an
    /// account this client believes lives at a *foreign* org's server. This client never dials
    /// `domain` itself — it only ever talks to the server it `connect`ed to (`self`'s own
    /// WebSocket); that server is solely responsible for deciding, from `hint`, whether to answer
    /// locally or federate the request onward (system-design.md §3.3 steps 2-4, ADR 0001: the hint
    /// is advisory routing information, never a trust input). The verification below is identical
    /// either way — it is the only trust anchor regardless of which path the bundle took.
    pub async fn fetch_bundle(
        &mut self,
        target: [u8; 32],
        hint: Option<String>,
        tamper: bool,
    ) -> Result<PrekeyBundle> {
        let fetch = Fetch {
            target,
            hint: hint.clone(),
            tamper,
        };
        let reply = self
            .request(Op::Fetch, &fetch, Op::Bundle, "bundle")
            .await
            .map_err(|e| crate::error::classify_federation_error(e, hint.as_deref()))?;
        let bundle: Bundle = reply.decode()?;
        verify_bundle(&target, &bundle.bundle)?;
        Ok(bundle.bundle)
    }

    /// Route an opaque, client-signed envelope to an online peer. Returns whether it was delivered
    /// (offline delivery / mailbox is T07).
    pub async fn route(&mut self, to: [u8; 32], blob: Vec<u8>) -> Result<bool> {
        self.route_with_hint(to, None, blob).await
    }

    /// Route an opaque, client-signed envelope to `to`, optionally naming a foreign-domain
    /// `hint` (task 2.8, `docs/api/wire-protocol.md` §2) — the wire-level routing hint that tells
    /// this client's own server to forward the envelope across a federation boundary
    /// (`FedRoute`, docs/api/federation-protocol-v1.md) rather than deliver locally. Same
    /// "this client never dials `hint` itself" caveat as
    /// [`fetch_bundle`](Self::fetch_bundle)'s identical parameter: only the server this client is
    /// `connect`ed to ever federates a request onward.
    pub async fn route_with_hint(
        &mut self,
        to: [u8; 32],
        hint: Option<String>,
        blob: Vec<u8>,
    ) -> Result<bool> {
        let body = RouteBody {
            to,
            to_hint: hint.clone(),
            blob: OpaqueBlob::new(blob),
        };
        let reply = self
            .request(Op::Route, &body, Op::RouteOk, "route_ok")
            .await
            .map_err(|e| crate::error::classify_federation_error(e, hint.as_deref()))?;
        let ok: RouteOk = reply.decode()?;
        Ok(ok.delivered)
    }

    /// Request an ephemeral TURN credential, distinct per request, for a new P2P session (T05,
    /// §5.4). The returned [`TurnGrant`] carries the candidate ladder (TURN/UDP → TURN/TCP →
    /// TURN/TLS-443) and an HMAC credential the client feeds straight into its ICE config — no
    /// static TURN secret ever touches the client (webrtc-nat-traversal invariant 4). Reuse of a
    /// captured credential within its TTL is bounded by coturn's `user-quota`, not rejected outright.
    /// A `turn_unavailable` error means the org runs no relay (air-gapped / dev); the caller falls
    /// back to the host/STUN ladder.
    pub async fn request_turn_credentials(&mut self) -> Result<TurnGrant> {
        let reply = self
            .request(
                Op::TurnReq,
                &TurnReq::default(),
                Op::TurnGrant,
                "turn_grant",
            )
            .await?;
        Ok(reply.decode()?)
    }

    /// Await the next envelope delivered to this client.
    pub async fn next_deliver(&mut self) -> Result<Deliver> {
        if let Some(d) = self.pending_delivers.pop_front() {
            return Ok(d);
        }
        let frame = self.recv_frame().await?;
        match frame.op {
            Op::Deliver => Ok(frame.decode()?),
            Op::Err => Err(SignalError::Server(frame.decode()?)),
            other => Err(SignalError::Unexpected {
                got: other,
                expected: "deliver",
            }),
        }
    }

    /// Close the WebSocket cleanly.
    pub async fn close(mut self) -> Result<()> {
        self.ws
            .close(None)
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))
    }

    // -- internals -----------------------------------------------------------

    async fn send(&mut self, op: Op, body: &impl Serialize) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let frame = Frame::new(op, id, body)?;
        let bytes = frame.to_bytes()?;
        self.ws
            .send(Message::Binary(bytes))
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))?;
        Ok(id)
    }

    /// Send a request and read frames until the matching reply (buffering interleaved delivers).
    async fn request(
        &mut self,
        op: Op,
        body: &impl Serialize,
        expect: Op,
        expected_name: &'static str,
    ) -> Result<Frame> {
        let _id = self.send(op, body).await?;
        loop {
            let frame = self.recv_frame().await?;
            match frame.op {
                Op::Deliver => self.pending_delivers.push_back(frame.decode()?),
                Op::Err => return Err(SignalError::Server(frame.decode()?)),
                got if got == expect => return Ok(frame),
                got => {
                    return Err(SignalError::Unexpected {
                        got,
                        expected: expected_name,
                    })
                }
            }
        }
    }

    async fn recv_frame(&mut self) -> Result<Frame> {
        while let Some(msg) = self.ws.next().await {
            let msg = msg.map_err(|e| SignalError::Ws(e.to_string()))?;
            match msg {
                Message::Binary(bytes) => return Ok(Frame::from_bytes(&bytes)?),
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err(SignalError::ClosedEarly("frame")),
                Message::Text(_) => return Err(SignalError::Ws("unexpected text frame".into())),
                _ => continue,
            }
        }
        Err(SignalError::ClosedEarly("frame"))
    }
}

#[cfg(test)]
mod tests {
    use super::install_crypto_provider;

    /// T3.13/F13: deleting `install_crypto_provider`'s body (or its call site in
    /// [`super::SignalingClient::connect`]) must turn this test red — every `wss://` connection
    /// was dead on arrival (runtime panic, no `CryptoProvider`) before this was fixed, and nothing
    /// tested it. This is the narrowest possible non-vacuous check: it doesn't prove `connect()`
    /// itself calls this (the stronger, `test-support`-gated integration test in
    /// `apps/cli/tests/wss_tls.rs` does that, over a real self-signed TLS handshake), but it does
    /// prove the extracted function actually installs a usable default provider.
    #[test]
    fn install_crypto_provider_installs_a_default() {
        install_crypto_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "install_crypto_provider() must leave a default rustls CryptoProvider installed"
        );
    }
}
