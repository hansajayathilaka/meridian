//! The async client half of the rendezvous protocol: connect, authenticate by account-key
//! challenge, publish a bundle, fetch-and-verify a peer bundle, and route/receive opaque envelopes.

use std::collections::VecDeque;

use futures_util::{SinkExt, StreamExt};
use meridian_identity::{sign, KeyHandle, SecretStore};
use meridian_proto::{
    Auth, AuthOk, Bundle, Challenge, Deliver, Fetch, Frame, Op, OpaqueBlob, PrekeyBundle, Publish,
    PublishOk, RouteBody, RouteOk,
};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::bundle::{generate_bundle, verify_bundle, GeneratedBundle};
use crate::error::{Result, SignalError};

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
    /// Connect to `url` (`ws://` or, with a TLS build, `wss://`), complete the challenge–response
    /// handshake by signing `nonce ‖ server_domain` through `store`, and register the account.
    pub async fn connect(
        url: &str,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        account_pub: [u8; 32],
        invite: Option<String>,
        max_bundle_v: u16,
    ) -> Result<Self> {
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| SignalError::Ws(e.to_string()))?;
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
    pub async fn fetch_bundle(&mut self, target: [u8; 32], tamper: bool) -> Result<PrekeyBundle> {
        let fetch = Fetch { target, tamper };
        let reply = self
            .request(Op::Fetch, &fetch, Op::Bundle, "bundle")
            .await?;
        let bundle: Bundle = reply.decode()?;
        verify_bundle(&target, &bundle.bundle)?;
        Ok(bundle.bundle)
    }

    /// Route an opaque, client-signed envelope to an online peer. Returns whether it was delivered
    /// (offline delivery / mailbox is T07).
    pub async fn route(&mut self, to: [u8; 32], blob: Vec<u8>) -> Result<bool> {
        let body = RouteBody {
            to,
            blob: OpaqueBlob::new(blob),
        };
        let reply = self
            .request(Op::Route, &body, Op::RouteOk, "route_ok")
            .await?;
        let ok: RouteOk = reply.decode()?;
        Ok(ok.delivered)
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
