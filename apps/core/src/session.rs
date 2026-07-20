//! The P2P **session substrate** (T04): moves T03 chat off the server relay and onto a direct
//! WebRTC peer connection. It ties together the [`Transport`](meridian_transport::Transport) seam,
//! the crypto ratchet (via [`ChatState`]), the `mrd.ctrl/1` control channel, and the
//! [`StreamRegistry`], implementing the dial/answer state machine of
//! [system-design §7.1](../../docs/architecture/system-design.md) steps 6–14 and the session state
//! machine in `docs/architecture/diagrams/session-state-machine.mermaid`.
//!
//! ## The load-bearing security property: fingerprint binding (§4.6)
//! SDP and the DTLS fingerprint travel **inside** ratchet-encrypted, identity-signed envelopes
//! ([`SignalContent`]), so the rendezvous only ever routes opaque blobs — it can neither read nor
//! rewrite an offer. After the handshake the substrate cross-checks the transport's *negotiated*
//! remote fingerprint against the one the peer *asserted* in its encrypted envelope; any mismatch
//! tears the session down before a byte of content flows. A malicious relay that rewrites the outer
//! routing cannot touch the inner SDP, and a MITM that terminates DTLS presents a fingerprint that
//! fails the check. This is why we can put the servers out of the data path and still trust it.
//!
//! ## Transport independence
//! Once connected, chat and ctrl ride data channels peer-to-peer; the relay is only used for
//! signaling and can vanish mid-conversation without interrupting the session (the headline demo).
//! The same [`MessageEnvelope`](meridian_envelope::MessageEnvelope) bytes are valid over the relay or a
//! data channel (§4.3), so re-homing chat is a change of carrier, not of format.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use meridian_envelope::ctrl::ChanCfgWire;
use meridian_envelope::{ChatContent, CtrlFrame, MessageId, SignalContent, StreamAdvert};
use meridian_identity::{KeyHandle, SecretStore};
use meridian_transport::{
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, Path, RelayTransport,
    Sdp, SessionHandle, Transport,
};

use crate::relay::{self, GatherClasses};

use crate::chat::{ChatError, ChatState};
use crate::streams::{CapabilityError, StreamRegistry};

/// Channel-0 label — always opened first, reliable/ordered (§5.3).
pub const CTRL_LABEL: &str = "mrd.ctrl/1";
/// The re-homed Tier-1 chat stream label.
pub const CHAT_LABEL: &str = "mrd.chat/1";
const CTRL_SID: u64 = 0;
const CHAT_SID: u64 = 1;

/// Errors from the P2P substrate.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("transport error: {0}")]
    Transport(#[from] meridian_transport::TransportError),
    #[error("crypto/envelope error: {0}")]
    Chat(#[from] ChatError),
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    #[error("signaling relay error: {0}")]
    Relay(String),
    /// The negotiated DTLS fingerprint did not match the identity-bound value from the encrypted
    /// envelope — the session is torn down (§4.6). Fail closed, always.
    #[error(
        "DTLS fingerprint mismatch: negotiated {negotiated} != asserted {asserted} — torn down"
    )]
    FingerprintMismatch {
        negotiated: String,
        asserted: String,
    },
    /// A signaling envelope carried a payload we did not expect at this point in the handshake.
    #[error("unexpected signaling payload during {phase}")]
    UnexpectedSignal { phase: &'static str },
    /// The peer requires a mandatory stream type we do not support (graceful capability rejection).
    #[error("capability exchange failed: {0}")]
    Capability(#[from] CapabilityError),
    /// The peer rejected our stream OPEN.
    #[error("peer rejected stream {sid}: {code} ({reason})")]
    StreamRejected {
        sid: u64,
        code: String,
        reason: String,
    },
    /// The relay closed before signaling completed.
    #[error("signaling ended before the session was established")]
    SignalingEnded,
}

/// A signaling carrier for the offer/answer/ICE exchange — the rendezvous relay in production, an
/// in-memory channel in tests. Only used until the peer connection is up; after that the session is
/// server-independent.
#[async_trait::async_trait]
pub trait SignalRelay: Send {
    /// Route an opaque, already-sealed envelope blob to `to`.
    async fn send(&mut self, to: &[u8; 32], blob: Vec<u8>) -> Result<(), SessionError>;
    /// Await the next delivered `(from, blob)`.
    async fn recv(&mut self) -> Result<([u8; 32], Vec<u8>), SessionError>;
}

/// An in-process [`SignalRelay`] pair for the substrate demo and tests. Dropping one end simulates
/// the rendezvous going away.
pub struct MemRelay {
    peer_ik: [u8; 32],
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
}

impl MemRelay {
    /// A connected pair `(relay_for_a, relay_for_b)` routing between the two identities.
    pub fn pair(a_ik: [u8; 32], b_ik: [u8; 32]) -> (Self, Self) {
        let (tx_a, rx_b) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, rx_a) = tokio::sync::mpsc::unbounded_channel();
        (
            MemRelay {
                peer_ik: b_ik,
                tx: tx_a,
                rx: rx_a,
            },
            MemRelay {
                peer_ik: a_ik,
                tx: tx_b,
                rx: rx_b,
            },
        )
    }
}

#[async_trait::async_trait]
impl SignalRelay for MemRelay {
    async fn send(&mut self, _to: &[u8; 32], blob: Vec<u8>) -> Result<(), SessionError> {
        self.tx.send(blob).map_err(|_| SessionError::SignalingEnded)
    }
    async fn recv(&mut self) -> Result<([u8; 32], Vec<u8>), SessionError> {
        match self.rx.recv().await {
            Some(blob) => Ok((self.peer_ik, blob)),
            None => Err(SessionError::SignalingEnded),
        }
    }
}

/// Our role in the session (who dialed). Diagnostic + decides who sends the chat-stream OPEN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// A snapshot for `meridian session info` and the demo script. Beyond the T04 fields it carries the
/// **why**: the effective relay policy, which candidate classes were offered, and — when relayed —
/// the relay server and transport rung, so the latency-vs-privacy trade shows as numbers (§5.4).
#[derive(Clone, Debug)]
pub struct SessionInfo {
    /// Logical transport (wire behavior is identical across backends): `webrtc-datachannel`.
    pub transport: &'static str,
    /// Selected candidate-pair class.
    pub path: Path,
    /// The relay server that carried the pair, when `path == Relay`.
    pub relay_server: Option<String>,
    /// The relay transport rung (udp/tcp/tls-443), when `path == Relay`.
    pub relay_transport: Option<RelayTransport>,
    /// Last measured ctrl keepalive round-trip, if any.
    pub rtt_ms: Option<f64>,
    /// Open stream labels, ctrl first.
    pub streams: Vec<String>,
    /// The effective relay policy for this session.
    pub policy: IcePolicy,
    /// The candidate classes offered to the peer under `policy`.
    pub offered: GatherClasses,
    /// A short human explanation of why this path was chosen.
    pub reason: String,
}

impl SessionInfo {
    /// The `candidates offered: …` line the relay-policy demo prints — and the privacy claim it can
    /// make. Under `relay-only` this is exactly "relay only; peer never saw our host/srflx IPs".
    pub fn candidates_offered_line(&self) -> String {
        let base = format!("candidates offered: {}", self.offered.describe());
        if !self.offered.host && !self.offered.srflx {
            format!("{base}; peer never saw our host/srflx IPs")
        } else {
            base
        }
    }
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport={} path={}", self.transport, self.path)?;
        if let (Some(srv), Some(xport)) = (&self.relay_server, self.relay_transport) {
            write!(f, " ({srv}, {xport})")?;
        }
        match self.rtt_ms {
            Some(ms) => write!(f, " rtt={ms:.1}ms")?,
            None => write!(f, " rtt=?")?,
        }
        write!(f, " streams=[{}]", self.streams.join(", "))?;
        write!(
            f,
            " policy={} why={}",
            relay::policy_str(self.policy),
            self.reason
        )
    }
}

/// Explain why a session landed on `path` under `policy` — honest, derivable from the two.
fn path_reason(policy: IcePolicy, path: Path) -> String {
    match (policy, path) {
        (IcePolicy::RelayOnly, _) => {
            "relay-only policy: host/srflx candidates never offered".to_string()
        }
        (IcePolicy::PreferRelay, Path::Relay) => {
            "prefer-relay policy: relay pair preferred over direct".to_string()
        }
        (_, Path::Relay) => {
            "no working direct/srflx pair — relayed (hostile NAT/egress)".to_string()
        }
        (_, Path::Direct) => "direct host pair".to_string(),
        (_, Path::Srflx) => "server-reflexive (STUN) pair — no relay needed".to_string(),
    }
}

/// An event surfaced by [`P2pSession::pump`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// A decrypted chat payload arrived on `mrd.chat/1`.
    Chat(ChatContent),
    /// A keepalive was received (and echoed).
    Keepalive,
    /// A keepalive echo we were waiting on returned (carries the token).
    KeepaliveEcho(u64),
    /// The peer opened a stream (sid, type).
    StreamOpened(u64, String),
    /// The peer closed a stream.
    StreamClosed(u64),
    /// The peer connection closed.
    Closed,
}

/// A live P2P session: one peer connection multiplexing the ctrl channel and re-homed chat, with the
/// servers out of the data path.
pub struct P2pSession<T: Transport> {
    transport: Arc<T>,
    conn: SessionHandle,
    role: Role,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    ctrl_ch: ChannelId,
    chat_ch: ChannelId,
    labels: HashMap<ChannelId, &'static str>,
    registry: Arc<StreamRegistry>,
    peer_caps: Vec<StreamAdvert>,
    open_streams: BTreeSet<u64>,
    next_sid: u64,
    local_fp: Fingerprint,
    remote_fp: Fingerprint,
    keepalive_t: u64,
    last_rtt_ms: Option<f64>,
    /// The relay policy this session gathered under (governs the `candidates offered` claim).
    policy: IcePolicy,
}

impl<T: Transport> P2pSession<T> {
    /// Our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The peer's advertised stream types (from its `Hello`).
    pub fn peer_capabilities(&self) -> &[StreamAdvert] {
        &self.peer_caps
    }

    /// The bound, verified DTLS fingerprints (local, remote) — equal-by-identity after §4.6.
    pub fn fingerprints(&self) -> (&Fingerprint, &Fingerprint) {
        (&self.local_fp, &self.remote_fp)
    }

    /// The effective relay policy this session gathered under.
    pub fn policy(&self) -> IcePolicy {
        self.policy
    }

    /// A snapshot for the demo/diagnostics.
    pub async fn info(&self) -> SessionInfo {
        let detail = self
            .transport
            .selected_path_detail(&self.conn)
            .await
            .unwrap_or_else(|_| meridian_transport::PathDetail::direct(Path::Direct));
        let mut streams: Vec<String> = vec![CTRL_LABEL.to_string()];
        if self.open_streams.contains(&CHAT_SID) {
            streams.push(CHAT_LABEL.to_string());
        }
        SessionInfo {
            transport: "webrtc-datachannel",
            path: detail.class,
            relay_server: detail.relay_server,
            relay_transport: detail.relay_transport,
            rtt_ms: self.last_rtt_ms,
            streams,
            policy: self.policy,
            offered: relay::gather_classes(self.policy),
            reason: path_reason(self.policy, detail.class),
        }
    }

    /// Send a chat message over the re-homed `mrd.chat/1` data channel (no server). Returns the
    /// message id.
    pub async fn send_chat(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
        body: &str,
    ) -> Result<MessageId, SessionError> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| SessionError::Relay(e.to_string()))?;
        let content = ChatContent::Text {
            id,
            body: body.to_string(),
        };
        let blob = chat.seal_outbound(store, handle, &self.our_ik, &self.peer_ik, &content)?;
        self.transport
            .send(&self.conn, &self.chat_ch, &blob)
            .await?;
        Ok(id)
    }

    /// Seal + send an arbitrary chat payload (e.g. a delivery receipt) over the chat channel.
    pub async fn send_chat_content(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
        content: &ChatContent,
    ) -> Result<(), SessionError> {
        let blob = chat.seal_outbound(store, handle, &self.our_ik, &self.peer_ik, content)?;
        self.transport
            .send(&self.conn, &self.chat_ch, &blob)
            .await?;
        Ok(())
    }

    /// Send a `mrd.ctrl/1` keepalive; the peer echoes it. Use [`ping`](Self::ping) to also measure
    /// the round trip.
    pub async fn keepalive(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
    ) -> Result<u64, SessionError> {
        self.keepalive_t += 1;
        let t = self.keepalive_t;
        self.send_ctrl(store, handle, chat, &CtrlFrame::Keepalive { t })
            .await?;
        Ok(t)
    }

    /// Open an additional stream by type over `mrd.ctrl/1` (the `register_stream_type` extension
    /// point in action — core-api-contracts `open_stream`). The type MUST be registered locally; the
    /// peer's `Accept`/`Reject` is surfaced through [`pump`](Self::pump) as
    /// [`SessionEvent::StreamOpened`] or a [`SessionError::StreamRejected`], matching the async ctrl
    /// protocol. Returns the assigned stream id. T04 only exercises this for `mrd.chat/1`; T09 (file
    /// transfer) is the first second stream type to drive it — with zero core edits.
    pub async fn open_stream(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
        ty: &str,
        params: Vec<u8>,
    ) -> Result<crate::streams::StreamId, SessionError> {
        let st = self
            .registry
            .get(ty)
            .ok_or_else(|| SessionError::StreamRejected {
                sid: 0,
                code: "unsupported".to_string(),
                reason: format!("no local stream type {ty}"),
            })?;
        self.next_sid += 1;
        let sid = self.next_sid;
        let cfg = st.channel_cfg();
        self.send_ctrl(
            store,
            handle,
            chat,
            &CtrlFrame::Open {
                sid,
                ty: ty.to_string(),
                params,
                chan: ChanCfgWire {
                    reliable: cfg.reliable,
                    ordered: cfg.ordered,
                    max_rtx: cfg.max_retransmits,
                    rtp: false,
                },
            },
        )
        .await?;
        Ok(sid)
    }

    /// Restart ICE on a network change, keeping the session and ratchet alive (invariant 5). The
    /// crypto/ratchet state ([`ChatState`]) is untouched; only the candidate pairs are renegotiated.
    pub async fn ice_restart(&mut self) -> Result<(), SessionError> {
        self.transport.ice_restart(&self.conn).await?;
        Ok(())
    }

    /// Tear the session down.
    pub async fn close(&mut self) -> Result<(), SessionError> {
        self.transport.close(&self.conn).await?;
        Ok(())
    }

    /// Process exactly one inbound data-channel frame, demultiplexing ctrl vs chat and driving the
    /// ctrl protocol (keepalive echo, stream open/accept/reject/close). Returns `None` if the
    /// session closed. Ctrl housekeeping needs the ratchet, hence `store`/`handle`/`chat`.
    pub async fn pump(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
    ) -> Result<Option<SessionEvent>, SessionError> {
        let Some((cid, blob)) = self.transport.recv(&self.conn).await? else {
            return Ok(Some(SessionEvent::Closed));
        };
        match self.labels.get(&cid).copied() {
            Some(l) if l == CHAT_LABEL => {
                let content =
                    chat.open_inbound(store, handle, &self.our_ik, &self.peer_ik, &blob)?;
                Ok(Some(SessionEvent::Chat(content)))
            }
            _ => {
                // Treat anything else (ctrl, or a not-yet-labelled channel) as a ctrl frame.
                let frame = self.open_ctrl(store, handle, chat, &blob)?;
                self.handle_ctrl(store, handle, chat, frame).await
            }
        }
    }

    /// Send + await a keepalive echo, returning the round-trip milliseconds.
    pub async fn ping(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
    ) -> Result<f64, SessionError> {
        let t = self.keepalive(store, handle, chat).await?;
        let start = std::time::Instant::now();
        loop {
            match self.pump(store, handle, chat).await? {
                Some(SessionEvent::KeepaliveEcho(echo)) if echo == t => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.last_rtt_ms = Some(ms);
                    return Ok(ms);
                }
                Some(SessionEvent::Closed) | None => return Err(SessionError::SignalingEnded),
                _ => continue,
            }
        }
    }

    // -- internals --------------------------------------------------------------------------------

    async fn send_ctrl(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
        frame: &CtrlFrame,
    ) -> Result<(), SessionError> {
        let content = SignalContent::Ctrl {
            frame: frame.encode()?,
        };
        let blob = chat.seal_bytes(
            store,
            handle,
            &self.our_ik,
            &self.peer_ik,
            &content.encode()?,
        )?;
        self.transport
            .send(&self.conn, &self.ctrl_ch, &blob)
            .await?;
        Ok(())
    }

    fn open_ctrl(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
        blob: &[u8],
    ) -> Result<CtrlFrame, SessionError> {
        let plaintext = chat.open_bytes(store, handle, &self.our_ik, &self.peer_ik, blob)?;
        match SignalContent::decode(&plaintext)? {
            SignalContent::Ctrl { frame } => Ok(CtrlFrame::decode(&frame)?),
            _ => Err(SessionError::UnexpectedSignal { phase: "ctrl" }),
        }
    }

    async fn handle_ctrl(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
        frame: CtrlFrame,
    ) -> Result<Option<SessionEvent>, SessionError> {
        match frame {
            CtrlFrame::Keepalive { t } => {
                // Echo keepalives back to the sender. We distinguish our own echo (matching an
                // outstanding ping) from a peer-initiated keepalive by whether t <= our counter.
                if t <= self.keepalive_t {
                    Ok(Some(SessionEvent::KeepaliveEcho(t)))
                } else {
                    self.send_ctrl(store, handle, chat, &CtrlFrame::Keepalive { t })
                        .await?;
                    Ok(Some(SessionEvent::Keepalive))
                }
            }
            CtrlFrame::Open {
                sid, ty, params, ..
            } => {
                let decision = self.decide_open(sid, &ty, &params);
                match decision {
                    crate::streams::OpenDecision::Accept => {
                        self.send_ctrl(store, handle, chat, &CtrlFrame::Accept { sid })
                            .await?;
                        self.open_streams.insert(sid);
                        Ok(Some(SessionEvent::StreamOpened(sid, ty)))
                    }
                    crate::streams::OpenDecision::Reject { code, reason } => {
                        self.send_ctrl(
                            store,
                            handle,
                            chat,
                            &CtrlFrame::Reject { sid, code, reason },
                        )
                        .await?;
                        Ok(None)
                    }
                }
            }
            CtrlFrame::Accept { sid } => {
                self.open_streams.insert(sid);
                Ok(Some(SessionEvent::StreamOpened(
                    sid,
                    CHAT_LABEL.to_string(),
                )))
            }
            CtrlFrame::Reject { sid, code, reason } => {
                Err(SessionError::StreamRejected { sid, code, reason })
            }
            CtrlFrame::Close { sid, .. } => {
                self.open_streams.remove(&sid);
                Ok(Some(SessionEvent::StreamClosed(sid)))
            }
            CtrlFrame::Hello { streams, .. } => {
                // A late/duplicate Hello after the handshake — refresh caps, no event.
                self.peer_caps = streams;
                Ok(None)
            }
        }
    }

    fn decide_open(&self, sid: u64, ty: &str, params: &[u8]) -> crate::streams::OpenDecision {
        match self.registry.get(ty) {
            Some(st) => st.on_open(
                sid,
                params,
                &crate::streams::PolicyCtx {
                    peer_ik: self.peer_ik,
                    // T04 has no persisted contact list yet; T08 wires real first-contact state.
                    first_contact: false,
                },
            ),
            None => crate::streams::OpenDecision::Reject {
                code: "unsupported".to_string(),
                reason: format!("unknown stream type {ty}"),
            },
        }
    }
}

/// Dial a peer with the default (host/STUN, `direct` policy) ICE config — the T04 entry point.
#[allow(clippy::too_many_arguments)]
pub async fn dial<T: Transport>(
    transport: Arc<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    chat: &mut ChatState,
    relay: &mut dyn SignalRelay,
    registry: Arc<StreamRegistry>,
) -> Result<P2pSession<T>, SessionError> {
    dial_with_config(
        transport,
        store,
        handle,
        our_ik,
        peer_ik,
        chat,
        relay,
        registry,
        IceConfig::default(),
    )
    .await
}

/// Dial a peer under an explicit [`IceConfig`] — the T05 entry point that carries the resolved relay
/// policy and the ephemeral TURN servers. Creates the peer connection (gathering candidates per the
/// policy — `relay-only` strips host/srflx *before* this point), seals the SDP offer + DTLS
/// fingerprint into an envelope, routes it over `relay`, applies the answer, **cross-checks the
/// fingerprint (§4.6)**, then exchanges `Hello` and opens the chat stream. The crypto session with
/// `peer_ik` must already exist (T03's X3DH).
#[allow(clippy::too_many_arguments)]
pub async fn dial_with_config<T: Transport>(
    transport: Arc<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    chat: &mut ChatState,
    relay: &mut dyn SignalRelay,
    registry: Arc<StreamRegistry>,
    cfg: IceConfig,
) -> Result<P2pSession<T>, SessionError> {
    let policy = cfg.policy;
    let conn = transport.new_session(cfg).await?;
    let ctrl_ch = transport
        .add_data_channel(&conn, ChannelCfg::reliable_ordered(CTRL_LABEL))
        .await?;
    let chat_ch = transport
        .add_data_channel(&conn, ChannelCfg::reliable_ordered(CHAT_LABEL))
        .await?;

    // Seal SDP offer + our fingerprint + candidates inside a signed, ratchet-encrypted envelope.
    let offer = transport.local_description(&conn)?;
    let local_fp = transport.local_fingerprint(&conn)?;
    let ice = candidate_strings(&transport, &conn).await?;
    let offer_content = SignalContent::SdpOffer {
        sdp: offer.0,
        dtls_fp: local_fp.0.clone(),
        ice,
    };
    let blob = chat.seal_bytes(store, handle, &our_ik, &peer_ik, &offer_content.encode()?)?;
    relay.send(&peer_ik, blob).await?;

    // Await the answer.
    let (answer_sdp, asserted_fp, answer_ice) =
        recv_sdp(relay, store, handle, &our_ik, &peer_ik, chat, false).await?;
    transport
        .set_remote_description(&conn, Sdp(answer_sdp))
        .await?;
    for c in answer_ice {
        transport.add_ice_candidate(&conn, IceCandidate(c)).await?;
    }

    let remote_fp = verify_fingerprint(&transport, &conn, &asserted_fp).await?;

    let mut session = P2pSession {
        transport,
        conn,
        role: Role::Initiator,
        our_ik,
        peer_ik,
        ctrl_ch,
        chat_ch,
        labels: HashMap::from([(ctrl_ch, CTRL_LABEL), (chat_ch, CHAT_LABEL)]),
        registry,
        peer_caps: Vec::new(),
        open_streams: BTreeSet::from([CTRL_SID]),
        next_sid: CHAT_SID,
        local_fp,
        remote_fp,
        keepalive_t: 0,
        last_rtt_ms: None,
        policy,
    };
    session.handshake(store, handle, chat).await?;
    Ok(session)
}

/// Answer an incoming dial with the default ICE config — the T04 entry point.
#[allow(clippy::too_many_arguments)]
pub async fn answer<T: Transport>(
    transport: Arc<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    chat: &mut ChatState,
    relay: &mut dyn SignalRelay,
    registry: Arc<StreamRegistry>,
) -> Result<P2pSession<T>, SessionError> {
    answer_with_config(
        transport,
        store,
        handle,
        our_ik,
        peer_ik,
        chat,
        relay,
        registry,
        IceConfig::default(),
    )
    .await
}

/// Answer an incoming dial under an explicit [`IceConfig`] — the T05 entry point. Receives the offer
/// envelope over `relay`, creates the peer connection (gathering per the policy), seals the answer,
/// cross-checks the fingerprint (§4.6), then exchanges `Hello`. The offer envelope is also the X3DH
/// opening message, so this establishes the responder ratchet if not already present.
#[allow(clippy::too_many_arguments)]
pub async fn answer_with_config<T: Transport>(
    transport: Arc<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    chat: &mut ChatState,
    relay: &mut dyn SignalRelay,
    registry: Arc<StreamRegistry>,
    cfg: IceConfig,
) -> Result<P2pSession<T>, SessionError> {
    let policy = cfg.policy;
    let (offer_sdp, asserted_fp, offer_ice) =
        recv_sdp(relay, store, handle, &our_ik, &peer_ik, chat, true).await?;

    let conn = transport.new_session(cfg).await?;
    let ctrl_ch = transport
        .add_data_channel(&conn, ChannelCfg::reliable_ordered(CTRL_LABEL))
        .await?;
    let chat_ch = transport
        .add_data_channel(&conn, ChannelCfg::reliable_ordered(CHAT_LABEL))
        .await?;
    transport
        .set_remote_description(&conn, Sdp(offer_sdp))
        .await?;
    for c in offer_ice {
        transport.add_ice_candidate(&conn, IceCandidate(c)).await?;
    }

    let answer_sdp = transport.local_description(&conn)?;
    let local_fp = transport.local_fingerprint(&conn)?;
    let ice = candidate_strings(&transport, &conn).await?;
    let answer_content = SignalContent::SdpAnswer {
        sdp: answer_sdp.0,
        dtls_fp: local_fp.0.clone(),
        ice,
    };
    let blob = chat.seal_bytes(store, handle, &our_ik, &peer_ik, &answer_content.encode()?)?;
    relay.send(&peer_ik, blob).await?;

    let remote_fp = verify_fingerprint(&transport, &conn, &asserted_fp).await?;

    let mut session = P2pSession {
        transport,
        conn,
        role: Role::Responder,
        our_ik,
        peer_ik,
        ctrl_ch,
        chat_ch,
        labels: HashMap::from([(ctrl_ch, CTRL_LABEL), (chat_ch, CHAT_LABEL)]),
        registry,
        peer_caps: Vec::new(),
        open_streams: BTreeSet::from([CTRL_SID]),
        next_sid: CHAT_SID,
        local_fp,
        remote_fp,
        keepalive_t: 0,
        last_rtt_ms: None,
        policy,
    };
    session.handshake(store, handle, chat).await?;
    Ok(session)
}

impl<T: Transport> P2pSession<T> {
    /// Exchange `Hello` (capability advertisement) and open the chat stream, per §7.1 step 14. Both
    /// sides send `Hello`; the initiator opens `mrd.chat/1`; the loop runs until we have the peer's
    /// caps and the chat stream is open. An unknown *mandatory* peer capability is a graceful
    /// teardown (acceptance criterion), never a panic.
    async fn handshake(
        &mut self,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        chat: &mut ChatState,
    ) -> Result<(), SessionError> {
        let hello = self.registry.hello();
        self.send_ctrl(store, handle, chat, &hello).await?;
        if self.role == Role::Initiator {
            self.send_ctrl(
                store,
                handle,
                chat,
                &CtrlFrame::Open {
                    sid: CHAT_SID,
                    ty: CHAT_LABEL.to_string(),
                    params: Vec::new(),
                    chan: ChanCfgWire {
                        reliable: true,
                        ordered: true,
                        max_rtx: None,
                        rtp: false,
                    },
                },
            )
            .await?;
        }

        let mut got_hello = false;
        while !(got_hello && self.open_streams.contains(&CHAT_SID)) {
            let Some((cid, blob)) = self.transport.recv(&self.conn).await? else {
                return Err(SessionError::SignalingEnded);
            };
            // During the handshake, only ctrl frames are expected; a stray chat frame would arrive
            // before its stream is open, so treat everything as ctrl here.
            let _ = cid;
            let frame = self.open_ctrl(store, handle, chat, &blob)?;
            match frame {
                CtrlFrame::Hello { .. } => {
                    // Capability check — reject unknown mandatory types gracefully.
                    if let Err(e) = self.registry.check_peer(&frame) {
                        let _ = self
                            .send_ctrl(
                                store,
                                handle,
                                chat,
                                &CtrlFrame::Close {
                                    sid: CTRL_SID,
                                    status: "capability".to_string(),
                                },
                            )
                            .await;
                        let _ = self.transport.close(&self.conn).await;
                        return Err(e.into());
                    }
                    if let CtrlFrame::Hello { streams, .. } = &frame {
                        self.peer_caps = streams.clone();
                    }
                    got_hello = true;
                }
                other => {
                    // Open / Accept / Reject drive stream setup.
                    self.handle_ctrl(store, handle, chat, other).await?;
                }
            }
        }
        Ok(())
    }
}

/// Read candidate strings for trickling into an envelope.
async fn candidate_strings<T: Transport>(
    transport: &Arc<T>,
    conn: &SessionHandle,
) -> Result<Vec<String>, SessionError> {
    Ok(transport
        .local_candidates(conn)
        .await?
        .into_iter()
        .map(|c| c.0)
        .collect())
}

/// Receive one signaling envelope and decode it as an SDP offer (`want_offer`) or answer.
async fn recv_sdp(
    relay: &mut dyn SignalRelay,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: &[u8; 32],
    peer_ik: &[u8; 32],
    chat: &mut ChatState,
    want_offer: bool,
) -> Result<(Vec<u8>, String, Vec<String>), SessionError> {
    loop {
        let (from, blob) = relay.recv().await?;
        if &from != peer_ik {
            continue; // not our peer; ignore
        }
        let plaintext = chat.open_bytes(store, handle, our_ik, peer_ik, &blob)?;
        match SignalContent::decode(&plaintext)? {
            SignalContent::SdpOffer { sdp, dtls_fp, ice } if want_offer => {
                return Ok((sdp, dtls_fp, ice))
            }
            SignalContent::SdpAnswer { sdp, dtls_fp, ice } if !want_offer => {
                return Ok((sdp, dtls_fp, ice))
            }
            SignalContent::IceTrickle { .. } => continue, // pre-connection trickle, ignore for now
            _ => {
                return Err(SessionError::UnexpectedSignal {
                    phase: if want_offer { "offer" } else { "answer" },
                })
            }
        }
    }
}

/// The §4.6 cross-check: the transport's negotiated remote fingerprint MUST equal the fingerprint
/// the peer asserted inside its identity-signed envelope. Mismatch ⇒ teardown, fail closed.
async fn verify_fingerprint<T: Transport>(
    transport: &Arc<T>,
    conn: &SessionHandle,
    asserted: &str,
) -> Result<Fingerprint, SessionError> {
    let negotiated = transport.dtls_fingerprint(conn)?;
    if negotiated.0 != asserted {
        let _ = transport.close(conn).await;
        return Err(SessionError::FingerprintMismatch {
            negotiated: negotiated.0,
            asserted: asserted.to_string(),
        });
    }
    Ok(negotiated)
}
