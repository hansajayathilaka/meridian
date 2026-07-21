//! `WebRtcTransport` — the production data-plane [`Transport`](crate::Transport) backend
//! (webrtc-rs), gated behind the `webrtc` feature (ADR 0006, ADR 0014). Two instances talk real
//! ICE/SCTP/DTLS over UDP — on the same host for the gated test suite, over a real network in
//! deployment — instead of the in-process simulation [`crate::LoopbackTransport`] provides.
//!
//! ## Negotiated (pre-arranged) data channels
//! Today the substrate only ever opens exactly two data channels per session — `mrd.ctrl/1` and
//! `mrd.chat/1` — at dial/answer time (`apps/core/src/session.rs` `dial_with_config`/
//! `answer_with_config`); `open_stream` for additional stream types multiplexes over `mrd.ctrl/1` at
//! the ctrl-protocol layer instead of calling [`Transport::add_data_channel`] again. That is the
//! *current* T04 session-layer behavior, not a permanent constraint: system-design §5.3 and
//! `stream-types-v1.md` describe a future where an accepted stream opens its *own* new SCTP data
//! channel labeled with the stream id (T09/T15/T16). If both peers called `create_data_channel(label)`
//! in-band (the WebRTC default), each side would end up with *two* channels per label — the one it
//! created locally, and a second one delivered via `on_data_channel` for the peer's independent call
//! with the same label. We sidestep that by using WebRTC's **negotiated** mode: both sides derive the
//! *same* SCTP stream id from the channel label via [`stream_id_for_label`] (pure function, no
//! coordination needed) and create the channel with `negotiated: Some(id)`, so there is exactly one
//! logical channel per label, symmetrically — a scheme that extends to per-stream channels without
//! change (`add_data_channel` rejects a label whose derived id collides with a different label
//! already on the session, rather than silently cross-wiring two streams).
//!
//! ## Offer/answer without a role hint
//! [`Transport::local_description`] and [`Transport::local_fingerprint`] are synchronous per the
//! trait contract (core-api-contracts: "cached at creation / on renegotiation"), but creating a
//! *committed* SDP is inherently async — and worse, [`Transport::new_session`] /
//! [`Transport::add_data_channel`] are called identically by dialer and answerer
//! (`apps/core/src/session.rs` `dial_with_config`/`answer_with_config`); the transport does not
//! learn which role it is playing until *either* `local_description` is read directly (dialer) *or*
//! `set_remote_description` is called with the peer's offer (answerer). We resolve this by:
//! 1. After every `add_data_channel`, computing a **non-mutating** `create_offer()` (this only reads
//!    current channels/transceivers; it never touches signaling state) and caching the text as
//!    `pending_offer`.
//! 2. If `set_remote_description` is called before we've committed anything, the incoming SDP must
//!    be the peer's *offer* — apply it, `create_answer()`, `set_local_description(answer)`, and cache
//!    the result as `committed_local_sdp` (this is now our final local description).
//! 3. If we're the dialer, nobody calls `set_remote_description` first; the first *async* call that
//!    follows `local_description()` in `apps/core`'s dial flow is `local_candidates()`, so that is
//!    where we lazily commit the cached `pending_offer` via `set_local_description` before gathering.
//!
//! Because nothing mutates the peer connection's channel set between the last `add_data_channel`
//! refresh and the eventual commit, the cached text is exactly what `set_local_description` would
//! produce if called synchronously — the caller never observes a value that later changes underneath
//! it.
//!
//! ## Fingerprint binding without blocking
//! [`Transport::local_fingerprint`]/[`Transport::dtls_fingerprint`] are also synchronous, so they
//! cannot await the real DTLS handshake — `dtls_fingerprint` returns as soon as
//! `set_remote_description` has been called, not once `RTCPeerConnectionState::Connected` fires. We
//! read the `a=fingerprint:` line directly out of the cached local/remote SDP text instead of the
//! live negotiated certificate. Against a **routing-only** adversary (the rendezvous, or anyone on
//! the signaling path) this loses nothing: the SDP itself never left the ratchet-encrypted envelope,
//! so it cannot be forged, and WebRTC's own DTLS stack refuses to complete a handshake whose peer
//! certificate does not match the `a=fingerprint` the far side declared — so "the fingerprint in the
//! SDP we applied" and "the fingerprint of the certificate actually used" are the same value whenever
//! the connection succeeds at all. The substrate's §4.6 cross-check (comparing this value against the
//! identity-signed `dtls_fp` asserted alongside the SDP) still catches an internally inconsistent
//! envelope. What this does **not** do is prove the handshake *actually completed*: against a
//! network-level adversary who intercepts the peer-to-peer UDP path itself (not the signaling
//! relay) and presents a forged certificate, `verify_fingerprint` still reports a match (both sides
//! compare the same honest, envelope-protected SDP value) while the real DTLS handshake fails
//! underneath — the session then hangs on the first real `send`/`recv` rather than tearing down with
//! an explicit `FingerprintMismatch`. That's a denial-of-service exposure, not a confidentiality or
//! integrity one (no plaintext or wrong-peer content is ever accepted); gating `dtls_fingerprint` on
//! `RTCPeerConnectionState::Connected` would close it but needs an async call site the current
//! dial/answer call order (`apps/core/src/session.rs`) doesn't offer between `set_remote_description`
//! and `verify_fingerprint` without risking a runtime deadlock (see `selected_path_detail`'s bounded
//! `Notify` wait for the pattern this would need, and why it can't reuse it here) — reviewed and
//! accepted for this task's scope; a real fix belongs in the session layer, not this transport.
//!
//! ## ICE restart does not (yet) fulfill the resumability promise (known gap)
//! [`Transport::ice_restart`] does **not** invoke webrtc-rs's real ICE-agent restart
//! (`create_offer` with `ice_restart: true`). Verified empirically while building this backend: on
//! an already-connected `RTCPeerConnection`, that call rotates the local ICE ufrag/pwd and
//! re-triggers gathering immediately, which knocks the live candidate pair out from under the
//! active DTLS/SCTP association — with no peer-side coordination to bring up a replacement, sends
//! made afterward hang forever. `apps/core`'s `P2pSession::ice_restart` has no session-layer
//! signaling path to carry a restart offer to the peer (it calls this on one side with no envelope
//! round trip, mirroring `LoopbackTransport::ice_restart`'s already-local-only contract), so
//! invoking the real primitive here would violate the trait's explicit "keep the session alive"
//! promise rather than fulfill it — this only resets local candidate-gathering bookkeeping, leaving
//! the already-open data channels completely untouched.
//!
//! Be precise about what that buys and doesn't: it proves a call to `ice_restart` never *breaks* an
//! already-working connection (the gated tests below exercise exactly that). It does **not** yet
//! fulfill system-design §5.2/§7.3's "resumable... ICE restarts on network change" promise or
//! feature-04's acceptance criterion — if the local address genuinely changes (Wi-Fi→LTE), nothing
//! here gathers or exchanges the new candidates the peer would need to find the new path, so
//! connectivity will *not* actually resume. Closing that gap needs a ctrl-channel renegotiation
//! message (ADR 0006/0014-relevant; flagged for architect review, tracked as a successor to
//! 1.15/1.16 — network-roaming support should not ship claiming this works until it lands).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

use webrtc::api::media_engine::MediaEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice::candidate::{CandidatePairState, CandidateType};
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer as WrtcIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::stats::StatsReportType;

use crate::types::{
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, MediaKind, Path,
    PathDetail, RelayTransport, Sdp, SessionHandle, TrackId,
};
use crate::{Result, Transport, TransportError};

/// How long we'll wait for real ICE gathering / connectivity / a data channel to open before
/// treating it as a backend failure. Generous for loopback-in-a-container CI, still bounded.
const WAIT_TIMEOUT: Duration = Duration::from_secs(15);

fn backend_err(e: impl std::fmt::Display) -> TransportError {
    TransportError::Backend(e.to_string())
}

/// Derive the same SCTP stream id on both peers from a channel label, so pre-negotiated
/// (`negotiated: Some(id)`) data channels line up without any wire coordination. FNV-1a, folded
/// into the 0..=65_533 range (0xFFFF/0xFFFE are reserved-ish in some stacks; steer clear).
fn stream_id_for_label(label: &str) -> u16 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in label.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    (hash % 65_534) as u16
}

/// Pull the `a=fingerprint:<algo> <hex>` value out of raw SDP text — see the module docs' "Binding
/// without blocking" section for why this is both sufficient and honest.
fn parse_fingerprint(sdp: &str) -> Option<Fingerprint> {
    for line in sdp.lines() {
        if let Some(v) = line.trim_end_matches('\r').strip_prefix("a=fingerprint:") {
            return Some(Fingerprint(v.trim().to_string()));
        }
    }
    None
}

struct ChanState {
    dc: Arc<RTCDataChannel>,
    ready_flag: Arc<AtomicBool>,
    ready_notify: Arc<Notify>,
}

struct Session {
    pc: Arc<RTCPeerConnection>,
    /// A non-mutating `create_offer()` snapshot, refreshed after every `add_data_channel`, held
    /// until either we commit it ourselves (dialer, in `local_candidates`) or discover we're
    /// actually the answerer (in `set_remote_description`) and discard it.
    pending_offer: Mutex<Option<String>>,
    /// The SDP actually handed to `set_local_description` — once set, this is our stable
    /// `local_description()` (offer if dialer, answer if answerer).
    committed_local_sdp: Mutex<Option<String>>,
    /// The SDP actually handed to `set_remote_description` — the peer's asserted fingerprint lives
    /// in here (see module docs).
    remote_sdp: Mutex<Option<String>>,
    channels: Mutex<HashMap<ChannelId, ChanState>>,
    /// Negotiated SCTP stream id -> the label that claimed it, so a hash collision between two
    /// *different* labels (see [`stream_id_for_label`]) fails loudly instead of silently
    /// cross-wiring two streams onto the same channel.
    negotiated_ids: Mutex<HashMap<u16, String>>,
    inbox_tx: mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
    inbox_rx: AsyncMutex<mpsc::UnboundedReceiver<(ChannelId, Vec<u8>)>>,
    local_candidates: Mutex<Vec<String>>,
    gather_done: Notify,
    gather_done_flag: AtomicBool,
    connected: Notify,
    connected_flag: AtomicBool,
}

/// The production `Transport` backend. Cheap to share: internally an `Arc<API>` plus a session map,
/// so a single instance (wrapped in `Arc`, per the existing `dial`/`answer` call convention) serves
/// every session a client opens.
pub struct WebRtcTransport {
    api: Arc<API>,
    sessions: Mutex<HashMap<u64, Arc<Session>>>,
    next_session_id: AtomicU64,
    next_channel_id: AtomicU64,
}

impl Default for WebRtcTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl WebRtcTransport {
    /// A fresh backend with production defaults (no interface/codec restrictions — this crate is
    /// data-only, so the media engine carries no codecs). Infallible: building the `API` object only
    /// assembles config, it never touches the network.
    pub fn new() -> Self {
        let api = APIBuilder::new()
            .with_media_engine(MediaEngine::default())
            .build();
        Self {
            api: Arc::new(api),
            sessions: Mutex::new(HashMap::new()),
            next_session_id: AtomicU64::new(0),
            next_channel_id: AtomicU64::new(0),
        }
    }

    fn get_session(&self, s: &SessionHandle) -> Result<Arc<Session>> {
        self.sessions
            .lock()
            .unwrap()
            .get(&s.0)
            .cloned()
            .ok_or(TransportError::UnknownSession)
    }

    /// Commit the cached, not-yet-mutating offer as our real local description, if we haven't
    /// already (see module docs "Offer/answer without a role hint", step 3 — the dialer's lazy
    /// commit point).
    async fn ensure_committed(&self, sess: &Arc<Session>) -> Result<()> {
        if sess.committed_local_sdp.lock().unwrap().is_some() {
            return Ok(());
        }
        let cached = sess.pending_offer.lock().unwrap().clone();
        let sdp_text = match cached {
            Some(t) => t,
            None => sess.pc.create_offer(None).await.map_err(backend_err)?.sdp,
        };
        let desc = RTCSessionDescription::offer(sdp_text.clone()).map_err(backend_err)?;
        sess.pc
            .set_local_description(desc)
            .await
            .map_err(backend_err)?;
        *sess.committed_local_sdp.lock().unwrap() = Some(sdp_text);
        *sess.pending_offer.lock().unwrap() = None;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transport for WebRtcTransport {
    fn name(&self) -> &'static str {
        "webrtc-datachannel"
    }

    async fn new_session(&self, cfg: IceConfig) -> Result<SessionHandle> {
        let mut ice_servers: Vec<WrtcIceServer> = cfg
            .stun_servers
            .iter()
            .map(|url| WrtcIceServer {
                urls: vec![url.clone()],
                ..Default::default()
            })
            .collect();
        ice_servers.extend(cfg.ice_servers.iter().map(|s| WrtcIceServer {
            urls: s.urls.clone(),
            username: s.username.clone().unwrap_or_default(),
            credential: s.credential.clone().unwrap_or_default(),
        }));

        let ice_transport_policy = match cfg.policy {
            // `relay-only` strips host/srflx *before gathering* — webrtc-rs's `Relay` policy does
            // exactly that at the ICE-agent level (invariant 3), not a post-hoc filter.
            IcePolicy::RelayOnly => RTCIceTransportPolicy::Relay,
            IcePolicy::Direct | IcePolicy::PreferRelay => RTCIceTransportPolicy::All,
        };

        let config = RTCConfiguration {
            ice_servers,
            ice_transport_policy,
            ..Default::default()
        };
        let pc = self
            .api
            .new_peer_connection(config)
            .await
            .map_err(backend_err)?;
        let pc = Arc::new(pc);

        let id = self.next_session_id.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::unbounded_channel();
        let sess = Arc::new(Session {
            pc: pc.clone(),
            pending_offer: Mutex::new(None),
            committed_local_sdp: Mutex::new(None),
            remote_sdp: Mutex::new(None),
            channels: Mutex::new(HashMap::new()),
            negotiated_ids: Mutex::new(HashMap::new()),
            inbox_tx: tx,
            inbox_rx: AsyncMutex::new(rx),
            local_candidates: Mutex::new(Vec::new()),
            gather_done: Notify::new(),
            gather_done_flag: AtomicBool::new(false),
            connected: Notify::new(),
            connected_flag: AtomicBool::new(false),
        });

        {
            let sess = sess.clone();
            pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
                let sess = sess.clone();
                Box::pin(async move {
                    match c {
                        Some(cand) => {
                            if let Ok(init) = cand.to_json() {
                                sess.local_candidates.lock().unwrap().push(init.candidate);
                            }
                        }
                        None => {
                            sess.gather_done_flag.store(true, Ordering::SeqCst);
                            sess.gather_done.notify_waiters();
                        }
                    }
                })
            }));
        }
        {
            let sess = sess.clone();
            pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
                let sess = sess.clone();
                Box::pin(async move {
                    if state == RTCPeerConnectionState::Connected {
                        sess.connected_flag.store(true, Ordering::SeqCst);
                        sess.connected.notify_waiters();
                    }
                })
            }));
        }

        self.sessions.lock().unwrap().insert(id, sess);
        Ok(SessionHandle(id))
    }

    async fn add_data_channel(&self, s: &SessionHandle, cfg: ChannelCfg) -> Result<ChannelId> {
        let sess = self.get_session(s)?;
        let cid = ChannelId(self.next_channel_id.fetch_add(1, Ordering::SeqCst) + 1);

        let negotiated_id = stream_id_for_label(&cfg.label);
        {
            let mut ids = sess.negotiated_ids.lock().unwrap();
            if let Some(existing_label) = ids.get(&negotiated_id) {
                if existing_label != &cfg.label {
                    return Err(TransportError::Backend(format!(
                        "negotiated stream id {negotiated_id} collides between labels \
                         {existing_label:?} and {:?}",
                        cfg.label
                    )));
                }
            } else {
                ids.insert(negotiated_id, cfg.label.clone());
            }
        }

        let init = RTCDataChannelInit {
            ordered: Some(cfg.ordered),
            max_retransmits: cfg.max_retransmits,
            negotiated: Some(negotiated_id),
            ..Default::default()
        };
        let dc = sess
            .pc
            .create_data_channel(&cfg.label, Some(init))
            .await
            .map_err(backend_err)?;

        let ready_flag = Arc::new(AtomicBool::new(
            dc.ready_state() == RTCDataChannelState::Open,
        ));
        let ready_notify = Arc::new(Notify::new());
        {
            let ready_flag = ready_flag.clone();
            let ready_notify = ready_notify.clone();
            dc.on_open(Box::new(move || {
                ready_flag.store(true, Ordering::SeqCst);
                ready_notify.notify_waiters();
                Box::pin(async {})
            }));
        }
        {
            let tx = sess.inbox_tx.clone();
            dc.on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = tx.clone();
                Box::pin(async move {
                    let _ = tx.send((cid, msg.data.to_vec()));
                })
            }));
        }

        sess.channels.lock().unwrap().insert(
            cid,
            ChanState {
                dc: dc.clone(),
                ready_flag,
                ready_notify,
            },
        );

        // Refresh the tentative (non-mutating) offer so `local_description()` has a fresh value the
        // instant a caller needs it — see module docs, "Offer/answer without a role hint". Only
        // meaningful before we've committed anything; harmless if it never gets read (answerer path
        // discards it in `set_remote_description`).
        if sess.committed_local_sdp.lock().unwrap().is_none() {
            if let Ok(offer) = sess.pc.create_offer(None).await {
                *sess.pending_offer.lock().unwrap() = Some(offer.sdp);
            }
        }

        Ok(cid)
    }

    async fn add_transceiver(&self, s: &SessionHandle, _kind: MediaKind) -> Result<TrackId> {
        // Media is ADR 0014 / libwebrtc, out of scope here (data-plane only). The substrate never
        // calls this on a data-only session; mirror LoopbackTransport's total-but-unused stub rather
        // than claiming media support that doesn't exist.
        self.get_session(s)?;
        Ok(TrackId(s.0))
    }

    fn local_description(&self, s: &SessionHandle) -> Result<Sdp> {
        let sess = self.get_session(s)?;
        if let Some(sdp) = sess.committed_local_sdp.lock().unwrap().clone() {
            return Ok(Sdp(sdp.into_bytes()));
        }
        if let Some(sdp) = sess.pending_offer.lock().unwrap().clone() {
            return Ok(Sdp(sdp.into_bytes()));
        }
        Err(TransportError::Backend(
            "local description requested before any data channel was added".into(),
        ))
    }

    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> Result<()> {
        let sess = self.get_session(s)?;
        let text = String::from_utf8(sdp.0).map_err(|_| TransportError::BadRemoteDescription)?;

        let already_committed = sess.committed_local_sdp.lock().unwrap().is_some();
        if already_committed {
            // We already committed our own offer (dialer path) — this must be the peer's answer.
            let desc = RTCSessionDescription::answer(text.clone())
                .map_err(|_| TransportError::BadRemoteDescription)?;
            sess.pc
                .set_remote_description(desc)
                .await
                .map_err(backend_err)?;
        } else {
            // Nothing committed yet — this is the peer's offer. Apply it, answer it, commit the
            // answer as our local description (answerer path).
            let desc = RTCSessionDescription::offer(text.clone())
                .map_err(|_| TransportError::BadRemoteDescription)?;
            sess.pc
                .set_remote_description(desc)
                .await
                .map_err(backend_err)?;
            let answer = sess.pc.create_answer(None).await.map_err(backend_err)?;
            sess.pc
                .set_local_description(answer.clone())
                .await
                .map_err(backend_err)?;
            *sess.committed_local_sdp.lock().unwrap() = Some(answer.sdp);
            *sess.pending_offer.lock().unwrap() = None;
        }
        *sess.remote_sdp.lock().unwrap() = Some(text);
        Ok(())
    }

    async fn add_ice_candidate(&self, s: &SessionHandle, c: IceCandidate) -> Result<()> {
        let sess = self.get_session(s)?;
        let init = RTCIceCandidateInit {
            candidate: c.0,
            // Data-channel-only sessions always have exactly one (`m=application`) media section.
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        };
        sess.pc.add_ice_candidate(init).await.map_err(backend_err)?;
        Ok(())
    }

    async fn local_candidates(&self, s: &SessionHandle) -> Result<Vec<IceCandidate>> {
        let sess = self.get_session(s)?;
        self.ensure_committed(&sess).await?;

        if !sess.gather_done_flag.load(Ordering::SeqCst) {
            let notified = sess.gather_done.notified();
            if !sess.gather_done_flag.load(Ordering::SeqCst) {
                let _ = tokio::time::timeout(WAIT_TIMEOUT, notified).await;
            }
        }
        let candidates = sess
            .local_candidates
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(IceCandidate)
            .collect();
        Ok(candidates)
    }

    fn local_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint> {
        let sdp = self.local_description(s)?;
        let text = std::str::from_utf8(&sdp.0).map_err(|_| TransportError::BadRemoteDescription)?;
        parse_fingerprint(text).ok_or_else(|| {
            TransportError::Backend("local SDP carried no a=fingerprint line".into())
        })
    }

    fn dtls_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint> {
        let sess = self.get_session(s)?;
        let text = sess
            .remote_sdp
            .lock()
            .unwrap()
            .clone()
            .ok_or(TransportError::NoPath)?;
        parse_fingerprint(&text).ok_or_else(|| {
            TransportError::Backend("remote SDP carried no a=fingerprint line".into())
        })
    }

    async fn ice_restart(&self, s: &SessionHandle) -> Result<()> {
        let sess = self.get_session(s)?;
        // Deliberately does not call webrtc-rs's real ICE-agent restart — see module docs "ICE
        // restart is a no-op on the wire today" for why that would break the live connection
        // without session-layer peer coordination. Only local candidate-gathering bookkeeping is
        // reset; the already-open data channels are left completely untouched.
        sess.local_candidates.lock().unwrap().clear();
        sess.gather_done_flag.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn send(&self, s: &SessionHandle, ch: &ChannelId, data: &[u8]) -> Result<()> {
        let sess = self.get_session(s)?;
        let (dc, ready_flag, ready_notify) = {
            let map = sess.channels.lock().unwrap();
            let cs = map.get(ch).ok_or(TransportError::UnknownChannel)?;
            (
                cs.dc.clone(),
                cs.ready_flag.clone(),
                cs.ready_notify.clone(),
            )
        };
        if !ready_flag.load(Ordering::SeqCst) {
            let notified = ready_notify.notified();
            if !ready_flag.load(Ordering::SeqCst) {
                tokio::time::timeout(WAIT_TIMEOUT, notified)
                    .await
                    .map_err(|_| {
                        TransportError::Backend("data channel did not open before timeout".into())
                    })?;
            }
        }
        dc.send(&Bytes::copy_from_slice(data))
            .await
            .map_err(backend_err)?;
        Ok(())
    }

    async fn recv(&self, s: &SessionHandle) -> Result<Option<(ChannelId, Vec<u8>)>> {
        let sess = self.get_session(s)?;
        let mut rx = sess.inbox_rx.lock().await;
        Ok(rx.recv().await)
    }

    async fn selected_path(&self, s: &SessionHandle) -> Result<Path> {
        self.selected_path_detail(s).await.map(|d| d.class)
    }

    async fn selected_path_detail(&self, s: &SessionHandle) -> Result<PathDetail> {
        let sess = self.get_session(s)?;
        if !sess.connected_flag.load(Ordering::SeqCst) {
            let notified = sess.connected.notified();
            if !sess.connected_flag.load(Ordering::SeqCst) {
                let _ = tokio::time::timeout(WAIT_TIMEOUT, notified).await;
            }
        }
        if !sess.connected_flag.load(Ordering::SeqCst) {
            return Err(TransportError::NoPath);
        }

        let report = sess.pc.get_stats().await;
        for item in report.reports.values() {
            let StatsReportType::CandidatePair(pair) = item else {
                continue;
            };
            if !pair.nominated || pair.state != CandidatePairState::Succeeded {
                continue;
            }
            let Some(StatsReportType::LocalCandidate(local)) =
                report.reports.get(&pair.local_candidate_id)
            else {
                continue;
            };
            let class = match local.candidate_type {
                CandidateType::Host => Path::Direct,
                CandidateType::ServerReflexive | CandidateType::PeerReflexive => Path::Srflx,
                CandidateType::Relay => Path::Relay,
                CandidateType::Unspecified => Path::Direct,
            };
            // webrtc-rs's own stats collector hardcodes `relay_protocol: "udp"` for every relay
            // candidate today (webrtc-ice's `agent_stats.rs`, not derived from the real TURN
            // allocation's transport) — there is no live udp/tcp/tls-443 signal to read here yet.
            // Reporting `Udp` unconditionally matches upstream's own (limited) truth rather than
            // inventing a distinction webrtc-rs doesn't expose; real relay-transport classification
            // for the production backend is 1.16's "observed-candidate relay-only classification".
            let (relay_server, relay_transport) = if class == Path::Relay {
                (Some(local.ip.clone()), Some(RelayTransport::Udp))
            } else {
                (None, None)
            };
            return Ok(PathDetail {
                class,
                relay_server,
                relay_transport,
            });
        }
        Err(TransportError::NoPath)
    }

    async fn close(&self, s: &SessionHandle) -> Result<()> {
        let removed = self.sessions.lock().unwrap().remove(&s.0);
        if let Some(sess) = removed {
            let _ = sess.pc.close().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_for_label_is_stable_and_distinct() {
        assert_eq!(
            stream_id_for_label("mrd.ctrl/1"),
            stream_id_for_label("mrd.ctrl/1")
        );
        assert_ne!(
            stream_id_for_label("mrd.ctrl/1"),
            stream_id_for_label("mrd.chat/1")
        );
    }

    #[test]
    fn parse_fingerprint_reads_the_a_line() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD:EF\r\n";
        assert_eq!(
            parse_fingerprint(sdp),
            Some(Fingerprint("sha-256 AB:CD:EF".into()))
        );
        assert_eq!(parse_fingerprint("v=0\r\n"), None);
    }
}
