//! `BrowserTransport` — the browser realization of the frozen `Transport` trait
//! (`docs/api/core-api-contracts.md`), over the browser's native `RTCPeerConnection`/
//! `RTCDataChannel` via `web-sys`/`js-sys` (task 12.11).
//!
//! This is the single reason `Transport` is a trait at all (`system-design.md` §6: "browser policy
//! forbids any other WebRTC stack") — `apps/transport/src/webrtc_backend.rs`'s `WebRtcTransport`
//! is the native peer of this module; both implement the exact same trait, and this module mirrors
//! its structure and offer/answer bookkeeping wherever the two backends' underlying async WebRTC
//! APIs are shaped the same way (they are: `createOffer`/`setLocalDescription`/
//! `setRemoteDescription`/`createAnswer` are all Promise-based here, exactly as webrtc-rs's are
//! `async fn`s there).
//!
//! ## Offer/answer without a role hint (mirrors `webrtc_backend.rs`'s own section of the same name)
//! [`Transport::local_description`]/[`Transport::local_fingerprint`]/[`Transport::dtls_fingerprint`]
//! are synchronous per the trait contract, but every meaningful `RTCPeerConnection` operation is
//! Promise-based. Exactly like the native backend: after every [`Transport::add_data_channel`], a
//! **non-mutating** `createOffer()` is computed and cached as `pending_offer`; if
//! [`Transport::set_remote_description`] is called before anything is committed, the incoming SDP
//! must be the peer's offer (answer for real, cache the answer as `committed_local_sdp`); otherwise
//! the dialer lazily commits its cached `pending_offer` the first time [`Transport::local_candidates`]
//! is called (`ensure_committed`). [`Transport::local_description`] reads whichever of
//! `committed_local_sdp`/`pending_offer` is set; [`Transport::local_fingerprint`]/
//! [`Transport::dtls_fingerprint`] parse the `a=fingerprint:` line out of the local/remote cached SDP
//! text directly, same rationale as the native backend's own "Fingerprint binding without blocking"
//! section: the SDP itself only ever arrives already ratchet-encrypted, so this cannot be forged, and
//! DTLS refuses to complete a handshake against a peer certificate that doesn't match the asserted
//! fingerprint — the safety-critical binding `system-design.md` §7.1 step 13 depends on.
//!
//! ## `Send`/`Sync` on a single-threaded target
//! `Transport: Send + Sync` (the trait's own supertrait bound, `core-api-contracts.md`), and
//! `#[async_trait::async_trait]` (the concrete Rust definition in `apps/transport/src/lib.rs`)
//! additionally boxes every async method's future as `Pin<Box<dyn Future<Output = _> + Send>>` by
//! default. Every meaningful operation here holds `web_sys`/`js_sys` objects (`JsValue`-backed,
//! deliberately **not** `Send`/`Sync` — a JS value is only ever valid on the one thread that created
//! it) across `.await` points, so a literal reading of those bounds is unsatisfiable on this target.
//! `apps/signaling/src/ws_transport.rs`'s `WasmWsConnection` already hit and resolved the identical
//! problem for the sibling browser-only transport seam: `wasm32-unknown-unknown` (this workspace's
//! only wasm32 target, no `+atomics`, confirmed by `rust-toolchain.toml`) has **no thread-spawning
//! capability at all**, so no `BrowserTransport` (or any future it returns) can ever actually cross a
//! real OS thread boundary — the same soundness argument crates like `send_wrapper` package up
//! generically for exactly this shape of problem. [`AssertSend`] below is that same argument, applied
//! at the future level (needed here, unlike `ws_transport.rs`, because `Transport`'s concrete
//! `async_trait`-generated signatures — unlike the internal, `pub(crate)`-only `WsConnection` trait —
//! are frozen by `core-api-contracts.md` and cannot be given a `?Send` opt-out without changing that
//! contract, which is out of this task's scope); `unsafe impl Send`/`Sync for BrowserTransport` below
//! is the same argument applied to the struct itself, for `Transport`'s own supertrait bound.
//! (Compile-time tripwire, same as `ws_transport.rs`'s: gated on `not(target_feature = "atomics")` so
//! a future switch to a genuinely multi-threaded wasm build fails to compile here instead of silently
//! shipping unsound code.)

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_channel::{mpsc, oneshot};
use futures_util::lock::Mutex as AsyncMutex;
use futures_util::StreamExt;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelInit, RtcDataChannelType,
    RtcIceCandidateInit, RtcIceCandidatePairStats, RtcIceCandidateStats, RtcIceServer,
    RtcIceTransportPolicy, RtcOfferOptions, RtcPeerConnection, RtcPeerConnectionIceEvent,
    RtcPeerConnectionState, RtcSdpType, RtcSessionDescriptionInit, RtcStatsIceCandidatePairState,
    RtcStatsIceCandidateType, RtcStatsReport, RtcStatsType,
};

use meridian_core::transport::{
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, MediaKind, Path,
    PathDetail, RelayTransport, Result, Sdp, SessionHandle, TrackId, Transport, TransportError,
};

/// How long a bounded wait ([`Transport::local_candidates`]'s gather wait,
/// [`Transport::send`]'s "wait for the channel to open" wait,
/// [`Transport::selected_path_detail`]'s "wait for `connected`" wait) will block before giving up —
/// mirrors `WebRtcTransport`'s own `WAIT_TIMEOUT`. Generous for a headless-browser CI tab, still
/// bounded.
const WAIT_TIMEOUT: Duration = Duration::from_secs(15);

/// SAFETY: see this module's doc comment, "`Send`/`Sync` on a single-threaded target". This
/// workspace's only wasm32 target (`wasm32-unknown-unknown`, no `+atomics`) has no thread-spawning
/// capability at all, so a future built entirely on this single JS/wasm thread can never actually be
/// polled from a different real OS thread despite capturing `!Send` `JsValue`-backed handles —
/// `unsafe impl<F> Send for AssertSend<F>` is therefore sound on this one target/feature
/// combination, same reasoning `apps/signaling/src/ws_transport.rs`'s `unsafe impl Send for
/// WasmWsConnection` already established and had reviewed for the sibling browser-only transport
/// seam. Applied here at the future level (rather than only at the struct level) because
/// `Transport`'s `async_trait`-generated method signatures box every returned future as
/// `Pin<Box<dyn Future<Output = _> + Send>>` — a bound this module cannot opt out of without editing
/// the frozen trait in `apps/transport/src/lib.rs`, out of this task's scope.
///
/// (review tripwire) `#[cfg(not(target_feature = "atomics"))]`: if this workspace ever turns on the
/// `atomics`/`bulk-memory` target features for a genuinely multi-threaded wasm build, a
/// `JsValue`-backed future really can cross threads and this `unsafe impl` becomes unsound — gated so
/// that future switch fails to compile here instead of silently shipping unsound code.
struct AssertSend<F>(F);

#[cfg(not(target_feature = "atomics"))]
unsafe impl<F> Send for AssertSend<F> {}

impl<F: Future> Future for AssertSend<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: a structural, non-moving projection from `Pin<&mut AssertSend<F>>` to
        // `Pin<&mut F>` — `AssertSend` is a bare newtype with no `Drop` impl and never hands out
        // `&mut F` other than through this pin projection, satisfying `Pin`'s structural-pinning
        // requirements.
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}

/// A one-shot-broadcast "this happened" flag: fires at most once, and every
/// [`wait`](Signal::wait) call registered before that either observes it already fired or is woken
/// the moment it does. Bridges `RTCPeerConnection`/`RTCDataChannel`'s callback-based event model
/// (`onicecandidate`'s gathering-complete signal, `onconnectionstatechange`'s `Connected` signal,
/// a data channel's `onopen`) onto plain `.await`able points, the same role
/// `tokio::sync::Notify` plays in `webrtc_backend.rs`. Single-threaded (wasm32, no real
/// concurrency), so the fired-check-then-register sequence in [`wait`](Signal::wait) needs no extra
/// synchronization: nothing can run between the check and the register except at an actual
/// `.await` point, and there is none in between.
#[derive(Clone)]
struct Signal(Rc<SignalInner>);

struct SignalInner {
    fired: Cell<bool>,
    waiters: RefCell<Vec<oneshot::Sender<()>>>,
}

impl Signal {
    fn new() -> Self {
        Signal(Rc::new(SignalInner {
            fired: Cell::new(false),
            waiters: RefCell::new(Vec::new()),
        }))
    }

    /// Mark this signal fired (idempotent — a second `fire()` is a no-op) and wake every waiter
    /// registered so far.
    fn fire(&self) {
        if !self.0.fired.replace(true) {
            for w in self.0.waiters.borrow_mut().drain(..) {
                let _ = w.send(());
            }
        }
    }

    /// Un-fire this signal (used by [`Transport::ice_restart`], which re-gathers candidates from
    /// scratch — mirrors `WebRtcTransport::ice_restart` resetting `gather_done_flag`).
    fn reset(&self) {
        self.0.fired.set(false);
    }

    /// Resolve immediately if already fired; otherwise wait for the next [`fire`](Signal::fire).
    async fn wait(&self) {
        if self.0.fired.get() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.0.waiters.borrow_mut().push(tx);
        let _ = rx.await;
    }
}

/// Flatten a caught JS exception/rejection into a [`TransportError::Backend`] — same pattern as
/// `apps/signaling/src/ws_transport.rs`'s `js_err`/`apps/store/src/webcrypto.rs`'s `js_err`.
fn js_backend_err(e: JsValue) -> TransportError {
    let detail = e
        .as_string()
        .or_else(|| js_sys::Error::from(e.clone()).message().as_string())
        .unwrap_or_else(|| format!("{e:?}"));
    TransportError::Backend(detail)
}

/// Derive an SCTP negotiated stream id from a channel label — the same FNV-1a construction
/// `webrtc_backend.rs::stream_id_for_label` uses, **but folded into a narrower range** (see below).
/// Pre-negotiated (`negotiated: true, id: ...`) data channels need both sides to agree on the
/// numeric id without any wire coordination.
///
/// ## Modulus is `1_000`, not `65_534` like the native backend's own `stream_id_for_label`
/// Discovered empirically against a real headless Chromium (this task's own loopback test, run
/// against a version-matched Chrome-for-Testing/`chromedriver` pair — not simulated): asking
/// `RTCPeerConnection::createDataChannel` for a **negotiated** channel with `id` outside a small
/// range Chrome accepts locally throws `OperationError: RTCDataChannel creation failed` — reproduced
/// directly (`"mrd.ctrl/1"`'s un-folded FNV-1a hash landed on `10747`, which failed every time; every
/// id this module has exercised under `1_000` succeeded), consistent with Chromium's own SCTP
/// transport requesting a much smaller number of outbound streams by default than the
/// `0..=65_533` range RFC 8831 itself permits and `webrtc-rs`'s own SCTP stack apparently tolerates
/// (`webrtc_backend.rs`'s otherwise-identical function, exercised only against `webrtc-rs`↔`webrtc-rs`
/// peers so far, never hit this). **This is a real, confirmed browser-vs-native numeric-id mismatch
/// for the same channel label** — not yet reconciled between the two backends, since this task's own
/// scope is `apps/wasm/src/transport.rs` only (`apps/transport/src/webrtc_backend.rs` is a different
/// crate, out of scope here). A genuine browser↔native session (task 12.17, the deferred
/// real-network interop proof) will renegotiate onto *disjoint* ids for `mrd.ctrl/1` under today's
/// two independent moduli and fail to connect on that channel — flagged here explicitly rather than
/// silently left for 12.17 to rediscover from scratch; the fix likely belongs in
/// `webrtc_backend.rs`/a shared constant, once 12.17 confirms `webrtc-rs`'s own real ceiling (not
/// assumed here, per this task's own "verify, don't invent" instruction).
fn stream_id_for_label(label: &str) -> u16 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in label.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    (hash % 1_000) as u16
}

/// Pull the `a=fingerprint:<algo> <hex>` value out of raw SDP text — byte-for-byte the same
/// extraction `webrtc_backend.rs::parse_fingerprint` performs, and for the identical reason (see
/// this module's doc comment, "Offer/answer without a role hint").
fn parse_fingerprint(sdp: &str) -> Option<Fingerprint> {
    for line in sdp.lines() {
        if let Some(v) = line.trim_end_matches('\r').strip_prefix("a=fingerprint:") {
            return Some(Fingerprint(v.trim().to_string()));
        }
    }
    None
}

fn build_rtc_configuration(cfg: &IceConfig) -> RtcConfiguration {
    let config = RtcConfiguration::new();
    let servers = Array::new();

    for url in &cfg.stun_servers {
        let server = RtcIceServer::new();
        let urls = Array::new();
        urls.push(&JsValue::from_str(url));
        server.set_urls(&urls.into());
        servers.push(&server.into());
    }
    for s in &cfg.ice_servers {
        let server = RtcIceServer::new();
        let urls = Array::new();
        for url in &s.urls {
            urls.push(&JsValue::from_str(url));
        }
        server.set_urls(&urls.into());
        if let Some(u) = &s.username {
            server.set_username(u);
        }
        if let Some(c) = &s.credential {
            server.set_credential(c);
        }
        servers.push(&server.into());
    }
    config.set_ice_servers(&servers.into());

    config.set_ice_transport_policy(match cfg.policy {
        // `relay-only` strips host/srflx *before gathering* — `RtcIceTransportPolicy::Relay` does
        // exactly that at the ICE-agent level (invariant 3), not a post-hoc filter. Mirrors
        // `webrtc_backend.rs::new_session`'s identical policy mapping.
        IcePolicy::RelayOnly => RtcIceTransportPolicy::Relay,
        IcePolicy::Direct | IcePolicy::PreferRelay => RtcIceTransportPolicy::All,
    });
    config
}

async fn create_offer_text(pc: &RtcPeerConnection) -> Result<String> {
    let value = JsFuture::from(pc.create_offer())
        .await
        .map_err(js_backend_err)?;
    let init: RtcSessionDescriptionInit = value.unchecked_into();
    init.get_sdp()
        .ok_or_else(|| TransportError::Backend("createOffer() produced no sdp".into()))
}

async fn create_answer_text(pc: &RtcPeerConnection) -> Result<String> {
    let value = JsFuture::from(pc.create_answer())
        .await
        .map_err(js_backend_err)?;
    let init: RtcSessionDescriptionInit = value.unchecked_into();
    init.get_sdp()
        .ok_or_else(|| TransportError::Backend("createAnswer() produced no sdp".into()))
}

async fn set_local_description_text(
    pc: &RtcPeerConnection,
    ty: RtcSdpType,
    sdp: &str,
) -> Result<()> {
    let init = RtcSessionDescriptionInit::new(ty);
    init.set_sdp(sdp);
    JsFuture::from(pc.set_local_description(&init))
        .await
        .map_err(js_backend_err)?;
    Ok(())
}

async fn set_remote_description_text(
    pc: &RtcPeerConnection,
    ty: RtcSdpType,
    sdp: &str,
) -> Result<()> {
    let init = RtcSessionDescriptionInit::new(ty);
    init.set_sdp(sdp);
    JsFuture::from(pc.set_remote_description(&init))
        .await
        .map_err(js_backend_err)?;
    Ok(())
}

/// One data channel's browser-side state: the channel object itself, its "opened" [`Signal`], and
/// the `wasm-bindgen` `Closure`s wired to it — kept alive here for the channel's lifetime (dropping
/// a `Closure` invalidates the JS-side function pointer it installed, exactly the hazard
/// `ws_transport.rs`'s `WasmWsConnection` docs already call out).
struct ChanState {
    dc: RtcDataChannel,
    ready: Signal,
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

/// One peer connection's browser-side state — the direct analogue of `webrtc_backend.rs::Session`.
struct Session {
    pc: RtcPeerConnection,
    /// A non-mutating `createOffer()` snapshot, refreshed after every `add_data_channel`, held
    /// until either we commit it ourselves (dialer, in `ensure_committed`) or discover we're
    /// actually the answerer (in `apply_remote_offer_and_answer`) and discard it.
    pending_offer: RefCell<Option<String>>,
    /// The SDP actually handed to `setLocalDescription` — once set, this is our stable
    /// `local_description()` (offer if dialer, answer if answerer).
    committed_local_sdp: RefCell<Option<String>>,
    /// The SDP actually handed to `setRemoteDescription` — the peer's asserted fingerprint lives
    /// in here.
    remote_sdp: RefCell<Option<String>>,
    channels: RefCell<HashMap<ChannelId, Rc<ChanState>>>,
    /// Negotiated SCTP stream id -> the label that claimed it, so a hash collision between two
    /// *different* labels (see [`stream_id_for_label`]) fails loudly instead of silently
    /// cross-wiring two streams — mirrors `webrtc_backend.rs::Session::negotiated_ids`.
    negotiated_ids: RefCell<HashMap<u16, String>>,
    inbox_tx: mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
    /// Async-aware (never-panicking) mutex, not a bare `RefCell`: two overlapping `recv()` callers
    /// on the same session must serialize, not panic on a double mutable borrow — see this file's
    /// `Cargo.toml` entry for `futures-util`.
    inbox_rx: AsyncMutex<mpsc::UnboundedReceiver<(ChannelId, Vec<u8>)>>,
    local_candidates: Rc<RefCell<Vec<String>>>,
    gather_done: Signal,
    connected: Signal,
    _on_ice_candidate: Closure<dyn FnMut(RtcPeerConnectionIceEvent)>,
    _on_connection_state_change: Closure<dyn FnMut()>,
}

/// The browser `Transport` backend (task 12.11). One instance owns every session a client opens —
/// cheap to construct, holds no network resources until [`Transport::new_session`] is called.
pub struct BrowserTransport {
    sessions: RefCell<HashMap<u64, Rc<Session>>>,
    next_session_id: Cell<u64>,
    next_channel_id: Cell<u64>,
}

impl Default for BrowserTransport {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: see this module's doc comment, "`Send`/`Sync` on a single-threaded target" — identical
// reasoning to `AssertSend` above and to `apps/signaling/src/ws_transport.rs`'s `unsafe impl Send
// for WasmWsConnection`, applied here to satisfy `Transport`'s own `: Send + Sync` supertrait bound
// (`core-api-contracts.md`) for the concrete `BrowserTransport` type itself.
#[cfg(not(target_feature = "atomics"))]
unsafe impl Send for BrowserTransport {}
#[cfg(not(target_feature = "atomics"))]
unsafe impl Sync for BrowserTransport {}

impl BrowserTransport {
    /// A fresh backend with no sessions yet. Infallible: this only allocates local bookkeeping, it
    /// never touches the network or constructs any `RTCPeerConnection`.
    pub fn new() -> Self {
        Self {
            sessions: RefCell::new(HashMap::new()),
            next_session_id: Cell::new(0),
            next_channel_id: Cell::new(0),
        }
    }

    fn get_session(&self, s: &SessionHandle) -> Result<Rc<Session>> {
        self.sessions
            .borrow()
            .get(&s.0)
            .cloned()
            .ok_or(TransportError::UnknownSession)
    }

    fn next_session_id(&self) -> u64 {
        let id = self.next_session_id.get() + 1;
        self.next_session_id.set(id);
        id
    }

    fn next_channel_id(&self) -> u64 {
        let id = self.next_channel_id.get() + 1;
        self.next_channel_id.set(id);
        id
    }

    /// Commit the cached, not-yet-mutating offer as our real local description, if we haven't
    /// already (see this module's doc comment, "Offer/answer without a role hint" — the dialer's
    /// lazy commit point, mirrors `webrtc_backend.rs::WebRtcTransport::ensure_committed`).
    async fn ensure_committed(&self, sess: &Rc<Session>) -> Result<()> {
        if sess.committed_local_sdp.borrow().is_some() {
            return Ok(());
        }
        let cached = sess.pending_offer.borrow().clone();
        let sdp_text = match cached {
            Some(t) => t,
            None => create_offer_text(&sess.pc).await?,
        };
        set_local_description_text(&sess.pc, RtcSdpType::Offer, &sdp_text).await?;
        *sess.committed_local_sdp.borrow_mut() = Some(sdp_text);
        *sess.pending_offer.borrow_mut() = None;
        Ok(())
    }

    /// Apply `text` as a genuine remote **offer** and produce a genuine local **answer** —
    /// `setRemoteDescription`, `createAnswer`, `setLocalDescription`, then cache the answer as
    /// `committed_local_sdp` (discarding any stale `pending_offer`) and `text` itself as
    /// `remote_sdp`. Shared, unconditional body for both `Transport::set_remote_description`'s
    /// "nothing committed yet" branch and `Transport::set_remote_offer_and_answer` — mirrors
    /// `webrtc_backend.rs::WebRtcTransport::apply_remote_offer_and_answer` exactly.
    async fn apply_remote_offer_and_answer(&self, sess: &Rc<Session>, text: String) -> Result<()> {
        set_remote_description_text(&sess.pc, RtcSdpType::Offer, &text).await?;
        let answer_text = create_answer_text(&sess.pc).await?;
        set_local_description_text(&sess.pc, RtcSdpType::Answer, &answer_text).await?;
        *sess.committed_local_sdp.borrow_mut() = Some(answer_text);
        *sess.pending_offer.borrow_mut() = None;
        *sess.remote_sdp.borrow_mut() = Some(text);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transport for BrowserTransport {
    fn name(&self) -> &'static str {
        "browser-rtcdatachannel"
    }

    async fn new_session(&self, cfg: IceConfig) -> Result<SessionHandle> {
        AssertSend(async move {
            let config = build_rtc_configuration(&cfg);
            let pc = RtcPeerConnection::new_with_configuration(&config).map_err(js_backend_err)?;

            let local_candidates = Rc::new(RefCell::new(Vec::new()));
            let gather_done = Signal::new();
            let connected = Signal::new();

            let on_ice_candidate = {
                let local_candidates = local_candidates.clone();
                let gather_done = gather_done.clone();
                Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
                    move |ev: RtcPeerConnectionIceEvent| match ev.candidate() {
                        Some(c) => local_candidates.borrow_mut().push(c.candidate()),
                        None => gather_done.fire(),
                    },
                )
            };
            pc.set_onicecandidate(Some(on_ice_candidate.as_ref().unchecked_ref()));

            let on_connection_state_change = {
                let connected = connected.clone();
                let pc = pc.clone();
                Closure::<dyn FnMut()>::new(move || {
                    if pc.connection_state() == RtcPeerConnectionState::Connected {
                        connected.fire();
                    }
                })
            };
            pc.set_onconnectionstatechange(Some(
                on_connection_state_change.as_ref().unchecked_ref(),
            ));

            let (inbox_tx, inbox_rx) = mpsc::unbounded();
            let id = self.next_session_id();
            let sess = Rc::new(Session {
                pc,
                pending_offer: RefCell::new(None),
                committed_local_sdp: RefCell::new(None),
                remote_sdp: RefCell::new(None),
                channels: RefCell::new(HashMap::new()),
                negotiated_ids: RefCell::new(HashMap::new()),
                inbox_tx,
                inbox_rx: AsyncMutex::new(inbox_rx),
                local_candidates,
                gather_done,
                connected,
                _on_ice_candidate: on_ice_candidate,
                _on_connection_state_change: on_connection_state_change,
            });
            self.sessions.borrow_mut().insert(id, sess);
            Ok(SessionHandle(id))
        })
        .await
    }

    async fn add_data_channel(&self, s: &SessionHandle, cfg: ChannelCfg) -> Result<ChannelId> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let cid = ChannelId(self.next_channel_id());

            let negotiated_id = stream_id_for_label(&cfg.label);
            {
                let mut ids = sess.negotiated_ids.borrow_mut();
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

            let init = RtcDataChannelInit::new();
            init.set_ordered(cfg.ordered);
            if let Some(max_retransmits) = cfg.max_retransmits {
                init.set_max_retransmits(max_retransmits);
            }
            init.set_negotiated(true);
            init.set_id(negotiated_id);
            let dc = sess
                .pc
                .create_data_channel_with_data_channel_dict(&cfg.label, &init);
            // Spec default `binaryType` is `"blob"` (an async `Blob` read on every message) — force
            // `"arraybuffer"` so `onmessage`'s `MessageEvent::data()` is directly a `js_sys::ArrayBuffer`
            // (see `add_data_channel`'s `on_message` closure below).
            dc.set_binary_type(RtcDataChannelType::Arraybuffer);

            let ready = Signal::new();
            let on_open = {
                let ready = ready.clone();
                Closure::<dyn FnMut()>::new(move || ready.fire())
            };
            dc.set_onopen(Some(on_open.as_ref().unchecked_ref()));

            let on_message = {
                let tx = sess.inbox_tx.clone();
                Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
                    if let Ok(buf) = ev.data().dyn_into::<js_sys::ArrayBuffer>() {
                        let bytes = Uint8Array::new(&buf).to_vec();
                        let _ = tx.unbounded_send((cid, bytes));
                    }
                    // Anything else (a stray text frame, if `binaryType` were ever misconfigured)
                    // is silently dropped — this protocol is binary-only, mirroring
                    // `ws_transport.rs::WsEvent::Text`'s "protocol violation, not a crash" handling.
                })
            };
            dc.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            sess.channels.borrow_mut().insert(
                cid,
                Rc::new(ChanState {
                    dc,
                    ready,
                    _on_open: on_open,
                    _on_message: on_message,
                }),
            );

            // Refresh the tentative (non-mutating) offer so `local_description()` has a fresh value
            // the instant a caller needs it — see this module's doc comment, "Offer/answer without
            // a role hint". Only meaningful before we've committed anything; harmless if it's never
            // read (the answerer path discards it in `apply_remote_offer_and_answer`).
            if sess.committed_local_sdp.borrow().is_none() {
                if let Ok(text) = create_offer_text(&sess.pc).await {
                    *sess.pending_offer.borrow_mut() = Some(text);
                }
            }

            Ok(cid)
        })
        .await
    }

    async fn add_transceiver(&self, s: &SessionHandle, _kind: MediaKind) -> Result<TrackId> {
        // Media is ADR 0014 / libwebrtc, explicitly out of this task's scope (data-plane only) —
        // mirror `WebRtcTransport`'s/`LoopbackTransport`'s own total-but-unused stub rather than
        // claiming media support that doesn't exist. The substrate never calls this on a
        // data-only session.
        AssertSend(async move {
            self.get_session(s)?;
            Ok(TrackId(s.0))
        })
        .await
    }

    fn local_description(&self, s: &SessionHandle) -> Result<Sdp> {
        let sess = self.get_session(s)?;
        if let Some(sdp) = sess.committed_local_sdp.borrow().clone() {
            return Ok(Sdp(sdp.into_bytes()));
        }
        if let Some(sdp) = sess.pending_offer.borrow().clone() {
            return Ok(Sdp(sdp.into_bytes()));
        }
        Err(TransportError::Backend(
            "local description requested before any data channel was added".into(),
        ))
    }

    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> Result<()> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let text =
                String::from_utf8(sdp.0).map_err(|_| TransportError::BadRemoteDescription)?;

            let already_committed = sess.committed_local_sdp.borrow().is_some();
            if already_committed {
                // We already committed our own not-yet-answered offer — this must be the peer's
                // answer. See `apps/transport/src/lib.rs`'s doc comment on this trait method for
                // exactly when that inference is (and is not) valid.
                set_remote_description_text(&sess.pc, RtcSdpType::Answer, &text).await?;
                *sess.remote_sdp.borrow_mut() = Some(text);
            } else {
                // Nothing committed yet — this is the peer's offer (answerer path).
                self.apply_remote_offer_and_answer(&sess, text).await?;
            }
            Ok(())
        })
        .await
    }

    async fn set_remote_offer_and_answer(&self, s: &SessionHandle, sdp: Sdp) -> Result<()> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let text =
                String::from_utf8(sdp.0).map_err(|_| TransportError::BadRemoteDescription)?;
            self.apply_remote_offer_and_answer(&sess, text).await
        })
        .await
    }

    async fn add_ice_candidate(&self, s: &SessionHandle, c: IceCandidate) -> Result<()> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let init = RtcIceCandidateInit::new(&c.0);
            // Data-channel-only sessions always have exactly one (`m=application`) media section —
            // mirrors `webrtc_backend.rs::add_ice_candidate`'s identical assumption.
            init.set_sdp_mid(Some("0"));
            init.set_sdp_m_line_index(Some(0));
            JsFuture::from(
                sess.pc
                    .add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init)),
            )
            .await
            .map_err(js_backend_err)?;
            Ok(())
        })
        .await
    }

    async fn local_candidates(&self, s: &SessionHandle) -> Result<Vec<IceCandidate>> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            self.ensure_committed(&sess).await?;
            // Best-effort bounded wait — a caller that reads candidates before gathering finishes
            // (unusual, but not a bug) still gets whatever has trickled in so far rather than
            // blocking forever.
            let _ = wasmtimer::tokio::timeout(WAIT_TIMEOUT, sess.gather_done.wait()).await;
            let candidates: Vec<IceCandidate> = sess
                .local_candidates
                .borrow()
                .iter()
                .cloned()
                .map(IceCandidate)
                .collect();
            Ok(candidates)
        })
        .await
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
            .borrow()
            .clone()
            .ok_or(TransportError::NoPath)?;
        parse_fingerprint(&text).ok_or_else(|| {
            TransportError::Backend("remote SDP carried no a=fingerprint line".into())
        })
    }

    async fn ice_restart(&self, s: &SessionHandle) -> Result<()> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            // Reset local candidate-gathering bookkeeping *before* triggering the restart, not
            // after — mirrors `webrtc_backend.rs::ice_restart`'s identical ordering, so a caller
            // that immediately calls `local_candidates()` once this returns waits on the *new*
            // gathering pass's own completion, not whatever `onicecandidate` callbacks the restart
            // itself is about to fire as a side effect of `createOffer` below.
            sess.local_candidates.borrow_mut().clear();
            sess.gather_done.reset();

            let options = RtcOfferOptions::new();
            options.set_ice_restart(true);
            let value = JsFuture::from(sess.pc.create_offer_with_rtc_offer_options(&options))
                .await
                .map_err(js_backend_err)?;
            let init: RtcSessionDescriptionInit = value.unchecked_into();
            let text = init.get_sdp().ok_or_else(|| {
                TransportError::Backend("createOffer(iceRestart) produced no sdp".into())
            })?;
            set_local_description_text(&sess.pc, RtcSdpType::Offer, &text).await?;
            *sess.committed_local_sdp.borrow_mut() = Some(text);
            *sess.pending_offer.borrow_mut() = None;
            Ok(())
        })
        .await
    }

    async fn send(&self, s: &SessionHandle, ch: &ChannelId, data: &[u8]) -> Result<()> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let chan = sess
                .channels
                .borrow()
                .get(ch)
                .cloned()
                .ok_or(TransportError::UnknownChannel)?;
            wasmtimer::tokio::timeout(WAIT_TIMEOUT, chan.ready.wait())
                .await
                .map_err(|_| {
                    TransportError::Backend("data channel did not open before timeout".into())
                })?;
            chan.dc.send_with_u8_array(data).map_err(js_backend_err)?;
            Ok(())
        })
        .await
    }

    async fn recv(&self, s: &SessionHandle) -> Result<Option<(ChannelId, Vec<u8>)>> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let mut rx = sess.inbox_rx.lock().await;
            Ok(rx.next().await)
        })
        .await
    }

    async fn buffered_amount(&self, s: &SessionHandle, ch: &ChannelId) -> Result<u64> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            let chan = sess
                .channels
                .borrow()
                .get(ch)
                .cloned()
                .ok_or(TransportError::UnknownChannel)?;
            Ok(chan.dc.buffered_amount() as u64)
        })
        .await
    }

    async fn selected_path(&self, s: &SessionHandle) -> Result<Path> {
        self.selected_path_detail(s).await.map(|d| d.class)
    }

    async fn selected_path_detail(&self, s: &SessionHandle) -> Result<PathDetail> {
        AssertSend(async move {
            let sess = self.get_session(s)?;
            if sess.pc.connection_state() != RtcPeerConnectionState::Connected {
                let _ = wasmtimer::tokio::timeout(WAIT_TIMEOUT, sess.connected.wait()).await;
            }
            if sess.pc.connection_state() != RtcPeerConnectionState::Connected {
                return Err(TransportError::NoPath);
            }

            let stats_value = JsFuture::from(sess.pc.get_stats())
                .await
                .map_err(js_backend_err)?;
            let report: RtcStatsReport = stats_value.unchecked_into();
            let values = report.values();
            loop {
                let next = values.next().map_err(js_backend_err)?;
                if next.done() {
                    break;
                }
                let pair: RtcIceCandidatePairStats = next.value().unchecked_into();
                if pair.get_type() != Some(RtcStatsType::CandidatePair) {
                    continue;
                }
                if pair.get_nominated() != Some(true) {
                    continue;
                }
                if pair.get_state() != Some(RtcStatsIceCandidatePairState::Succeeded) {
                    continue;
                }
                let Some(local_id) = pair.get_local_candidate_id() else {
                    continue;
                };
                let Some(local_obj) = report.get(&local_id) else {
                    continue;
                };
                let local: RtcIceCandidateStats = local_obj.unchecked_into();
                let class = match local.get_candidate_type() {
                    Some(RtcStatsIceCandidateType::Host) => Path::Direct,
                    Some(RtcStatsIceCandidateType::Serverreflexive)
                    | Some(RtcStatsIceCandidateType::Peerreflexive) => Path::Srflx,
                    Some(RtcStatsIceCandidateType::Relayed) => Path::Relay,
                    _ => Path::Direct,
                };
                let (relay_server, relay_transport) = if class == Path::Relay {
                    // No live udp/tcp/tls-443 relay-transport-rung signal is exposed by the
                    // `RTCStatsReport` shape read here — same open gap
                    // `webrtc_backend.rs::selected_path_detail` documents for its own backend
                    // (webrtc-rs's stats collector hardcodes the same thing today).
                    (local.get_ip_address(), Some(RelayTransport::Udp))
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
        })
        .await
    }

    async fn close(&self, s: &SessionHandle) -> Result<()> {
        AssertSend(async move {
            if let Some(sess) = self.sessions.borrow_mut().remove(&s.0) {
                sess.pc.close();
            }
            Ok(())
        })
        .await
    }
}
