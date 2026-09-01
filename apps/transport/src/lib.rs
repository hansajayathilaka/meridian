//! meridian-transport — the `Transport` trait and its implementations.
//!
//! Public API contract: ../../docs/api/core-api-contracts.md ("Traits the platform MUST implement").
//! Design: ../../docs/architecture/system-design.md §5 (transport & session substrate),
//! ../../docs/adr/0014-media-stack.md (webrtc-rs for data, libwebrtc for media),
//! ../../docs/adr/0006-terminal-transport.md.
//!
//! `Transport` is the single seam that lets one Rust core run on five targets (D02): the browser
//! wraps `RTCPeerConnection`, native wraps webrtc-rs/libwebrtc, and tests use [`LoopbackTransport`].
//! Consumers of `meridian-core` never branch on which is in use — the session substrate
//! ([`meridian_core::session`]) drives whichever `Transport` it is handed.
//!
//! ## What lives here vs. in the substrate
//! This crate is a *dumb pipe*: it creates peer connections, gathers ICE candidates, exchanges SDP,
//! reports the negotiated DTLS fingerprint, and moves opaque bytes on labelled data channels. It has
//! **no** knowledge of ratchets, envelopes, the ctrl protocol, or stream types — all of that is the
//! substrate's job (system-design §5.2/§5.3). Crucially, the transport never sees plaintext content
//! and never authenticates the peer: identity binding is the substrate's fingerprint cross-check
//! (§4.6), done *after* the handshake this crate performs.
//!
//! The data-plane trait deliberately carries a few methods beyond the frozen core-api-contracts
//! subset (`send`/`recv`/`selected_path`/`local_candidates`/`close`) — the contract lists the
//! session-negotiation surface; a working substrate additionally needs to move bytes and observe the
//! selected path. These are additive to that subset, not a divergence from it.

mod types;

pub use types::{
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, IceServer, MediaKind,
    NatScenario, Path, PathDetail, RelayTransport, Sdp, SessionHandle, TrackId,
};

mod loopback;
pub use loopback::{LoopbackFabric, LoopbackTransport};

#[cfg(feature = "webrtc")]
mod webrtc_backend;
#[cfg(feature = "webrtc")]
pub use webrtc_backend::WebRtcTransport;

/// Errors surfaced by a [`Transport`]. The substrate maps these onto session teardown; none of them
/// ever weaken the fingerprint check or fall back to an unencrypted path (webrtc-nat-traversal
/// invariant).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The referenced session handle is not known to this transport (closed or never created).
    #[error("unknown session handle")]
    UnknownSession,
    /// A data channel referenced by id does not exist on the session.
    #[error("unknown data channel")]
    UnknownChannel,
    /// A remote description could not be parsed / did not reference a reachable peer.
    #[error("invalid or unroutable remote description")]
    BadRemoteDescription,
    /// The session has no path yet (ICE has not selected a candidate pair).
    #[error("no candidate pair selected yet")]
    NoPath,
    /// The peer connection was torn down.
    #[error("session closed")]
    Closed,
    /// Backend-specific failure (webrtc-rs, browser). Carries a message for diagnostics.
    #[error("transport backend error: {0}")]
    Backend(String),
}

/// Convenience alias for transport results.
pub type Result<T> = std::result::Result<T, TransportError>;

/// The transport abstraction every platform implements (core-api-contracts §"Traits the platform
/// MUST implement"). Created per §7.1 of the system design: `new_session` → add channels → exchange
/// SDP/ICE → handshake → the substrate cross-checks [`dtls_fingerprint`](Transport::dtls_fingerprint)
/// against the identity-bound value from the encrypted envelope (§4.6).
///
/// SDP and ICE candidates are **opaque** to this trait's callers on the wire: the substrate carries
/// them inside ratchet-encrypted envelopes, so a `Sdp` value never travels to a server in cleartext
/// (webrtc-nat-traversal invariant 2).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// A short, stable identifier for *which* backend this is (`"loopback"`, and later the real
    /// webrtc-rs/browser backend names). Additive to the frozen core-api-contracts subset, like
    /// [`selected_path_detail`](Transport::selected_path_detail) — every implementation states this
    /// explicitly (no default) so callers such as `SessionInfo` never have to guess or hardcode a
    /// backend name that may not be the one actually running.
    fn name(&self) -> &'static str;

    /// Create a new peer connection and begin gathering local candidates per `cfg` (the policy in
    /// `cfg` decides whether host/srflx candidates are gathered at all — `relay-only` strips them
    /// *before* gathering so peers never learn each other's IPs, invariant 3).
    async fn new_session(&self, cfg: IceConfig) -> Result<SessionHandle>;

    /// Add a data channel with the given reliability/ordering config. The label is the stream id the
    /// substrate assigns (channel 0 is always `mrd.ctrl/1`).
    async fn add_data_channel(&self, s: &SessionHandle, cfg: ChannelCfg) -> Result<ChannelId>;

    /// Attach a media transceiver (audio/video). Data-plane sessions never call this; it exists so
    /// the same trait covers the libwebrtc media backend (ADR 0014). Loopback returns a stub id.
    async fn add_transceiver(&self, s: &SessionHandle, kind: MediaKind) -> Result<TrackId>;

    /// The local session description (offer or answer) to seal into an envelope and route to the
    /// peer. Synchronous: the value is cached at creation / on renegotiation (core-api-contracts).
    fn local_description(&self, s: &SessionHandle) -> Result<Sdp>;

    /// Apply the peer's session description (decrypted from its envelope). Links the two ends.
    ///
    /// Implementations infer offer-vs-answer from local commit state (whether this side has
    /// already committed a local description): a heuristic that is correct exactly when the
    /// currently-committed local description is *this side's own not-yet-answered offer* — true
    /// for the dialer at the original handshake, and true again for whichever side just called
    /// [`ice_restart`](Transport::ice_restart) and is now awaiting the peer's matching answer
    /// (task 10.22/[ADR 0025](../../../docs/adr/0025-ice-restart-renegotiation.md)) — regardless
    /// of how many times a session has restarted. It is **not** valid when `sdp` is instead a
    /// fresh, peer-initiated offer arriving while this side's own committed local description is
    /// stale/unrelated (the ICE-restart *answerer*'s case: it has old committed state from an
    /// earlier point in the session, not an outstanding offer of its own) — callers in that
    /// situation, who already know from their own protocol-level role decision that `sdp` is a
    /// genuine offer they must answer for real, should call
    /// [`set_remote_offer_and_answer`](Transport::set_remote_offer_and_answer) instead.
    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> Result<()>;

    /// Process `sdp` as a genuine remote **offer** and produce a genuine local **answer** via the
    /// real create-answer/set-local-description round trip, unconditionally — never inferring
    /// offer-vs-answer from local commit state the way [`set_remote_description`](Transport::set_remote_description)
    /// does. For use whenever a caller already knows, from its own protocol-level role decision
    /// (not from this trait), that it is receiving a genuine offer and must answer it for real —
    /// e.g. the answering side of an ICE restart (task 10.22 / ADR 0025), where a local
    /// description is already committed from earlier in the session's life (the original
    /// handshake, or this side's own prior [`ice_restart`](Transport::ice_restart) call) and so
    /// `set_remote_description`'s "already committed ⇒ must be an answer" inference would
    /// misclassify the peer's genuine offer. Commits the resulting real answer as the new local
    /// description (like `set_remote_description`'s own offer-handling branch), so a subsequent
    /// [`local_description`](Transport::local_description) call returns it.
    async fn set_remote_offer_and_answer(&self, s: &SessionHandle, sdp: Sdp) -> Result<()>;

    /// Add a trickled ICE candidate decrypted from a peer envelope.
    async fn add_ice_candidate(&self, s: &SessionHandle, c: IceCandidate) -> Result<()>;

    /// The locally-gathered candidates to trickle to the peer (host + srflx; relay is T05).
    async fn local_candidates(&self, s: &SessionHandle) -> Result<Vec<IceCandidate>>;

    /// Our **local** DTLS certificate fingerprint — the value the substrate asserts inside the
    /// identity-signed offer/answer envelope (§7.1 step 6) so the peer can bind it to our identity.
    /// In a real backend this is the fingerprint on the `a=fingerprint` line of
    /// [`local_description`](Transport::local_description).
    fn local_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint>;

    /// The **negotiated remote** DTLS fingerprint observed after the handshake. The substrate
    /// cross-checks this against the fingerprint asserted inside the identity-authenticated envelope;
    /// a mismatch tears the session down (§4.6). Synchronous per core-api-contracts.
    fn dtls_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint>;

    /// Restart ICE on a network change, keeping the peer connection (and the substrate's ratchet)
    /// alive — never a teardown + re-handshake on a Wi-Fi→LTE switch (invariant 5).
    async fn ice_restart(&self, s: &SessionHandle) -> Result<()>;

    // -- data plane (additive to the frozen core-api-contracts subset) --------------------------

    /// Send opaque bytes on a data channel. The substrate frames ratchet-sealed envelopes here.
    async fn send(&self, s: &SessionHandle, ch: &ChannelId, data: &[u8]) -> Result<()>;

    /// The number of bytes currently queued for send on `ch` — data already handed to
    /// [`send`](Transport::send) that has not yet drained out of the channel's outbound buffer
    /// (the real backend's SCTP association queue; the loopback fabric's own in-memory queue
    /// depth). The substrate/stream-type layer uses this as a backpressure read primitive: a bulk
    /// sender (T09) polls it against a low-watermark before queuing more instead of flooding the
    /// channel. This method only adds the read primitive — no watermark/callback/pause mechanism
    /// exists yet (that is task 10.7's job).
    ///
    /// A mandatory method, not a default-returning-`0` fallback: both in-tree backends can report
    /// a real value directly, and a silent `0` default would be a footgun for a third-party
    /// `Transport` implementor who forgot to override it, masking backpressure bugs rather than
    /// surfacing them.
    ///
    /// `Result<u64>`, matching every other method on this trait, even though no in-tree backend
    /// expects the query itself to fail in normal operation: `UnknownSession`/`UnknownChannel` on a
    /// stale or mismatched handle is still a real, reportable error, not a value a caller should
    /// mistake for "zero bytes buffered."
    async fn buffered_amount(&self, s: &SessionHandle, ch: &ChannelId) -> Result<u64>;

    /// Await the next inbound frame across any of the session's data channels, or `None` when the
    /// session has closed. Returns the channel it arrived on so the substrate can demultiplex
    /// (ctrl vs. chat vs. a stream).
    async fn recv(&self, s: &SessionHandle) -> Result<Option<(ChannelId, Vec<u8>)>>;

    /// The selected candidate-pair class once ICE has completed (`direct`/`relay`), for
    /// `meridian session info` and diagnostics.
    async fn selected_path(&self, s: &SessionHandle) -> Result<Path>;

    /// The selected pair *with* relay detail (server + transport) for `meridian session info` and
    /// `meridian doctor` — this is what lets the demo print `path=relay (turn-a, tls-443)` and so
    /// surface the latency-vs-egress cost as numbers, not vibes (T05, §5.4). The default derives a
    /// detail-less value from [`selected_path`](Transport::selected_path); real backends override it
    /// with the winning TURN allocation's server and transport.
    async fn selected_path_detail(&self, s: &SessionHandle) -> Result<PathDetail> {
        Ok(PathDetail::direct(self.selected_path(s).await?))
    }

    /// Tear the peer connection down.
    async fn close(&self, s: &SessionHandle) -> Result<()>;
}
