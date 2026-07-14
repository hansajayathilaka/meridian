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
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, MediaKind, Path, Sdp,
    SessionHandle, TrackId,
};

mod loopback;
pub use loopback::{LoopbackFabric, LoopbackTransport};

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
    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> Result<()>;

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

    /// Await the next inbound frame across any of the session's data channels, or `None` when the
    /// session has closed. Returns the channel it arrived on so the substrate can demultiplex
    /// (ctrl vs. chat vs. a stream).
    async fn recv(&self, s: &SessionHandle) -> Result<Option<(ChannelId, Vec<u8>)>>;

    /// The selected candidate-pair class once ICE has completed (`direct`/`relay`), for
    /// `meridian session info` and diagnostics.
    async fn selected_path(&self, s: &SessionHandle) -> Result<Path>;

    /// Tear the peer connection down.
    async fn close(&self, s: &SessionHandle) -> Result<()>;
}
