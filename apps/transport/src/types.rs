//! Value types crossing the [`Transport`](crate::Transport) boundary. These mirror the illustrative
//! signatures in core-api-contracts.md; concrete backends map them onto their own SDP/ICE objects.

/// The per-user/contact/org relay policy knob (system-design §5.4). It governs which candidate
/// classes are gathered at all — `relay-only` strips host/srflx *before* gathering (invariant 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IcePolicy {
    /// Gather host + server-reflexive + relay; prefer the lowest-latency pair (default).
    #[default]
    Direct,
    /// Gather all classes but prefer relay pairs (used when hiding IPs is desired but direct is a
    /// fallback). Relay minting itself is T05.
    PreferRelay,
    /// Strip host/srflx before gathering — only relay candidates are offered, so peers never learn
    /// each other's addresses (at a latency cost). Relay transport is T05; this variant is carried
    /// now so the policy surface is stable.
    RelayOnly,
}

/// ICE configuration handed to [`Transport::new_session`]. STUN servers give server-reflexive
/// candidates; TURN/relay is T05, so `stun_servers` is the only address list carried today.
#[derive(Clone, Debug, Default)]
pub struct IceConfig {
    /// STUN URLs (e.g. `stun:stun.l.google.com:19302`). Empty ⇒ host candidates only.
    pub stun_servers: Vec<String>,
    /// The relay policy for this session.
    pub policy: IcePolicy,
}

/// An opaque handle to a peer connection inside a [`Transport`](crate::Transport). Cheap to clone;
/// meaningful only to the transport that issued it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionHandle(pub u64);

/// An opaque handle to a data channel within a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(pub u64);

/// An opaque handle to a media track/transceiver. Data-plane sessions never use this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrackId(pub u64);

/// Data-channel reliability/ordering, chosen per stream type (system-design §5.3, wire-protocol §5).
/// `reliable+ordered` for ctrl & chat; `reliable+unordered` for file chunks; `unreliable` (via
/// `max_retransmits = Some(0)`) for live location/game streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCfg {
    /// The channel label — the substrate uses the stream id (`mrd.ctrl/1`, `mrd.chat/1`, …).
    pub label: String,
    /// Reliable (retransmitted) vs. best-effort delivery.
    pub reliable: bool,
    /// In-order vs. out-of-order delivery.
    pub ordered: bool,
    /// `Some(0)` ⇒ unreliable (no retransmits); `Some(n)` ⇒ bounded retransmits; `None` ⇒ default.
    pub max_retransmits: Option<u16>,
}

impl ChannelCfg {
    /// The reliable, ordered config used by channel 0 (`mrd.ctrl/1`) and `mrd.chat/1`.
    pub fn reliable_ordered(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            reliable: true,
            ordered: true,
            max_retransmits: None,
        }
    }
}

/// An opaque session description (SDP). The substrate treats the inner bytes as a blob and never
/// lets them travel to a server in cleartext — they ride inside a ratchet-encrypted envelope
/// (webrtc-nat-traversal invariant 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sdp(pub Vec<u8>);

impl Sdp {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// An opaque ICE candidate line, trickled inside encrypted envelopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceCandidate(pub String);

/// A DTLS certificate fingerprint (e.g. `sha-256 AB:CD:…`). Bound to identity by the substrate's
/// post-handshake cross-check (§4.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub String);

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Media transceiver kind (ADR 0014 media backend). Unused by data-plane sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
}

/// The class of the selected ICE candidate pair, surfaced for `meridian session info` (§5.4 ladder:
/// host → srflx → relay).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// Direct host-to-host (same LAN or open NAT).
    Direct,
    /// Server-reflexive (STUN-discovered) direct path.
    Srflx,
    /// Relayed through TURN (T05).
    Relay,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Path::Direct => "direct",
            Path::Srflx => "srflx",
            Path::Relay => "relay",
        })
    }
}
