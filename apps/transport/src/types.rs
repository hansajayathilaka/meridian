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

/// A TURN/relay ICE server with the ephemeral credential minted by the rendezvous (T05, §5.4).
/// `urls` is one server's ladder (e.g. its UDP, TCP, and TLS-443 forms); `username`/`credential`
/// are the per-session HMAC token — **never** a static TURN secret (webrtc-nat-traversal
/// invariant 4). Mirrors the browser's `RTCIceServer` shape so the WASM backend maps it 1:1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceServer {
    /// TURN URLs, e.g. `turn:turn.org:3478?transport=udp`, `turns:turn.org:443?transport=tcp`.
    pub urls: Vec<String>,
    /// Ephemeral username (`<expiry>:<nonce>`); `None` for a credential-less STUN entry.
    pub username: Option<String>,
    /// Ephemeral credential (`base64(HMAC-SHA1(secret, username))`).
    pub credential: Option<String>,
}

/// ICE configuration handed to [`Transport::new_session`]. STUN servers give server-reflexive
/// candidates; TURN relay servers (with ephemeral creds) enable the relay rung of the ladder (T05).
#[derive(Clone, Debug, Default)]
pub struct IceConfig {
    /// STUN URLs (e.g. `stun:stun.l.google.com:19302`). Empty ⇒ host candidates only.
    pub stun_servers: Vec<String>,
    /// TURN relay servers with ephemeral credentials (T05). Empty ⇒ no relay rung (host/STUN only).
    pub ice_servers: Vec<IceServer>,
    /// The relay policy for this session.
    pub policy: IcePolicy,
}

/// Which relay transport a relayed pair landed on — the hostile-egress ladder (§5.4). Surfaced in
/// `meridian session info`/`doctor` so the latency-vs-egress trade is visible, not hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTransport {
    /// TURN over UDP (lowest overhead).
    Udp,
    /// TURN over TCP (UDP to the relay is blocked, but 3478/tcp is open).
    Tcp,
    /// TURN over TLS on 443 — the last-resort path through hostile egress that only allows HTTPS.
    Tls443,
}

impl std::fmt::Display for RelayTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RelayTransport::Udp => "udp",
            RelayTransport::Tcp => "tcp",
            RelayTransport::Tls443 => "tls-443",
        })
    }
}

/// The selected candidate pair with the detail `meridian session info` prints: the class, and — when
/// relayed — which relay server and transport carried it. `Direct`/`Srflx` leave the relay fields
/// `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathDetail {
    pub class: Path,
    /// The relay's short label (from the winning TURN url's host), when `class == Relay`.
    pub relay_server: Option<String>,
    /// Which relay transport won, when `class == Relay`.
    pub relay_transport: Option<RelayTransport>,
}

impl PathDetail {
    /// A plain direct/srflx pair with no relay involved.
    pub fn direct(class: Path) -> Self {
        Self {
            class,
            relay_server: None,
            relay_transport: None,
        }
    }
}

/// A simulated NAT/egress condition for the deterministic `LoopbackTransport` — the four
/// netns-matrix cells (feature 05 scope) reproduced in-process so CI proves the policy/ladder logic
/// without `NET_ADMIN`. The real webrtc-rs backend derives the same outcomes from live ICE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NatScenario {
    /// Full-cone / open NAT: a host or server-reflexive pair connects directly.
    #[default]
    FullCone,
    /// Port-restricted cone: hole-punching still yields a working srflx pair.
    PortRestricted,
    /// Symmetric × symmetric: direct and srflx pairs fail; the session relays over TURN/UDP.
    SymmetricPair,
    /// UDP fully dropped (hostile egress): even STUN fails; the session relays over TURN/TLS-443.
    UdpBlocked,
}

impl NatScenario {
    /// Whether direct/srflx pairs fail, forcing a relay even under a `direct` policy.
    pub fn blocks_direct(self) -> bool {
        matches!(self, NatScenario::SymmetricPair | NatScenario::UdpBlocked)
    }

    /// Whether server-reflexive (STUN) candidates are reachable at all (UDP-blocked ⇒ no srflx).
    pub fn srflx_reachable(self) -> bool {
        !matches!(self, NatScenario::UdpBlocked)
    }

    /// Which relay transport a relayed pair lands on under this scenario.
    pub fn relay_transport(self) -> RelayTransport {
        match self {
            NatScenario::UdpBlocked => RelayTransport::Tls443,
            _ => RelayTransport::Udp,
        }
    }

    /// Parse the `--nat` demo/CLI knob. Accepts `full-cone`, `port-restricted`,
    /// `symmetric`/`symmetric:symmetric`, `udp-blocked`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "full-cone" | "fullcone" | "open" => Some(NatScenario::FullCone),
            "port-restricted" | "restricted" => Some(NatScenario::PortRestricted),
            "symmetric" | "symmetric:symmetric" | "sym" => Some(NatScenario::SymmetricPair),
            "udp-blocked" | "block-udp" | "udp-drop" => Some(NatScenario::UdpBlocked),
            _ => None,
        }
    }

    /// A human label for diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            NatScenario::FullCone => "full-cone",
            NatScenario::PortRestricted => "port-restricted",
            NatScenario::SymmetricPair => "symmetric:symmetric",
            NatScenario::UdpBlocked => "udp-blocked",
        }
    }
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
