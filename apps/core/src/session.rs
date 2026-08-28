//! The P2P **session substrate** (T04): moves T03 chat off the server relay and onto a direct
//! WebRTC peer connection. It ties together the [`Transport`](meridian_transport::Transport) seam,
//! the crypto ratchet (via [`ChatState`]), the `mrd.ctrl/1` control channel, and the
//! [`StreamRegistry`], implementing the dial/answer state machine of
//! [system-design §7.1](../../docs/architecture/system-design.md) steps 6–14 and the session state
//! machine in `docs/architecture/diagrams/session-state-machine.mermaid`.
//!
//! ## The load-bearing security property: fingerprint binding (§4.6)
//! SDP and the DTLS fingerprint travel **inside** ratchet-encrypted, AEAD-authenticated envelopes
//! ([`SignalContent`]) — envelope v2 carries no per-message signature at all
//! ([ADR 0016](../../docs/adr/0016-envelope-deniability.md)) — so the rendezvous only ever routes
//! opaque blobs — it can neither read nor rewrite an offer. After the handshake the substrate
//! cross-checks the transport's *negotiated* remote fingerprint against the one the peer *asserted*
//! in its encrypted envelope; any mismatch tears the session down before a byte of content flows. A
//! relay that only sees opaque ciphertext cannot read or forge the inner SDP (that opacity is a
//! property of the envelope encryption itself, independent of transport backend), and a MITM that
//! terminates DTLS presents a fingerprint that fails the check. An automated test actively mounting a
//! relay-rewrite attempt against a real rendezvous now exists (task 1.28: `apps/cli/tests/
//! relay_rewrite.rs`, run by `harnesses/mitm-sim/run.sh`) — a server rewriting routed blobs is
//! detected by the ratchet AEAD (the mutated ciphertext fails to decrypt) and no session establishes.
//! This is why we can put the servers out of the data path and still trust it.
//!
//! One honest residual that test surfaced: the *responder* rejects a rewritten offer immediately,
//! but the **dialer** then waits indefinitely for an answer that never comes — a hostile relay can
//! hang it with no diagnostic, and the same hang is reachable with no adversary at all (a peer that
//! is simply offline). Fail-closed (no session, nothing downgraded) and squarely inside threat-model
//! goal 6's conceded "a malicious server can deny service", but poor diagnostics. Not fixed in 1.28,
//! whose scope is adversarial test infrastructure — bounded in 1.33 (see [`recv_sdp`] and
//! [`SessionError::AnswerTimeout`]), mirroring the [`Transport::selected_path`] bounded wait this
//! same module already relied on. Federation (2.9+) later opened the mirror-image gap on the
//! *responder's* own wait for the offer — a route can be rejected server-side before any offer ever
//! arrives — closed in 2.17 (see [`SessionError::OfferTimeout`]).
//!
//! ## Transport independence
//! Once connected, chat and ctrl ride data channels peer-to-peer; the relay is only used for
//! signaling and can vanish mid-conversation without interrupting the session (the headline demo).
//! The same [`MessageEnvelope`](meridian_envelope::MessageEnvelope) bytes are valid over the relay or a
//! data channel (§4.3), so re-homing chat is a change of carrier, not of format.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use crate::trust::TrustStore;

/// Channel-0 label — always opened first, reliable/ordered (§5.3).
pub const CTRL_LABEL: &str = "mrd.ctrl/1";
/// The re-homed Tier-1 chat stream label.
pub const CHAT_LABEL: &str = "mrd.chat/1";
const CTRL_SID: u64 = 0;
const CHAT_SID: u64 = 1;

/// (1.33) How long [`dial_established`] will wait for the peer's answer before giving up. Bounds
/// the *dialer's* wait specifically — the responder's wait for the offer is unchanged (it already
/// fails fast on a malformed/tampered envelope; see `recv_sdp`'s `chat.open_bytes` call).
///
/// Mirrors [`Transport::selected_path`]'s own bounded wait (see its call sites' comments below) in
/// mechanism and spirit rather than inventing a new one: without a bound here, a peer that never
/// answers — offline, or a hostile relay that lets the responder reject without ever producing an
/// answer (1.28's adversarial relay-rewrite test) — hangs `dial` forever with no diagnostic, holding
/// a live transport session/ICE agent/UDP sockets the whole time.
///
/// **This bound sits downstream of, not alongside, the responder's own ICE-gather bound — it must
/// exceed it, not undercut it.** Trickle ICE isn't supported yet (inbound `IceTrickle` envelopes are
/// ignored pre-connection), so both sides gather their *full* candidate set before sealing and
/// sending SDP. On the real WebRTC backend that gather is itself bounded at up to 20s
/// (`GATHER_TIMEOUT` in `apps/transport/src/webrtc_backend.rs`, deliberately generous because real
/// STUN/TURN round trips legitimately take that long). So the wait this constant bounds actually
/// covers: relay latency (offer) + responder session setup + the responder's own up-to-~20s gather +
/// relay latency (answer) — a value anywhere near that inner 20s bound would spuriously abort a
/// handshake that was proceeding correctly on an honest-but-slow peer, reintroducing for that case
/// exactly the failure mode this task exists to fix for the adversarial one. 30s gives that full
/// chain room plus margin for two relay hops. The exact value is still a tuning knob, not a security
/// boundary — firing early only costs a spurious `AnswerTimeout` on an unusually slow-but-honest
/// peer, never a weaker session (fail-closed is unaffected either way).
///
/// Note for the record (not a new invariant, and improved since task 6.3): by the time `dial` reaches
/// this wait, the offer already asserts one of the peer's one-time prekeys (`used_opk` in the X3DH
/// preamble) — but that reference alone no longer guarantees the prekey is destroyed. Since task
/// 6.3's commit-on-successful-decrypt fix (ADR 0016 C2), the peer's vault only removes an OTK secret
/// after a decrypt against it actually *succeeds* (`take_otk_secret` runs only post-decrypt; the
/// provisional path uses the non-destructive `peek_otk_secret`). So a hostile relay that
/// rewrites-and-drops this offer (corrupting the ciphertext or preamble so the peer's decrypt fails)
/// no longer burns the peer's real one-time prekey the way an equivalent pre-6.3 attack would have —
/// the peer's vault entry survives intact for a genuine subsequent attempt. This closes the
/// "OTK-depletion amplifier" reading of this residual for the rewrite-and-drop case specifically;
/// what remains is the ordinary, already-bounded per-source OTK-issuance limit (§3.5) covering
/// *legitimate* fetches, which is not a new hole.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// (2.17) How long [`answer_with_config`] will wait for the offer envelope before giving up, on
/// *both* of its `recv_sdp` call sites: the initial offer wait and the 1.29 relay-fallback second
/// wait for the dialer's retried offer. Mirrors [`ANSWER_TIMEOUT`]'s reasoning for the opposite side
/// of the handshake — that doc comment already says explicitly it bounds "the dialer's wait
/// specifically — the responder's wait for the offer is unchanged," which was true until federation
/// (2.9+) introduced a failure mode 1.33 never covered: a route can now be rejected *server-side*
/// (closed policy, allowlist miss, rate limit) before any offer ever reaches the answering side, so
/// the bare `loop { relay.recv().await?; ... }` inside `recv_sdp` blocks forever with nothing to
/// reject — the same DoS-class gap 1.33 fixed for the dialer, just reachable from the other side now.
///
/// **Distinct constant, not a reuse of `ANSWER_TIMEOUT`**, even though the value is currently
/// identical: the two bound different sides of the handshake for different reasons (see
/// [`SessionError::OfferTimeout`] vs. [`SessionError::AnswerTimeout`]), and a distinct name keeps
/// each call site's intent readable and lets the two be tuned independently later without an
/// implicit coupling. The value itself is deliberately the *same* 30s: the two waits cover
/// overlapping chains built from the same underlying costs (one relay hop + one peer's up-to-~20s
/// full-candidate gather, since trickle ICE isn't supported — see `GATHER_TIMEOUT` in
/// `apps/transport/src/webrtc_backend.rs`), so there's no principled reason for a tighter number
/// here, and reusing 30s avoids introducing a second independently-tuned magic value with no data to
/// justify a different one. This also comfortably covers the relay-fallback second wait: by the time
/// that wait starts, the dialer has already detected its own `NoPath` (bounded by the transport's own
/// `WAIT_TIMEOUT`, 15s) and immediately re-dials, so this window only needs to absorb one more
/// gather-plus-relay-hop cycle — the same order of magnitude `ANSWER_TIMEOUT` already budgets for.
/// Not a security boundary any more than `ANSWER_TIMEOUT` is: firing early only costs a spurious
/// `OfferTimeout` on an unusually slow-but-honest dialer, never a weaker session.
///
/// OTK-amplifier check (2.17, mirroring `ANSWER_TIMEOUT`'s own note): waiting here does **not**
/// consume anything of the *answerer's* own that a hostile/absent dial could drain repeatedly.
/// `recv_sdp`'s loop only calls `relay.recv()` and, on this bound firing, `chat.open_bytes` is never
/// reached at all — no bytes arrived, so nothing is decrypted, no ratchet state advances, and no OTK
/// is consumed by this wait. Any OTK the *answerer* holds is consumed only when some caller fetches
/// its published prekey bundle from the rendezvous server (an X3DH-initiation event that happens
/// independently of whether this function is even running, and is already bounded by the server-side
/// per-source OTK-issuance cap, §3.5) — never as a side effect of waiting here. So a peer that spams
/// `answer()` calls against a target that never offers gains nothing beyond the cost of the calls it
/// makes itself; it cannot drain the answerer's OTKs through this wait.
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Under `relay-only`, a host/srflx (or unrecognized) candidate was actually gathered — the
    /// observation-based counterpart to the policy label (F20). Fail closed: the dial/answer
    /// aborts before this candidate is ever sent to the peer, rather than trusting the transport's
    /// construction alone to have honored the policy.
    #[error("relay-only violated: observed non-relay candidate ({candidate})")]
    RelayOnlyViolation { candidate: String },
    /// (1.33) The dialer's bounded wait (see [`ANSWER_TIMEOUT`]) for the peer's answer expired. The
    /// connection is torn down when this fires (no session, never a degraded one) — distinguishable
    /// from `Chat(ChatError::Crypto)` (a byte that *did* arrive but failed the ratchet AEAD, i.e.
    /// tampering detected) and from `Relay`/`SignalingEnded` (the relay itself misbehaved/vanished):
    /// this specifically means "the peer never answered", whether because it's offline or because a
    /// hostile relay silently dropped/rewrote the offer.
    #[error("timed out after {0:?} waiting for the peer's answer")]
    AnswerTimeout(Duration),
    /// (2.17) The answerer's bounded wait (see [`OFFER_TIMEOUT`]) for the dialer's offer expired —
    /// mirrors [`SessionError::AnswerTimeout`] on the opposite side of the handshake. Fires on either
    /// of `answer_with_config`'s `recv_sdp` calls: the initial offer wait, or the 1.29 relay-fallback
    /// second wait for the dialer's retried offer. No session is ever established when this fires
    /// (fail-closed, never a degraded one) — distinguishable from `Chat(ChatError::Crypto)` (tampering
    /// detected — a byte that *did* arrive but failed the ratchet AEAD) and from `Relay`/
    /// `SignalingEnded` (the relay itself misbehaved/vanished): this specifically means "no offer ever
    /// arrived", whether because the dialer is offline, a hostile relay silently dropped it, or
    /// (2.9+, federation) the route was rejected server-side — closed policy, allowlist miss, rate
    /// limit — before any offer could ever reach us.
    #[error("timed out after {0:?} waiting for the peer's offer")]
    OfferTimeout(Duration),
    /// (2.9) A federated signaling request was refused by the peer org's own admission policy —
    /// mirrors [`meridian_signaling::SignalError::FedDenied`] (`fed_denied`, task 2.6). A **policy**
    /// outcome, structurally distinct from [`SessionError::FingerprintMismatch`] and
    /// [`SessionError::Chat`]'s actual security checks below — never a security warning (ADR 0001;
    /// docs/security/verification-ux.md's canonical copy is reserved for real key substitution).
    #[error("federation denied by {hint}'s policy: {detail}")]
    FedDenied { hint: String, detail: String },
    /// (2.9) The hinted peer org could not be reached at all — mirrors
    /// [`meridian_signaling::SignalError::FedUnreachable`] (`fed_unreachable`, tasks 2.7/2.8). A
    /// **connectivity** outcome, orthogonal to [`SessionError::FedDenied`]'s policy outcome and to
    /// the fingerprint/envelope security checks.
    #[error("{hint} is unreachable at hint: {detail}")]
    FedUnreachable { hint: String, detail: String },
    /// (2.9) The hinted peer org was reached but doesn't hold this peer — mirrors
    /// [`meridian_signaling::SignalError::NotFoundAtHint`] (`not_found_at_hint`, task 2.7), the
    /// stale-hint case (ADR 0001: the hint is advisory, never a trust input). A **reachability**
    /// outcome only — never, under any circumstance, a security warning, and structurally distinct
    /// from [`SessionError::FingerprintMismatch`]/[`SessionError::Chat`]'s key-substitution/tamper
    /// checks (conflating the two is exactly the failure mode this task exists to prevent).
    #[error("unreachable at hint {hint}: no such account there ({detail})")]
    NotFoundAtHint { hint: String, detail: String },
    /// (task 5.5, review finding F5) [`P2pSession::recover_from_desync`]'s own error — either the
    /// underlying `ChatState`/ratchet machinery or the `TrustStore`, exactly the same two failure
    /// modes [`crate::desync::RecoveryError`] already distinguishes for
    /// `apps/cli/src/chat.rs`'s identical CLI-side call, surfaced here rather than invented afresh.
    #[error("desync recovery error: {0}")]
    Recovery(#[from] crate::desync::RecoveryError),
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
    /// The transport actually negotiating this session (e.g. `loopback` in tests/demo today; a real
    /// backend's own name once one lands, per T04/1.15) — not a fixed, backend-agnostic label.
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
    /// The candidate classes **actually gathered and offered** to the peer — observed from the
    /// real candidate lines the transport produced (F20), not merely implied by `policy`.
    pub offered: GatherClasses,
    /// A short human explanation of why this path was chosen.
    pub reason: String,
    /// `true` if this session only connected because the first attempt (under the configured
    /// `Direct`/`PreferRelay` policy) never converged and we retried forcing `RelayOnly` (1.29, Bug
    /// A). `policy`/`offered` above already reflect the retry's `RelayOnly` reality; this flag is
    /// what tells the operator a *fallback happened at all* rather than that being the configured
    /// policy from the start.
    pub relay_fallback: bool,
    /// How long the abandoned first attempt spent stuck before we gave up and retried — the added
    /// latency the fallback cost, surfaced rather than hidden (Feature 5's "show the cost" note).
    /// `None` unless `relay_fallback` is `true`.
    pub relay_fallback_wait_ms: Option<f64>,
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
        )?;
        if self.relay_fallback {
            match self.relay_fallback_wait_ms {
                Some(ms) => write!(
                    f,
                    " relay_fallback=true (direct/prefer-relay attempt stalled {ms:.0}ms before retrying relay-only)"
                )?,
                None => write!(f, " relay_fallback=true")?,
            }
        }
        Ok(())
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
    /// The candidate classes **actually observed** in our own gathered candidates (F20) — measured
    /// once, from the exact lines sent to the peer in the offer/answer, not re-derived from
    /// `policy` on every call.
    offered: GatherClasses,
    /// Set by [`Self::mark_relay_fallback`] when this session only connected via 1.29's Bug-A
    /// relay-only retry — see [`SessionInfo::relay_fallback`].
    relay_fallback: bool,
    /// The abandoned first attempt's wait, when `relay_fallback` is set — see
    /// [`SessionInfo::relay_fallback_wait_ms`].
    relay_fallback_wait_ms: Option<f64>,
    /// (task 2.14) `true` until this session's *first* `mrd.chat/1` content frame has been through
    /// the message-request gate. Set at construction from a snapshot — taken by
    /// [`dial_established`]/[`answer_with_config`] *before* the offer/answer handshake installed
    /// this session — of whether `peer_ik` was already a known contact. `false` from the start for
    /// a dialer (whose crypto session with `peer_ik` must already exist before `dial` is called,
    /// per [`dial_with_config`]'s doc) and for a responder answering an already-known peer;
    /// `true` for a responder's first-ever P2P session with an unrecognized peer.
    ///
    /// [`ChatState::open_inbound`]'s own first-contact detection (`!sessions.contains_key(from)`)
    /// cannot see this: by the time a chat frame reaches [`P2pSession::pump`], the session was
    /// already installed as a side effect of the SDP/offer-answer exchange's own `open_bytes`
    /// calls, so that check would always read `false`. This flag is what lets `pump` force the
    /// gate via [`ChatState::open_inbound_gated`] on exactly the first content frame, then clear
    /// itself once the gate has actually fired (inserted a [`crate::chat::MessageRequest`]) — see
    /// `pump`'s `CHAT_LABEL` arm. Left `true` on any *other* error (e.g. a forged first frame) so a
    /// subsequent, genuine first frame is still gated rather than slipping through ungated.
    ///
    /// (task 3.11) Also read (never mutated) by [`Self::decide_open`] as half of the live
    /// `PolicyCtx::first_contact` signal fed to every registered stream type's `on_open` hook — see
    /// that function's doc for why this flag alone is insufficient once the first chat frame has
    /// been processed, and `ChatState::pending_request` covers the rest.
    chat_first_contact_gate: bool,
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

    /// Record that this session only exists because [`dial_with_config`]/[`answer_with_config`]
    /// retried under a forced `relay-only` policy after the first attempt (under the caller's
    /// configured `Direct`/`PreferRelay`) never converged (1.29, Bug A). `wait_ms` is how long that
    /// abandoned first attempt was stuck before we gave up — the added latency the fallback cost.
    fn mark_relay_fallback(&mut self, wait_ms: f64) {
        self.relay_fallback = true;
        self.relay_fallback_wait_ms = Some(wait_ms);
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
            transport: self.transport.name(),
            path: detail.class,
            relay_server: detail.relay_server,
            relay_transport: detail.relay_transport,
            rtt_ms: self.last_rtt_ms,
            streams,
            policy: self.policy,
            offered: self.offered,
            reason: path_reason(self.policy, detail.class),
            relay_fallback: self.relay_fallback,
            relay_fallback_wait_ms: self.relay_fallback_wait_ms,
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
                if self.chat_first_contact_gate {
                    // (task 2.14) Force the gate on this content frame regardless of what
                    // `ChatState` itself can see (the session already exists — see the field's
                    // doc). `Err(ChatError::MessageRequest)` means the content decoded and
                    // verified fine and is now held in `chat.pending_requests`, exactly like the
                    // relay path (`ChatError::MessageRequest` propagates through
                    // `SessionError::Chat` via `?`, same as it did before this frame was gated) —
                    // clear the flag so subsequent frames (post accept/reject) use the ordinary,
                    // session-presence-based check. Any *other* error (bad decrypt, desync, …)
                    // leaves the flag set: a hostile/garbled first frame must not let a later,
                    // genuine first frame slip through ungated.
                    match chat.open_inbound_gated(
                        store,
                        handle,
                        &self.our_ik,
                        &self.peer_ik,
                        &blob,
                        true,
                        false,
                    ) {
                        Ok(content) => {
                            // Structurally unreachable while `force_first_contact` is `true` (that
                            // always takes the gate branch on a successful decode) — handled
                            // rather than assumed, and still clears the flag if it ever did fire.
                            self.chat_first_contact_gate = false;
                            Ok(Some(SessionEvent::Chat(content)))
                        }
                        Err(ChatError::MessageRequest) => {
                            self.chat_first_contact_gate = false;
                            Err(SessionError::Chat(ChatError::MessageRequest))
                        }
                        Err(e) => Err(SessionError::Chat(e)),
                    }
                } else {
                    let content =
                        chat.open_inbound(store, handle, &self.our_ik, &self.peer_ik, &blob)?;
                    Ok(Some(SessionEvent::Chat(content)))
                }
            }
            _ => {
                // Treat anything else (ctrl, or a not-yet-labelled channel) as a ctrl frame.
                let frame = self.open_ctrl(store, handle, chat, &blob)?;
                self.handle_ctrl(store, handle, chat, frame).await
            }
        }
    }

    /// (task 5.5, review finding F5) The P2P substrate's own receive-side half of task 4.9's guarded
    /// desync recovery — mirrors `apps/cli/src/chat.rs::maybe_attempt_recovery`'s gate discipline
    /// exactly, closing the gap review finding F5 named: before this task, `session.rs` held no
    /// `TrustStore`/`can_send` reference at all, so a key substitution against an already-established
    /// P2P session went undetected outside `meridian chat`'s relay path.
    ///
    /// **Deliberately decoupled from any live signaling connection.** By the time [`pump`](Self::pump)
    /// is looping, the rendezvous connection may already be gone — T04's headline "servers out of the
    /// data path" property (this module's own doc comment) — so this substrate makes no network calls
    /// of its own to recover from a desync. The caller supplies an already-fetched,
    /// already-signature-verified bundle for this session's peer (`bundle_owner_ik`/`peer_spk`/
    /// `peer_opk`/`hint` — the exact shape [`crate::desync::attempt_recovery`] already takes), however
    /// it obtained it — a reconnected `SignalingClient::fetch_bundle`, in practice — mirroring
    /// `fetch_with_retry`/`attempt_recovery`'s existing split between "fetch" (network, caller-owned)
    /// and "decide + apply" (I/O-free, here). Note that in the one production call path that exists
    /// today (a real `SignalingClient::fetch_bundle(peer_ik, ..)`), `meridian_signaling::verify_bundle`
    /// pins the fetched signature to the *exact requested* key, so a genuine on-the-wire substitution
    /// against `self.peer_ik` fails closed at that fetch, before this method is ever reached — exactly
    /// `crate::desync::attempt_recovery`'s own doc comment's point, restated here for this substrate's
    /// callers. `bundle_owner_ik` still exists as its own parameter (never assumed equal to this
    /// session's peer) precisely so a future fetch strategy that *can* resolve to a different key
    /// inherits the same guard automatically, and so this method's key-change handling stays testable
    /// in isolation (`apps/core/tests/session.rs`).
    ///
    /// **Ordering, precisely (mirrors `maybe_attempt_recovery`'s own doc, design requirement 2).**
    /// Returns `Ok(None)` without touching `chat`/`trust` at all when
    /// [`ChatState::recovery_recommended`] reads `false` for this session's peer (not yet at the
    /// repeated-`Desync` threshold) — callers should check this cheap, I/O-free condition *before*
    /// spending a network round trip on a bundle fetch at all, exactly as `maybe_attempt_recovery`
    /// does. Once recovery is recommended, delegates directly to
    /// [`crate::desync::attempt_recovery`], which itself resets the desync counter as its very first
    /// action (whatever the outcome) and consults [`TrustStore::can_send`] before ever calling
    /// [`ChatState::replace_session_as_initiator`] — so a peer already `Warn`/`Blocked` from an
    /// unresolved key change never gets an automatic re-handshake layered on top, and a substituted
    /// key is routed through [`TrustStore::observe_key_change`] exactly like any other key-change
    /// discovery, never silently accepted just because a recovery flow happened to be in progress.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_from_desync(
        &self,
        chat: &mut ChatState,
        trust: &mut TrustStore,
        store: &dyn SecretStore,
        handle: &KeyHandle,
        bundle_owner_ik: &[u8; 32],
        peer_spk: &[u8; 32],
        peer_opk: Option<[u8; 32]>,
        hint: &str,
        now_unix: u64,
    ) -> Result<Option<crate::desync::RecoveryOutcome>, SessionError> {
        if !chat.recovery_recommended(&self.peer_ik) {
            return Ok(None);
        }
        let outcome = crate::desync::attempt_recovery(
            chat,
            trust,
            store,
            handle,
            &self.our_ik,
            &self.peer_ik,
            bundle_owner_ik,
            peer_spk,
            peer_opk,
            hint,
            now_unix,
        )?;
        Ok(Some(outcome))
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
        let plaintext = chat.open_bytes(store, handle, &self.our_ik, &self.peer_ik, blob, false)?;
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
                let decision = self.decide_open(sid, &ty, &params, chat);
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

    /// (task 3.11 / review finding F11) `first_contact` is derived from **live** peer state, not a
    /// per-session snapshot, and — critically — is registry-agnostic: it answers "is this peer
    /// currently an undecided first contact" the same way regardless of which stream type `ty`
    /// names, so a hook a future stream type (file/media/…) writes for its own `on_open` sees the
    /// real signal without this substrate ever special-casing that type. Two conditions, either of
    /// which means "yes":
    ///   * `self.chat_first_contact_gate` — still `true` before this session's first-ever
    ///     `mrd.chat/1` content frame has even arrived (see that field's doc): a peer who opens some
    ///     *other* stream type before ever sending a chat message is exactly as much a first contact
    ///     as one who sends chat first.
    ///   * `chat.pending_request(&self.peer_ik).is_some()` — a `MessageRequest` already exists for
    ///     this peer and the local user has not yet accepted/rejected it. This is what
    ///     `chat_first_contact_gate` alone *cannot* see: that flag is cleared the moment the first
    ///     chat content frame is *processed* (`pump`'s `CHAT_LABEL` arm), independent of whether the
    ///     resulting `MessageRequest` has actually been decided — so a peer who has sent one chat
    ///     message, still awaiting accept/reject, and then opens a second (non-chat) stream must
    ///     still read as a first contact. Reuses `ChatState::pending_request` (already public, task
    ///     2.10/3.10) rather than duplicating `pending_requests` bookkeeping here.
    fn decide_open(
        &self,
        sid: u64,
        ty: &str,
        params: &[u8],
        chat: &ChatState,
    ) -> crate::streams::OpenDecision {
        match self.registry.get(ty) {
            Some(st) => {
                let first_contact =
                    self.chat_first_contact_gate || chat.pending_request(&self.peer_ik).is_some();
                st.on_open(
                    sid,
                    params,
                    &crate::streams::PolicyCtx {
                        peer_ik: self.peer_ik,
                        first_contact,
                    },
                )
            }
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
///
/// ## Relay fallback (1.29, Bug A)
/// Under a real NAT, `Direct`/`PreferRelay` can gather permanently-unreachable host/srflx
/// candidates that never resolve — the transport's own bounded wait (`selected_path`) then reports
/// [`TransportError::NoPath`] even though a relay pair would have worked (confirmed against the real
/// six-namespace NAT/coturn rig; see `docs/tasks/phase-1/1.29-ice-nomination-relay-fallback.md`).
/// When that happens **and** a TURN grant was actually available ([`relay_fallback_eligible`]), this
/// retries the *entire* offer/answer/ICE exchange once more forcing [`IcePolicy::RelayOnly`] — a
/// second full round trip through `relay`, not a silent instant retry, so it costs real wall-clock
/// time on top of the failed first attempt. That cost is never hidden: [`SessionInfo::relay_fallback`]
/// and [`SessionInfo::relay_fallback_wait_ms`] surface it (see `session info`/`doctor`), matching
/// Feature 5's "show the cost" requirement. This is a real behavioral addition to the single-phase
/// fallback [`seq-call-relay-fallback.mermaid`](../../../docs/architecture/diagrams/seq-call-relay-fallback.mermaid)
/// documented before 1.29 — see that diagram and
/// [Feature 5's spec](../../../docs/architecture/features/05-nat-traversal-relay-policy.md) for the
/// now-documented two-phase retry.
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
    let attempt_start = Instant::now();
    let policy = cfg.policy;
    let conn = transport.new_session(cfg.clone()).await?;
    // Every path below is fallible after the session exists; close it on any of them rather than
    // leaking a live peer connection (real backends hold real ICE agents/UDP sockets — a malicious
    // or malformed peer that keeps failing this handshake must not be able to leak one per attempt).
    let result = dial_established(
        &transport,
        conn,
        policy,
        store,
        handle,
        our_ik,
        peer_ik,
        chat,
        relay,
        registry.clone(),
    )
    .await;
    match result {
        Ok(session) => Ok(session),
        Err(SessionError::Transport(meridian_transport::TransportError::NoPath))
            if relay_fallback_eligible(&cfg) =>
        {
            let _ = transport.close(&conn).await;
            let wait_ms = attempt_start.elapsed().as_secs_f64() * 1000.0;
            let fallback_cfg = IceConfig {
                policy: IcePolicy::RelayOnly,
                ..cfg
            };
            let conn2 = transport.new_session(fallback_cfg).await?;
            let result2 = dial_established(
                &transport,
                conn2,
                IcePolicy::RelayOnly,
                store,
                handle,
                our_ik,
                peer_ik,
                chat,
                relay,
                registry,
            )
            .await;
            match result2 {
                Ok(mut session) => {
                    session.mark_relay_fallback(wait_ms);
                    Ok(session)
                }
                Err(e) => {
                    let _ = transport.close(&conn2).await;
                    Err(e)
                }
            }
        }
        Err(e) => {
            let _ = transport.close(&conn).await;
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dial_established<T: Transport>(
    transport: &Arc<T>,
    conn: SessionHandle,
    policy: IcePolicy,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    chat: &mut ChatState,
    relay: &mut dyn SignalRelay,
    registry: Arc<StreamRegistry>,
) -> Result<P2pSession<T>, SessionError> {
    // (task 2.14) Snapshot *before* anything below touches `chat`'s session map, for
    // `chat_first_contact_gate` (see that field's doc). In practice this reads `true` (known)
    // here: `dial`/`dial_with_config`'s own doc requires the caller to have already established
    // the crypto session with `peer_ik` (X3DH) before dialing, and nothing in this function's own
    // signaling touches a *new* session for `peer_ik` (the answer is opened via `chat.open_bytes`
    // on the session that already exists). Computed rather than hardcoded so the invariant is
    // enforced structurally, not just documented.
    let peer_known_before = chat.has_session(&peer_ik);

    let ctrl_ch = transport
        .add_data_channel(&conn, ChannelCfg::reliable_ordered(CTRL_LABEL))
        .await?;
    let chat_ch = transport
        .add_data_channel(&conn, ChannelCfg::reliable_ordered(CHAT_LABEL))
        .await?;

    // Seal SDP offer + our fingerprint + candidates inside a ratchet-encrypted, AEAD-authenticated
    // envelope (no per-message signature — envelope v2, ADR 0016).
    let offer = transport.local_description(&conn)?;
    let local_fp = transport.local_fingerprint(&conn)?;
    let ice = candidate_strings(transport, &conn).await?;
    // F20: abort here, before the offer is sealed and sent, if relay-only actually gathered
    // anything but relay candidates — never trust the policy label alone.
    enforce_relay_only(policy, &ice)?;
    let offered = relay::observed_classes(&ice);
    let offer_content = SignalContent::SdpOffer {
        sdp: offer.0,
        dtls_fp: local_fp.0.clone(),
        ice,
    };
    let blob = chat.seal_bytes(store, handle, &our_ik, &peer_ik, &offer_content.encode()?)?;
    relay.send(&peer_ik, blob).await?;

    // Await the answer, bounded (1.33 — see `ANSWER_TIMEOUT`'s doc for the full rationale): an
    // offline peer, or a hostile relay that lets the responder reject without ever producing an
    // answer, must not hang `dial` forever. On timeout the connection is closed by our caller
    // (`dial_with_config`'s catch-all `Err(e)` arm), the same cleanup path every other failure here
    // already goes through — no session leaks, and this is never a degraded session, just no session.
    let (answer_sdp, asserted_fp, answer_ice) = match tokio::time::timeout(
        ANSWER_TIMEOUT,
        recv_sdp(relay, store, handle, &our_ik, &peer_ik, chat, false),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(SessionError::AnswerTimeout(ANSWER_TIMEOUT)),
    };
    transport
        .set_remote_description(&conn, Sdp(answer_sdp))
        .await?;
    for c in answer_ice {
        transport.add_ice_candidate(&conn, IceCandidate(c)).await?;
    }

    let remote_fp = verify_fingerprint(transport, &conn, &asserted_fp).await?;

    // Wait (bounded by the transport's own connect timeout) for a real path before the ctrl
    // handshake below, which blocks on an unbounded `recv()`. A real backend's connection can
    // legitimately fail to converge (blocked UDP, unreachable peer, no relay reachable); without
    // this, that failure mode hangs `dial`/`answer` forever instead of erroring out cleanly. A
    // no-op for `LoopbackTransport`, which never blocks here.
    transport.selected_path(&conn).await?;

    let mut session = P2pSession {
        transport: transport.clone(),
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
        offered,
        relay_fallback: false,
        relay_fallback_wait_ms: None,
        chat_first_contact_gate: !peer_known_before,
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
///
/// ## Relay fallback (1.29, Bug A)
/// Mirrors [`dial_with_config`]'s retry (see its docs for the full rationale): if our own
/// `selected_path` wait times out under `Direct`/`PreferRelay` with a TURN grant available
/// ([`relay_fallback_eligible`]), we close this attempt and wait for the dialer's *retried* offer
/// (it independently detects the same timeout and re-dials forcing `RelayOnly`), then answer that
/// one instead. `chat`'s ratchet is already established from the first offer, so this second
/// `recv_sdp` is an ordinary subsequent envelope, not a second X3DH open.
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
    let attempt_start = Instant::now();
    let policy = cfg.policy;
    // (task 2.14) Snapshot *before* the first `recv_sdp` below, whose `chat.open_bytes` call
    // installs the responder session as a side effect on a genuine first-ever offer (X3DH) — same
    // ordering requirement as `ChatState::open_inbound`'s own `is_first_contact` snapshot (see
    // `chat_first_contact_gate`'s doc on `P2pSession`). Computed once, here, and reused for both
    // `answer_established` calls below (including the 1.29 relay-fallback retry's second
    // `recv_sdp`): that second offer lands on the *same*, by-then-already-installed session, so
    // recomputing this after it would always (wrongly) read "known".
    let peer_known_before = chat.has_session(&peer_ik);
    // Await the offer, bounded (2.17 — see `OFFER_TIMEOUT`'s doc for the full rationale, including
    // why this is a distinct constant/variant from the dialer-side `ANSWER_TIMEOUT`/`AnswerTimeout`):
    // a dialer that never offers — offline, a hostile relay that drops it, or (federation) a route
    // rejected server-side before any offer reaches us — must not hang `answer` forever.
    let (offer_sdp, asserted_fp, offer_ice) = match tokio::time::timeout(
        OFFER_TIMEOUT,
        recv_sdp(relay, store, handle, &our_ik, &peer_ik, chat, true),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(SessionError::OfferTimeout(OFFER_TIMEOUT)),
    };

    let conn = transport.new_session(cfg.clone()).await?;
    // See `dial_with_config`'s comment: close the session on any failure below rather than
    // leaking a live peer connection.
    let result = answer_established(
        &transport,
        conn,
        policy,
        offer_sdp,
        offer_ice,
        asserted_fp,
        store,
        handle,
        our_ik,
        peer_ik,
        chat,
        relay,
        registry.clone(),
        peer_known_before,
    )
    .await;
    match result {
        Ok(session) => Ok(session),
        Err(SessionError::Transport(meridian_transport::TransportError::NoPath))
            if relay_fallback_eligible(&cfg) =>
        {
            let _ = transport.close(&conn).await;
            let wait_ms = attempt_start.elapsed().as_secs_f64() * 1000.0;
            // Same bound as the initial wait above (2.17): the dialer's own retry is expected
            // quickly (it independently detected the same `NoPath`), but nothing guarantees it
            // arrives at all, so this second wait must not be able to hang forever either.
            let (offer_sdp2, asserted_fp2, offer_ice2) = match tokio::time::timeout(
                OFFER_TIMEOUT,
                recv_sdp(relay, store, handle, &our_ik, &peer_ik, chat, true),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => return Err(SessionError::OfferTimeout(OFFER_TIMEOUT)),
            };
            let fallback_cfg = IceConfig {
                policy: IcePolicy::RelayOnly,
                ..cfg
            };
            let conn2 = transport.new_session(fallback_cfg).await?;
            let result2 = answer_established(
                &transport,
                conn2,
                IcePolicy::RelayOnly,
                offer_sdp2,
                offer_ice2,
                asserted_fp2,
                store,
                handle,
                our_ik,
                peer_ik,
                chat,
                relay,
                registry,
                peer_known_before,
            )
            .await;
            match result2 {
                Ok(mut session) => {
                    session.mark_relay_fallback(wait_ms);
                    Ok(session)
                }
                Err(e) => {
                    let _ = transport.close(&conn2).await;
                    Err(e)
                }
            }
        }
        Err(e) => {
            let _ = transport.close(&conn).await;
            Err(e)
        }
    }
}

/// Whether a [`TransportError::NoPath`] from the *first* `selected_path` wait is eligible for the
/// relay-only retry (1.29, Bug A): only for `Direct`/`PreferRelay` (a `RelayOnly` session that
/// already failed under the strictest policy has nowhere cheaper to fall back to) **and** only when
/// a TURN grant was actually configured (retrying with no relay servers at all would just repeat
/// the identical failure — never spin on a hopeless retry).
fn relay_fallback_eligible(cfg: &IceConfig) -> bool {
    cfg.policy != IcePolicy::RelayOnly && !cfg.ice_servers.is_empty()
}

#[allow(clippy::too_many_arguments)]
async fn answer_established<T: Transport>(
    transport: &Arc<T>,
    conn: SessionHandle,
    policy: IcePolicy,
    offer_sdp: Vec<u8>,
    offer_ice: Vec<String>,
    asserted_fp: String,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    chat: &mut ChatState,
    relay: &mut dyn SignalRelay,
    registry: Arc<StreamRegistry>,
    peer_known_before: bool,
) -> Result<P2pSession<T>, SessionError> {
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
    let ice = candidate_strings(transport, &conn).await?;
    // F20: same fail-closed check as the dialer — abort before the answer is sealed and sent.
    enforce_relay_only(policy, &ice)?;
    let offered = relay::observed_classes(&ice);
    let answer_content = SignalContent::SdpAnswer {
        sdp: answer_sdp.0,
        dtls_fp: local_fp.0.clone(),
        ice,
    };
    let blob = chat.seal_bytes(store, handle, &our_ik, &peer_ik, &answer_content.encode()?)?;
    relay.send(&peer_ik, blob).await?;

    let remote_fp = verify_fingerprint(transport, &conn, &asserted_fp).await?;

    // See `dial_established`'s comment: fail fast (bounded) rather than hang forever on the
    // unbounded `recv()` inside the handshake below if the real connection never converges.
    transport.selected_path(&conn).await?;

    let mut session = P2pSession {
        transport: transport.clone(),
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
        offered,
        relay_fallback: false,
        relay_fallback_wait_ms: None,
        chat_first_contact_gate: !peer_known_before,
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

/// F20: enforce `relay-only` from **observed** gathered candidates, not the policy label alone.
/// `LoopbackTransport` and the webrtc-rs backend's `RTCIceTransportPolicy::Relay` are both built to
/// strip host/srflx before gathering under this policy — but this is the actual proof point of the
/// IP-hiding guarantee, checked against what a transport really produced rather than assumed from
/// its construction. Fail-closed: any non-relay (or unrecognized — see
/// [`relay::candidate_class`]) candidate aborts *before* the offer/answer carrying it is sealed and
/// sent to the peer, so a transport bug can never leak an address instead of merely being logged.
fn enforce_relay_only(policy: IcePolicy, candidates: &[String]) -> Result<(), SessionError> {
    if policy != IcePolicy::RelayOnly {
        return Ok(());
    }
    for c in candidates {
        if relay::candidate_class(c) != Some(relay::CandidateClass::Relay) {
            return Err(SessionError::RelayOnlyViolation {
                candidate: c.clone(),
            });
        }
    }
    Ok(())
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
        let plaintext = chat.open_bytes(store, handle, our_ik, peer_ik, &blob, false)?;
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
/// the peer asserted inside its ratchet-encrypted, AEAD-authenticated envelope. Mismatch ⇒ teardown,
/// fail closed.
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

#[cfg(test)]
mod tests {
    use super::*;

    // F20: the fail-closed abort itself, independent of any transport — a real transport is built
    // never to leak host/srflx under relay-only, so exercising the abort end-to-end would mean
    // deliberately misbuilding one; testing the pure decision function directly is the honest way
    // to prove "aborts on any non-relay candidate" without faking a backend bug.

    #[test]
    fn relay_only_passes_when_every_candidate_is_relay() {
        let candidates = vec![
            "candidate:relay 1 turn.example.org".to_string(),
            "candidate:4 1 udp 25108223 198.51.100.7 3478 typ relay".to_string(),
        ];
        assert!(enforce_relay_only(IcePolicy::RelayOnly, &candidates).is_ok());
    }

    #[test]
    fn relay_only_aborts_on_a_leaked_host_candidate() {
        let candidates = vec![
            "candidate:relay 1 turn.example.org".to_string(),
            "candidate:host 2 127.0.0.1".to_string(),
        ];
        let err = enforce_relay_only(IcePolicy::RelayOnly, &candidates).unwrap_err();
        assert!(matches!(err, SessionError::RelayOnlyViolation { .. }));
    }

    #[test]
    fn relay_only_aborts_on_a_leaked_srflx_candidate() {
        let candidates =
            vec!["candidate:1 1 udp 999 203.0.113.9 51269 typ srflx raddr 0.0.0.0".to_string()];
        assert!(enforce_relay_only(IcePolicy::RelayOnly, &candidates).is_err());
    }

    #[test]
    fn relay_only_aborts_on_an_unparseable_candidate_worst_case() {
        // A malformed/unrecognized line must never silently pass as "clean" under relay-only.
        let candidates = vec!["not-a-candidate-line".to_string()];
        assert!(enforce_relay_only(IcePolicy::RelayOnly, &candidates).is_err());
    }

    #[test]
    fn non_relay_only_policies_are_never_checked() {
        // direct/prefer-relay intentionally gather host/srflx; enforcement only applies under
        // relay-only.
        let candidates = vec!["candidate:host 1 127.0.0.1".to_string()];
        assert!(enforce_relay_only(IcePolicy::Direct, &candidates).is_ok());
        assert!(enforce_relay_only(IcePolicy::PreferRelay, &candidates).is_ok());
    }
}
