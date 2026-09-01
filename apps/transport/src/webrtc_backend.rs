//! `WebRtcTransport` — the production data-plane [`Transport`](crate::Transport) backend
//! (webrtc-rs), gated behind the `webrtc` feature (ADR 0006, ADR 0014). Two instances talk real
//! ICE/SCTP/DTLS over UDP — on the same host for the gated test suite, over a real network in
//! deployment — instead of the in-process simulation [`crate::LoopbackTransport`] provides.
//!
//! ## Negotiated (pre-arranged) data channels
//! `mrd.ctrl/1` and `mrd.chat/1` open at dial/answer time (`apps/core/src/session.rs`
//! `dial_with_config`/`answer_with_config`); every other registered stream type (T09 file transfer,
//! and future T15/T16 types) opens its *own* new SCTP data channel labeled `"{type}#{sid}"`, on
//! accept — both peers call [`Transport::add_data_channel`] symmetrically: the responder when it
//! decides to accept (alongside sending `Accept` on `mrd.ctrl/1`), the initiator on receiving that
//! `Accept` (`session.rs`'s `Open`- and `Accept`-handling arms both call it). If both peers called
//! `create_data_channel(label)` in-band (the WebRTC default), each side would end up with *two*
//! channels per label — the one it created locally, and a second one delivered via `on_data_channel`
//! for the peer's independent call with the same label. We sidestep that by using WebRTC's
//! **negotiated** mode: both sides derive the *same* SCTP stream id from the channel label via
//! [`stream_id_for_label`] (pure function, no coordination needed) and create the channel with
//! `negotiated: Some(id)`, so there is exactly one logical channel per label, symmetrically
//! (`add_data_channel` rejects a label whose derived id collides with a different label already on
//! the session, rather than silently cross-wiring two streams).
//!
//! ## SCTP max-message-size: the default is too small for a full `mrd.file/1` chunk (task 10.18 fix)
//! `webrtc-sctp`'s (and thus `webrtc-rs`'s) built-in default `max_message_size` is 65536 bytes
//! (`SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE`, RFC 8841 §6.1's own default) — too small for a "full"
//! 64 KiB `mrd.file/1` chunk once its own layers of framing are added on top: 65536 bytes of
//! plaintext, plus the per-chunk XChaCha20-Poly1305 tag (16 bytes,
//! `apps/streams/src/chunk.rs::seal_chunk`), plus the deterministic-CBOR `ChunkFrame{i, data}`
//! envelope's own map/key/byte-string-length overhead (14 bytes for a full chunk — measured directly
//! via `ChunkFrame::encode`, not estimated), plus the 1-byte resume-vs-chunk discriminator
//! (`apps/streams/src/resume.rs::FRAME_TAG_CHUNK`), plus the outer Double Ratchet frame this whole
//! blob is then sealed under a second time (`apps/crypto/src/ratchet.rs`: a 2-byte big-endian header
//! length prefix + an 80-byte encrypted header [24-byte random nonce + 40-byte header plaintext +
//! 16-byte Poly1305 tag] + a second 16-byte Poly1305 tag on the message ciphertext itself) — a
//! measured total of **65665 bytes** for one of the first 24 chunks of a file (65536 + 16 + 14 + 1 +
//! 2 + 80 + 16 = 65665), 129 bytes over the 65536-byte default — CBOR's variable-length uint
//! encoding of the chunk index grows that 14-byte figure by 1-4 bytes for later chunks (index ≥ 24,
//! ≥ 256, ≥ 65536), so a chunk late in a very large file can land a few bytes above 65665; the chosen
//! 256 KiB ceiling (below) has ~196 KiB of headroom regardless, so this doesn't change the fix, only
//! the precision of this comment. `WebRtcTransport::new()` built its
//! `SettingEngine` with no override, so both a dialer and an answerer negotiated that same
//! too-small ceiling — every multi-chunk file transfer failed deterministically on its first full
//! chunk (`docs/testing/soak-file-transfer-throughput.md`; found independently by tasks 10.14/10.15).
//!
//! **Two changes are both required, not just one** — confirmed by reading `webrtc-rs` 0.17.1's own
//! source (the pinned `webrtc-sctp`/`webrtc` crates under `~/.cargo/registry`), not just its public
//! API docs:
//! 1. [`SettingEngine::set_sctp_max_message_size_can_send`] raises *our own* willingness to send
//!    large messages. But `RTCSctpTransport::start`'s `calc_message_size` computes the actual, live
//!    ceiling as `min(what the peer's SDP declares it can receive, what we're willing to send)` — and
//!    `webrtc-rs` 0.17.1's own SDP writer (`add_data_media_section`, `peer_connection/sdp/mod.rs`)
//!    **never emits an `a=max-message-size` line at all**, on either side, under any `SettingEngine`
//!    configuration. Left at that, `get_application_media_section_max_message_size` always returns
//!    `None` when parsing the peer's SDP, so `calc_message_size` falls back to the RFC's own
//!    65536-byte default for "what the peer can receive" — meaning raising only `can_send` on both
//!    sides would silently do **nothing**: `calc_message_size(65536, can_send_size)` still returns
//!    `65536` whenever `can_send_size >= 65536` (see the vendored
//!    `webrtc-sctp-0.17.1/src/sctp_transport/mod.rs`'s `calc_message_size`, and that crate's own
//!    gated test `test_given_remote_max_message_size_is_none_when_data_channel_can_send_max_message_size_respected_on_send`,
//!    which proves exactly this — it asserts `ErrOutboundPacketTooLarge` at 65536 bytes even with
//!    `can_send` set to `Unbounded`, precisely because nothing declared a larger *receive* ceiling).
//! 2. So [`with_max_message_size_attr`] appends `a=max-message-size:<SCTP_MAX_MESSAGE_SIZE>` directly
//!    to the raw SDP text — applied lazily inside [`Transport::local_description`] itself, computed
//!    fresh from the pristine cached `pending_offer`/`committed_local_sdp` on every call, **not** at
//!    the point those are cached. That distinction matters: webrtc-rs's own `set_local_description`
//!    independently re-validates whatever text it is given against its *internal* snapshot of the
//!    just-generated offer/answer, byte-for-byte, rejecting any mismatch outright
//!    (`ErrSDPDoesNotMatchOffer`/`ErrSDPDoesNotMatchAnswer`) — so the text passed to
//!    `set_local_description` must stay exactly what `create_offer`/`create_answer` produced, while
//!    only the text this backend actually *asserts to the peer* (`local_description()`'s return
//!    value) carries the extra attribute. Since `apps/core/src/session.rs`'s `dial_with_config`/
//!    `answer_with_config` send exactly `local_description()`'s bytes to the peer inside the
//!    ratchet-encrypted ctrl envelope, the peer's own `set_remote_description` parses this line and
//!    sees our declared ceiling — the same mechanism `webrtc-rs`'s own test suite exercises by
//!    hand-appending the attribute to a test SDP (see [`with_max_message_size_attr`]'s own doc for
//!    why the attribute must be applied at the `local_description()` read boundary, not at write
//!    time, given that internal webrtc-rs validation).
//! 3. Steps 1 and 2 together are still only half the fix, and this half is easy to miss because it
//!    fails *silently* rather than with an error like step 1's: they raise the **send**-side ceiling
//!    end to end, but `RTCDataChannel::on_message`'s own doc comment already warns "OnMessage can
//!    currently receive messages up to 16384 bytes in size" — and empirically (confirmed by this
//!    module's own gated regression test, before this third fix was added) the real behavior is
//!    worse than a truncation: `RTCDataChannel::read_loop`'s internal read buffer is a fixed,
//!    non-configurable `webrtc::data_channel::DATA_CHANNEL_BUFFER_SIZE` (`u16::MAX` = 65535 bytes),
//!    and `webrtc_data::DataChannel::read_data_channel` returns `Error::ErrShortBuffer` whenever a
//!    reassembled message is larger than the caller's buffer — which `RTCDataChannel::read_loop`
//!    treats as a hard error, **closing the channel** rather than delivering anything. So even with
//!    steps 1–2 in place, sending one `SCTP_MAX_MESSAGE_SIZE`-sized message over the stock
//!    `on_message` callback API silently kills the channel before the receiver ever sees it — no
//!    error surfaces to the sender (`send()` already returned `Ok`), and no message ever reaches
//!    `recv()`. `SettingEngine::detach_data_channels()` (set once in `WebRtcTransport::new`) disables
//!    that internal read loop for every channel on this backend; `add_data_channel` then calls
//!    `RTCDataChannel::detach()` from its `on_open` handler and drives its own read loop
//!    ([`detached_channel_read_loop`]) with a buffer sized to [`SCTP_MAX_MESSAGE_SIZE`] instead.
//!
//! Both peers run identical code (`WebRtcTransport::new()` is the single shared constructor for
//! both `dial` and `answer` — `apps/core/src/session.rs` calls it identically on both paths), so both
//! declare (via step 2), honor (via step 1), and actually deliver (via step 3)
//! [`SCTP_MAX_MESSAGE_SIZE`]-sized messages symmetrically regardless of which side dials and which
//! answers — proven, not just asserted, by this module's own
//! `multi_chunk_file_transfer_completes_over_real_sctp` gated test (`apps/transport/tests/webrtc_backend.rs`),
//! which sends real multi-chunk-sized messages in *both* directions over one connected pair.
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
//! ## ICE restart: real local primitive, pending peer signaling (task 10.19 / ADR 0025)
//! [`Transport::ice_restart`] now invokes webrtc-rs's real ICE-agent restart —
//! `RTCPeerConnection::create_offer` with [`RTCOfferOptions`]'s `ice_restart: true`, followed by
//! `set_local_description` with the result — mirroring exactly how `dial_established`'s first offer
//! is produced and committed (see "Offer/answer without a role hint" above): local candidate-gathering
//! bookkeeping (`local_candidates`/`gather_done_flag`) is reset first, then the new offer is committed
//! as `committed_local_sdp`, so [`Transport::local_description`]/[`Transport::local_fingerprint`]/
//! [`Transport::local_candidates`] all immediately reflect the restarted state the same way they do
//! for the very first offer. Confirmed by reading `webrtc-ice` 0.17.1's own `Agent::restart` (the
//! `webrtc-rs` 0.17.1 dependency this crate pins): it generates a fresh local ufrag/pwd, clears the
//! selected candidate pair and every previously-known candidate, and re-triggers gathering — a real
//! restart, not a relabeled no-op (the gated test
//! `ice_restart_produces_a_genuinely_new_local_offer_without_disturbing_channels_or_fingerprint` in
//! `apps/transport/tests/webrtc_backend.rs` proves the ufrag/pwd actually change). The DTLS
//! certificate is never touched by any of this — `create_offer`/`set_local_description` never
//! recreate the `RTCPeerConnection` — so [`Transport::local_fingerprint`] is provably byte-identical
//! before and after (also proven by that same test), which is the invariant a later task's layered
//! fingerprint cross-check (ADR 0025) depends on holding at the transport level.
//!
//! **This is only the local half.** Exactly as before, `apps/core`'s `P2pSession::ice_restart` (as
//! of this task) has no session-layer signaling path to carry the resulting offer to the peer — ADR
//! 0025 designs that delivery (a tolerant, mailbox-eligible `IceRestartOffer`/`IceRestartAnswer`
//! round trip over `SignalRelay`, not the data channel the restart may itself be repairing) as
//! separate, later tasks (10.20–10.23). Calling only this primitive, on one or both sides of an
//! already-connected pair, with no peer coordination, still knocks the live candidate pair out from
//! under the active DTLS/SCTP association exactly as the old module doc warned — `Agent::restart`
//! unilaterally deletes the selected pair and rotates local credentials regardless of whether the
//! peer ever learns about it. Only once the full round trip lands does a restart actually leave the
//! session resumable; until then, invoking this transport primitive by itself does not fulfill
//! system-design §5.2/§7.3's "resumable... ICE restarts on network change" promise or feature-04's
//! acceptance criterion. `LoopbackTransport::ice_restart` stays an explicit, documented no-op per
//! ADR 0025 — the loopback fabric has no real network to restart, so there is nothing for it to
//! simulate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::{SctpMaxMessageSize, SettingEngine};
use webrtc::api::{APIBuilder, API};
use webrtc::data::data_channel::DataChannel as DetachedDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice::candidate::{CandidatePairState, CandidateType};
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer as WrtcIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::offer_answer_options::RTCOfferOptions;
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

/// Bounds the *entire* `local_candidates` flow — committing the local SDP (which, for the dialer,
/// is what actually kicks off ICE/TURN gathering) plus the wait for gathering to finish — not just
/// the final "wait for `gather_done`" step `WAIT_TIMEOUT` already covered on its own.
///
/// Needed because of a real, confirmed gap (see
/// `docs/tasks/phase-1/1.30-turn-tcp-dependency-gap.md`): the pinned `webrtc-ice` 0.17.1 has no
/// client-side TURN-over-TCP support at all, and under `IcePolicy::RelayOnly` against a
/// UDP-blocked network, its relay-candidate gathering worker can stall indefinitely *before*
/// `local_candidates`'s own `WAIT_TIMEOUT`-bounded wait point is ever reached (empirically, this
/// hung well past 90 seconds with no output at all — nowhere close to bounded by `WAIT_TIMEOUT`).
/// Wrapping the whole flow in one outer timeout guarantees this fails loud within a bounded window
/// instead of hanging silently, regardless of exactly where inside the flow the stall occurs.
const GATHER_TIMEOUT: Duration = Duration::from_secs(20);

/// How long [`close`](WebRtcTransport::close) will wait for each data channel's `buffered_amount`
/// to drain to zero before tearing the peer connection down. `send()` (below) only guarantees the
/// bytes were handed to the SCTP association's outgoing queue, not that they left the process —
/// unlike `LoopbackTransport::send`, which delivers straight into the peer's inbox before
/// returning, so a same-process caller's `close()` can never race a delivery already in flight.
/// Bounded (rather than unbounded) so a peer that vanished mid-send can't hang teardown forever;
/// short, because in practice this only ever needs to cover "let the runtime poll the SCTP
/// flush task once", not a real network RTT.
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// `webrtc-ice`'s own defaults (`disconnected_timeout` 5s + `failed_timeout` 25s, i.e. 30s before
/// the ICE agent gives up on a `Checking` phase that never found *any* valid pair) exceed
/// [`WAIT_TIMEOUT`] — under a real NAT, permanently-unreachable host/srflx pairs (expected: that's
/// just what NAT does) sit in `Checking` well past our own bounded wait, so the caller times out
/// with "no candidate pair selected yet" long before the ICE agent itself would ever have declared
/// the direct/srflx pairs a lost cause and kept servicing the (working) relay-vs-relay pair.
/// Tightened here — confirmed against the real six-namespace NAT/coturn rig (`tools/netns-nat-matrix.sh`)
/// — so the agent's own give-up horizon sits comfortably inside `WAIT_TIMEOUT`, leaving room for
/// several full connectivity-check rounds against the relay pair before our own bound expires.
/// Deliberately still well above one keepalive/check round (not a hair-trigger) so a merely-slow
/// real link isn't mistaken for a dead one.
///
/// (task 2.16) `disconnected_timeout`+`failed_timeout` was `2s`+`4s` (6s total) from 1.29 until this
/// task found a second, distinct failure mode it was too tight for: a **valid** host-candidate pair
/// (both peers on the same reachable network, e.g. the `session_connect_webrtc.rs` acceptance test)
/// can fail to get validated within a 6s Checking budget whenever *other* ICE-server gathering
/// (STUN reflexive probing, a TURN Allocate) is concurrently running against a server that's
/// configured but doesn't actually answer — confirmed by repeated, timestamped reproduction: the
/// Checking→Failed transition landed almost exactly 6.0s after Checking began, every time, with a
/// real host/host pair sitting right there unvalidated. Widening to `3s`+`9s` (12s total — still
/// comfortably inside [`WAIT_TIMEOUT`]'s 15s, preserving 1.29's own margin requirement) fixed it
/// (repeated local runs: session establishes directly, no 1.29 relay-fallback retry needed, in
/// ~21–23s total end to end instead of failing after ~70–90s across two doomed attempts). This is a
/// **narrower, distinct problem from 1.29's** (1.29: even a *correct* relay-vs-relay pair under real
/// NAT got zero STUN responses at all, a hard non-convergence unrelated to timeout length, which is
/// why 1.29 rejected timeout-tuning as insufficient *for that problem* and added the session-level
/// relay-fallback retry instead) — here the pair genuinely was reachable and would have validated
/// given a little more of the *existing* Checking budget, no protocol-level non-convergence
/// involved. Verified locally against every NAT-scenario test this sandbox can run without
/// `NET_ADMIN` (`nat_matrix_selects_the_right_path`, `relay_only_strips_host_and_srflx_before_gathering`,
/// `doctor_connects_all_four_cells`, `symmetric_nat_relays_over_udp`,
/// `udp_blocked_falls_back_to_tls_443`) — all still pass unchanged. Per 1.29's own precedent, a
/// change to these constants should still get a live confirmation run against the real
/// `tools/netns-nat-matrix.sh` rig (this sandbox has no `NET_ADMIN`/`iproute2` to run it) before
/// being considered fully verified — flagged for connectivity-debugger follow-up.
const ICE_DISCONNECTED_TIMEOUT: Duration = Duration::from_secs(3);
const ICE_FAILED_TIMEOUT: Duration = Duration::from_secs(9);
const ICE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// (task 10.18) The negotiated SCTP association ceiling this backend declares (in SDP, via
/// [`with_max_message_size_attr`]) and honors (via `SettingEngine::set_sctp_max_message_size_can_send`
/// in [`WebRtcTransport::new`]) on both the dial and answer paths — see the module doc's "SCTP
/// max-message-size" section for why *both* halves are required against real `webrtc-rs` 0.17.1
/// peers, and why this is symmetric regardless of which side dials.
///
/// 256 KiB. A measured full `mrd.file/1` chunk needs ~65665 bytes on the wire for one of the first 24
/// chunks of a file (module doc has the byte-by-byte accounting: 65536-byte plaintext + 16-byte
/// chunk AEAD tag + 14 bytes of CBOR `ChunkFrame` framing + 1-byte frame-kind discriminator + 2-byte
/// ratchet header-length prefix + 80-byte encrypted ratchet header + 16-byte ratchet AEAD tag; CBOR's
/// variable-length chunk-index encoding adds a few more bytes for a chunk later in a very large
/// file) — comfortably (~4x) under this value,
/// while still leaving headroom for any other single-frame payload this substrate ever puts on one
/// SCTP message (a resume bitmap, a future stream type's own frame) without needing to re-tune this
/// constant every time chunk-adjacent framing grows by a few bytes. 256 KiB is also not a
/// stack-specific outlier: it is the same order of magnitude several real-world WebRTC
/// implementations already treat as an unremarkable default receive ceiling.
const SCTP_MAX_MESSAGE_SIZE: u32 = 256 * 1024;

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

/// (task 10.18) Append the `a=max-message-size` attribute this backend declares to a local SDP
/// offer/answer's raw text — see the module doc's "SCTP max-message-size" section for why this
/// manual step is required (webrtc-rs 0.17.1 never writes this attribute itself, on either side, no
/// matter how `SettingEngine` is configured).
///
/// **Called only from [`Transport::local_description`], lazily, on every read — never at the point
/// `pending_offer`/`committed_local_sdp` are cached.** That is deliberate, not incidental: webrtc-rs's
/// own `set_local_description` re-validates whatever text it is given against its *internal*
/// snapshot of the just-generated offer/answer, byte-for-byte, and rejects any mismatch outright
/// (`Error::ErrSDPDoesNotMatchOffer`/`ErrSDPDoesNotMatchAnswer` — confirmed empirically: an earlier
/// version of this fix mutated the text before `set_local_description` and every gated test in
/// `apps/transport/tests/webrtc_backend.rs` failed with exactly that error). So the text passed to
/// `set_local_description` must stay byte-identical to whatever `create_offer`/`create_answer`
/// produced; only the text actually asserted to the peer (`local_description()`'s return value, and
/// thus what `apps/core/src/session.rs` hands to the peer's `set_remote_description`) carries the
/// extra attribute. Computing it fresh from the pristine cached copy on every call (rather than
/// mutating the cached copy in place) also means repeat calls to `local_description()` never
/// accumulate multiple copies of the line.
///
/// Safe to append at the very end of the whole SDP text unconditionally — a data-channel-only
/// session always has exactly one `m=application` media section and nothing after it for the
/// appended line to be mistakenly attributed to (see [`Transport::add_ice_candidate`]'s own
/// `sdp_mline_index: 0` for the same one-media-section assumption already relied on elsewhere in
/// this file).
///
/// Debug-asserts the input never already carries this attribute: `webrtc-rs` 0.17.1 never writes it
/// (that's why this function exists at all), but a future point-release upgrade fixing that upstream
/// gap would otherwise get silently duplicated into two conflicting `a=max-message-size` lines,
/// exactly the kind of upgrade-time regression this function's whole existence is meant to guard
/// against, not reintroduce. If this assertion ever fires, `SCTP_MAX_MESSAGE_SIZE`/this workaround
/// should be revisited against whatever `webrtc-rs` version triggered it.
fn with_max_message_size_attr(mut sdp: String) -> String {
    debug_assert!(
        !sdp.contains("a=max-message-size:"),
        "webrtc-rs's SDP writer already emitted a=max-message-size — this workaround (task 10.18) \
         is stale for the pinned webrtc-rs version and would now duplicate the line"
    );
    sdp.push_str(&format!("a=max-message-size:{SCTP_MAX_MESSAGE_SIZE}\r\n"));
    sdp
}

/// (task 10.18) Drives one detached data channel's inbound reads, forwarding each fully-reassembled
/// message into `tx` — the replacement for `RTCDataChannel::on_message`'s internal read loop (see
/// [`with_max_message_size_attr`]'s call site in `add_data_channel` for why that internal loop's
/// fixed, non-configurable buffer cannot carry a message above `webrtc::data_channel`'s hardcoded
/// `DATA_CHANNEL_BUFFER_SIZE` (`u16::MAX` = 65535 bytes) — silently closing the channel instead of
/// delivering anything larger). `buf` is sized to [`SCTP_MAX_MESSAGE_SIZE`], the same ceiling this
/// backend negotiates for sending, so nothing this backend could ever legally send to itself is too
/// big to read back. Runs until the underlying stream reports EOF/closed (`Ok((0, _))`), a read
/// error (peer reset, association torn down), or `tx`'s receiver is gone (the session itself was
/// dropped) — every exit path is a quiet `return`, matching `RTCDataChannel::read_loop`'s own
/// close-on-EOF-or-error behavior, since a background per-channel task has no caller left to report
/// an error to by the time any of those happen.
async fn detached_channel_read_loop(
    dc: Arc<DetachedDataChannel>,
    cid: ChannelId,
    tx: mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
) {
    let mut buf = vec![0u8; SCTP_MAX_MESSAGE_SIZE as usize];
    loop {
        match dc.read_data_channel(&mut buf).await {
            Ok((0, _)) => return,
            Ok((n, _is_string)) => {
                if tx.send((cid, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
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
    ///
    /// Three non-default knobs:
    /// - `set_ice_timeouts` (see [`ICE_DISCONNECTED_TIMEOUT`] / [`ICE_FAILED_TIMEOUT`] /
    ///   [`ICE_KEEPALIVE_INTERVAL`]'s docs) — without it, `webrtc-ice`'s own defaults leave the ICE
    ///   agent's internal "give up on `Checking`" horizon (30s) past [`WAIT_TIMEOUT`] (15s), so a
    ///   real NAT's permanently-unreachable host/srflx pairs under `IcePolicy::Direct`/`PreferRelay`
    ///   (`RTCIceTransportPolicy::All`) leave us timing out before the agent would ever have moved
    ///   on to nominate the (working) relay-vs-relay pair.
    /// - `set_sctp_max_message_size_can_send` (see [`SCTP_MAX_MESSAGE_SIZE`] and the module doc's
    ///   "SCTP max-message-size" section) — task 10.18: raises the *send*-side ceiling. Without it
    ///   (and without [`with_max_message_size_attr`]'s matching SDP change, applied at every
    ///   offer/answer generation point below), `webrtc-sctp`'s 65536-byte default silently rejects a
    ///   single full `mrd.file/1` chunk outbound.
    /// - `detach_data_channels` — task 10.18's other, easy-to-miss half: raising the send ceiling
    ///   alone still leaves the *receive* side capped, because `RTCDataChannel::on_message`'s
    ///   internal read loop uses a fixed, non-configurable 65535-byte buffer and closes the channel
    ///   outright on anything larger rather than truncating. Detaching hands channels back to us as
    ///   raw streams (`add_data_channel` drives its own read loop via
    ///   [`detached_channel_read_loop`], buffered to [`SCTP_MAX_MESSAGE_SIZE`]) instead of relying
    ///   on that internal loop.
    pub fn new() -> Self {
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_ice_timeouts(
            Some(ICE_DISCONNECTED_TIMEOUT),
            Some(ICE_FAILED_TIMEOUT),
            Some(ICE_KEEPALIVE_INTERVAL),
        );
        setting_engine
            .set_sctp_max_message_size_can_send(SctpMaxMessageSize::Bounded(SCTP_MAX_MESSAGE_SIZE));
        setting_engine.detach_data_channels();
        let api = APIBuilder::new()
            .with_media_engine(MediaEngine::default())
            .with_setting_engine(setting_engine)
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

    /// Apply `text` as a genuine remote **offer** and produce a genuine local **answer** —
    /// `set_remote_description`, `create_answer`, `set_local_description`, then cache the answer as
    /// `committed_local_sdp` (discarding any stale `pending_offer`) and `text` itself as
    /// `remote_sdp`. Shared, unconditional body for both [`Transport::set_remote_description`]'s
    /// "nothing committed yet" branch (the original handshake's answerer path, where this is
    /// reached *because* `committed_local_sdp` was still empty) and
    /// [`Transport::set_remote_offer_and_answer`] (any later point in the session where the caller
    /// already knows, from its own protocol-level role decision, that `text` is a genuine offer —
    /// e.g. task 10.22's ICE-restart answerer, where `committed_local_sdp` is already `Some` from
    /// earlier in the session's life and so could never itself be used to infer that this is an
    /// offer). See `set_remote_offer_and_answer`'s own doc comment (`apps/transport/src/lib.rs`)
    /// for the full rationale for why these two call sites need a shared, commit-state-independent
    /// primitive rather than each re-deriving it.
    async fn apply_remote_offer_and_answer(&self, sess: &Arc<Session>, text: String) -> Result<()> {
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
        *sess.remote_sdp.lock().unwrap() = Some(text);
        Ok(())
    }

    /// The actual gather-and-collect body of [`Transport::local_candidates`], factored out so the
    /// whole thing (commit + wait) can be wrapped in one outer [`GATHER_TIMEOUT`] by the caller.
    async fn gather_local_candidates(&self, sess: &Arc<Session>) -> Result<Vec<IceCandidate>> {
        self.ensure_committed(sess).await?;

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
        // (task 10.18) Detach-and-drive-our-own-reads, rather than `RTCDataChannel::on_message` —
        // see the module doc's "SCTP max-message-size" section, part 3: `on_message`'s internal
        // read loop uses a fixed, non-configurable `DATA_CHANNEL_BUFFER_SIZE` (`u16::MAX` = 65535
        // bytes) buffer and, on any single message that reassembles to *more* than that, closes the
        // channel outright rather than truncating or erroring gracefully — silently swallowing
        // exactly the >64 KiB messages this fix exists to carry. `SettingEngine::detach_data_channels`
        // (set once, for every channel, in `WebRtcTransport::new`) disables that internal read loop
        // entirely in favor of the raw stream handed back by `RTCDataChannel::detach`, so here we
        // read it ourselves with a buffer sized to [`SCTP_MAX_MESSAGE_SIZE`].
        {
            let ready_flag = ready_flag.clone();
            let ready_notify = ready_notify.clone();
            let tx = sess.inbox_tx.clone();
            let dc_for_detach = dc.clone();
            dc.on_open(Box::new(move || {
                ready_flag.store(true, Ordering::SeqCst);
                ready_notify.notify_waiters();
                let tx = tx.clone();
                let dc_for_detach = dc_for_detach.clone();
                Box::pin(async move {
                    // `detach()` only fails if `detach_data_channels` wasn't enabled (it always is,
                    // here) or the channel isn't open yet (it just was, per `handle_open`'s own
                    // ordering — `data_channel` is stored before `on_open` fires) — never expected
                    // to fail in practice, but if it somehow did, the honest behavior is "this
                    // channel never delivers anything" rather than a panic.
                    if let Ok(detached) = dc_for_detach.detach().await {
                        tokio::spawn(detached_channel_read_loop(detached, cid, tx));
                    }
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
        // (task 10.18) `with_max_message_size_attr` is applied here, at the read boundary, rather
        // than at write time when `committed_local_sdp`/`pending_offer` are cached — see the module
        // doc's "SCTP max-message-size" section and [`with_max_message_size_attr`]'s own doc for
        // why: webrtc-rs's `set_local_description` independently re-checks whatever text it's given
        // against its *own* internal snapshot of the just-generated offer/answer (byte-for-byte,
        // rejecting any mismatch as `ErrSDPDoesNotMatchOffer`/`ErrSDPDoesNotMatchAnswer`), so the
        // text handed to `set_local_description` must stay exactly what `create_offer`/
        // `create_answer` produced. Only the text this trait method actually asserts to the peer —
        // computed fresh from the pristine cached copy on every call, never accumulating repeat
        // appends across multiple calls — carries the extra attribute.
        if let Some(sdp) = sess.committed_local_sdp.lock().unwrap().clone() {
            return Ok(Sdp(with_max_message_size_attr(sdp).into_bytes()));
        }
        if let Some(sdp) = sess.pending_offer.lock().unwrap().clone() {
            return Ok(Sdp(with_max_message_size_attr(sdp).into_bytes()));
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
            // We already committed our own not-yet-answered offer — this must be the peer's
            // answer. Valid whenever the committed local description is genuinely this side's own
            // outstanding offer: the dialer at the original handshake, or either side immediately
            // after its own `ice_restart()` call awaiting the peer's matching answer — regardless
            // of how many times the session has restarted. NOT valid when the committed state is
            // instead stale/unrelated and `sdp` is a fresh, peer-initiated offer (the ICE-restart
            // *answerer*'s case) — see this trait method's own doc comment (`apps/transport/src/lib.rs`)
            // and `set_remote_offer_and_answer` for the unconditional alternative such callers use
            // instead.
            let desc = RTCSessionDescription::answer(text.clone())
                .map_err(|_| TransportError::BadRemoteDescription)?;
            sess.pc
                .set_remote_description(desc)
                .await
                .map_err(backend_err)?;
            *sess.remote_sdp.lock().unwrap() = Some(text);
        } else {
            // Nothing committed yet — this is the peer's offer (answerer path).
            self.apply_remote_offer_and_answer(&sess, text).await?;
        }
        Ok(())
    }

    async fn set_remote_offer_and_answer(&self, s: &SessionHandle, sdp: Sdp) -> Result<()> {
        let sess = self.get_session(s)?;
        let text = String::from_utf8(sdp.0).map_err(|_| TransportError::BadRemoteDescription)?;
        self.apply_remote_offer_and_answer(&sess, text).await
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
        // See `GATHER_TIMEOUT`'s docs: this bounds `ensure_committed` (which kicks off gathering
        // for the dialer) *and* the wait for it to finish as a single unit, so a stall anywhere in
        // that flow — not just at the final `notified()` wait point — still fails loud instead of
        // hanging.
        tokio::time::timeout(GATHER_TIMEOUT, self.gather_local_candidates(&sess))
            .await
            .map_err(|_| {
                TransportError::Backend(format!(
                    "ICE candidate gathering did not complete within {GATHER_TIMEOUT:?} — this is \
                     a known gap when relay-only policy meets a UDP-blocked network: the pinned \
                     webrtc-ice 0.17.1 has no client-side TURN-over-TCP support at all, so a TURN \
                     server reachable only over TCP/TLS can stall gathering indefinitely (see \
                     docs/tasks/phase-1/1.30-turn-tcp-dependency-gap.md)"
                ))
            })?
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
        // (task 10.19 / ADR 0025) The real primitive: `create_offer(ice_restart: true)` rotates
        // the ICE agent's local ufrag/pwd and re-triggers gathering (`webrtc-ice`'s own
        // `Agent::restart`, confirmed by reading its source: it clears the selected candidate pair
        // and every known candidate, then re-gathers), producing a fresh offer exactly the way
        // `dial_established`'s first offer was produced (mirrored below) — see module docs' "ICE
        // restart: real local primitive, pending peer signaling" section for the full picture and
        // what this alone does/doesn't buy.
        //
        // Reset local candidate-gathering bookkeeping *before* triggering the restart, not after,
        // so a caller that immediately calls `local_candidates()` once this returns waits on the
        // *new* gathering pass's own completion signal rather than racing whatever `on_ice_candidate`
        // callbacks the restart itself is about to fire as a side effect of `create_offer` below.
        sess.local_candidates.lock().unwrap().clear();
        sess.gather_done_flag.store(false, Ordering::SeqCst);

        let options = RTCOfferOptions {
            ice_restart: true,
            ..Default::default()
        };
        let offer = sess
            .pc
            .create_offer(Some(options))
            .await
            .map_err(backend_err)?;
        let desc = RTCSessionDescription::offer(offer.sdp.clone()).map_err(backend_err)?;
        sess.pc
            .set_local_description(desc)
            .await
            .map_err(backend_err)?;
        // Mirrors `ensure_committed`'s own cache update for the very first offer: `committed_local_sdp`
        // is what `Transport::local_description`/`local_fingerprint` read from, so both immediately
        // reflect the restarted state, and `pending_offer` is cleared since there is nothing left to
        // lazily commit — we just committed directly.
        *sess.committed_local_sdp.lock().unwrap() = Some(offer.sdp);
        *sess.pending_offer.lock().unwrap() = None;
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

    async fn buffered_amount(&self, s: &SessionHandle, ch: &ChannelId) -> Result<u64> {
        let sess = self.get_session(s)?;
        let dc = {
            let map = sess.channels.lock().unwrap();
            map.get(ch)
                .ok_or(TransportError::UnknownChannel)?
                .dc
                .clone()
        };
        // The real SCTP outbound queue depth (bytes handed to `send()` not yet flushed) — see
        // `close()`'s drain loop above, which already relies on this same call.
        Ok(dc.buffered_amount().await as u64)
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
            // inventing a distinction webrtc-rs doesn't expose. NOTE: this is the relay *transport
            // rung* (udp/tcp/tls-443), a different gap from candidate *class* (host/srflx/relay) —
            // 1.16 closed the latter (`meridian_core::relay::observed_classes`/
            // `enforce_relay_only`); this rung-classification gap is still open and has no assigned
            // task yet, though 1.27's real packet captures are the most likely place it gets solved.
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
            // Drain each data channel's outstanding `send()`s before tearing the association
            // down. Without this, a message queued just before `close()` (e.g. the responder's
            // final chat reply in `apps/cli`'s `session connect`) can be silently dropped:
            // `RTCDataChannel::send` returning only means the bytes were accepted into the SCTP
            // association's outgoing buffer, not that they were actually written to the wire —
            // and `pc.close()` tears down the ICE/DTLS/SCTP stack (and the underlying UDP socket)
            // immediately, with no flush of its own. Bounded by `CLOSE_DRAIN_TIMEOUT` so a peer
            // that is gone (nothing will ever drain the buffer) can't hang teardown forever.
            let dcs: Vec<Arc<RTCDataChannel>> = sess
                .channels
                .lock()
                .unwrap()
                .values()
                .map(|c| c.dc.clone())
                .collect();
            let deadline = tokio::time::Instant::now() + CLOSE_DRAIN_TIMEOUT;
            for dc in dcs {
                while dc.buffered_amount().await > 0 && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
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

    #[test]
    fn max_message_size_attr_is_appended_and_parseable_by_webrtc_rs_own_reader() {
        // (task 10.18) Guards the exact mechanism the module doc's "SCTP max-message-size" section
        // relies on: webrtc-rs 0.17.1 never writes this line itself, so this crate must, and it must
        // land somewhere webrtc-rs's own SDP attribute reader will actually find it (i.e. inside the
        // one `m=application` media section, not after it / outside any section).
        let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
                    m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                    c=IN IP4 0.0.0.0\r\na=sctp-port:5000\r\n";
        let out = with_max_message_size_attr(sdp.to_string());
        assert!(out.ends_with(&format!("a=max-message-size:{SCTP_MAX_MESSAGE_SIZE}\r\n")));
        assert_eq!(
            out.matches("a=max-message-size:").count(),
            1,
            "must append exactly once, not accumulate across repeated calls to the same text"
        );
    }
}
