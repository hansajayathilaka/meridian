<!-- Source: docs/tasks/README.md's "Live carry-forwards" (WebRtcTransport::ice_restart no-op),
     live-reconfirmed by tasks 10.15/10.17; architect consult forced by the fix's own scope (new
     wire-level signaling behavior, a breaking session-layer API change). -->
> **Nav:** [ADR index](./README.md) · [ADR 0006 (terminal transport)](./0006-terminal-transport.md) ·
> [ADR 0007 (offline mailbox)](./0007-offline-mailbox.md) ·
> [ADR 0014 (media stack)](./0014-media-stack.md) ·
> [webrtc-nat-traversal skill](../../.claude/skills/webrtc-nat-traversal/SKILL.md) ·
> [system design §5](../architecture/system-design.md) · [wire-protocol.md §3](../api/wire-protocol.md) ·
> [task 10.17](../tasks/phase-10/10.17-phase-exit-demo.md)

# ADR 0025: ICE-restart renegotiation rides the mailbox, not a standing relay connection

**Status:** Accepted. Fills in a mechanism system design left as a one-line promise (§5.2:
"resumable (ICE restarts on network change)"; §7.3: "triggers ICE restart within the session") —
does not contradict or supersede any other Accepted ADR.

## Context

`WebRtcTransport::ice_restart` (`apps/transport/src/webrtc_backend.rs`) has, since it was first built,
only reset local ICE candidate-gathering bookkeeping — it never invokes webrtc-rs's real ICE-agent
restart (`create_offer` with `ice_restart: true`), because doing so unilaterally would rotate the local
ICE ufrag/pwd and knock the live candidate pair out from under the active DTLS/SCTP association with
no peer-side coordination to bring up a replacement. `P2pSession::ice_restart` (`apps/core/src/session.rs`)
has no session-layer signaling path to carry a restart offer to the peer at all — it calls the transport
on one side with no envelope round trip. This was named as a known gap in the transport's own module
doc from the start, and empirically confirmed live by tasks 10.15 and 10.17 this phase: after a real
15-second network cut, `ice_restart()` returns `Ok` on both sides, but the data channel never recovers
— the sender never receives the receiver's resume bitmap, and no chunks are resent. This currently
holds Phase 10's exit gate open (see task 10.17's Outcome).

Closing this gap needs the peer to receive a fresh SDP offer/answer round trip — the same shape as the
original dial/answer handshake (`SignalContent::SdpOffer`/`SdpAnswer`, `apps/envelope/src/signal.rs`),
sealed the same way. The original handshake sends these over `SignalRelay` (the rendezvous-mediated,
server-relayed signaling path), never over the P2P data channel, because at initial-dial time no data
channel exists yet to carry them. An ICE restart is needed precisely when the P2P path — and thus the
`mrd.ctrl/1` data channel every ordinary `CtrlFrame` rides on — may itself be degraded or fully dead, so
a restart offer has the identical problem: it cannot reliably ride the channel it exists to repair, and
must go out-of-band the same way the original offer did.

The immediate design question this ADR resolves: **how does an unsolicited restart offer reach a peer
that isn't actively listening for one**, without reintroducing a property the project has already
built and tested against — feature 04's own acceptance criterion that, once a session is up, "the
servers are out of the data path, demonstrably" (`docs/architecture/features/04-p2p-session-substrate.md`).
`apps/cli/src/session_connect.rs` and `apps/cli/src/send.rs` both explicitly close the rendezvous
connection the instant the P2P session is established, naming this exact property in their own
comments. `docs/security/anonymity-and-retention.md`'s server-visibility table already concedes the
rendezvous operator sees "that two keys signaled; timing" but explicitly *cannot* see how long a
call subsequently ran, because the client disconnects. A design that requires either side to hold a
`SignalRelay`/`SignalingClient` connection open for a session's entire remaining lifetime — "just in
case" a restart is ever needed — would quietly reopen that signal to the server: a real,
previously-unrecorded privacy cost that must be an explicit decision, not an accidental consequence of
an API shape.

## Options

- **A. A standing second listener.** Every caller keeps a `SignalRelay` connection open (or
  reconnects it) for the full duration of every established session, polling it in parallel with the
  transport's own event loop, so either side can push/receive a restart offer at any time.
  **Rejected** — reverses feature 04's tested "servers out of the data path" property and gives the
  rendezvous operator a continuous session-duration presence signal it does not have today, for every
  session, whether or not a restart is ever needed. The cost is paid up front by every caller
  (today's CLI, tomorrow's TUI/mobile) for a benefit (fast restart) that is needed rarely.
- **B. Route the restart offer/answer through the existing hard-fail dial/answer contract**
  (`SignalRelay::send`/`recv`, backed by `RendezvousRelay::send`'s `route_with_hint` →
  `map_route_result`, which turns "peer not currently connected" into a hard `SessionError::Relay`).
  **Rejected** — this contract is deliberately hard-fail because, for a *fresh* dial, there is no
  session yet to fall back on and a queued offer would be stale by the time it's read (the offerer's
  own gathered candidates will have long expired). An ICE restart has no such excuse to hard-fail:
  a live ratchet session and established trust already exist, which is exactly the precondition
  [ADR 0007](./0007-offline-mailbox.md)'s mailbox targets.
- **C. Route the restart offer/answer tolerantly, through the same mailbox-eligible path T07 already
  built (`SignalingClient::route_with_hint_detailed`, `RouteOutcome{delivered, queued}`), reconnecting
  to the rendezvous transiently and on demand rather than holding a connection open. (Chosen.)**

## Decision

**Option C.** Two new `SignalContent` variants, `IceRestartOffer{sdp, dtls_fp, ice}` and
`IceRestartAnswer{sdp, dtls_fp, ice}` (`apps/envelope/src/signal.rs`, same shape as `SdpOffer`/
`SdpAnswer`, documented in `wire-protocol.md` §3's Content union alongside them — this is the same
tier as the existing session-substrate signaling variants, not a `mrd.ctrl/1` `CtrlFrame` addition;
that channel already correctly rejected embedding feature-specific concerns like a file-transfer
`Resume` frame, per `wire-protocol.md` §5's own recorded correction, and ICE restart is generic
session-substrate behavior, not a feature-specific one, so that precedent does not apply here).

**Delivery is tolerant, not hard-fail.** Sending a restart offer/answer accepts `RouteOutcome::queued`
as a normal, non-error outcome — if the peer isn't currently connected to the rendezvous, the envelope
waits in their mailbox until they next reconnect for any reason, exactly like an ordinary offline chat
message. Neither side holds a relay connection open for the session's duration to make this work:
`P2pSession::ice_restart` takes a freshly-constructed `SignalRelay` the same way `dial`/`answer` do,
used only for the bounded duration of one restart attempt, then dropped again.

**One symmetric method, not separate initiate/listen roles.** An ICE restart is needed exactly when
the shared candidate pair breaks — observable independently from either end of the same broken path —
so both sides plausibly decide to restart around the same real-world moment far more often than glare
in the one-shot initial dial. `P2pSession::ice_restart(relay, store, handle, chat)` is called the same
way by whichever side decides to trigger it: the lexicographically-smaller identity key (the
existing `dial`/`answer` role tie-break, `apps/cli/src/chat.rs`'s convention, reusable via the
session's own already-held `our_ik`/`peer_ik`) sends its offer and waits (bounded) for an answer,
discarding any incoming offer it sees in that window; the other side waits briefly for an incoming
offer first and answers it if one arrives, falling through to send its own only if nothing showed up.
This collapses "where does the listening loop live" to: nowhere permanent — it lives inside one
bounded, on-demand call.

**Fingerprint check is layered, not replaced.** A real ICE restart never recreates the
`RTCPeerConnection`, so the DTLS certificate — and thus the fingerprint — is provably unchanged across
it. The restart flow keeps the ordinary asserted-vs-negotiated cross-check
(`apps/core/src/session.rs`'s `verify_fingerprint`, §4.6) on the restart offer/answer's own `dtls_fp`
field (SDP-substitution protection, unweakened), **and adds** a second, distinct assertion that the
result still equals the session's own cached `local_fp`/`remote_fp`. A mismatch on the second check is
a new `SessionError::RestartFingerprintDrift` (an implementation defect signal — something rotated the
cert unexpectedly), never conflated with the ordinary `FingerprintMismatch` (a handshake-time
authentication failure).

**`Transport::ice_restart`'s contract changes to invoke the real primitive.** Making it call
webrtc-rs's real `create_offer(ice_restart: true)` and requiring callers to re-read
`local_description`/`local_fingerprint`/candidates afterward (mirroring `dial_established`'s existing
pattern for the first offer) is a new *mandatory* trait method contract, allowed pre-1.0 while only
in-tree implementors exist (`docs/api/core-api-contracts.md`'s own stability policy).
`LoopbackTransport::ice_restart` stays an explicit, documented no-op — the loopback fabric never has a
real network to restart, so there is nothing for it to simulate.

**Automatic detection/triggering is explicitly out of scope.** Nothing here decides *when* a restart
should be attempted — `WebRtcTransport` still only wires `on_peer_connection_state_change` for
`Connected` (no `Disconnected`/`Failed` handling), and `Transport::recv()` still has no bounded
timeout anywhere in its call chain (an already-named, separate carry-forward,
`docs/tasks/README.md`). A caller (today, an operator or test driver) decides to call `ice_restart`;
closing the detection gap is a distinct, motivated-but-separable follow-up, not bundled here.

## Pros

- Preserves feature 04's tested "servers out of the data path" property for the ordinary case (no
  restart ever needed) — the overwhelming majority of sessions pay zero cost for this capability.
- No new continuous-presence signal to the rendezvous operator: a restart attempt is exactly as visible
  as one ordinary offline-tolerant message exchange, already priced into the existing anonymity model.
- Reuses `SdpOffer`/`SdpAnswer`'s existing wire tier, `SignalContent`'s existing envelope-sealing path,
  T07's existing mailbox-drain machinery, and the existing dial/answer identity-key tie-break — no new
  crypto, no new server-side storage shape, no new client subsystem.
- Layering (not replacing) the fingerprint check keeps every envelope's claim about transport state
  independently verified, the same discipline §4.6 already establishes elsewhere.

## Cons (accepted, with mitigations)

- **A restart is not instantaneous** — it depends on the responder next reconnecting to the rendezvous
  if it isn't already connected when the offer is sent, rather than an always-on channel guaranteeing
  immediate delivery. Mitigation: this is the same trade-off T07 already accepted for offline
  messaging generally; a session actively exchanging data (the only time a restart matters) means both
  sides are, in practice, already connected or about to reconnect for other reasons far more often than
  not — this is not a regression against "always broken," which is today's actual behavior.
- **Glare handling adds a small amount of session-layer state/logic** (the wait-briefly-then-decide
  window) that a naive single-initiator design wouldn't need. Mitigation: this collapses to *less*
  total API surface than two separate initiate/listen methods would need, and reuses tie-break logic
  the session already has.
- **`P2pSession::ice_restart`'s signature changes** (gains `relay`/`store`/`handle`/`chat` parameters)
  — a breaking change to a public `meridian-core` method. Mitigation: no real caller depends on
  today's broken no-op behavior; `docs/api/core-api-contracts.md` is updated in the same task that
  ships this.
- **No conformance-vector suite exists for `SignalContent` today** (unlike the envelope itself) — this
  ADR does not invent one to cover the two new variants, matching the existing scope of what is and
  isn't vectored; noted rather than silently expanded.

## Consequences

- `apps/envelope/src/signal.rs`'s `SignalContent` gains `IceRestartOffer`/`IceRestartAnswer`;
  `docs/api/wire-protocol.md` §3's Content union documents them alongside `sdp_offer`/`sdp_answer`.
- `apps/transport/src/webrtc_backend.rs`'s "ICE restart does not (yet) fulfill the resumability
  promise (known gap)" module-doc section is retired/rewritten once the real primitive is wired in.
- `apps/core/src/session.rs` gains the symmetric `ice_restart` signaling logic, the layered fingerprint
  check, and `SessionError::RestartFingerprintDrift`; `docs/api/core-api-contracts.md`'s
  `P2pSession::ice_restart` entry reflects the new signature.
- `docs/tasks/README.md`'s "Live carry-forwards" entry for this gap is closed out once the
  implementation tasks land and task 10.17's exit-gate demo is re-run clean; the separate
  automatic-detection carry-forward (`Transport::recv()` has no bounded timeout) remains open,
  unaffected by this ADR.
