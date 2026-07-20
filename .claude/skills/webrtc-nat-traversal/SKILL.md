---
name: webrtc-nat-traversal
description: Use when working on transport, sessions, ICE/STUN/TURN, DTLS-SRTP, connectivity, or the relay policy. Covers the fingerprint-binding invariant, relay-only semantics, the data/media split, and how to debug connectivity.
---
# WebRTC & NAT Traversal — enforcement skill

**Read first:** [ADR 0006 (transport)](../../../docs/adr/0006-terminal-transport.md),
[ADR 0014 (media stack)](../../../docs/adr/0014-media-stack.md),
[system design §5](../../../docs/architecture/system-design.md), and the
[session state machine](../../../docs/architecture/diagrams/session-state-machine.mermaid).

## The stack (decided)
- **Data channels / ICE / SCTP / DTLS / SRTP:** `webrtc-rs` (pure Rust) on **all** targets — chat,
  files, location, tunnels, and the CLI.
- **Real-time media (audio 3A, codecs, capture):** `libwebrtc` via `meridian-media-sys` on desktop and
  mobile only ([ADR 0014](../../../docs/adr/0014-media-stack.md)).
- Both sit behind the `Transport` trait ([core-api-contracts](../../../docs/api/core-api-contracts.md)) —
  consumers never branch on which is in use.

## Invariants (violations are defects)
1. **Fingerprint binding.** The DTLS fingerprint is carried inside the ratchet-encrypted SDP envelope
   and cross-checked after the handshake; mismatch ⇒ teardown. Never trust the signaling path for media
   auth (design §4.6).
2. **SDP/ICE never travel in cleartext to the server.** They ride inside signed, encrypted envelopes;
   the rendezvous routes opaque blobs and must never see or edit SDP.
3. **`relay-only` strips host/srflx candidates before gathering** — not merely deselects them — so peers
   never learn each other's IPs. `direct | prefer-relay | relay-only` is a per-user/contact/org knob
   (design §5.4). Respect it; surface the latency-vs-privacy trade, don't decide it for the operator.
4. **TURN creds are ephemeral per-session HMAC tokens** minted by the rendezvous. No static TURN
   secrets in clients.
5. **ICE restart on network change** keeps the session and ratchet state alive; don't tear down and
   re-handshake on a Wi-Fi→LTE switch.

## Debugging connectivity (see the connectivity-debugger agent)
Candidate ladder: host → server-reflexive (STUN) → relay (TURN/UDP → TURN/TCP → TURN/TLS-443). If a
pair fails: identify which candidate classes were gathered, which pairs were tried, and where the path
is blocked. `meridian doctor` is the diagnostic surface (feature 05). Symmetric×symmetric NAT ⇒ expect
relay; UDP-blocked ⇒ expect TURN/TLS-443. Never "fix" a connectivity failure by weakening the
fingerprint check or falling back to an unencrypted path.

## Where this lives (T05 landed)
- **Ephemeral TURN minting:** `meridian-rendezvous` `turn.rs` (HMAC-SHA1 REST creds, per-mint nonce ⇒
  every grant is distinct) + the `TurnReq`/`TurnGrant` ops in `meridian-proto`; client:
  `SignalingClient::request_turn_credentials`. coturn config: `infra/coturn/turnserver.conf` — reuse
  of one captured credential within its TTL is bounded by `user-quota`, not rejected outright.
- **Policy resolution** (`direct|prefer-relay|relay-only` across org/user/contact): `meridian-core`
  `relay.rs`; the transport enforces it at gather time (`IcePolicy` in `meridian-transport`).
- **Path + why:** `SessionInfo` (path, relay server/transport, offered classes, reason) and the
  transport's `selected_path_detail`. **Diagnostic:** CLI `doctor.rs`. **Matrix:**
  `tools/netns-nat-matrix.sh` + `tools/testrig`; deterministic coverage in `harnesses/nat-matrix`.
- Adding relay to a session: build the `IceConfig` via `meridian_core::relay::ice_config` and dial
  with `dial_with_config`/`answer_with_config` — do **not** hand-roll candidate stripping.
