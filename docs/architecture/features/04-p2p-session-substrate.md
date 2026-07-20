<!-- Source: tasks/T04-p2p-session-substrate.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T04 — P2P Session Substrate (WebRTC Data Channels)

**Priority:** P0 — the transport backbone · **Design refs:** §5.1–5.3, §7.1 steps 6–14, ADR-6 · **Depends on:** T03 · **Indicative effort:** 3–4 eng-weeks

## Goal
Move the T03 chat off the server relay and onto a direct WebRTC peer connection: SDP/ICE exchanged inside ratchet-encrypted envelopes, DTLS fingerprint bound to identity, ctrl channel + stream-type registry established. After this task the servers are *out of the data path*, demonstrably.

## Scope
In: `Transport` trait + first impl (webrtc-rs; libdatachannel spike as fallback per ADR-6); session dial/answer state machine (lazy dial, trickle ICE via T02 envelope routing); **fingerprint binding:** DTLS fingerprint carried inside the encrypted offer/answer, cross-checked post-handshake, mismatch ⇒ teardown (§4.6); channel 0 `mrd.ctrl/1` — capability advertisement, stream OPEN/ACCEPT/REJECT/CLOSE, keepalive; stream-type registry API (`register_stream_type(name, ver, channel_cfg, policy_hook)`); `mrd.chat/1` re-homed onto a reliable-ordered data channel; ICE restart on network change; host+srflx candidates with public STUN (TURN is T05).
Out: TURN/relay policy (T05), media (T10), any second stream type (T09 proves extensibility).

## Deliverables
1. `meridian-core` session/transport modules + stream registry with doc `stream-types-v1.md` (the extension contract that T09/T10/T15/T16 implement against — review it as if third parties will code to it, because eventually they will).
2. Fingerprint-mismatch integration test (malicious-server harness rewrites the *outer* envelope routing — proving it can't touch the inner SDP; plus a forced-mismatch unit test at the DTLS layer).
3. Network-namespace test rig (`netns` script) simulating two LANs behind distinct NATs.

## Working output (demo script)
```
$ meridian chat mrd1:<bob>@localhost          # both peers on LAN, server running
  [session] ICE: direct (host) — P2P established, DTLS fp verified ✔
$ docker stop meridian-rendezvous             # kill the server mid-conversation
  — chat continues uninterrupted —            # ← the headline demo
$ meridian session info
  transport=loopback path=direct rtt=1.8ms streams=[mrd.ctrl/1, mrd.chat/1]
```

## Acceptance criteria
Server-down chat continuity ≥30 min with keepalives; Wi-Fi→other-interface switch recovers via ICE restart <5 s; capability exchange rejects unknown mandatory stream types gracefully; fingerprint mismatch tears down 100% of the time in the forced test; zero SDP bytes visible to the opacity-audit harness (extends T03's audit).

## Risks / notes
webrtc-rs SCTP behavior under loss needs early soak testing — if throughput or stability disappoints, the ADR-6 fallback (libdatachannel FFI) must be exercised *within this task*, not discovered during T09's 1 GiB transfers.

**Verification status (recorded honestly, F9 — updated as of 1.15):** a real webrtc-rs `Transport`
backend (`WebRtcTransport`, real ICE/SCTP/DTLS) now exists behind the `webrtc` feature
([1.15](../../tasks/phase-1/1.15-webrtc-backend.md)), gated into CI (`cargo test -p meridian-transport
-p meridian-core --features webrtc`, opt-in so default builds stay pure-Rust/network-free). Server-down
chat continuity, capability exchange rejecting unknown mandatory types, and DTLS-fingerprint binding
(a peer whose SDP-declared fingerprint doesn't match its real certificate can never complete the
handshake at all — `apps/transport/tests/webrtc_backend.rs::tampered_remote_fingerprint_never_connects`)
are now proven against the real backend, not only the `netns` simulation rig / `LoopbackTransport` test
double. **Still simulation-only / deferred:** the ICE-restart acceptance line below ("Wi-Fi→other-interface
switch recovers via ICE restart <5 s") — 1.15 found that webrtc-rs's real ICE-agent restart breaks an
already-connected peer connection with no peer-side signaling to recover it, so `ice_restart()` is
currently a documented no-op on the wire; this criterion is **not met against a real network change**
and needs a session-layer renegotiation path before it can be (flagged for architect review, tracked as
a 1.15/1.16 successor). The netns/tcpdump wire-level NAT matrix and observed-candidate relay-only
classification are 1.16's job.
