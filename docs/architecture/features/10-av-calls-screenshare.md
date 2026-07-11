<!-- Source: tasks/T10-av-calls-screenshare.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T10 — Voice / Video / Screenshare (1:1)

**Priority:** P2 · **Design refs:** §4.6, §5.3, §7.3 · **Depends on:** T05, T06 · **Indicative effort:** 3–4 eng-weeks

## Goal
End-to-end-encrypted 1:1 calls: `mrd.call.audio/1`, `mrd.call.video/1`, `mrd.screen/1` as media stream types (RTP transceivers instead of data channels), with the fingerprint-in-envelope identity binding and live relay fallback — demonstrated cross-org.

## Scope
In: ring/accept/decline over the signaling path (works session-less, §7.3); SDP renegotiation adding Opus + VP9/AV1 transceivers; DTLS-SRTP with post-handshake fingerprint cross-check (inherits T04 binding — media gets identity authentication, not just transport encryption); mid-call ICE restart (network switch) and mid-call path change (direct→relay) without drop; screenshare as a video transceiver with content-hint `detail`, per-window params in OPEN; desktop/CLI capture-and-send; CLI receive = save-to-file or play audio (video *rendering* in terminal explicitly out per §6); mute/hold; call quality stats surface (RTT, loss, jitter, current path).
Out: group calls / SFU / SFrame (Phase 4 — the §4.6 pre-commitment is restated in the spec doc so nobody ships a trusted SFU later), recording.

## Deliverables
1. Media stream types + platform capture shims (desktop via libwebrtc or platform APIs per §6 — the ADR-6/§6 media-stack question is *decided in this task* with a spike report).
2. `calls-v1.md` spec incl. the group-call E2E pre-commitment.
3. Automated A/V loopback test (tone/pattern generator → assert received) on the netns rig incl. forced relay and mid-call failover cases.

## Working output (demo script)
```
$ meridian call mrd1:<bob>@org-b.test --video      # cross-org, direct path
  [call] connected | path=direct | fp verified ✔ | 24ms rtt
$ testrig block-direct                              # force failover mid-call
  [call] path=relay(turn-a↔turn-b) | 71ms rtt      ← call continues, no drop
$ meridian screenshare start --window "Grafana"     # bob sees the window
$ tcpdump at TURN: SRTP ciphertext only (assert in CI capture check)
```

## Acceptance criteria
Loopback audio intelligible (PESQ score threshold) at 2% loss; failover gap < 2 s audio, < 4 s video; screenshare legible at 1080p text; fingerprint mismatch (forced) tears down before any media flows; TURN capture contains zero parseable RTP plaintext.

## Risks / notes
This task carries the largest platform-integration risk (codec/hardware paths). Timebox the pure-Rust media spike to one week; falling back to libwebrtc bindings on desktop is an acceptable ADR-6 outcome, not a failure.
