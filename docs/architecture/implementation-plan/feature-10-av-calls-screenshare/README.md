> **Nav:** [plan index](../README.md) · **Milestone M2** · [canonical spec: T10](../../features/10-av-calls-screenshare.md) · [ADR 0014 media stack](../../../adr/0014-media-stack.md) · [webrtc-nat-traversal skill](../../../../.claude/skills/webrtc-nat-traversal/SKILL.md)

# Feature 10 — Voice / Video / Screenshare (1:1)

**Milestone:** M2 · **Depends on:** Feature 05 + Feature 06 · **Canonical spec:**
[T10](../../features/10-av-calls-screenshare.md).

**Goal (from spec).** E2EE 1:1 calls — `mrd.call.audio/1`, `mrd.call.video/1`, `mrd.screen/1` as media
stream types (RTP transceivers), with fingerprint-in-envelope identity binding and **live relay fallback**,
demonstrated cross-org. **`[ADR]`** ADR 0014 (media stack — the libwebrtc/pure-Rust question is *decided
in this task* with a spike report) + **`[SEC]`** (media identity binding).

**Exit acceptance (spec §Acceptance).** Loopback audio intelligible at 2% loss (PESQ threshold); failover
gap <2 s audio / <4 s video; screenshare legible at 1080p; forced fingerprint mismatch tears down before
any media flows; TURN capture contains zero parseable RTP plaintext.

> **Depends on M0 Phase 3** — media reuses the real transport + relay path; do not stack on the simulated
> backend (R0 future-risk #3).

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F10.1 | Media-stack decision spike (libwebrtc vs pure-Rust) → spike report + ADR update | [ADR] | M0 P3 | ☐ |
| F10.2 | Media stream types + RTP transceivers (Opus, VP9/AV1) via SDP renegotiation | [ADR][SEC] | F10.1 | ☐ |
| F10.3 | Ring/accept/decline over signaling (session-less, §7.3) | [SEC] | F10.1 | ☐ |
| F10.4 | DTLS-SRTP + post-handshake fingerprint cross-check (media identity auth) | [ADR][SEC] | F10.2 | ☐ |
| F10.5 | Mid-call ICE restart + direct→relay path change without drop | [ADR] | F10.2 | ☐ |
| F10.6 | Screenshare transceiver (content-hint detail) + desktop/CLI capture; CLI receive = save/play | — | F10.2 | ☐ |
| F10.7 | `calls-v1.md` (incl. group-call E2E pre-commitment) + A/V loopback test on netns (relay + failover) | [ADR][SEC] | F10.4, F10.5 | ☐ |

- **F10.1 [ADR]** — resolves ADR 0014's remaining media-stack fork; timeboxed spike; libwebrtc-on-desktop is an acceptable outcome. Review: architect. DoD 5.
- **F10.2 [ADR][SEC]** — transceivers + codecs. Tests: renegotiation adds Opus/VP9. DoD 3,4.
- **F10.3 [SEC]** — call setup works session-less. Tests: ring/accept/decline. DoD 4.
- **F10.4 [ADR][SEC]** — **media gets identity authentication, not just transport encryption**; forced mismatch tears down before media. Tests: mismatch → no media flows. Review: security-reviewer + architect. DoD 2,4.
- **F10.5 [ADR]** — mid-call failover. Tests: block-direct mid-call → relay, no drop; gap thresholds. DoD 2.
- **F10.6** — screenshare + capture shims. Tests: 1080p legibility; CLI save/play. DoD 4.
- **F10.7 [ADR][SEC]** — the spec doc **restates the group-call E2E pre-commitment** (no trusted SFU later, §4.6); loopback test asserts TURN sees only SRTP ciphertext. Tests: PESQ threshold; TURN capture has zero parseable RTP. DoD 2,7.
