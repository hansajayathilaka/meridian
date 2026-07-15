> **Nav:** [plan index](../README.md) · [review-phase template](../review-phase-template.md) · [ADR 0014 media stack](../../../adr/0014-media-stack.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Review R2 — Rich Streams & Real-Time Media (closes Milestone M2)

Closes **M2 (Features 09 File Transfer, 10 A/V Calls, 16 Tunnels)** via the
[review-phase template](../review-phase-template.md). `R2.<m>` remediation tasks are fixed here before M3.

**Status:** ☐ not started (runs when F09/F10/F16 are all built).

## Inputs
- **Milestone under review:** M2 — Features 09, 10, 16.
- **New/changed surfaces:** three stream types (`mrd.file/1`, the media types, `mrd.tunnel.tcp/1` +
  `mrd.fs/1`); the `stream-types-v1.md`/`calls-v1.md`/`tunnel-security.md` docs; the media-stack decision
  (ADR 0014 update); SCTP soak/throughput reports.
- **Most-sensitive change:** **the stream-type extension contract under real load + the tunnel policy
  model.** Deepest pass: (a) the additive-only invariant actually held (zero `apps/core` session edits
  across all three features); (b) media identity binding (DTLS-SRTP fingerprint cross-check) fails closed
  before media flows; (c) the tunnel allowlist is un-bypassable (default-deny, every header/port/DNS trick
  rejected); (d) TURN/relay sees only ciphertext (RTP + tunnel).

## The five areas
1. **Security review** — media fingerprint binding, tunnel allowlist bypass surface, `mrd.fs` read-only
   enforcement, per-chunk AEAD integrity, and relay-only ciphertext-only under real media.
2. **Completed-work review** — F09/F10/F16 vs acceptance sections + DoD (byte-perfect resume ≤2%, PESQ +
   failover thresholds, SSH echo overhead, bypass rejections, server-stopped reassertion).
3. **Missing tasks** — the third-party `mrd.echo/1` reference check on `stream-types-v1.md`; the ADR 0014
   media-stack decision recorded as a superseding/updating ADR; the SCTP→QUIC (ADR-6) numbers committed,
   not hidden.
4. **Gaps needing new steps** — any core-crate edit that slipped past the additive-only rule; the group-
   call E2E pre-commitment present in `calls-v1.md`.
5. **Future risks** — SCTP throughput ceiling (feeds the Phase-4 QUIC call); libwebrtc build-maintenance
   ops tax; tunnel feature's enterprise-review posture.

## Findings & remediation
Findings → `findings.md`; each actionable finding → an `R2.<m>` task here, driven with
[`/next-task`](../../../../.claude/commands/next-task.md). **M3 does not start until this gate is clear.**
