> **Nav:** [plan index](../README.md) · [review-phase template](../review-phase-template.md) · [testing strategy §7](../../../testing/strategy.md) · [handoff readiness](../../../handoff-readiness.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Review R4 — GA Sign-off (closes Milestone M4 and the program)

The final review gate: a **whole-system** review plus the GA gate. Closes **M4 (Feature 14)** and the
entire program. Instantiates the [review-phase template](../review-phase-template.md) at full scope, and
adds the GA-specific exits.

**Status:** ☐ not started (runs when Feature 14 is built and R1–R3 are cleared).

## Inputs
- **Under review:** the whole stack — all 16 features, the M0 foundation, and every prior review gate's
  accepted-risk register.
- **Most-sensitive items:** (a) the **external crypto review** of the composed ratchet — the package
  assembled in M0 **T5.1** must be delivered and its findings closed (this is load-bearing per R0 future-
  risk: the hand-composed ratchet's only independent scrutiny); (b) air-gapped operability end-to-end;
  (c) supply-chain (signed releases, reproducible builds posture); (d) the ADR-6 SCTP→QUIC decision, now
  informed by the M2 F09/F16 throughput reports.

## The five areas (whole-system)
1. **Security review** — external crypto-review closure; re-confirm the "must never" list holds across
   federation, mailbox, media, tunnels, mobile push, and multi-device together (not just per-feature).
2. **Completed-work review** — every feature spec's acceptance met; the DoD green repo-wide; all harnesses
   live (no stubs), all conformance vectors byte-identical across all five targets.
3. **Missing tasks** — any deferred Phase-3/Phase-4 follow-ups explicitly registered (padding/batching,
   sealed-sender, group calls/MLS, QUIC) — recorded, not silently dropped.
4. **Gaps needing new steps** — GA blockers: air-gapped install proven per release, updater supply chain,
   CODEOWNERS on core crates, the Apache-2.0 full text (handoff-readiness §G).
5. **Future risks** — the post-GA roadmap (Phase 2 PQXDH bump, Phase 3 groups/MLS, Phase 4 QUIC/DHT
   resolver) framed with the trade-offs each carries.

## GA exits (in addition to the standard loop)
- External crypto review delivered and its findings closed (or explicitly risk-accepted with sign-off).
- `just lint && just test` green repo-wide; every M0–M3 review gate cleared; each milestone's accepted-risk
  register consolidated here.
- Air-gapped install and upgrade/rollback game-days pass on a clean machine.

## Findings & remediation
Findings → `findings.md`; each actionable finding → an `R4.<m>` task here, driven with
[`/next-task`](../../../../.claude/commands/next-task.md). GA is declared only when this gate is clear.
