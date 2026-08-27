<!-- Created by /start-review-phase. The todo list below is filled by /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 7 — Review of Phase 6

**Kind:** review · **Status:** in progress · **Reviews phase(s):** Phase 6 (Envelope v2, tasks 6.1–6.8)

## Goal
Sweep everything built since the Phase-5 review for bugs, gaps, loopholes, and on-the-fly decisions
before the next build phase. Scope is Phase 6 — Envelope v2 (ADR 0016): the AAD/wire-shape cutover,
commit-on-successful-decrypt, SPK rotation policy + enforcement, the `eid` replay-dedup key, the
re-pointed adversarial test suite, `ratchet-v2.json`/`envelope-v2.json` conformance vectors, the C4
doc-sync, and the flag-day exit-gate demo.

## Chosen feature(s) / scope
- **Phase 6 — Envelope v2** (all 8 tasks, 6.1–6.8) — [phase-6/README.md](../phase-6/README.md).
  Diff range: `bf476c5` (Phase 5 close) `..` `ab71157` (current `main`/this branch's base) — merge
  PRs #80 (pick-phase) and #81 (all of 6.1–6.8 + exit gate). No untracked out-of-band PRs landed in
  this window: PR #75 (`Include webrtc feature in cargo build step`) is still **open**, targets a
  non-`main` branch (`claude/p2p-messaging-e2e-test-tmrf3m`), and has not merged — out of scope.
  PRs #66–73 were already swept by Phase 5's review.

## Dependency check
Phase 6 is closed (8/8 tasks `[x]`, exit gate 6.8 passed) per the master tracker. This review phase
follows it per the lifecycle (`/start-review-phase` always follows a closed build phase).

## Review sweep
Delegated in parallel, each an independent full-diff read (phase-wide diff, so single-lens agents
rather than the combined `reviewer` agent):
- **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications.
- **security-reviewer** — anonymity-model "must never" list, key/opacity/logging/metrics invariants;
  crypto-protocols discipline for the AAD/commit-on-decrypt rewrite.
- **architect** — ADR 0016 conformance, dependency-graph/stream-registry contracts, wire/API contract
  discipline (`docs/api/`).
- **test-engineer** — coverage gaps across the pyramid + adversarial harnesses for the new AEAD-only
  detector and `eid` dedup.

Findings, on-the-fly decisions, and coverage gaps: [review-report.md](./review-report.md).

## Tasks (todo)
<!-- Filled by /plan-review-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
(none yet — /plan-review-phase turns the report's findings into numbered fix-tasks)

## Exit criteria
All fix-tasks `[x]`, tree green, docs synced, findings closed per the report's verdict. Then:
`/start-review-phase`'s usual successor build phase is picked via `/pick-next-phase` once
`/plan-review-phase` has drained this phase's findings into tasks and they're done.
