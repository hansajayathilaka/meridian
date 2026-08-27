<!-- Created by /start-review-phase. The todo list below is filled by /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 7 — Review of Phase 6

**Kind:** review · **Status:** in progress (sweep complete, fix-tasks not yet planned) · **Reviews
phase(s):** Phase 6 (Envelope v2, tasks 6.1–6.8)

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

Findings, on-the-fly decisions, and coverage gaps: [review-report.md](./review-report.md). **9
findings — 1 blocking, 6 should-fix, 2 nits.** No on-the-fly decision needs `/adr` ratification.
Verdict: blocked until F1 (an untested flag-day hard-reject path) lands, then clear for the next build
phase (T07/T14).

## Tasks (todo)
<!-- Filled by /plan-review-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
Each fix-task is independent (no build-order dependency on another in this batch); 7.1 lands first only
because it's the blocking item gating the phase verdict, not because of a technical conflict. N2 was
**not** converted to a task — the report's own verdict defers the 12-site stale-doc sweep to a future
`/plan-phase` since it spans many files outside a tight scope and none is security-critical prose;
already recorded as an unowned carry-forward in the master tracker.

- [x] **7.1** Flag-day hard-reject test coverage (F1 blocking, F2) — [file](./7.1-flag-day-hard-reject-coverage.md)
- [x] **7.2** Zeroize discarded/peeked OTK and SPK secret copies (F3, F4) — [file](./7.2-zeroize-otk-spk-secret-copies.md)
- [x] **7.3** Stale v1-signature prose in `route_tamper.rs` (F5) — [file](./7.3-route-tamper-stale-signature-prose.md)
- [x] **7.4** Property test for `eid` dedup bound + duplicate detection (F6) — [file](./7.4-eid-dedup-property-test.md)
- [ ] **7.5** Boundary-case conformance vectors for `envelope-v2.json` (F7) — [file](./7.5-envelope-v2-boundary-vectors.md)
- [ ] **7.6** Resolve the `eid`/mailbox naming collision before T07 planning (N1) — [file](./7.6-eid-mailbox-naming-collision-note.md)

## Exit criteria
All fix-tasks `[x]`, tree green, docs synced, findings closed per the report's verdict. Then:
`/pick-next-phase` for the next build phase (T07/T14, unblocked by Phase 6).
