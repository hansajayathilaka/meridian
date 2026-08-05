> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 3 — Review of Phase 2

**Kind:** review · **Status:** in progress · **Reviews phase(s):** Phase 2 (Cross-Org Federation, tasks 2.1–2.17) plus the Phase-1 follow-ups that landed in the same window (1.32, 1.33) and the untracked out-of-band work merged alongside (PRs #36–#42: figment config loading / ADR 0018, Docker Hub publish pipeline, Dokploy deploy stack + fixes, coturn config fixes, CLI `wss://` support).

## Goal
Sweep everything built since the Phase-1 review report for bugs, gaps, loopholes, dead ends,
missing pieces, and simplification opportunities, before the next build phase starts. Concretely:
the full diff `3ad5d49..9f81e1c` (merge of PR #31 — the Phase-2 pick — through the merge of
PR #46 that closed Phase 2): 148 files, ~17.8k insertions. Four parallel review lenses:

- **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications.
- **security-reviewer** — the anonymity-model "must never" list; key/opacity/logging/metrics
  invariants; the new s2s trust boundary (ADR 0017); the new deploy surface (Dokploy/coturn/edge).
- **architect** — ADR drift (0016/0017/0018 vs. code), dependency-graph contracts
  (server ⊬ core, `meridian-signaling` never in the server), stream-registry contract.
- **test-engineer** — coverage gaps across the pyramid + adversarial harness frontier
  (the uncovered-attack list accumulated in the tracker: SPK grace-window aging, stale-bundle
  replay, same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion).

Also capture **decisions made on the fly** during the window that were never ratified — in
particular the untracked PRs #36–#42 (only ADR 0018 was recorded) and any residuals noted in
tracker prose but not in a binding doc.

## Chosen feature(s) / scope
- Review of [T06 — Cross-Org Federation](../../architecture/features/06-cross-org-federation.md)
  as built in [Phase 2](../phase-2/README.md) (2.1–2.17), including ADR 0017 and
  `federation-protocol-v1.md`.
- Review of Phase-1 follow-ups 1.32 (relay attacks past the signature) and 1.33 (bounded answer
  wait), which merged in this window.
- Review of untracked operational work: `.github/workflows/docker-publish.yml`,
  `infra/deploy/dokploy.compose.yml` + env example, `apps/rendezvous/docker-entrypoint.sh`,
  figment config loading (ADR 0018), coturn config fixes, CLI `wss://` support,
  `docs/operations/`.

## Dependency check
Phase 2 is fully closed (all of 2.1–2.17 `[x]`; tree green in real CI including the netns
NAT-matrix rig, conformance vectors, and the cross-org abuse/acceptance suite). Review phases
alternate with build phases, so Phase 3 is unblocked by definition.

## Tasks (todo)
<!-- Filled by /plan-review-phase from review-report.md. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
_Pending — run `/plan-review-phase` after the [review report](./review-report.md)._

## Exit criteria
All findings from [review-report.md](./review-report.md) triaged into fix-tasks (or explicitly
waived with reasons), all fix-tasks `[x]`, unratified architectural decisions recorded via
`/adr`, tree green, docs synced.
