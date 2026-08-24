> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 5 — Review of Phase 4

**Kind:** review · **Status:** sweep done, findings triaged next via `/plan-review-phase` · **Reviews
phase(s):** Phase 4 (T08 — Verification & Contact Trust + T17 — Terminal TUI Client, tasks 4.1–4.52)
plus the untracked out-of-band work merged alongside/after it (PRs #66–#73: a clippy `result_large_err`
fix, CI job-split + fixes, the Windows/Linux release-binary pipeline (ADR 0022, superseded same-window
by ADR 0023), a Windows TUI double-input bug fix, TUI message-status-indicator UX (Sent vs. Delivered),
and a Docker-based P2P wire-level proof demo).

**Sweep result:** [review-report.md](./review-report.md) — 18 findings, **0 blocking**, 9 should-fix,
9 nits. Verdict: green to proceed; no blocker for the next build phase. The headline is that Phase 4's
own unusually heavy internal review discipline (seven T17 exit-gate attempts, six defects caught
pre-close) left nothing blocking here, but six already-named residual findings from Phase 4's README
remain unowned, and the out-of-band Sent/Delivered message-status feature (landed outside the
tracked-task pipeline) reproduces the same reconciliation-gap class T17's own closure chain spent six
waves fixing.

## Goal
Sweep everything built since the Phase-3 review report for bugs, gaps, loopholes, dead ends, missing
pieces, and simplification opportunities, before the next build phase (envelope-v2, per Phase 4's own
committed trigger) starts. Concretely: the full diff `adea446..4ac194d` (Phase 3's closing commit
through the current HEAD): 107 commits landing Phase 4 (94 files, ~45.5k insertions — T08's trust
module + `meridian-mitm-sim`, T17's entire `apps/tui` crate, seven exit-gate attempts and six
gap-closure waves), plus 19 further commits of untracked out-of-band work (19 files, ~1.3k insertions).
Four parallel review lenses:

- **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications —
  especially across the seven-exit-gate-attempt T17 closure chain (4.28→4.52), where six real defects
  were found and fixed in sequence; a phase that took that many passes to close is exactly the kind of
  history worth an independent adversarial re-read rather than trusting the chain's own sign-offs.
- **security-reviewer** — the anonymity-model "must never" list; key/opacity/logging/metrics
  invariants; T08's trust-state machine (TOFU→pinned→verified, un-softenable key-change blocking);
  the sealed-local-store invariant (ADR 0021, `at_rest::seal`) across every new `apps/tui` write path;
  the six `decrypt_seed()` call-site `spawn_blocking` fix (4.51) and its own already-named residual
  (`live_store`'s thirteen handlers, split off rather than fixed).
- **architect** — ADR drift (0020/0021/0022/0023 vs. code, including 0022's same-window supersession by
  0023 — was that self-correction done cleanly, and does 0022's file still read as history rather than
  as live guidance?), dependency-graph contracts (`apps/tui` depends on `meridian-core` only, per ADR
  0020; server ⊬ core), the T17 extension-registry contract (Definition of Done gate 9) as the first
  real consumer client other features will plug into.
- **test-engineer** — coverage gaps across the pyramid + the adversarial harness frontier; whether the
  six known, unowned residual findings below (latency, drain-window flake, partial-failure repair,
  stale keybinding doc, stale `contacts.json.trust` export) are still accurate and still unowned; the
  new Docker-based P2P wire-proof demo and message-status-indicator tests' real coverage value.

Also capture **decisions made on the fly** during the window that were never ratified via `/adr` —
Phase 4's own README names several fix-shape decisions made by architect consults recorded inline in
task files (4.40, 4.42) rather than as ADRs; confirm none of those actually needed one.

## Chosen feature(s) / scope
- Review of [T08 — Verification & Contact Trust](../../architecture/features/08-verification-trust.md)
  and [T17 — Terminal TUI Client](../../architecture/features/17-terminal-tui-client.md) as built in
  [Phase 4](../phase-4/README.md) (4.1–4.52), including ADR 0020 and ADR 0021.
- Review of untracked operational/UX work merged after Phase 4 closed: `.github/workflows/ci.yml` job
  split (PR #67, #69) + a clippy `result_large_err` fix (PR #66) in
  `apps/rendezvous/src/federation/outbound.rs`; the Windows/Linux release-binary pipeline
  (`.github/workflows/release-binaries.yml`, PR #68/#70, ADR 0022 → superseded same-window by ADR 0023
  once the pipeline was corrected to ship the `meridian` CLI/TUI executable rather than the server);
  a Windows TUI double-character-input fix (PR #71, `apps/tui/src/lib.rs`); TUI message-status
  indicators — Sent split from Delivered (PR #72, `apps/tui/src/screens/chat.rs` +
  `apps/tui/tests/screens_chat.rs`); and `demo/p2p-wire-proof/` — a Docker-based wire-level proof of the
  core P2P claim (PR #73).

## Dependency check
Phase 4 is fully closed (all of 4.1–4.52 `[x]`; T08's `harnesses/mitm-sim/run.sh` and T17's full
acceptance demo both confirmed passing live, the latter on its seventh exit-gate attempt per 4.52).
Review phases alternate with build phases, so Phase 5 is unblocked by definition.

## Tasks (todo)
<!-- Filled by /plan-review-phase from review-report.md. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
Not yet broken down — `/plan-review-phase` turns [review-report.md](./review-report.md)'s F1–F9
should-fix findings (F10, N1–N8 optional) into numbered fix-tasks next.

## Exit criteria
All findings from the [review report](./review-report.md) triaged into fix-tasks (or explicitly waived
with reasons), all fix-tasks `[x]`, unratified architectural decisions recorded via `/adr`, tree green,
docs synced.
