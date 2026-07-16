# Contributing to Meridian

This repo is built to be worked on by Claude Code sessions and humans alike. The design documents in
[docs/](./docs/INDEX.md) are the source of truth; code serves them, not the other way around.

## Start here
- Read the root [CLAUDE.md](./CLAUDE.md) and the [docs index](./docs/INDEX.md).
- All work is tracked in the [task tracker](./docs/tasks/README.md) — numbered phases (`P`) and tasks
  (`P.N`), each task a file with goal/scope/deliverables/risks/tests/reviews/status.
- Features ship in priority order: [roadmap](./docs/architecture/roadmap.md). The critical path is
  features 01→04.

## Workflow — five commands
Drive delivery one command at a time (contract in the
[task-tracking skill](./.claude/skills/task-tracking/SKILL.md)); each reads only the tracker + the one
file it needs:

```
Build phase:   /pick-next-phase → /plan-phase → /next-task ×N
Review phase:  /start-review-phase → /plan-review-phase → /next-task ×N
```

Build and review phases **alternate** — after each build phase a review phase sweeps it for bugs, gaps,
loopholes, and on-the-fly decisions before the next build starts. [/new-task](./.claude/commands/new-task.md)
remains only as a manual per-feature escape hatch.

## Definition of Task (the unit `/plan-phase` produces)
A **task** is the smallest mergeable unit. It must:
1. **Be one focused change** — a single concern, ideally one crate/module.
2. **Be independently testable** — ships with its own test(s) passing in isolation.
3. **Have explicit deliverables** — named files/functions/tests in the task file.
4. **Have acceptance criteria** — a concrete pass/fail tied to the Definition of Done below.
5. **Fit one session / one PR** and leave the tree green.
6. **Declare dependencies** and **sync docs** if behaviour/wire/diagram changed.

Anything larger is split into multiple tasks at plan time.

## Definition of Done (every change must satisfy)
A change is **not done** until all of the following hold:

1. **Builds & lints clean.** `just build` and `just lint` (fmt + clippy) pass. Rust is auto-formatted by
   the PostToolUse hook; clippy is clean (no warnings).
2. **Tests for the right layer pass.** Run [/test](./.claude/commands/test.md). Security tests
   (opacity audit, `mitm-sim`, ghost-device, FS/PCS, fingerprint-mismatch) are never weakened to go
   green — a failure there is a real defect. See [testing/strategy.md](./docs/testing/strategy.md).
3. **Wire/API changes are versioned & vector-checked.** If bytes on the wire changed, the version bumped
   and **conformance vectors regenerated** (byte-identical across CLI/WASM/mobile). See the
   [api-contracts skill](./.claude/skills/api-contracts/SKILL.md).
4. **Security invariants intact.** For anything touching identity, keys, signaling, storage, logging, or
   metrics, run [/review](./.claude/commands/review.md) and satisfy the
   [anonymity-model skill](./.claude/skills/anonymity-model/SKILL.md) "must never" list. The two CI
   enforcement lints (no-serde-on-blob, metrics-allowlist) must pass.
5. **No architectural drift.** The change does not contradict an [ADR](./docs/adr/README.md). A changed
   decision is recorded via [/adr](./.claude/commands/adr.md) (supersede, don't silently edit).
6. **Additive stream types touch the registry only** — zero core-crate edits
   ([stream-type-authoring skill](./.claude/skills/stream-type-authoring/SKILL.md)).
7. **Docs synced.** Behavior, diagram, or decision changes are reflected via
   [/doc-sync](./.claude/commands/doc-sync.md). All relative links resolve.
8. **No invented design.** If a detail is absent from the docs, insert `TODO: confirm` and flag it —
   never guess architecture.

## Guardrails baked into the repo
- `.claude/settings.json` denies `git push` and `rm -rf`; auto-formats Rust on edit.
- `meridian-rendezvous` must not depend on `meridian-core` (only `meridian-proto`) — enforced by
  `just lint-invariants`.
- CODEOWNERS-style protection of core crates is expected once the org is set up
  (`<!-- TODO: confirm CODEOWNERS once GitHub org/teams exist -->`).

## Subagents to delegate to
[task-picker](./.claude/agents/task-picker.md) (what's next) ·
[planner](./.claude/agents/planner.md) (task breakdown) ·
[rust-dev](./.claude/agents/rust-dev.md) / [web-dev](./.claude/agents/web-dev.md) (implementation) ·
[code-reviewer](./.claude/agents/code-reviewer.md) (correctness/gaps in review phases) ·
[architect](./.claude/agents/architect.md) (design conformance) ·
[security-reviewer](./.claude/agents/security-reviewer.md) (privacy/crypto) ·
[test-engineer](./.claude/agents/test-engineer.md) ·
[devops](./.claude/agents/devops.md) ·
[connectivity-debugger](./.claude/agents/connectivity-debugger.md) (WebRTC/NAT).
