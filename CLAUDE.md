# CLAUDE.md — Meridian

Root memory for Claude Code. Keep this short; link into `docs/` and `.claude/` rather than duplicating.

## What this is
Meridian is a decentralized, end-to-end-encrypted, cross-platform communication platform.
Infrastructure exists only to help peers **rendezvous** and to **relay** media when direct P2P fails;
no server ever sees plaintext content. Federated identity lets a user on one org's server reach a user
on another's. Full narrative: [docs/architecture/system-design.md](./docs/architecture/system-design.md).

**Design docs are the source of truth.** Do not invent architecture that contradicts them. Start at
[docs/INDEX.md](./docs/INDEX.md). Definition of Done + workflow: [CONTRIBUTING.md](./CONTRIBUTING.md).
Resolved decisions & readiness: [docs/handoff-readiness.md](./docs/handoff-readiness.md). Terms:
[docs/glossary.md](./docs/glossary.md).

## Stack (authoritative: [docs/architecture/stack.md](./docs/architecture/stack.md))
- **Shared core:** Rust (`meridian-core` + sub-crates) → native + WASM. One core, five targets.
- **Crypto:** X3DH + Double Ratchet via **vodozemac** ([ADR 0011](./docs/adr/0011-ratchet-library.md)); OpenMLS for groups (later); never bespoke.
- **P2P:** webrtc-rs (data/ICE/SCTP) + libwebrtc (media) behind a `Transport` trait ([ADR 0014](./docs/adr/0014-media-stack.md)).
- **Clients:** terminal (ratatui), browser (SvelteKit + WASM), desktop (Tauri v2), mobile (SwiftUI/Compose over UniFFI).
- **Server:** `meridian-rendezvous` (axum + tokio + sqlx), depends only on `meridian-proto`; relay = coturn.
- **Monorepo:** Cargo workspace + pnpm + Gradle/SPM, glued by `just` + `xtask` ([ADR 0009](./docs/adr/0009-monorepo-tooling.md)).

Scoped memory: [apps/CLAUDE.md](./apps/CLAUDE.md) · [infra/CLAUDE.md](./infra/CLAUDE.md).

## Dev environment
Use the dev container ([.devcontainer/README.md](./.devcontainer/README.md)) — Reopen in Container and
everything (Rust, wasm target, Node/pnpm, Tauri deps, chromium+mermaid, Docker-in-Docker) is set up and
lint-verified.

## Commands (mirror CI; see [.github/workflows/ci.yml](./.github/workflows/ci.yml))
```
just setup        # install toolchains
just build        # cargo workspace + pnpm + codegen
just test         # nextest + adversarial harnesses + conformance vectors
cargo nextest run -p <crate>    # narrowest test loop
just two-orgs     # local two-org federation demo stack
```
(Placeholder `Justfile` recipes ship as stubs in this scaffold.)

## Conventions
- **Security invariants are non-negotiable.** Before touching identity, keys, signaling, storage,
  logging, or metrics, read [docs/security/threat-model.md](./docs/security/threat-model.md) and the
  "must never" list in [docs/security/anonymity-and-retention.md](./docs/security/anonymity-and-retention.md).
- **"Anonymity" is scoped:** pseudonymity + E2EE + optional relay-only IP-hiding — **not** Tor-grade.
  Never overclaim in code, copy, or docs.
- **Wire/API contracts are canonical** ([docs/api/](./docs/api/README.md)); diagrams yield to them.
  Wire changes are versioned and must pass conformance vectors.
- **ADRs are binding** ([docs/adr/](./docs/adr/README.md)). Don't diverge silently — supersede with a
  new ADR and involve the `architect` subagent.
- **Additive stream types touch the registry only**, never core crates.
- **Server never depends on `meridian-core`** (only `meridian-proto`); dependency graph stays acyclic.
- If a needed detail is absent from the design, insert `TODO: confirm` — do not invent.
- Rust: `cargo fmt` (enforced by a PostToolUse hook) + `cargo clippy` clean before done.

## Claude Code tooling ([.claude/](./.claude/))
- **Workflow commands** (drive delivery): [/pick-next-phase](./.claude/commands/pick-next-phase.md) ·
  [/plan-phase](./.claude/commands/plan-phase.md) · [/next-task](./.claude/commands/next-task.md) ·
  [/start-review-phase](./.claude/commands/start-review-phase.md) ·
  [/plan-review-phase](./.claude/commands/plan-review-phase.md)
- **Other commands:** [/review](./.claude/commands/review.md) · [/test](./.claude/commands/test.md) ·
  [/deploy-check](./.claude/commands/deploy-check.md) · [/doc-sync](./.claude/commands/doc-sync.md) ·
  [/adr](./.claude/commands/adr.md) · [/spike](./.claude/commands/spike.md) ·
  [/new-task](./.claude/commands/new-task.md) (manual escape hatch)
- **Subagents:** [task-picker](./.claude/agents/task-picker.md) · [planner](./.claude/agents/planner.md) ·
  [rust-dev](./.claude/agents/rust-dev.md) · [web-dev](./.claude/agents/web-dev.md) ·
  [code-reviewer](./.claude/agents/code-reviewer.md) · [architect](./.claude/agents/architect.md) ·
  [security-reviewer](./.claude/agents/security-reviewer.md) ·
  [test-engineer](./.claude/agents/test-engineer.md) · [devops](./.claude/agents/devops.md) ·
  [connectivity-debugger](./.claude/agents/connectivity-debugger.md)
- **Skills:** [task-tracking](./.claude/skills/task-tracking/SKILL.md) ·
  [anonymity-model](./.claude/skills/anonymity-model/SKILL.md) ·
  [api-contracts](./.claude/skills/api-contracts/SKILL.md) ·
  [deployment](./.claude/skills/deployment/SKILL.md) ·
  [crypto-protocols](./.claude/skills/crypto-protocols/SKILL.md) ·
  [webrtc-nat-traversal](./.claude/skills/webrtc-nat-traversal/SKILL.md) ·
  [stream-type-authoring](./.claude/skills/stream-type-authoring/SKILL.md)

## How work flows (task tracking)
All delivery is driven from the [task tracker](./docs/tasks/README.md) — one scannable activity list of
numbered phases (`P`) and tasks (`P.N`), each task linking to its own file (goal, scope, deliverables,
risks, tests, reviews, status). You drive it with **five commands**, and each session reads only the
tracker plus the one task file it needs — not the whole doc tree.

```
Build phase:   /pick-next-phase → /plan-phase → /next-task ×N
Review phase:  /start-review-phase → /plan-review-phase → /next-task ×N
```

Build and review phases alternate: after each build phase, a review phase sweeps it for bugs, gaps,
loopholes, and on-the-fly decisions before the next build starts. Phase 0 (foundation, T01–T05) is done;
the "issues to fix" work is Phase 1. Contract + numbering + the **Definition of Task** live in the
[task-tracking skill](./.claude/skills/task-tracking/SKILL.md). `/new-task` remains only as a manual
per-feature escape hatch.
