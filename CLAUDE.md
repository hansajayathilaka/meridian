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
- **Commands:** [/new-task](./.claude/commands/new-task.md) · [/review](./.claude/commands/review.md) ·
  [/test](./.claude/commands/test.md) · [/deploy-check](./.claude/commands/deploy-check.md) ·
  [/doc-sync](./.claude/commands/doc-sync.md) · [/adr](./.claude/commands/adr.md) ·
  [/spike](./.claude/commands/spike.md)
- **Subagents:** [architect](./.claude/agents/architect.md) ·
  [security-reviewer](./.claude/agents/security-reviewer.md) ·
  [test-engineer](./.claude/agents/test-engineer.md) · [devops](./.claude/agents/devops.md) ·
  [connectivity-debugger](./.claude/agents/connectivity-debugger.md)
- **Skills:** [anonymity-model](./.claude/skills/anonymity-model/SKILL.md) ·
  [api-contracts](./.claude/skills/api-contracts/SKILL.md) ·
  [deployment](./.claude/skills/deployment/SKILL.md) ·
  [crypto-protocols](./.claude/skills/crypto-protocols/SKILL.md) ·
  [webrtc-nat-traversal](./.claude/skills/webrtc-nat-traversal/SKILL.md) ·
  [stream-type-authoring](./.claude/skills/stream-type-authoring/SKILL.md)

## Start a feature
Run `/new-task <feature>`; it reads the matching spec in
[docs/architecture/features/](./docs/architecture/features/) and the docs that spec references, then
plans → implements → tests. Feature order: [docs/architecture/roadmap.md](./docs/architecture/roadmap.md).
