# Meridian

A decentralized, end-to-end-encrypted, cross-platform communication platform. Self-hostable
signaling (rendezvous) and relay (TURN) infrastructure exists only to help peers discover and reach
each other; **no server ever sees plaintext content**. A shareable, key-derived identity lets users on
different orgs' servers communicate with no central directory.

> **Status:** initial scaffold — repository structure, documentation, and Claude Code tooling.
> Application source is intentionally limited to placeholder entry points and config stubs.

## Documentation
Everything starts at **[docs/INDEX.md](./docs/INDEX.md)**, which maps all design documents into:
- [Architecture](./docs/architecture/README.md) — system design, stack, data model, feature specs, diagrams.
- [ADRs](./docs/adr/README.md) — the binding decisions.
- [API & protocol](./docs/api/README.md) — canonical wire format and core contracts.
- [Security](./docs/security/README.md) — threat model, threat→mitigation matrix, privacy & retention.
- [Testing](./docs/testing/README.md) — verification strategy.
- [Operations](./docs/operations/README.md) — deployment, monitoring, runbook.

## Working with Claude Code
This repo is Claude-Code-ready. Read [CLAUDE.md](./CLAUDE.md) for the project memory, then use the
slash commands and subagents under [.claude/](./.claude/). Begin a feature with `/new-task <feature>`.

## Layout
```
CLAUDE.md            root memory       .claude/     commands · agents · skills · settings
docs/                all design docs   apps/        application code (scaffold stubs) + scoped memory
.github/workflows/   CI (lint·test·build)           infra/       deploy · coturn (stubs) + scoped memory
```

## Security posture (read before contributing)
Meridian provides pseudonymous key-identity, E2EE for all modalities, and **optional** relay-only
IP-hiding. It is **not** Tor-grade anonymity, and the docs are deliberately honest about what metadata
remains visible. See [docs/security/anonymity-and-retention.md](./docs/security/anonymity-and-retention.md).
