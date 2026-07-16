# CLAUDE.md — infra/ (deployment & operations)

Scoped memory for infrastructure. Inherits the root [CLAUDE.md](../CLAUDE.md). Work here is tracked like
everything else via the [task tracker](../docs/tasks/README.md) and the five workflow commands.

## Contents (scaffold)
- `deploy/` — docker-compose (small org) and Helm chart (K8s): `meridian-rendezvous` + Postgres +
  coturn + TLS. Stubs only in this scaffold.
- `coturn/` — TURN server config stub.

Reference: [operations/deployment.md](../docs/operations/deployment.md),
[monitoring.md](../docs/operations/monitoring.md), [runbook.md](../docs/operations/runbook.md),
[deployment topology](../docs/operations/diagrams/deployment-topology.mermaid), and the
[deployment skill](../.claude/skills/deployment/SKILL.md).

## Infra rules
- **E2EE-safe observability only** — export the allowed metrics; the "never exported" set is blocked by
  a CI lint ([monitoring.md](../docs/operations/monitoring.md)).
- **Air-gapped is first-class** — internal DNS + private CA, static federation map, internal STUN/TURN,
  no external egress.
- **No secrets in the repo**; TURN uses ephemeral per-session HMAC credentials.
- **Rollback stays green.** Upgrade and rollback paths each leave a passing smoke suite.
- Undefined thresholds/cadence are `TODO: confirm`, not guessed. Involve the
  [devops](../.claude/agents/devops.md) subagent and run
  [/deploy-check](../.claude/commands/deploy-check.md) before shipping.
