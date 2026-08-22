# Operations

- [Deployment & self-hosting](./deployment.md) — what an org runs, config surface, air-gapped install.
- [The `meridian-rendezvous` Docker image](./docker-image.md) — CI publish pipeline, GitHub Container Registry (ghcr.io)
  setup, and changing settings at runtime via env vars.
- [Native executables (Linux + Windows)](./release-binaries.md) — the companion binary release
  channel, built on the same trigger as the Docker image.
- [Monitoring & observability](./monitoring.md) — metrics allowed vs. forbidden under E2EE.
- [Incident, rollback & failure-mode runbook](./runbook.md).
- [Deployment topology diagram](./diagrams/deployment-topology.mermaid).

Full ops-kit feature spec: [feature 14](../architecture/features/14-selfhosting-ops-kit.md).
Used by the [devops](../../.claude/agents/devops.md) subagent, the
[/deploy-check](../../.claude/commands/deploy-check.md) command, and the
[deployment skill](../../.claude/skills/deployment/SKILL.md).
