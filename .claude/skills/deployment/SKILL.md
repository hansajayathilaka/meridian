---
name: deployment
description: Use when deploying, self-hosting, or operating the stack — Helm/compose/coturn config, air-gapped install, monitoring, upgrade/rollback, and pre-deploy checks. Optimized for a small self-hosting team.
---
# Deployment & Operations — enforcement skill

**Sources:** [operations/deployment.md](../../../docs/operations/deployment.md) ·
[monitoring.md](../../../docs/operations/monitoring.md) ·
[runbook.md](../../../docs/operations/runbook.md) ·
[ops-kit feature spec](../../../docs/architecture/features/14-selfhosting-ops-kit.md) ·
[deployment topology](../../../docs/operations/diagrams/deployment-topology.mermaid).

## What an org deploys
Two containers plus a database: `meridian-rendezvous` (axum + SQLite default / Postgres flag) and
`coturn`, with TLS certs. Rendezvous is near-stateless → active-passive behind a VIP suffices; TURN
scales horizontally and is the only real capacity-planning component (bandwidth-bound).

## Guardrails
1. **E2EE-safe observability.** Export only the allowed metrics (connections, envelope rates, mailbox
   depth, **prekey-pool depth**, federation health, TURN bandwidth). The "never exported" set is
   blocked by a CI lint. See [monitoring.md](../../../docs/operations/monitoring.md).
2. **Air-gapped is first-class.** Internal DNS + private CA; static federation map; internal STUN/TURN
   only; no external egress (assert with a capture). Client updates via the org's signed artifact
   mirror.
3. **Secrets discipline.** No secrets in the repo; TURN uses ephemeral per-session HMAC creds.
4. **Rollback always green.** Upgrade and `ops/rollback.sh` each leave a passing smoke suite.
5. **Config surface is documented per key with its security consequence.**

## Before deploying
Run [/deploy-check](../../commands/deploy-check.md) and involve the [devops](../../agents/devops.md)
subagent. Where a concrete threshold/cadence is undefined in the docs, it is marked
`TODO: confirm` — fill in per deployment, do not guess.
