---
description: Pre-deploy verification checklist.
---
Run the pre-deploy verification for: **$ARGUMENTS** (default: full stack).

Ground in [operations/deployment.md](../../docs/operations/deployment.md), [monitoring.md](../../docs/operations/monitoring.md), [runbook.md](../../docs/operations/runbook.md), and the [ops-kit feature spec](../../docs/architecture/features/14-selfhosting-ops-kit.md). Delegate to the `devops` subagent.

Checklist:
1. **Build & tests green** — workspace build, `/test`, and the adversarial + conformance suites.
2. **Migrations** — reviewed, reversible, and match the [data model](../../docs/architecture/data-model.md).
3. **Config surface** — every key documented with its security consequence; secrets not committed.
4. **Observability lint** — metrics endpoint exposes only the allowed list; none of the "never exported" set ([monitoring.md](../../docs/operations/monitoring.md)).
5. **Air-gap sanity** (if applicable) — no external egress; internal STUN/TURN only; static federation map present.
6. **Rollback ready** — `ops/rollback.sh` path verified; know the rollback trigger.
7. **E2EE invariants intact** — no server-side plaintext/contact-graph path introduced ([anonymity model](../../docs/security/anonymity-and-retention.md)).

Output a go / no-go with any blocking items.
