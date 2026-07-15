> **Nav:** [plan index](../README.md) · **Milestone M4** · [canonical spec: T14](../../features/14-selfhosting-ops-kit.md) · [ADR 0008 infra topology](../../../adr/0008-infra-topology.md) · [deployment skill](../../../../.claude/skills/deployment/SKILL.md)

# Feature 14 — Self-Hosting & Operations Kit

**Milestone:** M4 · **Depends on:** Feature 06, Feature 07 (may start absorbing 06/07/08 hardening earlier)
· **Canonical spec:** [T14](../../features/14-selfhosting-ops-kit.md).

**Goal (from spec).** An org of 2–5 engineers can deploy, observe, upgrade, and **air-gap** the full stack
from documentation alone — proven by a scripted offline install with zero uplink egress. **`[SEC]`** for
the metadata-minimizing defaults and the metrics allowlist; **`[ADR]`** ADR 0008.

**Exit acceptance (spec §Acceptance).** Air-gapped install completes with **zero packets on the uplink
capture**; every §9.2 config key documented with its security consequence; dashboard shows all §9.4
exported metrics and **none of the "never exported" list** (CI metrics-endpoint lint — the real one from
M0 T1.1); a new engineer runs the upgrade runbook unassisted in a game-day.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F14.1 | Reference deploys: `docker-compose` (small org) + Helm chart (rendezvous+Postgres+coturn+TLS) | [ADR] | M1 | ☐ |
| F14.2 | Full §9.2 config surface implemented + documented with each key's security consequence | [SEC] | F14.1 | ☐ |
| F14.3 | Prometheus metrics (§9.4, incl. prekey-pool-depth alert) + Grafana dashboard; metrics-allowlist enforced | [SEC] | F14.1, M0 T1.1 | ☐ |
| F14.4 | Metadata-minimizing logging defaults (salted-hash keys, short retention) via M0 `LogId` | [SEC] | M0 T1.10 | ☐ |
| F14.5 | `meridian doctor --server` (fed link health, cert expiry, TURN reachability) | — | F14.1 | ☐ |
| F14.6 | Backup/restore + upgrade + rollback runbooks (game-day validated) | — | F14.1 | ☐ |
| F14.7 | Air-gapped install path: offline bundle, private-CA, static map, internal-STUN policy | [SEC] | F14.1 | ☐ |
| F14.8 | Anti-abuse hardening carried from 06/08: contact-token enforcement + first-contact PoW option | [SEC] | F06, F08 | ☐ |
| F14.9 | Load report: 5k clients / 50 msg/s federation on the 2-vCPU box (§9.1, measured) | — | F14.1 | ☐ |

- **F14.1 [ADR]** — compose + Helm reference deploys. Review: architect + devops. Tests: both bring a working stack up (smoke green). DoD 7.
- **F14.2 [SEC]** — every §9.2 key documented with its **security consequence**, org-overrides documented not hidden. DoD 4,7.
- **F14.3 [SEC]** — dashboards + alert rules; the metrics-endpoint lint (M0 **T1.1**, now non-vacuous) proves none of the "never exported" list ships. Tests: dashboard shows exported set; lint blocks a rogue metric. DoD 4.
- **F14.4 [SEC]** — wire the M0 `LogId` (T1.10) as the default; salted-hash account keys, short retention. DoD 4.
- **F14.5** — server doctor. Tests: reports fed/cert/TURN health. DoD 7.
- **F14.6** — runbooks; wire the demo into CI so ops docs don't rot (compose weekly, air-gap per release). DoD 7.
- **F14.7 [SEC]** — the headline: offline bundle install with **tcpdump-verified zero uplink egress**. Tests: air-gapped install, silent uplink. DoD 7.
- **F14.8 [SEC]** — the §3.5 anti-abuse follow-ups deferred from 06/08 land here. Review: security-reviewer. Tests: contact-token + PoW enforcement at the edge. DoD 4.
- **F14.9** — the §9.1 capacity claim, now measured (complements M0 T4.2). DoD 2.
