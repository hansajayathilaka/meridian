<!-- Source: tasks/T14-selfhosting-ops-kit.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T14 — Self-Hosting & Operations Kit

**Priority:** P3 (but starts absorbing hardening follow-ups from T06/T07 earlier) · **Design refs:** §9, ADR-8, §10 · **Depends on:** T06, T07 · **Indicative effort:** 2–3 eng-weeks

## Goal
An org of 2–5 engineers can deploy, observe, upgrade, and air-gap the full stack from documentation alone — proven by a scripted offline install on a machine with no internet.

## Scope
In: reference deploys — `docker-compose` (small org) and Helm chart (K8s), both covering rendezvous+Postgres+coturn+TLS; the full §9.2 config surface implemented and documented; Prometheus metrics per §9.4 (incl. prekey-pool depth alert rule — the non-obvious one) + a shipped Grafana dashboard; metadata-minimizing logging defaults (salted-hash account keys, short retention) with the org-override documented, not hidden; `meridian doctor --server` (federation link health, cert expiry, TURN reachability); backup/restore runbook (what's in the DB: prekeys/device records/mailbox — and what losing it costs: reachability, never security); upgrade + rollback runbook; **air-gapped install path:** offline artifact bundle, private-CA walkthrough, static federation map, internal-STUN-only client policy push; anti-abuse hardening carried over: contact-token enforcement option + first-contact PoW stamp option at the federation edge (§3.5 follow-ups from T06/T08).
Out: managed-hosting anything, multi-region HA beyond the §8/ADR-8 active-passive note.

## Deliverables
1. `deploy/` (compose + Helm) and `ops/` (runbooks, dashboard JSON, alert rules).
2. `air-gapped-install.md` — validated by the demo below, not by review.
3. Load report: 5k concurrent clients / 50 msg/s federation on the 2-vCPU reference box (§9.1 claim, now measured).

## Working output (demo script)
```
$ ./ops/make-offline-bundle.sh → meridian-offline-1.0.tar (images, charts, docs, sigs)
— copy to a VM with networking to the internet DISABLED —
$ tar xf … && ./install.sh --air-gapped --ca ./private-ca --fed-map ./federation_map.toml
  stack up in <15 min, zero external egress (verified: tcpdump on the VM uplink is silent)
$ open grafana → connections, envelope rates, mailbox depth, prekey pool: all live
$ ./ops/drain-prekeys-drill.sh → alert fires; client first-contact falls back per §10
$ helm upgrade … && ./ops/rollback.sh   # both leave a working stack (smoke suite green)
```

## Acceptance criteria
Air-gapped install completes with zero packets on the uplink capture; every §9.2 config key is documented with its security consequence; dashboard shows all §9.4 "exported" metrics and *none* of the "never exported" list (checked by a metrics-endpoint lint in CI); a new engineer executes the upgrade runbook unassisted in a game-day.

## Risks / notes
Ops docs rot fastest — wire the demo script into CI (compose path weekly, air-gap path per release) so the kit is continuously proven, not archaeologically trusted.
