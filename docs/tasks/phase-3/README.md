> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 3 — Review of Phase 2

**Kind:** review · **Status:** in progress · **Reviews phase(s):** Phase 2 (Cross-Org Federation, tasks 2.1–2.17) plus the Phase-1 follow-ups that landed in the same window (1.32, 1.33) and the untracked out-of-band work merged alongside (PRs #36–#42: figment config loading / ADR 0018, Docker Hub publish pipeline, Dokploy deploy stack + fixes, coturn config fixes, CLI `wss://` support).

## Goal
Sweep everything built since the Phase-1 review report for bugs, gaps, loopholes, dead ends,
missing pieces, and simplification opportunities, before the next build phase starts. Concretely:
the full diff `3ad5d49..9f81e1c` (merge of PR #31 — the Phase-2 pick — through the merge of
PR #46 that closed Phase 2): 148 files, ~17.8k insertions. Four parallel review lenses:

- **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications.
- **security-reviewer** — the anonymity-model "must never" list; key/opacity/logging/metrics
  invariants; the new s2s trust boundary (ADR 0017); the new deploy surface (Dokploy/coturn/edge).
- **architect** — ADR drift (0016/0017/0018 vs. code), dependency-graph contracts
  (server ⊬ core, `meridian-signaling` never in the server), stream-registry contract.
- **test-engineer** — coverage gaps across the pyramid + adversarial harness frontier
  (the uncovered-attack list accumulated in the tracker: SPK grace-window aging, stale-bundle
  replay, same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion).

Also capture **decisions made on the fly** during the window that were never ratified — in
particular the untracked PRs #36–#42 (only ADR 0018 was recorded) and any residuals noted in
tracker prose but not in a binding doc.

## Chosen feature(s) / scope
- Review of [T06 — Cross-Org Federation](../../architecture/features/06-cross-org-federation.md)
  as built in [Phase 2](../phase-2/README.md) (2.1–2.17), including ADR 0017 and
  `federation-protocol-v1.md`.
- Review of Phase-1 follow-ups 1.32 (relay attacks past the signature) and 1.33 (bounded answer
  wait), which merged in this window.
- Review of untracked operational work: `.github/workflows/docker-publish.yml`,
  `infra/deploy/dokploy.compose.yml` + env example, `apps/rendezvous/docker-entrypoint.sh`,
  figment config loading (ADR 0018), coturn config fixes, CLI `wss://` support,
  `docs/operations/`.

## Dependency check
Phase 2 is fully closed (all of 2.1–2.17 `[x]`; tree green in real CI including the netns
NAT-matrix rig, conformance vectors, and the cross-org abuse/acceptance suite). Review phases
alternate with build phases, so Phase 3 is unblocked by definition.

## Tasks (todo)
<!-- Filled by /plan-review-phase from review-report.md. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
22 fix-tasks covering all 25 findings. Every F#/N# is accounted for — see the coverage note below.

**Wave 1 — the blocking gate** (must land before the next build phase; 3.2 before 3.3 to serialise
the two `link.rs` edits and let 3.3 reuse 3.2's `with_deadline` helper)
- [x] **3.1** Enforce federation policy on the outbound dial path (F1, blocking) — [file](./3.1-outbound-federation-policy.md)
- [x] **3.2** Un-wedge the inbound s2s listener: concurrent, time-bounded accept (F2+N5, blocking) — [file](./3.2-inbound-accept-loop-hardening.md)
- [x] **3.3** Bound every outbound s2s I/O exchange (F3, blocking) — [file](./3.3-outbound-s2s-timeouts.md)

**Wave 2 — test harness** (deliberately after the gate so the blockers aren't held hostage to an
11-file refactor; deliberately before everything else so no 12th `make_ca` copy appears)
- [x] **3.4** Extract the shared s2s test harness (PKI + server boot) (F18) — [file](./3.4-federation-test-support-harness.md)

**Wave 3 — federation server** (dependency-ordered: they edit the same two functions)
- [x] **3.5** Stop the reachability pre-check double-spending route budgets (F4) — [file](./3.5-fed-ratelimit-double-spend.md)
- [x] **3.6** Accept-side peer identity must consider all authenticated SANs (F9) — [file](./3.6-multi-san-peer-identity.md)
- [x] **3.7** Reuse TLS config + one link per federated message, SRV failover (F10+N2) — [file](./3.7-federation-link-reuse.md)
- [x] **3.8** Count federated deliveries in `envelopes_routed_total` (F8+N4) — [file](./3.8-fed-delivery-metrics.md)
- [ ] **3.9** Resolve the dead per-partner `policy` field in `federation_map.toml` (F7) — [file](./3.9-federation-map-policy-field.md)

**Wave 4 — parallel track** (core client + CI; no federation-server contention, can run alongside wave 3)
- [x] **3.10** Bound `pending_requests` against a stranger flood (F5) — [file](./3.10-message-request-flood-bound.md)
- [x] **3.11** Thread first-contact state into `decide_open` (ctrl-frame gate) (F11) — [file](./3.11-first-contact-ctrl-gate.md)
- [x] **3.12** Build the rendezvous image pre-merge + schedule the `--ignored` runner (F12) — [file](./3.12-ci-docker-build-gate.md)
- [x] **3.13** Test the `wss://` crypto-provider install (F13) — [file](./3.13-wss-crypto-provider-test.md)
- [ ] **3.14** Conformance vectors for the c2s hint extension (F20) — [file](./3.14-c2s-hint-conformance-vectors.md)

**Wave 5 — docs, ops, ratification**
- [ ] **3.15** Doc-sync the federation wire/deploy facts (F14+F15) — [file](./3.15-federation-protocol-doc-sync.md)
- [ ] **3.16** Warn on private-CA trust anchors under SRV discovery (F6) — [file](./3.16-private-ca-srv-hazard.md)
- [ ] **3.17** Give the production stack a federation surface with a C7 guard-rail (F17) — [file](./3.17-dokploy-federation-surface.md)
- [ ] **3.18** Fix the live coturn `realm` placeholder (F19) — [file](./3.18-coturn-realm-placeholder.md)
- [ ] **3.19** ADR 0019 — container image distribution + signing (F16 remainder) — [file](./3.19-adr-image-distribution-signing.md)

**Wave 6 — last** (depend on everything settling)
- [ ] **3.20** Resolve the `ROUTE_REPLY_GRACE` false-positive-success residual (may yield ADR 0020) — [file](./3.20-route-reply-grace-residual.md)
- [ ] **3.21** Nit sweep (N1, N3) — [file](./3.21-phase-3-nit-sweep.md)
- [ ] **3.22** s2s framing adversarial suite (**optional — first to cut**) — [file](./3.22-s2s-framing-adversarial.md)

### Findings with no task, and why
- **"Fine as-is" ratification list** (zero s2s replay dedup, per-request reachability, the two-orgs
  tombstone, `OFFER_TIMEOUT`/`ANSWER_TIMEOUT` 30 s, ICE 3s+9s, srv+private-CA config rejection, the
  300/600/30 defaults) — the report records each as already anchored in a binding doc. **One
  carry-forward obligation:** "zero s2s replay dedup → envelope-v2 `eid`" must appear in the
  envelope-v2 task's obligations when Feature 08/09 is planned.
- **`demo/two-orgs/run-walkthrough.sh` has no CI smoke** — docker-only and human-run; the report
  judges this acceptable. Revisit if it rots.
- **`relay_rewrite.rs`'s ~4–5 s slack over its 30 s `ANSWER_TIMEOUT`** — no defect today. If it ever
  flakes, widen `SIDE_TIMEOUT`, **never** `ANSWER_TIMEOUT`.
- **Phase-1 carried adversarial frontier** (SPK grace-window aging, stale-bundle replay,
  same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion) — pre-existing
  Phase-1 carry-forward, not a Phase-2 regression; covering it here would roughly double the phase.
  Carried forward, not dropped.

## ADR obligations
- **3.19 → ADR 0019** (required): ghcr.io as the distribution channel + the signing decision.
- **3.20 → ADR 0020** (conditional): only if the RTT measurement leads to reopening the
  "no `FedRouteOk`" wire decision; a tightened-and-documented constant needs doc-sync only.
- **3.9 and 3.16** need an **architect decision** but neither warrants a new ADR — 3.16 may instead
  need an amending note on [ADR 0017](../../adr/0017-federation-trust-boundary.md).

## Exit criteria
All findings from the [review report](./review-report.md) triaged into fix-tasks (or explicitly
waived with reasons), all fix-tasks `[x]`, unratified architectural decisions recorded via
`/adr`, tree green, docs synced.
