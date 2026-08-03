<!-- Created by /pick-next-phase. The todo list below is filled by /plan-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 2 — Cross-Org Federation

**Kind:** build · **Status:** in progress · **Reviews phase(s):** n/a (build phase; Phase 3 will review it)

## Goal
Ship **Feature 06 — Cross-Org Federation**: a user registered on Org A's rendezvous establishes a
verified E2EE P2P session with a user on Org B's rendezvous, with the two servers discovering each
other via DNS SRV *or* a static federation map (air-gap mode). This is the
[§7.1 cross-org walkthrough](../../architecture/system-design.md) made runnable as one script — the
"requirement 3" proof that Meridian federates without ever letting a server see plaintext.

**Acceptance demo** (from the [feature spec](../../architecture/features/06-cross-org-federation.md)):
`cd demo/two-orgs && docker compose up` brings up two complete stacks (rendezvous + coturn ×2, private
CA, static map, no internet); Alice registers on `org-a.test`, Bob on `org-b.test`; `meridian chat
mrd1:<bob>@org-b.test` federates, verifies the bundle under the requested key, lands in Bob's
message-request queue, and goes P2P with a verified DTLS fingerprint; `grep -c plaintext /logs/*` → 0
at both servers.

## Chosen feature(s) / scope
- **T06 — Cross-Org Federation** — [spec](../../architecture/features/06-cross-org-federation.md) ·
  depends on T04 (T05 recommended) — **all done ✔** (Phase 0 tasks 0.4, 0.5)

**In scope** (feature spec §Scope): s2s protocol over mTLS in both WebPKI and private-CA modes;
federated prekey fetch + envelope forwarding honouring the routing invariant *client → own server →
foreign server → client*, **never** client → foreign server (§3.3 step 2); DNS SRV
`_meridian-fed._tcp` discovery **and** `federation_map.toml` static mode; federation policy
`open | allowlist | closed`; per-origin-server and per-account rate limits at the federation edge;
the first-contact **message-request gate** (§3.5); and a new versioned wire contract
`docs/api/federation-protocol-v1.md`.

**Out of scope** (deliberately, per the spec): contact tokens & PoW stamps (→ T08/T14), multi-hint IDs
(design Phase 3), and cross-org presence — which is per-request only *by design* (§3.4), not an
omission.

**Deliverables:** (1) federation module in `meridian-rendezvous` + `demo/two-orgs/` compose stack;
(2) `federation-protocol-v1.md`; (3) abuse tests — rate-limit enforcement, allowlist/`closed`
rejection, oversized-envelope rejection, and the cross-org **malicious-server bundle-substitution**
test (Org B's server lies → Alice's client aborts).

## Dependency check

**Why Phase 2 is unblocked now.**
Phase 0 delivered Features 01–05 (tasks 0.1–0.5, all `[x]`). Phase 1 was the review sweep of Phase 0;
its blocking gate for Phase 2 — findings **F1, F2, F3, F10, F11** — was fully satisfied by Group D
(tasks 1.13–1.16, 1.22, 1.24–1.27, 1.29, 1.30). Feature 06 declares `Depends on: T04 (T05
recommended)` ([spec](../../architecture/features/06-cross-org-federation.md)); both are complete, so
even the recommended dependency is met. The build/review cadence is respected: Phase 1 (review) sits
between Phase 0 (build) and Phase 2 (build); Phase 3 will review Phase 2.

**Why Feature 06 and not 08 or 09.** With 01–05 done the unblocked set is {06, 08, 09}
([roadmap](../../architecture/roadmap.md) dependency table).
- **06 is the critical path.** Track C is `02→06→07→14`; 06 is the sole gate on Features 07, 10 and
  14, and transitively on 11, 12 and 15. It is also P1 in priority order. Choosing 08 or 09 instead
  unblocks nothing new.
- **08 is not parallel with 06 — it consumes it.** Feature 08's scope explicitly includes
  message-request UX finalization "from T06" and cross-org directory-attestation ingest, and task
  1.18 deferred desync auto-recovery into 08 behind block-on-key-change. Running them concurrently
  would race on the same first-contact/trust surface. 08 belongs to the next build phase.
- **09 is the one genuinely parallel option** (Track B; an additive stream type that touches only the
  registry). It is deliberately **not** bundled here: 06 alone is ~3 eng-weeks — a new s2s protocol,
  a new wire contract, a two-stack docker demo and an abuse-test suite. Adding 09 would roughly double
  the surface the Phase 3 review sweep has to cover and break the "one coherent, reviewable unit"
  property of a phase.

**Open Phase-1 follow-ups — non-blocking, but they sit on the path Feature 06 extends.**
Tasks **1.32** and **1.33** remain `[ ]`. Neither is in Phase 2's blocking gate and both are
should-fix/nit class, so they do not block starting this phase — but both touch code Feature 06 builds
directly on top of, so `/plan-phase` should sequence around them:
- **[1.32](../phase-1/1.32-relay-attacks-past-signature.md)** — relay attacks that *pass* the envelope
  signature check (forged `Deliver.from`, replay, reorder, cross-delivery). Feature 06 turns the
  single-hop route into a **two-hop, cross-trust-boundary** route in which the *foreign* server asserts
  `from` to the home server. Landing 06 first means the s2s decisions about who attests `from`, replay
  windows and de-duplication get made with no adversarial harness in hand, and 1.32 then has to be
  retrofitted onto a two-hop path. It also overlaps Feature 06's own deliverable 3 (abuse tests) and
  the [ADR 0016](../../adr/0016-envelope-deniability.md) mitm-sim test obligations.
- **[1.33](../phase-1/1.33-bound-answer-wait.md)** — the dialer's unbounded `recv_sdp` wait in
  `apps/core/src/session.rs`. Federation multiplies the failure modes of that signaling path (two
  servers, mTLS, SRV resolution, policy rejection), and Feature 06's acceptance criterion *"a
  `closed`-policy org rejects inbound federation with a clean client-side error"* is exactly a case
  where the dialer must surface a diagnosable error instead of hanging.

**Recommendation:** close 1.32 and 1.33 before the first Phase 2 task that touches s2s routing or
signaling. They stay numbered under Phase 1 (they are Phase-1 findings); Phase 1 cannot be marked
fully `[x]` until they land.

**Carried-over `TODO: confirm` addressed to this phase.**
[`docs/api/rendezvous-protocol-v1.md`](../../api/rendezvous-protocol-v1.md) records that persistence
is in-memory by default and that the sqlx implementation stores a prekey bundle as a single CBOR blob
rather than a normalized schema — *"TODO: confirm normalized schema + Postgres in T06/T07."*
`/plan-phase` must either resolve this or explicitly re-defer it to T07.

## Reading list for `/plan-phase`
- **ADRs (binding):** [0002 federation mechanism](../../adr/0002-federation-mechanism.md) (the core
  one — s2s mTLS + SRV/static map, air-gap/private-CA, bilateral abuse handling) ·
  [0001 identity scheme](../../adr/0001-identity-scheme.md) ("hint is advisory") ·
  [0016 envelope deniability](../../adr/0016-envelope-deniability.md) (mitm-sim obligations the abuse
  tests must not contradict) · [0007 offline mailbox](../../adr/0007-offline-mailbox.md) (what 06 must
  *not* absorb) · [0008 infra topology](../../adr/0008-infra-topology.md) ·
  [0013 server web framework](../../adr/0013-server-web-framework.md).
- **Design / wire contracts:** [system-design.md](../../architecture/system-design.md) §3.3 (routing
  invariant), §3.4 (per-request presence), §3.5 (anti-spam / message request), §7.1 (the walkthrough
  that *is* the acceptance test) · [rendezvous-protocol-v1.md](../../api/rendezvous-protocol-v1.md) ·
  [wire-protocol.md](../../api/wire-protocol.md) ·
  [messaging-envelope-v1.md](../../api/messaging-envelope-v1.md) (forwarding must be byte-identical
  across the boundary; conformance vectors apply) ·
  [data-model.md](../../architecture/data-model.md) ·
  [seq-cross-org-setup.mermaid](../../architecture/diagrams/seq-cross-org-setup.mermaid).
- **Security:** [threat-model.md](../../security/threat-model.md) A2 (server "colludes with a malicious
  counterpart server in a federation") ·
  [threat-mitigation-matrix.md](../../security/threat-mitigation-matrix.md) (A2×2 dual-side MITM →
  T06 cross-org substitution test; federation rate limits per origin-server/account) ·
  [anonymity-and-retention.md](../../security/anonymity-and-retention.md) — the ceiling on what two
  federating orgs may learn (who-signals-whom, per request; never content, never presence
  subscriptions).
- **Skills:** [api-contracts](../../../.claude/skills/api-contracts/SKILL.md) (a new
  `federation-protocol-v1.md` is a versioned wire contract and needs conformance vectors) ·
  [anonymity-model](../../../.claude/skills/anonymity-model/SKILL.md) ·
  [deployment](../../../.claude/skills/deployment/SKILL.md) (two-stack demo) ·
  [task-tracking](../../../.claude/skills/task-tracking/SKILL.md).

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->

**Gate — Phase-1 follow-ups that must land first** (they stay numbered under Phase 1)
- [x] **1.32** Relay attacks that pass the envelope signature check — [file](../phase-1/1.32-relay-attacks-past-signature.md)
- [x] **1.33** Bound the dialer's wait for an answer in `recv_sdp` — [file](../phase-1/1.33-bound-answer-wait.md)

**Decide before any byte is shaped**
- [x] **2.1** ADR 0017 — federation trust boundary (peer auth + cross-org `from` attestation) — [file](./2.1-adr-federation-trust-boundary.md)

**Contracts**
- [x] **2.2** `federation-protocol-v1.md` + s2s wire types + conformance vectors — [file](./2.2-federation-protocol-v1.md)
- [x] **2.3** c2s extension for federation (hint fields, error codes, vectors) — [file](./2.3-c2s-federation-extension.md)

**Server spine**
- [x] **2.4** s2s mTLS link: listener + dialer (WebPKI and private-CA) — [file](./2.4-s2s-mtls-link.md)
- [x] **2.5** Discovery: DNS SRV + `federation_map.toml` static mode — [file](./2.5-federation-discovery.md)
- [x] **2.6** Federation policy (`open | allowlist | closed`) + edge rate limits — [file](./2.6-federation-policy-limits.md)
- [x] **2.7** Federated prekey fetch, both sides (§3.3 steps 2–4) — [file](./2.7-federated-prekey-fetch.md)
- [x] **2.8** Federated envelope forwarding + per-request reachability (§3.3 step 5, §3.4) — [file](./2.8-federated-route-reachability.md)

**Client**
- [x] **2.9** Client federation error taxonomy: clean `closed` error + stale-hint case — [file](./2.9-client-federation-errors.md)
- [x] **2.10** First-contact message-request gate (client-side, §3.5) — [file](./2.10-message-request-gate.md)

**Follow-up surfaced by 2.9's review** — architect required a new task rather than folding the fix
into 2.9 (would reopen an already-narrow review) or into 2.11 (wrong agent/reviewer lineup).
- [x] **2.15** Thread the peer's org hint into live signaling/chat routing (blocks 2.11, 2.12) — [file](./2.15-thread-route-hint.md)

**Demo + exit gate**
- [~] **2.11** `demo/two-orgs/`: two full stacks, private CA, both discovery modes — [file](./2.11-demo-two-orgs.md)
- [ ] **2.12** Cross-org abuse + acceptance suite (the phase exit gate) — [file](./2.12-cross-org-abuse-acceptance.md)

**Carried in from Phase 1** — not T06 work, and not on the DAG below. A production defect surfaced by
[1.32](../phase-1/1.32-relay-attacks-past-signature.md) and confirmed by its security review: it lands
here because it needs fixing, not because Feature 06 depends on it. It is independent of every task
above and can run at any point in the phase.
- [x] **2.13** A replayed envelope permanently wedges the receiving ratchet — [file](./2.13-ratchet-replay-dos.md)

**Follow-up surfaced by 2.10's review** — architect + security-reviewer both required this be
tracked explicitly rather than silently deferred to Feature 08.
- [ ] **2.14** Wire the message-request gate into the P2P session substrate (`session connect`
  currently bypasses 2.10's gate entirely) — [file](./2.14-p2p-message-request-gate.md)

### Dependency order
```
1.32 ─┬─► 2.1 ─► 2.2 ─┬─► 2.3 ─┐
      │                └─► 2.4 ─► 2.6 ─┤
      └────────────────────────────────┼─► 2.7 ─► 2.8 ─► 2.9 ─► 2.15 ─┐
                            2.5 ───────┘         ▲                   │
                                                 │                   ├─► 2.12
                            1.33 ────────────────┴───────────────────┘
                            2.10 ────────────────────────────────────┘
                            2.4,2.5,2.7,2.8 ─► 2.15 ─► 2.11 ──────────┘
```
**Parallel tracks.** Track P (no dependencies, start immediately): **2.5**, **2.10**, **1.33**.
Track S (server spine, serialized): 1.32 → 2.1 → 2.2 → 2.3 → 2.4 → 2.6 → 2.7 → 2.8 → 2.9 → 2.15.
**2.15 surfaced by 2.9's review** (client never sends a real hint on the routing path, only on
fetch) — it now gates 2.11 and 2.12, since both need real cross-org routing to run at all.
2.4 and 2.5 both touch `config::Federation` — sequence them if one developer.

## Exit criteria
- Every Phase 2 task `[x]`.
- Tree green: `cargo test --workspace` and `cargo clippy --workspace --all-targets -D warnings` clean;
  all invariant lints (including `lint-server-no-core.sh` — federation must **not** pull
  `meridian-core` into the server) pass.
- Docs synced (`tools/check-docs.sh`, no broken links); `federation-protocol-v1.md` published and
  covered by conformance vectors.
- The acceptance demo runs: `demo/two-orgs` walkthrough passes under **both** discovery modes; a
  `closed`-policy org rejects inbound federation with a clean client-side error; a substituted bundle
  from the foreign server fails closed; killing either rendezvous after setup does not interrupt the
  P2P session; the stale-hint case reports "unreachable at hint" and never a security warning; the
  opacity audit passes at both servers.
- Then: `/start-review-phase` for Phase 3.
