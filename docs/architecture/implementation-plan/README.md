<!-- Source: post-Feature-5 review. This directory is the REMEDIATION plan; the feature cadence resumes at
     roadmap.md once Phase 5 clears. Every task closes one or more review findings by construction — see
     the traceability map below. One folder per phase, one file per task, so a session can open exactly the
     task it is about to build. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [ADR index](../../adr/README.md) · [Definition of Done](../../../CONTRIBUTING.md) · [test strategy](../../testing/strategy.md)

# Implementation Plan — Remediation of the Features 1–5 Review

This plan turns the Features 1–5 review into buildable work. It sits **between** the completed critical
path (Features 01–05) and the next roadmap feature (06, Cross-Org Federation): the review found the
*code* sound but the *guardrails, conformance surface, and real transport* incomplete, so the
foundation is hardened here before more features stack on it.

**Remaining work: 6 phases, 37 tasks.**

## How this is organized (so a session can navigate straight to a task)

```
implementation-plan/
├── README.md                       ← you are here (the index + baseline + traceability)
├── phase-0-truth-restoration/
│   ├── README.md                   ← phase intro + task table
│   ├── T0.1-adr-0015-ratchet-composition.md
│   └── … one file per task
├── phase-1-ci-gates/
├── phase-2-crypto-freeze/
├── phase-3-transport-backend/
├── phase-4-deferred-correctness/
└── phase-5-ga-readiness/
```

**Task-ID → file convention.** A task ID `T<phase>.<n>` lives at
`phase-<phase>-<slug>/T<phase>.<n>-<slug>.md`. The [`/next-task`](../../../.claude/commands/next-task.md)
loop resolves an ID to its file by opening the phase folder's `README.md` (the task table links every
task file). Open **one task file** to get that task's full context — scope, deliverables, tests,
verification, dependencies — without loading its siblings.

**Every task file carries the same fields:**
- **Scope** — the one thing it builds.
- **Touches** — crates/files/docs, with an **[ADR]** tag for ADR-bound areas (crypto, transport, wire
  protocol, federation) and a **[SEC]** tag for identity, keys, crypto, signaling, storage, logging,
  metrics, or federation. Tagged tasks get **architect** and/or **security-reviewer** sign-off *before* build.
- **Deliverables** — the documented artifacts produced.
- **Tests** — the tests that prove it works (authored test-first).
- **Verification (DoD)** — the [Definition of Done](../../../CONTRIBUTING.md) items satisfied, by number.
- **Depends on** — upstream task IDs.
- **Status** — ☐ not started · ◐ in progress · ☑ done. `/next-task` updates this on go/no-go.

**How tasks are sized.** Each builds exactly **one small, self-contained thing** that can be planned,
built test-first, tested, and reviewed in a single focused pass. That granularity is deliberate: the
review's worst findings (a lint that checks nothing, a "frozen" format with no vectors, a completed
feature running on a simulated transport) all came from work too coarse to verify. Small tasks close
that class of gap by construction.

## Relationship to the [roadmap](../roadmap.md)

The roadmap orders *features*; this plan orders the *remediation* that must land before the roadmap
resumes. Feature tasks (06–16) are still started with
[`/new-task <feature>`](../../../.claude/commands/new-task.md); remediation tasks here are driven one at
a time with [`/next-task`](../../../.claude/commands/next-task.md). **Phase 5 is the explicit hand-back
point.**

## Phases (dependency-ordered)

Phase 0 and Phase 1 are pure-guardrail (documentation truth and CI enforcement) with near-zero
product-code risk, so they land first and stop the findings from regressing while later phases are built.

| Phase | Theme | Tasks | Gate before it |
|---|---|---|---|
| [0 — Truth restoration](./phase-0-truth-restoration/README.md) | Doc & ADR integrity | 6 | — |
| [1 — CI gates](./phase-1-ci-gates/README.md) | Make the enforcement layer real | 10 | — |
| [2 — Crypto freeze](./phase-2-crypto-freeze/README.md) | Conformance vectors + key hygiene | 7 | Phases 0–1 |
| [3 — Transport backend](./phase-3-transport-backend/README.md) | Real WebRTC; close F04/F05 | 8 | Phase 1 |
| [4 — Deferred correctness](./phase-4-deferred-correctness/README.md) | Gaps inside completed features | 4 | Phase 2 (partial) |
| [5 — GA readiness](./phase-5-ga-readiness/README.md) | External review + roadmap hand-back | 2 | All prior |

## Part A — Completed work (baseline, carried forward as done)

Features 01–05 are **done** and are not re-planned or re-opened here. Where the review found a gap
*inside* a completed feature, the gap is carried as a remediation task (see Part C) — the feature itself
still stands.

| # | Feature | Status | Verified by |
|---|---------|--------|-------------|
| 01 | Identity & Keystore Core | **Done** | `meridian-identity` + CLI; `test-vectors/identity-v1.json` consumed byte-for-byte by `apps/identity/tests/conformance.rs`; 10⁶ fuzz + flipped-bit + same-principal + plaintext-never-on-disk all pass |
| 02 | Rendezvous Server MVP | **Done** | `meridian-rendezvous` binary + Dockerfile; challenge/response auth, exact-key bundle fetch, fail-closed tampered-bundle abort (`mitm-sim`); opaque routing verified |
| 03 | E2EE Messaging (relayed) | **Done** | In-house composed Double Ratchet + X3DH in `meridian-crypto`, verified line-by-line against `messaging-envelope-v1.md`; FS/PCS/out-of-order/restart-resume tests pass; opacity audit passes |
| 04 | P2P Session Substrate | **Done (substrate logic)** | `Transport` trait, session state machine, fingerprint binding, ctrl channel, stream registry, ICE-restart — all tested against `LoopbackTransport` |
| 05 | NAT Traversal & Relay Policy | **Done (policy logic)** | Three-position policy, strip-before-gather, ephemeral TURN minting, `meridian doctor` — all tested in-process |

> **Honesty note carried into the plan.** Features 04 and 05 are complete at the *substrate/policy*
> layer but their *wire-level* acceptance (real WebRTC, real coturn, packet captures) was never
> demonstrated, because no production transport backend exists. That divergence is closed by
> **[Phase 3](./phase-3-transport-backend/README.md)**, and until it lands the specs are annotated
> "wire-level verification deferred" by **[T0.5](./phase-0-truth-restoration/T0.5-annotate-feature-specs.md)** —
> the features are not silently overclaimed.

## Part C — Traceability: every review finding → the task that closes it

| Review area | Finding | Closed by |
|---|---|---|
| 1 Library change | No X3DH/ratchet/envelope/safety-number vectors | T2.1, T2.2, T2.3, T2.4 |
| 1 | ADR supersede procedure not followed (no ADR 0015) | T0.1, T0.2 |
| 1 | 10 docs still say vodozemac (`.claude/` first) | T0.3 |
| 1 | cargo-deny AGPL gate absent | T1.4 |
| 1 | X3DH master secret + header keys un-zeroized | T2.5 |
| 1 | At-rest key depends on signature determinism | T2.6 |
| 1 | Opacity-audit harness is a stub | T1.5 |
| 1 | T03 spec still says "no hand-rolled ratchet" | T0.5 |
| 2 Completed work | F02 5k-capacity test is phantom | T4.2 |
| 2 | F03 desync→fresh-X3DH not implemented | T4.1 |
| 2 | F04 no webrtc-rs backend; `session info` overclaims | T3.1, T3.3 |
| 2 | F04 weakened `malicious_relay` test | T4.3 |
| 2 | F05 wire-level acceptance simulated; coturn unrun; single-session overclaim | T3.5, T3.6 |
| 3 Missing tasks | Conformance vectors + CI runner | T2.1–T2.4, T2.7 |
| 3 | wasm32 build validation | T2.7 |
| 3 | Roadmap corruption + ADR 0013 splice | T0.4 |
| 4 Gaps | Metrics-allowlist lint vacuous | T1.1 |
| 4 | no-serde-on-blob bypassable | T1.2 |
| 4 | Server fails open on config error | T1.7 |
| 4 | Tamper hook in production binary | T1.8 |
| 4 | Relay-only line from policy not observation | T3.3 |
| 4 | lint-server-no-core grep too narrow | T1.6 |
| 4 | Salted-hash LogId missing before observability | T1.10 |
| 4 | Rate-limiter unbounded growth | T1.9 |
| 4 | Clippy non-blocking | T1.3 |
| 5 Future risks | Deniability vs envelope-signature contradiction | T0.6 |
| 5 | External crypto review load-bearing | T5.1 |
| 5 | Feature 10 stacking on unproven invariants | Phase 3 (all) |
| 5 | Interop debt compounds silently | T2.1–T2.4, T2.7 |
| 5 | Verified-contact key-change (goal 2, deferred to F08) | out of scope — tracked at Feature 08 |

## Part D — ADR-bound / security-sensitive tasks (require pre-build review)

**[ADR]**-tagged tasks get **architect** sign-off before build; **[SEC]** tasks get **security-reviewer**
sign-off. Both-tagged tasks get both. `/next-task` reads the tags in each task file and routes the
planning and final-review steps automatically.

- **architect + security-reviewer:** T0.1, T0.6, T2.1, T2.2, T2.3, T2.6, T3.2, T3.3, T3.6, T4.4.
- **architect only:** T1.4, T1.6, T3.1, T3.4, T3.5*, T3.7, T3.8. (*T3.5 also SEC.)
- **security-reviewer only:** T0.3, T1.1, T1.2, T1.7, T1.8, T1.10, T2.4, T2.5, T4.1, T4.3, T5.1.
