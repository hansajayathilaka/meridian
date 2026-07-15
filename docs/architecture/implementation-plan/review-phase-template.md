<!-- The reusable structure every milestone review gate (R1–R4) instantiates. Modeled on R0 — the
     Features 1–5 review. Copy this into review-r<N>-<slug>/README.md and fill it in when the milestone's
     features are all built. -->
> **Nav:** [plan index](./README.md) · [Definition of Done](../../../CONTRIBUTING.md) · [threat model](../../security/threat-model.md) · [test strategy](../../testing/strategy.md)

# Review-phase template (how each R-gate runs)

A **review phase** is a first-class phase, not a checkbox. It closes a milestone by re-running the
security-weighted, five-area review that R0 (the Features 1–5 review) ran, scoped to everything the
milestone touched, and then **fixes what it finds before the next milestone starts**. Copy this file to
`review-r<N>-<slug>/README.md`, set the scope, and work the loop.

## Inputs (fill these in per gate)
- **Milestone under review:** M&lt;N&gt; — &lt;features&gt;.
- **New/changed surfaces:** the crates, wire formats, ADRs, docs, and infra this milestone added.
- **Most-sensitive change:** the one crypto/keys/identity/signaling/storage/logging/metrics/federation
  change that carries the most risk (this gets the deepest security pass).

## Step 1 — Scope & delegate (orchestrator, Opus)
Read the milestone's feature specs, the ADRs they touch, and the threat/anonymity docs. Then delegate
independent review threads, exactly as R0 did — keep working while they run:
- **`security-reviewer`** (Opus) — the "must never" list + threat model over the milestone's most
  sensitive surfaces. **Always** for anything touching identity, keys, crypto, signaling, storage,
  logging, metrics, push payloads, or federation.
- **`architect`** (Opus) — ADR conformance and doc/diagram drift for any new component, dependency, wire
  change, or decision; opens a superseding ADR if the milestone diverged.
- **`test-engineer`** (Sonnet) — inventory the test estate vs the DoD-named security tests and each
  feature's acceptance section; **run the suite** and report pass/fail; hunt weakened/stub/`#[ignore]`
  tests and missing conformance vectors.

## Step 2 — The five review areas (the findings report)
Produce a findings report in this folder (`findings.md`), most-severe first, grouped by:
1. **Security review** of the milestone's most sensitive change — do the invariants still hold?
2. **Completed-work review** — each feature vs its spec's acceptance criteria and the Definition of Done.
3. **Missing tasks** — tests, docs/diagram sync, conformance vectors, error handling at trust boundaries
   that a spec or the DoD required but that were skipped.
4. **Gaps needing new steps** — where the built state diverges from the design.
5. **Future risks** — architectural, security, operational trajectory problems.

Every finding cites **file:line** and the spec/ADR/doc it fails, with a severity and a recommended step.

## Step 3 — Decompose findings into remediation tasks (`R<N>.<m>`)
Turn every actionable finding into a task **in this folder**, with the standard fields (Scope · Touches
with [ADR]/[SEC] tags · Deliverables · Tests · Verification (DoD) · Depends on · Status · Pre-build
review). Add a traceability table (finding → `R<N>.<m>`) so the gate closes its findings by construction.
Tag the ADR/SEC tasks so `/next-task` routes them to `architect`/`security-reviewer` before build.

## Step 4 — Fix, then gate
Drive the `R<N>.<m>` tasks with [`/next-task`](../../../.claude/commands/next-task.md) until all are
done and `just lint && just test` (plus the milestone's harnesses and conformance vectors) are green.
**The milestone is not complete — and the next milestone does not start — until this gate is clear.**
Escalate to the user via `AskUserQuestion` only for a finding that forces an architectural decision
superseding an ADR (as R0's deniability finding, T0.6, does).

## Step 5 — Roll up
Update the [status dashboard](./README.md#where-are-we-right-now-status-dashboard): mark the milestone
Done and its review gate cleared, and record any risk explicitly **accepted** (not fixed) with the reason.
