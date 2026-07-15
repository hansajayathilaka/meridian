---
description: Drive the next unblocked task from the implementation plan through the orchestrated build loop.
---
Drive **one** task from the remediation plan
([docs/architecture/implementation-plan/](../../docs/architecture/implementation-plan/README.md)) end to
end: pick the next unblocked task → plan it → build it test-first → test & verify against its Definition
of Done → final review → go/no-go. Optional argument to pin a specific task: **$ARGUMENTS** (e.g.
`T2.1`); if empty, select automatically.

**Plan layout.** The plan is a directory: one folder per phase, one file per task. Read the plan
[`README.md`](../../docs/architecture/implementation-plan/README.md) for the phase table and the
findings→task map, then each `phase-<n>-*/README.md` for that phase's task table. A task ID `T<phase>.<n>`
resolves to `phase-<phase>-<slug>/T<phase>.<n>-<slug>.md`; open **that one file** for the task's full
context (Scope, Touches with [ADR]/[SEC] tags, Deliverables, Tests, Verification, Depends on, Status).
Each task file names its own required pre-build review under **Pre-build review**.

## Your role (orchestrator, Opus)
You are the **orchestrator** and you stay on Opus. You own sequencing, delegation, and the final
go/no-go — you do **not** collapse the loop into a single inline pass. Each sub-phase below names the
subagent it MUST be delegated to and the model that subagent runs on. Delegate explicitly; wait for each
step before starting the next dependent step. Independent delegations may run in parallel.

This loop advances **exactly one task** and then stops for review. Do not chain into the next task.

## The loop

### 0. Select the task
- Scan the phase `README.md` task tables for the **lowest-numbered task whose Status is ☐/◐ and whose
  every "Depends on" is ☑ done** (respect `$ARGUMENTS` if given, but refuse a task whose dependencies are
  unmet and say why). Set its Status to ◐ in its task file.
- Open the task file and read its fields (Scope, Touches, Deliverables, Tests, Verification, Depends on)
  and the **[ADR]/[SEC] tags**. Read the docs the task cites (the relevant feature spec, ADRs,
  `messaging-envelope-v1.md`, the [threat model](../../docs/security/threat-model.md) +
  [anonymity model](../../.claude/skills/anonymity-model/SKILL.md) for any [SEC] task). Never invent
  design — if a needed detail is absent, insert `TODO: confirm` and flag it.
- State the selected task ID, its scope in one sentence, and its tags before proceeding.

### 1. Plan (Opus subagents — design sign-off BEFORE any code)
- **If the task is [ADR]-tagged:** delegate design review to the **`architect`** subagent (Opus). It must
  return a verdict (consistent / contradicts ADR-XXXX / needs new ADR) and the minimal compliant shape.
  **Do not proceed to build on a "contradicts" or "needs new ADR" verdict** — escalate (see §6).
- **If the task is [SEC]-tagged:** delegate to the **`security-reviewer`** subagent (Opus) for a
  threat-model-grounded design check (identity/keys/crypto/signaling/storage/logging/metrics/federation).
- **Both tags → both subagents** (run them in parallel). Untagged task → you plan it inline (still Opus).
- Fold their guidance into a short, concrete build spec: the files to touch, the exact tests to write
  first, and the DoD items to satisfy. This build spec is the contract the Sonnet agents build against.

### 2. Test-first (Sonnet — tests before implementation)
- Delegate **test authoring** to the **`test-engineer`** subagent, **model: `sonnet`**. It writes the
  failing tests enumerated in the task's "Tests" field (unit/property/integration/harness/vector as the
  [test strategy](../../docs/testing/strategy.md) dictates), plus the negative/adversarial cases a [SEC]
  task needs. Security tests are written to be strict — never trivially-true.
  - *Tooling note:* if the `test-engineer` agent lacks Write access in this setup, it returns the exact
    test files and their paths, and you hand them to the build agent in §3 to write — either way the
    tests are **authored by Sonnet and committed before implementation exists**, and they must **fail**
    first (red). Run them and confirm red before §3.

### 3. Build (Sonnet — implement to green)
- Delegate implementation to a **`general-purpose`** subagent, **model: `sonnet`** (the "build agent"),
  with the §1 build spec and the §2 red tests. Its job: make those tests pass with the smallest change
  that satisfies the task's Scope — no scope creep into other tasks, no core-crate edits for additive
  stream types (registry only), no weakening of any test to go green.
- Rust is auto-formatted by the PostToolUse hook; the build agent leaves `cargo clippy` clean.

### 4. Verify against the Definition of Done
- Run, narrowest-first, the checks the task's **Verification (DoD)** field names — mirror CI:
  `just build`, `just lint` (fmt + clippy + `lint-invariants`), `/test <scope>`, the named harnesses,
  and any conformance-vector runner the task adds. For [SEC] tasks confirm the relevant invariant lint
  (metrics-allowlist, no-serde-on-blob, server-no-core, log-no-raw-id) actually **passes and is
  non-vacuous**.
- A security-test or harness failure is a real defect — fix the root cause, never the assertion. If a
  gate is green only because it checks nothing, that is a failure of this task.

### 5. Final review (Opus subagents)
- Re-delegate to **`architect`** ([ADR] tasks) and/or **`security-reviewer`** ([SEC] tasks), **Opus**, to
  review the *diff* against the design and the "must never" list. For any task, also run a general
  correctness/simplification pass (`/review` or the code-review skill).
- The reviewers report findings; you decide whether they are addressed or accepted-with-reason.

### 6. Go / no-go (you, Opus)
- **Go:** every DoD item for the task is satisfied, tests are green and strict, reviewers cleared. Commit
  with a message citing the task ID and the findings it closes; run `/doc-sync` if behavior/diagrams
  changed. Set the task file's **Status to ☑ done** (and update the row in its phase `README.md` table).
  **Stop** — report what landed and name the next unblocked task; do not auto-continue.
- **No-go / escalation:** if design review returned "contradicts ADR / needs new ADR", or a [SEC] finding
  changes a stated guarantee (e.g. **T0.6**, the deniability decision), **do not build** — use
  `AskUserQuestion` to put the decision to the user with enough context to answer, then record the
  outcome (a new/superseding ADR) before any implementation. This is the only point in the loop that
  pauses for a human.

## Guardrails (from [CONTRIBUTING.md](../../CONTRIBUTING.md))
- One task per invocation; small by design.
- Wire/API changes are versioned and conformance-vector-checked (DoD 3).
- ADRs are binding — supersede, never silently diverge (DoD 5).
- Never weaken a security test to pass (DoD 2).
- No invented design — `TODO: confirm` and flag (DoD 8).

End by summarizing: the task ID, what was delegated to whom (and on which model), the DoD result per
item, and the next unblocked task.
