<!-- Copy this file to docs/tasks/phase-N/P.N-<slug>.md and fill every section.
     Shape mirrors the feature specs in docs/architecture/features/. -->
> **Nav:** [tracker](../README.md) · [phase](./README.md) · [feature spec](../../architecture/features/) · [Definition of Done](../../../CONTRIBUTING.md)

# P.N — <Task title>

**Phase:** <N — name> · **Feature:** <T## — name or "review fix"> · **Depends on:** <task ids or —> · **Status:** pending

## Goal
<One or two sentences: what this task makes true that wasn't before.>

## Scope
- **In:** <the single concern this task covers.>
- **Out:** <explicitly what it does NOT touch — deferred to which task/phase.>

## Deliverables
1. <named file / function / type>
2. <named test(s)>

## Risks / notes
<Traps, invariants to respect, `TODO: confirm` items.>

## Tests
<Exact command(s) that prove this task, narrowest first — e.g. `cargo nextest run -p meridian-<crate>`
or the harness under `harnesses/`. Independently runnable.>

## Reviews
<Which reviewers must sign off: architect / security-reviewer / test-engineer / code-reviewer, and why.>

## Links
- Feature spec: <../../architecture/features/NN-...md>
- ADRs: <if any>
- PR: <filled at /next-task time>
