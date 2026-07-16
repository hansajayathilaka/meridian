---
description: Pick the next unblocked task, implement it end-to-end, test, update the tracker, and open/update the PR.
---
Load the [task-tracking skill](../skills/task-tracking/SKILL.md) and follow its `/next-task` contract.
Optional task override: **$ARGUMENTS** (defaults to the next unblocked task).

1. Read the master tracker [docs/tasks/README.md](../../docs/tasks/README.md). Delegate to the **task-picker** agent to return the next unblocked task (deps done, status pending) for the current phase — or use `$ARGUMENTS` if given.
2. Read only that task file. Mark it `- [~]` in the tracker + phase README.
3. Implement with the right developer agent — **rust-dev** for core/server crates, **web-dev** for the browser/WASM client — strictly within the task's Scope. Honour the invariants (server-no-core, wire types from `meridian-proto`, never hand-roll crypto, additive stream types touch the registry only).
4. Run the task's Tests (narrowest first). Get the required **Reviews** sign-off (security-reviewer / architect / test-engineer / code-reviewer as the task specifies). Satisfy the [Definition of Done](../../CONTRIBUTING.md); run `/doc-sync` if behaviour/wire/diagrams changed.
5. Update the task file Status, mark `- [x]`, refresh the tracker ▶ NOW/NEXT.
6. Commit (use the push-retry loop in the skill §6). Open a **draft PR** if the branch has none, else update it. Keep messages scoped to the one task.

If the task turns out too large for one PR, stop and split it into sub-tasks via `/plan-phase` rather than sprawling. End by reporting the task against its acceptance criteria.
