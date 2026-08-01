---
description: Pick the next unblocked task(s), implement end-to-end, test, update the tracker, and open/update the PR.
---
Load the [task-tracking skill](../skills/task-tracking/SKILL.md) and follow its `/next-task` contract.
**$ARGUMENTS** — optional, one of:
- empty → the single next unblocked task (default, unchanged).
- a specific task id (e.g. `2.4`) → that one task.
- a count (e.g. `3`) or `all` → a **batch**: keep going through unblocked tasks in the current phase
  until that many are done, or `all` of them are, back-to-back in this run.

1. Read the master tracker [docs/tasks/README.md](../../docs/tasks/README.md). Delegate to the
   **task-picker** agent: for the default/single-id case, return the next unblocked task; for a batch,
   return the ordered list of unblocked tasks it can commit to up front (task-picker stops the list at
   the first task that isn't cleanly unblocked — see its contract).
2. For **each** task in order, repeat steps 2a–2f before moving to the next:
   1. Read only that task file. Mark it `- [~]` in the tracker + phase README.
   2. Implement with the right developer agent — **rust-dev** for core/server crates, **web-dev** for
      the browser/WASM client — strictly within the task's Scope. Honour the invariants (server-no-core,
      wire types from `meridian-proto`, never hand-roll crypto, additive stream types touch the registry
      only).
   3. Run the task's Tests (narrowest first). Get the required **Reviews** sign-off (security-reviewer /
      architect / test-engineer / code-reviewer as the task specifies) — this single pass **is** the
      security/architecture gate in the [Definition of Done](../../CONTRIBUTING.md); do not also run
      `/review` on the same diff, that command is for ad-hoc scopes outside this workflow. Satisfy the
      remaining Definition of Done gates; run `/doc-sync` if behaviour/wire/diagrams changed.
   4. Update the task file Status, mark `- [x]`, refresh the tracker ▶ NOW/NEXT.
   5. Commit **this task alone** (use the push-retry loop in the skill §6) — one commit per task even in
      a batch run, so each task stays independently reviewable and revertable. Keep the message scoped
      to the one task.
   6. If this task turns out too large for one PR, **stop the whole run here** (do not start the next
      queued task) and split it into sub-tasks via `/plan-phase` instead.
3. After the loop ends (batch exhausted, count reached, or stopped early), open a **draft PR** if the
   branch has none, else push the accumulated commits to update it. One PR carries every commit from
   this run.

End by reporting each completed task against its acceptance criteria, and — if the run stopped before
covering the full requested batch — exactly which task it stopped at and why.
