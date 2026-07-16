---
description: Turn a review report's findings into numbered fix-tasks and fill the review phase todo list.
---
Load the [task-tracking skill](../skills/task-tracking/SKILL.md) and follow its `/plan-review-phase`
contract. Optional phase override: **$ARGUMENTS** (defaults to the review phase at ▶ NEXT).

1. Read the master tracker and the target `docs/tasks/phase-N/review-report.md`.
2. Delegate to the **planner** agent. Convert each **actionable** finding (blocking + should-fix; nits only if cheap) into a fix-task that satisfies the **Definition of Task**. Group by area; order blocking first. Skip findings that are duplicates or need no action, noting why.
3. For each fix-task, write `docs/tasks/phase-N/N.M-<slug>.md` from [TEMPLATE-task.md](../../docs/tasks/TEMPLATE-task.md), linking back to the report finding id (F#). Architectural decisions to ratify → open an ADR via `/adr` and reference it.
4. Populate the phase README todo list + master tracker checkbox tree. Set ▶ NEXT to `/next-task`.

End by listing the fix-tasks with their source finding ids and severities.
