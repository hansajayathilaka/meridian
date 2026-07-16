---
description: Select the feature(s) for the next build phase and create its phase README (no task breakdown yet).
---
Load the [task-tracking skill](../skills/task-tracking/SKILL.md) and follow its `/pick-next-phase`
contract. Optional focus/override: **$ARGUMENTS**.

1. Read the master tracker [docs/tasks/README.md](../../docs/tasks/README.md) to find the next phase number and the ▶ NOW/NEXT pointer. Confirm the previous build phase has been review-swept (a review phase should sit between build phases).
2. Delegate to the **task-picker** agent: from [docs/architecture/features/](../../docs/architecture/features/) and the [roadmap](../../docs/architecture/roadmap.md) dependency table, choose the feature(s) whose dependencies are all done. Respect priority order and the parallel-track guidance. If `$ARGUMENTS` names a feature, honour it but verify its deps are met (flag if not).
3. Create `docs/tasks/phase-N/README.md` from [TEMPLATE-phase-readme.md](../../docs/tasks/TEMPLATE-phase-readme.md): goal, chosen feature(s) with spec links, dependency check. **Do not break tasks down** — that is `/plan-phase`.
4. Add the new phase to the master tracker and set ▶ NEXT to `/plan-phase`.

End by naming the phase, the chosen feature(s), and the dependency rationale.
