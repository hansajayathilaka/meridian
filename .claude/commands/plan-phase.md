---
description: Break the picked phase's feature(s) into small independently-testable tasks and fill the phase todo list.
---
Load the [task-tracking skill](../skills/task-tracking/SKILL.md) and follow its `/plan-phase` contract.
Optional phase override: **$ARGUMENTS** (defaults to the phase at ▶ NEXT).

1. Read the master tracker and the target `docs/tasks/phase-N/README.md`, plus the feature spec(s) it references and only the design docs those specs cite (system-design sections, wire/API contracts, threat model — per the feature). Keep reading scoped.
2. Delegate to the **planner** agent (and the **architect** agent if the phase touches architecture, the wire protocol, or an ADR). Break each feature into tasks that each satisfy the **Definition of Task** (single concern, independently testable, explicit deliverables, fits one PR). Order them by dependency.
3. For each task, write `docs/tasks/phase-N/N.M-<slug>.md` from [TEMPLATE-task.md](../../docs/tasks/TEMPLATE-task.md) — fill Goal, Scope (In/Out), Deliverables, Risks, Tests, Reviews, Dependencies, Links. Insert `TODO: confirm` rather than inventing missing design detail.
4. Populate the phase README todo list and the master tracker checkbox tree. Set ▶ NEXT to `/next-task`.

End by listing the task ids with one-line summaries and their dependency order.
