---
description: Open a review phase, sweep everything built since the last review, and write a full review report.
---
Load the [task-tracking skill](../skills/task-tracking/SKILL.md) and follow its `/start-review-phase`
contract. Optional scope override: **$ARGUMENTS** (defaults to all build work since the last review).

1. Read the master tracker to determine the next phase number and which build phase(s)/tasks this review covers.
2. Create `docs/tasks/phase-N/README.md` from [TEMPLATE-phase-readme.md](../../docs/tasks/TEMPLATE-phase-readme.md) with **Kind: review** and the reviewed scope.
3. Run the review sweep over the reviewed scope's diff and deliverables, delegating in parallel where possible:
   - **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications.
   - **security-reviewer** — anonymity-model "must never" list, key/opacity/logging/metrics invariants.
   - **architect** — ADR drift, dependency-graph and stream-registry contracts.
   - **test-engineer** — coverage gaps across the pyramid + adversarial harnesses.
   Also collect **decisions made on the fly** during earlier build phases that were never recorded.
4. Write `docs/tasks/phase-N/review-report.md` from [TEMPLATE-review-report.md](../../docs/tasks/TEMPLATE-review-report.md): each finding with severity (blocking / should-fix / nit), file:line, and recommended fix; unratified decisions (architectural ones → `/adr`); coverage gaps; a verdict.
5. Add the phase to the master tracker and set ▶ NEXT to `/plan-review-phase`.

Do not fix anything here — this command only reports. End with the finding count by severity and the verdict.
