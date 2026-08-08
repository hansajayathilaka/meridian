---
name: task-tracking
description: Use when running any of the five workflow commands (/pick-next-phase, /plan-phase, /next-task, /start-review-phase, /plan-review-phase) or when creating, numbering, planning, implementing, or reviewing phases and tasks in docs/tasks/. Encodes the phase lifecycle, numbering, the Definition of Task, the file templates, and how the tracker stays in sync.
---
# Task Tracking — the Meridian delivery workflow

This is the single source of truth for **how work is picked, planned, built, and reviewed**. The five
slash commands are thin entry points; the actual contract lives here. Keep reading cheap: a command
reads **only** the master tracker plus the one phase/task file it needs — never the whole doc tree.

**Read first (once, only the parts you need):**
- Master tracker: [docs/tasks/README.md](../../../docs/tasks/README.md) — always start here.
- Definition of Done (8 gates): [CONTRIBUTING.md](../../../CONTRIBUTING.md).
- Feature specs (the "what"): [docs/architecture/features/](../../../docs/architecture/features/) +
  [roadmap.md](../../../docs/architecture/roadmap.md) dependency DAG.

---

## 1. The phase lifecycle

Work advances one **phase** at a time. Build phases and review phases alternate:

```
Build phase:   /pick-next-phase → /plan-phase → /next-task ×N
Review phase:  /start-review-phase → /plan-review-phase → /next-task ×N (fix-tasks)
```

- **Phase 0 — Foundation** is already DONE (T01–T05), recorded retroactively.
- A **review phase** always follows a build phase: it reviews everything built since the last review,
  writes a report, and turns findings into fix-tasks that flow through `/next-task` like any other work.
- These *execution* phases are distinct from the *design narrative* Phase 0–4 in
  `docs/architecture/system-design.md §11`. Do not conflate them.

## 2. Numbering & layout

- Phases are numbered `0, 1, 2, …`. Tasks are `P.N` (phase number, then task number within the phase).
- Tasks group under feature headings inside a phase. The master tracker's checkbox tree mirrors this.
- On-disk layout under `docs/tasks/`:
  ```
  docs/tasks/
    README.md                     ← master tracker (▶ NOW/NEXT + full phase→task tree)
    TEMPLATE-task.md
    TEMPLATE-phase-readme.md
    TEMPLATE-review-report.md
    phase-0/
      README.md                   ← phase overview + its todo list
      0.1-identity-keystore.md     … one file per task
    phase-1/
      README.md
      review-report.md            ← review phases only
      1.1-<slug>.md …
  ```

## 3. Definition of Task

A **task** is the smallest mergeable unit. Split anything larger at plan time. A task must:
1. **Be one focused change** — a single concern, ideally one crate/module.
2. **Be independently testable** — ships with its own test(s) passing in isolation
   (`cargo nextest run -p <crate>` or the relevant harness).
3. **Have explicit deliverables** — named files/functions/tests, listed in the task file.
4. **Have acceptance criteria** — a concrete pass/fail condition tied to the Definition of Done.
5. **Fit one session / one PR** and leave the tree green (`just build` + `cargo clippy` clean).
6. **Declare dependencies** on other tasks, and **sync docs** if behaviour/wire/diagram changed.

## 4. Status marks (used in every tracker and phase README)

`- [ ]` pending · `- [~]` in progress · `- [x]` done · `- [!]` blocked (note why).
Every task line links to its task file, e.g. `**2.3** Foo` linking to `phase-2/2.3-foo.md`.

## 5. The five command contracts

Each command: (a) reads the master tracker to orient, (b) does its one job, (c) updates the tracker's
▶ NOW/NEXT pointer and the relevant checkboxes, (d) never leaves the tracker inconsistent.

### `/pick-next-phase`
- Delegate to **task-picker** (or reason directly): read `docs/architecture/features/` +
  `roadmap.md` deps; choose the feature(s) for the next-numbered build phase whose dependencies are done.
- Create `docs/tasks/phase-N/README.md` from `TEMPLATE-phase-readme.md` (goal, scope, chosen features,
  dependency check, links to the feature specs). **Do not break down tasks yet.**
- Add the new phase to the master tracker and move ▶ NEXT to `/plan-phase`.

### `/plan-phase`
- Delegate to **planner** (+ **architect** if the phase touches architecture/wire/ADRs).
- Read the phase README + referenced feature specs. Break the feature(s) into tasks that each satisfy
  the Definition of Task. Write one task file per task from `TEMPLATE-task.md`.
- Populate the phase README todo list + the master tracker checkbox tree. Move ▶ NEXT to `/next-task`.

### `/next-task`
- Default (no argument): delegate to **task-picker** to return the next unblocked task (respects deps +
  status). A count (`/next-task 3`) or `/next-task all` instead asks task-picker for an **ordered batch**
  of that many unblocked tasks in the current phase — it stops the list early at the first task that
  isn't cleanly unblocked, so a short batch is expected and not an error.
- For each task in the batch, in order: mark it `- [~]`. Implement with the right dev agent: **rust-dev**
  (core/server) or **web-dev** (browser/WASM). Follow the task file's Scope/Deliverables. Run its tests
  (narrowest first).
- Get the task's `Reviews` sign-off (the reviewers its file names) via **one `reviewer` agent call**
  covering every lens the file names (security-reviewer / architect / code-reviewer) — not one agent
  call per named reviewer. A single pass over the same diff is cheaper than three, and the combined
  agent produces a verdict per lens, so the sign-off is exactly as complete as running them
  separately. Only spawn a single-lens agent (e.g. **security-reviewer** alone) when the task file
  names exactly one reviewer; **test-engineer** stays a separate call when a task names it — adding
  test coverage is a different kind of work, not another read-only lens over the same diff. That
  pass **is** the Definition of Done's security/architecture gate — it's grounded in the same
  threat-model docs `/review` uses, so don't also run `/review` on the same diff here; that command
  is for ad-hoc scopes outside this workflow. Satisfy the rest of the Definition of Done. Update the
  task file Status, mark `- [x]`, refresh ▶ NOW/NEXT.
- Commit **that one task** before starting the next in the batch — one commit per task keeps each
  independently reviewable/revertable even when several land in one run. If a task turns out too large
  for one PR, stop the whole run there rather than starting the next queued task.
- Once the batch (or single task) is done, open/update the PR (draft) — one PR carries every commit from
  the run. See §6 for the commit/push retry.

### `/start-review-phase`
- Create the next-numbered phase as a **review phase** (`phase-N/README.md`, kind: review).
- Run the review sweep across everything built since the last review, delegating to **code-reviewer**
  (correctness/loopholes/gaps), **security-reviewer** (privacy/crypto invariants), **architect**
  (ADR drift), and **test-engineer** (coverage/adversarial), in parallel where possible — a whole
  phase's worth of diff is large enough that dedicated single-lens agents each going deep is worth
  the extra reads (unlike a single task's diff at the `/next-task` Reviews gate, which uses the
  combined `reviewer` agent instead — see below). Also capture any decisions made on the fly.
- Write `docs/tasks/phase-N/review-report.md` from `TEMPLATE-review-report.md`: findings with severity
  (blocking / should-fix / nit), affected files, and recommended fix. Move ▶ NEXT to `/plan-review-phase`.

### `/plan-review-phase`
- Read the review report. Convert each actionable finding into a numbered **fix-task** (one task file
  each, satisfying the Definition of Task). Architectural decisions → record via `/adr`.
- Populate the phase todo + master tracker. Move ▶ NEXT to `/next-task`.

## 6. Commit / push discipline

Never weaken a security assertion or invent design to make a task pass. Push fails intermittently in
this environment — use the retry loop (substitute the real branch):
```
cd /home/user/meridian
for i in 1 2 3 4; do
  git push -u origin <branch> 2>&1 | tail -4 && break
  sleep $((2**i))
done
```
After pushing, open a **draft PR** if none is open for the branch, then keep the tracker as the record.

## 7. Definition of done for a phase

A phase is done when every task is `- [x]`, the tree is green, docs are synced (`/doc-sync`), and — for
build phases — the feature's acceptance demo runs. Then the next command is `/start-review-phase`.
