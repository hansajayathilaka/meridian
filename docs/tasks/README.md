# Meridian — Task Tracker

The single activity list for the project. Drive work with the five commands (see the
[task-tracking skill](../../.claude/skills/task-tracking/SKILL.md)); this file is always the record.

```
Build phase:   /pick-next-phase → /plan-phase → /next-task ×N
Review phase:  /start-review-phase → /plan-review-phase → /next-task ×N (fix-tasks)
```

**Status marks:** `[ ]` pending · `[~]` in progress · `[x]` done · `[!]` blocked.
Numbering is `P.N` (phase.task). These *execution* phases differ from the *design* Phase 0–4 in
[system-design.md §11](../architecture/system-design.md) — don't conflate them.

---

## ▶ NOW / NEXT

- **NOW:** Phase 0 complete (foundation shipped).
- **NEXT:** run **`/start-review-phase`** to open Phase 1 (review of Phase 0 → "issues to fix").
- After Phase 1 fixes land: **`/pick-next-phase`** selects Phase 2 (T06 Cross-Org Federation).

---

## Phases

### Phase 0 — Foundation · **done** · [details](./phase-0/README.md)
Trust-critical substrate: identity, E2EE messaging, P2P session, NAT traversal. Recorded retroactively.
- [x] **0.1** Identity & Keystore Core (T01) — [file](./phase-0/0.1-identity-keystore.md)
- [x] **0.2** Rendezvous Server MVP (T02) — [file](./phase-0/0.2-rendezvous-mvp.md)
- [x] **0.3** E2EE Messaging, relayed (T03) — [file](./phase-0/0.3-e2ee-messaging.md)
- [x] **0.4** P2P Session Substrate (T04) — [file](./phase-0/0.4-p2p-session-substrate.md)
- [x] **0.5** NAT Traversal & Relay Policy (T05) — [file](./phase-0/0.5-nat-traversal-relay.md)

### Phase 1 — Review of Phase 0 · **not started**
Created by `/start-review-phase`. Reviews tasks 0.1–0.5; findings become fix-tasks `1.1…`.

### Phase 2 — Cross-Org Federation (T06) · **not started**
Selected by `/pick-next-phase` after Phase 1. Critical path — unblocks 07/10/14.

### Phase 3 — Review of Phase 2 · **not started**
…build → review alternating thereafter.

---

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
