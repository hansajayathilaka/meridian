---
description: Create a new ADR or supersede an existing one (decisions are binding).
---
Create or update an Architecture Decision Record for: **$ARGUMENTS**

ADRs are binding ([docs/adr/](../../docs/adr/README.md)); this flow keeps them consistent. Involve the
[architect](../../.claude/agents/architect.md) subagent.

1. **Check for conflict.** Read the [ADR index](../../docs/adr/README.md). Does this change an existing
   decision? If yes, you will **supersede**, not silently edit.
2. **Pick the next number.** Use the highest existing ADR number + 1, zero-padded (e.g. `0015`). Slug
   the title: `docs/adr/00NN-short-slug.md`.
3. **Write it in the house format** (match existing ADRs): a source/nav header, then
   `# ADR 00NN: <title>`, **Status** (Proposed/Accepted), **Context**, **Options** (each with a fair
   pro/con), **Decision**, **Pros**, **Cons (accepted, with mitigations)**, **Consequences**. Do not
   present one option as inevitable — give the alternatives their strongest case (see how 0011/0014 are
   written).
4. **If superseding:** set the old ADR's Status to `Superseded by 00NN` and add a one-line pointer at
   its top; add "Supersedes 00MM" to the new one.
5. **Update the index table** in `docs/adr/README.md` (row + any "resolved/open" notes).
6. **Cross-link** from the affected [system design](../../docs/architecture/system-design.md) or
   [stack](../../docs/architecture/stack.md) section, and run [/doc-sync](./doc-sync.md).

Output the new/updated ADR path and the index diff.
