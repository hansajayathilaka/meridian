---
description: Update docs and diagrams after a change.
---
Synchronize documentation for the change: **$ARGUMENTS**

1. Identify which docs are affected. Start from the [docs index](../../docs/INDEX.md).
2. If the **wire format or public API** changed → update [wire-protocol.md](../../docs/api/wire-protocol.md) / [core-api-contracts.md](../../docs/api/core-api-contracts.md) **first** (they are canonical; diagrams yield to them) and bump the version per the protocol's versioning rules.
3. If **behavior or a flow** changed → update the relevant [diagram](../../docs/architecture/diagrams/README.md) `.mermaid` source. Keep sequence-diagram message text free of `;` and `'` (Mermaid parser hazards).
4. If a **design decision** changed → do not silently edit prose; add or supersede an [ADR](../../docs/adr/README.md) and involve the `architect` subagent.
5. If a **feature's acceptance demo** changed → update its spec under [features/](../../docs/architecture/features/).
6. Re-check that all relative links resolve. Leave `TODO: confirm` for anything not determinable from the design.

Summarize the doc/diagram edits made.
