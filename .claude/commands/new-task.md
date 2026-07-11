---
description: Start a feature — read the relevant design docs, plan, implement, and test.
---
You are starting work on a feature for Meridian. The feature/scope is: **$ARGUMENTS**

Follow this grounded workflow. Do not skip the reading step — this repo's design is the source of truth.

1. **Locate the spec.** Find the matching feature spec under [docs/architecture/features/](../../docs/architecture/features/) (features are numbered 01–16; see the [roadmap](../../docs/architecture/roadmap.md)). Read it fully, including its "working output" demo and acceptance criteria.
2. **Read the grounding docs it references:**
   - [System design](../../docs/architecture/system-design.md) for the sections it cites.
   - [Wire protocol](../../docs/api/wire-protocol.md) and [core API contracts](../../docs/api/core-api-contracts.md) if it touches the wire or public API.
   - [Threat model](../../docs/security/threat-model.md) and [privacy & retention](../../docs/security/anonymity-and-retention.md) — **always**, to respect the "must never" invariants.
   - Any relevant [ADRs](../../docs/adr/README.md). If your plan contradicts an ADR, stop and escalate to the `architect` subagent instead of quietly diverging.
3. **Plan.** Produce a short step list mapped to the spec's acceptance criteria. Identify which crates under [apps/](../../apps/) change. State assumptions explicitly; if a needed detail is absent from the docs, insert a `TODO: confirm` rather than inventing it.
4. **Implement** against the [API contracts](../../docs/api/core-api-contracts.md). Additive stream types must not modify core crates (see [ADR 0007 context] and the stream-plugin contract).
5. **Test.** Satisfy the spec's demo and the cross-cutting harnesses in the [test strategy](../../docs/testing/strategy.md). Run `/test $ARGUMENTS`.
6. **Sync docs** if behavior or diagrams changed: run `/doc-sync $ARGUMENTS`.

End by summarizing what you did against each acceptance criterion.
