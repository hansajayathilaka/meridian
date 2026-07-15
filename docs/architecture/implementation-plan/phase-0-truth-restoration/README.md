> **Nav:** [plan index](../README.md) · [ADR index](../../../adr/README.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Phase 0 — Truth restoration: doc & ADR integrity

*No product code changes. Fixes the recorded design so the ADRs, the stack doc, and — most importantly
— the `.claude/` guidance that steers future sessions stop teaching a superseded decision.*

| Task | Scope (one line) | Tags | Depends on | Status |
|---|---|---|---|---|
| [T0.1](./T0.1-adr-0015-ratchet-composition.md) | Write ADR 0015 (ratchet composed in `meridian-crypto`) | [ADR][SEC] | — | ☐ |
| [T0.2](./T0.2-adr-0011-header-and-index.md) | Correct ADR 0011 status line + the ADR index | — | T0.1 | ☐ |
| [T0.3](./T0.3-doc-sync-vodozemac-drift.md) | Doc-sync the vodozemac drift (10 locations) | [SEC] | T0.1 | ☐ |
| [T0.4](./T0.4-repair-roadmap-and-adr-0013.md) | Repair roadmap phasing + ADR 0013 splice artifact | — | — | ☐ |
| [T0.5](./T0.5-annotate-feature-specs.md) | Annotate F03/F04/F05 specs wire-level-deferred | — | T0.1 | ☐ |
| [T0.6](./T0.6-deniability-decision.md) | Open the deniability-vs-envelope-signature ADR decision | [ADR][SEC] | — | ☐ |
