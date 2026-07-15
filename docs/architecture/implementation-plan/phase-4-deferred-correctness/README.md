> **Nav:** [plan index](../README.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Phase 4 — Deferred correctness & completed-work gaps

*Independent correctness items the review found inside completed features. Grouped here because none
blocks the foundation, but each closes a real gap.*

**Gate before this phase:** Phase 2 (partial — T4.1/T4.4 depend on vector tasks).

| Task | Scope (one line) | Tags | Depends on | Status |
|---|---|---|---|---|
| [T4.1](./T4.1-desync-recovery.md) | Desync → fresh-X3DH auto-recovery (F03 §10) | [SEC] | T2.2 | ☐ |
| [T4.2](./T4.2-capacity-test.md) | Real 5k-connection capacity test (F02) | — | — | ☐ |
| [T4.3](./T4.3-malicious-relay-test.md) | Make `malicious_relay_cannot_touch_inner_sdp` a real test | [SEC] | — | ☐ |
| [T4.4](./T4.4-spk-rotation.md) | SPK rotation policy: confirm design, then implement | [ADR][SEC] | T2.3 | ☐ |
