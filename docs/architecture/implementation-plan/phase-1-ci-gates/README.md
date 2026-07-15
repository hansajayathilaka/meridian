> **Nav:** [plan index](../README.md) · [Definition of Done](../../../../CONTRIBUTING.md) · [anonymity model](../../../../.claude/skills/anonymity-model/SKILL.md)

# Phase 1 — Make the CI gates real (enforcement layer)

*The review's central finding: the code is clean but the gates that keep it clean are hollow. These land
before Phase 2+ so new work can't slip through a decorative check. Each task makes one gate actually fail
on the violation it names.*

| Task | Scope (one line) | Tags | Depends on | Status |
|---|---|---|---|---|
| [T1.1](./T1.1-metrics-allowlist.md) | Metrics allowlist: assert on rendered output, not macro style | [SEC] | — | ☐ |
| [T1.2](./T1.2-no-serde-on-blob.md) | no-serde-on-blob: deny envelope-content decode in the server | [SEC] | — | ☐ |
| [T1.3](./T1.3-clippy-blocking.md) | Make clippy blocking (drop `\|\| true`) | — | — | ☐ |
| [T1.4](./T1.4-cargo-deny.md) | Land `deny.toml` + a real cargo-deny job | [ADR] | T0.1 | ☐ |
| [T1.5](./T1.5-opacity-harness.md) | Re-point the opacity-audit harness at the real test | — | — | ☐ |
| [T1.6](./T1.6-lint-server-no-core.md) | Harden lint-server-no-core to the resolved graph | [ADR] | — | ☐ |
| [T1.7](./T1.7-config-fail-closed.md) | Fail closed on config-load error | [SEC] | — | ☐ |
| [T1.8](./T1.8-gate-tamper-hook.md) | Feature-gate the bundle-tamper hook out of release | [SEC] | — | ☐ |
| [T1.9](./T1.9-ratelimiter-eviction.md) | Evict expired rate-limiter entries | — | — | ☐ |
| [T1.10](./T1.10-log-id.md) | Salted-hash `LogId` + tracing-identifier lint | [SEC] | — | ☐ |
