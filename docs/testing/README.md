# Testing

- [Test & verification strategy](./strategy.md) — conformance vectors, opacity audits,
  adversarial harnesses, NAT matrix, ops CI, external review gates.

Every task feature spec under [architecture/features](../architecture/features/) carries its
own runnable acceptance demo; this document defines the cross-cutting harnesses and CI triggers.
Used by the [test-engineer](../../.claude/agents/test-engineer.md) subagent and the
[/test](../../.claude/commands/test.md) command.
