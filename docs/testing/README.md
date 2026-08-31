# Testing

- [Test & verification strategy](./strategy.md) — conformance vectors, opacity audits,
  adversarial harnesses, NAT matrix, ops CI, external review gates.
- [Soak test: `meridian send` throughput (T09 / task 10.14)](./soak-file-transfer-throughput.md) —
  the feature spec's named 1 GiB/10 GiB netns soak run feeding ADR-6; records a blocking
  pre-existing SCTP-message-size defect found while attempting it.

Every task feature spec under [architecture/features](../architecture/features/) carries its
own runnable acceptance demo; this document defines the cross-cutting harnesses and CI triggers.
Used by the [test-engineer](../../.claude/agents/test-engineer.md) subagent and the
[/test](../../.claude/commands/test.md) command.
