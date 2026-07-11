# Security

Start here for anything touching confidentiality, identity, or privacy.

- [Threat model & security goals](./threat-model.md) — **canonical**; who we protect against,
  what is out of scope.
- [Threat → mitigation → verifying-test matrix](./threat-mitigation-matrix.md) — every adversary
  mapped to a mitigation and the CI harness that proves it.
- [Privacy model, retention & the "anonymity" question](./anonymity-and-retention.md) — the honest
  scope of privacy claims and the server-side "must never" list.

The [security-reviewer](../../.claude/agents/security-reviewer.md) subagent loads the threat model
before every review; the [/review](../../.claude/commands/review.md) command references it.
