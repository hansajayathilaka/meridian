# CLAUDE.md — harnesses/ (adversarial test suites)

Scoped memory. Inherits [root](../CLAUDE.md). These are **shell** harnesses (not workspace crates) that
prove security properties by attacking the system. Referenced by the
[test strategy](../docs/testing/strategy.md) and the [test-engineer](../.claude/agents/test-engineer.md) agent.

## Contents
- `mitm-sim/` — a malicious rendezvous that substitutes bundles/keys; must fail closed against verified contacts.
- `opacity-audit/` — asserts the server/SDP path exposes only opaque bytes (no plaintext, no metadata).
- `ghost-device/` — detects silent extra-device insertion (multi-device attack).
- `nat-matrix/` — connectivity across NAT shapes (pairs with `tools/netns-nat-matrix.sh`).

## Rules
- **A failure here is a real defect — never weakened to go green.** Do not relax an attack, loosen an
  assertion, or skip a case to make a build pass. If the property genuinely changed, that's an
  [/adr](../.claude/commands/adr.md) + **security-reviewer** conversation, not a harness edit.
- Harnesses assert *negative* properties (attack does NOT succeed / data does NOT leak) — keep them
  adversarial; a harness that only exercises the happy path is a bug.
- New security-relevant behaviour ships with the harness that would catch its regression.
