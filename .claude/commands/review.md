---
description: Security / performance / correctness review of a diff or scope.
---
Review the following change (diff, file set, or scope): **$ARGUMENTS**

Ground the review in the design before commenting:

1. **Security first.** Load the [threat model](../../docs/security/threat-model.md), the [threat → mitigation matrix](../../docs/security/threat-mitigation-matrix.md), and the [privacy & retention "must never" list](../../docs/security/anonymity-and-retention.md). For anything touching identity, keys, signaling, storage, logging, or metrics, delegate to the `security-reviewer` subagent. Explicitly check:
   - No plaintext content or contact graph persisted or logged server-side.
   - No raw client identifiers in logs (salted hashes only); no PII in URLs or push payloads.
   - Server never asserts a key a client trusts without signature verification.
   - Key-change / device-change handling stays fail-closed for verified contacts.
2. **Correctness.** Does it honor the [wire protocol](../../docs/api/wire-protocol.md) and [core API contracts](../../docs/api/core-api-contracts.md)? Are wire-format changes versioned per the protocol's versioning rules and covered by conformance vectors?
3. **Architecture.** Does it contradict any [ADR](../../docs/adr/README.md)? If so, flag it and involve the `architect` subagent.
4. **Performance.** Call out N+1 queries, unbounded fan-out, blocking in async paths, and hot-path allocations — especially in session/transport and file-transfer code.
5. **Tests.** Confirm the change is covered by the relevant harness in the [test strategy](../../docs/testing/strategy.md).

Output findings grouped by severity (blocking / should-fix / nit) with a file:line and a concrete fix.
