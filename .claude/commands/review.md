---
description: Security / performance / correctness review of a diff or scope.
---
Standalone, ad-hoc review — for a diff or scope outside the tracked task flow. Inside `/next-task`, the
task's `Reviews` sign-off already applies this same checklist and satisfies the Definition of Done's
security gate; don't run this command again on top of it there (that would just duplicate the review).

Review the following change (diff, file set, or scope): **$ARGUMENTS**

Ground the review in the design before commenting. For anything that touches identity/keys/crypto/
signaling/storage/logging/metrics/federation, or architecture/ADRs/the wire protocol, delegate to the
**`reviewer`** subagent (one combined pass covering correctness, security/privacy, and architecture —
not a separate `security-reviewer` call and a separate `architect` call over the same diff). It checks:

1. **Security.** No plaintext content or contact graph persisted or logged server-side; no raw client
   identifiers in logs (salted hashes only); no PII in URLs or push payloads; the server never asserts
   a key a client trusts without signature verification; key/device-change handling stays fail-closed
   for verified contacts — grounded in the [threat model](../../docs/security/threat-model.md), the
   [threat → mitigation matrix](../../docs/security/threat-mitigation-matrix.md), and the
   [privacy & retention "must never" list](../../docs/security/anonymity-and-retention.md).
2. **Correctness.** Does it honor the [wire protocol](../../docs/api/wire-protocol.md) and [core API contracts](../../docs/api/core-api-contracts.md)? Are wire-format changes versioned per the protocol's versioning rules and covered by conformance vectors?
3. **Architecture.** Does it contradict any [ADR](../../docs/adr/README.md)?
4. **Performance.** Call out N+1 queries, unbounded fan-out, blocking in async paths, and hot-path allocations — especially in session/transport and file-transfer code.
5. **Tests.** Confirm the change is covered by the relevant harness in the [test strategy](../../docs/testing/strategy.md).

Output findings grouped by severity (blocking / should-fix / nit) with a file:line and a concrete fix.
