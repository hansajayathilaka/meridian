---
name: anonymity-model
description: Use when writing or reviewing any code, log line, schema, metric, or UX/doc copy that could touch identity, message content, metadata, logging, retention, or privacy claims. Encodes exactly what Meridian's privacy model guarantees, what it does NOT, and the server-side "must never" invariants.
---
# Anonymity / Privacy Model — enforcement skill

**Read the canonical source before acting:**
[docs/security/anonymity-and-retention.md](../../../docs/security/anonymity-and-retention.md) and
[docs/security/threat-model.md](../../../docs/security/threat-model.md).

## Scope — state it accurately, never overclaim
Meridian is **not** anonymity software in the Tor/mixnet sense. It provides:
- Pseudonymous, self-certifying **key identity** (a 256-bit key, no directory to enumerate).
- **End-to-end content confidentiality** for all modalities against all infrastructure.
- **Optional** peer-IP hiding via `relay-only` mode (latency trade).
- **Metadata minimization, not elimination** — the involved orgs' servers still see who-signals-whom
  and timing; direct-mode peers see each other's IPs.

If you find code, a comment, UX string, or doc claiming stronger anonymity than this, fix it.

## The "must never" list (hard invariants — any violation is a defect)
1. Never log or persist plaintext message/media content server-side.
2. Never store a server-side contact graph or materialize who-talks-to-whom beyond transient routing.
3. Never put personal/sensitive data in URLs, query strings, or push payloads (push = content-free
   wake ping only).
4. Never persist raw client identifiers in logs — salted per-deploy hashes, short retention.
5. Never let a server assert a key a client trusts without signature verification.
6. Never add a "convenience" capability to the offline mailbox (search, server-side read state); it
   stays ciphertext-only, TTL/quota-bounded. See [ADR 0007](../../../docs/adr/0007-offline-mailbox.md).

## When reviewing, cross-check
- The exposure table and residual-risk list in the canonical doc.
- The [threat → mitigation matrix](../../../docs/security/threat-mitigation-matrix.md): every safety
  claim must map to a verifying test.
- Retention defaults (logs 7d salted-hash; mailbox TTL 14d, `TTL=0` = pure-P2P).

Pair with the [security-reviewer](../../agents/security-reviewer.md) subagent for anything non-trivial.
