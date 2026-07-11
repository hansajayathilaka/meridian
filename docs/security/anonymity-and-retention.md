# Privacy Model, Data Retention & the "Anonymity" Question

<!-- Synthesis of: p2p-comms-design.md §1.2/§1.3, §5.4; DOC-02 §3 (retention); DOC-03 residual risk.
     No new architecture is introduced here — this reorganizes existing decisions. -->
> **Nav:** [docs index](../INDEX.md) · [threat model](./threat-model.md) · [threat→mitigation matrix](./threat-mitigation-matrix.md) · [data model](../architecture/data-model.md)

## Terminology, stated plainly

Meridian does **not** provide anonymity in the Tor/mixnet sense, and this document exists so no
one — human or future Claude Code session — accidentally claims that it does. What Meridian
actually provides is a precise, weaker set of guarantees:

- **Pseudonymous, self-certifying identity.** A user is a 256-bit key, not a name, phone number,
  or email. There is no central directory to enumerate (see [ADR 0001](../adr/0001-identity-scheme.md)).
- **End-to-end content confidentiality** for every modality, against all infrastructure
  (see [threat model](./threat-model.md) goal 1).
- **Optional IP-hiding between peers** via `relay-only` mode, traded against latency
  (see [ADR 0008](../adr/0008-infra-topology.md) and system design §5.4).
- **Metadata minimization**, *not* metadata elimination.

The word "anonymity" appears in tooling names (the [anonymity-model skill](../../.claude/skills/anonymity-model/SKILL.md),
the [security-reviewer](../../.claude/agents/security-reviewer.md) agent) as shorthand for this
bundle. Those tools are built to enforce the honest scope below, never to overclaim.

## What is exposed, and to whom (never paper over this)

| Observer | Sees | Does NOT see |
|---|---|---|
| Signaling/relay operator (own org) | that two keys signaled; timing; mailbox sizes/timestamps | message/media content; contact graphs beyond transient routing |
| The two federating orgs | who-signals-whom across the boundary, per request | content; presence subscriptions (per-request reachability only) |
| Peer you talk to (`direct` mode) | your IP address | — (in `relay-only` mode, not even this) |
| TURN relay | ciphertext flow metadata (IPs, volume, timing) | content (DTLS-SRTP is E2E for 1:1) |

Full metadata hiding (mixnet-grade) is **out of scope for v1** and tracked as an open question
(system design §12 Q1).

## The "must never" list (enforced by the anonymity-model skill)

These are hard invariants. Any code, log line, schema, or metric that violates one is a defect:

1. **Never log or persist plaintext message/media content** anywhere server-side.
2. **Never store a server-side contact graph** or materialize who-talks-to-whom beyond transient
   routing state.
3. **Never put personal or sensitive data in URLs, query strings, or push payloads** — push is a
   content-free wake ping only.
4. **Never persist raw client identifiers in logs** — use per-deploy salted hashes, short retention.
5. **Never let a server assert a key** a client will trust without signature verification
   (impersonation is defeated at the client, see [threat model](./threat-model.md) goal 2).
6. **Never add a "convenience" feature to the mailbox** (search, server-side read state) — its
   security argument is its poverty of function ([ADR 0007](../adr/0007-offline-mailbox.md)).

## Retention defaults

<!-- Source: DOC-02 §3 -->
- **Rendezvous logs:** salted-hash identifiers, 7-day retention (org-overridable — documented, not
  hidden).
- **Offline mailbox:** ciphertext only, TTL 14 days default, `TTL=0` disables the store entirely
  (pure-P2P mode). See [ADR 0007](../adr/0007-offline-mailbox.md).
- **Client history:** user-controlled; disappearing-messages timer enforced on both ends at the
  stream-type layer. A compromised peer can obviously retain — stated honestly in UX copy.

## Residual risk accepted (v1)

<!-- Source: p2p-comms-design.md §1.3, DOC-03 -->
Direct-mode peer IPs; org-bounded who-signals-whom + timing; the TTL-bounded ciphertext mailbox;
live-endpoint compromise; no post-quantum protection until the PQXDH bundle bump; browser-served
code is not binary-signed; group properties weaker than 1:1 until MLS; air-gapped iOS has no push.
Each is detailed in the [threat→mitigation matrix](./threat-mitigation-matrix.md).
